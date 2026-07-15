/* =============================================================================
 * driver/main.c
 *
 * DriverEntry, DriverUnload, and the IRP dispatch table setup.
 *
 * EDUCATIONAL NOTES
 * -----------------
 *  * DriverEntry runs at PASSIVE_LEVEL inside the System process.
 *  * We create a "control device object" that the user-mode app opens with
 *    CreateFile(L"\\\\.\\dmmdzz_injector"). All IOCTLs land on that device.
 *  * A symbolic link in the Win32 namespace (\??\) makes the device visible
 *    to user mode as \\.\dmmdzz_injector.
 *  * This driver performs NO hardware access; it is purely a software
 *    in-memory learning vehicle.
 *
 *  KDU MODE (DMMDZZ_KDU_MODE):
 *  ---------------------------
 *  When loaded via KDU (manual mapping), the DriverObject provided by KDU
 *  may not be fully compatible with IoCreateDevice on all Windows versions.
 *  To work around this, DriverEntry acts as a trampoline that calls
 *  IoCreateDriver() — an exported but undocumented ntoskrnl API — to create
 *  a brand new, kernel-managed DriverObject. The real initialization then
 *  runs with this proper DriverObject, avoiding the crash in
 *  IoCreateDevice -> ObfReferenceObject(NULL).
 *
 *  Build:
 *    Normal:  cl.exe ...                          -> dmmdzz_injector.sys
 *    KDU:     cl.exe ... /DDMMDZZ_KDU_MODE ...    -> dmmdzz_injector_kdu.sys
 * ============================================================================= */
#include "driver.h"

DRIVER_UNLOAD dmmdzz_Unload;
DRIVER_DISPATCH dmmdzz_CreateClose;
DRIVER_DISPATCH dmmdzz_DeviceControl;

/* Forward decls from sibling translation units */
NTSTATUS dmmdzz_HandleIoctl(PIRP Irp, PIO_STACK_LOCATION IoStack, ULONG OutLen);

#ifdef DMMDZZ_KDU_MODE
/*
 * IoCreateDriver is exported by ntoskrnl but not declared in standard WDK
 * headers (ntddk.h / ntifs.h). It creates a proper DRIVER_OBJECT via the
 * object manager, inserts it into \Driver\<name>, and calls the provided
 * initialization routine. This is the cleanest way to obtain a fully
 * functional DriverObject when running under KDU's manual mapping.
 */
NTKERNELAPI NTSTATUS NTAPI IoCreateDriver(
    IN PUNICODE_STRING DriverName,        /* optional, may be NULL */
    IN PDRIVER_INITIALIZE InitializationFunction
);
#endif

/* -------------------------------------------------------------------------
 * Shared initialization: create device, symbolic link, wire up dispatch.
 * Called with a proper DriverObject (either from I/O Manager or IoCreateDriver).
 * ------------------------------------------------------------------------- */
static NTSTATUS dmmdzz_Init(PDRIVER_OBJECT DriverObject)
{
    NTSTATUS          status;
    UNICODE_STRING    devName;
    UNICODE_STRING    dosName;
    PDEVICE_OBJECT    devObj = NULL;

    RtlInitUnicodeString(&devName, DEVICE_NAME);

    /* Create a control device. DO_BUFFERED_IO => I/O Manager will allocate
     * the system buffer for IOCTL input/output (METHOD_BUFFERED). */
    status = IoCreateDevice(
        DriverObject,
        0,                       /* DeviceExtensionSize - we keep state global */
        &devName,
        FILE_DEVICE_UNKNOWN,
        FILE_DEVICE_SECURE_OPEN,
        FALSE,                   /* not exclusive */
        &devObj);

    if (!NT_SUCCESS(status)) {
        DbgPrint(DMMDZZ_DBG_TAG " IoCreateDevice failed 0x%08X\n", status);
        return status;
    }

    /* Win32-visible name */
    RtlInitUnicodeString(&dosName, DOS_DEVICE_NAME);
    status = IoCreateSymbolicLink(&dosName, &devName);
    if (!NT_SUCCESS(status)) {
        DbgPrint(DMMDZZ_DBG_TAG " IoCreateSymbolicLink failed 0x%08X\n", status);
        IoDeleteDevice(devObj);
        return status;
    }

    /* Wire up dispatch routines */
    DriverObject->MajorFunction[IRP_MJ_CREATE]         = dmmdzz_CreateClose;
    DriverObject->MajorFunction[IRP_MJ_CLOSE]          = dmmdzz_CreateClose;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = dmmdzz_DeviceControl;
    DriverObject->DriverUnload                          = dmmdzz_Unload;

    /* METHOD_BUFFERED uses buffered I/O */
    devObj->Flags |= DO_BUFFERED_IO;
    devObj->Flags &= ~DO_DEVICE_INITIALIZING;

    DbgPrint(DMMDZZ_DBG_TAG " DriverEntry OK\n");
    return STATUS_SUCCESS;
}

/* -------------------------------------------------------------------------
 * DriverEntry
 *
 * In KDU mode: trampoline that calls IoCreateDriver to get a proper
 *              DriverObject, then calls dmmdzz_Init via dmmdzz_RealEntry.
 * In normal mode: called directly by the I/O Manager with a valid DriverObject.
 * ------------------------------------------------------------------------- */
#ifdef DMMDZZ_KDU_MODE

/* Real entry point called by IoCreateDriver with a kernel-managed DriverObject */
static NTSTATUS dmmdzz_RealEntry(PDRIVER_OBJECT DriverObject,
                                 PUNICODE_STRING RegistryPath)
{
    UNREFERENCED_PARAMETER(RegistryPath);
    DbgPrint(DMMDZZ_DBG_TAG " RealEntry (via IoCreateDriver)\n");
    return dmmdzz_Init(DriverObject);
}

/* KDU trampoline: KDU calls this with its manually-created DriverObject.
 * We ignore it and create a fresh, proper DriverObject via IoCreateDriver. */
NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject,
                     PUNICODE_STRING RegistryPath)
{
    UNREFERENCED_PARAMETER(DriverObject);
    UNREFERENCED_PARAMETER(RegistryPath);

    DbgPrint(DMMDZZ_DBG_TAG " KDU mode: calling IoCreateDriver\n");

    UNICODE_STRING driverName;
    RtlInitUnicodeString(&driverName, DRIVER_OBJ_NAME);

    NTSTATUS status = IoCreateDriver(&driverName, dmmdzz_RealEntry);
    if (!NT_SUCCESS(status)) {
        DbgPrint(DMMDZZ_DBG_TAG " IoCreateDriver failed 0x%08X\n", status);
    }
    return status;
}

#else /* !DMMDZZ_KDU_MODE — normal SCM/test-signing load */

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject,
                     PUNICODE_STRING RegistryPath)
{
    UNREFERENCED_PARAMETER(RegistryPath);
    DbgPrint(DMMDZZ_DBG_TAG " DriverEntry\n");
    return dmmdzz_Init(DriverObject);
}

#endif /* DMMDZZ_KDU_MODE */

/* -------------------------------------------------------------------------
 * Unload - tear down everything in reverse order
 * ------------------------------------------------------------------------- */
VOID dmmdzz_Unload(PDRIVER_OBJECT DriverObject)
{
    UNICODE_STRING dosName;
    PDEVICE_OBJECT dev, next;

    DbgPrint(DMMDZZ_DBG_TAG " Unload\n");

    RtlInitUnicodeString(&dosName, DOS_DEVICE_NAME);
    IoDeleteSymbolicLink(&dosName);

    for (dev = DriverObject->DeviceObject; dev; dev = next) {
        next = dev->NextDevice;
        IoDeleteDevice(dev);
    }

    DbgPrint(DMMDZZ_DBG_TAG " Unload OK\n");
}

/* -------------------------------------------------------------------------
 * IRP_MJ_CREATE / IRP_MJ_CLOSE - minimal handlers
 * ------------------------------------------------------------------------- */
NTSTATUS dmmdzz_CreateClose(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);
    Irp->IoStatus.Status      = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

/* -------------------------------------------------------------------------
 * IRP_MJ_DEVICE_CONTROL dispatcher
 * ------------------------------------------------------------------------- */
NTSTATUS dmmdzz_DeviceControl(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    PIO_STACK_LOCATION ioStack;
    NTSTATUS           status;
    ULONG              outLen;

    UNREFERENCED_PARAMETER(DeviceObject);

    ioStack = IoGetCurrentIrpStackLocation(Irp);
    outLen  = ioStack->Parameters.DeviceIoControl.OutputBufferLength;

    /* All handling lives in ioctl.c so this file stays focused on lifecycle */
    status = dmmdzz_HandleIoctl(Irp, ioStack, outLen);

    Irp->IoStatus.Status      = status;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return status;
}
