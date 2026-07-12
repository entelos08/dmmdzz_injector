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
 *  IMPORTANT: This source is written against the WDK. On Linux there is no
 *  WDK; build the driver on Windows with Visual Studio + WDK, then sign it
 *  with a test certificate (or enable TESTSIGNING on the target machine).
 * ============================================================================= */
#include "driver.h"

DRIVER_UNLOAD dmmdzz_Unload;
DRIVER_DISPATCH dmmdzz_CreateClose;
DRIVER_DISPATCH dmmdzz_DeviceControl;

/* Forward decls from sibling translation units */
NTSTATUS dmmdzz_HandleIoctl(PIRP Irp, PIO_STACK_LOCATION IoStack, ULONG OutLen);

/* -------------------------------------------------------------------------
 * DriverEntry
 * ------------------------------------------------------------------------- */
NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
    NTSTATUS          status;
    UNICODE_STRING    devName;
    UNICODE_STRING    dosName;
    PDEVICE_OBJECT    devObj = NULL;

    UNREFERENCED_PARAMETER(RegistryPath);

    DbgPrint("[dmmdzz] DriverEntry\n");

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
        DbgPrint("[dmmdzz] IoCreateDevice failed 0x%08X\n", status);
        return status;
    }

    /* Win32-visible name */
    RtlInitUnicodeString(&dosName, DOS_DEVICE_NAME);
    status = IoCreateSymbolicLink(&dosName, &devName);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[dmmdzz] IoCreateSymbolicLink failed 0x%08X\n", status);
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

    DbgPrint("[dmmdzz] DriverEntry OK\n");
    return STATUS_SUCCESS;
}

/* -------------------------------------------------------------------------
 * Unload - tear down everything in reverse order
 * ------------------------------------------------------------------------- */
VOID dmmdzz_Unload(PDRIVER_OBJECT DriverObject)
{
    UNICODE_STRING dosName;
    PDEVICE_OBJECT dev, next;

    DbgPrint("[dmmdzz] Unload\n");

    RtlInitUnicodeString(&dosName, DOS_DEVICE_NAME);
    IoDeleteSymbolicLink(&dosName);

    for (dev = DriverObject->DeviceObject; dev; dev = next) {
        next = dev->NextDevice;
        IoDeleteDevice(dev);
    }

    DbgPrint("[dmmdzz] Unload OK\n");
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
