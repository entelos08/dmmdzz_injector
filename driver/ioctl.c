/* =============================================================================
 * driver/ioctl.c
 *
 * IRP_MJ_DEVICE_CONTROL body. Each IOCTL code is handled in a small helper;
 * the helpers live in memory.c and process.c.
 *
 * IRQL: PASSIVE_LEVEL - that is required to issue MmCopyVirtualMemory /
 *        PsLookupProcessByProcessId / KeStackAttachProcess.
 *
 * BUFFERING
 *   We use METHOD_BUFFERED, so:
 *     Irp->AssociatedIrp.SystemBuffer  -> the single shared input+output buf
 *     IoStack->Parameters.DeviceIoControl.InputBufferLength
 *     IoStack->Parameters.DeviceIoControl.OutputBufferLength
 *   The I/O Manager copies the user buffer into the system buffer on the way
 *   in, and copies OutputBufferLength bytes back on the way out.
 * ============================================================================= */
#include "driver.h"

NTSTATUS dmmdzz_FindProcess(PDMMDZZ_FIND_PROCESS p);
NTSTATUS dmmdzz_EnumModule (PDMMDZZ_ENUM_MODULE  p);
NTSTATUS dmmdzz_QueryBase  (PDMMDZZ_QUERY_BASE   p);
NTSTATUS dmmdzz_ReadMemory (PDMMDZZ_MEM_OP p, PVOID  buf, ULONG bufLen);
NTSTATUS dmmdzz_WriteMemory(PDMMDZZ_MEM_OP p, PVOID  buf, ULONG bufLen);

/* Validate a single pointer is fully contained inside a system buffer */
static __forceinline BOOLEAN InBounds(const VOID *buf, ULONG bufLen,
                                      const VOID *p, SIZE_T sz)
{
    return ((ULONG_PTR)p >= (ULONG_PTR)buf) &&
           ((ULONG_PTR)p + sz <= (ULONG_PTR)buf + bufLen);
}

/* -------------------------------------------------------------------------
 * dmmdzz_HandleIoctl
 * ------------------------------------------------------------------------- */
NTSTATUS dmmdzz_HandleIoctl(PIRP Irp, PIO_STACK_LOCATION IoStack, ULONG OutLen)
{
    NTSTATUS status   = STATUS_SUCCESS;
    ULONG    inLen    = IoStack->Parameters.DeviceIoControl.InputBufferLength;
    PVOID    sysBuf   = Irp->AssociatedIrp.SystemBuffer;
    ULONG    code     = IoStack->Parameters.DeviceIoControl.IoControlCode;
    ULONG    retBytes = 0;

    if (!sysBuf && (inLen || OutLen)) {
        return STATUS_INVALID_PARAMETER;
    }

    switch (code) {

    case IOCTL_DMMDZZ_GET_VERSION: {
        PDMMDZZ_VERSION v = (PDMMDZZ_VERSION)sysBuf;
        if (OutLen < sizeof(*v)) { status = STATUS_BUFFER_TOO_SMALL; break; }
        v->Major  = 0; v->Minor = 1; v->Build = 0;
        v->Hdr.Status = STATUS_SUCCESS;
        v->Hdr.ExtendedStatus = 0;
        retBytes = sizeof(*v);
        break;
    }

    case IOCTL_DMMDZZ_FIND_PROCESS: {
        PDMMDZZ_FIND_PROCESS p = (PDMMDZZ_FIND_PROCESS)sysBuf;
        if (inLen < sizeof(*p) || OutLen < sizeof(*p)) {
            status = STATUS_BUFFER_TOO_SMALL; break;
        }
        status = dmmdzz_FindProcess(p);
        retBytes = sizeof(*p);
        break;
    }

    case IOCTL_DMMDZZ_ENUM_MODULE_BASE: {
        PDMMDZZ_ENUM_MODULE p = (PDMMDZZ_ENUM_MODULE)sysBuf;
        if (inLen < sizeof(*p) || OutLen < sizeof(*p)) {
            status = STATUS_BUFFER_TOO_SMALL; break;
        }
        status = dmmdzz_EnumModule(p);
        retBytes = sizeof(*p);
        break;
    }

    case IOCTL_DMMDZZ_QUERY_BASE: {
        PDMMDZZ_QUERY_BASE p = (PDMMDZZ_QUERY_BASE)sysBuf;
        if (inLen < sizeof(*p) || OutLen < sizeof(*p)) {
            status = STATUS_BUFFER_TOO_SMALL; break;
        }
        status = dmmdzz_QueryBase(p);
        retBytes = sizeof(*p);
        break;
    }

    case IOCTL_DMMDZZ_READ_MEMORY:
    case IOCTL_DMMDZZ_WRITE_MEMORY: {
        PDMMDZZ_MEM_OP p = (PDMMDZZ_MEM_OP)sysBuf;
        if (inLen < sizeof(*p)) { status = STATUS_BUFFER_TOO_SMALL; break; }

        /* The payload lives at p->BufferOffset inside the same system buffer */
        if (p->BufferOffset + p->Size > (SIZE_T)inLen) {
            status = STATUS_INVALID_PARAMETER; break;
        }
        PVOID payload = (PVOID)((ULONG_PTR)sysBuf + p->BufferOffset);

        if (code == IOCTL_DMMDZZ_READ_MEMORY) {
            if (OutLen < p->BufferOffset + p->Size) {
                status = STATUS_BUFFER_TOO_SMALL; break;
            }
            status = dmmdzz_ReadMemory(p, payload, inLen);
            retBytes = (ULONG)(p->BufferOffset + p->BytesTransferred);
        } else {
            status = dmmdzz_WriteMemory(p, payload, inLen);
            retBytes = sizeof(*p);   /* we only return the header */
        }
        break;
    }

    default:
        status = STATUS_INVALID_DEVICE_REQUEST;
        break;
    }

    Irp->IoStatus.Information = retBytes;
    return status;
}
