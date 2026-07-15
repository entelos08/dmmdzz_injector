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
NTSTATUS dmmdzz_ScanMemory (PDMMDZZ_SCAN_REQUEST p, PVOID buf, ULONG bufLen);
NTSTATUS dmmdzz_EnumModules(PDMMDZZ_ENUM_MODULES p, PVOID buf, ULONG bufLen);
NTSTATUS dmmdzz_PtrScan    (PDMMDZZ_PTRSCAN_REQUEST p, PVOID buf, ULONG bufLen);
NTSTATUS dmmdzz_HideProcess  (PDMMDZZ_HIDE_PROCESS p);
NTSTATUS dmmdzz_UnhideProcess(PDMMDZZ_HIDE_PROCESS p);

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
        DbgPrint(DMMDZZ_DBG_TAG " %s: inLen=%lu OutLen=%lu sizeof(MEM_OP)=%lu code=0x%X\n",
                 (code == IOCTL_DMMDZZ_READ_MEMORY) ? "READ" : "WRITE",
                 inLen, OutLen, (ULONG)sizeof(*p), code);
        if (inLen < sizeof(*p)) {
            DbgPrint(DMMDZZ_DBG_TAG " %s: inLen < sizeof(MEM_OP) -> BUFFER_TOO_SMALL\n",
                     (code == IOCTL_DMMDZZ_READ_MEMORY) ? "READ" : "WRITE");
            status = STATUS_BUFFER_TOO_SMALL; break;
        }
        DbgPrint(DMMDZZ_DBG_TAG " %s: ProcessId=%p Address=0x%llX Size=%llu BufferOffset=%llu\n",
                 (code == IOCTL_DMMDZZ_READ_MEMORY) ? "READ" : "WRITE",
                 p->ProcessId, (ULONGLONG)p->Address,
                 (ULONGLONG)p->Size, (ULONGLONG)p->BufferOffset);

        /* The payload lives at p->BufferOffset inside the same system buffer */
        if (p->BufferOffset + p->Size > (SIZE_T)inLen) {
            DbgPrint(DMMDZZ_DBG_TAG " %s: BufferOffset+Size (%llu+%llu=%llu) > inLen (%lu) -> INVALID_PARAMETER\n",
                     (code == IOCTL_DMMDZZ_READ_MEMORY) ? "READ" : "WRITE",
                     (ULONGLONG)p->BufferOffset, (ULONGLONG)p->Size,
                     (ULONGLONG)(p->BufferOffset + p->Size), inLen);
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

    case IOCTL_DMMDZZ_SCAN_MEMORY: {
        PDMMDZZ_SCAN_REQUEST p = (PDMMDZZ_SCAN_REQUEST)sysBuf;
        DbgPrint(DMMDZZ_DBG_TAG " SCAN_MEMORY: inLen=%lu OutLen=%lu sizeof(req)=%lu\n",
                 inLen, OutLen, (ULONG)sizeof(*p));
        if (inLen < sizeof(*p)) {
            DbgPrint(DMMDZZ_DBG_TAG " SCAN_MEMORY: inLen < sizeof(req) -> BUFFER_TOO_SMALL\n");
            status = STATUS_BUFFER_TOO_SMALL; break;
        }

        DbgPrint(DMMDZZ_DBG_TAG " SCAN_MEMORY: ValueOff=%lu ValueSize=%llu MaxResults=%lu ResultsOff=%lu\n",
                 p->ValueOffset, (ULONGLONG)p->ValueSize, p->MaxResults, p->ResultsOffset);

        /* Validate value bytes are within input buffer */
        if (p->ValueOffset + p->ValueSize > (SIZE_T)inLen) {
            DbgPrint(DMMDZZ_DBG_TAG " SCAN_MEMORY: value bytes exceed inLen -> INVALID_PARAMETER\n");
            status = STATUS_INVALID_PARAMETER; break;
        }

        /* Results array must fit in output buffer */
        if (OutLen < p->ResultsOffset) {
            DbgPrint(DMMDZZ_DBG_TAG " SCAN_MEMORY: OutLen < ResultsOff -> BUFFER_TOO_SMALL\n");
            status = STATUS_BUFFER_TOO_SMALL; break;
        }

        /* System buffer size = max(inLen, OutLen) */
        ULONG sysBufLen = (inLen > OutLen) ? inLen : OutLen;

        status = dmmdzz_ScanMemory(p, sysBuf, sysBufLen);
        DbgPrint(DMMDZZ_DBG_TAG " SCAN_MEMORY: ScanMemory returned 0x%08X, ResultsCount=%lu\n",
                 status, p->ResultsCount);

        /* Return header + results array */
        retBytes = p->ResultsOffset +
                   p->ResultsCount * (ULONG)sizeof(ULONG_PTR);
        break;
    }

    case IOCTL_DMMDZZ_ENUM_MODULES: {
        PDMMDZZ_ENUM_MODULES p = (PDMMDZZ_ENUM_MODULES)sysBuf;
        DbgPrint(DMMDZZ_DBG_TAG " ENUM_MODULES: inLen=%lu OutLen=%lu\n", inLen, OutLen);
        if (inLen < sizeof(*p)) {
            DbgPrint(DMMDZZ_DBG_TAG " ENUM_MODULES: inLen < sizeof(req) -> BUFFER_TOO_SMALL\n");
            status = STATUS_BUFFER_TOO_SMALL; break;
        }
        /* Validate modules array fits in the buffer */
        if (p->ModulesOffset + (SIZE_T)p->MaxModules * sizeof(DMMDZZ_MODULE_ENTRY) > (SIZE_T)((inLen > OutLen) ? inLen : OutLen)) {
            DbgPrint(DMMDZZ_DBG_TAG " ENUM_MODULES: modules array exceeds buffer -> INVALID_PARAMETER\n");
            status = STATUS_INVALID_PARAMETER; break;
        }
        ULONG sysBufLen = (inLen > OutLen) ? inLen : OutLen;
        status = dmmdzz_EnumModules(p, sysBuf, sysBufLen);
        DbgPrint(DMMDZZ_DBG_TAG " ENUM_MODULES: returned 0x%08X, ModuleCount=%lu\n",
                 status, p->ModuleCount);
        retBytes = p->ModulesOffset + p->ModuleCount * (ULONG)sizeof(DMMDZZ_MODULE_ENTRY);
        break;
    }

    case IOCTL_DMMDZZ_PTRSCAN: {
        PDMMDZZ_PTRSCAN_REQUEST p = (PDMMDZZ_PTRSCAN_REQUEST)sysBuf;
        DbgPrint(DMMDZZ_DBG_TAG " PTRSCAN: inLen=%lu OutLen=%lu\n", inLen, OutLen);
        if (inLen < sizeof(*p)) {
            DbgPrint(DMMDZZ_DBG_TAG " PTRSCAN: inLen < sizeof(req) -> BUFFER_TOO_SMALL\n");
            status = STATUS_BUFFER_TOO_SMALL; break;
        }
        DbgPrint(DMMDZZ_DBG_TAG " PTRSCAN: Target=0x%llX Depth=%lu MaxChains=%lu NumMods=%lu\n",
                 (ULONGLONG)p->TargetAddress, p->MaxDepth, p->MaxChains, p->NumModuleRanges);
        /* Validate module ranges and results fit in buffer */
        ULONG sysBufLen = (inLen > OutLen) ? inLen : OutLen;
        if (p->ModuleRangesOffset + (SIZE_T)p->NumModuleRanges * sizeof(DMMDZZ_MODULE_RANGE) > (SIZE_T)sysBufLen) {
            DbgPrint(DMMDZZ_DBG_TAG " PTRSCAN: module ranges exceed buffer -> INVALID_PARAMETER\n");
            status = STATUS_INVALID_PARAMETER; break;
        }
        if (p->ResultsOffset > sysBufLen) {
            DbgPrint(DMMDZZ_DBG_TAG " PTRSCAN: ResultsOff > bufLen -> INVALID_PARAMETER\n");
            status = STATUS_INVALID_PARAMETER; break;
        }
        status = dmmdzz_PtrScan(p, sysBuf, sysBufLen);
        DbgPrint(DMMDZZ_DBG_TAG " PTRSCAN: returned 0x%08X, ChainCount=%lu\n",
                 status, p->ChainCount);
        retBytes = p->ResultsOffset + p->ChainCount * (ULONG)sizeof(DMMDZZ_PTR_CHAIN);
        break;
    }

    case IOCTL_DMMDZZ_HIDE_PROCESS: {
        PDMMDZZ_HIDE_PROCESS p = (PDMMDZZ_HIDE_PROCESS)sysBuf;
        if (inLen < sizeof(*p) || OutLen < sizeof(*p)) {
            status = STATUS_BUFFER_TOO_SMALL; break;
        }
        DbgPrint(DMMDZZ_DBG_TAG " HIDE_PROCESS: PID=%p\n", p->ProcessId);
        status = dmmdzz_HideProcess(p);
        DbgPrint(DMMDZZ_DBG_TAG " HIDE_PROCESS: returned 0x%08X EPROCESS=%p\n",
                 status, (PVOID)p->EProcessVA);
        retBytes = sizeof(*p);
        break;
    }

    case IOCTL_DMMDZZ_UNHIDE_PROCESS: {
        PDMMDZZ_HIDE_PROCESS p = (PDMMDZZ_HIDE_PROCESS)sysBuf;
        if (OutLen < sizeof(*p)) {
            status = STATUS_BUFFER_TOO_SMALL; break;
        }
        DbgPrint(DMMDZZ_DBG_TAG " UNHIDE_PROCESS\n");
        status = dmmdzz_UnhideProcess(p);
        DbgPrint(DMMDZZ_DBG_TAG " UNHIDE_PROCESS: returned 0x%08X EPROCESS=%p\n",
                 status, (PVOID)p->EProcessVA);
        retBytes = sizeof(*p);
        break;
    }

    default:
        status = STATUS_INVALID_DEVICE_REQUEST;
        break;
    }

    Irp->IoStatus.Information = retBytes;
    return status;
}
