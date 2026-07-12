/* =============================================================================
 * driver/memory.c
 *
 * Read/write user-mode virtual memory of an arbitrary process from the kernel.
 *
 * EDUCATIONAL NOTES
 * -----------------
 *  * KeStackAttachProcess switches into the target process's address space.
 *  * ProbeForRead validates user-range addresses for reading.
 *  * For WRITES: we must temporarily change page protection with
 *    ZwProtectVirtualMemory because code/data pages may be read-only.
 *    ProbeForWrite would reject read-only pages, so we bypass it and
 *    instead: change protection → write → restore protection.
 *
 *  * IRQL: must be PASSIVE_LEVEL for KeStackAttachProcess / ZwProtectVirtualMemory.
 *
 *  * IMPORTANT: The caller (ioctl.c) already computed the payload pointer:
 *      buf == sysBuf + p->BufferOffset
 *    So we use buf directly, do NOT add p->BufferOffset again.
 * ============================================================================= */
#include "driver.h"

/* Undocumented but exported by ntoskrnl */
NTSYSAPI NTSTATUS NTAPI ZwProtectVirtualMemory(
    IN      HANDLE    ProcessHandle,
    IN OUT  PVOID     *BaseAddress,
    IN OUT  PSIZE_T   RegionSize,
    IN      ULONG     NewProtect,
    OUT     PULONG    OldProtect
);

NTSYSAPI NTSTATUS NTAPI ZwQueryVirtualMemory(
    IN  HANDLE                   ProcessHandle,
    IN  PVOID                    BaseAddress,
    IN  MEMORY_INFORMATION_CLASS MemoryInformationClass,
    OUT PVOID                    MemoryInformation,
    IN  SIZE_T                   MemoryInformationLength,
    OUT PSIZE_T                  ReturnLength
);

#ifndef PAGE_EXECUTE_READWRITE
#define PAGE_EXECUTE_READWRITE 0x40
#endif

/* Scan chunk size: 64KB. The chunk buffer is allocated once and reused
 * for all regions. We copy (CHUNK + valueSize - 1) bytes each iteration
 * to handle values spanning chunk boundaries. */
#define SCAN_CHUNK_SIZE  0x10000

/* -------------------------------------------------------------------------
 * IOCTL_DMMDZZ_READ_MEMORY
 * ------------------------------------------------------------------------- */
NTSTATUS dmmdzz_ReadMemory(PDMMDZZ_MEM_OP p, PVOID buf, ULONG bufLen)
{
    NTSTATUS   status = STATUS_SUCCESS;
    PEPROCESS  target = NULL;
    KAPC_STATE apc;
    SIZE_T     done = 0;

    UNREFERENCED_PARAMETER(bufLen);

    status = PsLookupProcessByProcessId(p->ProcessId, &target);
    if (!NT_SUCCESS(status)) {
        p->Hdr.Status = status;
        p->Hdr.ExtendedStatus = 2;
        return status;
    }

    KeStackAttachProcess(target, &apc);

    __try {
        ProbeForRead((PVOID)p->Address, p->Size, 1);
        RtlCopyMemory(buf, (PVOID)p->Address, p->Size);
        done = p->Size;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        status = GetExceptionCode();
        done = 0;
    }

    KeUnstackDetachProcess(&apc);
    ObDereferenceObject(target);

    p->BytesTransferred   = done;
    p->Hdr.Status         = status;
    p->Hdr.ExtendedStatus = NT_SUCCESS(status) ? 0 : 3;
    return status;
}

/* -------------------------------------------------------------------------
 * IOCTL_DMMDZZ_WRITE_MEMORY
 *
 * For write operations, the target page may be read-only (e.g. PE header,
 * code section). We use ZwProtectVirtualMemory to temporarily make it
 * writable, then write, then restore the original protection.
 * ------------------------------------------------------------------------- */
NTSTATUS dmmdzz_WriteMemory(PDMMDZZ_MEM_OP p, PVOID buf, ULONG bufLen)
{
    NTSTATUS   status = STATUS_SUCCESS;
    PEPROCESS  target = NULL;
    KAPC_STATE apc;
    SIZE_T     done = 0;

    UNREFERENCED_PARAMETER(bufLen);

    status = PsLookupProcessByProcessId(p->ProcessId, &target);
    if (!NT_SUCCESS(status)) {
        p->Hdr.Status = status;
        p->Hdr.ExtendedStatus = 2;
        return status;
    }

    KeStackAttachProcess(target, &apc);

    __try {
        /*
         * Step 1: Change page protection to writable.
         * ZwProtectVirtualMemory wants a base address aligned to page boundary
         * and a region size. It rounds BaseAddress down and RegionSize up.
         */
        PVOID  baseAddr  = (PVOID)p->Address;
        SIZE_T regionSize = p->Size;
        ULONG  oldProtect = 0;

        status = ZwProtectVirtualMemory(
            (HANDLE)-1,         /* NtCurrentProcess() */
            &baseAddr,
            &regionSize,
            PAGE_EXECUTE_READWRITE,
            &oldProtect
        );

        if (!NT_SUCCESS(status)) {
            /* Protection change failed — can't write safely */
            done = 0;
        } else {
            /* Step 2: Write the data */
            RtlCopyMemory((PVOID)p->Address, buf, p->Size);
            done = p->Size;

            /* Step 3: Restore original protection */
            PVOID  restoreBase  = (PVOID)p->Address;
            SIZE_T restoreSize  = p->Size;
            ULONG  tmpProtect   = 0;

            ZwProtectVirtualMemory(
                (HANDLE)-1,
                &restoreBase,
                &restoreSize,
                oldProtect,
                &tmpProtect
            );
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        status = GetExceptionCode();
        done = 0;
    }

    KeUnstackDetachProcess(&apc);
    ObDereferenceObject(target);

    p->BytesTransferred   = done;
    p->Hdr.Status         = status;
    p->Hdr.ExtendedStatus = NT_SUCCESS(status) ? 0 : 4;
    return status;
}

/* -------------------------------------------------------------------------
 * IOCTL_DMMDZZ_SCAN_MEMORY
 *
 * Kernel-side memory scanner. Attaches to the target process, enumerates
 * all committed readable memory regions via ZwQueryVirtualMemory, and
 * searches for exact byte-pattern matches using RtlCompareMemory.
 *
 * Matching addresses are written into the results array in the system
 * buffer. The scan stops when MaxResults is reached or all regions are
 * exhausted.
 *
 * Buffer layout:
 *   [DMMDZZ_SCAN_REQUEST][value bytes][results: ULONG_PTR[]]
 *
 * Safety:
 *   - All user-memory access is protected by __try/__except.
 *   - Memory is copied into a kernel buffer before scanning, so faults
 *     only skip the affected chunk, not the entire scan.
 * ------------------------------------------------------------------------- */
NTSTATUS dmmdzz_ScanMemory(PDMMDZZ_SCAN_REQUEST p, PVOID buf, ULONG bufLen)
{
    NTSTATUS   status      = STATUS_SUCCESS;
    PEPROCESS  target      = NULL;
    KAPC_STATE apc;
    PUCHAR     chunkBuf    = NULL;
    ULONG      resultCount = 0;

    /* --- Validate parameters --- */
    if (p->ValueSize == 0 || p->ValueSize > DMMDZZ_SCAN_MAX_VALUE_SIZE) {
        p->Hdr.Status = STATUS_INVALID_PARAMETER;
        p->Hdr.ExtendedStatus = 1;
        p->ResultsCount = 0;
        return STATUS_INVALID_PARAMETER;
    }

    /* Value bytes must be inside the buffer */
    if (p->ValueOffset + p->ValueSize > bufLen) {
        p->Hdr.Status = STATUS_INVALID_PARAMETER;
        p->Hdr.ExtendedStatus = 1;
        p->ResultsCount = 0;
        return STATUS_INVALID_PARAMETER;
    }

    /* Results array must fit in the buffer */
    ULONG availResults = (bufLen - p->ResultsOffset) / sizeof(ULONG_PTR);
    if (p->MaxResults > availResults)
        p->MaxResults = availResults;
    if (p->MaxResults == 0) {
        p->Hdr.Status = STATUS_INVALID_PARAMETER;
        p->Hdr.ExtendedStatus = 1;
        p->ResultsCount = 0;
        return STATUS_INVALID_PARAMETER;
    }

    /* Pointer to the search value (in kernel system buffer) */
    PUCHAR  valuePtr  = (PUCHAR)buf + p->ValueOffset;
    SIZE_T  valueSize = p->ValueSize;

    /* Pointer to results array */
    PULONG_PTR results = (PULONG_PTR)((PUCHAR)buf + p->ResultsOffset);

    /* --- Lookup target process --- */
    status = PsLookupProcessByProcessId(p->ProcessId, &target);
    if (!NT_SUCCESS(status)) {
        p->Hdr.Status = status;
        p->Hdr.ExtendedStatus = 2;
        p->ResultsCount = 0;
        return status;
    }

    /* --- Allocate chunk buffer: CHUNK + valueSize - 1 for boundary overlap --- */
    SIZE_T chunkBufSize = SCAN_CHUNK_SIZE + valueSize - 1;
    chunkBuf = (PUCHAR)ExAllocatePoolWithTag(
        NonPagedPool, chunkBufSize, 'sZmm');
    if (!chunkBuf) {
        ObDereferenceObject(target);
        p->Hdr.Status = STATUS_INSUFFICIENT_RESOURCES;
        p->Hdr.ExtendedStatus = 5;
        p->ResultsCount = 0;
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    /* --- Attach to target process address space --- */
    KeStackAttachProcess(target, &apc);

    __try {
        /* Scan user address space: skip first 64KB (null guard page area),
         * stop at 0x00007FFFFFFFFFFF (user-space limit on x64). */
        PVOID addr    = (PVOID)0x10000;
        PVOID maxAddr = (PVOID)0x00007FFFFFFFFFFFULL;

        while (addr < maxAddr && resultCount < p->MaxResults) {
            MEMORY_BASIC_INFORMATION mbi;
            SIZE_T returnLength = 0;

            status = ZwQueryVirtualMemory(
                (HANDLE)-1,     /* NtCurrentProcess() — we are attached */
                addr,
                MemoryBasicInformation,
                &mbi,
                sizeof(mbi),
                &returnLength);

            if (!NT_SUCCESS(status))
                break;

            /* Advance to next region regardless of whether we scan this one */
            PVOID nextAddr = (PUCHAR)mbi.BaseAddress + mbi.RegionSize;

            /* Only scan committed, readable, non-guarded regions */
            if (mbi.State == MEM_COMMIT &&
                !(mbi.Protect & PAGE_NOACCESS) &&
                !(mbi.Protect & PAGE_GUARD) &&
                (mbi.Protect & (PAGE_READONLY | PAGE_READWRITE |
                                PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE |
                                PAGE_WRITECOPY | PAGE_EXECUTE_WRITECOPY))) {

                PUCHAR regionBase = (PUCHAR)mbi.BaseAddress;
                SIZE_T regionSize = mbi.RegionSize;

                /* Scan this region in chunks */
                SIZE_T off = 0;
                while (off < regionSize && resultCount < p->MaxResults) {
                    SIZE_T remaining = regionSize - off;
                    SIZE_T toCopy = (remaining < chunkBufSize)
                                  ? remaining : chunkBufSize;

                    if (toCopy < valueSize)
                        break;

                    /* Copy chunk into kernel buffer (safe from user faults) */
                    __try {
                        RtlCopyMemory(chunkBuf, regionBase + off, toCopy);
                    }
                    __except (EXCEPTION_EXECUTE_HANDLER) {
                        /* Page fault in this chunk — skip it */
                        off += toCopy;
                        continue;
                    }

                    /* Scan positions: [0 .. toCopy - valueSize] */
                    SIZE_T scanLen = toCopy - valueSize + 1;
                    for (SIZE_T i = 0; i < scanLen; i++) {
                        if (RtlCompareMemory(chunkBuf + i, valuePtr,
                                             valueSize) == valueSize) {
                            results[resultCount++] =
                                (ULONG_PTR)(regionBase + off + i);
                            if (resultCount >= p->MaxResults)
                                break;
                        }
                    }

                    /* Advance by scanLen to avoid re-scanning overlap.
                     * The next chunk will start at off + scanLen, and its
                     * first (valueSize-1) bytes overlap with this chunk's
                     * tail — but those positions weren't scanned yet. */
                    off += scanLen;
                }
            }

            addr = nextAddr;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        /* Top-level safety net — return partial results */
        status = GetExceptionCode();
    }

    KeUnstackDetachProcess(&apc);

    if (chunkBuf)
        ExFreePoolWithTag(chunkBuf, 'sZmm');
    ObDereferenceObject(target);

    p->ResultsCount   = resultCount;
    p->Hdr.Status     = status;
    p->Hdr.ExtendedStatus = NT_SUCCESS(status) ? 0 : 6;
    return status;
}
