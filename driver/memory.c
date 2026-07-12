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

#ifndef PAGE_EXECUTE_READWRITE
#define PAGE_EXECUTE_READWRITE 0x40
#endif

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
