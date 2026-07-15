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
#include <intrin.h>

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

/* ZwReadVirtualMemory is resolved dynamically via MmGetSystemRoutineAddress
 * because it is NOT exported by ntoskrnl.exe on modern Windows (confirmed
 * via dumpbin /exports). The fallback path uses IsRangeValid + RtlCopyMemory. */
typedef NTSTATUS (*PFN_ZwReadVirtualMemory)(
    IN  HANDLE   ProcessHandle,
    IN  PVOID    BaseAddress,
    OUT PVOID    Buffer,
    IN  SIZE_T   Size,
    OUT PSIZE_T  BytesRead OPTIONAL
);
static PFN_ZwReadVirtualMemory g_ZwReadVirtualMemory = NULL;

/* MmCopyVirtualMemory — undocumented but exported by ntoskrnl.
 * Used internally by NtWriteVirtualMemory. It locks the target pages,
 * maps them into kernel space with write access (via MDL), and copies.
 * This bypasses SEC_IMAGE protection restrictions that cause
 * ZwProtectVirtualMemory to fail on DLL code sections.
 *
 * IMPORTANT: MmCopyVirtualMemory expects USER-MODE addresses for both
 * SourceAddress and TargetAddress. Our source buffer (buf) is in kernel
 * space. We work around this by allocating a temporary user buffer in
 * the target process, copying kernel data there, then calling
 * MmCopyVirtualMemory with the temp buffer as the source. */
typedef NTSTATUS (*PFN_MmCopyVirtualMemory)(
    IN  PEPROCESS      SourceProcess,
    IN  PVOID          SourceAddress,
    IN  PEPROCESS      TargetProcess,
    IN  PVOID          TargetAddress,
    IN  SIZE_T         BufferSize,
    IN  KPROCESSOR_MODE PreviousMode,
    OUT PSIZE_T        ReturnSize
);
static PFN_MmCopyVirtualMemory g_MmCopyVirtualMemory = NULL;

/* ZwAllocateVirtualMemory / ZwFreeVirtualMemory — for temp user buffer */
NTSYSAPI NTSTATUS NTAPI ZwAllocateVirtualMemory(
    IN      HANDLE    ProcessHandle,
    IN OUT  PVOID     *BaseAddress,
    IN      ULONG_PTR ZeroBits,
    IN OUT  PSIZE_T   RegionSize,
    IN      ULONG     AllocationType,
    IN      ULONG     Protect
);
NTSYSAPI NTSTATUS NTAPI ZwFreeVirtualMemory(
    IN      HANDLE    ProcessHandle,
    IN OUT  PVOID     *BaseAddress,
    IN OUT  PSIZE_T   RegionSize,
    IN      ULONG     FreeType
);

#ifndef PAGE_EXECUTE_READWRITE
#define PAGE_EXECUTE_READWRITE 0x40
#endif
#ifndef PAGE_READWRITE
#define PAGE_READWRITE 0x04
#endif
#ifndef PAGE_WRITECOPY
#define PAGE_WRITECOPY 0x08
#endif
#ifndef PAGE_EXECUTE_WRITECOPY
#define PAGE_EXECUTE_WRITECOPY 0x80
#endif

/* Scan chunk size: 64KB. The chunk buffer is allocated once and reused
 * for all regions. We copy (CHUNK + valueSize - 1) bytes each iteration
 * to handle values spanning chunk boundaries. */
#define SCAN_CHUNK_SIZE  0x10000

/* -------------------------------------------------------------------------
 * dmmdzz_IsRangeValid
 *
 * Check if all pages in [addr, addr+size) are currently valid (resident in
 * physical memory). This replaces __try/__except for probing user memory,
 * because SEH exception tables are NOT registered in KDU-mapped drivers,
 * causing KMODE_EXCEPTION_NOT_HANDLED BSODs when RtlCopyMemory faults.
 *
 * NOTE: MmIsAddressValid is not a hard guarantee — the page could be paged
 * out between the check and the access. Use dmmdzz_SafeCopyUser for the
 * actual copy, which uses ZwReadVirtualMemory to handle faults safely.
 * ------------------------------------------------------------------------- */
BOOLEAN dmmdzz_IsRangeValid(PVOID addr, SIZE_T size)
{
    if (size == 0) return TRUE;
    PUCHAR start = (PUCHAR)((ULONG_PTR)addr & ~((ULONG_PTR)0xFFF));
    PUCHAR end   = (PUCHAR)(((ULONG_PTR)addr + size - 1) & ~((ULONG_PTR)0xFFF));
    for (PUCHAR page = start; page <= end; page += 0x1000) {
        if (!MmIsAddressValid(page))
            return FALSE;
    }
    return TRUE;
}

/* -------------------------------------------------------------------------
 * dmmdzz_SafeCopyUser
 *
 * Safely copy user-mode memory (from the currently-attached process) into
 * a kernel buffer. Uses ZwReadVirtualMemory which handles page faults
 * internally via ntoskrnl's properly-registered SEH tables — unlike our
 * KDU-mapped driver whose SEH tables are NOT registered, causing BSODs.
 *
 * This replaces the pattern: dmmdzz_IsRangeValid() + RtlCopyMemory(),
 * which has a TOCTOU race: the page can be paged out between the check
 * and the copy, causing an unhandled page fault -> BSOD.
 *
 * We still call dmmdzz_IsRangeValid first as a fast-path filter to skip
 * definitely-invalid regions without the syscall overhead.
 *
 * Returns TRUE if all bytes were copied, FALSE on any error.
 * ------------------------------------------------------------------------- */
BOOLEAN dmmdzz_SafeCopyUser(PVOID dst, PVOID src, SIZE_T size)
{
    SIZE_T    bytesRead = 0;
    NTSTATUS  s;

    if (size == 0) return TRUE;

    /* Lazy-resolve ZwReadVirtualMemory (not in some ntoskrnl.lib versions). */
    if (!g_ZwReadVirtualMemory) {
        UNICODE_STRING name;
        RtlInitUnicodeString(&name, L"ZwReadVirtualMemory");
        g_ZwReadVirtualMemory =
            (PFN_ZwReadVirtualMemory)MmGetSystemRoutineAddress(&name);
        if (!g_ZwReadVirtualMemory) {
            /* Fallback: pure IsRangeValid + RtlCopyMemory (old behavior).
             * Less safe but allows the driver to load on systems where
             * the export is unavailable. */
            if (!dmmdzz_IsRangeValid(src, size))
                return FALSE;
            RtlCopyMemory(dst, src, size);
            return TRUE;
        }
    }

    /* Fast path: skip definitely-invalid pages without a syscall */
    if (!dmmdzz_IsRangeValid(src, size))
        return FALSE;

    /* Safe path: ZwReadVirtualMemory handles page faults internally.
     * (HANDLE)-1 = NtCurrentProcess() — we are attached to the target. */
    s = g_ZwReadVirtualMemory((HANDLE)-1, src, dst, size, &bytesRead);
    return NT_SUCCESS(s) && bytesRead == size;
}

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

    /* __try/__except does NOT work in KDU-mapped drivers (SEH tables are
     * not registered). dmmdzz_SafeCopyUser uses ZwReadVirtualMemory which
     * handles page faults via ntoskrnl's properly-registered SEH, avoiding
     * the TOCTOU race in dmmdzz_IsRangeValid + RtlCopyMemory. */
    if (dmmdzz_SafeCopyUser(buf, (PVOID)p->Address, p->Size)) {
        done = p->Size;
    } else {
        status = STATUS_ACCESS_VIOLATION;
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
 * code section of a SEC_IMAGE / MEM_MAPPED DLL). We try multiple methods:
 *
 *   0. MmCopyVirtualMemory with temp user buffer (PRIMARY)
 *      MmCopyVirtualMemory is the internal impl behind NtWriteVirtualMemory
 *      (WriteProcessMemory). It locks target pages via MDL and maps them
 *      writable into kernel space, bypassing SEC_IMAGE restrictions.
 *      Since it expects user-mode source addresses, we allocate a temp
 *      user buffer in the target process, copy kernel data there, then
 *      call MmCopyVirtualMemory(temp -> target code).
 *
 *   1. ZwProtectVirtualMemory + RtlCopyMemory (fallback)
 *      Changes page protection to PAGE_EXECUTE_READWRITE, writes, restores.
 *      Fails with STATUS_SECTION_PROTECTION on SEC_IMAGE / MEM_MAPPED pages.
 *
 *   2. Direct RtlCopyMemory if page is already writable
 *      Queries protection via ZwQueryVirtualMemory; writes directly if the
 *      page is already writable (e.g. after user-mode VirtualProtectEx).
 *
 *   3. Direct PTE manipulation (last resort)
 *      Sets the R/W bit in the page table entry. Requires the PTE self-map
 *      base to be correct. On Windows 10 1607+ with KASLR, the PTE base
 *      is randomized, so the hardcoded 0xFFFFF68000000000 may be wrong.
 * ------------------------------------------------------------------------- */
NTSTATUS dmmdzz_WriteMemory(PDMMDZZ_MEM_OP p, PVOID buf, ULONG bufLen)
{
    NTSTATUS   status = STATUS_SUCCESS;
    PEPROCESS  target = NULL;
    KAPC_STATE apc;
    SIZE_T     done = 0;

    UNREFERENCED_PARAMETER(bufLen);

    DbgPrint(DMMDZZ_DBG_TAG " WriteMemory: pid=%p VA=0x%llX Size=%llu buf=%p bufLen=%lu\n",
             p->ProcessId, (ULONGLONG)p->Address,
             (ULONGLONG)p->Size, buf, bufLen);

    status = PsLookupProcessByProcessId(p->ProcessId, &target);
    if (!NT_SUCCESS(status)) {
        DbgPrint(DMMDZZ_DBG_TAG " WriteMemory: PsLookupProcessByProcessId failed 0x%08X\n",
                 status);
        p->Hdr.Status = status;
        p->Hdr.ExtendedStatus = 2;
        return status;
    }

    /* All methods require attaching to the target process. */
    KeStackAttachProcess(target, &apc);

    /* --- Dump full page info for diagnosis --- */
    {
        MEMORY_BASIC_INFORMATION mbi;
        SIZE_T returnLength = 0;

        RtlZeroMemory(&mbi, sizeof(mbi));
        status = ZwQueryVirtualMemory(
            (HANDLE)-1,
            (PVOID)p->Address,
            MemoryBasicInformation,
            &mbi,
            sizeof(mbi),
            &returnLength
        );

        if (NT_SUCCESS(status)) {
            DbgPrint(DMMDZZ_DBG_TAG " WriteMemory: PAGE INFO for VA=0x%llX:\n",
                     (ULONGLONG)p->Address);
            DbgPrint(DMMDZZ_DBG_TAG "   BaseAddress       = 0x%llX\n",
                     (ULONGLONG)mbi.BaseAddress);
            DbgPrint(DMMDZZ_DBG_TAG "   AllocationBase    = 0x%llX\n",
                     (ULONGLONG)mbi.AllocationBase);
            DbgPrint(DMMDZZ_DBG_TAG "   AllocationProtect = 0x%08X\n",
                     mbi.AllocationProtect);
            DbgPrint(DMMDZZ_DBG_TAG "   RegionSize        = 0x%llX\n",
                     (ULONGLONG)mbi.RegionSize);
            DbgPrint(DMMDZZ_DBG_TAG "   State             = 0x%08X (%s)\n",
                     mbi.State,
                     mbi.State == 0x1000  ? "MEM_COMMIT" :
                     mbi.State == 0x2000  ? "MEM_RESERVE" :
                     mbi.State == 0x10000 ? "MEM_FREE" : "?");
            DbgPrint(DMMDZZ_DBG_TAG "   Protect           = 0x%08X\n",
                     mbi.Protect);
            DbgPrint(DMMDZZ_DBG_TAG "   Type              = 0x%08X (%s)\n",
                     mbi.Type,
                     mbi.Type == 0x1000000 ? "MEM_IMAGE" :
                     mbi.Type == 0x40000   ? "MEM_MAPPED" :
                     mbi.Type == 0x20000   ? "MEM_PRIVATE" : "?");
        } else {
            DbgPrint(DMMDZZ_DBG_TAG " WriteMemory: ZwQueryVirtualMemory failed 0x%08X\n",
                     status);
        }
    }

    /* --- Method 0: MDL mapping + MmProtectMdlSystemAddress (PRIMARY) ---
     *
     * Maps the target code page into kernel space via MDL, then changes
     * the KERNEL mapping's protection to writable. This bypasses SEC_IMAGE
     * restrictions because:
     *
     * - MmProbeAndLockPages(IoReadAccess) locks the physical page for READ.
     *   PAGE_EXECUTE_READ allows read access, so this succeeds on code pages.
     *   (Using IoWriteAccess would FAIL on read-only pages.)
     *
     * - MmMapLockedPagesSpecifyCache creates a NEW kernel-space PTE pointing
     *   to the same physical page. The kernel mapping starts read-only.
     *
     * - MmProtectMdlSystemAddress(PAGE_READWRITE) changes the KERNEL PTE's
     *   protection to writable. This operates on the system-space mapping,
     *   NOT the user-space VAD, so SEC_IMAGE restrictions do NOT apply.
     *
     * - RtlCopyMemory to the kernel mapping writes to the same physical
     *   page as the user-space code address. */
    {
        PMDL mdl = IoAllocateMdl((PVOID)p->Address, (ULONG)p->Size, FALSE, FALSE, NULL);
        if (mdl) {
            DbgPrint(DMMDZZ_DBG_TAG " WriteMemory: trying MDL mapping\n");

            /* Lock pages for READ access (succeeds on PAGE_EXECUTE_READ).
             * NOTE: MmProbeAndLockPages can raise exceptions, but we verified
             * State=MEM_COMMIT via ZwQueryVirtualMemory, so it should succeed.
             * ntoskrnl's own SEH handles internal exceptions; the raised
             * exception is for the caller, but since the page is valid,
             * no exception will be raised. */
            MmProbeAndLockPages(mdl, UserMode, IoReadAccess);

            /* Map into kernel space (read-only initially) */
            PVOID kernelAddr = MmMapLockedPagesSpecifyCache(
                mdl, KernelMode, MmCached, NULL, FALSE, NormalPagePriority);

            if (kernelAddr) {
                /* Change kernel mapping protection to writable */
                status = MmProtectMdlSystemAddress(mdl, PAGE_READWRITE);

                if (NT_SUCCESS(status)) {
                    DbgPrint(DMMDZZ_DBG_TAG " WriteMemory: MDL mapped at 0x%llX (writable), writing\n",
                             (ULONGLONG)kernelAddr);

                    /* Write to kernel mapping = write to same physical page */
                    RtlCopyMemory(kernelAddr, buf, p->Size);
                    done = p->Size;
                    status = STATUS_SUCCESS;

                    DbgPrint(DMMDZZ_DBG_TAG " WriteMemory: wrote %llu bytes via MDL mapping\n",
                             (ULONGLONG)done);
                } else {
                    DbgPrint(DMMDZZ_DBG_TAG " WriteMemory: MmProtectMdlSystemAddress failed 0x%08X\n",
                             status);
                }

                MmUnmapLockedPages(kernelAddr, mdl);
            } else {
                DbgPrint(DMMDZZ_DBG_TAG " WriteMemory: MmMapLockedPagesSpecifyCache failed\n");
            }

            /* Only unlock if pages were actually locked.
             * Check MDL_MDL_LOCKED flag (0x2) in MdlFlags. */
            if (mdl->MdlFlags & MDL_PAGES_LOCKED) {
                MmUnlockPages(mdl);
            }
            IoFreeMdl(mdl);

            if (done > 0) {
                KeUnstackDetachProcess(&apc);
                goto write_done;
            }
        } else {
            DbgPrint(DMMDZZ_DBG_TAG " WriteMemory: IoAllocateMdl failed\n");
        }
    }

    /* --- Method 1: ZwProtectVirtualMemory + RtlCopyMemory --- */
    {
        PVOID    baseAddr = (PVOID)((ULONG_PTR)p->Address & ~((ULONG_PTR)0xFFF));
        SIZE_T   regionSize = (SIZE_T)p->Size +
                              ((SIZE_T)p->Address - (SIZE_T)baseAddr);
        regionSize = (regionSize + 0xFFF) & ~((SIZE_T)0xFFF);
        ULONG    oldProtect = 0;

        DbgPrint(DMMDZZ_DBG_TAG " WriteMemory: trying ZwProtectVirtualMemory "
                 "base=0x%llX size=%llu\n",
                 (ULONGLONG)baseAddr, regionSize);

        status = ZwProtectVirtualMemory(
            (HANDLE)-1,      /* NtCurrentProcess() — we are attached */
            &baseAddr,
            &regionSize,
            PAGE_EXECUTE_READWRITE,
            &oldProtect
        );

        if (NT_SUCCESS(status)) {
            DbgPrint(DMMDZZ_DBG_TAG " WriteMemory: ZwProtectVirtualMemory succeeded, "
                     "oldProtect=0x%X\n", oldProtect);

            /* Write the data */
            RtlCopyMemory((PVOID)p->Address, buf, p->Size);
            done = p->Size;

            /* Restore original protection */
            {
                ULONG tmp = 0;
                ZwProtectVirtualMemory(
                    (HANDLE)-1,
                    &baseAddr,
                    &regionSize,
                    oldProtect,
                    &tmp
                );
            }

            DbgPrint(DMMDZZ_DBG_TAG " WriteMemory: wrote %llu bytes via "
                     "ZwProtectVirtualMemory\n", (ULONGLONG)done);
            KeUnstackDetachProcess(&apc);
            goto write_done;
        }

        DbgPrint(DMMDZZ_DBG_TAG " WriteMemory: ZwProtectVirtualMemory failed 0x%08X, "
                 "checking page protection\n", status);
    }

    /* --- Method 2b: Direct RtlCopyMemory if page is already writable ---
     * ZwProtectVirtualMemory fails on SEC_IMAGE pages regardless of current
     * protection. However, if user-mode VirtualProtectEx was called before
     * the IOCTL, the page may already be writable. We query the protection
     * BEFORE writing to avoid a BSOD on non-writable pages (SEH doesn't
     * work in KDU-mapped drivers, so an unhandled page fault = BSOD). */
    {
        MEMORY_BASIC_INFORMATION mbi;
        SIZE_T returnLength = 0;

        status = ZwQueryVirtualMemory(
            (HANDLE)-1,            /* NtCurrentProcess() — we are attached */
            (PVOID)p->Address,
            MemoryBasicInformation,
            &mbi,
            sizeof(mbi),
            &returnLength
        );

        if (NT_SUCCESS(status) &&
            (mbi.Protect & (PAGE_READWRITE | PAGE_EXECUTE_READWRITE |
                            PAGE_WRITECOPY | PAGE_EXECUTE_WRITECOPY)))
        {
            DbgPrint(DMMDZZ_DBG_TAG " WriteMemory: page already writable "
                     "(Protect=0x%X), writing directly\n", mbi.Protect);
            RtlCopyMemory((PVOID)p->Address, buf, p->Size);
            done = p->Size;
            status = STATUS_SUCCESS;
            DbgPrint(DMMDZZ_DBG_TAG " WriteMemory: wrote %llu bytes via direct copy\n",
                     (ULONGLONG)done);
            KeUnstackDetachProcess(&apc);
            goto write_done;
        }

        DbgPrint(DMMDZZ_DBG_TAG " WriteMemory: page not writable "
                 "(Protect=0x%X status=0x%08X), trying PTE\n",
                 NT_SUCCESS(status) ? mbi.Protect : 0, status);
    }

    /* --- Method 3: Direct PTE manipulation (last resort) ---
     * On Windows 10 1607+ with KASLR, the PTE base is randomized.
     * The hardcoded 0xFFFFF68000000000 may be wrong, causing
     * MmIsAddressValid to return false for the PTE address. */
    {
        ULONG_PTR va = p->Address;
        const ULONG_PTR pteBase = 0xFFFFF68000000000ULL;
        ULONG_PTR pteAddr = pteBase + ((va >> 12) << 3);

        DbgPrint(DMMDZZ_DBG_TAG " WriteMemory: PTE addr=0x%llX (VA=0x%llX)\n",
                 (ULONGLONG)pteAddr, (ULONGLONG)va);

        if (MmIsAddressValid((PVOID)pteAddr)) {
            volatile ULONG_PTR* pte = (volatile ULONG_PTR*)pteAddr;
            ULONG_PTR oldPte = *pte;

            DbgPrint(DMMDZZ_DBG_TAG " WriteMemory: old PTE=0x%llX (R/W=%d Present=%d)\n",
                     (ULONGLONG)oldPte, (int)(oldPte & 0x2 ? 1 : 0),
                     (int)(oldPte & 0x1 ? 1 : 0));

            /* Set R/W bit (bit 1) to 1 to make the page writable */
            *pte = oldPte | 0x2;

            /* Flush TLB for this page */
            __invlpg((PVOID)va);

            /* Write the data */
            RtlCopyMemory((PVOID)va, buf, p->Size);
            done = p->Size;

            /* Restore original PTE */
            *pte = oldPte;

            /* Flush TLB again */
            __invlpg((PVOID)va);

            DbgPrint(DMMDZZ_DBG_TAG " WriteMemory: wrote %llu bytes via PTE modification\n",
                     (ULONGLONG)done);
            status = STATUS_SUCCESS;
        } else {
            DbgPrint(DMMDZZ_DBG_TAG " WriteMemory: PTE address 0x%llX invalid!\n",
                     (ULONGLONG)pteAddr);
            status = STATUS_ACCESS_VIOLATION;
        }
    }

    KeUnstackDetachProcess(&apc);

write_done:
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
 *   - User-memory access is guarded by MmIsAddressValid (via dmmdzz_IsRangeValid).
 *     __try/__except is NOT used because SEH tables are not registered in
 *     KDU-mapped drivers, causing KMODE_EXCEPTION_NOT_HANDLED BSODs.
 *   - Memory is copied into a kernel buffer before scanning, so invalid
 *     pages only skip the affected chunk, not the entire scan.
 * ------------------------------------------------------------------------- */
NTSTATUS dmmdzz_ScanMemory(PDMMDZZ_SCAN_REQUEST p, PVOID buf, ULONG bufLen)
{
    NTSTATUS   status      = STATUS_SUCCESS;
    PEPROCESS  target      = NULL;
    KAPC_STATE apc;
    PUCHAR     chunkBuf    = NULL;
    ULONG      resultCount = 0;

    DbgPrint(DMMDZZ_DBG_TAG " ScanMemory: buf=%p bufLen=%lu ValueSize=%llu ValueOff=%lu MaxResults=%lu ResultsOff=%lu\n",
             buf, bufLen, (ULONGLONG)p->ValueSize, p->ValueOffset,
             p->MaxResults, p->ResultsOffset);

    /* --- Validate parameters --- */
    if (p->ValueSize == 0 || p->ValueSize > DMMDZZ_SCAN_MAX_VALUE_SIZE) {
        DbgPrint(DMMDZZ_DBG_TAG " ScanMemory: bad ValueSize -> INVALID_PARAMETER\n");
        p->Hdr.Status = STATUS_INVALID_PARAMETER;
        p->Hdr.ExtendedStatus = 1;
        p->ResultsCount = 0;
        return STATUS_INVALID_PARAMETER;
    }

    /* Value bytes must be inside the buffer */
    if (p->ValueOffset + p->ValueSize > bufLen) {
        DbgPrint(DMMDZZ_DBG_TAG " ScanMemory: value exceeds bufLen -> INVALID_PARAMETER\n");
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
        DbgPrint(DMMDZZ_DBG_TAG " ScanMemory: MaxResults=0 -> INVALID_PARAMETER\n");
        p->Hdr.Status = STATUS_INVALID_PARAMETER;
        p->Hdr.ExtendedStatus = 1;
        p->ResultsCount = 0;
        return STATUS_INVALID_PARAMETER;
    }

    DbgPrint(DMMDZZ_DBG_TAG " ScanMemory: validation OK, MaxResults=%lu, starting scan...\n",
             p->MaxResults);

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

    /* NOTE: No __try/__except — SEH doesn't work in KDU-mapped drivers.
     * Page validity is checked per-chunk with MmIsAddressValid below. */
    {
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

            if (!NT_SUCCESS(status)) {
                /* ZwQueryVirtualMemory returns STATUS_INVALID_PARAMETER
                 * when we've reached the end of the address space.
                 * Treat this as "scan complete", not an error. */
                status = STATUS_SUCCESS;
                break;
            }

            /* Advance to next region regardless of whether we scan this one */
            PVOID nextAddr = (PUCHAR)mbi.BaseAddress + mbi.RegionSize;

            /* Safety: if RegionSize is 0 or nextAddr didn't advance,
             * break to prevent infinite loop */
            if (nextAddr <= addr || mbi.RegionSize == 0)
                break;

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

                    /* Copy chunk into kernel buffer safely. dmmdzz_SafeCopyUser
                     * uses ZwReadVirtualMemory to handle page faults internally
                     * (ntoskrnl SEH), avoiding KDU BSODs from TOCTOU races. */
                    if (!dmmdzz_SafeCopyUser(chunkBuf, regionBase + off, toCopy)) {
                        /* Invalid page in this chunk — skip it */
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

    KeUnstackDetachProcess(&apc);

    if (chunkBuf)
        ExFreePoolWithTag(chunkBuf, 'sZmm');
    ObDereferenceObject(target);

    p->ResultsCount   = resultCount;
    p->Hdr.Status     = status;
    p->Hdr.ExtendedStatus = NT_SUCCESS(status) ? 0 : 6;

    DbgPrint(DMMDZZ_DBG_TAG " ScanMemory: done. resultCount=%lu status=0x%08X\n",
             resultCount, status);
    return status;
}
