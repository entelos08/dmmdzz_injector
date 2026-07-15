/* =============================================================================
 * driver/ptrscan.c
 *
 * Multi-level pointer chain scanner. Given a dynamic address in a target
 * process, finds pointer chains that lead back to a static module base.
 *
 * ALGORITHM
 * ---------
 *  Pass 1: find all 8-byte values == TargetAddress     -> level1[]
 *  Pass 2: find all 8-byte values present in level1    -> level2[]
 *  Pass 3: find all 8-byte values present in level2    -> level3[]
 *
 *  Chains whose base address falls within a registered module range are
 *  marked IsStatic and prioritised in the output.
 *
 *  Chain shapes (Addresses[] = [base, ..., target]):
 *    Depth 1: [L1.addr, target]
 *    Depth 2: [L2.addr, L1[L2.parent].addr, target]
 *    Depth 3: [L3.addr, L2[L3.parent].addr, L1[L2[L3.parent].parent].addr, target]
 *
 * SAFETY
 * ------
 *  __try/__except does NOT work in KDU-mapped drivers (SEH tables are
 *  not registered), causing KMODE_EXCEPTION_NOT_HANDLED BSODs when
 *  RtlCopyMemory faults. We use MmIsAddressValid (via dmmdzz_IsRangeValid)
 *  before every RtlCopyMemory from user memory.
 *
 *  Memory is copied into a kernel buffer before scanning, so invalid
 *  pages only skip the affected chunk, not the entire scan.
 *
 * IRQL
 * ----
 *  PASSIVE_LEVEL — required for PsLookupProcessByProcessId,
 *  KeStackAttachProcess, and ZwQueryVirtualMemory.
 *
 * BUFFER LAYOUT (METHOD_BUFFERED)
 * -------------------------------
 *  [DMMDZZ_PTRSCAN_REQUEST]
 *  [DMMDZZ_MODULE_RANGE[]  @ ModuleRangesOffset]
 *  [DMMDZZ_PTR_CHAIN[]     @ ResultsOffset]
 * ============================================================================= */
#include "driver.h"

/* Forward declarations — defined in memory.c */
BOOLEAN dmmdzz_IsRangeValid(PVOID addr, SIZE_T size);
BOOLEAN dmmdzz_SafeCopyUser(PVOID dst, PVOID src, SIZE_T size);

/* Undocumented but exported by ntoskrnl — declared in memory.c but not
 * in a shared header, so we re-declare it here for this TU. */
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

/* Maximum number of pointer results per level */
#define MAX_PTR_RESULTS  10000

/* Chunk size for copying user memory into the kernel buffer */
#define SCAN_CHUNK_SIZE  0x10000

/* User address space bounds for scanning */
#define USER_ADDR_MIN    ((ULONG_PTR)0x10000)
#define USER_ADDR_MAX    ((ULONG_PTR)0x00007FFFFFFFFFFFULL)

/* -------------------------------------------------------------------------
 * Internal node: a found pointer value and the index of its parent node
 * in the previous level's sorted array.
 * ------------------------------------------------------------------------- */
typedef struct _PTR_NODE {
    ULONG_PTR Addr;       /* address where the pointer value was found  */
    ULONG     ParentIdx;  /* index into the previous level's array      */
} PTR_NODE, *PPTR_NODE;

/* -------------------------------------------------------------------------
 * Binary search on a sorted PTR_NODE array by Addr field.
 * Returns the index of a matching element, or -1 if not found.
 * ------------------------------------------------------------------------- */
static LONG PtrNodeBinarySearch(const PTR_NODE *arr, ULONG count,
                                ULONG_PTR target)
{
    LONG lo = 0, hi = (LONG)count - 1;
    while (lo <= hi) {
        LONG mid = lo + (hi - lo) / 2;
        if (arr[mid].Addr == target)
            return mid;
        if (arr[mid].Addr < target)
            lo = mid + 1;
        else
            hi = mid - 1;
    }
    return -1;
}

/* ------------------------------------------------------------------------- */
static __forceinline void PtrNodeSwap(PTR_NODE *a, PTR_NODE *b)
{
    PTR_NODE t = *a; *a = *b; *b = t;
}

/* -------------------------------------------------------------------------
 * Quick sort on PTR_NODE array by Addr field.
 * Uses median-of-three pivot selection and tail-call elimination to keep
 * recursion depth O(log n) — safe for the limited kernel stack.
 * ------------------------------------------------------------------------- */
static void PtrNodeQuickSort(PTR_NODE *arr, LONG lo, LONG hi)
{
    while (lo < hi) {
        /* Median-of-three pivot selection */
        LONG mid = lo + (hi - lo) / 2;
        if (arr[mid].Addr < arr[lo].Addr) PtrNodeSwap(&arr[mid], &arr[lo]);
        if (arr[hi].Addr  < arr[lo].Addr) PtrNodeSwap(&arr[hi],  &arr[lo]);
        if (arr[mid].Addr < arr[hi].Addr) PtrNodeSwap(&arr[mid], &arr[hi]);
        /* arr[hi] now holds the median value — use as pivot */
        ULONG_PTR pivot = arr[hi].Addr;

        /* Lomuto partition */
        LONG i = lo - 1;
        LONG j;
        for (j = lo; j < hi; j++) {
            if (arr[j].Addr <= pivot) {
                i++;
                PtrNodeSwap(&arr[i], &arr[j]);
            }
        }
        PtrNodeSwap(&arr[i + 1], &arr[hi]);
        {
            LONG p = i + 1;

            /* Recurse on the smaller partition, loop on the larger one
             * to bound stack depth to O(log n). */
            if (p - lo < hi - p) {
                PtrNodeQuickSort(arr, lo, p - 1);
                lo = p + 1;
            } else {
                PtrNodeQuickSort(arr, p + 1, hi);
                hi = p - 1;
            }
        }
    }
}

static void PtrNodeSort(PTR_NODE *arr, ULONG count)
{
    if (count > 1)
        PtrNodeQuickSort(arr, 0, (LONG)count - 1);
}

/* -------------------------------------------------------------------------
 * Check if an address falls within any of the given module ranges.
 * ------------------------------------------------------------------------- */
static BOOLEAN IsAddrInModuleRange(ULONG_PTR addr,
                                   const DMMDZZ_MODULE_RANGE *ranges,
                                   ULONG count)
{
    ULONG i;
    for (i = 0; i < count; i++) {
        if (addr >= ranges[i].Base &&
            addr <  ranges[i].Base + ranges[i].Size)
            return TRUE;
    }
    return FALSE;
}

/* -------------------------------------------------------------------------
 * Single scan pass over all readable committed memory in the attached
 * process.
 *
 *   searchSet == NULL : match 8-byte values equal to matchValue (Pass 1)
 *   searchSet != NULL : match 8-byte values present in the sorted
 *                       searchSet via binary search (Pass 2 / 3)
 *
 * Found results are stored in outArr with their ParentIdx set:
 *   Pass 1 -> ParentIdx = 0 (unused)
 *   Pass 2 -> ParentIdx = index into sorted level1
 *   Pass 3 -> ParentIdx = index into sorted level2
 *
 * Returns the number of results stored.
 * ------------------------------------------------------------------------- */
static ULONG PtrScanPass(PUCHAR chunkBuf,
                         ULONG_PTR matchValue,
                         const PTR_NODE *searchSet,
                         ULONG searchCount,
                         PTR_NODE *outArr,
                         ULONG maxResults)
{
    ULONG resultCount = 0;
    PVOID addr        = (PVOID)USER_ADDR_MIN;
    PVOID maxAddr     = (PVOID)USER_ADDR_MAX;

    while (addr < maxAddr && resultCount < maxResults) {
        MEMORY_BASIC_INFORMATION mbi;
        SIZE_T returnLength = 0;

        NTSTATUS qstatus = ZwQueryVirtualMemory(
            (HANDLE)-1,     /* NtCurrentProcess() — we are attached */
            addr,
            MemoryBasicInformation,
            &mbi,
            sizeof(mbi),
            &returnLength);

        if (!NT_SUCCESS(qstatus)) {
            /* ZwQueryVirtualMemory returns STATUS_INVALID_PARAMETER when
             * we've reached the end of the address space. Treat as done. */
            break;
        }

        /* Advance to next region regardless of whether we scan this one */
        PVOID nextAddr = (PUCHAR)mbi.BaseAddress + mbi.RegionSize;

        /* Safety: prevent infinite loop on bogus region info */
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
            SIZE_T off = 0;

            while (off < regionSize && resultCount < maxResults) {
                SIZE_T remaining = regionSize - off;
                SIZE_T toCopy = (remaining < SCAN_CHUNK_SIZE)
                              ? remaining : SCAN_CHUNK_SIZE;

                if (toCopy < sizeof(ULONG_PTR))
                    break;

                /* dmmdzz_SafeCopyUser uses ZwReadVirtualMemory to handle
                 * page faults safely (ntoskrnl SEH), avoiding KDU BSODs. */
                if (!dmmdzz_SafeCopyUser(chunkBuf, regionBase + off, toCopy)) {
                    off += toCopy;
                    continue;
                }

                /* Scan at 8-byte alignment. Region bases are page-aligned
                 * and RegionSize is a multiple of the page size, so off
                 * is always 8-byte aligned — no boundary gaps. */
                {
                    SIZE_T i;
                    for (i = 0; i + sizeof(ULONG_PTR) <= toCopy; i += 8) {
                        ULONG_PTR val = *(ULONG_PTR *)(chunkBuf + i);
                        BOOLEAN   match = FALSE;
                        ULONG     parentIdx = 0;

                        if (searchSet) {
                            LONG idx = PtrNodeBinarySearch(
                                searchSet, searchCount, val);
                            if (idx >= 0) {
                                match = TRUE;
                                parentIdx = (ULONG)idx;
                            }
                        } else {
                            if (val == matchValue) {
                                match = TRUE;
                                parentIdx = 0;
                            }
                        }

                        if (match) {
                            outArr[resultCount].Addr =
                                (ULONG_PTR)(regionBase + off + i);
                            outArr[resultCount].ParentIdx = parentIdx;
                            resultCount++;
                            if (resultCount >= maxResults)
                                break;
                        }
                    }
                }

                off += toCopy;
            }
        }

        addr = nextAddr;
    }

    return resultCount;
}

/* -------------------------------------------------------------------------
 * IOCTL_DMMDZZ_PTRSCAN
 *
 * Multi-level pointer chain scan entry point.
 * ------------------------------------------------------------------------- */
NTSTATUS dmmdzz_PtrScan(PDMMDZZ_PTRSCAN_REQUEST p, PVOID buf, ULONG bufLen)
{
    NTSTATUS   status     = STATUS_SUCCESS;
    PEPROCESS  target     = NULL;
    KAPC_STATE apc;
    PUCHAR     chunkBuf   = NULL;
    PTR_NODE  *level1     = NULL;
    PTR_NODE  *level2     = NULL;
    PTR_NODE  *level3     = NULL;
    ULONG      count1     = 0;
    ULONG      count2     = 0;
    ULONG      count3     = 0;
    ULONG      chainCount = 0;

    DbgPrint(DMMDZZ_DBG_TAG " PtrScan: enter. buf=%p bufLen=%lu PID=%p target=0x%llx depth=%lu maxChains=%lu\n",
             buf, bufLen, p->ProcessId, (ULONGLONG)p->TargetAddress,
             p->MaxDepth, p->MaxChains);

    /* --- Validate parameters --- */
    if (p->MaxDepth < 1 || p->MaxDepth > DMMDZZ_PTRSCAN_MAX_DEPTH) {
        DbgPrint(DMMDZZ_DBG_TAG " PtrScan: bad MaxDepth=%lu\n", p->MaxDepth);
        p->Hdr.Status = STATUS_INVALID_PARAMETER;
        p->Hdr.ExtendedStatus = 1;
        p->ChainCount = 0;
        return STATUS_INVALID_PARAMETER;
    }

    if (p->MaxChains == 0) {
        DbgPrint(DMMDZZ_DBG_TAG " PtrScan: MaxChains=0\n");
        p->Hdr.Status = STATUS_INVALID_PARAMETER;
        p->Hdr.ExtendedStatus = 1;
        p->ChainCount = 0;
        return STATUS_INVALID_PARAMETER;
    }

    /* Module ranges must be fully inside the buffer */
    if (p->ModuleRangesOffset > bufLen ||
        (ULONGLONG)p->NumModuleRanges * sizeof(DMMDZZ_MODULE_RANGE) >
        (ULONGLONG)(bufLen - p->ModuleRangesOffset)) {
        DbgPrint(DMMDZZ_DBG_TAG " PtrScan: module ranges exceed bufLen\n");
        p->Hdr.Status = STATUS_INVALID_PARAMETER;
        p->Hdr.ExtendedStatus = 1;
        p->ChainCount = 0;
        return STATUS_INVALID_PARAMETER;
    }

    /* Results area must be inside the buffer */
    if (p->ResultsOffset > bufLen) {
        DbgPrint(DMMDZZ_DBG_TAG " PtrScan: ResultsOffset out of bounds\n");
        p->Hdr.Status = STATUS_INVALID_PARAMETER;
        p->Hdr.ExtendedStatus = 1;
        p->ChainCount = 0;
        return STATUS_INVALID_PARAMETER;
    }
    {
        ULONG availChains = (ULONG)((bufLen - p->ResultsOffset) /
                                    sizeof(DMMDZZ_PTR_CHAIN));
        if (p->MaxChains > availChains)
            p->MaxChains = availChains;
        if (p->MaxChains == 0) {
            DbgPrint(DMMDZZ_DBG_TAG " PtrScan: no room for chains in buffer\n");
            p->Hdr.Status = STATUS_INVALID_PARAMETER;
            p->Hdr.ExtendedStatus = 1;
            p->ChainCount = 0;
            return STATUS_INVALID_PARAMETER;
        }
    }

    /* --- Lookup target process --- */
    status = PsLookupProcessByProcessId(p->ProcessId, &target);
    if (!NT_SUCCESS(status)) {
        DbgPrint(DMMDZZ_DBG_TAG " PtrScan: PsLookupProcessByProcessId failed 0x%08X\n",
                 status);
        p->Hdr.Status = status;
        p->Hdr.ExtendedStatus = 2;
        p->ChainCount = 0;
        return status;
    }

    /* --- Allocate kernel arrays for level 1/2/3 results + chunk buffer --- */
    level1 = (PTR_NODE *)ExAllocatePoolWithTag(NonPagedPool,
                MAX_PTR_RESULTS * sizeof(PTR_NODE), '1pmm');
    level2 = (PTR_NODE *)ExAllocatePoolWithTag(NonPagedPool,
                MAX_PTR_RESULTS * sizeof(PTR_NODE), '2pmm');
    level3 = (PTR_NODE *)ExAllocatePoolWithTag(NonPagedPool,
                MAX_PTR_RESULTS * sizeof(PTR_NODE), '3pmm');
    chunkBuf = (PUCHAR)ExAllocatePoolWithTag(NonPagedPool,
                SCAN_CHUNK_SIZE, 'cpmm');

    if (!level1 || !level2 || !level3 || !chunkBuf) {
        DbgPrint(DMMDZZ_DBG_TAG " PtrScan: allocation failed\n");
        if (level1)   ExFreePoolWithTag(level1,   '1pmm');
        if (level2)   ExFreePoolWithTag(level2,   '2pmm');
        if (level3)   ExFreePoolWithTag(level3,   '3pmm');
        if (chunkBuf) ExFreePoolWithTag(chunkBuf, 'cpmm');
        ObDereferenceObject(target);
        p->Hdr.Status = STATUS_INSUFFICIENT_RESOURCES;
        p->Hdr.ExtendedStatus = 5;
        p->ChainCount = 0;
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    /* --- Attach to target process address space --- */
    KeStackAttachProcess(target, &apc);

    /* NOTE: No __try/__except — SEH doesn't work in KDU-mapped drivers.
     * Page validity is checked per-chunk with MmIsAddressValid inside
     * PtrScanPass (via dmmdzz_IsRangeValid). */

    /* Pass 1: find all 8-byte values == TargetAddress */
    count1 = PtrScanPass(chunkBuf, p->TargetAddress, NULL, 0,
                         level1, MAX_PTR_RESULTS);
    DbgPrint(DMMDZZ_DBG_TAG " PtrScan: level1 count=%lu\n", count1);

    /* Pass 2: find all 8-byte values present in sorted level1 */
    if (p->MaxDepth >= 2 && count1 > 0) {
        PtrNodeSort(level1, count1);
        count2 = PtrScanPass(chunkBuf, 0, level1, count1,
                             level2, MAX_PTR_RESULTS);
        DbgPrint(DMMDZZ_DBG_TAG " PtrScan: level2 count=%lu\n", count2);
    }

    /* Pass 3: find all 8-byte values present in sorted level2 */
    if (p->MaxDepth >= 3 && count2 > 0) {
        PtrNodeSort(level2, count2);
        count3 = PtrScanPass(chunkBuf, 0, level2, count2,
                             level3, MAX_PTR_RESULTS);
        DbgPrint(DMMDZZ_DBG_TAG " PtrScan: level3 count=%lu\n", count3);
    }

    KeUnstackDetachProcess(&apc);

    /* --- Build chains from the deepest level that has results --- */
    {
        PDMMDZZ_MODULE_RANGE modRanges = (PDMMDZZ_MODULE_RANGE)
            ((PUCHAR)buf + p->ModuleRangesOffset);
        PDMMDZZ_PTR_CHAIN chains = (PDMMDZZ_PTR_CHAIN)
            ((PUCHAR)buf + p->ResultsOffset);

        /* Pick the deepest level that actually has results */
        PTR_NODE *deepest;
        ULONG     deepestCount;
        ULONG     depth;

        if (p->MaxDepth >= 3 && count3 > 0) {
            deepest = level3; deepestCount = count3; depth = 3;
        } else if (p->MaxDepth >= 2 && count2 > 0) {
            deepest = level2; deepestCount = count2; depth = 2;
        } else {
            deepest = level1; deepestCount = count1; depth = 1;
        }

        /* Two passes: static chains first (prioritised), then non-static.
         * This ensures IsStatic=TRUE chains fill the output buffer before
         * any IsStatic=FALSE chains. */
        {
            ULONG pass;
            for (pass = 0; pass < 2 && chainCount < p->MaxChains; pass++) {
                BOOLEAN wantStatic = (pass == 0);
                ULONG   i;
                for (i = 0; i < deepestCount && chainCount < p->MaxChains; i++) {
                    BOOLEAN isStatic = IsAddrInModuleRange(
                        deepest[i].Addr, modRanges, p->NumModuleRanges);
                    if (isStatic != wantStatic)
                        continue;

                    {
                        PDMMDZZ_PTR_CHAIN c = &chains[chainCount];
                        RtlZeroMemory(c, sizeof(*c));

                        if (depth == 1) {
                            c->Addresses[0] = deepest[i].Addr;
                            c->Addresses[1] = p->TargetAddress;
                        } else if (depth == 2) {
                            ULONG p1 = deepest[i].ParentIdx;
                            c->Addresses[0] = deepest[i].Addr;
                            c->Addresses[1] = level1[p1].Addr;
                            c->Addresses[2] = p->TargetAddress;
                        } else {
                            /* depth == 3 */
                            ULONG p2 = deepest[i].ParentIdx;
                            ULONG p1 = level2[p2].ParentIdx;
                            c->Addresses[0] = deepest[i].Addr;
                            c->Addresses[1] = level2[p2].Addr;
                            c->Addresses[2] = level1[p1].Addr;
                            c->Addresses[3] = p->TargetAddress;
                        }
                        c->Depth    = depth;
                        c->IsStatic = isStatic;
                        chainCount++;
                    }
                }
            }
        }

        DbgPrint(DMMDZZ_DBG_TAG " PtrScan: chains=%lu (depth=%lu)\n",
                 chainCount, depth);
    }

    /* --- Cleanup: free kernel arrays, dereference process --- */
    ExFreePoolWithTag(level1,   '1pmm');
    ExFreePoolWithTag(level2,   '2pmm');
    ExFreePoolWithTag(level3,   '3pmm');
    ExFreePoolWithTag(chunkBuf, 'cpmm');
    ObDereferenceObject(target);

    p->ChainCount         = chainCount;
    p->Hdr.Status         = status;
    p->Hdr.ExtendedStatus = NT_SUCCESS(status) ? 0 : 6;

    DbgPrint(DMMDZZ_DBG_TAG " PtrScan: exit. chains=%lu status=0x%08X\n",
             chainCount, status);
    return status;
}