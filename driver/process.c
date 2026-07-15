/* =============================================================================
 * driver/process.c
 *
 * Process & module lookups used by the IOCTL handlers.
 *
 * EDUCATIONAL NOTES
 * -----------------
 *  * PsLookupProcessByProcessId returns a referenced EPROCESS pointer. You
 *    MUST ObDereferenceObject() it or you leak a kernel reference (memory
 *    leak + the process cannot exit).
 *  * KeStackAttachProcess / KeUnstackDetachProcess switch the address space
 *    so that the VA you read/write refers to the target process. This must
 *    be done at PASSIVE_LEVEL and is NOT valid at DISPATCH_LEVEL.
 *  * Walking the PEB->Ldr lists (InLoadOrderModuleList) gives every loaded
 *    module. We must be inside the target's address space to read those VAs.
 *  * In real code, you would also probe user addresses with
 *    ProbeForRead/ProbeForWrite. We are reading kernel-trusted PEB fields
 *    here, so probing is not strictly required, but a robust driver would
 *    wrap user-buffer touches in a __try/__except.
 * ============================================================================= */
#include "driver.h"

/* -------------------------------------------------------------------------
 * Undocumented but stable kernel exports (present since Windows 7).
 * These are NOT declared in ntddk.h / ntifs.h but are exported by
 * ntoskrnl.lib. We declare them here so the compiler knows the correct
 * signatures (instead of defaulting to "int func()" which triggers C4013).
 * ------------------------------------------------------------------------- */
PUCHAR NTAPI PsGetProcessImageFileName(PEPROCESS Process);
PPEB   NTAPI PsGetProcessPeb(PEPROCESS Process);
PVOID  NTAPI PsGetProcessWow64Process(PEPROCESS Process);  /* returns PEB32 or NULL */

/* Undocumented but stable since Windows 7 - needed for PEB->Ldr walking.
 * In a WDK build you can #include <ntddk.h> only; the PEB/LDR structures
 * are partially declared in ntifs.h. For learning we declare what we use. */
typedef struct _LDR_DATA_TABLE_ENTRY {
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    LIST_ENTRY InInitializationOrderLinks;
    PVOID      DllBase;
    PVOID      EntryPoint;
    ULONG      SizeOfImage;
    USHORT     FullDllNameLength;     /* not used here */
    PWSTR      FullDllName;            /* not used here */
    USHORT     BaseDllNameLength;
    PWSTR      BaseDllName;
} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;

typedef struct _PEB_LDR_DATA {
    ULONG      Length;
    BOOLEAN    Initialized;
    PVOID      SsHandle;
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
} PEB_LDR_DATA, *PPEB_LDR_DATA;

typedef struct _PEB {
    BOOLEAN InheritedAddressSpace;
    BOOLEAN ReadImageFileExecOptions;
    BOOLEAN BeingDebugged;
    BOOLEAN BitField;
    PVOID  Mutant;
    PVOID  ImageBaseAddress;
    PPEB_LDR_DATA Ldr;
    /* ... we only need up to Ldr */
} PEB, *PPEB;

/* -------------------------------------------------------------------------
 * WOW64 (32-bit) PEB / LDR structures.
 *
 * WOW64 processes have TWO PEBs:
 *   - PEB64 (returned by PsGetProcessPeb): holds 64-bit modules (wow64*.dll,
 *     64-bit ntdll). This is what we walked before — it does NOT contain
 *     GameAssembly.dll for a 32-bit IL2CPP game.
 *   - PEB32 (returned by PsGetProcessWow64Process): holds the 32-bit modules
 *     of the actual application (dmmdzz.exe, 32-bit ntdll, GameAssembly.dll,
 *     UnityPlayer.dll, etc.). All pointers are 32-bit ULONGs.
 *
 * To find GameAssembly.dll in a 32-bit Unity IL2CPP game, we must walk PEB32.
 * We zero-extend 32-bit pointers to 64-bit for dmmdzz_SafeCopyUser calls.
 * ------------------------------------------------------------------------- */
/* NOTE: LIST_ENTRY32 is already defined in ntdef.h (shipped with WDK).
 * We reuse it rather than redefining. */

typedef struct _PEB32_LDR_DATA {
    ULONG         Length;                /* 0x00 */
    UCHAR         Initialized;           /* 0x04 */
    ULONG         SsHandle;              /* 0x08 */
    LIST_ENTRY32  InLoadOrderModuleList; /* 0x0C */
} PEB32_LDR_DATA, *PPEB32_LDR_DATA;

typedef struct _LDR_DATA_TABLE_ENTRY32 {
    LIST_ENTRY32  InLoadOrderLinks;           /* 0x00 */
    LIST_ENTRY32  InMemoryOrderLinks;         /* 0x08 */
    LIST_ENTRY32  InInitializationOrderLinks; /* 0x10 */
    ULONG         DllBase;                    /* 0x18 */
    ULONG         EntryPoint;                 /* 0x1C */
    ULONG         SizeOfImage;                /* 0x20 */
    USHORT        FullDllNameLength;          /* 0x24 */
    ULONG         FullDllName;                /* 0x28 */
    USHORT        BaseDllNameLength;          /* 0x2C */
    ULONG         BaseDllName;                /* 0x30 */
} LDR_DATA_TABLE_ENTRY32, *PLDR_DATA_TABLE_ENTRY32;

typedef struct _PEB32 {
    UCHAR  InheritedAddressSpace;    /* 0x00 */
    UCHAR  ReadImageFileExecOptions; /* 0x01 */
    UCHAR  BeingDebugged;            /* 0x02 */
    UCHAR  BitField;                 /* 0x03 */
    ULONG  Mutant;                   /* 0x04 */
    ULONG  ImageBaseAddress;         /* 0x08 */
    ULONG  Ldr;                      /* 0x0C — pointer to PEB32_LDR_DATA */
} PEB32, *PPEB32;

/* PsGetProcessId is exported by ntoskrnl; PsGetCurrentProcess is a macro. */
extern POBJECT_TYPE *PsProcessType;

/* Forward declarations of safe user-memory accessors defined in memory.c.
 * These replace __try/__except (which does NOT work in KDU-mapped drivers
 * because SEH tables are not registered). See memory.c for details. */
BOOLEAN dmmdzz_IsRangeValid(PVOID addr, SIZE_T size);
BOOLEAN dmmdzz_SafeCopyUser(PVOID dst, PVOID src, SIZE_T size);

/* -------------------------------------------------------------------------
 * Convert a WCHAR (NUL-terminated) image name to lower-case in-place for
 * case-insensitive comparison. Image names in the loader list are mixed-case.
 * ------------------------------------------------------------------------- */
static void dmmdzz_ToLowerW(WCHAR *s)
{
    for (; *s; ++s) {
        if (*s >= L'A' && *s <= L'Z') *s = (WCHAR)(*s - L'A' + L'a');
    }
}

static BOOLEAN dmmdzz_EndsWithW(const WCHAR *hay, SIZE_T hayLen,
                                const WCHAR *needle, SIZE_T needleLen)
{
    if (needleLen > hayLen) return FALSE;
    const WCHAR *p = hay + (hayLen - needleLen);
    for (SIZE_T i = 0; i < needleLen; ++i)
        if (p[i] != needle[i]) return FALSE;
    return TRUE;
}

/* -------------------------------------------------------------------------
 * IOCTL_DMMDZZ_FIND_PROCESS
 *
 * Walk the active process list (via PsLookupProcessByProcessId enumeration
 * is impractical, so we use the system-process's active list head obtained
 * from PsInitialSystemProcess). For each EPROCESS we read ImageFileName
 * (a 15-byte ASCII field that holds the image base name truncated).
 *
 * A simpler and more robust educational approach is to iterate PID 4..65535
 * with PsLookupProcessByProcessId. We do that here.
 * ------------------------------------------------------------------------- */
NTSTATUS dmmdzz_FindProcess(PDMMDZZ_FIND_PROCESS p)
{
    NTSTATUS   status;
    PEPROCESS  proc = NULL;
    UCHAR      image[16] = {0};
    WCHAR      wImage[16] = {0};
    WCHAR      targetLower[DMMDZZ_NAME_MAX];

    /* Copy and lowercase the requested name */
    RtlZeroMemory(targetLower, sizeof(targetLower));
    ULONG n = 0;
    for (; n < DMMDZZ_NAME_MAX - 1 && p->ProcessName[n]; ++n)
        targetLower[n] = p->ProcessName[n];
    targetLower[n] = L'\0';
    dmmdzz_ToLowerW(targetLower);

    for (ULONG pid = 4; pid <= 0xFFFF; ++pid) {
        status = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)pid, &proc);
        if (!NT_SUCCESS(status)) continue;

        /* PsGetProcessImageFileName returns an ASCII name (max 15 chars) */
        PUCHAR name = PsGetProcessImageFileName(proc);
        if (name) {
            SIZE_T i = 0;
            for (; i < sizeof(image) - 1 && name[i]; ++i) {
                image[i] = name[i];
                if (image[i] >= 'A' && image[i] <= 'Z')
                    image[i] = (UCHAR)(image[i] - 'A' + 'a');
                wImage[i] = (WCHAR)image[i];
            }
            wImage[i] = L'\0';

            /* Compare as wide strings; allow either full match or
             * suffix match (e.g. user passes "target.exe"). */
            SIZE_T hayLen  = i;
            SIZE_T needLen = n;
            BOOLEAN match = (hayLen == needLen) &&
                            dmmdzz_EndsWithW(wImage, hayLen, targetLower, needLen);

            if (match) {
                p->ProcessId  = (HANDLE)(ULONG_PTR)pid;
                p->EProcessVA = (ULONG_PTR)proc;
                p->Hdr.Status = STATUS_SUCCESS;
                p->Hdr.ExtendedStatus = 0;
                ObDereferenceObject(proc);
                return STATUS_SUCCESS;
            }
        }
        ObDereferenceObject(proc);
        proc = NULL;
    }

    p->Hdr.Status = STATUS_NOT_FOUND;
    p->Hdr.ExtendedStatus = 0;
    p->ProcessId  = NULL;
    p->EProcessVA = 0;
    return STATUS_NOT_FOUND;
}

/* -------------------------------------------------------------------------
 * Helper: attach to target's address space and walk PEB->Ldr list to find a
 * module by base name. If ModuleName[0]==0 returns the main image (.exe).
 *
 * This is the 64-bit PEB walker for native x64 processes.
 * ------------------------------------------------------------------------- */
static NTSTATUS dmmdzz_WalkLdr64(HANDLE Pid,
                                 const WCHAR *ModuleName,
                                 ULONG ModuleNameLen,
                                 PULONG_PTR OutBase,
                                 PULONG      OutSize)
{
    NTSTATUS       status;
    PEPROCESS      proc = NULL;
    KAPC_STATE     apc;
    PPEB           peb = NULL;
    PPEB_LDR_DATA  ldr = NULL;
    LIST_ENTRY    *head, *cur;
    PLDR_DATA_TABLE_ENTRY entry = NULL;

    /* Kernel-stack copies of user-mode structures. We never dereference
     * user pointers directly — everything is copied via dmmdzz_SafeCopyUser. */
    PEB                 pebCopy;
    PEB_LDR_DATA        ldrCopy;
    LDR_DATA_TABLE_ENTRY entryCopy;

    status = PsLookupProcessByProcessId(Pid, &proc);
    if (!NT_SUCCESS(status)) return status;

    /* PsGetProcessPeb is exported since Vista. Returns user-mode VA of PEB. */
    peb = (PPEB)PsGetProcessPeb(proc);
    if (!peb) { status = STATUS_ACCESS_DENIED; goto out; }

    KeStackAttachProcess(proc, &apc);

    /* NOTE: No __try/__except — SEH tables are NOT registered in KDU-mapped
     * drivers, so any page fault here would cause KMODE_EXCEPTION_NOT_HANDLED
     * BSOD. We use dmmdzz_SafeCopyUser (ZwReadVirtualMemory) to safely read
     * user-mode PEB / LDR / entry structures into kernel stack copies.
     * ZwReadVirtualMemory handles page faults internally via ntoskrnl's
     * properly-registered SEH tables. */

    /* 1. Copy PEB into kernel stack */
    if (!dmmdzz_SafeCopyUser(&pebCopy, peb, sizeof(pebCopy))) {
        status = STATUS_ACCESS_DENIED;
        goto detach;
    }
    ldr = pebCopy.Ldr;
    if (!ldr) { status = STATUS_ACCESS_DENIED; goto detach; }

    /* 2. Copy PEB_LDR_DATA into kernel stack */
    if (!dmmdzz_SafeCopyUser(&ldrCopy, ldr, sizeof(ldrCopy))) {
        status = STATUS_ACCESS_DENIED;
        goto detach;
    }
    /* IMPORTANT: head must be the USER-MODE address of InLoadOrderModuleList
     * (not &ldrCopy.InLoadOrderModuleList which is a kernel stack address),
     * because the list's Flink/Blink pointers are user-mode VAs. Comparing
     * cur (user VA) against a kernel stack address would never match,
     * causing an infinite loop. */
    head = (LIST_ENTRY *)((PUCHAR)ldr + FIELD_OFFSET(PEB_LDR_DATA, InLoadOrderModuleList));
    cur  = ldrCopy.InLoadOrderModuleList.Flink;

    /* Safety: malformed list head */
    if (!cur) { status = STATUS_ACCESS_DENIED; goto detach; }

    while (cur != head) {
        entry = CONTAINING_RECORD(cur, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);

        /* 3. Copy LDR_DATA_TABLE_ENTRY into kernel stack. If unreadable,
         *    we cannot advance (Flink is inside the same struct), so stop. */
        if (!dmmdzz_SafeCopyUser(&entryCopy, entry, sizeof(entryCopy))) {
            break;
        }

        if (ModuleNameLen == 0) {
            /* First entry is the main image */
            *OutBase = (ULONG_PTR)entryCopy.DllBase;
            *OutSize = entryCopy.SizeOfImage;
            status = STATUS_SUCCESS;
            goto detach;
        }

        /* Compare base name (case-insensitive). The user passed a
         * wide string; we lowercase both sides in-place copies. */
        if (entryCopy.BaseDllName && entryCopy.BaseDllNameLength) {
            USHORT  cch   = entryCopy.BaseDllNameLength / sizeof(WCHAR);
            WCHAR   tmp[DMMDZZ_NAME_MAX];
            if (cch >= DMMDZZ_NAME_MAX) cch = DMMDZZ_NAME_MAX - 1;

            if (dmmdzz_SafeCopyUser(tmp, entryCopy.BaseDllName,
                                    cch * sizeof(WCHAR))) {
                tmp[cch] = L'\0';
                dmmdzz_ToLowerW(tmp);

                /* Suffix match lets the user pass just "ntdll.dll" etc. */
                if (dmmdzz_EndsWithW(tmp, cch, ModuleName, ModuleNameLen)) {
                    *OutBase = (ULONG_PTR)entryCopy.DllBase;
                    *OutSize = entryCopy.SizeOfImage;
                    status = STATUS_SUCCESS;
                    goto detach;
                }
            }
        }
        cur = entryCopy.InLoadOrderLinks.Flink;
    }
    status = STATUS_NOT_FOUND;

detach:
    KeUnstackDetachProcess(&apc);

out:
    if (proc) ObDereferenceObject(proc);
    return status;
}

/* -------------------------------------------------------------------------
 * 32-bit PEB walker for WOW64 processes.
 *
 * WOW64 processes have a PEB32 (returned by PsGetProcessWow64Process) whose
 * Ldr field is a 32-bit pointer to a PEB32_LDR_DATA. All list-entry pointers
 * inside are 32-bit ULONGs. We zero-extend each to 64-bit before passing to
 * dmmdzz_SafeCopyUser.
 *
 * Layout reminder (32-bit):
 *   PEB32.Ldr                         @ offset 0x0C (ULONG)
 *   PEB32_LDR_DATA.InLoadOrderModuleList @ offset 0x0C (LIST_ENTRY32)
 *   LDR_DATA_TABLE_ENTRY32.InLoadOrderLinks @ offset 0x00
 *     -> entry VA == cur (no CONTAINING_RECORD offset needed)
 *   LDR_DATA_TABLE_ENTRY32.DllBase      @ offset 0x18 (ULONG)
 *   LDR_DATA_TABLE_ENTRY32.SizeOfImage  @ offset 0x20 (ULONG)
 *   LDR_DATA_TABLE_ENTRY32.BaseDllName  @ offset 0x30 (ULONG pointer to WCHAR)
 *   LDR_DATA_TABLE_ENTRY32.BaseDllNameLength @ offset 0x2C (USHORT, bytes)
 * ------------------------------------------------------------------------- */
static NTSTATUS dmmdzz_WalkLdr32(HANDLE Pid,
                                 const WCHAR *ModuleName,
                                 ULONG ModuleNameLen,
                                 PULONG_PTR OutBase,
                                 PULONG      OutSize)
{
    NTSTATUS       status;
    PEPROCESS      proc = NULL;
    KAPC_STATE     apc;
    ULONG          peb32Addr = 0;       /* 32-bit PEB VA */
    ULONG          ldr32Addr = 0;       /* 32-bit PEB_LDR_DATA VA */
    ULONG          head32    = 0;       /* 32-bit &InLoadOrderModuleList */
    ULONG          cur32     = 0;       /* current Flink (32-bit) */

    /* Kernel-stack copies of 32-bit user-mode structures. */
    PEB32                 peb32Copy;
    PEB32_LDR_DATA        ldr32Copy;
    LDR_DATA_TABLE_ENTRY32 entry32Copy;

    status = PsLookupProcessByProcessId(Pid, &proc);
    if (!NT_SUCCESS(status)) return status;

    /* PsGetProcessWow64Process returns PEB32 (32-bit VA) for WOW64 procs,
     * NULL for native 64-bit procs. The returned pointer is a user-mode VA
     * but stored as 64-bit PVOID — the high 32 bits are zero. */
    PVOID wow64 = PsGetProcessWow64Process(proc);
    if (!wow64) { status = STATUS_ACCESS_DENIED; goto out; }
    peb32Addr = (ULONG)(ULONG_PTR)wow64;

    KeStackAttachProcess(proc, &apc);

    /* 1. Copy PEB32 into kernel stack (zero-extend 32-bit VA to 64-bit) */
    if (!dmmdzz_SafeCopyUser(&peb32Copy,
                             (PVOID)(ULONG_PTR)peb32Addr,
                             sizeof(peb32Copy))) {
        status = STATUS_ACCESS_DENIED;
        goto detach;
    }
    ldr32Addr = peb32Copy.Ldr;
    if (!ldr32Addr) { status = STATUS_ACCESS_DENIED; goto detach; }

    /* 2. Copy PEB32_LDR_DATA into kernel stack */
    if (!dmmdzz_SafeCopyUser(&ldr32Copy,
                             (PVOID)(ULONG_PTR)ldr32Addr,
                             sizeof(ldr32Copy))) {
        status = STATUS_ACCESS_DENIED;
        goto detach;
    }
    /* head = user-mode 32-bit address of InLoadOrderModuleList.
     * In PEB32_LDR_DATA, InLoadOrderModuleList is at offset 0x0C. */
    head32 = ldr32Addr + FIELD_OFFSET(PEB32_LDR_DATA, InLoadOrderModuleList);
    cur32  = ldr32Copy.InLoadOrderModuleList.Flink;

    if (!cur32) { status = STATUS_ACCESS_DENIED; goto detach; }

    while (cur32 != head32) {
        /* In LDR_DATA_TABLE_ENTRY32, InLoadOrderLinks is at offset 0x00,
         * so the entry VA == cur (no CONTAINING_RECORD adjustment). */
        ULONG entry32 = cur32;

        RtlZeroMemory(&entry32Copy, sizeof(entry32Copy));
        if (!dmmdzz_SafeCopyUser(&entry32Copy,
                                 (PVOID)(ULONG_PTR)entry32,
                                 sizeof(entry32Copy))) {
            break;
        }

        if (ModuleNameLen == 0) {
            /* First entry is the main image */
            *OutBase = (ULONG_PTR)entry32Copy.DllBase;
            *OutSize = entry32Copy.SizeOfImage;
            status = STATUS_SUCCESS;
            goto detach;
        }

        /* Compare base name (case-insensitive). BaseDllName is a 32-bit
         * pointer to a WCHAR buffer; zero-extend to 64-bit for SafeCopyUser. */
        if (entry32Copy.BaseDllName && entry32Copy.BaseDllNameLength) {
            USHORT  cch   = entry32Copy.BaseDllNameLength / sizeof(WCHAR);
            WCHAR   tmp[DMMDZZ_NAME_MAX];
            if (cch >= DMMDZZ_NAME_MAX) cch = DMMDZZ_NAME_MAX - 1;

            if (dmmdzz_SafeCopyUser(tmp,
                                    (PVOID)(ULONG_PTR)entry32Copy.BaseDllName,
                                    cch * sizeof(WCHAR))) {
                tmp[cch] = L'\0';
                dmmdzz_ToLowerW(tmp);

                if (dmmdzz_EndsWithW(tmp, cch, ModuleName, ModuleNameLen)) {
                    *OutBase = (ULONG_PTR)entry32Copy.DllBase;
                    *OutSize = entry32Copy.SizeOfImage;
                    status = STATUS_SUCCESS;
                    goto detach;
                }
            }
        }
        cur32 = entry32Copy.InLoadOrderLinks.Flink;
    }
    status = STATUS_NOT_FOUND;

detach:
    KeUnstackDetachProcess(&apc);

out:
    if (proc) ObDereferenceObject(proc);
    return status;
}

/* -------------------------------------------------------------------------
 * Dispatcher: detect WOW64 and route to the correct walker.
 *
 * PsGetProcessWow64Process returns non-NULL for 32-bit (WOW64) processes.
 * For native 64-bit processes it returns NULL, and we use the 64-bit walker.
 * ------------------------------------------------------------------------- */
static NTSTATUS dmmdzz_WalkLdr(HANDLE Pid,
                               const WCHAR *ModuleName,
                               ULONG ModuleNameLen,
                               PULONG_PTR OutBase,
                               PULONG      OutSize)
{
    NTSTATUS  status;
    PEPROCESS proc = NULL;

    status = PsLookupProcessByProcessId(Pid, &proc);
    if (!NT_SUCCESS(status)) return status;

    PVOID wow64 = PsGetProcessWow64Process(proc);
    ObDereferenceObject(proc);

    if (wow64) {
        return dmmdzz_WalkLdr32(Pid, ModuleName, ModuleNameLen, OutBase, OutSize);
    } else {
        return dmmdzz_WalkLdr64(Pid, ModuleName, ModuleNameLen, OutBase, OutSize);
    }
}

/* -------------------------------------------------------------------------
 * IOCTL_DMMDZZ_ENUM_MODULE_BASE
 * ------------------------------------------------------------------------- */
NTSTATUS dmmdzz_EnumModule(PDMMDZZ_ENUM_MODULE p)
{
    ULONG_PTR base = 0;
    ULONG     size = 0;
    NTSTATUS  status;

    /* Count wide chars in ModuleName (already NUL-terminated by user mode) */
    ULONG n = 0;
    for (; n < DMMDZZ_NAME_MAX && p->ModuleName[n]; ++n) ;

    /* Lowercase the request name so the comparison in WalkLdr is consistent */
    dmmdzz_ToLowerW(p->ModuleName);

    status = dmmdzz_WalkLdr(p->ProcessId, p->ModuleName, n, &base, &size);

    p->DllBase    = base;
    p->SizeOfImage= size;
    p->Hdr.Status = status;
    p->Hdr.ExtendedStatus = 0;
    return status;
}

/* -------------------------------------------------------------------------
 * IOCTL_DMMDZZ_QUERY_BASE  (shortcut: returns main image base)
 * ------------------------------------------------------------------------- */
NTSTATUS dmmdzz_QueryBase(PDMMDZZ_QUERY_BASE p)
{
    ULONG_PTR base = 0;
    ULONG     size = 0;
    NTSTATUS  status = dmmdzz_WalkLdr(p->ProcessId, L"", 0, &base, &size);

    p->DllBase     = base;
    p->SizeOfImage = size;
    p->Hdr.Status  = status;
    p->Hdr.ExtendedStatus = 0;
    return status;
}

/* ===========================================================================
 * DKOM process hiding (ActiveProcessLinks unlink)
 *
 * Unlinks a process from the kernel's ActiveProcessLinks list so that
 * NtQuerySystemInformation / task manager / Process Hacker no longer
 * enumerate it. PsLookupProcessByProcessId still works (it uses the CID
 * handle table, not the list), so the driver can still R/W the hidden
 * process's memory.
 *
 * Only ONE process may be hidden at a time (sufficient for hiding ctl.exe).
 * The original LIST_ENTRY neighbors are saved so UNHIDE can restore them.
 * =========================================================================== */

/* Saved state for restoring a hidden process. */
static PEPROCESS  g_HiddenProc  = NULL;
static LIST_ENTRY g_SavedLinks  = {0};
static ULONG      g_LinksOffset = 0;

/* -------------------------------------------------------------------------
 * Dynamically locate the ActiveProcessLinks offset within EPROCESS.
 *
 * UniqueProcessId (HANDLE, 8 bytes on x64) is immediately followed by
 * ActiveProcessLinks (LIST_ENTRY). We find UniqueProcessId by searching
 * the current process's EPROCESS for its own PID, then verify the same
 * offset in the System process (PID 4) holds the value 4.
 *
 * This avoids hardcoding version-specific offsets (0x2F0 on older Win10,
 * 0x448 on Win10 2004+ / Win11).
 * ----------------------------------------------------------------------- */
static ULONG dmmdzz_GetActiveProcessLinksOffset(VOID)
{
    if (g_LinksOffset != 0)
        return g_LinksOffset;

    PEPROCESS curProc = IoGetCurrentProcess();
    PEPROCESS sysProc = PsInitialSystemProcess;
    if (!curProc || !sysProc)
        return 0;

    HANDLE curPid = PsGetProcessId(curProc);
    if (!curPid)
        return 0;

    PUCHAR base = (PUCHAR)curProc;
    for (ULONG off = 0x10; off < 0x0800; off += sizeof(PVOID)) {
        /* Check if this offset holds the current PID */
        if (*(HANDLE*)(base + off) != curPid)
            continue;

        /* Verify: same offset in System EPROCESS should be 4 */
        if (*(HANDLE*)((PUCHAR)sysProc + off) != (HANDLE)4)
            continue;

        /* UniqueProcessId found at 'off'. ActiveProcessLinks = off + 8. */
        ULONG linksOff = off + sizeof(HANDLE);

        /* Sanity: Flink/Blink should look like kernel-mode addresses */
        PLIST_ENTRY links = (PLIST_ENTRY)(base + linksOff);
        if ((ULONG_PTR)links->Flink > (ULONG_PTR)0xFFFF000000000000ULL &&
            (ULONG_PTR)links->Blink > (ULONG_PTR)0xFFFF000000000000ULL) {
            g_LinksOffset = linksOff;
            DbgPrint(DMMDZZ_DBG_TAG " ActiveProcessLinks offset dynamically found: 0x%X\n", linksOff);
            return linksOff;
        }
    }

    DbgPrint(DMMDZZ_DBG_TAG " FAILED to locate ActiveProcessLinks offset\n");
    return 0;
}

NTSTATUS dmmdzz_HideProcess(PDMMDZZ_HIDE_PROCESS p)
{
    if (g_HiddenProc != NULL) {
        p->Hdr.Status = STATUS_ALREADY_COMPLETE;
        p->Hdr.ExtendedStatus = 1;  /* already hiding something */
        return STATUS_ALREADY_COMPLETE;
    }

    PEPROCESS proc = NULL;
    NTSTATUS status = PsLookupProcessByProcessId(p->ProcessId, &proc);
    if (!NT_SUCCESS(status)) {
        p->Hdr.Status = status;
        return status;
    }

    ULONG linksOff = dmmdzz_GetActiveProcessLinksOffset();
    if (linksOff == 0) {
        ObDereferenceObject(proc);
        p->Hdr.Status = STATUS_NOT_FOUND;
        p->Hdr.ExtendedStatus = 2;  /* offset lookup failed */
        return STATUS_NOT_FOUND;
    }

    PLIST_ENTRY entry = (PLIST_ENTRY)((PUCHAR)proc + linksOff);

    /* Save original neighbors for later restore */
    g_SavedLinks.Flink = entry->Flink;
    g_SavedLinks.Blink = entry->Blink;

    /* Unlink: prev->Flink = next, next->Blink = prev */
    entry->Blink->Flink = entry->Flink;
    entry->Flink->Blink = entry->Blink;

    /* Point entry to itself — a valid empty list. If the process exits
     * while hidden, RemoveEntryList becomes a no-op (no BSOD). */
    entry->Flink = entry;
    entry->Blink = entry;

    /* Keep the EPROCESS pointer (and the reference from PsLookup — this
     * prevents the object from being freed if ctl.exe crashes before
     * unhiding). The reference is released in dmmdzz_UnhideProcess. */
    g_HiddenProc = proc;

    p->EProcessVA         = (ULONG_PTR)proc;
    p->Hdr.Status         = STATUS_SUCCESS;
    p->Hdr.ExtendedStatus = linksOff;
    DbgPrint(DMMDZZ_DBG_TAG " Process PID=%p hidden (EPROCESS=%p, linksOff=0x%X)\n",
             p->ProcessId, proc, linksOff);
    return STATUS_SUCCESS;
}

NTSTATUS dmmdzz_UnhideProcess(PDMMDZZ_HIDE_PROCESS p)
{
    if (g_HiddenProc == NULL) {
        p->Hdr.Status = STATUS_NOT_FOUND;
        p->Hdr.ExtendedStatus = 1;  /* nothing hidden */
        return STATUS_NOT_FOUND;
    }

    ULONG linksOff = dmmdzz_GetActiveProcessLinksOffset();
    if (linksOff == 0) {
        p->Hdr.Status = STATUS_NOT_FOUND;
        p->Hdr.ExtendedStatus = 2;
        return STATUS_NOT_FOUND;
    }

    PLIST_ENTRY entry = (PLIST_ENTRY)((PUCHAR)g_HiddenProc + linksOff);

    /* Re-insert between the saved neighbors */
    PLIST_ENTRY savedFlink = g_SavedLinks.Flink;
    PLIST_ENTRY savedBlink = g_SavedLinks.Blink;

    entry->Flink = savedFlink;
    entry->Blink = savedBlink;
    savedFlink->Blink = entry;
    savedBlink->Flink = entry;

    p->EProcessVA         = (ULONG_PTR)g_HiddenProc;
    p->Hdr.Status         = STATUS_SUCCESS;
    p->Hdr.ExtendedStatus = linksOff;
    DbgPrint(DMMDZZ_DBG_TAG " Process PID=%p unhidden (EPROCESS=%p)\n",
             p->ProcessId, g_HiddenProc);

    /* Release the reference we held since HideProcess */
    ObDereferenceObject(g_HiddenProc);
    g_HiddenProc = NULL;
    RtlZeroMemory(&g_SavedLinks, sizeof(g_SavedLinks));
    return STATUS_SUCCESS;
}
