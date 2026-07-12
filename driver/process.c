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

/* PsGetProcessId is exported by ntoskrnl; PsGetCurrentProcess is a macro. */
extern POBJECT_TYPE *PsProcessType;

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
 * ------------------------------------------------------------------------- */
static NTSTATUS dmmdzz_WalkLdr(HANDLE Pid,
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

    status = PsLookupProcessByProcessId(Pid, &proc);
    if (!NT_SUCCESS(status)) return status;

    /* PsGetProcessPeb is exported since Vista. Returns user-mode VA of PEB. */
    peb = (PPEB)PsGetProcessPeb(proc);
    if (!peb) { status = STATUS_ACCESS_DENIED; goto out; }

    KeStackAttachProcess(proc, &apc);

    __try {
        /* Validate PEB readability */
        ProbeForRead(peb, sizeof(*peb), 1);
        ldr = peb->Ldr;
        if (!ldr) { status = STATUS_ACCESS_DENIED; __leave; }

        ProbeForRead(ldr, sizeof(*ldr), 1);
        head = &ldr->InLoadOrderModuleList;
        cur  = head->Flink;

        while (cur != head) {
            entry = CONTAINING_RECORD(cur, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);

            /* Read the entry safely */
            ProbeForRead(entry, sizeof(*entry), 1);

            if (ModuleNameLen == 0) {
                /* First entry is the main image */
                *OutBase = (ULONG_PTR)entry->DllBase;
                *OutSize = entry->SizeOfImage;
                status = STATUS_SUCCESS;
                __leave;
            }

            /* Compare base name (case-insensitive). The user passed a
             * wide string; we lowercase both sides in-place copies. */
            if (entry->BaseDllName && entry->BaseDllNameLength) {
                USHORT  cch   = entry->BaseDllNameLength / sizeof(WCHAR);
                WCHAR   tmp[DMMDZZ_NAME_MAX];
                if (cch >= DMMDZZ_NAME_MAX) cch = DMMDZZ_NAME_MAX - 1;

                ProbeForRead(entry->BaseDllName, cch * sizeof(WCHAR), 1);
                RtlCopyMemory(tmp, entry->BaseDllName, cch * sizeof(WCHAR));
                tmp[cch] = L'\0';
                dmmdzz_ToLowerW(tmp);

                /* Suffix match lets the user pass just "ntdll.dll" etc. */
                if (dmmdzz_EndsWithW(tmp, cch, ModuleName, ModuleNameLen)) {
                    *OutBase = (ULONG_PTR)entry->DllBase;
                    *OutSize = entry->SizeOfImage;
                    status = STATUS_SUCCESS;
                    __leave;
                }
            }
            cur = cur->Flink;
        }
        status = STATUS_NOT_FOUND;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        status = GetExceptionCode();
    }

    KeUnstackDetachProcess(&apc);

out:
    if (proc) ObDereferenceObject(proc);
    return status;
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
