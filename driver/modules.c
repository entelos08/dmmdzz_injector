/* =============================================================================
 * driver/modules.c
 *
 * Enumerate loaded modules of a target process by walking the PEB LDR list.
 *
 * EDUCATIONAL NOTES
 * -----------------
 *  * Every user-mode process has a PEB (Process Environment Block) whose
 *    `Ldr` field points to a PEB_LDR_DATA structure. That structure holds
 *    three doubly-linked circular lists of LDR_DATA_TABLE_ENTRY records:
 *      - InLoadOrderModuleList          (order modules were loaded)
 *      - InMemoryOrderModuleList        (order in memory)
 *      - InInitializationOrderModuleList (init order)
 *    We walk InLoadOrderModuleList because InLoadOrderLinks is the FIRST
 *    field of LDR_DATA_TABLE_ENTRY, so the list pointer IS the entry base.
 *
 *  * To read another process's PEB we must be inside its address space,
 *    so we KeStackAttachProcess before touching any of these VAs.
 *
 *  * __try/__except does NOT work in KDU-mapped drivers (the SEH tables
 *    are not registered, so any exception -> KMODE_EXCEPTION_NOT_HANDLED
 *    BSOD). We guard every user-mode read with dmmdzz_IsRangeValid, which
 *    uses MmIsAddressValid to confirm the page is resident before we touch it.
 *
 *  * x64 struct offsets used here are stable across Windows 7..11:
 *      PEB.Ldr                              = 0x18
 *      PEB_LDR_DATA.InLoadOrderModuleList   = 0x10  (LIST_ENTRY: Flink,Blink)
 *      LDR_DATA_TABLE_ENTRY.DllBase         = 0x30
 *      LDR_DATA_TABLE_ENTRY.SizeOfImage     = 0x40
 *      LDR_DATA_TABLE_ENTRY.BaseDllName     = 0x58  (UNICODE_STRING, 16 bytes)
 *    We use raw byte offsets (not the C struct from process.c) because the
 *    struct in process.c models BaseDllName as a PWSTR, while the real
 *    loader entry stores a full UNICODE_STRING there.
 * ============================================================================= */
#include "driver.h"

/* -------------------------------------------------------------------------
 * Forward declarations
 * ------------------------------------------------------------------------- */
/* Defined in memory.c. Probes whether every page covering [addr, addr+size)
 * is currently valid via MmIsAddressValid. Replaces __try/__except because
 * SEH tables are not registered in KDU-mapped drivers. */
BOOLEAN dmmdzz_IsRangeValid(PVOID addr, SIZE_T size);

/* Defined in memory.c. Safely copies user-mode memory into a kernel buffer
 * using ZwReadVirtualMemory (handles page faults via ntoskrnl SEH). */
BOOLEAN dmmdzz_SafeCopyUser(PVOID dst, PVOID src, SIZE_T size);

/* Undocumented but exported by ntoskrnl (stable since Vista). Returns the
 * user-mode VA of the target's PEB. Declared here returning PVOID because
 * we access PEB fields via raw byte offsets (see PEB_LDR_OFFSET below). */
PVOID NTAPI PsGetProcessPeb(PEPROCESS Process);

/* -------------------------------------------------------------------------
 * Local x64-compatible types
 * ------------------------------------------------------------------------- */
/* UNICODE_STRING64 is provided by the WDK (ntdef.h): 16 bytes on x64
 *   USHORT Length; USHORT MaximumLength; [4 pad]; ULONG64 Buffer;
 * We use it to read the BaseDllName field of LDR_DATA_TABLE_ENTRY in the
 * target process without depending on the host's struct alignment. */

/* -------------------------------------------------------------------------
 * x64 struct offsets (stable across Windows 7..11)
 * ------------------------------------------------------------------------- */
#define PEB_LDR_OFFSET              0x18   /* PEB.Ldr (PPEB_LDR_DATA)        */
#define PEB_LDR_DATA_INLOAD_OFFSET  0x10   /* PEB_LDR_DATA.InLoadOrderModuleList */
#define LDR_ENTRY_DLLBASE_OFFSET    0x30   /* LDR_DATA_TABLE_ENTRY.DllBase   */
#define LDR_ENTRY_SIZE_OFFSET       0x40   /* LDR_DATA_TABLE_ENTRY.SizeOfImage */
#define LDR_ENTRY_BASENAME_OFFSET   0x58   /* LDR_DATA_TABLE_ENTRY.BaseDllName (UNICODE_STRING) */
/* Number of bytes at the start of each LDR_DATA_TABLE_ENTRY that we touch
 * (covers DllBase, SizeOfImage, and the full BaseDllName UNICODE_STRING
 * which ends at 0x58 + 0x10 = 0x68). */
#define LDR_ENTRY_PROBE_SIZE        0x68

/* -------------------------------------------------------------------------
 * IOCTL_DMMDZZ_ENUM_MODULES
 *
 * Walks InLoadOrderModuleList of the target process and copies each module's
 * base / size / name into the output buffer at p->ModulesOffset.
 *
 * Buffer layout (METHOD_BUFFERED):
 *   [DMMDZZ_ENUM_MODULES header][DMMDZZ_MODULE_ENTRY Modules[]]
 *
 * Arguments:
 *   p       - header (in/out). Caller sets ProcessId, MaxModules, ModulesOffset.
 *   buf     - system buffer base (== Irp->AssociatedIrp.SystemBuffer)
 *   bufLen  - size of the system buffer
 *
 * Returns:
 *   STATUS_SUCCESS           - list walked (ModuleCount entries written)
 *   STATUS_INVALID_PARAMETER - buffer too small / MaxModules == 0 (ext=1)
 *   <other>                  - PsLookupProcessByProcessId failure (ext=2)
 *   STATUS_ACCESS_DENIED     - PEB / Ldr not readable (ext=3)
 * ------------------------------------------------------------------------- */
NTSTATUS dmmdzz_EnumModules(PDMMDZZ_ENUM_MODULES p, PVOID buf, ULONG bufLen)
{
    NTSTATUS              status   = STATUS_SUCCESS;
    PEPROCESS             target   = NULL;
    KAPC_STATE            apc;
    PVOID                 peb      = NULL;
    PVOID                 ldr      = NULL;
    LIST_ENTRY           *head     = NULL;
    LIST_ENTRY           *cur      = NULL;
    PDMMDZZ_MODULE_ENTRY  outEntry = NULL;
    ULONG                 count    = 0;

    DbgPrint(DMMDZZ_DBG_TAG " EnumModules: buf=%p bufLen=%lu MaxModules=%lu ModulesOffset=%lu\n",
             buf, bufLen, p->MaxModules, p->ModulesOffset);

    /* --- Validate buffer: the modules array must fit inside buf --- */
    {
        ULONG64 needed = (ULONG64)p->ModulesOffset +
                         (ULONG64)p->MaxModules * (ULONG64)sizeof(DMMDZZ_MODULE_ENTRY);
        if (p->MaxModules == 0 || needed > (ULONG64)bufLen) {
            DbgPrint(DMMDZZ_DBG_TAG " EnumModules: buffer too small (needed=%llu bufLen=%lu) -> INVALID_PARAMETER\n",
                     needed, bufLen);
            p->Hdr.Status         = STATUS_INVALID_PARAMETER;
            p->Hdr.ExtendedStatus = 1;
            p->ModuleCount        = 0;
            return STATUS_INVALID_PARAMETER;
        }
    }

    outEntry = (PDMMDZZ_MODULE_ENTRY)((PUCHAR)buf + p->ModulesOffset);

    /* --- Look up target process --- */
    status = PsLookupProcessByProcessId(p->ProcessId, &target);
    if (!NT_SUCCESS(status)) {
        DbgPrint(DMMDZZ_DBG_TAG " EnumModules: PsLookupProcessByProcessId(%p) failed 0x%08X\n",
                 p->ProcessId, status);
        p->Hdr.Status         = status;
        p->Hdr.ExtendedStatus = 2;
        p->ModuleCount        = 0;
        return status;
    }

    /* --- Get PEB (user-mode VA). Must be inside the process to read it. --- */
    peb = PsGetProcessPeb(target);
    if (!peb) {
        DbgPrint(DMMDZZ_DBG_TAG " EnumModules: PsGetProcessPeb returned NULL -> ACCESS_DENIED\n");
        p->Hdr.Status         = STATUS_ACCESS_DENIED;
        p->Hdr.ExtendedStatus = 3;
        p->ModuleCount        = 0;
        ObDereferenceObject(target);
        return STATUS_ACCESS_DENIED;
    }

    /* --- Attach to target address space --- */
    KeStackAttachProcess(target, &apc);

    /* NOTE: No __try/__except — SEH doesn't work in KDU-mapped drivers.
     * Every user-mode read below uses dmmdzz_SafeCopyUser (ZwReadVirtualMemory)
     * which handles page faults via ntoskrnl's properly-registered SEH,
     * avoiding the TOCTOU race in dmmdzz_IsRangeValid + RtlCopyMemory. */
    {
        /* Step 1: Read PEB->Ldr (pointer at PEB + 0x18). */
        if (!dmmdzz_SafeCopyUser(&ldr, (PUCHAR)peb + PEB_LDR_OFFSET, sizeof(ldr))) {
            DbgPrint(DMMDZZ_DBG_TAG " EnumModules: PEB@%p not readable -> ACCESS_DENIED\n", peb);
            status = STATUS_ACCESS_DENIED;
            goto done;
        }
        if (!ldr) {
            DbgPrint(DMMDZZ_DBG_TAG " EnumModules: PEB->Ldr is NULL -> ACCESS_DENIED\n");
            status = STATUS_ACCESS_DENIED;
            goto done;
        }

        /* Step 2: Read PEB_LDR_DATA.InLoadOrderModuleList (LIST_ENTRY at +0x10).
         * The list head is a LIST_ENTRY whose Flink points to the
         * InLoadOrderLinks of the first LDR_DATA_TABLE_ENTRY. */
        LIST_ENTRY listHead;
        if (!dmmdzz_SafeCopyUser(&listHead,
                                 (PUCHAR)ldr + PEB_LDR_DATA_INLOAD_OFFSET,
                                 sizeof(listHead))) {
            DbgPrint(DMMDZZ_DBG_TAG " EnumModules: PEB_LDR_DATA@%p not readable -> ACCESS_DENIED\n", ldr);
            status = STATUS_ACCESS_DENIED;
            goto done;
        }
        head = (LIST_ENTRY *)((PUCHAR)ldr + PEB_LDR_DATA_INLOAD_OFFSET);
        cur  = listHead.Flink;

        /* Safety: malformed list head */
        if (!cur) {
            DbgPrint(DMMDZZ_DBG_TAG " EnumModules: head->Flink is NULL -> ACCESS_DENIED\n");
            status = STATUS_ACCESS_DENIED;
            goto done;
        }

        /* Step 3: Walk the list until we loop back to the head or hit MaxModules. */
        while (cur != head && count < p->MaxModules) {
            /* InLoadOrderLinks is the first field of LDR_DATA_TABLE_ENTRY
             * (offset 0x00), so the entry base address == cur. */
            PUCHAR entry = (PUCHAR)cur;

            /* Copy the whole entry region we need into a kernel buffer
             * safely. dmmdzz_SafeCopyUser uses ZwReadVirtualMemory which
             * handles page faults via ntoskrnl's SEH. */
            UCHAR entryBuf[LDR_ENTRY_PROBE_SIZE];
            if (!dmmdzz_SafeCopyUser(entryBuf, entry, sizeof(entryBuf))) {
                DbgPrint(DMMDZZ_DBG_TAG " EnumModules: entry@%p not fully readable, skipping\n", entry);
                /* Try to at least read Flink (first 8 bytes) to advance;
                 * if that fails too, stop walking. */
                PVOID flink;
                if (!dmmdzz_SafeCopyUser(&flink, entry, sizeof(flink)))
                    break;
                cur = (LIST_ENTRY *)flink;
                continue;
            }

            /* Read fields from entryBuf (kernel buffer, safe to dereference). */
            PVOID             dllBase  = *(PVOID *)(entryBuf + LDR_ENTRY_DLLBASE_OFFSET);
            ULONG             sizeOfImg= *(ULONG  *)(entryBuf + LDR_ENTRY_SIZE_OFFSET);
            UNICODE_STRING64  name;
            RtlZeroMemory(&name, sizeof(name));
            /* Copy the UNICODE_STRING at +0x58 (16 bytes) from the kernel
             * buffer (no user memory touch here). */
            RtlCopyMemory(&name, entryBuf + LDR_ENTRY_BASENAME_OFFSET, sizeof(name));

            /* Fill the output entry. */
            PDMMDZZ_MODULE_ENTRY dst = &outEntry[count];
            RtlZeroMemory(dst, sizeof(*dst));
            dst->DllBase     = (ULONG_PTR)dllBase;
            dst->SizeOfImage = sizeOfImg;

            /* Copy the base name. name.Length is in BYTES. */
            if (name.Buffer && name.Length) {
                ULONG nameBytes = name.Length;
                ULONG capBytes  = (DMMDZZ_MAX_MODULE_NAME - 1) * sizeof(WCHAR);
                if (nameBytes > capBytes)
                    nameBytes = capBytes;

                if (!dmmdzz_SafeCopyUser(dst->BaseDllName,
                                         (PVOID)name.Buffer, nameBytes)) {
                    DbgPrint(DMMDZZ_DBG_TAG " EnumModules: name buffer@%p not readable, empty name\n",
                             (PVOID)name.Buffer);
                } else {
                    /* Null-terminate (dst is already zeroed, but be explicit). */
                    dst->BaseDllName[nameBytes / sizeof(WCHAR)] = L'\0';
                }
            }

            DbgPrint(DMMDZZ_DBG_TAG " EnumModules: [%lu] base=%p size=%lu name=%ws\n",
                     count, dllBase, sizeOfImg, dst->BaseDllName);

            count++;

            /* Advance: next entry's InLoadOrderLinks.Flink is the first 8
             * bytes of entryBuf (kernel buffer, safe to read). */
            cur = ((PLIST_ENTRY)entryBuf)->Flink;
        }
    }

done:
    KeUnstackDetachProcess(&apc);
    ObDereferenceObject(target);

    p->ModuleCount        = count;
    p->Hdr.Status         = status;
    /* All post-attach failures here are PEB/Ldr access failures (ext=3). */
    p->Hdr.ExtendedStatus = NT_SUCCESS(status) ? 0 : 3;

    DbgPrint(DMMDZZ_DBG_TAG " EnumModules: done. count=%lu status=0x%08X ext=%lu\n",
             count, p->Hdr.Status, p->Hdr.ExtendedStatus);
    return p->Hdr.Status;
}
