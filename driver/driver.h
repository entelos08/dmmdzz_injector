/* =============================================================================
 * driver/driver.h
 *
 * Shared definitions between the kernel driver (.sys) and the user-mode
 * controller (.exe). Everything that crosses the user/kernel boundary is
 * declared here so both sides agree on layout.
 *
 * EDUCATIONAL NOTES
 * ------------------
 *  * IOCTL codes use the METHOD_BUFFERED I/O method: the I/O Manager copies
 *    the user buffer into a kernel-system-space buffer on the way in and
 *    back on the way out. This is the simplest, safest method for learning.
 *  * DEVICE_TYPE 0x8000..0xFFFF is reserved for customer-developed devices.
 *  * The "target.exe" name below is a PLACEHOLDER for learning only.
 * ============================================================================= */
#ifndef _DRIVER_H_
#define _DRIVER_H_

#ifdef _KERNEL_MODE
  /* Kernel mode: ntifs.h includes ntddk.h and adds process-related APIs
   * (PsLookupProcessByProcessId, KeStackAttachProcess, KAPC_STATE, etc.)
   * that we need for memory read/write operations. */
  #include <ntifs.h>
#else
  /* User mode (MinGW/MSVC): windef.h gives us the Windows base types.
   * NTSTATUS is a LONG typedef normally provided by winternl.h; we define
   * it here to avoid pulling in extra headers. */
  #include <windef.h>
  #include <winioctl.h>
  #ifndef _NTDEF_
    typedef LONG NTSTATUS;
  #endif
#endif

/* -------------------------------------------------------------------------
 * Device + symbolic link names. These MUST match between driver and usermode.
 * \\Device\\<DeviceName>     - the device object created in the kernel
 * \\??\\<DosDeviceName>      - the Win32-visible symbolic link
 *
 * build_driver.ps1 generates driver_names.h with a random stem per build so
 * that the .sys filename, device name, service name, etc. all differ between
 * builds (defeats name/hash-based detection). If driver_names.h is not found
 * (e.g. compiling without the build script), the original defaults are used.
 * ------------------------------------------------------------------------- */
#if defined(__has_include)
  #if __has_include("driver_names.h")
    #include "driver_names.h"
  #endif
#endif

#ifndef DRIVER_STEM
  #define DRIVER_STEM "dmmdzz_injector"
#endif
#ifndef DRIVER_SYS_FILE
  #define DRIVER_SYS_FILE L"dmmdzz_injector.sys"
#endif
#ifndef DRIVER_SERVICE_NAME
  #define DRIVER_SERVICE_NAME "dmmdzz_injector"
#endif
#ifndef DEVICE_NAME
  #define DEVICE_NAME L"\\Device\\dmmdzz_injector"
#endif
#ifndef DOS_DEVICE_NAME
  #define DOS_DEVICE_NAME L"\\??\\dmmdzz_injector"
#endif
#ifndef DRIVER_OBJ_NAME
  #define DRIVER_OBJ_NAME L"\\Driver\\dmmdzz_injector"
#endif
#ifndef WIN32_DEVICE_PATH
  #define WIN32_DEVICE_PATH L"\\\\.\\dmmdzz_injector"
#endif

/* -------------------------------------------------------------------------
 * IOCTL device type, function-code base, and debug log tag. These are also
 * overridable by driver_names.h so every build produces a driver with
 * different IOCTL numeric codes and a different DbgPrint prefix string
 * (defeats signature matching on both the .sys and the user-mode .exe,
 * which share this header). When driver_names.h is absent the historical
 * defaults are used.
 * ------------------------------------------------------------------------- */
#ifndef DMMDZZ_DEVICE_TYPE
  #define DMMDZZ_DEVICE_TYPE  0x8000
#endif
#ifndef DMMDZZ_IOCTL_FUNC_BASE
  #define DMMDZZ_IOCTL_FUNC_BASE 0x800
#endif
#ifndef DMMDZZ_DBG_TAG
  #define DMMDZZ_DBG_TAG "[dmmdzz]"
#endif

/* -------------------------------------------------------------------------
 * IOCTL codes
 *
 * Device type : 0x8000  (user-defined range)
 * Function    : 0x800..  (function codes)
 * Method      : METHOD_BUFFERED
 * Access      : FILE_ANY_ACCESS
 *
 * CTL_CODE(DeviceType, Function, Method, Access) is documented in the WDK.
 * ------------------------------------------------------------------------- */
/* NOTE: DMMDZZ_DEVICE_TYPE is defined above (overridable by driver_names.h). */

#define IOCTL_DMMDZZ_GET_VERSION        CTL_CODE(DMMDZZ_DEVICE_TYPE, DMMDZZ_IOCTL_FUNC_BASE + 0,  METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_DMMDZZ_FIND_PROCESS       CTL_CODE(DMMDZZ_DEVICE_TYPE, DMMDZZ_IOCTL_FUNC_BASE + 1,  METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_DMMDZZ_ENUM_MODULE_BASE   CTL_CODE(DMMDZZ_DEVICE_TYPE, DMMDZZ_IOCTL_FUNC_BASE + 2,  METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_DMMDZZ_READ_MEMORY        CTL_CODE(DMMDZZ_DEVICE_TYPE, DMMDZZ_IOCTL_FUNC_BASE + 3,  METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_DMMDZZ_WRITE_MEMORY       CTL_CODE(DMMDZZ_DEVICE_TYPE, DMMDZZ_IOCTL_FUNC_BASE + 4,  METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_DMMDZZ_QUERY_BASE         CTL_CODE(DMMDZZ_DEVICE_TYPE, DMMDZZ_IOCTL_FUNC_BASE + 5,  METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_DMMDZZ_SCAN_MEMORY        CTL_CODE(DMMDZZ_DEVICE_TYPE, DMMDZZ_IOCTL_FUNC_BASE + 6,  METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_DMMDZZ_ENUM_MODULES       CTL_CODE(DMMDZZ_DEVICE_TYPE, DMMDZZ_IOCTL_FUNC_BASE + 7,  METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_DMMDZZ_PTRSCAN            CTL_CODE(DMMDZZ_DEVICE_TYPE, DMMDZZ_IOCTL_FUNC_BASE + 8,  METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_DMMDZZ_HIDE_PROCESS       CTL_CODE(DMMDZZ_DEVICE_TYPE, DMMDZZ_IOCTL_FUNC_BASE + 9,  METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_DMMDZZ_UNHIDE_PROCESS     CTL_CODE(DMMDZZ_DEVICE_TYPE, DMMDZZ_IOCTL_FUNC_BASE + 10, METHOD_BUFFERED, FILE_ANY_ACCESS)

/* -------------------------------------------------------------------------
 * Shared data structures
 * ------------------------------------------------------------------------- */

/* Maximum length of a process / module image name we carry in one IOCTL */
#define DMMDZZ_NAME_MAX  260

/* Generic status code returned in the OutputBuffer of every request */
typedef struct _DMMDZZ_STATUS {
    NTSTATUS Status;          /* NTSTATUS mirror                */
    ULONG    ExtendedStatus;  /* driver-specific extra info     */
} DMMDZZ_STATUS, *PDMMDZZ_STATUS;

/* IOCTL_DMMDZZ_GET_VERSION ------------------------------------------------ */
typedef struct _DMMDZZ_VERSION {
    DMMDZZ_STATUS Hdr;
    ULONG         Major;
    ULONG         Minor;
    ULONG         Build;
} DMMDZZ_VERSION, *PDMMDZZ_VERSION;

/* IOCTL_DMMDZZ_FIND_PROCESS ----------------------------------------------- */
typedef struct _DMMDZZ_FIND_PROCESS {
    /* In  */
    WCHAR  ProcessName[DMMDZZ_NAME_MAX];   /* e.g. L"target.exe"         */
    /* Out */
    DMMDZZ_STATUS Hdr;
    HANDLE        ProcessId;               /* PEPROCESS-cast PID returned */
    ULONG_PTR     EProcessVA;              /* VA of the EPROCESS object   */
} DMMDZZ_FIND_PROCESS, *PDMMDZZ_FIND_PROCESS;

/* IOCTL_DMMDZZ_ENUM_MODULE_BASE ------------------------------------------- */
typedef struct _DMMDZZ_ENUM_MODULE {
    /* In  */
    HANDLE  ProcessId;
    WCHAR   ModuleName[DMMDZZ_NAME_MAX];   /* L""  -> first module / .exe */
    /* Out */
    DMMDZZ_STATUS Hdr;
    ULONG_PTR     DllBase;                 /* base VA of the module        */
    ULONG         SizeOfImage;             /* size in bytes                */
} DMMDZZ_ENUM_MODULE, *PDMMDZZ_ENUM_MODULE;

/* IOCTL_DMMDZZ_QUERY_BASE ------------------------------------------------- */
/* Shortcut: returns the main executable base of the given PID */
typedef struct _DMMDZZ_QUERY_BASE {
    /* In  */
    HANDLE ProcessId;
    /* Out */
    DMMDZZ_STATUS Hdr;
    ULONG_PTR     DllBase;
    ULONG         SizeOfImage;
} DMMDZZ_QUERY_BASE, *PDMMDZZ_QUERY_BASE;

/* IOCTL_DMMDZZ_READ_MEMORY / WRITE_MEMORY --------------------------------- */
typedef struct _DMMDZZ_MEM_OP {
    /* In  */
    HANDLE    ProcessId;
    ULONG_PTR Address;                     /* target VA in remote process  */
    SIZE_T    Size;                        /* number of bytes              */
    ULONG_PTR BufferOffset;                /* offset of payload inside the
                                             IOCTL buffer (follows header) */
    /* Out */
    DMMDZZ_STATUS Hdr;
    SIZE_T    BytesTransferred;
} DMMDZZ_MEM_OP, *PDMMDZZ_MEM_OP;

/* IOCTL_DMMDZZ_SCAN_MEMORY ------------------------------------------------ */
/* Kernel-side memory scan: searches target process for exact byte pattern.
 *
 * Buffer layout (METHOD_BUFFERED):
 *   [DMMDZZ_SCAN_REQUEST header][value bytes][results array]
 *
 * The driver attaches to the target process, enumerates committed readable
 * regions via ZwQueryVirtualMemory, and uses RtlCompareMemory to find
 * exact matches. Matching addresses are written to the results array.
 */
#define DMMDZZ_SCAN_MAX_VALUE_SIZE  256

typedef struct _DMMDZZ_SCAN_REQUEST {
    /* In  */
    HANDLE    ProcessId;
    SIZE_T    ValueSize;                   /* size of search value (bytes)  */
    ULONG     ValueOffset;                 /* offset to value in buffer     */
    ULONG     MaxResults;                  /* max addresses to return       */
    ULONG     ResultsOffset;               /* offset to results array       */
    /* Out */
    DMMDZZ_STATUS Hdr;
    ULONG     ResultsCount;                /* actual matches found          */
} DMMDZZ_SCAN_REQUEST, *PDMMDZZ_SCAN_REQUEST;

/* IOCTL_DMMDZZ_ENUM_MODULES ----------------------------------------------- */
/* Enumerate all loaded modules of a process by walking the PEB LDR list.
 *
 * Buffer layout (METHOD_BUFFERED):
 *   [DMMDZZ_ENUM_MODULES header][DMMDZZ_MODULE_ENTRY Modules[]]
 *
 * The driver attaches to the target process, reads PEB->Ldr, and walks
 * InLoadOrderModuleList to collect base/size/name of each loaded module.
 */
#define DMMDZZ_MAX_MODULE_NAME  64

typedef struct _DMMDZZ_MODULE_ENTRY {
    ULONG_PTR DllBase;
    ULONG     SizeOfImage;
    WCHAR     BaseDllName[DMMDZZ_MAX_MODULE_NAME];  /* null-terminated */
} DMMDZZ_MODULE_ENTRY, *PDMMDZZ_MODULE_ENTRY;

typedef struct _DMMDZZ_ENUM_MODULES {
    /* In  */
    HANDLE    ProcessId;
    ULONG     MaxModules;       /* capacity of Modules[] array */
    ULONG     ModulesOffset;    /* offset to Modules[] in buffer */
    /* Out */
    DMMDZZ_STATUS Hdr;
    ULONG     ModuleCount;      /* actual number returned */
} DMMDZZ_ENUM_MODULES, *PDMMDZZ_ENUM_MODULES;

/* IOCTL_DMMDZZ_PTRSCAN ---------------------------------------------------- */
/* Multi-level pointer chain scan. Given a dynamic address, finds pointer
 * chains that lead back to a static module base.
 *
 * Buffer layout (METHOD_BUFFERED):
 *   [DMMDZZ_PTRSCAN_REQUEST header][DMMDZZ_MODULE_RANGE[]][DMMDZZ_PTR_CHAIN[]]
 *
 * The driver does up to MaxDepth passes over process memory:
 *   Pass 1: find all 8-byte values == TargetAddress  (level-1 pointers)
 *   Pass 2: find all 8-byte values in level-1 set    (level-2 pointers)
 *   Pass 3: find all 8-byte values in level-2 set    (level-3 pointers)
 * Chains whose base falls within a module range are marked IsStatic.
 */
#define DMMDZZ_PTRSCAN_MAX_DEPTH  3

typedef struct _DMMDZZ_MODULE_RANGE {
    ULONG_PTR Base;
    SIZE_T    Size;
} DMMDZZ_MODULE_RANGE, *PDMMDZZ_MODULE_RANGE;

typedef struct _DMMDZZ_PTR_CHAIN {
    ULONG     Depth;            /* number of hops (1 = direct ptr to target) */
    ULONG_PTR Addresses[DMMDZZ_PTRSCAN_MAX_DEPTH + 1]; /* [base,...,target] */
    BOOLEAN   IsStatic;         /* base address is in a module range */
} DMMDZZ_PTR_CHAIN, *PDMMDZZ_PTR_CHAIN;

typedef struct _DMMDZZ_PTRSCAN_REQUEST {
    /* In  */
    HANDLE    ProcessId;
    ULONG_PTR TargetAddress;
    ULONG     MaxDepth;         /* 1..3 */
    ULONG     MaxChains;        /* max chains to return */
    ULONG     NumModuleRanges;  /* for static checking */
    ULONG     ModuleRangesOffset;  /* offset to DMMDZZ_MODULE_RANGE[] */
    ULONG     ResultsOffset;       /* offset to DMMDZZ_PTR_CHAIN[] */
    /* Out */
    DMMDZZ_STATUS Hdr;
    ULONG     ChainCount;
} DMMDZZ_PTRSCAN_REQUEST, *PDMMDZZ_PTRSCAN_REQUEST;

/* IOCTL_DMMDZZ_HIDE_PROCESS / UNHIDE_PROCESS ------------------------------- */
/* DKOM (Direct Kernel Object Manipulation): unlink the target process from
 * the EPROCESS.ActiveProcessLinks list so NtQuerySystemInformation and the
 * task manager no longer enumerate it. PsLookupProcessByProcessId still
 * works (it uses the CID handle table, not the list), so memory R/W via
 * the driver remains functional on a hidden process.
 *
 * The driver saves the original LIST_ENTRY so UNHIDE can restore it.
 * Only ONE process may be hidden at a time (sufficient for hiding ctl.exe).
 */
typedef struct _DMMDZZ_HIDE_PROCESS {
    /* In  */
    HANDLE    ProcessId;            /* PID of process to hide/unhide */
    /* Out */
    DMMDZZ_STATUS Hdr;
    ULONG_PTR EProcessVA;           /* EPROCESS VA for confirmation */
} DMMDZZ_HIDE_PROCESS, *PDMMDZZ_HIDE_PROCESS;

#endif /* _DRIVER_H_ */
