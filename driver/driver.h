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
 * ------------------------------------------------------------------------- */
#define DEVICE_NAME     L"\\Device\\dmmdzz_injector"
#define DOS_DEVICE_NAME L"\\??\\dmmdzz_injector"

/* Magic tag used by the test signing/SCM start path */
#define DRIVER_SERVICE_NAME  "dmmdzz_injector"

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
#define DMMDZZ_DEVICE_TYPE  0x8000

#define IOCTL_DMMDZZ_GET_VERSION        CTL_CODE(DMMDZZ_DEVICE_TYPE, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_DMMDZZ_FIND_PROCESS       CTL_CODE(DMMDZZ_DEVICE_TYPE, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_DMMDZZ_ENUM_MODULE_BASE   CTL_CODE(DMMDZZ_DEVICE_TYPE, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_DMMDZZ_READ_MEMORY        CTL_CODE(DMMDZZ_DEVICE_TYPE, 0x803, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_DMMDZZ_WRITE_MEMORY       CTL_CODE(DMMDZZ_DEVICE_TYPE, 0x804, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_DMMDZZ_QUERY_BASE         CTL_CODE(DMMDZZ_DEVICE_TYPE, 0x805, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_DMMDZZ_SCAN_MEMORY        CTL_CODE(DMMDZZ_DEVICE_TYPE, 0x806, METHOD_BUFFERED, FILE_ANY_ACCESS)

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

#endif /* _DRIVER_H_ */
