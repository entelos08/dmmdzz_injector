// =============================================================================
// usermode/driver_ctl.hpp
//
// Thin RAII wrapper around the Windows driver device handle and the IOCTL
// calls we support. Everything here is plain Win32 API, so it links cleanly
// under MinGW-w64 on Linux.
//
// EDUCATIONAL NOTES
// -----------------
//  * CreateFileW(L"\\\\.\\dmmdzz_injector", ...) opens the symbolic link the
//    driver created with IoCreateSymbolicLink. The kernel object behind it
//    is the control device returned by IoCreateDevice.
//  * DeviceIoControl is the user-mode entry point for IRP_MJ_DEVICE_CONTROL.
//    The kernel's IO manager builds an IRP, copies the user input buffer
//    (METHOD_BUFFERED) into a system buffer, and routes it to our driver.
//  * We use overlapped=FALSE for simplicity; the IRP completes synchronously.
// =============================================================================
#pragma once

#include <windows.h>
#include <string>
#include <vector>
#include <cstdint>
#include "../driver/driver.h"

namespace dmmdzz {

class DriverCtl {
public:
    DriverCtl() = default;
    ~DriverCtl();

    DriverCtl(const DriverCtl&)            = delete;
    DriverCtl& operator=(const DriverCtl&) = delete;

    // Open the driver device. Throws std::runtime_error on failure.
    void Open(const std::wstring& deviceName = WIN32_DEVICE_PATH);

    // Try to open the device. Returns true on success, false if the
    // device doesn't exist (driver not loaded yet). Does not throw.
    bool TryOpen(const std::wstring& deviceName = WIN32_DEVICE_PATH);

    void Close();
    bool IsOpen() const { return hDevice_ != INVALID_HANDLE_VALUE; }

    // ---- IOCTL wrappers ---------------------------------------------------
    void GetVersion(OUT DMMDZZ_VERSION& v);

    // Look up a process by image base name (e.g. "target.exe").
    // Returns the PID; on failure throws std::runtime_error.
    uint32_t FindProcess(const std::wstring& imageName,
                         OUT uintptr_t* eProcessVA = nullptr);

    // Enumerate the base address of a loaded module inside the target.
    // moduleName=="" returns the main executable image.
    void EnumModule(uint32_t pid,
                    const std::wstring& moduleName,
                    OUT uintptr_t* dllBase,
                    OUT uint32_t*     sizeOfImage);

    void QueryBase(uint32_t pid,
                   OUT uintptr_t* dllBase,
                   OUT uint32_t*   sizeOfImage);

    // Read Size bytes from remote VA into outBuf.
    void ReadMemory(uint32_t pid, uintptr_t remoteVA,
                    void* outBuf, size_t size);

    // Write Size bytes from inBuf into remote VA.
    void WriteMemory(uint32_t pid, uintptr_t remoteVA,
                     const void* inBuf, size_t size);

    // Kernel-side memory scan: searches target process for exact byte pattern.
    // Returns matching addresses in 'outAddrs'. The scan is performed entirely
    // in the kernel driver (attaches to target process, enumerates regions
    // via ZwQueryVirtualMemory, compares with RtlCompareMemory).
    // maxResults caps the number of matches returned.
    void ScanMemory(uint32_t pid, const void* value, size_t valueSize,
                    std::vector<uintptr_t>& outAddrs,
                    size_t maxResults = 50000);

    // Enumerate all loaded modules of a process by walking the PEB LDR list.
    // The driver attaches to the target process and walks InLoadOrderModuleList.
    void EnumModules(uint32_t pid,
                     std::vector<DMMDZZ_MODULE_ENTRY>& outModules,
                     ULONG maxModules = 512);

    // Multi-level pointer chain scan. Given a dynamic target address, finds
    // pointer chains that lead back to it (up to maxDepth hops). Chains whose
    // base falls within one of moduleRanges are marked IsStatic.
    void PtrScan(uint32_t pid,
                 uintptr_t targetAddress,
                 ULONG maxDepth,
                 const std::vector<DMMDZZ_MODULE_RANGE>& moduleRanges,
                 std::vector<DMMDZZ_PTR_CHAIN>& outChains,
                 ULONG maxChains = 1000);

    // DKOM: hide a process by unlinking it from ActiveProcessLinks.
    // After this, task manager / NtQuerySystemInformation won't list it.
    // The driver can still R/W its memory (PID lookup uses the CID table).
    // Only one process may be hidden at a time. Returns EPROCESS VA.
    uintptr_t HideProcess(uint32_t pid);

    // Restore a previously hidden process back into the list.
    void UnhideProcess();

private:
    HANDLE hDevice_ = INVALID_HANDLE_VALUE;

    // Generic IOCTL sender - allocates the system buffer, fills it,
    // invokes DeviceIoControl, and copies back the result.
    DWORD SendIoctl(DWORD code,
                    const void* in,  DWORD inLen,
                    void* out,       DWORD outLen,
                    OUT DWORD* bytesReturned);
};

} // namespace dmmdzz
