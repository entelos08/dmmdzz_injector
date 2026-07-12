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
#include <cstdint>
#include "../driver/driver.h"

namespace dmmdzz {

class DriverCtl {
public:
    DriverCtl() = default;
    ~DriverCtl();

    DriverCtl(const DriverCtl&)            = delete;
    DriverCtl& operator=(const DriverCtl&) = delete;

    // Open \\.\dmmdzz_injector. Throws std::runtime_error on failure.
    void Open(const std::wstring& deviceName = L"\\\\.\\dmmdzz_injector");

    // Try to open the device. Returns true on success, false if the
    // device doesn't exist (driver not loaded yet). Does not throw.
    bool TryOpen(const std::wstring& deviceName = L"\\\\.\\dmmdzz_injector");

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
