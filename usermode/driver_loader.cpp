// =============================================================================
// usermode/driver_loader.cpp
//
// SCM (Service Control Manager) glue for auto-loading the kernel driver.
// =============================================================================
#include "driver_loader.hpp"

#include <windows.h>
#include <cstdio>
#include <stdexcept>
#include <cstring>

#include "../driver/driver.h"

namespace dmmdzz {

DriverLoader::~DriverLoader()
{
    Unload();
}

// -----------------------------------------------------------------------------
// Find the .sys file in the same directory as the running .exe.
// e.g.  C:\tools\dmmdzz_ctl.exe  ->  C:\tools\dmmdzz_injector.sys
// -----------------------------------------------------------------------------
std::wstring DriverLoader::FindSysPath() const
{
    wchar_t exePath[MAX_PATH] = {0};
    DWORD len = GetModuleFileNameW(nullptr, exePath, MAX_PATH);
    if (len == 0 || len >= MAX_PATH)
        throw std::runtime_error("GetModuleFileNameW failed");

    // Strip the .exe filename, keep the directory
    std::wstring dir(exePath);
    size_t slash = dir.find_last_of(L"\\/");
    if (slash != std::wstring::npos)
        dir.resize(slash + 1);
    else
        dir = L".\\";

    // Build the .sys path: <dir>dmmdzz_injector.sys
    std::wstring sysPath = dir + L"dmmdzz_injector.sys";

    // Check existence
    DWORD attr = GetFileAttributesW(sysPath.c_str());
    if (attr == INVALID_FILE_ATTRIBUTES)
        throw std::runtime_error(
            "Driver file not found: " +
            std::string(sysPath.begin(), sysPath.end()) +
            "\n  Place dmmdzz_injector.sys in the same directory as dmmdzz_ctl.exe");

    return sysPath;
}

// -----------------------------------------------------------------------------
void DriverLoader::EnsureLoaded(const std::wstring& sysPath,
                                const std::string&  serviceName)
{
    svcName_ = serviceName;

    // Resolve the .sys path
    std::wstring finalSysPath = sysPath.empty() ? FindSysPath() : sysPath;

    // Open SCM
    hSCM_ = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_ALL_ACCESS);
    if (!hSCM_)
        throw std::runtime_error(
            "OpenSCManager failed (GetLastError=" +
            std::to_string(GetLastError()) +
            "). Are you running as Administrator?");

    // Try to open an existing service
    // Convert serviceName (narrow) to wide for the W-suffix API
    std::wstring svcNameW(serviceName.begin(), serviceName.end());

    hSvc_ = OpenServiceW(hSCM_, svcNameW.c_str(), SERVICE_ALL_ACCESS);
    if (hSvc_) {
        // Service already exists - check if it's running
        ownsSvc_ = false;

        SERVICE_STATUS status = {};
        if (QueryServiceStatus(hSvc_, &status)) {
            if (status.dwCurrentState == SERVICE_RUNNING) {
                std::printf("[*] Driver service '%s' is already running.\n",
                            serviceName.c_str());
                loaded_ = true;
                return;
            }
        }

        // Not running - try to start it
        std::printf("[*] Starting existing driver service '%s' ...\n",
                    serviceName.c_str());
        if (StartServiceW(hSvc_, 0, nullptr)) {
            loaded_ = true;
            std::printf("[+] Driver service started.\n");
            return;
        }

        DWORD err = GetLastError();
        if (err == ERROR_SERVICE_ALREADY_RUNNING) {
            loaded_ = true;
            std::printf("[+] Driver service was already running.\n");
            return;
        }

        // Failed to start - delete and recreate
        std::printf("[!] StartService failed (err=%lu), recreating service...\n", err);
        DeleteService(hSvc_);
        CloseServiceHandle(hSvc_);
        hSvc_ = nullptr;
    }

    // Create a new service
    std::printf("[*] Creating driver service '%s' ...\n", serviceName.c_str());
    std::printf("    sys path: %ls\n", finalSysPath.c_str());

    hSvc_ = CreateServiceW(
        hSCM_,
        svcNameW.c_str(),           // service name
        svcNameW.c_str(),           // display name
        SERVICE_ALL_ACCESS,
        SERVICE_KERNEL_DRIVER,      // this is a .sys driver
        SERVICE_DEMAND_START,       // start on demand
        SERVICE_ERROR_NORMAL,
        finalSysPath.c_str(),       // path to .sys
        nullptr, nullptr, nullptr, nullptr, nullptr);

    if (!hSvc_) {
        DWORD err = GetLastError();
        throw std::runtime_error(
            "CreateService failed (GetLastError=" + std::to_string(err) +
            ").\n  Common causes:\n"
            "    - Not running as Administrator\n"
            "    - Test signing not enabled (bcdedit /set testsigning on)\n"
            "    - Path contains invalid characters");
    }
    ownsSvc_ = true;

    // Start the service
    std::printf("[*] Starting driver service ...\n");
    if (!StartServiceW(hSvc_, 0, nullptr)) {
        DWORD err = GetLastError();
        if (err == ERROR_SERVICE_ALREADY_RUNNING) {
            loaded_ = true;
            std::printf("[+] Driver service was already running.\n");
            return;
        }

        // Start failed - clean up and report
        std::string hint;
        if (err == 577)  // ERROR_INVALID_IMAGE_HASH
            hint = "\n  Hint: Enable test signing:  bcdedit /set testsigning on  (reboot)";
        else if (err == 1058)  // SERVICE_DISABLED
            hint = "\n  Hint: The driver may be disabled in the registry";
        else if (err == 31)   // ERROR_GEN_FAILURE
            hint = "\n  Hint: Driver init failed - check DbgPrint output with DebugView";

        DeleteService(hSvc_);
        CloseServiceHandle(hSvc_);
        hSvc_ = nullptr;
        throw std::runtime_error(
            "StartService failed (GetLastError=" + std::to_string(err) + ")" + hint);
    }

    loaded_ = true;
    std::printf("[+] Driver service created and started.\n");
}

// -----------------------------------------------------------------------------
void DriverLoader::Unload()
{
    if (hSvc_) {
        // Stop the service if we own it
        if (ownsSvc_ && loaded_) {
            SERVICE_STATUS status = {};
            ControlService(hSvc_, SERVICE_CONTROL_STOP, &status);
            std::printf("[*] Driver service stopped.\n");
        }
        // Delete the service if we created it
        if (ownsSvc_) {
            DeleteService(hSvc_);
            std::printf("[*] Driver service deleted.\n");
        }
        CloseServiceHandle(hSvc_);
        hSvc_ = nullptr;
    }
    if (hSCM_) {
        CloseServiceHandle(hSCM_);
        hSCM_ = nullptr;
    }
    loaded_ = false;
    ownsSvc_ = false;
}

} // namespace dmmdzz
