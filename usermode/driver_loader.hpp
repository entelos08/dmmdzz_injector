// =============================================================================
// usermode/driver_loader.hpp
//
// Automatic driver service management via the Service Control Manager (SCM).
//
// EDUCATIONAL NOTES
// -----------------
//  * Windows kernel drivers cannot be "double-clicked" to load. They must be
//    registered as a service via SCM, then started with StartService().
//  * CreateService(SERVICE_KERNEL_DRIVER) tells SCM this is a .sys driver,
//    not a regular Win32 service.
//  * StartService causes SCM to load the .sys into kernel memory and call
//    the driver's DriverEntry().
//  * ControlService(SERVICE_CONTROL_STOP) triggers the driver's Unload routine.
//  * DeleteService removes the registration; the .sys file itself is not deleted.
//
// This class automates the sc create / sc start / sc stop / sc delete cycle
// so the user can just run dmmdzz_ctl.exe without manual SCM commands.
// =============================================================================
#pragma once

#include <windows.h>
#include <string>
#include <cstdint>
#include "../driver/driver.h"   // DRIVER_SERVICE_NAME

namespace dmmdzz {

class DriverLoader {
public:
    DriverLoader() = default;
    ~DriverLoader();

    DriverLoader(const DriverLoader&)            = delete;
    DriverLoader& operator=(const DriverLoader&) = delete;

    // Make sure the driver service is installed and running.
    // sysPath: full path to the .sys file. If empty, looks for the .sys
    //          next to the running .exe (e.g. dmmdzz_injector.sys).
    // serviceName: SCM service name. Defaults to DRIVER_SERVICE_NAME.
    // Throws std::runtime_error on fatal failure.
    void EnsureLoaded(const std::wstring& sysPath      = L"",
                      const std::string&  serviceName  = DRIVER_SERVICE_NAME);

    // Stop and delete the service if we created it.
    // Safe to call even if the service was already gone.
    void Unload();

    bool IsLoaded() const { return loaded_; }

private:
    // Find the .sys file next to the current .exe.
    std::wstring FindSysPath() const;

    SC_HANDLE hSCM_  = nullptr;
    SC_HANDLE hSvc_  = nullptr;
    bool      loaded_    = false;   // service is running
    bool      ownsSvc_   = false;   // we created it (should delete on unload)
    std::string svcName_;
};

} // namespace dmmdzz
