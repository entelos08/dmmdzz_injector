// =============================================================================
// usermode/process.hpp
//
// Pure user-mode helpers that do NOT touch the driver. They illustrate how
// the Win32 toolhelp API exposes the process list and module list that the
// driver can also see (via the kernel's EPROCESS / PEB->Ldr data).
//
// Comparing these results against the driver's IOCTLs is a useful learning
// exercise: same data, two very different code paths.
// =============================================================================
#pragma once

#include <windows.h>
#include <tlhelp32.h>
#include <string>
#include <vector>
#include <cstdint>
#include <stdexcept>

namespace dmmdzz {

struct ModuleInfo {
    std::wstring name;
    uintptr_t    base;
    uint32_t     size;
};

// Find a process PID by image base name (e.g. "target.exe").
// Throws std::runtime_error on not-found.
uint32_t FindProcessByName(const std::wstring& imageName);

// Enumerate all loaded modules of the given PID.
// Returns the list sorted by load order.
std::vector<ModuleInfo> EnumModules(uint32_t pid);

// Convenience: look up one module by name; moduleName=="" returns main image.
ModuleInfo GetModule(uint32_t pid, const std::wstring& moduleName);

// Enable SE_DEBUG_NAME privilege in the current token so we can OpenProcess
// on system-protected processes. Returns true on success.
bool EnableDebugPrivilege();

} // namespace dmmdzz
