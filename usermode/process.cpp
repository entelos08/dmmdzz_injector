// =============================================================================
// usermode/process.cpp
// =============================================================================
#include "process.hpp"

#include <algorithm>
#include <cwctype>

namespace dmmdzz {

static std::wstring ToLower(std::wstring s) {
    std::transform(s.begin(), s.end(), s.begin(),
                   [](wchar_t c){ return std::towlower(c); });
    return s;
}

static bool EndsWithI(const std::wstring& hay, const std::wstring& needle) {
    if (needle.size() > hay.size()) return false;
    return ToLower(hay).compare(hay.size() - needle.size(),
                               needle.size(),
                               ToLower(needle)) == 0;
}

// -----------------------------------------------------------------------------
bool EnableDebugPrivilege()
{
    HANDLE token;
    if (!OpenProcessToken(GetCurrentProcess(),
                          TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
                          &token))
        return false;

    /* SE_DEBUG_NAME 宏在 UNICODE 定义时展开为宽字符串 (L"SeDebugPrivilege"),
     * 在窄字符模式下展开为窄字符串。使用 LookupPrivilegeValue 宏让其自动匹配。
     * 调整令牌特权在 user-mode 是必需的, 否则 OpenProcess 对受保护
     * 进程会返回 ERROR_ACCESS_DENIED。 */
    TOKEN_PRIVILEGES tp{};
    BOOL ok = LookupPrivilegeValue(nullptr, SE_DEBUG_NAME, &tp.Privileges[0].Luid);
    if (!ok) { CloseHandle(token); return false; }

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    ok = AdjustTokenPrivileges(token, FALSE, &tp, sizeof(tp), nullptr, nullptr);
    CloseHandle(token);
    return ok && GetLastError() != ERROR_NOT_ALL_ASSIGNED;
}

// -----------------------------------------------------------------------------
uint32_t FindProcessByName(const std::wstring& imageName)
{
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE)
        throw std::runtime_error("CreateToolhelp32Snapshot(PROCESS) failed");

    PROCESSENTRY32W pe{};
    pe.dwSize = sizeof(pe);

    uint32_t result = 0;
    if (Process32FirstW(snap, &pe)) {
        do {
            if (EndsWithI(pe.szExeFile, imageName)) {
                result = pe.th32ProcessID;
                break;
            }
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);

    if (result == 0)
        throw std::runtime_error("Process '" +
            std::string(imageName.begin(), imageName.end()) + "' not found");
    return result;
}

// -----------------------------------------------------------------------------
std::vector<ModuleInfo> EnumModules(uint32_t pid)
{
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
    if (snap == INVALID_HANDLE_VALUE)
        throw std::runtime_error("CreateToolhelp32Snapshot(MODULE) failed");

    std::vector<ModuleInfo> mods;
    MODULEENTRY32W me{};
    me.dwSize = sizeof(me);

    if (Module32FirstW(snap, &me)) {
        do {
            mods.push_back({
                me.szModule,
                (uintptr_t)me.modBaseAddr,
                (uint32_t)me.modBaseSize
            });
        } while (Module32NextW(snap, &me));
    }
    CloseHandle(snap);
    return mods;
}

// -----------------------------------------------------------------------------
ModuleInfo GetModule(uint32_t pid, const std::wstring& moduleName)
{
    auto mods = EnumModules(pid);
    if (mods.empty())
        throw std::runtime_error("No modules enumerated for pid " +
            std::to_string(pid));

    if (moduleName.empty())
        return mods.front();   // first module is the main .exe

    for (auto& m : mods) {
        if (EndsWithI(m.name, moduleName))
            return m;
    }
    throw std::runtime_error("Module '" +
        std::string(moduleName.begin(), moduleName.end()) + "' not found");
}

} // namespace dmmdzz
