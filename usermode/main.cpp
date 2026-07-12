// =============================================================================
// usermode/main.cpp
//
// Command-line driver that demonstrates the four educational features:
//   1. Dynamic PID lookup by image name       (driver + user-mode variants)
//   2. Module base enumeration
//   3. Driver-assisted memory read            (read a known PE header)
//   4. Driver-assisted memory write           (flip a byte, write it back)
//
// The default demo target is "target.exe" - a PLACEHOLDER. Run any program
// and rename its window/argv, or actually rename notepad.exe to target.exe,
// to make the demo work.
//
// USAGE
//     dmmdzz_ctl.exe                       (uses default target.exe)
//     dmmdzz_ctl.exe <image.exe>           (override target)
//
// The .exe automatically loads dmmdzz_injector.sys from the same directory
// via the Service Control Manager (SCM), and unloads it on exit. No manual
// 'sc create' / 'sc start' / 'sc delete' needed.
//
// EDUCATIONAL: run as Administrator on Windows with test-signing enabled.
// =============================================================================
#include "driver_ctl.hpp"
#include "driver_loader.hpp"
#include "process.hpp"

#include <windows.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>
#include <memory>

static void PrintHex(const void* data, size_t size, uintptr_t baseVA)
{
    const uint8_t* p = static_cast<const uint8_t*>(data);
    for (size_t i = 0; i < size; i += 16) {
        std::printf("  %016llX  ", static_cast<unsigned long long>(baseVA + i));
        for (size_t j = 0; j < 16; ++j) {
            if (i + j < size) std::printf("%02X ", p[i + j]);
            else              std::printf("   ");
            if (j == 7) std::printf(" ");
        }
        std::printf(" |");
        for (size_t j = 0; j < 16 && i + j < size; ++j) {
            uint8_t c = p[i + j];
            std::printf("%c", (c >= 0x20 && c < 0x7F) ? (char)c : '.');
        }
        std::printf("|\n");
    }
}

int main(int argc, char** argv)
{
    std::wstring target = L"target.exe";
    if (argc >= 2) {
        // Convert narrow argv[1] -> wide. Simple ASCII is enough for the demo.
        target.assign(argv[1], argv[1] + std::strlen(argv[1]));
    }

    std::printf("=== dmmdzz_injector - EDUCATIONAL kernel learning tool ===\n");
    std::printf("Target image: %s\n", argv[1] ? argv[1] : "target.exe");
    std::printf("----------------------------------------------------------\n");

    try {
        // 0. Try to enable debug privilege so we can OpenProcess later
        dmmdzz::EnableDebugPrivilege();

        // 1. Try to open the device first.
        //    If KDU (or sc start) already loaded the driver, the device
        //    \\.\dmmdzz_injector will exist and we can skip SCM entirely.
        //    This is the "KDU path": no test signing, no reboot, no service.
        dmmdzz::DriverCtl drv;
        std::printf("[*] Probing device \\.\\dmmdzz_injector ...\n");
        bool deviceReady = drv.TryOpen();

        std::unique_ptr<dmmdzz::DriverLoader> loader;
        if (!deviceReady) {
            // Device not found - load the driver via SCM ourselves.
            // This requires test signing or a properly signed .sys.
            std::printf("[*] Device not found, loading driver via SCM ...\n");
            loader = std::make_unique<dmmdzz::DriverLoader>();
            loader->EnsureLoaded();
            std::printf("[*] Opening driver device \\.\\dmmdzz_injector ...\n");
            drv.Open();
        } else {
            std::printf("[+] Device already available (driver pre-loaded by KDU or sc).\n");
        }

        DMMDZZ_VERSION v{};
        drv.GetVersion(v);
        std::printf("[+] Driver version: %u.%u.%u\n", v.Major, v.Minor, v.Build);

        // 2. Look up the target PID via the driver (kernel side)
        std::printf("[*] Asking driver to find process '%s' ...\n",
                    argv[1] ? argv[1] : "target.exe");
        uintptr_t eProcVA = 0;
        uint32_t  pidDrv = drv.FindProcess(target, &eProcVA);
        std::printf("[+] Driver reports PID=%u  EPROCESS VA=0x%016llX\n",
                    pidDrv, static_cast<unsigned long long>(eProcVA));

        // 2b. Also look it up with the Win32 toolhelp API for comparison
        uint32_t pidWin = 0;
        try {
            pidWin = dmmdzz::FindProcessByName(target);
            std::printf("[+] Toolhelp32  reports PID=%u (should match)\n", pidWin);
        } catch (const std::exception& e) {
            std::printf("[!] Toolhelp lookup failed: %s\n", e.what());
        }

        // 3. Enumerate the main module base via the driver
        uintptr_t dllBase = 0;
        uint32_t  imgSize = 0;
        std::printf("[*] Asking driver for main module base ...\n");
        drv.QueryBase(pidDrv, &dllBase, &imgSize);
        std::printf("[+] Driver reports DllBase=0x%016llX  Size=0x%X (%u bytes)\n",
                    static_cast<unsigned long long>(dllBase),
                    imgSize, imgSize);

        // 3b. Compare with Win32 module enumeration
        try {
            auto mods = dmmdzz::EnumModules(pidDrv);
            std::printf("[+] Toolhelp enumerated %zu modules; first module:\n",
                        mods.size());
            std::printf("    %-30ls base=0x%016llX size=0x%X\n",
                        mods.empty() ? L"<none>" : mods[0].name.c_str(),
                        static_cast<unsigned long long>(mods.empty() ? 0 : mods[0].base),
                        mods.empty() ? 0 : mods[0].size);
        } catch (const std::exception& e) {
            std::printf("[!] Toolhelp module enum failed: %s\n", e.what());
        }

        // 4. READ MEMORY through the driver - read the PE header at DllBase.
        //    First 64 bytes contain "MZ" + the DOS header. A nice sanity check.
        std::printf("[*] Reading 64 bytes of PE header at 0x%016llX via driver ...\n",
                    static_cast<unsigned long long>(dllBase));
        uint8_t peHdr[64] = {};
        drv.ReadMemory(pidDrv, dllBase, peHdr, sizeof(peHdr));
        PrintHex(peHdr, sizeof(peHdr), dllBase);
        if (peHdr[0] == 'M' && peHdr[1] == 'Z') {
            std::printf("[+] PE 'MZ' signature verified.\n");
        } else {
            std::printf("[!] PE signature mismatch - read may have failed.\n");
        }

        // 5. WRITE MEMORY through the driver - flip the 'M' to 'm' and back.
        //    This proves bidirectional communication. We restore immediately
        //    so we never leave the target in a broken state.
        uint8_t original = peHdr[0];
        uint8_t flipped  = (original == 'M') ? 'm' : 'X';
        std::printf("[*] Writing byte 0x%02X at 0x%016llX via driver ...\n",
                    flipped, static_cast<unsigned long long>(dllBase));
        drv.WriteMemory(pidDrv, dllBase, &flipped, 1);

        uint8_t verify = 0;
        drv.ReadMemory(pidDrv, dllBase, &verify, 1);
        std::printf("[+] Verified after write: 0x%02X ('%c')\n",
                    verify, (verify >= 0x20 && verify < 0x7F) ? verify : '.');

        std::printf("[*] Restoring original byte 0x%02X ...\n", original);
        drv.WriteMemory(pidDrv, dllBase, &original, 1);

        std::printf("----------------------------------------------------------\n");
        std::printf("[+] Educational demo complete.\n");
        std::printf("    Review the kernel debugger output (DbgPrint) to see the\n");
        std::printf("    IRP flow on the driver side.\n");
        return 0;

    } catch (const std::exception& e) {
        std::fprintf(stderr, "[!] Error: %s\n", e.what());
        std::fprintf(stderr,
            "\nTroubleshooting:\n"
            "  * Run as Administrator.\n"
            "  * Enable test signing:  bcdedit /set testsigning on  (reboot)\n"
            "  * Is dmmdzz_injector.sys next to dmmdzz_ctl.exe?\n"
            "  * Is the target process actually running?\n");
        return 1;
    }
}
