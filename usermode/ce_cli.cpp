// =============================================================================
// usermode/ce_cli.cpp
//
// Cheat Engine style CLI memory scanner. Uses the kernel driver for reads/
// writes (bypasses usermode hooks) and VirtualQueryEx for region enumeration.
//
// Usage:
//   dmmdzz_ce.exe <process.exe>
//
// Commands:
//   scan <type> <op> <value> [value2]   First scan
//   next <type> <op> <value> [value2]   Next scan (filter)
//   list [n]                            List results (default 20)
//   write <addr> <type> <value>         Write value to address
//   read  <addr> <type> [len]           Read value at address
//   watch <addr> <type>                 Watch address (refresh every 1s)
//   export <file>                       Export results to file
//   regions                             List memory regions
//   info                                Show process info
//   reset                               Clear scan results
//   help                                Show this help
//   quit                                Exit
//
// Types: i8 u8 i16 u16 i32 u64 i64 u64 f32 f64 str wstr bytes
// Ops:   eq ne gt lt ge le range increased decreased changed unchanged
// =============================================================================
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>
#include <thread>
#include <chrono>
#include <atomic>
#include <algorithm>
#include <sstream>
#include <iomanip>
#include <iostream>
#include <fstream>

#include <windows.h>

#include "driver_ctl.hpp"
#include "driver_loader.hpp"
#include "process.hpp"
#include "scanner.hpp"

// ---------------------------------------------------------------------------
// Helper: trim whitespace
// ---------------------------------------------------------------------------
static std::string trim(const std::string& s) {
    size_t a = s.find_first_not_of(" \t\r\n");
    if (a == std::string::npos) return "";
    size_t b = s.find_last_not_of(" \t\r\n");
    return s.substr(a, b - a + 1);
}

// ---------------------------------------------------------------------------
// Helper: split string by spaces
// ---------------------------------------------------------------------------
static std::vector<std::string> splitArgs(const std::string& line) {
    std::vector<std::string> args;
    std::istringstream iss(line);
    std::string tok;
    while (iss >> tok) args.push_back(tok);
    return args;
}

// ---------------------------------------------------------------------------
// Helper: parse hex or decimal address
// ---------------------------------------------------------------------------
static uintptr_t parseAddr(const std::string& s) {
    if (s.substr(0, 2) == "0x" || s.substr(0, 2) == "0X")
        return (uintptr_t)std::stoull(s.substr(2), nullptr, 16);
    return (uintptr_t)std::stoull(s, nullptr, 0);
}

// ---------------------------------------------------------------------------
// Progress display thread
// ---------------------------------------------------------------------------
static void progressThread(Scanner& sc) {
    while (sc.scanning) {
        size_t total = sc.totalBytes;
        size_t done  = sc.scannedBytes;
        double pct   = total ? (100.0 * done / total) : 0;
        size_t mb    = done / (1024 * 1024);
        size_t totalMb = total / (1024 * 1024);

        std::printf("\r  [Progress] %zu/%zu MB  (%.1f%%)  Results: %zu    ",
                    mb, totalMb, pct, sc.resultCount());
        std::fflush(stdout);
        std::this_thread::sleep_for(std::chrono::milliseconds(200));
    }
    std::printf("\r%80s\r", ""); // clear line
}

// ---------------------------------------------------------------------------
// Print help
// ---------------------------------------------------------------------------
static void printHelp() {
    std::printf(
        "\n  Commands:\n"
        "    scan <type> <op> <val> [val2]   First scan — scan all readable memory\n"
        "    next <type> <op> <val> [val2]   Next scan — filter previous results\n"
        "    list [n]                        List results (default 20, 0 = all)\n"
        "    write <addr> <type> <val>       Write value to address\n"
        "    read  <addr> <type> [len]       Read value at address\n"
        "    watch <addr> <type>             Watch address (Ctrl+C to stop)\n"
        "    export <file>                   Export results to file\n"
        "    regions                         List memory regions\n"
        "    info                            Show process info\n"
        "    reset                           Clear scan results\n"
        "    help                            Show this help\n"
        "    quit                            Exit\n"
        "\n"
        "  Types: i8 u8 i16 u16 i32 u32 i64 u64 f32 f64 str wstr bytes\n"
        "  Ops:   eq ne gt lt ge le range increased decreased changed unchanged\n"
        "\n"
        "  Examples:\n"
        "    scan i32 eq 100                 Find all int32 == 100\n"
        "    next i32 eq 200                 Filter: now == 200\n"
        "    next i32 increased              Filter: value increased\n"
        "    scan f32 range 1.0 10.0         Find float in [1.0, 10.0]\n"
        "    scan bytes eq \"DE AD BE EF\"    Find byte pattern\n"
        "    write 0x12345678 i32 999        Write 999 at address\n"
        "    read 0x12345678 bytes 16        Read 16 bytes as hex\n"
        "\n");
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------
int main(int argc, char* argv[]) {
    std::printf("=== dmmdzz_injector - CE Style Memory Scanner ===\n");

    if (argc < 2) {
        std::printf("Usage: %s <process.exe>\n", argv[0]);
        std::printf("Example: %s target.exe\n", argv[0]);
        return 1;
    }

    const char* targetName = argv[1] ? argv[1] : "target.exe";

    // --- Enable debug privilege ---
    dmmdzz::EnableDebugPrivilege();

    // --- Load driver --- (must outlive Scanner, which holds a reference)
    dmmdzz::DriverCtl drv;
    uint32_t  pid = 0;
    uintptr_t eproc = 0;
    uintptr_t dllBase = 0;
    uint32_t  dllSize = 0;

    try {
        // Try opening existing device first (e.g., KDU already loaded)
        if (!drv.TryOpen()) {
            std::printf("[*] Device not found, loading driver via SCM...\n");
            dmmdzz::DriverLoader loader;
            loader.EnsureLoaded();
            std::printf("[+] Driver loaded.\n");
            drv.Open();
        } else {
            std::printf("[+] Device already open (driver pre-loaded).\n");
        }

        // --- Get driver version ---
        DMMDZZ_VERSION v{};
        drv.GetVersion(v);
        std::printf("[+] Driver version: %u.%u.%u\n", v.Major, v.Minor, v.Build);

        // --- Find target process ---
        std::wstring wTarget(targetName, targetName + std::strlen(targetName));
        pid = drv.FindProcess(wTarget, &eproc);
        std::printf("[+] Target: %s  PID=%u  EPROCESS=0x%llX\n",
                    targetName, pid, (unsigned long long)eproc);

        // --- Get main module base ---
        drv.QueryBase(pid, &dllBase, &dllSize);
        std::printf("[+] Main module: base=0x%llX  size=0x%X (%u bytes)\n",
                    (unsigned long long)dllBase, dllSize, dllSize);

    } catch (const std::exception& e) {
        std::fprintf(stderr, "[!] Error: %s\n", e.what());
        std::fprintf(stderr,
            "\nTroubleshooting:\n"
            "  * Run as Administrator.\n"
            "  * Is dmmdzz_injector.sys next to dmmdzz_ce.exe?\n"
            "  * Is the target process actually running?\n"
            "  * If using KDU, run: kdu.exe -map dmmdzz_injector.sys\n");
        return 1;
    }

    // --- Create scanner --- (drv is alive for the whole main scope)
    Scanner sc(drv, pid);
    std::printf("[+] Scanner ready. Type 'help' for commands.\n\n");

    // --- REPL ---
    char line[1024];
    while (true) {
        std::printf("ce> ");
        std::fflush(stdout);
        if (!std::fgets(line, sizeof(line), stdin)) break;

        std::string input = trim(line);
        if (input.empty()) continue;

        auto args = splitArgs(input);
        if (args.empty()) continue;

        std::string cmd = args[0];

        // -------------------------------------------------------------------
        if (cmd == "quit" || cmd == "exit" || cmd == "q") {
            break;

        // -------------------------------------------------------------------
        } else if (cmd == "help" || cmd == "h" || cmd == "?") {
            printHelp();

        // -------------------------------------------------------------------
        } else if (cmd == "info") {
            std::printf("  Process:  %s\n", targetName);
            std::printf("  PID:      %u\n", pid);
            std::printf("  EPROCESS: 0x%llX\n", (unsigned long long)eproc);
            std::printf("  Base:     0x%llX  Size: 0x%X\n",
                        (unsigned long long)dllBase, dllSize);
            std::printf("  Results:  %zu\n", sc.resultCount());
            std::printf("  FirstScan: %s\n", sc.isFirstScan() ? "yes" : "no");

        // -------------------------------------------------------------------
        } else if (cmd == "regions") {
            auto regs = sc.enumRegions();
            std::printf("\n  %-18s %-12s %-10s %s\n", "Base", "Size", "Protect", "Flags");
            std::printf("  ----------------------------------------------------------\n");
            for (auto& r : regs) {
                std::printf("  0x%016llX   0x%08llX   %08X  %s%s%s\n",
                            (unsigned long long)r.base,
                            (unsigned long long)r.size,
                            r.protect,
                            r.readable ? "R" : "-",
                            r.writable ? "W" : "-",
                            r.executable ? "X" : "-");
            }
            std::printf("  Total: %zu regions\n\n", regs.size());

        // -------------------------------------------------------------------
        } else if (cmd == "scan" || cmd == "next") {
            if (args.size() < 3) {
                std::printf("  Usage: %s <type> <op> <value> [value2]\n", cmd.c_str());
                continue;
            }
            DataType dt = parseDataType(args[1]);
            ScanOp   op = parseScanOp(args[2]);
            std::string val1 = args.size() > 3 ? args[3] : "";
            std::string val2 = args.size() > 4 ? args[4] : "";

            // For increased/decreased/changed/unchanged, no value needed
            if (op == ScanOp::INCREASED || op == ScanOp::DECREASED ||
                op == ScanOp::CHANGED    || op == ScanOp::UNCHANGED) {
                if (cmd == "scan" && sc.isFirstScan()) {
                    std::printf("[*] First scan with '%s' — storing all values as baseline...\n",
                                scanOpName(op));
                }
            }

            std::printf("[*] %s: %s %s %s%s%s ...\n",
                        cmd == "scan" ? "Scanning" : "Filtering",
                        dataTypeName(dt), scanOpName(op),
                        val1.c_str(),
                        !val2.empty() ? " ~ " : "",
                        val2.c_str());

            // Launch progress thread
            std::thread prog(progressThread, std::ref(sc));

            if (cmd == "scan") {
                sc.firstScan(dt, op, val1, val2);
            } else {
                sc.nextScan(dt, op, val1, val2);
            }

            prog.join();
            std::printf("[+] Done. Results: %zu\n\n", sc.resultCount());

        // -------------------------------------------------------------------
        } else if (cmd == "list" || cmd == "ls") {
            size_t n = 20;
            if (args.size() > 1) n = (size_t)std::stoul(args[1]);
            if (n == 0) n = sc.resultCount();

            const auto& res = sc.results();
            size_t show = std::min(n, res.size());

            std::printf("\n  %-18s  %-20s  %-20s\n", "Address", "Value", "Previous");
            std::printf("  ----------------------------------------------------------\n");
            DataType dispType = sc.lastScanType();
            for (size_t i = 0; i < show; i++) {
                std::string cur  = sc.formatValue(dispType,
                                                  res[i].curValue.data(), res[i].curValue.size());
                std::string prev = res[i].prevValue.empty() ? "-" :
                    sc.formatValue(dispType, res[i].prevValue.data(), res[i].prevValue.size());
                std::printf("  0x%016llX  %-20s  %-20s\n",
                            (unsigned long long)res[i].address, cur.c_str(), prev.c_str());
            }
            if (res.size() > show) {
                std::printf("  ... (%zu more, use 'list %zu' or 'list 0' for all)\n",
                            res.size() - show, res.size());
            }
            std::printf("  Total: %zu results\n\n", res.size());

        // -------------------------------------------------------------------
        } else if (cmd == "write" || cmd == "w") {
            if (args.size() < 4) {
                std::printf("  Usage: write <addr> <type> <value>\n");
                continue;
            }
            uintptr_t addr = parseAddr(args[1]);
            DataType dt = parseDataType(args[2]);
            std::string val = args[3];
            if (sc.writeValue(addr, dt, val)) {
                std::printf("[+] Wrote %s to 0x%llX\n", val.c_str(), (unsigned long long)addr);
            } else {
                std::printf("[!] Write failed.\n");
            }

        // -------------------------------------------------------------------
        } else if (cmd == "read" || cmd == "r") {
            if (args.size() < 3) {
                std::printf("  Usage: read <addr> <type> [len]\n");
                continue;
            }
            uintptr_t addr = parseAddr(args[1]);
            DataType dt = parseDataType(args[2]);
            size_t sz = 16;
            if (args.size() > 3) sz = (size_t)std::stoul(args[3]);
            else {
                size_t ts = [](DataType t) -> size_t {
                    switch (t) {
                    case DataType::I8: case DataType::U8: return 1;
                    case DataType::I16: case DataType::U16: return 2;
                    case DataType::I32: case DataType::U32: case DataType::F32: return 4;
                    case DataType::I64: case DataType::U64: case DataType::F64: return 8;
                    default: return 16;
                    }
                }(dt);
                sz = ts;
            }

            std::vector<uint8_t> buf;
            if (sc.readValue(addr, sz, buf)) {
                std::printf("  0x%016llX: ", (unsigned long long)addr);
                if (dt == DataType::BYTES) {
                    for (size_t i = 0; i < buf.size(); i++) {
                        if (i) std::printf(" ");
                        std::printf("%02X", buf[i]);
                    }
                    std::printf("\n");
                } else {
                    std::printf("%s\n", sc.formatValue(dt, buf.data(), buf.size()).c_str());
                }
            } else {
                std::printf("[!] Read failed.\n");
            }

        // -------------------------------------------------------------------
        } else if (cmd == "watch") {
            if (args.size() < 3) {
                std::printf("  Usage: watch <addr> <type>\n");
                continue;
            }
            uintptr_t addr = parseAddr(args[1]);
            DataType dt = parseDataType(args[2]);
            size_t sz = [](DataType t) -> size_t {
                switch (t) {
                case DataType::I8: case DataType::U8: return 1;
                case DataType::I16: case DataType::U16: return 2;
                case DataType::I32: case DataType::U32: case DataType::F32: return 4;
                case DataType::I64: case DataType::U64: case DataType::F64: return 8;
                default: return 16;
                }
            }(dt);

            std::printf("[*] Watching 0x%llX (press Ctrl+C to stop)\n", (unsigned long long)addr);
            std::string lastVal;
            while (true) {
                std::vector<uint8_t> buf;
                if (sc.readValue(addr, sz, buf)) {
                    std::string val = sc.formatValue(dt, buf.data(), buf.size());
                    if (val != lastVal) {
                        std::printf("  [%s] 0x%llX = %s\n",
                                    "now", (unsigned long long)addr, val.c_str());
                        lastVal = val;
                    }
                }
                std::this_thread::sleep_for(std::chrono::milliseconds(500));
                // Check if Enter was pressed (non-blocking)
                // Note: simplified — user presses Ctrl+C to exit
            }

        // -------------------------------------------------------------------
        } else if (cmd == "export") {
            if (args.size() < 2) {
                std::printf("  Usage: export <file>\n");
                continue;
            }
            std::ofstream f(args[1]);
            if (!f) {
                std::printf("[!] Cannot open %s for writing.\n", args[1].c_str());
                continue;
            }
            f << "Address,Value,Previous\n";
            DataType dispType = sc.lastScanType();
            for (auto& r : sc.results()) {
                f << std::hex << "0x" << r.address << ","
                  << sc.formatValue(dispType, r.curValue.data(), r.curValue.size()) << ","
                  << (r.prevValue.empty() ? "-" :
                      sc.formatValue(dispType, r.prevValue.data(), r.prevValue.size()))
                  << "\n";
            }
            f.close();
            std::printf("[+] Exported %zu results to %s\n", sc.resultCount(), args[1].c_str());

        // -------------------------------------------------------------------
        } else if (cmd == "reset") {
            sc.reset();
            std::printf("[+] Results cleared.\n");

        // -------------------------------------------------------------------
        } else {
            std::printf("  Unknown command: '%s'. Type 'help'.\n", cmd.c_str());
        }
    }

    std::printf("\n[*] Goodbye.\n");
    return 0;
}
