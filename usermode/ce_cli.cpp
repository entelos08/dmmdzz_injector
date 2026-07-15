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
//   dump  <addr> <size|auto> <file>    Dump memory region to file (chunked)
//   watch <addr> <type>                 Watch address (refresh every 1s)
//   export <file>                       Export results to file
//   regions                             List memory regions
//   findmeta [ver...] [-n max] [-o f]   Find IL2CPP global-metadata.dat magic
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
    std::string cur;
    bool inQuote = false;
    for (size_t i = 0; i < line.size(); i++) {
        char c = line[i];
        if (c == '"') {
            inQuote = !inQuote;
            // Quotes are delimiters that don't go into the token
        } else if ((c == ' ' || c == '\t') && !inQuote) {
            if (!cur.empty()) { args.push_back(cur); cur.clear(); }
        } else {
            cur.push_back(c);
        }
    }
    if (!cur.empty()) args.push_back(cur);
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
// Helper: parse a single hex byte argument (e.g., "10", "0x10", "FF").
// Returns true on success. Used by 'findmeta' to append version bytes to the
// search pattern.
// ---------------------------------------------------------------------------
static bool parseHexByte(const std::string& s, uint8_t& out) {
    std::string clean = s;
    if (clean.size() >= 2 && clean[0] == '0' && (clean[1] == 'x' || clean[1] == 'X'))
        clean = clean.substr(2);
    if (clean.empty() || clean.size() > 2) return false;
    for (char c : clean) {
        if (!std::isxdigit((unsigned char)c)) return false;
    }
    out = (uint8_t)std::stoul(clean, nullptr, 16);
    return true;
}

// ---------------------------------------------------------------------------
// Helper: compute the total allocation size for a given address.
//
// Walks forward through all MEMORY_BASIC_INFORMATION regions that share the
// same AllocationBase as 'addr' and sums their RegionSize. This gives the
// full size of the original VirtualAlloc/mmap reservation — useful for
// estimating how much memory to dump when a magic header (e.g., IL2CPP
// global-metadata.dat) is found inside a large allocation.
// ---------------------------------------------------------------------------
static SIZE_T queryAllocationSize(HANDLE hProc, uintptr_t addr) {
    MEMORY_BASIC_INFORMATION mbi;
    if (!VirtualQueryEx(hProc, (LPCVOID)addr, &mbi, sizeof(mbi))) return 0;
    uintptr_t allocBase = (uintptr_t)mbi.AllocationBase;
    if (!allocBase) return mbi.RegionSize;

    SIZE_T total = 0;
    uintptr_t cur = allocBase;
    while (VirtualQueryEx(hProc, (LPCVOID)cur, &mbi, sizeof(mbi))) {
        if ((uintptr_t)mbi.AllocationBase != allocBase) break;
        total += mbi.RegionSize;
        cur = (uintptr_t)mbi.BaseAddress + mbi.RegionSize;
    }
    return total;
}

// ---------------------------------------------------------------------------
// Helper: compute the precise size of an IL2CPP global-metadata.dat block
// by parsing its header.
//
// The metadata header layout:
//   int32_t sanity;    // 0xFAB11BAF (AF 1B B1 FA in little-endian)
//   int32_t version;
//   ... (int32 offset, int32 size) pairs for each section ...
//
// The file size equals the maximum of all (offset + size) values across
// all sections. Section offsets are monotonically increasing (sections are
// laid out sequentially in the file), so we stop parsing as soon as an
// offset decreases — this tells us we've left the header and are now
// reading section data, which avoids false positives from string/method
// tables being misinterpreted as offset/size pairs.
//
// 'allocSize' is used as an upper bound (the metadata cannot be larger
// than its containing allocation). Pass 0 to skip the cap.
//
// Returns 0 if the magic is not found or the size cannot be determined.
// ---------------------------------------------------------------------------
static size_t computeIl2cppMetadataSize(const uint8_t* header, size_t headerLen,
                                        size_t allocSize)
{
    if (headerLen < 16) return 0;

    // Check magic: AF 1B B1 FA
    if (header[0] != 0xAF || header[1] != 0x1B ||
        header[2] != 0xB1 || header[3] != 0xFA) {
        return 0;
    }

    // Parse (offset, size) pairs starting after sanity(4) + version(4).
    // Section offsets are monotonically increasing; when we encounter an
    // offset that decreases, we've left the header.
    size_t  maxSize    = 0;
    int32_t prevOffset = -1;

    for (size_t off = 8; off + 8 <= headerLen; off += 8) {
        int32_t sectionOffset = *(const int32_t*)(header + off);
        int32_t sectionSize   = *(const int32_t*)(header + off + 4);

        // Skip empty sections (both 0)
        if (sectionOffset == 0 && sectionSize == 0) continue;

        // Stop if offset decreases — we've left the header
        if (sectionOffset > 0 && prevOffset >= 0 && sectionOffset < prevOffset) {
            break;
        }

        if (sectionOffset > 0) {
            prevOffset = sectionOffset;
        }

        if (sectionOffset > 0 && sectionSize > 0) {
            size_t end = (size_t)sectionOffset + (size_t)sectionSize;
            if (end > maxSize) maxSize = end;
        }
    }

    if (maxSize == 0) return 0;

    // Cap at allocation size (safety)
    if (allocSize > 0 && maxSize > allocSize) {
        maxSize = allocSize;
    }

    return maxSize;
}

// ---------------------------------------------------------------------------
// Helper: check if a string is a known scan op (so we can support the
// shorthand "scan i32 100" which omits the implicit "eq").
// ---------------------------------------------------------------------------
static bool isKnownScanOp(const std::string& s) {
    return s == "eq" || s == "="  ||
           s == "ne" || s == "!=" ||
           s == "gt" || s == ">"  ||
           s == "lt" || s == "<"  ||
           s == "ge" || s == ">=" ||
           s == "le" || s == "<=" ||
           s == "range" || s == "rng" ||
           s == "increased" || s == "inc" ||
           s == "decreased" || s == "dec" ||
           s == "changed"   || s == "chg" ||
           s == "unchanged" || s == "unc";
}

// ---------------------------------------------------------------------------
// Helper: convert a null-terminated WCHAR array to a std::string (narrow).
// ---------------------------------------------------------------------------
static std::string wcharToStr(const WCHAR* w) {
    if (!w || !w[0]) return "";
    std::string out;
    for (size_t i = 0; i < DMMDZZ_MAX_MODULE_NAME && w[i]; i++) {
        out.push_back((char)(w[i] & 0xFF));
    }
    return out;
}

// ---------------------------------------------------------------------------
// Helper: case-insensitive string comparison (for module name matching).
// ---------------------------------------------------------------------------
static std::string toLowerStr(const std::string& s) {
    std::string r = s;
    std::transform(r.begin(), r.end(), r.begin(),
                   [](unsigned char c){ return (char)std::tolower(c); });
    return r;
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
        "    scan <type> [op] <val> [val2]   First scan (op defaults to eq)\n"
        "    next <type> [op] <val> [val2]   Next scan — filter previous results\n"
        "    list [n]                        List results (default 20, 0 = all)\n"
        "    write <addr> <type> <val>       Write value to address\n"
        "    read  <addr> <type> [len]       Read value at address\n"
        "    dump  <addr> <size|auto> <file>  Dump memory to file (auto = precise IL2CPP size)\n"
        "    watch <addr> <type>             Watch address (Ctrl+C to stop)\n"
        "    ptrscan <addr> [-d <depth>] [-m <module>]\n"
        "                                    Find pointer chains to address\n"
        "    findmeta [ver...] [-n max] [-o f]  Find IL2CPP metadata magic\n"
        "    export <file>                   Export results to file\n"
        "    regions                         List memory regions\n"
        "    info [modules]                  Show process info / loaded modules\n"
        "    reset                           Clear scan results\n"
        "    help                            Show this help\n"
        "    quit                            Exit\n"
        "\n"
        "  Types: i8 u8 i16 u16 i32 u32 i64 u64 f32 f64 str wstr bytes\n"
        "  Ops:   eq ne gt lt ge le range increased decreased changed unchanged\n"
        "\n"
        "  Examples:\n"
        "    scan i32 100                    Shorthand for: scan i32 eq 100\n"
        "    scan i32 eq 100                 Find all int32 == 100\n"
        "    next i32 eq 200                 Filter: now == 200\n"
        "    next i32 increased              Filter: value increased\n"
        "    scan f32 range 1.0 10.0         Find float in [1.0, 10.0]\n"
        "    scan bytes eq \"DE AD BE EF\"    Find byte pattern\n"
        "    write 0x12345678 i32 999        Write 999 at address\n"
        "    read 0x12345678 bytes 16        Read 16 bytes as hex\n"
        "    dump 0x0CACC020 auto meta.dat   Auto-detect size & dump (no padding)\n"
        "    info modules                    List all loaded modules + bases\n"
        "    ptrscan 0x12345678              Find ptr chains (depth 3)\n"
        "    ptrscan 0x12345678 -d 2         Limit to depth 2\n"
        "    ptrscan 0x12345678 -m GameAssembly.dll\n"
        "                                    Only mark chains in that module\n"
        "    findmeta                        Find AF 1B B1 FA (global-metadata.dat)\n"
        "    findmeta 10                     Find AF 1B B1 FA 10 (with version byte)\n"
        "    findmeta 10 00 00 00            Full 4-byte version (IL2CPP header)\n"
        "    findmeta 10 -n 100              Limit to 100 results\n"
        "    findmeta 10 -o meta.txt         Write results to meta.txt\n"
        "\n");
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------
int main(int argc, char* argv[]) {
    // Set console to UTF-8 so Chinese characters display correctly.
    SetConsoleOutputCP(65001);
    SetConsoleCP(65001);

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

            // Optional: list loaded modules via driver PEB LDR walk
            if (args.size() > 1 && (args[1] == "modules" || args[1] == "mods")) {
                try {
                    std::vector<DMMDZZ_MODULE_ENTRY> mods;
                    drv.EnumModules(pid, mods, 512);

                    // Key modules to highlight (Unity / IL2CPP / common engines)
                    auto isKeyModule = [](const std::string& name) {
                        std::string n = toLowerStr(name);
                        return n.find("gameassembly") != std::string::npos ||
                               n.find("unityplayer") != std::string::npos ||
                               n.find("unityengine") != std::string::npos ||
                               n.find("mono-2.0")   != std::string::npos ||
                               n.find("mono.dll")   != std::string::npos ||
                               n.find("libil2cpp")  != std::string::npos ||
                               n.find("ue4")        != std::string::npos ||
                               n.find("ue5")        != std::string::npos;
                    };

                    std::printf("\n  Loaded Modules (%zu):\n", mods.size());
                    std::printf("  %-18s %-12s %-12s %s\n",
                                "Base", "Size", "End", "Name");
                    std::printf("  ----------------------------------------------------------------\n");
                    for (auto& m : mods) {
                        std::string name = wcharToStr(m.BaseDllName);
                        bool key = isKeyModule(name);
                        std::printf("  0x%016llX   0x%08llX   0x%08llX  %s%s\n",
                                    (unsigned long long)m.DllBase,
                                    (unsigned long long)m.SizeOfImage,
                                    (unsigned long long)(m.DllBase + m.SizeOfImage),
                                    key ? "[*] " : "    ",
                                    name.c_str());
                    }
                    std::printf("  ([*] = key engine module — likely static base)\n\n");
                } catch (const std::exception& e) {
                    std::printf("[!] EnumModules failed: %s\n", e.what());
                }
            }

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
                std::printf("  Usage: %s <type> [op] <value> [value2]\n", cmd.c_str());
                std::printf("         (op defaults to 'eq'; e.g. 'scan i32 100')\n");
                continue;
            }
            DataType dt = parseDataType(args[1]);

            // Support shorthand: if args[2] is not a known op, treat it as the
            // value and default to EQ. This fixes the bug where 'scan i32 100'
            // was parsed as op="100" (→EQ) with empty value → user-mode fallback.
            ScanOp      op;
            std::string val1;
            std::string val2;
            if (isKnownScanOp(args[2])) {
                op   = parseScanOp(args[2]);
                val1 = args.size() > 3 ? args[3] : "";
                val2 = args.size() > 4 ? args[4] : "";
            } else {
                op   = ScanOp::EQ;
                val1 = args[2];
                val2 = args.size() > 3 ? args[3] : "";
            }

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

            bool scanOk = true;
            try {
                if (cmd == "scan") {
                    sc.firstScan(dt, op, val1, val2);
                } else {
                    sc.nextScan(dt, op, val1, val2);
                }
            } catch (const std::exception& e) {
                sc.scanning = false;
                scanOk = false;
                std::printf("\n[!] Scan error: %s\n", e.what());
            }

            prog.join();
            if (scanOk)
                std::printf("[+] Done. Results: %zu\n\n", sc.resultCount());
            else
                std::printf("\n");

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
        } else if (cmd == "dump") {
            // dump <addr> <size|auto> <file>
            //
            // Dumps a memory region to a file using chunked reads. This
            // bypasses the METHOD_BUFFERED single-IOCTL size limit (which
            // would otherwise cap reads at ~1 MB) by issuing multiple
            // ReadMemory IOCTLs of 1 MB each. Failed chunks are filled with
            // zeros so the output file always has the requested size.
            //
            // If size is 'auto', the command reads the IL2CPP metadata header
            // at <addr> and computes the precise file size from the section
            // table — no trailing zero padding. Falls back to the allocation
            // size if the magic is not found.
            //
            // Examples:
            //   dump 0x0CACC020 auto metadata.dat     (auto-detect size)
            //   dump 0x0CACC020 0x239D000 metadata.dat (explicit size)
            if (args.size() < 4) {
                std::printf("  Usage: dump <addr> <size|auto> <file>\n");
                std::printf("         size can be hex (0x...), decimal, or 'auto'\n");
                std::printf("  Examples:\n");
                std::printf("         dump 0x0CACC020 auto metadata.dat\n");
                std::printf("         dump 0x0CACC020 0x239D000 metadata.dat\n");
                continue;
            }

            uintptr_t   addr = parseAddr(args[1]);
            std::string path = args[3];
            size_t      size = 0;

            if (args[2] == "auto") {
                // --- Auto-detect precise size ---
                // Read enough of the header to cover all known IL2CPP versions
                // (max ~26 offset/size pairs = ~216 bytes; 512 is generous).
                const size_t HDR_LEN = 512;
                uint8_t      header[HDR_LEN] = {};
                try {
                    drv.ReadMemory(pid, addr, header, HDR_LEN);
                } catch (const std::exception& e) {
                    std::printf("[!] Failed to read header for auto-detect: %s\n", e.what());
                    std::printf("[    Try explicit size instead.\n");
                    continue;
                }

                // Get allocation info as fallback + upper bound
                SIZE_T allocSize = 0;
                HANDLE hProc     = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
                if (hProc) {
                    allocSize = queryAllocationSize(hProc, addr);
                    CloseHandle(hProc);
                }

                size = computeIl2cppMetadataSize(header, HDR_LEN, allocSize);
                if (size > 0) {
                    int32_t ver = *(const int32_t*)(header + 4);
                    std::printf("[*] Auto: IL2CPP metadata v%d\n", ver);
                    std::printf("[*] Auto: precise size = 0x%zX (%.2f MB)\n",
                                size, (double)size / (1024.0 * 1024.0));
                    if (allocSize > size) {
                        std::printf("[*] Allocation was 0x%llX — trimming %zu trailing bytes\n",
                                    (unsigned long long)allocSize, (size_t)(allocSize - size));
                    }
                } else if (allocSize > 0) {
                    size = allocSize;
                    std::printf("[*] Auto: not IL2CPP metadata, using allocation size 0x%zX (%.2f MB)\n",
                                size, (double)size / (1024.0 * 1024.0));
                } else {
                    std::printf("[!] Auto-detect failed: cannot query allocation size.\n");
                    std::printf("[    Try explicit size instead.\n");
                    continue;
                }
            } else {
                size = (size_t)std::stoull(args[2], nullptr, 0);
            }

            if (size == 0) {
                std::printf("[!] Size cannot be 0.\n");
                continue;
            }

            std::ofstream f(path, std::ios::binary);
            if (!f) {
                std::printf("[!] Cannot open '%s' for writing.\n", path.c_str());
                continue;
            }

            const size_t CHUNK = 0x100000; // 1 MB per IOCTL (safe for METHOD_BUFFERED)
            std::vector<uint8_t> buf;
            size_t total         = 0;
            size_t failedChunks  = 0;

            std::printf("[*] Dumping 0x%llX  size=0x%zX (%.2f MB)  ->  %s\n",
                        (unsigned long long)addr, size,
                        (double)size / (1024.0 * 1024.0), path.c_str());
            std::printf("[*] Using %zu KB chunks...\n", CHUNK / 1024);

            while (total < size) {
                size_t toRead = std::min(CHUNK, size - total);
                buf.resize(toRead);

                bool ok = false;
                try {
                    drv.ReadMemory(pid, addr + total, buf.data(), toRead);
                    ok = true;
                } catch (const std::exception& e) {
                    std::memset(buf.data(), 0, toRead);
                    failedChunks++;
                    if (failedChunks <= 3) {
                        std::printf("\n[!] Read failed at 0x%llX (+0x%zX): %s  (zero-filled)\n",
                                    (unsigned long long)(addr + total), total, e.what());
                    }
                }

                f.write((const char*)buf.data(), toRead);
                total += toRead;

                // Progress
                double pct = 100.0 * total / size;
                size_t mb      = total / (1024 * 1024);
                size_t totalMb = size / (1024 * 1024);
                std::printf("\r  [Progress] %zu/%zu MB  (%.1f%%)  ",
                            mb, totalMb, pct);
                std::fflush(stdout);
            }

            f.close();
            std::printf("\n[+] Dumped %zu bytes (0x%zX) from 0x%llX to %s\n",
                        total, total, (unsigned long long)addr, path.c_str());
            if (failedChunks > 0) {
                std::printf("[!] %zu chunk(s) failed to read (filled with zeros)\n",
                            failedChunks);
            }
            std::printf("\n");

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
        } else if (cmd == "ptrscan" || cmd == "ps") {
            if (args.size() < 2) {
                std::printf("  Usage: ptrscan <addr> [-d <depth>] [-m <module>]\n");
                std::printf("         depth default=3, module filter optional\n");
                continue;
            }

            uintptr_t targetAddr = parseAddr(args[1]);
            ULONG maxDepth = 3;
            std::string moduleFilter;

            // Parse optional -d and -m flags (any order)
            for (size_t i = 2; i < args.size(); i++) {
                if (args[i] == "-d" && i + 1 < args.size()) {
                    maxDepth = (ULONG)std::stoul(args[++i]);
                    if (maxDepth < 1) maxDepth = 1;
                    if (maxDepth > DMMDZZ_PTRSCAN_MAX_DEPTH)
                        maxDepth = DMMDZZ_PTRSCAN_MAX_DEPTH;
                } else if (args[i] == "-m" && i + 1 < args.size()) {
                    moduleFilter = args[++i];
                } else {
                    std::printf("  Unknown option: %s\n", args[i].c_str());
                    continue;
                }
            }

            // Build module ranges for static checking.
            // If -m <module> is specified, only pass that module's range.
            // Otherwise enumerate all modules so any in-module chain is static.
            std::vector<DMMDZZ_MODULE_RANGE> ranges;
            if (!moduleFilter.empty()) {
                try {
                    // widen module name
                    std::wstring wMod(moduleFilter.begin(), moduleFilter.end());
                    uintptr_t base = 0;
                    uint32_t  size = 0;
                    drv.EnumModule(pid, wMod, &base, &size);
                    if (base && size) {
                        DMMDZZ_MODULE_RANGE r;
                        r.Base = base;
                        r.Size = size;
                        ranges.push_back(r);
                        std::printf("[*] Module filter: %s  base=0x%llX size=0x%X\n",
                                    moduleFilter.c_str(),
                                    (unsigned long long)base, size);
                    } else {
                        std::printf("[!] Module '%s' not found, no static filter.\n",
                                    moduleFilter.c_str());
                    }
                } catch (const std::exception& e) {
                    std::printf("[!] EnumModule('%s') failed: %s\n",
                                moduleFilter.c_str(), e.what());
                }
            } else {
                // No filter: pass all loaded modules as ranges
                try {
                    std::vector<DMMDZZ_MODULE_ENTRY> mods;
                    drv.EnumModules(pid, mods, 512);
                    ranges.reserve(mods.size());
                    for (auto& m : mods) {
                        if (m.DllBase && m.SizeOfImage) {
                            DMMDZZ_MODULE_RANGE r;
                            r.Base = m.DllBase;
                            r.Size = m.SizeOfImage;
                            ranges.push_back(r);
                        }
                    }
                    std::printf("[*] Using %zu module ranges for static check.\n",
                                ranges.size());
                } catch (const std::exception& e) {
                    std::printf("[!] EnumModules failed: %s (proceeding without ranges)\n",
                                e.what());
                }
            }

            std::printf("[*] PtrScan: target=0x%llX depth=%lu maxChains=1000...\n",
                        (unsigned long long)targetAddr, maxDepth);

            std::vector<DMMDZZ_PTR_CHAIN> chains;
            try {
                drv.PtrScan(pid, targetAddr, maxDepth, ranges, chains, 1000);
            } catch (const std::exception& e) {
                std::printf("[!] PtrScan failed: %s\n", e.what());
                continue;
            }

            if (chains.empty()) {
                std::printf("[*] No pointer chains found to 0x%llX (depth %lu).\n",
                            (unsigned long long)targetAddr, maxDepth);
                continue;
            }

            // Sort: static chains first, then by depth (deeper first = more specific)
            std::sort(chains.begin(), chains.end(),
                [](const DMMDZZ_PTR_CHAIN& a, const DMMDZZ_PTR_CHAIN& b) {
                    if (a.IsStatic != b.IsStatic) return a.IsStatic > b.IsStatic;
                    return a.Depth > b.Depth;
                });

            std::printf("\n  Pointer Chains to 0x%llX (%zu found):\n",
                        (unsigned long long)targetAddr, chains.size());
            std::printf("  ----------------------------------------------------------\n");
            for (size_t i = 0; i < chains.size(); i++) {
                auto& c = chains[i];
                std::printf("  %s  depth=%u  ",
                            c.IsStatic ? "[STATIC]" : "[heap  ]",
                            c.Depth);
                // Print chain: base -> ... -> [target]
                for (ULONG j = 0; j <= c.Depth; j++) {
                    if (j == c.Depth) {
                        std::printf("-> [0x%llX]", (unsigned long long)c.Addresses[j]);
                    } else {
                        std::printf("0x%llX -> ", (unsigned long long)c.Addresses[j]);
                    }
                }
                std::printf("\n");
            }
            std::printf("\n  ([STATIC] = base in a module — survives restart)\n\n");

        // -------------------------------------------------------------------
        } else if (cmd == "findmeta") {
            // Search for the IL2CPP global-metadata.dat magic header in the
            // target process memory. The file starts with 0xFAB11BAF which
            // in little-endian byte order is: AF 1B B1 FA. When the game
            // loads, this file is mapped into memory; this command finds all
            // occurrences so they can be dumped with 'read'.
            //
            // Usage:
            //   findmeta [ver_byte...] [-n max_results] [-o output_file]
            //
            // Each ver_byte is a hex byte appended to the 4-byte magic to
            // filter by version (e.g., '10' -> AF 1B B1 FA 10).
            const uint8_t MAGIC[4] = { 0xAF, 0x1B, 0xB1, 0xFA };
            std::vector<uint8_t> pattern(MAGIC, MAGIC + 4);

            size_t      maxResults = 1000;
            std::string outFile;

            for (size_t i = 1; i < args.size(); i++) {
                if (args[i] == "-n" && i + 1 < args.size()) {
                    maxResults = (size_t)std::stoul(args[++i]);
                    if (maxResults == 0) maxResults = 1000;
                    if (maxResults > 50000) maxResults = 50000;
                } else if (args[i] == "-o" && i + 1 < args.size()) {
                    outFile = args[++i];
                } else {
                    uint8_t b;
                    if (parseHexByte(args[i], b)) {
                        pattern.push_back(b);
                    } else {
                        std::printf("  Invalid byte: '%s' (use hex like 10, 0x10, FF)\n",
                                    args[i].c_str());
                    }
                }
            }

            // Display the search pattern
            std::printf("[*] Pattern: ");
            for (size_t i = 0; i < pattern.size(); i++) {
                if (i) std::printf(" ");
                std::printf("%02X", pattern[i]);
            }
            std::printf("  (%zu bytes)\n", pattern.size());

            // Kernel driver scan — searches all committed readable regions
            std::printf("[*] Running kernel scan (max %zu results)...\n", maxResults);
            std::vector<uintptr_t> addrs;
            try {
                drv.ScanMemory(pid, pattern.data(), pattern.size(),
                               addrs, maxResults);
            } catch (const std::exception& e) {
                std::printf("[!] Scan failed: %s\n", e.what());
                continue;
            }

            if (addrs.empty()) {
                std::printf("[*] No matches found.\n\n");
                continue;
            }

            std::printf("[+] Found %zu match(es)\n\n", addrs.size());

            // Open process for VirtualQueryEx (region size estimation)
            HANDLE hProc = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);

            // Result table
            std::printf("  %-4s %-18s %-18s %-12s %s\n",
                        "#", "Address", "AllocBase", "AllocSize", "First 32 bytes");
            std::printf("  -----------------------------------------------------------------------------------------------\n");

            std::ofstream f;
            if (!outFile.empty()) {
                f.open(outFile);
                f << "Index,Address,AllocBase,AllocSize,First32Bytes\n";
            }

            for (size_t i = 0; i < addrs.size(); i++) {
                uintptr_t addr = addrs[i];

                // Read first 32 bytes for visual confirmation of the header
                uint8_t preview[32] = {};
                try {
                    drv.ReadMemory(pid, addr, preview, sizeof(preview));
                } catch (...) {
                    // leave zeros if read fails
                }

                // Estimate dump size via the containing allocation
                SIZE_T    allocSize  = 0;
                uintptr_t allocBase  = addr;
                if (hProc) {
                    allocSize = queryAllocationSize(hProc, addr);
                    MEMORY_BASIC_INFORMATION mbi;
                    if (VirtualQueryEx(hProc, (LPCVOID)addr, &mbi, sizeof(mbi))) {
                        allocBase = (uintptr_t)mbi.AllocationBase;
                        if (!allocBase) allocBase = (uintptr_t)mbi.BaseAddress;
                    }
                }

                // Format preview bytes
                char previewStr[128] = {};
                int  pos = 0;
                for (size_t j = 0; j < 32; j++) {
                    pos += std::snprintf(previewStr + pos,
                                         sizeof(previewStr) - pos,
                                         "%02X ", preview[j]);
                }

                std::printf("  %-4zu 0x%016llX  0x%016llX  0x%09llX  %s\n",
                            i + 1,
                            (unsigned long long)addr,
                            (unsigned long long)allocBase,
                            (unsigned long long)allocSize,
                            previewStr);

                if (f.is_open()) {
                    f << (i + 1) << ",0x" << std::hex << addr
                      << ",0x" << allocBase
                      << ",0x" << allocSize << ",";
                    for (size_t j = 0; j < 32; j++) {
                        f << std::hex << (int)preview[j];
                        if (j < 31) f << " ";
                    }
                    f << "\n";
                }
            }

            if (hProc) CloseHandle(hProc);

            // Helpful hint for dumping the first match
            if (!addrs.empty()) {
                std::printf("\n  To dump metadata precisely (no trailing zeros), use:\n");
                std::printf("    dump 0x%016llX auto metadata.dat\n",
                            (unsigned long long)addrs[0]);
            }

            if (f.is_open()) {
                f.close();
                std::printf("[+] Results written to: %s\n", outFile.c_str());
            }
            std::printf("\n");

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
