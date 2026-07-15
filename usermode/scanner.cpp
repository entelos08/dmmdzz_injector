// =============================================================================
// usermode/scanner.cpp
// =============================================================================
#include "scanner.hpp"
#include <algorithm>
#include <cstring>
#include <thread>
#include <sstream>
#include <cmath>
#include <cctype>
#include <psapi.h>

// ---------------------------------------------------------------------------
// Utility: parse data type / scan op strings
// ---------------------------------------------------------------------------
DataType parseDataType(const std::string& s) {
    if (s == "i8"  || s == "s8")  return DataType::I8;
    if (s == "u8"  || s == "b")   return DataType::U8;
    if (s == "i16" || s == "s16") return DataType::I16;
    if (s == "u16")               return DataType::U16;
    if (s == "i32" || s == "s32") return DataType::I32;
    if (s == "u32" || s == "d")   return DataType::U32;
    if (s == "i64" || s == "s64") return DataType::I64;
    if (s == "u64" || s == "q")   return DataType::U64;
    if (s == "f32" || s == "f")   return DataType::F32;
    if (s == "f64" || s == "dbl") return DataType::F64;
    if (s == "str" || s == "string") return DataType::STR;
    if (s == "wstr"|| s == "wstring")return DataType::WSTR;
    if (s == "bytes"||s == "aob")   return DataType::BYTES;
    return DataType::I32; // default
}

ScanOp parseScanOp(const std::string& s) {
    if (s == "eq" || s == "=")       return ScanOp::EQ;
    if (s == "ne" || s == "!=")      return ScanOp::NE;
    if (s == "gt" || s == ">")       return ScanOp::GT;
    if (s == "lt" || s == "<")       return ScanOp::LT;
    if (s == "ge" || s == ">=")      return ScanOp::GE;
    if (s == "le" || s == "<=")      return ScanOp::LE;
    if (s == "range"||s == "rng")    return ScanOp::RANGE;
    if (s == "increased"||s == "inc")return ScanOp::INCREASED;
    if (s == "decreased"||s == "dec")return ScanOp::DECREASED;
    if (s == "changed"||s == "chg")  return ScanOp::CHANGED;
    if (s == "unchanged"||s == "unc")return ScanOp::UNCHANGED;
    return ScanOp::EQ;
}

const char* dataTypeName(DataType t) {
    switch (t) {
    case DataType::I8:   return "i8";
    case DataType::U8:   return "u8";
    case DataType::I16:  return "i16";
    case DataType::U16:  return "u16";
    case DataType::I32:  return "i32";
    case DataType::U32:  return "u32";
    case DataType::I64:  return "i64";
    case DataType::U64:  return "u64";
    case DataType::F32:  return "f32";
    case DataType::F64:  return "f64";
    case DataType::STR:  return "str";
    case DataType::WSTR: return "wstr";
    case DataType::BYTES:return "bytes";
    }
    return "?";
}

const char* scanOpName(ScanOp op) {
    switch (op) {
    case ScanOp::EQ:        return "eq";
    case ScanOp::NE:        return "ne";
    case ScanOp::GT:        return "gt";
    case ScanOp::LT:        return "lt";
    case ScanOp::GE:        return "ge";
    case ScanOp::LE:        return "le";
    case ScanOp::RANGE:     return "range";
    case ScanOp::INCREASED: return "increased";
    case ScanOp::DECREASED: return "decreased";
    case ScanOp::CHANGED:   return "changed";
    case ScanOp::UNCHANGED: return "unchanged";
    }
    return "?";
}

// ---------------------------------------------------------------------------
// Constructor / Destructor
// ---------------------------------------------------------------------------
Scanner::Scanner(DriverCtl& drv, uint32_t pid)
    : drv_(drv), pid_(pid) {
    hProc_ = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
}

Scanner::~Scanner() {
    if (hProc_) CloseHandle(hProc_);
}

bool Scanner::attachProcess(uint32_t pid) {
    pid_ = pid;
    if (hProc_) CloseHandle(hProc_);
    hProc_ = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    return hProc_ != nullptr;
}

// ---------------------------------------------------------------------------
// Enumerate readable memory regions via VirtualQueryEx
// ---------------------------------------------------------------------------
std::vector<MemRegion> Scanner::enumRegions() {
    std::vector<MemRegion> regions;
    if (!hProc_) return regions;

    SYSTEM_INFO si;
    GetSystemInfo(&si);

    uintptr_t addr = (uintptr_t)si.lpMinimumApplicationAddress;
    uintptr_t maxAddr = (uintptr_t)si.lpMaximumApplicationAddress;

    MEMORY_BASIC_INFORMATION mbi;
    while (addr < maxAddr) {
        if (VirtualQueryEx(hProc_, (LPCVOID)addr, &mbi, sizeof(mbi)) == 0)
            break;

        if (mbi.State == MEM_COMMIT && (mbi.Protect & (PAGE_READONLY | PAGE_READWRITE |
             PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_WRITECOPY))) {
            MemRegion r;
            r.base      = (uintptr_t)mbi.BaseAddress;
            r.size      = mbi.RegionSize;
            r.protect   = mbi.Protect;
            r.readable  = true;
            r.writable  = (mbi.Protect & (PAGE_READWRITE | PAGE_EXECUTE_READWRITE | PAGE_WRITECOPY)) != 0;
            r.executable= (mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE)) != 0;
            regions.push_back(r);
        }
        addr = (uintptr_t)mbi.BaseAddress + mbi.RegionSize;
    }
    return regions;
}

// ---------------------------------------------------------------------------
// Size of each data type
// ---------------------------------------------------------------------------
size_t Scanner::typeSize(DataType t) {
    switch (t) {
    case DataType::I8: case DataType::U8:     return 1;
    case DataType::I16: case DataType::U16:    return 2;
    case DataType::I32: case DataType::U32: case DataType::F32: return 4;
    case DataType::I64: case DataType::U64: case DataType::F64: return 8;
    default: return 0; // variable-length types
    }
}

// ---------------------------------------------------------------------------
// Parse a string value into bytes according to data type
// ---------------------------------------------------------------------------
std::vector<uint8_t> Scanner::parseValue(DataType t, const std::string& s) {
    std::vector<uint8_t> out;

    switch (t) {
    case DataType::I8: {
        int v = std::stoi(s);
        out.push_back((uint8_t)(int8_t)v);
        break;
    }
    case DataType::U8: {
        unsigned v = (unsigned)std::stoul(s);
        out.push_back((uint8_t)v);
        break;
    }
    case DataType::I16: {
        int16_t v = (int16_t)std::stoi(s);
        out.resize(2); std::memcpy(out.data(), &v, 2);
        break;
    }
    case DataType::U16: {
        uint16_t v = (uint16_t)std::stoul(s);
        out.resize(2); std::memcpy(out.data(), &v, 2);
        break;
    }
    case DataType::I32: {
        int32_t v = std::stoi(s);
        out.resize(4); std::memcpy(out.data(), &v, 4);
        break;
    }
    case DataType::U32: {
        uint32_t v = (uint32_t)std::stoul(s);
        out.resize(4); std::memcpy(out.data(), &v, 4);
        break;
    }
    case DataType::I64: {
        int64_t v = std::stoll(s);
        out.resize(8); std::memcpy(out.data(), &v, 8);
        break;
    }
    case DataType::U64: {
        uint64_t v = (uint64_t)std::stoull(s);
        out.resize(8); std::memcpy(out.data(), &v, 8);
        break;
    }
    case DataType::F32: {
        float v = std::stof(s);
        out.resize(4); std::memcpy(out.data(), &v, 4);
        break;
    }
    case DataType::F64: {
        double v = std::stod(s);
        out.resize(8); std::memcpy(out.data(), &v, 8);
        break;
    }
    case DataType::STR: {
        out.assign(s.begin(), s.end());
        out.push_back(0); // null terminator
        break;
    }
    case DataType::WSTR: {
        std::wstring ws(s.begin(), s.end());
        out.resize(ws.size() * 2);
        std::memcpy(out.data(), ws.c_str(), ws.size() * 2);
        out.push_back(0); out.push_back(0); // null terminator
        break;
    }
    case DataType::BYTES: {
        // Parse "DE AD BE EF" or "DEADBEEF" or "DE,AD,BE,EF"
        std::string clean = s;
        clean.erase(std::remove_if(clean.begin(), clean.end(),
            [](char c) { return c == ' ' || c == ',' || c == '\t'; }), clean.end());
        for (size_t i = 0; i + 1 < clean.size(); i += 2) {
            unsigned b;
            std::sscanf(clean.c_str() + i, "%02X", &b);
            out.push_back((uint8_t)b);
        }
        break;
    }
    }
    return out;
}

// ---------------------------------------------------------------------------
// Compare data against target with the given operation
// ---------------------------------------------------------------------------
bool Scanner::compareBytes(const uint8_t* data, size_t avail,
                           DataType type, ScanOp op,
                           const std::vector<uint8_t>& target,
                           const uint8_t* prevData, size_t prevAvail)
{
    size_t sz = typeSize(type);
    if (sz == 0) sz = target.size(); // variable-length
    if (avail < sz) return false;

    // For string/bytes, do direct comparison
    if (type == DataType::STR || type == DataType::WSTR || type == DataType::BYTES) {
        switch (op) {
        case ScanOp::EQ:
            return std::memcmp(data, target.data(), sz) == 0;
        case ScanOp::NE:
            return std::memcmp(data, target.data(), sz) != 0;
        default:
            return false;
        }
    }

    // Numeric comparison — extract values
    int64_t  curI = 0, tgtI = 0, prevI = 0;
    uint64_t curU = 0, tgtU = 0, prevU = 0;
    double   curD = 0, tgtD = 0, prevD = 0;
    bool     isFloat = (type == DataType::F32 || type == DataType::F64);
    bool     isSigned = (type == DataType::I8 || type == DataType::I16 ||
                         type == DataType::I32 || type == DataType::I64);

    std::memcpy(&curI, data, sz);
    curU = (uint64_t)curI;
    curD = isFloat ? (sz == 4 ? (double)*(float*)&curI : *(double*)&curI) : (double)curI;

    if (!target.empty()) {
        std::memcpy(&tgtI, target.data(), std::min(sz, target.size()));
        tgtU = (uint64_t)tgtI;
        tgtD = isFloat ? (sz == 4 ? (double)*(float*)&tgtI : *(double*)&tgtI) : (double)tgtI;
    }

    if (prevData && prevAvail >= sz) {
        std::memcpy(&prevI, prevData, sz);
        prevU = (uint64_t)prevI;
        prevD = isFloat ? (sz == 4 ? (double)*(float*)&prevI : *(double*)&prevI) : (double)prevI;
    }

    switch (op) {
    case ScanOp::EQ:        return isFloat ? (curD == tgtD) : (curU == tgtU);
    case ScanOp::NE:        return isFloat ? (curD != tgtD) : (curU != tgtU);
    case ScanOp::GT:        return isFloat ? (curD >  tgtD) : (isSigned ? curI >  tgtI : curU >  tgtU);
    case ScanOp::LT:        return isFloat ? (curD <  tgtD) : (isSigned ? curI <  tgtI : curU <  tgtU);
    case ScanOp::GE:        return isFloat ? (curD >= tgtD) : (isSigned ? curI >= tgtI : curU >= tgtU);
    case ScanOp::LE:        return isFloat ? (curD <= tgtD) : (isSigned ? curI <= tgtI : curU <= tgtU);
    case ScanOp::RANGE:     return isFloat ? (curD >= tgtD && curD <= tgtD) :
                                     (isSigned ? (curI >= tgtI && curI <= tgtI) : (curU >= tgtU && curU <= tgtU));
    case ScanOp::INCREASED: return isFloat ? (curD >  prevD) : (isSigned ? curI >  prevI : curU >  prevU);
    case ScanOp::DECREASED: return isFloat ? (curD <  prevD) : (isSigned ? curI <  prevI : curU <  prevU);
    case ScanOp::CHANGED:   return std::memcmp(data, prevData, sz) != 0;
    case ScanOp::UNCHANGED: return std::memcmp(data, prevData, sz) == 0;
    }
    return false;
}

// ---------------------------------------------------------------------------
// Read a chunk of memory via driver
// ---------------------------------------------------------------------------
bool Scanner::readChunk(uintptr_t addr, size_t len, std::vector<uint8_t>& out) {
    out.resize(len);
    try {
        drv_.ReadMemory(pid_, addr, out.data(), len);
        return true;
    } catch (...) {
        return false;
    }
}

// ---------------------------------------------------------------------------
// Scan a single region (called from worker threads)
// ---------------------------------------------------------------------------
void Scanner::scanRegion(const MemRegion& r, DataType type, ScanOp op,
                         const std::vector<uint8_t>& target,
                         const std::vector<uint8_t>& target2,
                         std::mutex& mtx)
{
    const size_t CHUNK = 0x10000; // 64KB per read
    size_t sz = typeSize(type);
    if (sz == 0) sz = target.size();
    if (sz == 0) return;

    size_t offset = 0;
    while (offset < r.size) {
        size_t toRead = std::min(CHUNK, r.size - offset);
        std::vector<uint8_t> buf;
        if (!readChunk(r.base + offset, toRead, buf)) {
            offset += toRead;
            scannedBytes += toRead;
            continue;
        }

        // Scan within this chunk
        for (size_t i = 0; i + sz <= buf.size(); i++) {
            // For RANGE op, we need two targets
            bool match = false;
            if (op == ScanOp::RANGE && !target2.empty()) {
                // Use compareBytes with target for lower bound
                // Then check upper bound manually
                match = compareBytes(buf.data() + i, buf.size() - i, type, ScanOp::GE, target, nullptr, 0);
                if (match) {
                    match = compareBytes(buf.data() + i, buf.size() - i, type, ScanOp::LE, target2, nullptr, 0);
                }
            } else {
                match = compareBytes(buf.data() + i, buf.size() - i, type, op, target, nullptr, 0);
            }

            if (match) {
                uintptr_t addr = r.base + offset + i;
                std::vector<uint8_t> val(buf.begin() + i, buf.begin() + i + sz);
                {
                    std::lock_guard<std::mutex> lk(mtx);
                    results_.push_back({addr, val, {}});
                }
            }
        }

        scannedBytes += toRead;
        offset += toRead;
    }
}

// ---------------------------------------------------------------------------
// First scan — scan all readable regions
//
// For EQ operations with a concrete byte pattern, the scan is delegated to
// the kernel driver (IOCTL_DMMDZZ_SCAN_MEMORY), which attaches to the target
// process, enumerates committed readable regions via ZwQueryVirtualMemory,
// and matches with RtlCompareMemory. This is both faster and more accurate
// than the user-mode fallback because it avoids repeated ReadMemory round
// trips and scans the *correct* process address space directly.
//
// Non-EQ operations (GT/LT/GE/LE/RANGE) and baseline ops (INCREASED/
// DECREASED/CHANGED/UNCHANGED) still use the user-mode multi-threaded path
// because the driver only implements exact byte matching.
// ---------------------------------------------------------------------------
void Scanner::firstScan(DataType type, ScanOp op,
                        const std::string& val1,
                        const std::string& val2)
{
    scanning = true;
    firstScan_ = false;
    lastType_ = type;
    results_.clear();
    scannedBytes = 0;

    // For "changed/unchanged/increased/decreased" on first scan, just store all values
    bool storeAll = (op == ScanOp::INCREASED || op == ScanOp::DECREASED ||
                     op == ScanOp::CHANGED    || op == ScanOp::UNCHANGED);

    // Only parse values when actually needed (storeAll ops don't need a target)
    std::vector<uint8_t> target;
    std::vector<uint8_t> target2;
    if (!storeAll) {
        if (!val1.empty()) target  = parseValue(type, val1);
        if (!val2.empty()) target2 = parseValue(type, val2);
    }

    // ----- Driver-side scan path (EQ only) -----
    // The driver performs exact byte matching, so we can use it for EQ on any
    // data type as long as we have a non-empty target within size limits.
    bool useDriverScan = (op == ScanOp::EQ) &&
                         !target.empty() &&
                         target.size() <= DMMDZZ_SCAN_MAX_VALUE_SIZE;

    if (useDriverScan) {
        // Kernel-side scan: driver attaches to pid_, enumerates regions,
        // and returns matching addresses. We do NOT need enumRegions() here
        // because the driver does its own ZwQueryVirtualMemory walk.
        std::printf("[*] Using kernel driver scan (value=%zu bytes)\n",
                    target.size());
        std::vector<uintptr_t> addrs;
        drv_.ScanMemory(pid_, target.data(), target.size(), addrs);
        std::printf("[*] Driver returned %zu matches\n", addrs.size());

        // Build result entries. Since the driver only returns addresses where
        // the bytes exactly equal target, curValue is simply target itself.
        results_.reserve(addrs.size());
        for (uintptr_t a : addrs) {
            results_.push_back({a, target, {}});
        }

        // Driver scan doesn't report byte progress; mark as done.
        totalBytes   = 0;
        scannedBytes = 0;
        scanning = false;
        return;
    }

    // ----- User-mode fallback path -----
    regions_ = enumRegions();
    totalBytes = 0;
    for (auto& r : regions_) totalBytes += r.size;

    if (storeAll) {
        // Store all values as baseline; no filtering
        std::mutex mtx;
        std::vector<std::thread> threads;
        unsigned nThreads = std::thread::hardware_concurrency();
        if (nThreads == 0) nThreads = 4;

        size_t perThread = (regions_.size() + nThreads - 1) / nThreads;
        for (unsigned t = 0; t < nThreads; t++) {
            size_t start = t * perThread;
            size_t end   = std::min(start + perThread, regions_.size());
            if (start >= end) break;

            threads.emplace_back([this, start, end, type, &mtx]() {
                size_t sz = typeSize(type);
                if (sz == 0) return;
                for (size_t r = start; r < end; r++) {
                    const MemRegion& reg = regions_[r];
                    size_t off = 0;
                    while (off < reg.size) {
                        size_t toRead = std::min((size_t)0x10000, reg.size - off);
                        std::vector<uint8_t> buf;
                        if (readChunk(reg.base + off, toRead, buf)) {
                            for (size_t i = 0; i + sz <= buf.size(); i++) {
                                uintptr_t addr = reg.base + off + i;
                                std::vector<uint8_t> val(buf.begin() + i, buf.begin() + i + sz);
                                std::lock_guard<std::mutex> lk(mtx);
                                results_.push_back({addr, val, {}});
                            }
                        }
                        scannedBytes += toRead;
                        off += toRead;
                    }
                }
            });
        }
        for (auto& t : threads) t.join();
    } else {
        // Multi-threaded scan with filtering (NE/GT/LT/GE/LE/RANGE)
        std::mutex mtx;
        std::vector<std::thread> threads;
        unsigned nThreads = std::thread::hardware_concurrency();
        if (nThreads == 0) nThreads = 4;

        size_t perThread = (regions_.size() + nThreads - 1) / nThreads;
        for (unsigned t = 0; t < nThreads; t++) {
            size_t start = t * perThread;
            size_t end   = std::min(start + perThread, regions_.size());
            if (start >= end) break;

            threads.emplace_back([this, start, end, type, op, &target, &target2, &mtx]() {
                for (size_t r = start; r < end; r++) {
                    scanRegion(regions_[r], type, op, target, target2, mtx);
                }
            });
        }
        for (auto& t : threads) t.join();
    }

    scanning = false;
}

// ---------------------------------------------------------------------------
// Next scan — filter existing results
// ---------------------------------------------------------------------------
void Scanner::nextScan(DataType type, ScanOp op,
                       const std::string& val1,
                       const std::string& val2)
{
    scanning = true;
    lastType_ = type;

    // Only parse values when actually needed
    bool needTarget = (op != ScanOp::INCREASED && op != ScanOp::DECREASED &&
                       op != ScanOp::CHANGED    && op != ScanOp::UNCHANGED);
    std::vector<uint8_t> target;
    std::vector<uint8_t> target2;
    if (needTarget) {
        if (!val1.empty()) target  = parseValue(type, val1);
        if (!val2.empty()) target2 = parseValue(type, val2);
    }

    size_t sz = typeSize(type);
    if (sz == 0 && !target.empty()) sz = target.size();
    if (sz == 0) sz = 4; // fallback for variable-length ops without target

    std::vector<ScanEntry> newResults;
    newResults.reserve(results_.size() / 4); // guess

    std::mutex mtx;
    std::vector<std::thread> threads;
    unsigned nThreads = std::thread::hardware_concurrency();
    if (nThreads == 0) nThreads = 4;

    size_t perThread = (results_.size() + nThreads - 1) / nThreads;

    for (unsigned t = 0; t < nThreads; t++) {
        size_t start = t * perThread;
        size_t end   = std::min(start + perThread, results_.size());
        if (start >= end) break;

        threads.emplace_back([this, start, end, type, op, sz, &target, &target2, &newResults, &mtx]() {
            for (size_t i = start; i < end; i++) {
                std::vector<uint8_t> cur;
                if (!readChunk(results_[i].address, sz, cur)) continue;

                bool match = false;
                if (op == ScanOp::RANGE && !target2.empty()) {
                    match = compareBytes(cur.data(), cur.size(), type, ScanOp::GE, target, nullptr, 0);
                    if (match) match = compareBytes(cur.data(), cur.size(), type, ScanOp::LE, target2, nullptr, 0);
                } else {
                    // For increased/decreased/changed/unchanged, use prevValue
                    const uint8_t* prev = results_[i].curValue.data();
                    size_t prevSz = results_[i].curValue.size();
                    match = compareBytes(cur.data(), cur.size(), type, op, target, prev, prevSz);
                }

                if (match) {
                    ScanEntry e;
                    e.address   = results_[i].address;
                    e.prevValue = results_[i].curValue;  // old current becomes previous
                    e.curValue  = cur;
                    std::lock_guard<std::mutex> lk(mtx);
                    newResults.push_back(std::move(e));
                }
            }
        });
    }
    for (auto& t : threads) t.join();

    results_ = std::move(newResults);
    scanning = false;
}

// ---------------------------------------------------------------------------
// Reset
// ---------------------------------------------------------------------------
void Scanner::reset() {
    results_.clear();
    regions_.clear();
    firstScan_ = true;
    scannedBytes = 0;
    totalBytes = 0;
}

// ---------------------------------------------------------------------------
// Write value to address
// ---------------------------------------------------------------------------
bool Scanner::writeValue(uintptr_t addr, DataType type, const std::string& valStr) {
    std::vector<uint8_t> data = parseValue(type, valStr);
    if (data.empty()) return false;
    try {
        drv_.WriteMemory(pid_, addr, data.data(), data.size());
        return true;
    } catch (...) {
        return false;
    }
}

// ---------------------------------------------------------------------------
// Read value from address
// ---------------------------------------------------------------------------
bool Scanner::readValue(uintptr_t addr, size_t len, std::vector<uint8_t>& out) {
    return readChunk(addr, len, out);
}

// ---------------------------------------------------------------------------
// Format value for display
// ---------------------------------------------------------------------------
std::string Scanner::formatValue(DataType type, const uint8_t* data, size_t len) {
    std::ostringstream ss;

    switch (type) {
    case DataType::I8:  if (len >= 1) ss << (int)*(const int8_t*)data; break;
    case DataType::U8:  if (len >= 1) ss << (unsigned)*(const uint8_t*)data; break;
    case DataType::I16: if (len >= 2) ss << *(const int16_t*)data; break;
    case DataType::U16: if (len >= 2) ss << *(const uint16_t*)data; break;
    case DataType::I32: if (len >= 4) ss << *(const int32_t*)data; break;
    case DataType::U32: if (len >= 4) ss << *(const uint32_t*)data; break;
    case DataType::I64: if (len >= 8) ss << *(const int64_t*)data; break;
    case DataType::U64: if (len >= 8) ss << *(const uint64_t*)data; break;
    case DataType::F32: if (len >= 4) ss << *(const float*)data; break;
    case DataType::F64: if (len >= 8) ss << *(const double*)data; break;
    case DataType::STR:
        for (size_t i = 0; i < len && data[i]; i++) ss << (char)data[i];
        break;
    case DataType::WSTR:
        for (size_t i = 0; i + 1 < len; i += 2) {
            wchar_t wc = *(const wchar_t*)(data + i);
            if (wc == 0) break;
            ss << (char)wc; // simple ASCII cast
        }
        break;
    case DataType::BYTES:
        for (size_t i = 0; i < len; i++) {
            ss << std::uppercase << std::hex;
            if (i) ss << " ";
            ss << (int)data[i];
        }
        break;
    }
    return ss.str();
}
