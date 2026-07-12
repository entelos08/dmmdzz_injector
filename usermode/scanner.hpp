// =============================================================================
// usermode/scanner.hpp
//
// Cheat Engine style memory scanner. Uses the kernel driver for reads/writes
// (bypasses usermode hooks) and VirtualQueryEx for region enumeration.
//
// Supported data types: i8 u8 i16 u16 i32 u32 i64 u64 f32 f64 str wstr bytes
// Supported scan ops:   eq ne gt lt ge le range increased decreased changed unchanged
// =============================================================================
#pragma once
#include <cstdint>
#include <string>
#include <vector>
#include <mutex>
#include <atomic>
#include <windows.h>
#include "driver_ctl.hpp"

using dmmdzz::DriverCtl;

// -----------------------------------------------------------------------
// Enums
// -----------------------------------------------------------------------
enum class DataType : int {
    I8, U8, I16, U16, I32, U32, I64, U64, F32, F64, STR, WSTR, BYTES
};

enum class ScanOp : int {
    EQ, NE, GT, LT, GE, LE, RANGE,
    INCREASED, DECREASED, CHANGED, UNCHANGED
};

// -----------------------------------------------------------------------
// Memory region info (from VirtualQueryEx)
// -----------------------------------------------------------------------
struct MemRegion {
    uintptr_t base;
    size_t    size;
    DWORD     protect;
    bool      readable;
    bool      writable;
    bool      executable;
};

// -----------------------------------------------------------------------
// Single scan result entry
// -----------------------------------------------------------------------
struct ScanEntry {
    uintptr_t              address;
    std::vector<uint8_t>   curValue;   // current value bytes
    std::vector<uint8_t>   prevValue;  // value from previous scan
};

// -----------------------------------------------------------------------
// Scanner class
// -----------------------------------------------------------------------
class Scanner {
public:
    Scanner(DriverCtl& drv, uint32_t pid);
    ~Scanner();

    // --- setup ---
    bool attachProcess(uint32_t pid);
    std::vector<MemRegion> enumRegions();

    // --- scanning ---
    // firstScan: scan all readable memory
    void firstScan(DataType type, ScanOp op,
                   const std::string& val1,
                   const std::string& val2 = "");

    // nextScan: filter existing results
    void nextScan(DataType type, ScanOp op,
                  const std::string& val1,
                  const std::string& val2 = "");

    void reset();

    // --- read / write ---
    bool writeValue(uintptr_t addr, DataType type, const std::string& valStr);
    bool readValue(uintptr_t addr, size_t len, std::vector<uint8_t>& out);
    std::string formatValue(DataType type, const uint8_t* data, size_t len);

    // --- results ---
    size_t resultCount() const { return results_.size(); }
    const std::vector<ScanEntry>& results() const { return results_; }
    bool isFirstScan() const { return firstScan_; }
    DataType lastScanType() const { return lastType_; }

    // --- progress ---
    std::atomic<size_t>  scannedBytes{0};
    std::atomic<size_t>  totalBytes{0};
    std::atomic<bool>    scanning{false};

private:
    DriverCtl&  drv_;
    uint32_t    pid_   = 0;
    HANDLE      hProc_ = nullptr;  // OpenProcess handle for VirtualQueryEx

    std::vector<ScanEntry>   results_;
    std::vector<MemRegion>   regions_;
    bool                     firstScan_ = true;
    DataType                 lastType_  = DataType::I32;

    // helpers
    size_t                  typeSize(DataType t);
    std::vector<uint8_t>    parseValue(DataType t, const std::string& s);
    bool                    compareBytes(const uint8_t* data, size_t avail,
                                         DataType type, ScanOp op,
                                         const std::vector<uint8_t>& target,
                                         const uint8_t* prevData, size_t prevAvail);
    void                    scanRegion(const MemRegion& r, DataType type, ScanOp op,
                                       const std::vector<uint8_t>& target,
                                       const std::vector<uint8_t>& target2,
                                       std::mutex& mtx);
    bool                    readChunk(uintptr_t addr, size_t len, std::vector<uint8_t>& out);
};

// -----------------------------------------------------------------------
// Utility: parse helpers
// -----------------------------------------------------------------------
DataType parseDataType(const std::string& s);
ScanOp   parseScanOp(const std::string& s);
const char* dataTypeName(DataType t);
const char* scanOpName(ScanOp op);
