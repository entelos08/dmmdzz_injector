// =============================================================================
// usermode/driver_ctl.cpp
// =============================================================================
#include "driver_ctl.hpp"

#include <stdexcept>
#include <cstring>
#include <vector>

namespace dmmdzz {

DriverCtl::~DriverCtl() { Close(); }

void DriverCtl::Open(const std::wstring& deviceName)
{
    hDevice_ = CreateFileW(
        deviceName.c_str(),
        GENERIC_READ | GENERIC_WRITE,
        0,
        nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        nullptr);

    if (hDevice_ == INVALID_HANDLE_VALUE) {
        DWORD err = GetLastError();
        throw std::runtime_error(
            "CreateFileW failed for " +
            std::string(deviceName.begin(), deviceName.end()) +
            " (GetLastError=" + std::to_string(err) + ")");
    }
}

bool DriverCtl::TryOpen(const std::wstring& deviceName)
{
    hDevice_ = CreateFileW(
        deviceName.c_str(),
        GENERIC_READ | GENERIC_WRITE,
        0,
        nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        nullptr);

    if (hDevice_ == INVALID_HANDLE_VALUE) {
        return false;  // device doesn't exist
    }
    return true;
}

void DriverCtl::Close()
{
    if (IsOpen()) {
        CloseHandle(hDevice_);
        hDevice_ = INVALID_HANDLE_VALUE;
    }
}

// -----------------------------------------------------------------------------
DWORD DriverCtl::SendIoctl(DWORD code,
                           const void* in,  DWORD inLen,
                           void* out,       DWORD outLen,
                           OUT DWORD* bytesReturned)
{
    if (!IsOpen())
        throw std::runtime_error("Device not open");

    BOOL ok = DeviceIoControl(
        hDevice_,
        code,
        const_cast<void*>(in),  inLen,
        out,                    outLen,
        bytesReturned,
        nullptr);

    if (!ok) {
        DWORD err = GetLastError();
        throw std::runtime_error(
            "DeviceIoControl(0x" + std::to_string(code) +
            ") failed (GetLastError=" + std::to_string(err) + ")");
    }
    return *bytesReturned;
}

// -----------------------------------------------------------------------------
void DriverCtl::GetVersion(OUT DMMDZZ_VERSION& v)
{
    DWORD ret = 0;
    SendIoctl(IOCTL_DMMDZZ_GET_VERSION, nullptr, 0, &v, sizeof(v), &ret);
    if (v.Hdr.Status != 0)
        throw std::runtime_error("Driver returned NTSTATUS 0x" +
            std::to_string((unsigned long)v.Hdr.Status));
}

// -----------------------------------------------------------------------------
uint32_t DriverCtl::FindProcess(const std::wstring& imageName,
                                OUT uintptr_t* eProcessVA)
{
    DMMDZZ_FIND_PROCESS req{};
    // Truncate to fit the wide buffer in the shared struct
    size_t n = std::min<size_t>(imageName.size(), DMMDZZ_NAME_MAX - 1);
    std::wmemcpy(req.ProcessName, imageName.c_str(), n);
    req.ProcessName[n] = L'\0';

    DWORD ret = 0;
    SendIoctl(IOCTL_DMMDZZ_FIND_PROCESS, &req, sizeof(req), &req, sizeof(req), &ret);

    if (req.Hdr.Status != 0)
        throw std::runtime_error("Process '" +
            std::string(imageName.begin(), imageName.end()) +
            "' not found by driver (NTSTATUS=0x" +
            std::to_string((unsigned long)req.Hdr.Status) + ")");

    if (eProcessVA) *eProcessVA = req.EProcessVA;
    return (uint32_t)(ULONG_PTR)req.ProcessId;
}

// -----------------------------------------------------------------------------
void DriverCtl::EnumModule(uint32_t pid,
                           const std::wstring& moduleName,
                           OUT uintptr_t* dllBase,
                           OUT uint32_t*     sizeOfImage)
{
    DMMDZZ_ENUM_MODULE req{};
    req.ProcessId = (HANDLE)(ULONG_PTR)pid;
    size_t n = std::min<size_t>(moduleName.size(), DMMDZZ_NAME_MAX - 1);
    std::wmemcpy(req.ModuleName, moduleName.c_str(), n);
    req.ModuleName[n] = L'\0';

    DWORD ret = 0;
    SendIoctl(IOCTL_DMMDZZ_ENUM_MODULE_BASE, &req, sizeof(req),
              &req, sizeof(req), &ret);

    if (req.Hdr.Status != 0)
        throw std::runtime_error("EnumModule failed (NTSTATUS=0x" +
            std::to_string((unsigned long)req.Hdr.Status) + ")");

    if (dllBase)     *dllBase     = req.DllBase;
    if (sizeOfImage) *sizeOfImage = req.SizeOfImage;
}

// -----------------------------------------------------------------------------
void DriverCtl::QueryBase(uint32_t pid,
                          OUT uintptr_t* dllBase,
                          OUT uint32_t*   sizeOfImage)
{
    DMMDZZ_QUERY_BASE req{};
    req.ProcessId = (HANDLE)(ULONG_PTR)pid;

    DWORD ret = 0;
    SendIoctl(IOCTL_DMMDZZ_QUERY_BASE, &req, sizeof(req),
              &req, sizeof(req), &ret);

    if (req.Hdr.Status != 0)
        throw std::runtime_error("QueryBase failed (NTSTATUS=0x" +
            std::to_string((unsigned long)req.Hdr.Status) + ")");

    if (dllBase)     *dllBase     = req.DllBase;
    if (sizeOfImage) *sizeOfImage = req.SizeOfImage;
}

// -----------------------------------------------------------------------------
// Read/Write memory.
//
// The driver expects a single contiguous system buffer:
//     [ DMMDZZ_MEM_OP header | payload bytes ]
// The header carries BufferOffset = sizeof(DMMDZZ_MEM_OP) and Size = payload.
// We therefore build one std::vector<uint8_t> and pass its pointer to
// DeviceIoControl with InputBufferLength == OutputBufferLength == total size.
// -----------------------------------------------------------------------------
void DriverCtl::ReadMemory(uint32_t pid, uintptr_t remoteVA,
                           void* outBuf, size_t size)
{
    if (size == 0) return;

    std::vector<uint8_t> buf(sizeof(DMMDZZ_MEM_OP) + size, 0);
    auto* hdr = reinterpret_cast<DMMDZZ_MEM_OP*>(buf.data());
    hdr->ProcessId   = (HANDLE)(ULONG_PTR)pid;
    hdr->Address     = remoteVA;
    hdr->Size        = size;
    hdr->BufferOffset= sizeof(DMMDZZ_MEM_OP);

    DWORD ret = 0;
    SendIoctl(IOCTL_DMMDZZ_READ_MEMORY,
              buf.data(), (DWORD)buf.size(),
              buf.data(), (DWORD)buf.size(),
              &ret);

    if (hdr->Hdr.Status != 0)
        throw std::runtime_error("ReadMemory failed (NTSTATUS=0x" +
            std::to_string((unsigned long)hdr->Hdr.Status) + ")");

    std::memcpy(outBuf, buf.data() + hdr->BufferOffset,
                hdr->BytesTransferred);
}

void DriverCtl::WriteMemory(uint32_t pid, uintptr_t remoteVA,
                            const void* inBuf, size_t size)
{
    if (size == 0) return;

    std::vector<uint8_t> buf(sizeof(DMMDZZ_MEM_OP) + size, 0);
    auto* hdr = reinterpret_cast<DMMDZZ_MEM_OP*>(buf.data());
    hdr->ProcessId   = (HANDLE)(ULONG_PTR)pid;
    hdr->Address     = remoteVA;
    hdr->Size        = size;
    hdr->BufferOffset= sizeof(DMMDZZ_MEM_OP);
    std::memcpy(buf.data() + hdr->BufferOffset, inBuf, size);

    DWORD ret = 0;
    SendIoctl(IOCTL_DMMDZZ_WRITE_MEMORY,
              buf.data(), (DWORD)buf.size(),
              buf.data(), (DWORD)buf.size(),
              &ret);

    if (hdr->Hdr.Status != 0)
        throw std::runtime_error("WriteMemory failed (NTSTATUS=0x" +
            std::to_string((unsigned long)hdr->Hdr.Status) + ")");
}

// -----------------------------------------------------------------------------
// ScanMemory — kernel-side memory scan via IOCTL_DMMDZZ_SCAN_MEMORY.
//
// Buffer layout:
//   [DMMDZZ_SCAN_REQUEST][value bytes][results: ULONG_PTR[]]
//
// The driver attaches to the target process, enumerates committed readable
// regions, and uses RtlCompareMemory to find exact matches. Matching
// addresses are written into the results area.
// -----------------------------------------------------------------------------
void DriverCtl::ScanMemory(uint32_t pid, const void* value, size_t valueSize,
                           std::vector<uintptr_t>& outAddrs,
                           size_t maxResults)
{
    outAddrs.clear();
    if (valueSize == 0 || maxResults == 0) return;

    // Align results offset to 8 bytes (for ULONG_PTR array)
    const ULONG headerSize  = sizeof(DMMDZZ_SCAN_REQUEST);
    const ULONG valueOffset = headerSize;
    const ULONG resultsOffset = (valueOffset + (ULONG)valueSize + 7) & ~7u;
    const ULONG totalSize  = resultsOffset +
                             (ULONG)(maxResults * sizeof(uintptr_t));

    std::vector<uint8_t> buf(totalSize, 0);
    auto* hdr = reinterpret_cast<DMMDZZ_SCAN_REQUEST*>(buf.data());

    hdr->ProcessId     = (HANDLE)(ULONG_PTR)pid;
    hdr->ValueSize     = valueSize;
    hdr->ValueOffset   = valueOffset;
    hdr->MaxResults    = (ULONG)maxResults;
    hdr->ResultsOffset = resultsOffset;

    // Copy value bytes into buffer
    std::memcpy(buf.data() + valueOffset, value, valueSize);

    DWORD ret = 0;
    SendIoctl(IOCTL_DMMDZZ_SCAN_MEMORY,
              buf.data(), totalSize,
              buf.data(), totalSize,
              &ret);

    if (hdr->Hdr.Status != 0)
        throw std::runtime_error("ScanMemory failed (NTSTATUS=0x" +
            std::to_string((unsigned long)hdr->Hdr.Status) + ")");

    // Extract results
    outAddrs.reserve(hdr->ResultsCount);
    uintptr_t* results = reinterpret_cast<uintptr_t*>(
        buf.data() + resultsOffset);
    for (ULONG i = 0; i < hdr->ResultsCount; i++) {
        outAddrs.push_back(results[i]);
    }
}

} // namespace dmmdzz
