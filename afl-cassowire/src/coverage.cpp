// src/coverage.cpp

#include "coverage.hpp"

#include <cerrno>
#include <cstring>
#include <sys/ipc.h>
#include <sys/shm.h>

namespace coverage {

namespace {

/// @brief shmat()s a SysV segment and returns its size via shmctl().
///
/// @param shm_id   Numeric SysV id.
/// @param out_ptr  Receives the mapping base on success.
/// @param out_size Receives the segment size in bytes on success.
/// @param error    Receives the reason on failure.
/// @return true on success.
bool attach_segment(int shm_id, std::uint8_t*& out_ptr, std::size_t& out_size, std::string& error) {
    if (shm_id < 0) {
        error = "invalid SysV shm id";
        return false;
    }

    struct shmid_ds ds {};
    if (shmctl(shm_id, IPC_STAT, &ds) != 0) {
        error = std::string("shmctl(IPC_STAT) failed: ") + std::strerror(errno);
        return false;
    }

    void* ptr = shmat(shm_id, nullptr, 0);
    if (ptr == reinterpret_cast<void*>(-1)) {
        error = std::string("shmat failed: ") + std::strerror(errno);
        return false;
    }

    out_ptr = static_cast<std::uint8_t*>(ptr);
    out_size = static_cast<std::size_t>(ds.shm_segsz);
    return true;
}

} // namespace

MapWindow::~MapWindow() {
    detach();
}

bool MapWindow::attach_cov(int shm_id, std::size_t announced_map_size, std::string& error) {
    const std::size_t len = map_view_size(announced_map_size);
    if (len == 0) {
        error = "announced map size is zero";
        return false;
    }

    std::uint8_t* ptr = nullptr;
    std::size_t seg_size = 0;
    if (!attach_segment(shm_id, ptr, seg_size, error)) {
        return false;
    }

    if (len > seg_size) {
        (void)shmdt(ptr);
        error = "coverage map view of " + std::to_string(len) +
                " bytes does not fit the " + std::to_string(seg_size) + "-byte segment";
        return false;
    }

    cov_ptr_ = ptr;
    cov_len_ = len;
    cov_snapshot_.resize(len);
    return true;
}

bool MapWindow::attach_cmp(int shm_id, std::string& error) {
    std::uint8_t* ptr = nullptr;
    std::size_t seg_size = 0;
    if (!attach_segment(shm_id, ptr, seg_size, error)) {
        return false;
    }

    // Exact match: the offsets below are pinned to the struct layout of the
    // AFL++ this proxy is built against. A different size means the layout
    // moved; refuse rather than snapshot the wrong bytes.
    if (seg_size != kCmpMapBytes) {
        (void)shmdt(ptr);
        error = "cmplog map is " + std::to_string(seg_size) + " bytes, expected " +
                std::to_string(kCmpMapBytes) + " (AFL++ struct cmp_map layout mismatch)";
        return false;
    }

    cmp_ptr_ = ptr;
    cmp_snapshot_.resize(kCmpHeaderBytes + kCmpSiteIdBytes + kCmpAttributeBytes);
    return true;
}

void MapWindow::capture() {
    if (cov_ptr_ != nullptr) {
        std::memcpy(cov_snapshot_.data(), cov_ptr_, cov_len_);
    }
    if (cmp_ptr_ != nullptr) {
        // [headers][site_ids][attributes] into one contiguous buffer.
        std::memcpy(cmp_snapshot_.data(), cmp_ptr_, kCmpHeaderBytes);
        std::memcpy(cmp_snapshot_.data() + kCmpHeaderBytes,
                    cmp_ptr_ + kCmpHeaderBytes + kCmpLogBytes, kCmpSiteIdBytes);
        std::memcpy(cmp_snapshot_.data() + kCmpHeaderBytes + kCmpSiteIdBytes,
                    cmp_ptr_ + kCmpHeaderBytes + kCmpLogBytes + kCmpSiteIdBytes,
                    kCmpAttributeBytes);
    }
}

void MapWindow::restore() {
    if (cov_ptr_ != nullptr) {
        std::memcpy(cov_ptr_, cov_snapshot_.data(), cov_len_);
    }
    if (cmp_ptr_ != nullptr) {
        std::memcpy(cmp_ptr_, cmp_snapshot_.data(), kCmpHeaderBytes);
        std::memcpy(cmp_ptr_ + kCmpHeaderBytes + kCmpLogBytes,
                    cmp_snapshot_.data() + kCmpHeaderBytes, kCmpSiteIdBytes);
        std::memcpy(cmp_ptr_ + kCmpHeaderBytes + kCmpLogBytes + kCmpSiteIdBytes,
                    cmp_snapshot_.data() + kCmpHeaderBytes + kCmpSiteIdBytes,
                    kCmpAttributeBytes);
    }
}

void MapWindow::detach() noexcept {
    if (cov_ptr_ != nullptr) {
        (void)shmdt(cov_ptr_);
        cov_ptr_ = nullptr;
        cov_len_ = 0;
    }
    if (cmp_ptr_ != nullptr) {
        (void)shmdt(cmp_ptr_);
        cmp_ptr_ = nullptr;
    }
}

} // namespace coverage
