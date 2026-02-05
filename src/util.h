#pragma once

#include <windows.h>
#include <string>
#include <vector>
#include <memory>
#include <chrono>
#include <iomanip>
#include <sstream>

namespace ProcessScope {

    // Core utility functions for Windows process analysis
    std::string GetLastErrorString();
    std::string WStringToString(const std::wstring& wstr);
    std::wstring StringToWString(const std::string& str);
    std::string GetTimestamp();
    bool IsProcess64Bit(HANDLE hProcess);
    std::string GetProtectionString(DWORD protection);
    std::string GetStateString(DWORD state);
    std::string GetTypeString(DWORD type);
    bool CreateDirectoryRecursive(const std::string& path);
    
    // RAII wrapper for Windows handles
    class Handle {
    private:
        HANDLE handle_;
    public:
        explicit Handle(HANDLE h = nullptr) : handle_(h) {}
        ~Handle() { if (handle_ && handle_ != INVALID_HANDLE_VALUE) CloseHandle(handle_); }
        Handle(const Handle&) = delete;
        Handle& operator=(const Handle&) = delete;
        Handle(Handle&& other) noexcept : handle_(other.handle_) { other.handle_ = nullptr; }
        Handle& operator=(Handle&& other) noexcept {
            if (this != &other) {
                if (handle_ && handle_ != INVALID_HANDLE_VALUE) CloseHandle(handle_);
                handle_ = other.handle_;
                other.handle_ = nullptr;
            }
            return *this;
        }
        HANDLE get() const { return handle_; }
        operator bool() const { return handle_ && handle_ != INVALID_HANDLE_VALUE; }
    };

} // namespace ProcessScope
