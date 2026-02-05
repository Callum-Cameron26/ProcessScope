#include "util.h"

namespace ProcessScope {

    std::string GetLastErrorString() {
        DWORD errorCode = GetLastError();
        if (errorCode == 0) return "No error";
        
        LPSTR messageBuffer = nullptr;
        size_t size = FormatMessageA(
            FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
            nullptr, errorCode, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
            (LPSTR)&messageBuffer, 0, nullptr);
        
        std::string message(messageBuffer, size);
        LocalFree(messageBuffer);
        return message;
    }

    std::string WStringToString(const std::wstring& wstr) {
        if (wstr.empty()) return std::string();
        
        int size = WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), -1, nullptr, 0, nullptr, nullptr);
        std::string result(size - 1, 0);
        WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), -1, &result[0], size, nullptr, nullptr);
        return result;
    }

    std::wstring StringToWString(const std::string& str) {
        if (str.empty()) return std::wstring();
        
        int size = MultiByteToWideChar(CP_UTF8, 0, str.c_str(), -1, nullptr, 0);
        std::wstring result(size - 1, 0);
        MultiByteToWideChar(CP_UTF8, 0, str.c_str(), -1, &result[0], size);
        return result;
    }

    std::string GetTimestamp() {
        auto now = std::chrono::system_clock::now();
        auto time_t = std::chrono::system_clock::to_time_t(now);
        auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
            now.time_since_epoch()) % 1000;
        
        std::stringstream ss;
        struct tm timeinfo;
        localtime_s(&timeinfo, &time_t);
        ss << std::put_time(&timeinfo, "%Y%m%d_%H%M%S");
        ss << "_" << std::setfill('0') << std::setw(3) << ms.count();
        return ss.str();
    }

    bool IsProcess64Bit(HANDLE hProcess) {
        if constexpr (sizeof(void*) == 8) {
            BOOL isWow64 = FALSE;
            if (!IsWow64Process(hProcess, &isWow64)) {
                return false;
            }
            return !isWow64;
        } else {
            return false;
        }
    }

    std::string GetProtectionString(DWORD protection) {
        std::string result;
        
        switch (protection & 0xFF) {
            case PAGE_EXECUTE:           result += "X"; break;
            case PAGE_EXECUTE_READ:      result += "RX"; break;
            case PAGE_EXECUTE_READWRITE: result += "RWX"; break;
            case PAGE_EXECUTE_WRITECOPY: result += "RCX"; break;
            case PAGE_NOACCESS:          result += "NO"; break;
            case PAGE_READONLY:          result += "R"; break;
            case PAGE_READWRITE:         result += "RW"; break;
            case PAGE_WRITECOPY:         result += "RC"; break;
            default:                     result += "??"; break;
        }
        
        if (protection & PAGE_GUARD) result += "G";
        if (protection & PAGE_NOCACHE) result += "NC";
        if (protection & PAGE_WRITECOMBINE) result += "WC";
        
        return result;
    }

    std::string GetStateString(DWORD state) {
        switch (state) {
            case MEM_COMMIT:  return "COMMIT";
            case MEM_FREE:    return "FREE";
            case MEM_RESERVE: return "RESERVE";
            default:          return "UNKNOWN";
        }
    }

    std::string GetTypeString(DWORD type) {
        switch (type) {
            case MEM_IMAGE:   return "IMAGE";
            case MEM_MAPPED:  return "MAPPED";
            case MEM_PRIVATE: return "PRIVATE";
            default:          return "UNKNOWN";
        }
    }

    bool CreateDirectoryRecursive(const std::string& path) {
        if (path.empty()) return false;
        
        std::wstring widePath = StringToWString(path);
        
        if (CreateDirectoryW(widePath.c_str(), nullptr)) {
            return true;
        }
        
        if (GetLastError() == ERROR_ALREADY_EXISTS) {
            return true;
        }
        
        if (GetLastError() == ERROR_PATH_NOT_FOUND) {
            size_t pos = path.find_last_of("\\/");
            if (pos != std::string::npos) {
                std::string parent = path.substr(0, pos);
                if (CreateDirectoryRecursive(parent)) {
                    return CreateDirectoryW(widePath.c_str(), nullptr) != FALSE ||
                           GetLastError() == ERROR_ALREADY_EXISTS;
                }
            }
        }
        
        return false;
    }

} // namespace ProcessScope
