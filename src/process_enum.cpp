#include "process_enum.h"
#include <tlhelp32.h>
#include <psapi.h>

#pragma comment(lib, "psapi.lib")

namespace ProcessScope {

    std::vector<ProcessInfo> ProcessEnumerator::EnumerateProcesses() {
        std::vector<ProcessInfo> processes;
        
        Handle hSnapshot(CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0));
        if (!hSnapshot) {
            return processes;
        }

        PROCESSENTRY32 pe32;
        pe32.dwSize = sizeof(PROCESSENTRY32);

        if (Process32First(hSnapshot.get(), &pe32)) {
            do {
                ProcessInfo info;
                info.pid = pe32.th32ProcessID;
                info.ppid = pe32.th32ParentProcessID;
                info.name = WStringToString(pe32.szExeFile);
                info.sessionId = 0; // Will be filled later if accessible

                // Try to get additional information for accessible processes
                Handle hProcess(OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pe32.th32ProcessID));
                if (hProcess) {
                    // Get full path
                    WCHAR path[MAX_PATH];
                    DWORD pathSize = MAX_PATH;
                    if (QueryFullProcessImageNameW(hProcess.get(), 0, path, &pathSize)) {
                        info.fullPath = WStringToString(std::wstring(path, pathSize));
                    }

                    // Get architecture
                    info.architecture = IsProcess64Bit(hProcess.get()) ? "x64" : "x86";

                    // Get session ID
                    DWORD sessionId;
                    if (ProcessIdToSessionId(pe32.th32ProcessID, &sessionId)) {
                        info.sessionId = sessionId;
                    }
                } else {
                    info.architecture = "Unknown";
                }

                processes.push_back(info);
            } while (Process32Next(hSnapshot.get(), &pe32));
        }

        return processes;
    }

    ProcessInfo ProcessEnumerator::GetProcessInfo(DWORD pid) {
        ProcessInfo info;
        info.pid = pid;

        Handle hProcess(OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid));
        if (!hProcess) {
            return info;
        }

        // Get process name from path
        WCHAR path[MAX_PATH];
        DWORD pathSize = MAX_PATH;
        if (QueryFullProcessImageNameW(hProcess.get(), 0, path, &pathSize)) {
            info.fullPath = WStringToString(std::wstring(path, pathSize));
            // Extract just the filename
            size_t lastSlash = info.fullPath.find_last_of("\\/");
            if (lastSlash != std::string::npos) {
                info.name = info.fullPath.substr(lastSlash + 1);
            } else {
                info.name = info.fullPath;
            }
        }

        // Get architecture
        info.architecture = IsProcess64Bit(hProcess.get()) ? "x64" : "x86";

        // Get session ID
        DWORD sessionId;
        if (ProcessIdToSessionId(pid, &sessionId)) {
            info.sessionId = sessionId;
        }

        // Get parent PID
        Handle hSnapshot(CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0));
        if (hSnapshot) {
            PROCESSENTRY32 pe32;
            pe32.dwSize = sizeof(PROCESSENTRY32);
            if (Process32First(hSnapshot.get(), &pe32)) {
                do {
                    if (pe32.th32ProcessID == pid) {
                        info.ppid = pe32.th32ParentProcessID;
                        break;
                    }
                } while (Process32Next(hSnapshot.get(), &pe32));
            }
        }

        return info;
    }

    bool ProcessEnumerator::IsProcessAccessible(DWORD pid) {
        Handle hProcess(OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid));
        return hProcess.operator bool();
    }

} // namespace ProcessScope
