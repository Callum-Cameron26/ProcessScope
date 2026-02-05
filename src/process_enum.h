#pragma once

#include "util.h"
#include <vector>
#include <string>

// Process information for enumeration and analysis
struct ProcessInfo {
    DWORD pid;
    DWORD ppid;
    std::string name;
    std::string fullPath;
    std::string architecture;
    DWORD sessionId;
    
    ProcessInfo() : pid(0), ppid(0), sessionId(0) {}
};

// Process enumeration with detailed information gathering
class ProcessEnumerator {
    public:
        std::vector<ProcessInfo> EnumerateProcesses();
        ProcessInfo GetProcessInfo(DWORD pid);
        bool IsProcessAccessible(DWORD pid);
};
