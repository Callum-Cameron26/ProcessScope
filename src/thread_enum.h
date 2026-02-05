#pragma once

#include "util.h"
#include "module_enum.h"
#include <vector>
#include <string>

// Thread information with anomaly detection
struct ThreadInfo {
    DWORD tid;
    uintptr_t startAddress;
    bool anomalousStart;
    
    ThreadInfo() : tid(0), startAddress(0), anomalousStart(false) {}
};

// Thread enumeration with start address validation
class ThreadEnumerator {
    public:
        std::vector<ThreadInfo> EnumerateThreads(DWORD pid);
        bool IsStartAddressInModule(uintptr_t address, const std::vector<ModuleInfo>& modules);
};
