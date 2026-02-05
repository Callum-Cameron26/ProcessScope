#pragma once

#include "util.h"
#include <vector>
#include <string>

// Memory region information with security analysis
struct MemoryRegion {
    uintptr_t baseAddress;
    size_t size;
    std::string state;
    std::string type;
    std::string protection;
    bool isExecutable;
    bool isWritable;
    bool isSuspicious;
    
    MemoryRegion() : baseAddress(0), size(0), isExecutable(false), isWritable(false), isSuspicious(false) {}
};

// Virtual memory scanner with suspicious region detection
class MemoryScanner {
    public:
        std::vector<MemoryRegion> ScanMemoryRegions(HANDLE hProcess);
};
