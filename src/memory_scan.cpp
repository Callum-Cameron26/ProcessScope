#include "memory_scan.h"

namespace ProcessScope {

    std::vector<MemoryRegion> MemoryScanner::ScanMemoryRegions(HANDLE hProcess) {
        std::vector<MemoryRegion> regions;
        
        if (!hProcess) {
            return regions;
        }

        uintptr_t currentAddress = 0;
        MEMORY_BASIC_INFORMATION mbi;
        
        while (VirtualQueryEx(hProcess, (LPCVOID)currentAddress, &mbi, sizeof(mbi)) == sizeof(mbi)) {
            // Only process committed regions
            if (mbi.State == MEM_COMMIT) {
                MemoryRegion region;
                region.baseAddress = reinterpret_cast<uintptr_t>(mbi.BaseAddress);
                region.size = mbi.RegionSize;
                region.state = GetStateString(mbi.State);
                region.type = GetTypeString(mbi.Type);
                region.protection = GetProtectionString(mbi.Protect);
                
                // Check execution and write permissions
                region.isExecutable = (mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | 
                                                      PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) != 0;
                region.isWritable = (mbi.Protect & (PAGE_READWRITE | PAGE_EXECUTE_READWRITE | 
                                                     PAGE_WRITECOPY | PAGE_EXECUTE_WRITECOPY)) != 0;
                
                // Flag only truly suspicious regions
                region.isSuspicious = false;
                
                // RWX regions are always suspicious
                if (mbi.Protect & PAGE_EXECUTE_READWRITE) {
                    region.isSuspicious = true;
                }
                
                // Executable private regions only suspicious if very large (>1MB)
                if (region.isExecutable && mbi.Type == MEM_PRIVATE && region.size > 1024*1024) {
                    region.isSuspicious = true;
                }
                
                regions.push_back(region);
            }
            
            // Move to next region
            currentAddress = reinterpret_cast<uintptr_t>(mbi.BaseAddress) + mbi.RegionSize;
            
            // Prevent infinite loop
            if (currentAddress < reinterpret_cast<uintptr_t>(mbi.BaseAddress)) {
                break;
            }
        }

        return regions;
    }

} // namespace ProcessScope
