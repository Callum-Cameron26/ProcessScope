#pragma once

#include "util.h"
#include "process_enum.h"
#include "module_enum.h"
#include "thread_enum.h"
#include "memory_scan.h"
#include "risk_score.h"
#include <string>

namespace ProcessScope {

    struct ScanResult {
        ProcessInfo processInfo;
        std::vector<ModuleInfo> modules;
        std::vector<ThreadInfo> threads;
        std::vector<MemoryRegion> memoryRegions;
        RiskAssessment riskAssessment;
        std::string errorMessage;
        bool success;
        
        ScanResult() : success(false) {}
    };

    class CLI {
    private:
        ProcessEnumerator processEnumerator_;
        ModuleEnumerator moduleEnumerator_;
        ThreadEnumerator threadEnumerator_;
        MemoryScanner memoryScanner_;
        RiskScorer riskScorer_;
        
        ScanResult ScanProcess(DWORD pid);
        void PrintProcessList();
        void PrintScanResult(const ScanResult& result);
        bool ExportToJson(const ScanResult& result, const std::string& filename);
        std::string GenerateJsonFilename(DWORD pid);
        
    public:
        int Run(int argc, char* argv[]);
    };

} // namespace ProcessScope
