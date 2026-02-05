#pragma once

#include "util.h"
#include "process_enum.h"
#include "module_enum.h"
#include "thread_enum.h"
#include "memory_scan.h"
#include <string>

// Risk assessment levels for process analysis
enum class RiskLevel {
    Low,
    Medium,
    High
};

// Risk assessment results with scoring details
struct RiskAssessment {
    int score;
    RiskLevel level;
    std::string details;
    
    RiskAssessment() : score(0), level(RiskLevel::Low) {}
};

// Risk scoring calculator with defensive heuristics
class RiskScorer {
    public:
        // Calculate comprehensive risk score based on modules, threads, and memory analysis
        RiskAssessment CalculateRiskScore(
            const ProcessInfo& processInfo,
            const std::vector<ModuleInfo>& modules,
            const std::vector<ThreadInfo>& threads,
            const std::vector<MemoryRegion>& memoryRegions
        );
        
    private:
        std::string GetRiskLevelString(RiskLevel level);
        int ScoreUnsignedModules(const std::vector<ModuleInfo>& modules);
        int ScoreAnomalousThreads(const std::vector<ThreadInfo>& threads, const std::vector<ModuleInfo>& modules);
        int ScoreSuspiciousMemory(const std::vector<MemoryRegion>& regions);
};
