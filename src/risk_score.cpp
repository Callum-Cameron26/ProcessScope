#include "risk_score.h"
#include <sstream>
#include <algorithm>
#include <cctype>

namespace ProcessScope {

    RiskAssessment RiskScorer::CalculateRiskScore(
        const ProcessInfo& /*processInfo*/,
        const std::vector<ModuleInfo>& modules,
        const std::vector<ThreadInfo>& threads,
        const std::vector<MemoryRegion>& memoryRegions) {
        
        RiskAssessment assessment;
        std::stringstream details;
        
        // Check for unsigned modules (excluding legitimate locations)
        int unsignedScore = ScoreUnsignedModules(modules);
        assessment.score += unsignedScore;
        if (unsignedScore > 0) {
            details << "Unsigned modules: +" << unsignedScore << "; ";
        }
        
        // Check for anomalous thread start addresses
        int anomalousScore = ScoreAnomalousThreads(threads, modules);
        assessment.score += anomalousScore;
        if (anomalousScore > 0) {
            details << "Anomalous thread starts: +" << anomalousScore << "; ";
        }
        
        // Check for suspicious memory regions
        int memoryScore = ScoreSuspiciousMemory(memoryRegions);
        assessment.score += memoryScore;
        if (memoryScore > 0) {
            details << "Suspicious memory: +" << memoryScore << "; ";
        }
        
        // Determine risk level based on total score
        if (assessment.score <= 2) {
            assessment.level = RiskLevel::Low;
        } else if (assessment.score <= 5) {
            assessment.level = RiskLevel::Medium;
        } else {
            assessment.level = RiskLevel::High;
        }
        
        assessment.details = details.str();
        if (assessment.details.empty()) {
            assessment.details = "No risk factors detected";
        }
        
        return assessment;
    }

    std::string RiskScorer::GetRiskLevelString(RiskLevel level) {
        switch (level) {
            case RiskLevel::Low:    return "Low";
            case RiskLevel::Medium: return "Medium";
            case RiskLevel::High:   return "High";
            default:                return "Unknown";
        }
    }

    int RiskScorer::ScoreUnsignedModules(const std::vector<ModuleInfo>& modules) {
        int unsignedCount = 0;
        for (const auto& module : modules) {
            if (!module.isSigned) {
                // Skip unsigned modules from trusted locations
                bool isLegitimateLocation = false;
                std::string lowerPath = module.fullPath;
                std::transform(lowerPath.begin(), lowerPath.end(), lowerPath.begin(), ::tolower);
                
                if (lowerPath.find("windows\\system32") != std::string::npos ||
                    lowerPath.find("windows\\syswow64") != std::string::npos ||
                    lowerPath.find("program files") != std::string::npos ||
                    lowerPath.find("programdata") != std::string::npos) {
                    isLegitimateLocation = true;
                }
                
                if (!isLegitimateLocation) {
                    unsignedCount++;
                }
            }
        }
        // Cap at +3 points to reduce false positives
        return (std::min)(unsignedCount, 3);
    }

    int RiskScorer::ScoreAnomalousThreads(const std::vector<ThreadInfo>& threads, const std::vector<ModuleInfo>& modules) {
        ThreadEnumerator enumerator;
        int anomalousCount = 0;
        
        for (const auto& thread : threads) {
            if (thread.startAddress != 0 && 
                !enumerator.IsStartAddressInModule(thread.startAddress, modules)) {
                anomalousCount++;
            }
        }
        
        return anomalousCount * 2; // +2 per anomalous thread
    }

    int RiskScorer::ScoreSuspiciousMemory(const std::vector<MemoryRegion>& regions) {
        int score = 0;
        
        for (const auto& region : regions) {
            if (region.isSuspicious) {
                if (region.protection.find("RWX") != std::string::npos) {
                    score += 3; // RWX regions are most dangerous
                } else if (region.isExecutable && region.type == "PRIVATE") {
                    score += 1; // Large executable private regions
                }
            }
        }
        
        return score;
    }

} // namespace ProcessScope
