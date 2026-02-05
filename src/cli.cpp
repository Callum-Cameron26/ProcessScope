#include "cli.h"
#include "json.hpp"
#include <iostream>
#include <iomanip>
#include <fstream>
#include <cstdlib>

using json = nlohmann::json;

namespace ProcessScope {

    int CLI::Run(int argc, char* argv[]) {
        if (argc < 2) {
            std::cout << "ProcessScope - Windows Process & Memory Inspection Toolkit\n";
            std::cout << "Usage:\n";
            std::cout << "  ProcessScope.exe --list                    List running processes\n";
            std::cout << "  ProcessScope.exe --scan <pid>              Scan a specific process\n";
            std::cout << "  ProcessScope.exe --scan-all                Scan all accessible processes\n";
            return 1;
        }

        std::string command = argv[1];
        
        if (command == "--list") {
            PrintProcessList();
            return 0;
        } else if (command == "--scan") {
            if (argc < 3) {
                std::cerr << "Error: PID required for --scan command\n";
                return 1;
            }
            
            DWORD pid = std::stoul(argv[2]);
            ScanResult result = ScanProcess(pid);
            PrintScanResult(result);
            
            if (result.success) {
                std::string filename = GenerateJsonFilename(pid);
                if (ExportToJson(result, filename)) {
                    std::cout << "\nReport exported to: " << filename << "\n";
                } else {
                    std::cout << "\nWarning: Failed to export JSON report\n";
                }
            }
            
            return result.success ? 0 : 1;
        } else if (command == "--scan-all") {
            std::vector<ProcessInfo> processes = processEnumerator_.EnumerateProcesses();
            int successCount = 0;
            int totalCount = 0;
            
            for (const auto& process : processes) {
                totalCount++;
                std::cout << "Scanning PID " << process.pid << " (" << process.name << ")...\n";
                
                ScanResult result = ScanProcess(process.pid);
                if (result.success) {
                    successCount++;
                    std::string filename = GenerateJsonFilename(process.pid);
                    ExportToJson(result, filename);
                }
            }
            
            std::cout << "\nScan completed: " << successCount << "/" << totalCount << " processes scanned successfully\n";
            return 0;
        } else {
            std::cerr << "Error: Unknown command '" << command << "'\n";
            return 1;
        }
    }

    ScanResult CLI::ScanProcess(DWORD pid) {
        ScanResult result;
        
        // Get process information
        result.processInfo = processEnumerator_.GetProcessInfo(pid);
        if (result.processInfo.pid == 0) {
            result.errorMessage = "Process not found or access denied";
            return result;
        }
        
        // Open process handle
        Handle hProcess(OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid));
        if (!hProcess) {
            result.errorMessage = "Failed to open process: " + GetLastErrorString();
            return result;
        }
        
        try {
            // Enumerate modules
            result.modules = moduleEnumerator_.EnumerateModules(hProcess.get());
            
            // Enumerate threads
            result.threads = threadEnumerator_.EnumerateThreads(pid);
            
            // Check for anomalous thread starts
            for (auto& thread : result.threads) {
                if (thread.startAddress != 0) {
                    thread.anomalousStart = !threadEnumerator_.IsStartAddressInModule(thread.startAddress, result.modules);
                }
            }
            
            // Scan memory regions
            result.memoryRegions = memoryScanner_.ScanMemoryRegions(hProcess.get());
            
            // Calculate risk score
            result.riskAssessment = riskScorer_.CalculateRiskScore(
                result.processInfo, result.modules, result.threads, result.memoryRegions);
            
            result.success = true;
        } catch (const std::exception& e) {
            result.errorMessage = "Exception during scan: " + std::string(e.what());
        }
        
        return result;
    }

    void CLI::PrintProcessList() {
        std::vector<ProcessInfo> processes = processEnumerator_.EnumerateProcesses();
        
        std::cout << std::left << std::setw(8) << "PID" 
                  << std::setw(8) << "PPID" 
                  << std::setw(12) << "Session"
                  << std::setw(8) << "Arch"
                  << std::setw(40) << "Name"
                  << "Path\n";
        std::cout << std::string(120, '-') << "\n";
        
        for (const auto& process : processes) {
            std::cout << std::left << std::setw(8) << process.pid
                      << std::setw(8) << process.ppid
                      << std::setw(12) << process.sessionId
                      << std::setw(8) << process.architecture
                      << std::setw(40) << (process.name.length() > 37 ? process.name.substr(0, 37) + "..." : process.name)
                      << process.fullPath << "\n";
        }
        
        std::cout << "\nTotal processes: " << processes.size() << "\n";
    }

    void CLI::PrintScanResult(const ScanResult& result) {
        if (!result.success) {
            std::cerr << "Error: " << result.errorMessage << "\n";
            return;
        }
        
        std::cout << "\n=== PROCESS INFORMATION ===\n";
        std::cout << "PID: " << result.processInfo.pid << "\n";
        std::cout << "PPID: " << result.processInfo.ppid << "\n";
        std::cout << "Name: " << result.processInfo.name << "\n";
        std::cout << "Path: " << result.processInfo.fullPath << "\n";
        std::cout << "Architecture: " << result.processInfo.architecture << "\n";
        std::cout << "Session ID: " << result.processInfo.sessionId << "\n";
        
        std::cout << "\n=== MODULES (" << result.modules.size() << ") ===\n";
        std::cout << std::left << std::setw(20) << "Name"
                  << std::setw(18) << "Base Address"
                  << std::setw(12) << "Size"
                  << std::setw(8) << "Signed"
                  << "Signer\n";
        std::cout << std::string(80, '-') << "\n";
        
        for (const auto& module : result.modules) {
            std::cout << std::left << std::setw(20) << (module.name.length() > 17 ? module.name.substr(0, 17) + "..." : module.name)
                      << "0x" << std::hex << std::setw(16) << module.baseAddress << std::dec
                      << std::setw(12) << module.size
                      << std::setw(8) << (module.isSigned ? "Yes" : "No")
                      << (module.signerName.length() > 30 ? module.signerName.substr(0, 30) + "..." : module.signerName) << "\n";
        }
        
        std::cout << "\n=== THREADS (" << result.threads.size() << ") ===\n";
        std::cout << std::left << std::setw(10) << "TID"
                  << std::setw(18) << "Start Address"
                  << "Anomalous\n";
        std::cout << std::string(40, '-') << "\n";
        
        for (const auto& thread : result.threads) {
            std::cout << std::left << std::setw(10) << thread.tid;
            if (thread.startAddress != 0) {
                std::cout << "0x" << std::hex << std::setw(16) << thread.startAddress << std::dec;
            } else {
                std::cout << std::setw(18) << "Unknown";
            }
            std::cout << (thread.anomalousStart ? " Yes" : " No") << "\n";
        }
        
        std::cout << "\n=== MEMORY SUMMARY ===\n";
        int suspiciousRegions = 0;
        int rwxRegions = 0;
        int executablePrivateRegions = 0;
        
        for (const auto& region : result.memoryRegions) {
            if (region.isSuspicious) {
                suspiciousRegions++;
                if (region.protection.find("RWX") != std::string::npos) {
                    rwxRegions++;
                }
                if (region.isExecutable && region.type == "PRIVATE") {
                    executablePrivateRegions++;
                }
            }
        }
        
        std::cout << "Total regions: " << result.memoryRegions.size() << "\n";
        std::cout << "Suspicious regions: " << suspiciousRegions << "\n";
        std::cout << "RWX regions: " << rwxRegions << "\n";
        std::cout << "Executable private regions: " << executablePrivateRegions << "\n";
        
        std::cout << "\n=== RISK ASSESSMENT ===\n";
        std::string levelStr;
        switch (result.riskAssessment.level) {
            case RiskLevel::Low:    levelStr = "Low"; break;
            case RiskLevel::Medium: levelStr = "Medium"; break;
            case RiskLevel::High:   levelStr = "High"; break;
        }
        
        std::cout << "Risk Score: " << result.riskAssessment.score << "\n";
        std::cout << "Risk Level: " << levelStr << "\n";
        std::cout << "Details: " << result.riskAssessment.details << "\n";
    }

    bool CLI::ExportToJson(const ScanResult& result, const std::string& filename) {
        try {
            json j;
            
            j["tool_info"]["name"] = "ProcessScope";
            j["tool_info"]["version"] = "1.0.0";
            j["tool_info"]["timestamp"] = GetTimestamp();
            
            j["host_info"]["computer_name"] = []() -> std::string {
                char* env = nullptr;
                size_t len = 0;
                _dupenv_s(&env, &len, "COMPUTERNAME");
                std::string result = env ? env : "Unknown";
                if (env) free(env);
                return result;
            }();
            j["host_info"]["username"] = []() -> std::string {
                char* env = nullptr;
                size_t len = 0;
                _dupenv_s(&env, &len, "USERNAME");
                std::string result = env ? env : "Unknown";
                if (env) free(env);
                return result;
            }();
            
            j["process"]["pid"] = result.processInfo.pid;
            j["process"]["ppid"] = result.processInfo.ppid;
            j["process"]["name"] = result.processInfo.name;
            j["process"]["full_path"] = result.processInfo.fullPath;
            j["process"]["architecture"] = result.processInfo.architecture;
            j["process"]["session_id"] = result.processInfo.sessionId;
            
            j["modules"] = json::array();
            for (const auto& module : result.modules) {
                json m;
                m["name"] = module.name;
                m["full_path"] = module.fullPath;
                m["base_address"] = "0x" + std::to_string(module.baseAddress);
                m["size"] = module.size;
                m["signed"] = module.isSigned;
                m["signer_name"] = module.signerName;
                j["modules"].push_back(m);
            }
            
            j["threads"] = json::array();
            for (const auto& thread : result.threads) {
                json t;
                t["tid"] = thread.tid;
                if (thread.startAddress != 0) {
                    t["start_address"] = "0x" + std::to_string(thread.startAddress);
                } else {
                    t["start_address"] = nullptr;
                }
                t["anomalous_start"] = thread.anomalousStart;
                j["threads"].push_back(t);
            }
            
            j["memory_regions"] = json::array();
            for (const auto& region : result.memoryRegions) {
                json r;
                r["base_address"] = "0x" + std::to_string(region.baseAddress);
                r["size"] = region.size;
                r["state"] = region.state;
                r["type"] = region.type;
                r["protection"] = region.protection;
                r["is_executable"] = region.isExecutable;
                r["is_writable"] = region.isWritable;
                r["is_suspicious"] = region.isSuspicious;
                j["memory_regions"].push_back(r);
            }
            
            j["risk_assessment"]["score"] = result.riskAssessment.score;
            std::string levelStr;
            switch (result.riskAssessment.level) {
                case RiskLevel::Low:    levelStr = "Low"; break;
                case RiskLevel::Medium: levelStr = "Medium"; break;
                case RiskLevel::High:   levelStr = "High"; break;
            }
            j["risk_assessment"]["level"] = levelStr;
            j["risk_assessment"]["details"] = result.riskAssessment.details;
            
            // Create directory if it doesn't exist
            size_t lastSlash = filename.find_last_of("\\/");
            if (lastSlash != std::string::npos) {
                std::string directory = filename.substr(0, lastSlash);
                CreateDirectoryRecursive(directory);
            }
            
            std::ofstream file(filename);
            if (!file.is_open()) {
                return false;
            }
            
            file << j.dump(4);
            file.close();
            
            return true;
        } catch (const std::exception&) {
            return false;
        }
    }

    std::string CLI::GenerateJsonFilename(DWORD pid) {
        return "./reports/" + std::to_string(pid) + "_" + GetTimestamp() + ".json";
    }

} // namespace ProcessScope
