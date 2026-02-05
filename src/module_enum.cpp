#include "module_enum.h"
#include <psapi.h>
#include <tlhelp32.h>

#pragma comment(lib, "psapi.lib")

namespace ProcessScope {

    std::vector<ModuleInfo> ModuleEnumerator::EnumerateModules(HANDLE hProcess) {
        std::vector<ModuleInfo> modules;
        
        if (!hProcess) {
            return modules;
        }

        // First try using EnumProcessModules (more reliable for 64-bit processes)
        HMODULE hMods[1024];
        DWORD cbNeeded;
        
        if (EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded)) {
            DWORD moduleCount = cbNeeded / sizeof(HMODULE);
            
            for (DWORD i = 0; i < moduleCount; i++) {
                ModuleInfo info;
                
                // Get module full path
                WCHAR szModName[MAX_PATH * 2];
                if (GetModuleFileNameExW(hProcess, hMods[i], szModName, sizeof(szModName) / sizeof(WCHAR))) {
                    info.fullPath = WStringToString(std::wstring(szModName));
                    
                    // Extract just the filename
                    size_t lastSlash = info.fullPath.find_last_of("\\/");
                    if (lastSlash != std::string::npos) {
                        info.name = info.fullPath.substr(lastSlash + 1);
                    } else {
                        info.name = info.fullPath;
                    }
                }
                
                // Get module base address and size
                MODULEINFO modInfo;
                if (GetModuleInformation(hProcess, hMods[i], &modInfo, sizeof(modInfo))) {
                    info.baseAddress = reinterpret_cast<uintptr_t>(modInfo.lpBaseOfDll);
                    info.size = modInfo.SizeOfImage;
                }
                
                // Verify signature
                if (!info.fullPath.empty()) {
                    SignatureInfo sigInfo = verifier_.VerifySignature(info.fullPath);
                    info.isSigned = sigInfo.isSigned;
                    info.signerName = sigInfo.signerName;
                }
                
                modules.push_back(info);
            }
        } else {
            // Fallback to Toolhelp32 for processes we can't query with EnumProcessModules
            Handle hSnapshot(CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, GetProcessId(hProcess)));
            if (hSnapshot) {
                MODULEENTRY32 me32;
                me32.dwSize = sizeof(MODULEENTRY32);
                
                if (Module32First(hSnapshot.get(), &me32)) {
                    do {
                        ModuleInfo info;
                        info.name = WStringToString(me32.szModule);
                        info.fullPath = WStringToString(me32.szExePath);
                        info.baseAddress = reinterpret_cast<uintptr_t>(me32.modBaseAddr);
                        info.size = me32.modBaseSize;
                        
                        // Verify signature
                        if (!info.fullPath.empty()) {
                            SignatureInfo sigInfo = verifier_.VerifySignature(info.fullPath);
                            info.isSigned = sigInfo.isSigned;
                            info.signerName = sigInfo.signerName;
                        }
                        
                        modules.push_back(info);
                    } while (Module32Next(hSnapshot.get(), &me32));
                }
            }
        }
        
        return modules;
    }

} // namespace ProcessScope
