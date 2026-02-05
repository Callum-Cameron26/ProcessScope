#include "thread_enum.h"
#include "module_enum.h"
#include <tlhelp32.h>
#include <winternl.h>

#pragma comment(lib, "ntdll.lib")

namespace ProcessScope {

    // Define NTSTATUS and function pointer types
    typedef NTSTATUS (NTAPI *NtQueryInformationThreadFunc)(
        HANDLE ThreadHandle,
        THREADINFOCLASS ThreadInformationClass,
        PVOID ThreadInformation,
        ULONG ThreadInformationLength,
        PULONG ReturnLength
    );

    std::vector<ThreadInfo> ThreadEnumerator::EnumerateThreads(DWORD pid) {
        std::vector<ThreadInfo> threads;
        
        Handle hSnapshot(CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0));
        if (!hSnapshot) {
            return threads;
        }

        THREADENTRY32 te32;
        te32.dwSize = sizeof(THREADENTRY32);

        if (Thread32First(hSnapshot.get(), &te32)) {
            do {
                if (te32.th32OwnerProcessID == pid) {
                    ThreadInfo info;
                    info.tid = te32.th32ThreadID;
                    
                    // Try to get thread start address using NtQueryInformationThread
                    Handle hThread(OpenThread(THREAD_QUERY_INFORMATION, FALSE, te32.th32ThreadID));
                    if (hThread) {
                        // Dynamically load ntdll
                        HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
                        if (hNtdll) {
                            NtQueryInformationThreadFunc NtQueryInformationThreadPtr = 
                                (NtQueryInformationThreadFunc)GetProcAddress(hNtdll, "NtQueryInformationThread");
                            
                            if (NtQueryInformationThreadPtr) {
                                PVOID startAddress = nullptr;
                                NTSTATUS status = NtQueryInformationThreadPtr(
                                    hThread.get(),
                                    (THREADINFOCLASS)0x9, // ThreadQuerySetWin32StartAddress
                                    &startAddress,
                                    sizeof(startAddress),
                                    nullptr
                                );
                                
                                if (status >= 0) {
                                    info.startAddress = reinterpret_cast<uintptr_t>(startAddress);
                                }
                            }
                        }
                    }
                    
                    threads.push_back(info);
                }
            } while (Thread32Next(hSnapshot.get(), &te32));
        }

        return threads;
    }

    bool ThreadEnumerator::IsStartAddressInModule(uintptr_t address, const std::vector<ModuleInfo>& modules) {
        for (const auto& module : modules) {
            uintptr_t moduleEnd = module.baseAddress + module.size;
            if (address >= module.baseAddress && address < moduleEnd) {
                return true;
            }
        }
        return false;
    }

} // namespace ProcessScope
