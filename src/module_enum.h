#pragma once

#include "util.h"
#include "signer_verify.h"
#include <vector>
#include <string>

// Module information with signature verification
struct ModuleInfo {
    std::string name;
    std::string fullPath;
    uintptr_t baseAddress;
    size_t size;
    bool isSigned;
    std::string signerName;
    
    ModuleInfo() : baseAddress(0), size(0), isSigned(false) {}
};

// Module enumeration with digital signature verification
class ModuleEnumerator {
    private:
        SignatureVerifier verifier_;
        
    public:
        explicit ModuleEnumerator();
        std::vector<ModuleInfo> EnumerateModules(HANDLE hProcess);
};
