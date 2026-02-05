#pragma once

#include "util.h"
#include <string>

// Digital signature verification results
struct SignatureInfo {
    bool isSigned;
    std::string signerName;
    std::string errorMessage;
    
    SignatureInfo() : isSigned(false) {}
};

// Digital signature verification using Windows API
class SignatureVerifier {
    public:
        SignatureInfo VerifySignature(const std::string& filePath);
};
