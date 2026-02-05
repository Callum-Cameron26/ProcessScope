#include "signer_verify.h"
#include <wintrust.h>
#include <softpub.h>
#include <wincrypt.h>

#pragma comment(lib, "wintrust.lib")
#pragma comment(lib, "crypt32.lib")

namespace ProcessScope {

    SignatureInfo SignatureVerifier::VerifySignature(const std::string& filePath) {
        SignatureInfo info;
        
        if (filePath.empty()) {
            info.errorMessage = "Empty file path";
            return info;
        }

        std::wstring widePath = StringToWString(filePath);
        
        WINTRUST_FILE_INFO fileInfo = {};
        fileInfo.cbStruct = sizeof(WINTRUST_FILE_INFO);
        fileInfo.pcwszFilePath = widePath.c_str();
        fileInfo.hFile = nullptr;
        fileInfo.pgKnownSubject = nullptr;

        WINTRUST_DATA winTrustData = {};
        winTrustData.cbStruct = sizeof(WINTRUST_DATA);
        winTrustData.pPolicyCallbackData = nullptr;
        winTrustData.pSIPClientData = nullptr;
        winTrustData.dwUIChoice = WTD_UI_NONE;
        winTrustData.fdwRevocationChecks = WTD_REVOKE_NONE;
        winTrustData.dwUnionChoice = WTD_CHOICE_FILE;
        winTrustData.dwStateAction = WTD_STATEACTION_VERIFY;
        winTrustData.hWVTStateData = nullptr;
        winTrustData.pwszURLReference = nullptr;
        winTrustData.dwProvFlags = WTD_SAFER_FLAG;
        winTrustData.dwUIContext = 0;
        winTrustData.pFile = &fileInfo;

        GUID policyGUID = WINTRUST_ACTION_GENERIC_VERIFY_V2;

        LONG result = WinVerifyTrust(nullptr, &policyGUID, &winTrustData);
        
        if (result == ERROR_SUCCESS) {
            info.isSigned = true;
            
            // Try to get signer information
            CRYPT_PROVIDER_DATA* provData = WTHelperProvDataFromStateData(winTrustData.hWVTStateData);
            if (provData && provData->csSigners > 0) {
                CRYPT_PROVIDER_SGNR* signer = provData->pasSigners;
                if (signer && signer->csCertChain > 0) {
                    CRYPT_PROVIDER_CERT* cert = &signer->pasCertChain[0];
                    if (cert && cert->pCert) {
                        // Get certificate name
                        DWORD nameSize = 0;
                        if (!CertGetNameStringW(cert->pCert, CERT_NAME_SIMPLE_DISPLAY_TYPE, 
                                              0, nullptr, nullptr, 0)) {
                            nameSize = CertGetNameStringW(cert->pCert, CERT_NAME_SIMPLE_DISPLAY_TYPE,
                                                         0, nullptr, nullptr, 0);
                        }
                        
                        if (nameSize > 0) {
                            std::wstring name(nameSize, 0);
                            CertGetNameStringW(cert->pCert, CERT_NAME_SIMPLE_DISPLAY_TYPE,
                                             0, nullptr, &name[0], nameSize);
                            info.signerName = WStringToString(name);
                        }
                    }
                }
            }
        } else {
            info.isSigned = false;
            switch (result) {
                case TRUST_E_NOSIGNATURE:
                    info.errorMessage = "No signature found";
                    break;
                case TRUST_E_SUBJECT_NOT_TRUSTED:
                    info.errorMessage = "Signature not trusted";
                    break;
                case TRUST_E_PROVIDER_UNKNOWN:
                    info.errorMessage = "Provider unknown";
                    break;
                case TRUST_E_ACTION_UNKNOWN:
                    info.errorMessage = "Action unknown";
                    break;
                case TRUST_E_SUBJECT_FORM_UNKNOWN:
                    info.errorMessage = "Subject form unknown";
                    break;
                default:
                    info.errorMessage = "Verification failed (error: " + std::to_string(result) + ")";
                    break;
            }
        }

        // Clean up
        winTrustData.dwStateAction = WTD_STATEACTION_CLOSE;
        WinVerifyTrust(nullptr, &policyGUID, &winTrustData);

        return info;
    }

} // namespace ProcessScope
