#pragma once
#include <keymaster/authorization_set.h>
#include "CborConverter.h"
#include "JavacardSecureElement.h"
#include <android-base/logging.h>
#include <JavacardKeymasterOperation.h>

namespace javacard_keymaster {
using ::keymaster::AuthorizationSet;
using ::javacard_keymaster::HmacSharingParameters;
using ::keymaster::HardwareAuthToken;
using std::shared_ptr;
using std::vector;

class JavacardKeymaster {
public:
    explicit JavacardKeymaster(shared_ptr<JavacardSecureElement> card)
        : card_(card), seResetListener_(nullptr) {
        card_->initializeJavacard();
    }
    virtual ~JavacardKeymaster() {}

    std::tuple<std::unique_ptr<Item>, keymaster_error_t> getHardwareInfo();

    keymaster_error_t addRngEntropy(const vector<uint8_t>& data);

    keymaster_error_t getHmacSharingParameters(vector<uint8_t>* seed, vector<uint8_t>* nonce);

    keymaster_error_t computeSharedHmac(const vector<HmacSharingParameters>& params, vector<uint8_t>* secret);

    keymaster_error_t generateKey(const AuthorizationSet& keyParams,
                              vector<uint8_t>* retKeyblob,
                              AuthorizationSet* swEnforced,
                              AuthorizationSet* hwEnforced,
                              AuthorizationSet* teeEnforced);

    keymaster_error_t attestKey(const vector<uint8_t>& keyblob,
                            const AuthorizationSet& keyParams,
                            const vector<uint8_t>& attestkeyBlob,
                            const AuthorizationSet& attestKeyParams,
                            const vector<uint8_t>& attestKeyIssuer,
                            vector<vector<uint8_t>>* certChain);
    
    keymaster_error_t getCertChain(vector<vector<uint8_t>>* certChain);

    keymaster_error_t importKey(const AuthorizationSet& keyParams,
                            const keymaster_key_format_t keyFormat,
                            const vector<uint8_t>& keyData,
                            vector<uint8_t>* retKeyblob,
                            AuthorizationSet* swEnforced,
                            AuthorizationSet* hwEnforced,
                            AuthorizationSet* teeEnforced);

    keymaster_error_t importWrappedKey(const vector<uint8_t>& wrappedKeyData,
                                   const vector<uint8_t>& wrappingKeyBlob,
                                   const vector<uint8_t>& maskingKey,
                                   const AuthorizationSet& unwrappingParams,
                                   int64_t passwordSid, int64_t biometricSid,
                                   vector<uint8_t>* retKeyblob,
                                   AuthorizationSet* swEnforced,
                                   AuthorizationSet* hwEnforced,
                                   AuthorizationSet* teeEnforced);

    keymaster_error_t upgradeKey(const vector<uint8_t>& keyBlobToUpgrade,
                             const AuthorizationSet& upgradeParams,
                             vector<uint8_t>* retKeyBlob);

    keymaster_error_t deleteKey(const vector<uint8_t>& keyBlob);

    keymaster_error_t deleteAllKeys();

    keymaster_error_t destroyAttestationIds();

    keymaster_error_t deviceLocked(bool passwordOnly,
                               const vector<uint8_t>& cborEncodedVerificationToken);

    keymaster_error_t earlyBootEnded();

    keymaster_error_t getKeyCharacteristics(const vector<uint8_t>& in_keyBlob,
                                        const vector<uint8_t>& in_appId,
                                        const vector<uint8_t>& in_appData,
                                        AuthorizationSet* swEnforced,
                                        AuthorizationSet* hwEnforced,
                                        AuthorizationSet* teeEnforced);
    

    keymaster_error_t begin(keymaster_purpose_t purpose, const vector<uint8_t>& keyBlob,
                                           const AuthorizationSet& inParams,
                                           const HardwareAuthToken& hwAuthToken,
                                           AuthorizationSet* outParams,
                                           std::unique_ptr<JavacardKeymasterOperation>& operation);

    void registerSeResetEventListener(shared_ptr<IJavacardSeResetListener> listener) {
        seResetListener_ = listener;
    }
                                           
    //std::unique_ptr<JavacardKeymasterOperation> getOperation(uint64_t operationHandle, BufferingMode bufMode, uint32_t macLength, OperationType operType);
private:
    keymaster_error_t handleErrorCode(keymaster_error_t err);
    std::tuple<std::unique_ptr<Item>, keymaster_error_t> sendRequest(Instruction ins);
    std::tuple<std::unique_ptr<Item>, keymaster_error_t> sendRequest(Instruction ins, Array& request);

    keymaster_error_t
    sendBeginImportWrappedKeyCmd(const std::vector<uint8_t>& transitKey,
                            const std::vector<uint8_t>& wrappingKeyBlob,
                            const std::vector<uint8_t>& maskingKey,
                            const AuthorizationSet& unwrappingParams);

    std::tuple<std::unique_ptr<Item>, keymaster_error_t>
    sendFinishImportWrappedKeyCmd(const AuthorizationSet& keyParams, 
                                const keymaster_key_format_t keyFormat,
                                const std::vector<uint8_t>& secureKey,
                                const std::vector<uint8_t>& tag,
                                const std::vector<uint8_t>& iv,
                                const std::vector<uint8_t>& wrappedKeyDescription,
                                int64_t passwordSid, int64_t biometricSid);
 
    const shared_ptr<JavacardSecureElement> card_;
    CborConverter cbor_;
    shared_ptr<IJavacardSeResetListener> seResetListener_;
};

} // javacard_keymaster
