#include <JavacardKeymaster.h>
#include <km_utils.h>
#include <keymaster/wrapped_key.h>
#include <keymaster/mem.h>

#define SE_POWER_RESET_STATUS_FLAG ( 1 << 30)

namespace javacard_keymaster {
using cppbor::Array;
using keymaster::KeymasterKeyBlob;
using keymaster::KeymasterBlob;

namespace {
//Extended error codes
enum ExtendedErrors {
    SW_CONDITIONS_NOT_SATISFIED = -10001,
    UNSUPPORTED_CLA = -10002,
    INVALID_P1P2 = -10003,
    UNSUPPORTED_INSTRUCTION = -10004,
    CMD_NOT_ALLOWED = -10005,
    SW_WRONG_LENGTH = -10006,
    INVALID_DATA = -10007,
    CRYPTO_ILLEGAL_USE = -10008,
    CRYPTO_ILLEGAL_VALUE = -10009,
    CRYPTO_INVALID_INIT = -10010,
    CRYPTO_NO_SUCH_ALGORITHM = -10011,
    CRYPTO_UNINITIALIZED_KEY = -10012,
    GENERIC_UNKNOWN_ERROR = -10013
};

static keymaster_error_t translateExtendedErrorsToHalErrors(keymaster_error_t errorCode) {
    keymaster_error_t err = errorCode;
    switch(static_cast<int32_t>(errorCode)) {
        case SW_CONDITIONS_NOT_SATISFIED:
        case UNSUPPORTED_CLA:
        case INVALID_P1P2:
        case INVALID_DATA:
        case CRYPTO_ILLEGAL_USE:
        case CRYPTO_ILLEGAL_VALUE:
        case CRYPTO_INVALID_INIT:
        case CRYPTO_UNINITIALIZED_KEY:
        case GENERIC_UNKNOWN_ERROR:
            err = KM_ERROR_UNKNOWN_ERROR;
            break;
        case CRYPTO_NO_SUCH_ALGORITHM:
            err = KM_ERROR_UNSUPPORTED_ALGORITHM;
            break;
        case UNSUPPORTED_INSTRUCTION:
        case CMD_NOT_ALLOWED:
        case SW_WRONG_LENGTH:
            err = KM_ERROR_UNIMPLEMENTED;
            break;
        default:
            break;
    }
    return err;
}

keymaster_error_t parseWrappedKey(const std::vector<uint8_t> &wrappedKeyData,
                                  std::vector<uint8_t> &iv, std::vector<uint8_t> &transitKey,
                                  std::vector<uint8_t> &secureKey, std::vector<uint8_t> &tag,
                                  AuthorizationSet &authList, keymaster_key_format_t &keyFormat,
                                  std::vector<uint8_t> &wrappedKeyDescription) {
    KeymasterBlob kmIv;
    KeymasterKeyBlob kmTransitKey;
    KeymasterKeyBlob kmSecureKey;
    KeymasterBlob kmTag;
    KeymasterBlob kmWrappedKeyDescription;

    size_t keyDataLen = wrappedKeyData.size();
    uint8_t *keyData = keymaster::dup_buffer(wrappedKeyData.data(), keyDataLen);
    keymaster_key_blob_t keyMaterial = {keyData, keyDataLen};

    keymaster_error_t error = parse_wrapped_key(KeymasterKeyBlob(keyMaterial), &kmIv, &kmTransitKey,
                                                &kmSecureKey, &kmTag, &authList,
                                                &keyFormat, &kmWrappedKeyDescription);
    if (error != KM_ERROR_OK)
        return error;
    blob2Vec(kmIv.data, kmIv.data_length, iv);
    blob2Vec(kmTransitKey.key_material, kmTransitKey.key_material_size, transitKey);
    blob2Vec(kmSecureKey.key_material, kmSecureKey.key_material_size, secureKey);
    blob2Vec(kmTag.data, kmTag.data_length, tag);
    blob2Vec(kmWrappedKeyDescription.data, kmWrappedKeyDescription.data_length, wrappedKeyDescription);

    return KM_ERROR_OK;
}

} // anonymous namespace

keymaster_error_t JavacardKeymaster::handleErrorCode(keymaster_error_t err) {
    //Check if secure element is reset
    uint32_t errorCode = static_cast<uint32_t>(0 - err);
    bool isSeResetOccurred = (0 != (errorCode & SE_POWER_RESET_STATUS_FLAG));

    if (isSeResetOccurred) {
        // TODO Handle clearing the operation entries.
        //Clear the operation table for Strongbox operations entries.
        //clearStrongboxOprHandleEntries(oprCtx);
        // Unmask the power reset status flag.
        errorCode &= ~SE_POWER_RESET_STATUS_FLAG;
    }
    return translateExtendedErrorsToHalErrors(static_cast<keymaster_error_t>(0 - errorCode));
}

std::tuple<std::unique_ptr<Item>, keymaster_error_t> JavacardKeymaster::sendRequest(Instruction ins) {
    auto [item, err] = card_->sendRequest(ins);
    return {std::move(item), handleErrorCode(err)};
}

std::tuple<std::unique_ptr<Item>, keymaster_error_t> JavacardKeymaster::sendRequest(Instruction ins, Array& request) {
    auto [item, err] = card_->sendRequest(ins, request);
    return {std::move(item), handleErrorCode(err)};
}

std::tuple<std::unique_ptr<Item>, keymaster_error_t> JavacardKeymaster::getHardwareInfo() {
    card_->initializeJavacard();
    return card_->sendRequest(Instruction::INS_GET_HW_INFO_CMD);
}

keymaster_error_t JavacardKeymaster::addRngEntropy(const vector<uint8_t>& data) {
    cppbor::Array request;
    // add key data
    request.add(data);
    auto [item, err] = sendRequest(Instruction::INS_ADD_RNG_ENTROPY_CMD, request);
    if (err != KM_ERROR_OK) {
        LOG(ERROR) << "Error in sending addRngEntropy.";
    }
    return err;
}

keymaster_error_t JavacardKeymaster::getHmacSharingParameters(vector<uint8_t>* seed, vector<uint8_t>* nonce) {
    card_->initializeJavacard();
    auto [item, err] = sendRequest(Instruction::INS_GET_SHARED_SECRET_PARAM_CMD);
     if (err == KM_ERROR_OK && !cbor_.getSharedSecretParameters(item, 1, *seed, *nonce)) {
        LOG(ERROR) << "Error in sending in getSharedSecretParameters.";
        return KM_ERROR_UNKNOWN_ERROR;
    }
    return err;
}

keymaster_error_t JavacardKeymaster::computeSharedHmac(const vector<HmacSharingParameters>& params, vector<uint8_t>* secret) {
    card_->initializeJavacard();
    cppbor::Array request;
    cbor_.addSharedSecretParameters(request, params);
    auto [item, err] = sendRequest(Instruction::INS_COMPUTE_SHARED_SECRET_CMD, request);
     if (err == KM_ERROR_OK && !cbor_.getBinaryArray(item, 1, *secret)) {
        LOG(ERROR) << "Error in sending in computeSharedHmac.";
        return KM_ERROR_UNKNOWN_ERROR;
    }
    return err;
}

keymaster_error_t JavacardKeymaster::generateKey(const AuthorizationSet& keyParams,
                                                 vector<uint8_t>* retKeyblob,
                                                 AuthorizationSet* swEnforced,
                                                 AuthorizationSet* hwEnforced,
                                                 AuthorizationSet* teeEnforced) {
    cppbor::Array array;
    // add key params
    cbor_.addKeyparameters(array, keyParams);
    auto [item, err] = sendRequest(Instruction::INS_GENERATE_KEY_CMD, array);
    if (err != KM_ERROR_OK) {
        LOG(ERROR) << "Error in sending generateKey.";
        return err;
    }
    if (!cbor_.getBinaryArray(item, 1, *retKeyblob) ||
        !cbor_.getKeyCharacteristics(item, 2, *swEnforced, *hwEnforced, *teeEnforced)) {
        LOG(ERROR) << "Error in decoding og response in generateKey.";
        return KM_ERROR_UNKNOWN_ERROR;
    }
    return err;

}

keymaster_error_t JavacardKeymaster::attestKey(const vector<uint8_t>& keyblob,
                                               const AuthorizationSet& keyParams,
                                               const vector<uint8_t>& attestKeyBlob,
                                               const AuthorizationSet& attestKeyParams,
                                               const vector<uint8_t>& attestKeyIssuer,
                                               vector<vector<uint8_t>>* certChain) {
    cppbor::Array array;
    array.add(keyblob);
    cbor_.addKeyparameters(array, keyParams);
    array.add(attestKeyBlob);
    cbor_.addKeyparameters(array, attestKeyParams);
    array.add(attestKeyIssuer);
    auto [item, err] = sendRequest(Instruction::INS_ATTEST_KEY_CMD, array);
    if (err != KM_ERROR_OK) {
        LOG(ERROR) << "Error in sending attestKey.";
        return err;
    }
    if (!cbor_.getMultiBinaryArray(item, 1, *certChain)) {
        LOG(ERROR) << "Error in decoding og response in attestKey.";
        return KM_ERROR_UNKNOWN_ERROR;
    }
    return err;
}

keymaster_error_t JavacardKeymaster::getCertChain(vector<vector<uint8_t>>* certChain) {
    vector<uint8_t> certChainData;
    auto [item, err] = sendRequest(Instruction::INS_GET_CERT_CHAIN_CMD);
    if (err != KM_ERROR_OK) {
        LOG(ERROR) << "Error in sending getCertChain.";
        return err;
    }
    if(!cbor_.getBinaryArray(item, 1, certChainData)) {
        LOG(ERROR) << "Error in decoding og response in getCertChain.";
        return KM_ERROR_UNKNOWN_ERROR;
    }
    err = getCertificateChain(certChainData, *certChain);
    if (err != KM_ERROR_OK) {
        LOG(ERROR) << "Error in getCertificateChain: " << (int32_t)err;
    }
    return err;
}

keymaster_error_t JavacardKeymaster::importKey(const AuthorizationSet& keyParams,
                                               const keymaster_key_format_t keyFormat,
                                               const vector<uint8_t>& keyData,
                                               vector<uint8_t>* retKeyblob,
                                               AuthorizationSet* swEnforced,
                                               AuthorizationSet* hwEnforced,
                                               AuthorizationSet* teeEnforced) {
    cppbor::Array array;
    cbor_.addKeyparameters(array, keyParams);
    array.add(static_cast<uint32_t>(keyFormat));
    array.add(keyData);
    auto [item, err] = sendRequest(Instruction::INS_IMPORT_KEY_CMD, array);
    if (err != KM_ERROR_OK) {
        LOG(ERROR) << "Error in sending importKey.";
        return err;
    }
    if (!cbor_.getBinaryArray(item, 1, *retKeyblob) ||
        !cbor_.getKeyCharacteristics(item, 2, *swEnforced, *hwEnforced, *teeEnforced)) {
        LOG(ERROR) << "Error in decoding the response in importKey.";
        return KM_ERROR_UNKNOWN_ERROR;
    }
    return err;
}

keymaster_error_t
JavacardKeymaster::sendBeginImportWrappedKeyCmd(const std::vector<uint8_t>& transitKey,
                                                const std::vector<uint8_t>& wrappingKeyBlob,
                                                const std::vector<uint8_t>& maskingKey,
                                                const AuthorizationSet& unwrappingParams) {
    Array request;
    request.add(std::vector<uint8_t>(transitKey));
    request.add(std::vector<uint8_t>(wrappingKeyBlob));
    request.add(std::vector<uint8_t>(maskingKey));
    cbor_.addKeyparameters(request, unwrappingParams);
    auto [item, err] = sendRequest(Instruction::INS_BEGIN_IMPORT_WRAPPED_KEY_CMD, request);
    if (err != KM_ERROR_OK) {
        LOG(ERROR) << "Error in sending sendBeginImportWrappedKeyCmd err: " << (int32_t) err;
    }
    return err;
}

std::tuple<std::unique_ptr<Item>, keymaster_error_t>
JavacardKeymaster::sendFinishImportWrappedKeyCmd(const AuthorizationSet& keyParams, 
                                                 const keymaster_key_format_t keyFormat,
                                                 const std::vector<uint8_t>& secureKey,
                                                 const std::vector<uint8_t>& tag,
                                                 const std::vector<uint8_t>& iv,
                                                 const std::vector<uint8_t>& wrappedKeyDescription,
                                                 int64_t passwordSid, int64_t biometricSid) {
    Array request;
    cbor_.addKeyparameters(request, keyParams);
    request.add(static_cast<uint64_t>(keyFormat));
    request.add(std::vector<uint8_t>(secureKey));
    request.add(std::vector<uint8_t>(tag));
    request.add(std::vector<uint8_t>(iv));
    request.add(std::vector<uint8_t>(wrappedKeyDescription));
    request.add(Uint(passwordSid));
    request.add(Uint(biometricSid));
    auto [item, err] = sendRequest(Instruction::INS_FINISH_IMPORT_WRAPPED_KEY_CMD, request);
    if (err != KM_ERROR_OK) {
        LOG(ERROR) << "Error in sending sendFinishImportWrappedKeyCmd err: " << (int32_t) err;
        return {nullptr, err};
    }
    return {std::move(item), err};
}

keymaster_error_t JavacardKeymaster::importWrappedKey(const vector<uint8_t>& wrappedKeyData,
                                                      const vector<uint8_t>& wrappingKeyBlob,
                                                      const vector<uint8_t>& maskingKey,
                                                      const AuthorizationSet& unwrappingParams,
                                                      int64_t passwordSid, int64_t biometricSid,
                                                      vector<uint8_t>* retKeyblob,
                                                      AuthorizationSet* swEnforced,
                                                      AuthorizationSet* hwEnforced,
                                                      AuthorizationSet* teeEnforced) {
    cppbor::Array array;
    std::unique_ptr<Item> item;
    std::vector<uint8_t> iv;
    std::vector<uint8_t> transitKey;
    std::vector<uint8_t> secureKey;
    std::vector<uint8_t> tag;
    AuthorizationSet authList;
    keymaster_key_format_t keyFormat;
    std::vector<uint8_t> wrappedKeyDescription;
    auto err = parseWrappedKey(wrappedKeyData, iv, transitKey, secureKey,
                    tag, authList, keyFormat, wrappedKeyDescription);
    if (err != KM_ERROR_OK) {
        LOG(ERROR) << "INS_IMPORT_WRAPPED_KEY_CMD error while parsing wrapped key status: " << (int32_t)err;
        return err;
    }
    // begin import
    err = sendBeginImportWrappedKeyCmd(transitKey, wrappingKeyBlob, maskingKey, unwrappingParams);
    if (err != KM_ERROR_OK) {
        return err;
    }
    // Finish the import
    std::tie(item, err) = sendFinishImportWrappedKeyCmd(
        authList, keyFormat, secureKey, tag, iv, wrappedKeyDescription, passwordSid, biometricSid);
    if (err != KM_ERROR_OK) {
        return err;
    }
    if (!cbor_.getBinaryArray(item, 1, *retKeyblob) ||
        !cbor_.getKeyCharacteristics(item, 2, *swEnforced, *hwEnforced, *teeEnforced)) {
        LOG(ERROR) << "Error in decoding the response in importWrappedKey.";
        return KM_ERROR_UNKNOWN_ERROR;
    }
    return KM_ERROR_OK;
}

keymaster_error_t JavacardKeymaster::upgradeKey(const vector<uint8_t>& keyBlobToUpgrade,
                                                const AuthorizationSet& upgradeParams,
                                                vector<uint8_t>* retKeyBlob) {
    cppbor::Array array;
    array.add(keyBlobToUpgrade);
    cbor_.addKeyparameters(array, upgradeParams);
    auto [item, err] = sendRequest(Instruction::INS_UPGRADE_KEY_CMD, array);
    if (err != KM_ERROR_OK) {
        LOG(ERROR) << "Error in sending upgradeKey err: " << (int32_t) err;
        return err;
    }
    if (!cbor_.getBinaryArray(item, 1, *retKeyBlob)) {
        LOG(ERROR) << "Error in decoding the response in upgradeKey.";
        return KM_ERROR_UNKNOWN_ERROR;
    }
    return KM_ERROR_OK;
}

keymaster_error_t JavacardKeymaster::deleteKey(const vector<uint8_t>& keyBlob) {
    cppbor::Array array;
    array.add(keyBlob);
    auto [_, err] = sendRequest(Instruction::INS_DELETE_KEY_CMD, array);
    if (err != KM_ERROR_OK) {
        LOG(ERROR) << "Error in sending deleteKey err: " << (int32_t) err;
        return err;
    }
    return KM_ERROR_OK;
}

keymaster_error_t JavacardKeymaster::deleteAllKeys() {
    auto [_, err] = sendRequest(Instruction::INS_DELETE_ALL_KEYS_CMD);
    if (err != KM_ERROR_OK) {
        LOG(ERROR) << "Error in sending deleteAllKeys err: " << (int32_t) err;
        return err;
    }
    return KM_ERROR_OK;
}

keymaster_error_t JavacardKeymaster::destroyAttestationIds() {
    auto [_, err] = sendRequest(Instruction::INS_DESTROY_ATT_IDS_CMD);
    if (err != KM_ERROR_OK) {
        LOG(ERROR) << "Error in sending destroyAttestationIds err: " << (int32_t) err;
        return err;
    }
    return KM_ERROR_OK;
}
#if 0
keymaster_error_t JavacardKeymaster::begin(KeyPurpose in_purpose, const std::vector<uint8_t>& in_keyBlob,
                                           const std::AuthorizationSet& in_params,
                                           const vector<uint8_t>& cborEncodedHwToken,
                                           uint64_t *operationHandle,
                                           uint32_t *bufMode,
                                           uint32_t *macLength) {

}
#endif

keymaster_error_t JavacardKeymaster::deviceLocked(bool passwordOnly,
                                                  const vector<uint8_t>& cborEncodedVerificationToken) {
    auto [_, err] = sendRequest(Instruction::INS_DEVICE_LOCKED_CMD);
    if (err != KM_ERROR_OK) {
        LOG(ERROR) << "Error in sending destroyAttestationIds err: " << (int32_t) err;
        return err;
    }
    return KM_ERROR_OK;
}

keymaster_error_t JavacardKeymaster::earlyBootEnded() {

}

keymaster_error_t JavacardKeymaster::getKeyCharacteristics(const std::vector<uint8_t>& in_keyBlob,
                                                           const std::vector<uint8_t>& in_appId,
                                                           const std::vector<uint8_t>& in_appData,
                                                           AuthorizationSet* swEnforced,
                                                           AuthorizationSet* hwEnforced,
                                                           AuthorizationSet* teeEnforced) {

}

keymaster_error_t JavacardKeymaster::exportKey(keymaster_key_format_t exportFormat,
                                               const vector<uint8_t>& keyBlob,
                                               const vector<uint8_t>& clientId,
                                               const vector<uint8_t>& appData,
                                               vector<uint8_t>* retKeyblob) {

}
#endif
} // javacard_keymaster