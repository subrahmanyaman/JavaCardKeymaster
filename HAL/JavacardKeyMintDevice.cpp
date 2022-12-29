/*
 * Copyright 2020, The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#define LOG_TAG "javacard.keymint.device.strongbox-impl"

#include "JavacardKeyMintDevice.h"

#include <regex.h>

#include <algorithm>
#include <iostream>
#include <iterator>
#include <memory>
#include <string>
#include <vector>

#include <KeyMintUtils.h>
#include <android-base/logging.h>
#include <android-base/properties.h>
#include <hardware/hw_auth_token.h>
#include <keymaster/android_keymaster_messages.h>
#include <keymaster/wrapped_key.h>

#include "JavacardKeyMintOperation.h"
#include "JavacardSharedSecret.h"

constexpr int minGcmMinMacLength = 96;
constexpr int maxGcmMinMacLength = 128;
constexpr int minHmacLengthBits = 64;
constexpr int sha256DigestLengthBits = 256;
constexpr int rsaPublicExponent = 65537;

namespace aidl::android::hardware::security::keymint {
using cppbor::Bstr;
using cppbor::EncodedItem;
using cppbor::Uint;
using ::keymaster::AuthorizationSet;
using ::keymaster::dup_buffer;
using ::keymaster::KeymasterBlob;
using ::keymaster::KeymasterKeyBlob;
using ::keymint::javacard::Instruction;
using std::string;

ScopedAStatus JavacardKeyMintDevice::defaultHwInfo(KeyMintHardwareInfo* info) {
    info->versionNumber = 2;
    info->keyMintAuthorName = "Google";
    info->keyMintName = "JavacardKeymintDevice";
    info->securityLevel = securitylevel_;
    info->timestampTokenRequired = true;
    return ScopedAStatus::ok();
}

ScopedAStatus JavacardKeyMintDevice::getHardwareInfo(KeyMintHardwareInfo* info) {
    auto [item, err] = card_->sendRequest(Instruction::INS_GET_HW_INFO_CMD);
    std::optional<string> optKeyMintName;
    std::optional<string> optKeyMintAuthorName;
    std::optional<uint64_t> optSecLevel;
    std::optional<uint64_t> optVersion;
    std::optional<uint64_t> optTsRequired;
    if (err != KM_ERROR_OK || !(optVersion = cbor_.getUint64(item, 1)) ||
        !(optSecLevel = cbor_.getUint64(item, 2)) ||
        !(optKeyMintName = cbor_.getByteArrayStr(item, 3)) ||
        !(optKeyMintAuthorName = cbor_.getByteArrayStr(item, 4)) ||
        !(optTsRequired = cbor_.getUint64(item, 5))) {
        LOG(ERROR) << "Error in response of getHardwareInfo.";
        LOG(INFO) << "Returning defaultHwInfo in getHardwareInfo.";
        return defaultHwInfo(info);
    }
    card_->initializeJavacard();
    info->keyMintName = std::move(optKeyMintName.value());
    info->keyMintAuthorName = std::move(optKeyMintAuthorName.value());
    info->timestampTokenRequired = (optTsRequired.value() == 1);
    info->securityLevel = static_cast<SecurityLevel>(std::move(optSecLevel.value()));
    info->versionNumber = static_cast<int32_t>(std::move(optVersion.value()));
    return ScopedAStatus::ok();
}

keymaster_error_t validateKeySize(keymaster_algorithm_t& algo, uint32_t& key_size) {
    switch (algo) {
        case KM_ALGORITHM_RSA:
            if (key_size != 2048) {
                LOG(ERROR) << "Invalid key size specified for RSA key generation";
                return KM_ERROR_UNSUPPORTED_KEY_SIZE;
            }
            break;

        case KM_ALGORITHM_EC:
            if (key_size != 256) {
                LOG(ERROR) << "Invalid key size specified for EC key generation";
                return KM_ERROR_UNSUPPORTED_KEY_SIZE;
            }
            break;

        case KM_ALGORITHM_AES:
            if (!(key_size == 128 || key_size == 256)) {
                LOG(ERROR) << "Invalid key size specified for AES key generation";
                return KM_ERROR_UNSUPPORTED_KEY_SIZE;
            }
            break;

        case KM_ALGORITHM_TRIPLE_DES:
            if (key_size != 168) {
                LOG(ERROR) << "Invalid key size specified for TDES key generation";
                return KM_ERROR_UNSUPPORTED_KEY_SIZE;
            }
            break;

        case KM_ALGORITHM_HMAC:
            if (!((key_size % 8 == 0)
                && key_size >= 64
                && key_size <= 512)) {
                 LOG(ERROR) << "Invalid key size specified for HMAC key generation";
                return KM_ERROR_UNSUPPORTED_KEY_SIZE;
            }
            break;

        default :
            return KM_ERROR_UNSUPPORTED_ALGORITHM;
    }
    return KM_ERROR_OK;
}

keymaster_error_t validateRSAKeyParam(AuthorizationSet& keyParams){
    uint64_t public_exponent;
    if (!keyParams.GetTagValue(keymaster::TAG_RSA_PUBLIC_EXPONENT, &public_exponent)) {
        LOG(ERROR) << "No public exponent specified for RSA key generation";
        return KM_ERROR_INVALID_ARGUMENT;
    }
    if (public_exponent != rsaPublicExponent) {
        LOG(ERROR) << "Invalid public exponent specified for RSA key generation";
        return KM_ERROR_INVALID_ARGUMENT;
    }
    return KM_ERROR_OK;
}

keymaster_error_t validateECKeyParam(AuthorizationSet& keyParams){
    keymaster_ec_curve_t curve;
    if (!keyParams.GetTagValue(keymaster::TAG_EC_CURVE, &curve)) {
        LOG(ERROR) << "Invalid EC curve";
        return KM_ERROR_UNSUPPORTED_KEY_SIZE;
    }
    if(curve !=  KM_EC_CURVE_P_256) {
        LOG(ERROR) << "Invalid EC curve";
        return KM_ERROR_UNSUPPORTED_KEY_SIZE;
    }
    return KM_ERROR_OK; 
}

keymaster_error_t validateAESKeyParam(AuthorizationSet& keyParams){
    if (keyParams.Contains(keymaster::TAG_BLOCK_MODE, KM_MODE_GCM)) {
        uint32_t min_tag_length;
        if (!keyParams.GetTagValue(keymaster::TAG_MIN_MAC_LENGTH, &min_tag_length))
            return KM_ERROR_MISSING_MIN_MAC_LENGTH;

        if ((min_tag_length % 8 != 0)
            || min_tag_length < minGcmMinMacLength
            || min_tag_length > maxGcmMinMacLength) {
                return KM_ERROR_UNSUPPORTED_MIN_MAC_LENGTH;
        }
    } else {
        // Not GCM
        if (keyParams.find(keymaster::TAG_MIN_MAC_LENGTH) != -1) {
            LOG(ERROR) << "KM_TAG_MIN_MAC_LENGTH found for non AES-GCM key";
            return KM_ERROR_INVALID_TAG;
        }
    }
    return KM_ERROR_OK;
}

keymaster_error_t validateTDESKeyParam(AuthorizationSet& keyParams){
    // Read Minimum Mac length - it must not be present
    if (keyParams.Contains(keymaster::TAG_MIN_MAC_LENGTH)) {
        return KM_ERROR_INVALID_TAG;
    }
    return KM_ERROR_OK;
}

keymaster_error_t validateHMACKeyParam(AuthorizationSet& keyParams) {
    // If params does not contain any digest throw unsupported digest error.
    keymaster_digest_t digest;
    if (!keyParams.GetTagValue(keymaster::TAG_DIGEST, &digest)) {
        return KM_ERROR_UNSUPPORTED_DIGEST;
    }
    if(digest != KM_DIGEST_SHA_2_256) {
        return KM_ERROR_UNSUPPORTED_DIGEST;
    }
    uint32_t min_mac_length_bits;
    if (!keyParams.GetTagValue(keymaster::TAG_MIN_MAC_LENGTH, &min_mac_length_bits)) {
        return KM_ERROR_MISSING_MIN_MAC_LENGTH;
    }
    if ((min_mac_length_bits % 8 != 0)
        || min_mac_length_bits < minHmacLengthBits
        || min_mac_length_bits > sha256DigestLengthBits) {
        return KM_ERROR_UNSUPPORTED_MIN_MAC_LENGTH;
    }
    return KM_ERROR_OK;
}

keymaster_error_t validateGenerateKeyParams(AuthorizationSet& keyParams) {
    keymaster_algorithm_t algo;
    // Check for unsupported tags.
    if (keyParams.Contains(KM_TAG_TRUSTED_USER_PRESENCE_REQUIRED) ||
            keyParams.Contains(KM_TAG_MIN_SECONDS_BETWEEN_OPS)) {
        return KM_ERROR_UNSUPPORTED_TAG;
    }
    if (keyParams.Contains(keymaster::TAG_PURPOSE, KM_PURPOSE_ATTEST_KEY) &&
        keyParams.GetTagCount(keymaster::TAG_PURPOSE) > 1) {
        // ATTEST_KEY cannot be combined with any other purpose.
        return KM_ERROR_INCOMPATIBLE_PURPOSE;
    }
    // Algorithm must be present
    if (!keyParams.GetTagValue(keymaster::TAG_ALGORITHM, &algo)) {
        return KM_ERROR_INVALID_ARGUMENT;
    }
    uint32_t key_size;
    if (keyParams.GetTagValue(keymaster::TAG_KEY_SIZE, &key_size)) {
        auto error =  validateKeySize(algo, key_size);
        if (error != KM_ERROR_OK) {
            return error;
        }
    } else {
        if(algo != KM_ALGORITHM_EC) {
            return KM_ERROR_UNSUPPORTED_KEY_SIZE;
        }
    }
    switch (algo) {
        case KM_ALGORITHM_RSA:
            return validateRSAKeyParam(keyParams);

        case KM_ALGORITHM_EC:
            return validateECKeyParam(keyParams);

        case KM_ALGORITHM_AES:
            return validateAESKeyParam(keyParams);

        case KM_ALGORITHM_TRIPLE_DES:
            return validateTDESKeyParam(keyParams);

        case KM_ALGORITHM_HMAC:
            return validateHMACKeyParam(keyParams);

        default :
            return KM_ERROR_UNSUPPORTED_ALGORITHM;
    }
    return KM_ERROR_OK;
}

ScopedAStatus JavacardKeyMintDevice::generateKey(const vector<KeyParameter>& keyParams,
                                                 const optional<AttestationKey>& attestationKey,
                                                 KeyCreationResult* creationResult) {
    AuthorizationSet key_parameters;
    key_parameters.Reinitialize(km_utils::KmParamSet(keyParams));
    auto error = validateGenerateKeyParams(key_parameters);
    if (error != KM_ERROR_OK) {
        LOG(ERROR) << "Error while validating generatekey key parameters.";
        return km_utils::kmError2ScopedAStatus(error);
    }
    cppbor::Array array;
    // add key params
    cbor_.addKeyparameters(array, keyParams);
    // add attestation key if any
    cbor_.addAttestationKey(array, attestationKey);
    auto [item, err] = card_->sendRequest(Instruction::INS_GENERATE_KEY_CMD, array);
    if (err != KM_ERROR_OK) {
        LOG(ERROR) << "Error in sending generateKey.";
        return km_utils::kmError2ScopedAStatus(err);
    }
    auto optKeyBlob = cbor_.getByteArrayVec(item, 1);
    auto optKeyChars = cbor_.getKeyCharacteristics(item, 2);
    auto optCertChain = cbor_.getCertificateChain(item, 3);
    if (!optKeyBlob || !optKeyChars || !optCertChain) {
        LOG(ERROR) << "Error in decoding og response in generateKey.";
        return km_utils::kmError2ScopedAStatus(KM_ERROR_UNKNOWN_ERROR);
    }
    creationResult->keyCharacteristics = std::move(optKeyChars.value());
    creationResult->certificateChain = std::move(optCertChain.value());
    creationResult->keyBlob = std::move(optKeyBlob.value());
    return ScopedAStatus::ok();
}

ScopedAStatus JavacardKeyMintDevice::addRngEntropy(const vector<uint8_t>& data) {
    cppbor::Array request;
    // add key data
    request.add(Bstr(data));
    auto [item, err] = card_->sendRequest(Instruction::INS_ADD_RNG_ENTROPY_CMD, request);
    if (err != KM_ERROR_OK) {
        LOG(ERROR) << "Error in sending addRngEntropy.";
        return km_utils::kmError2ScopedAStatus(err);
    }
    return ScopedAStatus::ok();
}

keymaster_error_t validateImportKeyParams(AuthorizationSet& keyParams, KeyFormat& keyFormat) {
    if (keyParams.Contains(keymaster::TAG_PURPOSE, KM_PURPOSE_ATTEST_KEY) &&
        keyParams.GetTagCount(keymaster::TAG_PURPOSE) > 1) {
        // ATTEST_KEY cannot be combined with any other purpose.
        return KM_ERROR_INCOMPATIBLE_PURPOSE;
    }
    // Check for unsupported tags.
    if (keyParams.Contains(KM_TAG_TRUSTED_USER_PRESENCE_REQUIRED) ||
            keyParams.Contains(KM_TAG_MIN_SECONDS_BETWEEN_OPS)) {
        return KM_ERROR_UNSUPPORTED_TAG;
    }
    keymaster_algorithm_t algo;
    // Algorithm must be present
    if (!keyParams.GetTagValue(keymaster::TAG_ALGORITHM, &algo)) {
        return KM_ERROR_INVALID_ARGUMENT;
    }
    // key format must be raw if aes, des or hmac and pkcs8 for rsa and ec.
    if ((algo == KM_ALGORITHM_AES || algo == KM_ALGORITHM_TRIPLE_DES || algo == KM_ALGORITHM_HMAC) && keyFormat != KeyFormat::RAW) {
        return KM_ERROR_UNIMPLEMENTED;
    }
    if ((algo == KM_ALGORITHM_RSA || algo == KM_ALGORITHM_EC) && keyFormat != KeyFormat::PKCS8) {
        return KM_ERROR_UNIMPLEMENTED;
    }
    uint32_t key_size;
    if (keyParams.GetTagValue(keymaster::TAG_KEY_SIZE, &key_size)) {
        auto error = validateKeySize(algo, key_size);
        if(error != KM_ERROR_OK) {
            return error;
        }
    }
    switch (algo) {
        case KM_ALGORITHM_RSA:
        case KM_ALGORITHM_EC:
        case KM_ALGORITHM_TRIPLE_DES:
            break;

        case KM_ALGORITHM_AES:
            return validateAESKeyParam(keyParams);

        case KM_ALGORITHM_HMAC:
            return validateHMACKeyParam(keyParams);

        default :
            return KM_ERROR_UNSUPPORTED_ALGORITHM;
    }
    return KM_ERROR_OK;
}

ScopedAStatus JavacardKeyMintDevice::importKey(const vector<KeyParameter>& keyParams,
                                               KeyFormat keyFormat, const vector<uint8_t>& keyData,
                                               const optional<AttestationKey>& attestationKey,
                                               KeyCreationResult* creationResult) {
    AuthorizationSet key_parameters;
    key_parameters.Reinitialize(km_utils::KmParamSet(keyParams));
    auto error = validateImportKeyParams(key_parameters, keyFormat);
    if (error != KM_ERROR_OK) {
        LOG(ERROR) << "Error in Importkey";
        return km_utils::kmError2ScopedAStatus(error);
    }
    cppbor::Array request;
    // add key params
    cbor_.addKeyparameters(request, keyParams);
    // add key format
    request.add(Uint(static_cast<uint8_t>(keyFormat)));
    // add key data
    request.add(Bstr(keyData));
    // add attestation key if any
    cbor_.addAttestationKey(request, attestationKey);

    auto [item, err] = card_->sendRequest(Instruction::INS_IMPORT_KEY_CMD, request);
    if (err != KM_ERROR_OK) {
        LOG(ERROR) << "Error in sending data in importKey.";
        return km_utils::kmError2ScopedAStatus(err);
    }
    auto optKeyBlob = cbor_.getByteArrayVec(item, 1);
    auto optKeyChars = cbor_.getKeyCharacteristics(item, 2);
    auto optCertChain = cbor_.getCertificateChain(item, 3);
    if (!optKeyBlob || !optKeyChars || !optCertChain) {
        LOG(ERROR) << "Error in decoding response in importKey.";
        return km_utils::kmError2ScopedAStatus(KM_ERROR_UNKNOWN_ERROR);
    }
    creationResult->keyCharacteristics = std::move(optKeyChars.value());
    creationResult->certificateChain = std::move(optCertChain.value());
    creationResult->keyBlob = std::move(optKeyBlob.value());
    return ScopedAStatus::ok();
}

// import wrapped key is divided into 2 stage operation.
ScopedAStatus JavacardKeyMintDevice::importWrappedKey(const vector<uint8_t>& wrappedKeyData,
                                                      const vector<uint8_t>& wrappingKeyBlob,
                                                      const vector<uint8_t>& maskingKey,
                                                      const vector<KeyParameter>& unwrappingParams,
                                                      int64_t passwordSid, int64_t biometricSid,
                                                      KeyCreationResult* creationResult) {
    cppbor::Array request;
    std::unique_ptr<Item> item;
    vector<uint8_t> keyBlob;
    std::vector<uint8_t> response;
    vector<KeyCharacteristics> keyCharacteristics;
    std::vector<uint8_t> iv;
    std::vector<uint8_t> transitKey;
    std::vector<uint8_t> secureKey;
    std::vector<uint8_t> tag;
    vector<KeyParameter> authList;
    KeyFormat keyFormat;
    std::vector<uint8_t> wrappedKeyDescription;
    keymaster_error_t errorCode = parseWrappedKey(wrappedKeyData, iv, transitKey, secureKey, tag,
                                                  authList, keyFormat, wrappedKeyDescription);
    if (errorCode != KM_ERROR_OK) {
        LOG(ERROR) << "Error in parse wrapped key in importWrappedKey.";
        return km_utils::kmError2ScopedAStatus(errorCode);
    }

    // begin import
    std::tie(item, errorCode) =
        sendBeginImportWrappedKeyCmd(transitKey, wrappingKeyBlob, maskingKey, unwrappingParams);
    if (errorCode != KM_ERROR_OK) {
        LOG(ERROR) << "Error in send begin import wrapped key in importWrappedKey.";
        return km_utils::kmError2ScopedAStatus(errorCode);
    }
    AuthorizationSet key_parameters;
    key_parameters.Reinitialize(km_utils::KmParamSet(authList));
    auto error = validateImportKeyParams(key_parameters, keyFormat);
    if (error != KM_ERROR_OK) {
        LOG(ERROR) << "Error in importWrappedKey.";
        return km_utils::kmError2ScopedAStatus(error);
    }
    // Finish the import
    std::tie(item, errorCode) = sendFinishImportWrappedKeyCmd(
        authList, keyFormat, secureKey, tag, iv, wrappedKeyDescription, passwordSid, biometricSid);
    if (errorCode != KM_ERROR_OK) {
        LOG(ERROR) << "Error in send finish import wrapped key in importWrappedKey.";
        return km_utils::kmError2ScopedAStatus(errorCode);
    }
    auto optKeyBlob = cbor_.getByteArrayVec(item, 1);
    auto optKeyChars = cbor_.getKeyCharacteristics(item, 2);
    auto optCertChain = cbor_.getCertificateChain(item, 3);
    if (!optKeyBlob || !optKeyChars || !optCertChain) {
        LOG(ERROR) << "Error in decoding the response in importWrappedKey.";
        return km_utils::kmError2ScopedAStatus(KM_ERROR_UNKNOWN_ERROR);
    }
    creationResult->keyCharacteristics = std::move(optKeyChars.value());
    creationResult->certificateChain = std::move(optCertChain.value());
    creationResult->keyBlob = std::move(optKeyBlob.value());
    return ScopedAStatus::ok();
}

std::tuple<std::unique_ptr<Item>, keymaster_error_t>
JavacardKeyMintDevice::sendBeginImportWrappedKeyCmd(const std::vector<uint8_t>& transitKey,
                                                    const std::vector<uint8_t>& wrappingKeyBlob,
                                                    const std::vector<uint8_t>& maskingKey,
                                                    const vector<KeyParameter>& unwrappingParams) {
    Array request;
    request.add(std::vector<uint8_t>(transitKey));
    request.add(std::vector<uint8_t>(wrappingKeyBlob));
    request.add(std::vector<uint8_t>(maskingKey));
    cbor_.addKeyparameters(request, unwrappingParams);
    return card_->sendRequest(Instruction::INS_BEGIN_IMPORT_WRAPPED_KEY_CMD, request);
}

std::tuple<std::unique_ptr<Item>, keymaster_error_t>
JavacardKeyMintDevice::sendFinishImportWrappedKeyCmd(
    const vector<KeyParameter>& keyParams, KeyFormat keyFormat,
    const std::vector<uint8_t>& secureKey, const std::vector<uint8_t>& tag,
    const std::vector<uint8_t>& iv, const std::vector<uint8_t>& wrappedKeyDescription,
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
    return card_->sendRequest(Instruction::INS_FINISH_IMPORT_WRAPPED_KEY_CMD, request);
}

ScopedAStatus JavacardKeyMintDevice::upgradeKey(const vector<uint8_t>& keyBlobToUpgrade,
                                                const vector<KeyParameter>& upgradeParams,
                                                vector<uint8_t>* keyBlob) {
    cppbor::Array request;
    // add key blob
    request.add(Bstr(keyBlobToUpgrade));
    // add key params
    cbor_.addKeyparameters(request, upgradeParams);
    auto [item, err] = card_->sendRequest(Instruction::INS_UPGRADE_KEY_CMD, request);
    if (err != KM_ERROR_OK) {
        LOG(ERROR) << "Error in sending in upgradeKey.";
        return km_utils::kmError2ScopedAStatus(err);
    }
    auto optKeyBlob = cbor_.getByteArrayVec(item, 1);
    if (!optKeyBlob) {
        LOG(ERROR) << "Error in decoding the response in upgradeKey.";
        return km_utils::kmError2ScopedAStatus(KM_ERROR_UNKNOWN_ERROR);
    }
    *keyBlob = std::move(optKeyBlob.value());
    return ScopedAStatus::ok();
}

ScopedAStatus JavacardKeyMintDevice::deleteKey(const vector<uint8_t>& keyBlob) {
    Array request;
    request.add(Bstr(keyBlob));
    auto [item, err] = card_->sendRequest(Instruction::INS_DELETE_KEY_CMD, request);
    if (err != KM_ERROR_OK) {
        LOG(ERROR) << "Error in sending in deleteKey.";
        return km_utils::kmError2ScopedAStatus(err);
    }
    return ScopedAStatus::ok();
}

ScopedAStatus JavacardKeyMintDevice::deleteAllKeys() {
    auto [item, err] = card_->sendRequest(Instruction::INS_DELETE_ALL_KEYS_CMD);
    if (err != KM_ERROR_OK) {
        LOG(ERROR) << "Error in sending in deleteAllKeys.";
        return km_utils::kmError2ScopedAStatus(err);
    }
    return ScopedAStatus::ok();
}

ScopedAStatus JavacardKeyMintDevice::destroyAttestationIds() {
    auto [item, err] = card_->sendRequest(Instruction::INS_DESTROY_ATT_IDS_CMD);
    if (err != KM_ERROR_OK) {
        LOG(ERROR) << "Error in sending in destroyAttestationIds.";
        return km_utils::kmError2ScopedAStatus(err);
    }
    return ScopedAStatus::ok();
}

ScopedAStatus JavacardKeyMintDevice::begin(KeyPurpose purpose, const std::vector<uint8_t>& keyBlob,
                                           const std::vector<KeyParameter>& params,
                                           const std::optional<HardwareAuthToken>& authToken,
                                           BeginResult* result) {

    cppbor::Array array;
    std::vector<uint8_t> response;
    // make request
    array.add(Uint(static_cast<uint64_t>(purpose)));
    array.add(Bstr(keyBlob));
    cbor_.addKeyparameters(array, params);
    HardwareAuthToken token = authToken.value_or(HardwareAuthToken());
    cbor_.addHardwareAuthToken(array, token);

    // Send earlyBootEnded if there is any pending earlybootEnded event.
    auto retErr = card_->sendEarlyBootEndedEvent(false);
    if (retErr != KM_ERROR_OK) {
        return km_utils::kmError2ScopedAStatus(retErr);
        ;
    }

    auto [item, err] = card_->sendRequest(Instruction::INS_BEGIN_OPERATION_CMD, array);
    if (err != KM_ERROR_OK) {
        LOG(ERROR) << "Error in sending in begin.";
        return km_utils::kmError2ScopedAStatus(err);
    }
    // return the result
    auto keyParams = cbor_.getKeyParameters(item, 1);
    auto optOpHandle = cbor_.getUint64(item, 2);
    auto optBufMode = cbor_.getUint64(item, 3);
    auto optMacLength = cbor_.getUint64(item, 4);

    if (!keyParams || !optOpHandle || !optBufMode || !optMacLength) {
        LOG(ERROR) << "Error in decoding the response in begin.";
        return km_utils::kmError2ScopedAStatus(KM_ERROR_UNKNOWN_ERROR);
    }
    result->params = std::move(keyParams.value());
    result->challenge = optOpHandle.value();
    result->operation = ndk::SharedRefBase::make<JavacardKeyMintOperation>(
        static_cast<keymaster_operation_handle_t>(optOpHandle.value()),
        static_cast<BufferingMode>(optBufMode.value()), optMacLength.value(), card_);
    return ScopedAStatus::ok();
}

ScopedAStatus
JavacardKeyMintDevice::deviceLocked(bool passwordOnly,
                                    const std::optional<TimeStampToken>& timestampToken) {
    Array request;
    int8_t password = 1;
    if (!passwordOnly) {
        password = 0;
    }
    request.add(Uint(password));
    cbor_.addTimeStampToken(request, timestampToken.value_or(TimeStampToken()));
    auto [item, err] = card_->sendRequest(Instruction::INS_DEVICE_LOCKED_CMD, request);
    if (err != KM_ERROR_OK) {
        return km_utils::kmError2ScopedAStatus(err);
    }
    return ScopedAStatus::ok();
}

ScopedAStatus JavacardKeyMintDevice::earlyBootEnded() {
    auto err = card_->sendEarlyBootEndedEvent(true);
    if (err != KM_ERROR_OK) {
        LOG(ERROR) << "Error in sending earlyBootEndedEvent.";
        return km_utils::kmError2ScopedAStatus(err);
    }
    return ScopedAStatus::ok();
}

ScopedAStatus JavacardKeyMintDevice::getKeyCharacteristics(
    const std::vector<uint8_t>& keyBlob, const std::vector<uint8_t>& appId,
    const std::vector<uint8_t>& appData, std::vector<KeyCharacteristics>* result) {
    cppbor::Array request;
    request.add(vector<uint8_t>(keyBlob));
    request.add(vector<uint8_t>(appId));
    request.add(vector<uint8_t>(appData));
    auto [item, err] = card_->sendRequest(Instruction::INS_GET_KEY_CHARACTERISTICS_CMD, request);
    if (err != KM_ERROR_OK) {
        LOG(ERROR) << "Error in sending in getKeyCharacteristics.";
        return km_utils::kmError2ScopedAStatus(err);
    }
    auto optKeyChars = cbor_.getKeyCharacteristics(item, 1);
    if (!optKeyChars) {
        LOG(ERROR) << "Error in sending in upgradeKey.";
        return km_utils::kmError2ScopedAStatus(KM_ERROR_UNKNOWN_ERROR);
    }
    *result = std::move(optKeyChars.value());
    return ScopedAStatus::ok();
}

keymaster_error_t
JavacardKeyMintDevice::parseWrappedKey(const vector<uint8_t>& wrappedKeyData,
                                       std::vector<uint8_t>& iv, std::vector<uint8_t>& transitKey,
                                       std::vector<uint8_t>& secureKey, std::vector<uint8_t>& tag,
                                       vector<KeyParameter>& authList, KeyFormat& keyFormat,
                                       std::vector<uint8_t>& wrappedKeyDescription) {
    KeymasterBlob kmIv;
    KeymasterKeyBlob kmTransitKey;
    KeymasterKeyBlob kmSecureKey;
    KeymasterBlob kmTag;
    AuthorizationSet authSet;
    keymaster_key_format_t kmKeyFormat;
    KeymasterBlob kmWrappedKeyDescription;

    size_t keyDataLen = wrappedKeyData.size();
    uint8_t* keyData = dup_buffer(wrappedKeyData.data(), keyDataLen);
    keymaster_key_blob_t keyMaterial = {keyData, keyDataLen};
    keymaster_error_t error =
        parse_wrapped_key(KeymasterKeyBlob(keyMaterial), &kmIv, &kmTransitKey, &kmSecureKey, &kmTag,
                          &authSet, &kmKeyFormat, &kmWrappedKeyDescription);
    if (error != KM_ERROR_OK) {
        LOG(ERROR) << "Error parsing wrapped key.";
        return error;
    }
    iv = km_utils::kmBlob2vector(kmIv);
    transitKey = km_utils::kmBlob2vector(kmTransitKey);
    secureKey = km_utils::kmBlob2vector(kmSecureKey);
    tag = km_utils::kmBlob2vector(kmTag);
    authList = km_utils::kmParamSet2Aidl(authSet);
    keyFormat = static_cast<KeyFormat>(kmKeyFormat);
    wrappedKeyDescription = km_utils::kmBlob2vector(kmWrappedKeyDescription);
    return KM_ERROR_OK;
}

ScopedAStatus JavacardKeyMintDevice::convertStorageKeyToEphemeral(
    const std::vector<uint8_t>& /* storageKeyBlob */,
    std::vector<uint8_t>* /* ephemeralKeyBlob */) {
    return km_utils::kmError2ScopedAStatus(KM_ERROR_UNIMPLEMENTED);
}

ScopedAStatus JavacardKeyMintDevice::getRootOfTrustChallenge(array<uint8_t, 16>* challenge) {
    auto [item, err] = card_->sendRequest(Instruction::INS_GET_ROT_CHALLENGE_CMD);
    if (err != KM_ERROR_OK) {
        LOG(ERROR) << "Error in sending in getRootOfTrustChallenge.";
        return km_utils::kmError2ScopedAStatus(err);
    }
    auto optChallenge = cbor_.getByteArrayVec(item, 1);
    if (!optChallenge) {
        LOG(ERROR) << "Error in sending in upgradeKey.";
        return km_utils::kmError2ScopedAStatus(KM_ERROR_UNKNOWN_ERROR);
    }
    std::move(optChallenge->begin(), optChallenge->begin() + 16, challenge->begin());
    return ScopedAStatus::ok();
}

ScopedAStatus JavacardKeyMintDevice::getRootOfTrust(const array<uint8_t, 16>& /*challenge*/,
                                                    vector<uint8_t>* /*rootOfTrust*/) {
    return km_utils::kmError2ScopedAStatus(KM_ERROR_UNIMPLEMENTED);
}

ScopedAStatus JavacardKeyMintDevice::sendRootOfTrust(const vector<uint8_t>& rootOfTrust) {
    cppbor::Array request;
    request.add(EncodedItem(rootOfTrust));  // taggedItem.
    auto [item, err] = card_->sendRequest(Instruction::INS_SEND_ROT_DATA_CMD, request);
    if (err != KM_ERROR_OK) {
        LOG(ERROR) << "Error in sending in sendRootOfTrust.";
        return km_utils::kmError2ScopedAStatus(err);
    }
    LOG(INFO) << "JavacardKeyMintDevice::sendRootOfTrust success";
    return ScopedAStatus::ok();
}

}  // namespace aidl::android::hardware::security::keymint
