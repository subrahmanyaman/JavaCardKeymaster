/*
 **
 ** Copyright 2020, The Android Open Source Project
 **
 ** Licensed under the Apache License, Version 2.0 (the "License");
 ** you may not use this file except in compliance with the License.
 ** You may obtain a copy of the License at
 **
 **     http://www.apache.org/licenses/LICENSE-2.0
 **
 ** Unless required by applicable law or agreed to in writing, software
 ** distributed under the License is distributed on an "AS IS" BASIS,
 ** WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 ** See the License for the specific language governing permissions and
 ** limitations under the License.
 */
#include <CborConverter.h>

#include <JavacardKeymaster4Device.h>
#include <android-base/logging.h>
#include <keymaster/km_openssl/openssl_err.h>
#include <keymaster/km_openssl/openssl_utils.h>
#include <keymaster/km_openssl/attestation_record.h>
#include <km_utils.h>
#include <time.h>


#define JAVACARD_KEYMASTER_NAME      "JavacardKeymaster4.1Device v1.0"
#define JAVACARD_KEYMASTER_AUTHOR    "Android Open Source Project"
#define PROP_BUILD_QEMU              "ro.kernel.qemu"
#define PROP_BUILD_FINGERPRINT       "ro.build.fingerprint"

namespace keymaster {
namespace V4_1 {
namespace javacard {

using javacard_keymaster::Instruction;
using std::vector;
using std::string;

constexpr size_t kOperationTableSize = 4;

struct KM_AUTH_LIST_Delete {
    void operator()(KM_AUTH_LIST* p) { KM_AUTH_LIST_free(p); }
};

namespace {

inline ErrorCode legacy_enum_conversion(const keymaster_error_t value) {
    return static_cast<ErrorCode>(value);
}

inline keymaster_tag_t legacy_enum_conversion(const Tag value) {
    return keymaster_tag_t(value);
}

inline Tag legacy_enum_conversion(const keymaster_tag_t value) {
    return Tag(value);
}

inline keymaster_tag_type_t typeFromTag(const keymaster_tag_t tag) {
    return keymaster_tag_get_type(tag);
}

inline keymaster_security_level_t legacy_enum_conversion(const SecurityLevel value) {
    return static_cast<keymaster_security_level_t>(value);
}

inline keymaster_key_format_t legacy_enum_conversion(const KeyFormat value) {
    return static_cast<keymaster_key_format_t>(value);
}

inline void hidlVec2KmBlob(const hidl_vec<uint8_t>& input, KeymasterBlob* blob) {
    blob->Reset(input.size());
    memcpy(blob->writable_data(), input.data(), input.size());
}


keymaster_key_param_set_t hidlKeyParams2Km(const hidl_vec<KeyParameter>& keyParams) {
    keymaster_key_param_set_t set;

    set.params = new keymaster_key_param_t[keyParams.size()];
    set.length = keyParams.size();

    for (size_t i = 0; i < keyParams.size(); ++i) {
        auto tag = legacy_enum_conversion(keyParams[i].tag);
        switch (typeFromTag(tag)) {
        case KM_ENUM:
        case KM_ENUM_REP:
            set.params[i] = keymaster_param_enum(tag, keyParams[i].f.integer);
            break;
        case KM_UINT:
        case KM_UINT_REP:
            set.params[i] = keymaster_param_int(tag, keyParams[i].f.integer);
            break;
        case KM_ULONG:
        case KM_ULONG_REP:
            set.params[i] = keymaster_param_long(tag, keyParams[i].f.longInteger);
            break;
        case KM_DATE:
            set.params[i] = keymaster_param_date(tag, keyParams[i].f.dateTime);
            break;
        case KM_BOOL:
            if (keyParams[i].f.boolValue)
                set.params[i] = keymaster_param_bool(tag);
            else
                set.params[i].tag = KM_TAG_INVALID;
            break;
        case KM_BIGNUM:
        case KM_BYTES:
            set.params[i] =
                keymaster_param_blob(tag, &keyParams[i].blob[0], keyParams[i].blob.size());
            break;
        case KM_INVALID:
        default:
            set.params[i].tag = KM_TAG_INVALID;
            /* just skip */
            break;
        }
    }

    return set;
}

static inline hidl_vec<KeyParameter> kmParamSet2Hidl(const keymaster_key_param_set_t& set) {
    hidl_vec<KeyParameter> result;
    if (set.length == 0 || set.params == nullptr) return result;

    result.resize(set.length);
    keymaster_key_param_t* params = set.params;
    for (size_t i = 0; i < set.length; ++i) {
        auto tag = params[i].tag;
        result[i].tag = legacy_enum_conversion(tag);
        switch (typeFromTag(tag)) {
        case KM_ENUM:
        case KM_ENUM_REP:
            result[i].f.integer = params[i].enumerated;
            break;
        case KM_UINT:
        case KM_UINT_REP:
            result[i].f.integer = params[i].integer;
            break;
        case KM_ULONG:
        case KM_ULONG_REP:
            result[i].f.longInteger = params[i].long_integer;
            break;
        case KM_DATE:
            result[i].f.dateTime = params[i].date_time;
            break;
        case KM_BOOL:
            result[i].f.boolValue = params[i].boolean;
            break;
        case KM_BIGNUM:
        case KM_BYTES:
            result[i].blob.setToExternal(const_cast<unsigned char*>(params[i].blob.data),
                                         params[i].blob.data_length);
            break;
        case KM_INVALID:
        default:
            params[i].tag = KM_TAG_INVALID;
            /* just skip */
            break;
        }
    }
    return result;
}

class KmParamSet : public keymaster_key_param_set_t {
    public:
        explicit KmParamSet(const hidl_vec<KeyParameter>& keyParams)
            : keymaster_key_param_set_t(hidlKeyParams2Km(keyParams)) {}
        KmParamSet(KmParamSet&& other) : keymaster_key_param_set_t{other.params, other.length} {
            other.length = 0;
            other.params = nullptr;
        }
        KmParamSet(const KmParamSet&) = delete;
        ~KmParamSet() { delete[] params; }
};

static keymaster_error_t encodeParametersVerified(const VerificationToken& verificationToken, std::vector<uint8_t>& asn1ParamsVerified) {
    if (verificationToken.parametersVerified.size() > 0) {
        AuthorizationSet paramSet;
        KeymasterBlob derBlob;
        UniquePtr<KM_AUTH_LIST, KM_AUTH_LIST_Delete> kmAuthList(KM_AUTH_LIST_new());

        paramSet.Reinitialize(KmParamSet(verificationToken.parametersVerified));

        auto err = build_auth_list(paramSet, kmAuthList.get());
        if (err != KM_ERROR_OK) {
            return err;
        }
        int len = i2d_KM_AUTH_LIST(kmAuthList.get(), nullptr);
        if (len < 0) {
            return TranslateLastOpenSslError();
        }

        if (!derBlob.Reset(len)) {
            return KM_ERROR_MEMORY_ALLOCATION_FAILED;
        }

        uint8_t* p = derBlob.writable_data();
        len = i2d_KM_AUTH_LIST(kmAuthList.get(), &p);
        if (len < 0) {
            return TranslateLastOpenSslError();
        }
        asn1ParamsVerified.insert(asn1ParamsVerified.begin(), p, p+len);
        derBlob.release();
    }
    return KM_ERROR_OK;
}

} // anonymous namespace

JavacardKeymaster4Device::JavacardKeymaster4Device(shared_ptr<JavacardKeymaster> jcImpl)
    : softKm_(new ::keymaster::AndroidKeymaster(
            []() -> auto {
            auto context = new JavaCardSoftKeymasterContext();
            context->SetSystemVersion(::javacard_keymaster::getOsVersion(), ::javacard_keymaster::getOsPatchlevel());
            return context;
            }(),
            kOperationTableSize, keymaster::MessageVersion(keymaster::KmVersion::KEYMASTER_4_1,
                                0 /* km_date */) )),  jcImpl_(jcImpl) { }

JavacardKeymaster4Device::~JavacardKeymaster4Device() {}

// Methods from IKeymasterDevice follow.
Return<void> JavacardKeymaster4Device::getHardwareInfo(getHardwareInfo_cb _hidl_cb) {
    uint64_t securityLevel = static_cast<uint64_t>(SecurityLevel::STRONGBOX);
    hidl_string jcKeymasterName;
    hidl_string jcKeymasterAuthor;
    string name;
    string author;
    auto [item, err] = jcImpl_->getHardwareInfo();
    if (err != KM_ERROR_OK ||
        !cbor_.getUint64<uint64_t>(item, 1, securityLevel) ||
        !cbor_.getBinaryArray(item, 2, name) ||
        !cbor_.getBinaryArray(item, 3, author)) {
        LOG(ERROR) << "Error in response of getHardwareInfo.";
        LOG(INFO) << "Returning defaultHwInfo in getHardwareInfo.";
        _hidl_cb(SecurityLevel::STRONGBOX, JAVACARD_KEYMASTER_NAME, JAVACARD_KEYMASTER_AUTHOR);
        return Void();
    }
    jcKeymasterName = name;
    jcKeymasterAuthor = author;
    _hidl_cb(static_cast<SecurityLevel>(securityLevel), jcKeymasterName, jcKeymasterAuthor);
    return Void();
}

Return<void> JavacardKeymaster4Device::getHmacSharingParameters(getHmacSharingParameters_cb _hidl_cb) {
    HmacSharingParameters hmacSharingParameters;
    vector<uint8_t> nonce;
    vector<uint8_t> seed;
    auto err = jcImpl_->getHmacSharingParameters(&seed, &nonce);
    hmacSharingParameters.seed = seed;
    memcpy(hmacSharingParameters.nonce.data(), nonce.data(), nonce.size());
    // TODO
    // Send earlyBootEnded if there is any pending earlybootEnded event.
    //handleSendEarlyBootEndedEvent();
    _hidl_cb(legacy_enum_conversion(err), hmacSharingParameters);
    return Void();
}

Return<void> JavacardKeymaster4Device::computeSharedHmac(const hidl_vec<HmacSharingParameters>& params, computeSharedHmac_cb _hidl_cb) {
    std::vector<uint8_t> secret;
    vector<::javacard_keymaster::HmacSharingParameters> reqParams(params.size());
    for(size_t i = 0; i < params.size(); i++) {
        reqParams[i].seed = params[i].seed;
        reqParams[i].nonce.insert(reqParams[i].nonce.end(), params[i].nonce.data(), params[i].nonce.data() + params[i].nonce.elementCount());
    }
    auto err = jcImpl_->computeSharedHmac(reqParams, &secret);
    // TODO
    // Send earlyBootEnded if there is any pending earlybootEnded event.
    //handleSendEarlyBootEndedEvent();
    _hidl_cb(legacy_enum_conversion(err), secret);
    return Void();
}

Return<ErrorCode> JavacardKeymaster4Device::addRngEntropy(const hidl_vec<uint8_t>& data) {
    auto err = jcImpl_->addRngEntropy(data);
    return legacy_enum_conversion(err);
}

Return<void> JavacardKeymaster4Device::generateKey(const hidl_vec<KeyParameter>& keyParams, generateKey_cb _hidl_cb) {
    AuthorizationSet paramSet;
    AuthorizationSet swEnforced;
    AuthorizationSet hwEnforced;
    AuthorizationSet teeEnforced;
    vector<uint8_t> retKeyblob;
    paramSet.Reinitialize(KmParamSet(keyParams));
    if (!paramSet.Contains(KM_TAG_CREATION_DATETIME) &&
        !paramSet.Contains(KM_TAG_ACTIVE_DATETIME)) {
        keymaster_key_param_t dateTime;
        dateTime.tag = KM_TAG_CREATION_DATETIME;
        dateTime.date_time = java_time(time(nullptr));
        paramSet.push_back(dateTime);
    }
    auto err = jcImpl_->generateKey(paramSet, &retKeyblob, &swEnforced, &hwEnforced, &teeEnforced);
    KeyCharacteristics keyCharacteristics;
    keyCharacteristics.softwareEnforced = kmParamSet2Hidl(swEnforced);
    keyCharacteristics.hardwareEnforced = kmParamSet2Hidl(hwEnforced);
    _hidl_cb(legacy_enum_conversion(err), retKeyblob, keyCharacteristics);
    return Void();
}

Return<void> JavacardKeymaster4Device::importKey(const hidl_vec<KeyParameter>& keyParams, KeyFormat keyFormat, const hidl_vec<uint8_t>& keyData, importKey_cb _hidl_cb) {
    AuthorizationSet paramSet;
    AuthorizationSet swEnforced;
    AuthorizationSet hwEnforced;
    AuthorizationSet teeEnforced;
    vector<uint8_t> retKeyblob;
    paramSet.Reinitialize(KmParamSet(keyParams));
    if (!paramSet.Contains(KM_TAG_CREATION_DATETIME) &&
        !paramSet.Contains(KM_TAG_ACTIVE_DATETIME)) {
        keymaster_key_param_t dateTime;
        dateTime.tag = KM_TAG_CREATION_DATETIME;
        dateTime.date_time = java_time(time(nullptr));
        paramSet.push_back(dateTime);
    }
    auto err = jcImpl_->importKey(paramSet, legacy_enum_conversion(keyFormat), keyData, &retKeyblob, &swEnforced, &hwEnforced, &teeEnforced);
    KeyCharacteristics keyCharacteristics;
    keyCharacteristics.softwareEnforced = kmParamSet2Hidl(swEnforced);
    keyCharacteristics.hardwareEnforced = kmParamSet2Hidl(hwEnforced);
    _hidl_cb(legacy_enum_conversion(err), retKeyblob, keyCharacteristics);
    return Void();
}

Return<void> JavacardKeymaster4Device::importWrappedKey(const hidl_vec<uint8_t> &wrappedKeyData, 
                                                        const hidl_vec<uint8_t> &wrappingKeyBlob,
                                                        const hidl_vec<uint8_t> &maskingKey,
                                                        const hidl_vec<KeyParameter> &unwrappingParams,
                                                        uint64_t passwordSid, uint64_t biometricSid,
                                                        importWrappedKey_cb _hidl_cb) {
    AuthorizationSet paramSet;
    AuthorizationSet swEnforced;
    AuthorizationSet hwEnforced;
    AuthorizationSet teeEnforced;
    vector<uint8_t> retKeyblob;
    paramSet.Reinitialize(KmParamSet(unwrappingParams));
    auto err = jcImpl_->importWrappedKey(wrappedKeyData, wrappingKeyBlob, maskingKey, paramSet,
                                         passwordSid, biometricSid, &retKeyblob, &swEnforced,
                                         &hwEnforced, &teeEnforced);
    KeyCharacteristics keyCharacteristics;
    keyCharacteristics.softwareEnforced = kmParamSet2Hidl(swEnforced);
    keyCharacteristics.hardwareEnforced = kmParamSet2Hidl(hwEnforced);
    _hidl_cb(legacy_enum_conversion(err), retKeyblob, keyCharacteristics);
    return Void();
}


Return<void> JavacardKeymaster4Device::attestKey(const hidl_vec<uint8_t>& keyToAttest, const hidl_vec<KeyParameter>& attestParams, attestKey_cb _hidl_cb) {
    AuthorizationSet paramSet;
    vector<vector<uint8_t>> certChain;
    hidl_vec<hidl_vec<uint8_t>> outCertChain;
    paramSet.Reinitialize(KmParamSet(attestParams));
    auto err = jcImpl_->attestKey(keyToAttest, paramSet, {}, AuthorizationSet(), {}, &certChain);
    if (err != KM_ERROR_OK) {
        LOG(ERROR) << "JavacardKeymaster4Device attestKey Failed in attestKey err: " << (int32_t) err;
        _hidl_cb(legacy_enum_conversion(err), outCertChain);
        return Void();
    }
    err = jcImpl_->getCertChain(&certChain);
    if (err != KM_ERROR_OK) {
        LOG(ERROR) << "JavacardKeymaster4Device attestKey Failed in getCertChain err: " << (int32_t) err;
        _hidl_cb(legacy_enum_conversion(err), outCertChain);
        return Void();
    }
    outCertChain.resize(certChain.size());
    for(int i = 0; i < certChain.size(); i++) {
        outCertChain[i] = certChain[i];
    }
   _hidl_cb(legacy_enum_conversion(err), outCertChain);
    return Void();
}

Return<void> JavacardKeymaster4Device::upgradeKey(const hidl_vec<uint8_t>& keyBlobToUpgrade,
                                                  const hidl_vec<KeyParameter>& upgradeParams,
                                                  upgradeKey_cb _hidl_cb) {
    AuthorizationSet paramSet;
    paramSet.Reinitialize(KmParamSet(upgradeParams));
    vector<uint8_t> upgradedKeyBlob;
    auto err = jcImpl_->upgradeKey(keyBlobToUpgrade, paramSet, &upgradedKeyBlob);
    _hidl_cb(legacy_enum_conversion(err), upgradedKeyBlob);
    return Void();
}

Return<ErrorCode> JavacardKeymaster4Device::deleteKey(const hidl_vec<uint8_t>& keyBlob) {
    auto err = jcImpl_->deleteKey(keyBlob);
    return legacy_enum_conversion(err);
}

Return<ErrorCode> JavacardKeymaster4Device::deleteAllKeys() {
    auto err = jcImpl_->deleteAllKeys();
    return legacy_enum_conversion(err);
}

Return<ErrorCode> JavacardKeymaster4Device::destroyAttestationIds() {
    auto err = jcImpl_->destroyAttestationIds();
    return legacy_enum_conversion(err);
}


Return<void> JavacardKeymaster4Device::getKeyCharacteristics(const hidl_vec<uint8_t>& keyBlob,
                                                             const hidl_vec<uint8_t>& clientId,
                                                             const hidl_vec<uint8_t>& appData,
                                                             getKeyCharacteristics_cb _hidl_cb) {
    AuthorizationSet swEnforced;
    AuthorizationSet hwEnforced;
    AuthorizationSet teeEnforced;
    auto err = jcImpl_->getKeyCharacteristics(keyBlob, clientId, appData, &swEnforced,
                                         &hwEnforced, &teeEnforced);
    KeyCharacteristics keyCharacteristics;
    keyCharacteristics.softwareEnforced = kmParamSet2Hidl(swEnforced);
    keyCharacteristics.hardwareEnforced = kmParamSet2Hidl(hwEnforced);
    _hidl_cb(legacy_enum_conversion(err), keyCharacteristics);
    return Void();
}

Return<void> JavacardKeymaster4Device::verifyAuthorization(uint64_t , const hidl_vec<KeyParameter>& , const HardwareAuthToken& , verifyAuthorization_cb _hidl_cb) {
    VerificationToken verificationToken;
    LOG(DEBUG) << "Verify authorizations UNIMPLEMENTED";
    _hidl_cb(ErrorCode::UNIMPLEMENTED, verificationToken);
    return Void();
}

#if 0


Return<void> JavacardKeymaster4Device::exportKey(KeyFormat exportFormat, const hidl_vec<uint8_t>& keyBlob, const hidl_vec<uint8_t>& clientId, const hidl_vec<uint8_t>& appData, exportKey_cb _hidl_cb) {
    ErrorCode errorCode = ErrorCode::UNKNOWN_ERROR;
    hidl_vec<uint8_t> resultKeyBlob;

    //Check if keyblob is corrupted
    getKeyCharacteristics(keyBlob, clientId, appData,
            [&](ErrorCode error, KeyCharacteristics /*keyCharacteristics*/) {
            errorCode = error;
            });

    if(errorCode != ErrorCode::OK) {
        LOG(ERROR) << "Error in exportKey: " << (int32_t) errorCode;
        _hidl_cb(errorCode, resultKeyBlob);
        return Void();
    }

    ExportKeyRequest request(softKm_->message_version());
    request.key_format = legacy_enum_conversion(exportFormat);
    request.SetKeyMaterial(keyBlob.data(), keyBlob.size());

    ExportKeyResponse response(softKm_->message_version());
    softKm_->ExportKey(request, &response);

    if(response.error == KM_ERROR_INCOMPATIBLE_ALGORITHM) {
        //Symmetric Keys cannot be exported.
        response.error = KM_ERROR_UNSUPPORTED_KEY_FORMAT;
        LOG(ERROR) << "error in exportKey: unsupported algorithm or key format";
    }
    if (response.error == KM_ERROR_OK) {
        resultKeyBlob.setToExternal(response.key_data, response.key_data_length);
    }
    errorCode = legacy_enum_conversion(response.error);
    LOG(DEBUG) << "exportKey status: " << (int32_t) errorCode;
    _hidl_cb(errorCode, resultKeyBlob);
    return Void();
}

Return<void> JavacardKeymaster4Device::begin(KeyPurpose purpose, const hidl_vec<uint8_t>& keyBlob, const hidl_vec<KeyParameter>& inParams, const HardwareAuthToken& authToken, begin_cb _hidl_cb) {
    ErrorCode errorCode = ErrorCode::UNKNOWN_ERROR;
    uint64_t operationHandle = 0;
    OperationType operType = OperationType::PRIVATE_OPERATION;
    hidl_vec<KeyParameter> outParams;
    LOG(DEBUG) << "INS_BEGIN_OPERATION_CMD purpose: " << (int32_t)purpose;
    /*
     * Asymmetric public key operations are processed inside softkeymaster and private
     * key operations are processed inside strongbox keymaster.
     * All symmetric key operations are processed inside strongbox keymaster.
     * If the purpose is either ENCRYPT / VERIFY then the operation type is set
     * to public operation and in case if the key turned out to be a symmetric key then
     * handleBeginOperation() function fallbacks to private key operation.
     */
    LOG(DEBUG) << "INS_BEGIN_OPERATION_CMD purpose: " << (int32_t)purpose;
    if (KeyPurpose::ENCRYPT == purpose || KeyPurpose::VERIFY == purpose) {
        operType = OperationType::PUBLIC_OPERATION;
    }
    errorCode = handleBeginOperation(purpose, keyBlob, inParams, authToken, outParams,
                                     operationHandle, operType);
    if (errorCode == ErrorCode::OK && isOperationHandleExists(operationHandle)) {
        LOG(DEBUG) << "Operation handle " << operationHandle << "already exists"
                      "in the opertion table. so aborting this opertaion.";
        // abort the operation.
        errorCode = abortOperation(operationHandle, operType);
        if (errorCode == ErrorCode::OK) {
            // retry begin to get an another operation handle.
            errorCode = handleBeginOperation(purpose, keyBlob, inParams, authToken, outParams,
                                             operationHandle, operType);
            if (errorCode == ErrorCode::OK && isOperationHandleExists(operationHandle)) {
                errorCode = ErrorCode::UNKNOWN_ERROR;
                LOG(ERROR) << "INS_BEGIN_OPERATION_CMD: Failed in begin operation as the"
                              "operation handle already exists in the operation table."
                           << (int32_t)errorCode;
                // abort the operation.
                auto abortErr = abortOperation(operationHandle, operType);
                if (abortErr != ErrorCode::OK) {
                    LOG(ERROR) << "Fail to abort the operation.";
                    errorCode = abortErr;
                }
            }
        }
    }
    // Create an entry inside the operation table for the new operation
    // handle.
    if (ErrorCode::OK == errorCode) operationTable[operationHandle] = operType;

    _hidl_cb(errorCode, outParams, operationHandle);
    return Void();
}

ErrorCode JavacardKeymaster4Device::handleBeginPublicKeyOperation(
    KeyPurpose purpose, const hidl_vec<uint8_t>& keyBlob, const hidl_vec<KeyParameter>& inParams,
    hidl_vec<KeyParameter>& outParams, uint64_t& operationHandle) {
    BeginOperationRequest request(softKm_->message_version());
    request.purpose = legacy_enum_conversion(purpose);
    request.SetKeyMaterial(keyBlob.data(), keyBlob.size());
    request.additional_params.Reinitialize(KmParamSet(inParams));

    BeginOperationResponse response(softKm_->message_version());
    /* For Symmetric key operation, the BeginOperation returns
     * KM_ERROR_INCOMPATIBLE_ALGORITHM error. */
    softKm_->BeginOperation(request, &response);
    ErrorCode errorCode = legacy_enum_conversion(response.error);
    LOG(DEBUG) << "INS_BEGIN_OPERATION_CMD softkm BeginOperation status: " << (int32_t)errorCode;
    if (ErrorCode::OK == errorCode) {
        outParams = kmParamSet2Hidl(response.output_params);
        operationHandle = response.op_handle;
    } else {
        LOG(ERROR) << "INS_BEGIN_OPERATION_CMD error in softkm BeginOperation status: "
                   << (int32_t)errorCode;
    }
    return errorCode;
}

ErrorCode JavacardKeymaster4Device::handleBeginPrivateKeyOperation(
    KeyPurpose purpose, const hidl_vec<uint8_t>& keyBlob, const hidl_vec<KeyParameter>& inParams,
    const HardwareAuthToken& authToken, hidl_vec<KeyParameter>& outParams,
    uint64_t& operationHandle) {
    ErrorCode errorCode = ErrorCode::UNKNOWN_ERROR;
    cppbor::Array array;
    std::vector<uint8_t> cborOutData;
    std::unique_ptr<Item> item;
    std::unique_ptr<Item> blobItem = nullptr;
    KeyCharacteristics keyCharacteristics;
    KeyParameter param;

    // Send earlyBootEnded if there is any pending earlybootEnded event.
    handleSendEarlyBootEndedEvent();
    /* Convert input data to cbor format */
    array.add(static_cast<uint64_t>(purpose));
    array.add(std::vector<uint8_t>(keyBlob));
    cborConverter_.addKeyparameters(array, inParams);
    cborConverter_.addHardwareAuthToken(array, authToken);
    std::vector<uint8_t> cborData = array.encode();

    // keyCharacteristics.hardwareEnforced is required to store algorithm, digest
    // and padding values in operationInfo structure. To retrieve
    // keyCharacteristics.hardwareEnforced, call getKeyCharacateristics. By
    // calling getKeyCharacateristics also helps in finding a corrupted keyblob.
    hidl_vec<uint8_t> applicationId;
    hidl_vec<uint8_t> applicationData;
    if (getTag(inParams, Tag::APPLICATION_ID, param)) {
        applicationId = param.blob;
    }
    if (getTag(inParams, Tag::APPLICATION_DATA, param)) {
        applicationData = param.blob;
    }
    // Call to getKeyCharacteristics.
    getKeyCharacteristics(keyBlob, applicationId, applicationData,
                          [&](ErrorCode error, KeyCharacteristics keyChars) {
                              errorCode = error;
                              keyCharacteristics = keyChars;
                          });
    LOG(DEBUG) << "INS_BEGIN_OPERATION_CMD StrongboxKM getKeyCharacteristics status: "
               << (int32_t)errorCode;

    if (errorCode == ErrorCode::OK) {
        errorCode = ErrorCode::UNKNOWN_ERROR;
        if (getTag(keyCharacteristics.hardwareEnforced, Tag::ALGORITHM, param)) {
            errorCode = sendData(Instruction::INS_BEGIN_OPERATION_CMD, cborData, cborOutData);
            if (errorCode == ErrorCode::OK) {
                // Skip last 2 bytes in cborData, it contains status.
                std::tie(item, errorCode) =
                    decodeData(cborConverter_,
                               std::vector<uint8_t>(cborOutData.begin(), cborOutData.end() - 2),
                               true, oprCtx_);
                if (errorCode == ErrorCode::OK) {
                    if (!cborConverter_.getKeyParameters(item, 1, outParams) ||
                        !cborConverter_.getUint64(item, 2, operationHandle)) {
                        errorCode = ErrorCode::UNKNOWN_ERROR;
                        outParams.setToExternal(nullptr, 0);
                        operationHandle = 0;
                        LOG(ERROR) << "INS_BEGIN_OPERATION_CMD: error in converting cbor "
                                      "data, status: "
                                   << (int32_t)errorCode;
                    } else {
                        /* Store the operationInfo */
                        oprCtx_->setOperationInfo(operationHandle, purpose, param.f.algorithm,
                                                  inParams);
                    }
                }
            }
        } else {
            LOG(ERROR) << "INS_BEGIN_OPERATION_CMD couldn't find algorithm tag: "
                       << (int32_t)Tag::ALGORITHM;
        }
    } else {
        LOG(ERROR) << "INS_BEGIN_OPERATION_CMD error in getKeyCharacteristics status: "
                   << (int32_t)errorCode;
    }
    return errorCode;
}

ErrorCode JavacardKeymaster4Device::handleBeginOperation(
    KeyPurpose purpose, const hidl_vec<uint8_t>& keyBlob, const hidl_vec<KeyParameter>& inParams,
    const HardwareAuthToken& authToken, hidl_vec<KeyParameter>& outParams,
    uint64_t& operationHandle, OperationType& operType) {
    ErrorCode errorCode = ErrorCode::UNKNOWN_ERROR;
    if (operType == OperationType::PUBLIC_OPERATION) {
        errorCode =
            handleBeginPublicKeyOperation(purpose, keyBlob, inParams, outParams, operationHandle);

        // For Symmetric operations handleBeginPublicKeyOperation function
        // returns INCOMPATIBLE_ALGORITHM error. Based on this error
        // condition it fallbacks to private key operation.
        if (errorCode == ErrorCode::INCOMPATIBLE_ALGORITHM) {
            operType = OperationType::PRIVATE_OPERATION;
        }
    }

    if (operType == OperationType::PRIVATE_OPERATION) {
        errorCode = handleBeginPrivateKeyOperation(purpose, keyBlob, inParams, authToken, outParams,
                                                   operationHandle);
    }
    return errorCode;
}

Return<void>
JavacardKeymaster4Device::update(uint64_t operationHandle, const hidl_vec<KeyParameter>& inParams,
                                 const hidl_vec<uint8_t>& input, const HardwareAuthToken& authToken,
                                 const VerificationToken& verificationToken, update_cb _hidl_cb) {
    ErrorCode errorCode = ErrorCode::UNKNOWN_ERROR;
    uint32_t inputConsumed = 0;
    hidl_vec<KeyParameter> outParams;
    hidl_vec<uint8_t> output;
    UpdateOperationResponse response(softKm_->message_version());
    OperationType operType = getOperationType(operationHandle);
    if (OperationType::UNKNOWN == operType) {  // operation handle not found
        LOG(ERROR) << " Operation handle is invalid. This could happen if invalid operation handle "
                      "is passed or if"
                   << " secure element reset occurred.";
        _hidl_cb(ErrorCode::INVALID_OPERATION_HANDLE, inputConsumed, outParams, output);
        return Void();
    }

    if (OperationType::PUBLIC_OPERATION == operType) {
        /* SW keymaster (Public key operation) */
        LOG(DEBUG) << "INS_UPDATE_OPERATION_CMD - swkm operation ";
        UpdateOperationRequest request(softKm_->message_version());
        request.op_handle = operationHandle;
        request.input.Reinitialize(input.data(), input.size());
        request.additional_params.Reinitialize(KmParamSet(inParams));

        softKm_->UpdateOperation(request, &response);
        errorCode = legacy_enum_conversion(response.error);
        LOG(DEBUG) << "INS_UPDATE_OPERATION_CMD - swkm update operation status: "
                   << (int32_t)errorCode;
        if (response.error == KM_ERROR_OK) {
            inputConsumed = response.input_consumed;
            outParams = kmParamSet2Hidl(response.output_params);
            output = kmBuffer2hidlVec(response.output);
        } else {
            LOG(ERROR) << "INS_UPDATE_OPERATION_CMD - error swkm update operation status: "
                       << (int32_t)errorCode;
        }
    } else {
        /* Strongbox Keymaster operation */
        std::vector<uint8_t> tempOut;
        /* OperationContext calls this below sendDataCallback callback function. This callback
         * may be called multiple times if the input data is larger than MAX_ALLOWED_INPUT_SIZE.
         */
        auto sendDataCallback = [&](std::vector<uint8_t>& data, bool) -> ErrorCode {
            cppbor::Array array;
            std::unique_ptr<Item> item;
            std::vector<uint8_t> cborOutData;
            std::vector<uint8_t> asn1ParamsVerified;
            // For symmetic ciphers only block aligned data is send to javacard Applet to reduce the
            // number of calls to
            // javacard. If the input message is less than block size then it is buffered inside the
            // HAL. so in case if
            // after buffering there is no data to send to javacard don't call javacard applet.
            // For AES GCM operations, even though the input length is 0(which is not block
            // aligned), if there is ASSOCIATED_DATA present in KeyParameters. Then we need to make
            // a call to javacard Applet.
            if (data.size() == 0 && !findTag(inParams, Tag::ASSOCIATED_DATA)) {
                // Return OK, since this is not error case.
                LOG(DEBUG) << "sendDataCallback: data size is zero";
                return ErrorCode::OK;
            }

            if (ErrorCode::OK !=
                (errorCode = encodeParametersVerified(verificationToken, asn1ParamsVerified))) {
                LOG(ERROR) << "sendDataCallback: error in encodeParametersVerified status: "
                           << (int32_t)errorCode;
                return errorCode;
            }

            // Convert input data to cbor format
            array.add(operationHandle);
            cborConverter_.addKeyparameters(array, inParams);
            array.add(data);
            cborConverter_.addHardwareAuthToken(array, authToken);
            cborConverter_.addVerificationToken(array, verificationToken, asn1ParamsVerified);
            std::vector<uint8_t> cborData = array.encode();

            errorCode = sendData(Instruction::INS_UPDATE_OPERATION_CMD, cborData, cborOutData);

            if (errorCode == ErrorCode::OK) {
                // Skip last 2 bytes in cborData, it contains status.
                std::tie(item, errorCode) =
                    decodeData(cborConverter_,
                               std::vector<uint8_t>(cborOutData.begin(), cborOutData.end() - 2),
                               true, oprCtx_);
                if (errorCode == ErrorCode::OK) {
                    /*Ignore inputConsumed from javacard SE since HAL consumes all the input */
                    // cborConverter_.getUint64(item, 1, inputConsumed);
                    // This callback function may gets called multiple times so parse and get the
                    // outParams only once. Otherwise there can be chance of duplicate entries in
                    // outParams. Use tempOut to collect all the cipher text and finally copy it to
                    // the output. getBinaryArray function appends the new cipher text at the end of
                    // the tempOut(std::vector<uint8_t>).
                    if ((outParams.size() == 0 &&
                         !cborConverter_.getKeyParameters(item, 2, outParams)) ||
                        !cborConverter_.getBinaryArray(item, 1, tempOut)) {
                        outParams.setToExternal(nullptr, 0);
                        tempOut.clear();
                        errorCode = ErrorCode::UNKNOWN_ERROR;
                        LOG(ERROR) << "sendDataCallback: INS_UPDATE_OPERATION_CMD: error while "
                                      "converting cbor data, status: "
                                   << (int32_t)errorCode;
                    }
                }
            }
            return errorCode;
        };
        if (ErrorCode::OK ==
            (errorCode =
                 oprCtx_->update(operationHandle, std::vector<uint8_t>(input), sendDataCallback))) {
            /* Consumed all the input */
            inputConsumed = input.size();
            output = tempOut;
        }
        LOG(DEBUG) << "Update operation status: " << (int32_t)errorCode;
        if (ErrorCode::OK != errorCode) {
            LOG(ERROR) << "Error in update operation, status: " << (int32_t)errorCode;
            abort(operationHandle);
        }
    }
    if (ErrorCode::OK != errorCode) {
        /* Delete the entry from operation table. */
        LOG(ERROR) << "Delete entry from operation table, status: " << (int32_t)errorCode;
        operationTable.erase(operationHandle);
    }

    _hidl_cb(errorCode, inputConsumed, outParams, output);
    return Void();
}

Return<void>
JavacardKeymaster4Device::finish(uint64_t operationHandle, const hidl_vec<KeyParameter>& inParams,
                                 const hidl_vec<uint8_t>& input, const hidl_vec<uint8_t>& signature,
                                 const HardwareAuthToken& authToken,
                                 const VerificationToken& verificationToken, finish_cb _hidl_cb) {
    ErrorCode errorCode = ErrorCode::UNKNOWN_ERROR;
    hidl_vec<KeyParameter> outParams;
    hidl_vec<uint8_t> output;
    FinishOperationResponse response(softKm_->message_version());
    OperationType operType = getOperationType(operationHandle);

    if (OperationType::UNKNOWN == operType) {  // operation handle not found
        LOG(ERROR) << " Operation handle is invalid. This could happen if invalid operation handle "
                      "is passed or if"
                   << " secure element reset occurred.";
        _hidl_cb(ErrorCode::INVALID_OPERATION_HANDLE, outParams, output);
        return Void();
    }

    if (OperationType::PUBLIC_OPERATION == operType) {
        /* SW keymaster (Public key operation) */
        LOG(DEBUG) << "FINISH - swkm operation ";
        FinishOperationRequest request(softKm_->message_version());
        request.op_handle = operationHandle;
        request.input.Reinitialize(input.data(), input.size());
        request.signature.Reinitialize(signature.data(), signature.size());
        request.additional_params.Reinitialize(KmParamSet(inParams));

        softKm_->FinishOperation(request, &response);

        errorCode = legacy_enum_conversion(response.error);
        LOG(DEBUG) << "FINISH - swkm operation, status: " << (int32_t)errorCode;

        if (response.error == KM_ERROR_OK) {
            outParams = kmParamSet2Hidl(response.output_params);
            output = kmBuffer2hidlVec(response.output);
        } else {
            LOG(ERROR) << "Error in finish operation, status: " << (int32_t)errorCode;
        }
    } else {
        /* Strongbox Keymaster operation */
        std::vector<uint8_t> tempOut;
        bool aadTag = false;
        /* OperationContext calls this below sendDataCallback callback function. This callback
         * may be called multiple times if the input data is larger than MAX_ALLOWED_INPUT_SIZE.
         * This callback function decides whether to call update/finish instruction based on the
         * input received from the OperationContext through finish variable.
         * if finish variable is false update instruction is called, if it is true finish
         * instruction is called.
         */
        auto sendDataCallback = [&](std::vector<uint8_t>& data, bool finish) -> ErrorCode {
            cppbor::Array array;
            Instruction ins;
            std::unique_ptr<Item> item;
            std::vector<uint8_t> cborOutData;
            int keyParamPos, outputPos;
            std::vector<uint8_t> asn1ParamsVerified;
            const hidl_vec<uint8_t> confToken = {}; //dummy

            if (ErrorCode::OK !=
                (errorCode = encodeParametersVerified(verificationToken, asn1ParamsVerified))) {
                LOG(ERROR) << "sendDataCallback: Error in encodeParametersVerified, status: "
                           << (int32_t)errorCode;
                return errorCode;
            }

            // In case if there is ASSOCIATED_DATA present in the keyparams, then make sure it is
            // either passed with update call or finish call. Don't send ASSOCIATED_DATA in both
            // update and finish calls. aadTag is used to check if ASSOCIATED_DATA is already sent
            // in update call. If addTag is true then skip ASSOCIATED_DATA from keyparams in finish
            // call.
            //  Convert input data to cbor format
            array.add(operationHandle);
            if (finish) {
                std::vector<KeyParameter> finishParams;
                LOG(DEBUG) << "sendDataCallback: finish operation";
                if (aadTag) {
                    for (int i = 0; i < inParams.size(); i++) {
                        if (inParams[i].tag != Tag::ASSOCIATED_DATA)
                            finishParams.push_back(inParams[i]);
                    }
                } else {
                    finishParams = inParams;
                }
                cborConverter_.addKeyparameters(array, finishParams);
                array.add(data);
                array.add(std::vector<uint8_t>(signature));
                cborConverter_.addHardwareAuthToken(array, authToken);
                cborConverter_.addVerificationToken(array, verificationToken, asn1ParamsVerified);
                array.add(std::vector<uint8_t>(confToken));
                ins = Instruction::INS_FINISH_OPERATION_CMD;
                keyParamPos = 1;
                outputPos = 2;
            } else {
                LOG(DEBUG) << "sendDataCallback: update operation";
                if (findTag(inParams, Tag::ASSOCIATED_DATA)) {
                    aadTag = true;
                }
                cborConverter_.addKeyparameters(array, inParams);
                array.add(data);
                cborConverter_.addHardwareAuthToken(array, authToken);
                cborConverter_.addVerificationToken(array, verificationToken, asn1ParamsVerified);
                ins = Instruction::INS_UPDATE_OPERATION_CMD;
                keyParamPos = 2;
                outputPos = 1;
            }
            std::vector<uint8_t> cborData = array.encode();
            errorCode = sendData(ins, cborData, cborOutData);

            if (errorCode == ErrorCode::OK) {
                // Skip last 2 bytes in cborData, it contains status.
                std::tie(item, errorCode) =
                    decodeData(cborConverter_,
                               std::vector<uint8_t>(cborOutData.begin(), cborOutData.end() - 2),
                               true, oprCtx_);
                if (errorCode == ErrorCode::OK) {
                    // There is a change that this finish callback may gets called multiple times if
                    // the input data size is larger the MAX_ALLOWED_INPUT_SIZE (Refer
                    // OperationContext) so parse and get the outParams only once. Otherwise there
                    // can be chance of duplicate entries in outParams. Use tempOut to collect all
                    // the cipher text and finally copy it to the output. getBinaryArray function
                    // appends the new cipher text at the end of the tempOut(std::vector<uint8_t>).
                    if ((outParams.size() == 0 &&
                         !cborConverter_.getKeyParameters(item, keyParamPos, outParams)) ||
                        !cborConverter_.getBinaryArray(item, outputPos, tempOut)) {
                        outParams.setToExternal(nullptr, 0);
                        tempOut.clear();
                        errorCode = ErrorCode::UNKNOWN_ERROR;
                        LOG(ERROR)
                            << "sendDataCallback: error while converting cbor data in operation: "
                            << (int32_t)ins << " decodeData, status: " << (int32_t)errorCode;
                    }
                }
            }
            return errorCode;
        };
        if (ErrorCode::OK ==
            (errorCode =
                 oprCtx_->finish(operationHandle, std::vector<uint8_t>(input), sendDataCallback))) {
            output = tempOut;
        }
        if (ErrorCode::OK != errorCode) {
            LOG(ERROR) << "Error in finish operation, status: " << (int32_t)errorCode;
            abort(operationHandle);
        }
    }
    /* Delete the entry from operation table. */
    operationTable.erase(operationHandle);
    oprCtx_->clearOperationData(operationHandle);
    LOG(DEBUG) << "finish operation, status: " << (int32_t)errorCode;
    _hidl_cb(errorCode, outParams, output);
    return Void();
}

ErrorCode JavacardKeymaster4Device::abortPrivateKeyOperation(uint64_t operationHandle) {
    ErrorCode errorCode = ErrorCode::UNKNOWN_ERROR;
    cppbor::Array array;
    std::unique_ptr<Item> item;
    std::vector<uint8_t> cborOutData;

    /* Convert input data to cbor format */
    array.add(operationHandle);
    std::vector<uint8_t> cborData = array.encode();

    errorCode = sendData(Instruction::INS_ABORT_OPERATION_CMD, cborData, cborOutData);

    if (errorCode == ErrorCode::OK) {
        // Skip last 2 bytes in cborData, it contains status.
        std::tie(item, errorCode) = decodeData(
            cborConverter_, std::vector<uint8_t>(cborOutData.begin(), cborOutData.end() - 2), true,
            oprCtx_);
    }
    return errorCode;
}

ErrorCode JavacardKeymaster4Device::abortPublicKeyOperation(uint64_t operationHandle) {
    ErrorCode errorCode = ErrorCode::UNKNOWN_ERROR;
    AbortOperationRequest request(softKm_->message_version());
    request.op_handle = operationHandle;

    AbortOperationResponse response(softKm_->message_version());
    softKm_->AbortOperation(request, &response);

    errorCode = legacy_enum_conversion(response.error);
    return errorCode;
}

ErrorCode JavacardKeymaster4Device::abortOperation(uint64_t operationHandle,
                                                   OperationType operType) {
    if (operType == OperationType::UNKNOWN) return ErrorCode::UNKNOWN_ERROR;

    if (OperationType::PUBLIC_OPERATION == operType) {
        return abortPublicKeyOperation(operationHandle);
    } else {
        return abortPrivateKeyOperation(operationHandle);
    }
}

Return<ErrorCode> JavacardKeymaster4Device::abort(uint64_t operationHandle) {
    ErrorCode errorCode = ErrorCode::UNKNOWN_ERROR;
    OperationType operType = getOperationType(operationHandle);
    if (OperationType::UNKNOWN == operType) {  // operation handle not found
        LOG(ERROR) << " Operation handle is invalid. This could happen if invalid "
                      "operation handle is passed or if"
                   << " secure element reset occurred.";
        return ErrorCode::INVALID_OPERATION_HANDLE;
    }

    errorCode = abortOperation(operationHandle, operType);
    if (errorCode == ErrorCode::OK) {
        /* Delete the entry on this operationHandle */
        oprCtx_->clearOperationData(operationHandle);
        operationTable.erase(operationHandle);
    }
    return errorCode;
}
#endif
// Methods from ::android::hardware::keymaster::V4_1::IKeymasterDevice follow.
Return<::android::hardware::keymaster::V4_1::ErrorCode>
JavacardKeymaster4Device::deviceLocked(bool passwordOnly, const VerificationToken& verificationToken) {
    vector<uint8_t> encodedVerificationToken;
    auto err = encodeVerificationToken(verificationToken, &encodedVerificationToken);
    if (err != KM_ERROR_OK) {
        LOG(ERROR) << "In deviceLocked failed to encode VerificationToken" << (int32_t) err;
        return static_cast<V41ErrorCode>(err);
    }
    err = jcImpl_->deviceLocked(passwordOnly, encodedVerificationToken);
    return static_cast<V41ErrorCode>(err);
}

Return<::android::hardware::keymaster::V4_1::ErrorCode> JavacardKeymaster4Device::earlyBootEnded() {
    auto err = jcImpl_->earlyBootEnded();
    return static_cast<V41ErrorCode>(err);
}

keymaster_error_t JavacardKeymaster4Device::encodeVerificationToken(const VerificationToken &verificationToken, vector<uint8_t>* encodedToken) {
    vector<uint8_t> asn1ParamsVerified;
    auto err = encodeParametersVerified(verificationToken, asn1ParamsVerified);
    if (err != KM_ERROR_OK) {
        LOG(DEBUG) << "INS_DEVICE_LOCKED_CMD: Error in encodeParametersVerified, status: " << (int32_t) err;
        return err;
    }
    cppbor::Array array;
    ::keymaster::VerificationToken token;
    token.challenge = verificationToken.challenge;
    token.timestamp = verificationToken.timestamp;
    token.security_level = legacy_enum_conversion(verificationToken.securityLevel);
    hidlVec2KmBlob(verificationToken.mac, &token.mac);
    cbor_.addVerificationToken(array, token, asn1ParamsVerified);
    *encodedToken = array.encode();
    return KM_ERROR_OK;
}

}  // javacard
}  // namespace V4_1
}  // namespace keymaster
