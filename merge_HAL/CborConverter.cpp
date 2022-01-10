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

#include "CborConverter.h"
#include <cppbor.h>
#include <map>
#include <memory>
#include <string>
#include <vector>

namespace javacard_keymaster {
using namespace cppbor;
//using namespace aidl::android::hardware::security::keymint;
//using namespace aidl::android::hardware::security::secureclock;
//using namespace aidl::android::hardware::security::sharedsecret;
using ::keymaster::KeymasterBlob;
using std::string;
using std::unique_ptr;
using std::vector;
/*
bool CborConverter::addAttestationKey(Array& array,
                                      const std::optional<AttestationKey>& attestationKey) {
    if (attestationKey.has_value()) {
        array.add(Bstr(attestationKey->keyBlob));
        addKeyparameters(array, attestationKey->attestKeyParams);
        array.add(Bstr(attestationKey->issuerSubjectName));
    } else {
        array.add(std::move(Bstr(vector<uint8_t>(0))));
        array.add(std::move(Map()));
        array.add(std::move(Bstr(vector<uint8_t>(0))));
    }
    return true;
}*/

inline keymaster_tag_type_t typeFromTag(const keymaster_tag_t tag) {
    return keymaster_tag_get_type(tag);
}

inline vector<uint8_t> kmBlob2vector(const keymaster_blob_t& blob) {
    vector<uint8_t> result(blob.data, blob.data + blob.data_length);
    return result;
}

bool CborConverter::addKeyparameters(Array& array, const keymaster_key_param_set_t& paramSet) {
    Map map;
    std::map<uint64_t, vector<uint8_t>> enum_repetition;
    std::map<uint64_t, Array> uint_repetition;
    for (size_t i = 0; i < paramSet.length; i++) {
        const auto& param = paramSet.params[i];
        switch (typeFromTag(param.tag)) {
        case KM_ENUM:
            map.add(static_cast<uint64_t>(param.tag), param.enumerated);
            break;
        case KM_UINT:
            map.add(static_cast<uint64_t>(param.tag), param.integer);
            break;
        case KM_UINT_REP:
            uint_repetition[static_cast<uint64_t>(param.tag)].add(param.integer);
            break;
        case KM_ENUM_REP:
            enum_repetition[static_cast<uint64_t>(param.tag)].push_back(
                static_cast<uint8_t>(param.enumerated));
            break;
        case KM_ULONG:
            map.add(static_cast<uint64_t>(param.tag), param.long_integer);
            break;
        case KM_ULONG_REP:
            uint_repetition[static_cast<uint64_t>(param.tag & 0x00000000ffffffff)].add(
                param.long_integer);
            break;
        case KM_DATE:
            map.add(static_cast<uint64_t>(param.tag), param.date_time);
            break;
        case KM_BOOL:
            map.add(static_cast<uint64_t>(param.tag), static_cast<uint8_t>(param.boolean));
            break;
        case KM_BIGNUM:
        case KM_BYTES:
            map.add(static_cast<uint64_t>(param.tag & 0x00000000ffffffff),
                    kmBlob2vector(param.blob));
            break;
        default:
            /* Invalid skip */
            break;
        }
    }
    if (0 < enum_repetition.size()) {
        for (auto const& [key, val] : enum_repetition) {
            Bstr bstr(val);
            map.add(key, std::move(bstr));
        }
    }
    if (0 < uint_repetition.size()) {
        for (auto& [key, val] : uint_repetition) {
            map.add(key, std::move(val));
        }
    }
    array.add(std::move(map));
    return true;
}
/*
bool CborConverter::addKeyparameters(Array& array, const vector<KeyParameter>& keyParams) {
    keymaster_key_param_set_t paramSet = km_utils::aidlKeyParams2Km(keyParams);
    return addKeyparameters(array, paramSet);
}

// Array of three maps
bool CborConverter::getKeyCharacteristics(const unique_ptr<Item>& item, const uint32_t pos,
                                          vector<KeyCharacteristics>& keyCharacteristics) {
    unique_ptr<Item> arrayItem(nullptr);
    getItemAtPos(item, pos, arrayItem);
    if ((arrayItem == nullptr) || (MajorType::ARRAY != getType(arrayItem))) return false;

    KeyCharacteristics swEnf{SecurityLevel::KEYSTORE, {}};
    KeyCharacteristics teeEnf{SecurityLevel::TRUSTED_ENVIRONMENT, {}};
    KeyCharacteristics sbEnf{SecurityLevel::STRONGBOX, {}};

    if (!getKeyParameters(arrayItem, 0, sbEnf.authorizations) ||
        !getKeyParameters(arrayItem, 1, teeEnf.authorizations) ||
        !getKeyParameters(arrayItem, 2, swEnf.authorizations)) {
        return false;
    }
    // VTS will fail if the authorizations list is empty.
    if (!sbEnf.authorizations.empty()) keyCharacteristics.push_back(std::move(sbEnf));
    if (!teeEnf.authorizations.empty()) keyCharacteristics.push_back(std::move(teeEnf));
    if (!swEnf.authorizations.empty()) keyCharacteristics.push_back(std::move(swEnf));
    return true;
}*/

bool CborConverter::getKeyCharacteristics(const std::unique_ptr<Item>& item, const uint32_t pos,
                               AuthorizationSet& swEnforced,
                               AuthorizationSet& hwEnforced,
                               AuthorizationSet& teeEnforced) {
    unique_ptr<Item> arrayItem(nullptr);
    getItemAtPos(item, pos, arrayItem);
    if ((arrayItem == nullptr) || (MajorType::ARRAY != getType(arrayItem))) return false;

    //KeyCharacteristics swEnf{SecurityLevel::KEYSTORE, {}};
    //KeyCharacteristics teeEnf{SecurityLevel::TRUSTED_ENVIRONMENT, {}};
    //KeyCharacteristics sbEnf{SecurityLevel::STRONGBOX, {}};

    if (!getKeyParameters(arrayItem, 0, swEnforced) ||
        !getKeyParameters(arrayItem, 1, hwEnforced) ||
        !getKeyParameters(arrayItem, 2, teeEnforced)) {
        return false;
    }
    return true;
}

bool CborConverter::getKeyParameter(const std::pair<const unique_ptr<Item>&, const unique_ptr<Item>&> pair,
                         AuthorizationSet& keyParams) {
    uint64_t key;
    uint64_t value;
    if (!getUint64(pair.first, key)) {
        return false;
    }
    switch (keymaster_tag_get_type(static_cast<keymaster_tag_t>(key))) {
    case KM_ENUM_REP: {
        /* ENUM_REP contains values encoded in a Binary string */
        const Bstr* bstr = pair.second.get()->asBstr();
        if (bstr == nullptr) return false;
        for (auto bchar : bstr->value()) {
            keymaster_key_param_t keyParam;
            keyParam.tag = static_cast<keymaster_tag_t>(key);
            keyParam.enumerated = bchar;
            keyParams.push_back(keyParam);
        }
    } break;
    case KM_ENUM: {
        keymaster_key_param_t keyParam;
        keyParam.tag = static_cast<keymaster_tag_t>(key);
        if (!getUint64(pair.second, value)) {
            return false;
        }
        keyParam.enumerated = static_cast<uint32_t>(value);
        keyParams.push_back(keyParam);
    } break;
    case KM_UINT: {
        keymaster_key_param_t keyParam;
        keyParam.tag = static_cast<keymaster_tag_t>(key);
        if (!getUint64(pair.second, value)) {
            return false;
        }
        keyParam.integer = static_cast<uint32_t>(value);
        keyParams.push_back(keyParam);
    } break;
    case KM_ULONG: {
        keymaster_key_param_t keyParam;
        keyParam.tag = static_cast<keymaster_tag_t>(key);
        if (!getUint64(pair.second, value)) {
            return false;
        }
        keyParam.long_integer = value;
        keyParams.push_back(keyParam);
    } break;
    case KM_UINT_REP: {
        /* UINT_REP contains values encoded in a Array */
        Array* array = const_cast<Array*>(pair.second.get()->asArray());
        if (array == nullptr) return false;
        for (int i = 0; i < array->size(); i++) {
            keymaster_key_param_t keyParam;
            keyParam.tag = static_cast<keymaster_tag_t>(key);
            std::unique_ptr<Item> item = std::move((*array)[i]);
            if (!getUint64(item, value)) {
                return false;
            }
            keyParam.integer = static_cast<uint32_t>(value);
            keyParams.push_back(keyParam);
        }
    } break;
    case KM_ULONG_REP: {
        /* ULONG_REP contains values encoded in a Array */
        Array* array = const_cast<Array*>(pair.second.get()->asArray());
        if (array == nullptr) return false;
        for (int i = 0; i < array->size(); i++) {
            keymaster_key_param_t keyParam;
            keyParam.tag = static_cast<keymaster_tag_t>(key);
            std::unique_ptr<Item> item = std::move((*array)[i]);
            if (!getUint64(item, keyParam.long_integer)) {
                return false;
            }
            keyParams.push_back(keyParam);
        }
    } break;
    case KM_DATE: {
        keymaster_key_param_t keyParam;
        keyParam.tag = static_cast<keymaster_tag_t>(key);
        if (!getUint64(pair.second, value)) {
            return false;
        }
        keyParam.date_time = value;
        keyParams.push_back(keyParam);
    } break;
    case KM_BOOL: {
        keymaster_key_param_t keyParam;
        keyParam.tag = static_cast<keymaster_tag_t>(key);
        if (!getUint64(pair.second, value)) {
            return false;
        }
        // TODO re-check the logic below
        keyParam.boolean = static_cast<bool>(value);
        keyParams.push_back(keyParam);
    } break;
    case KM_BYTES: {
        keymaster_key_param_t keyParam;
        keyParam.tag = static_cast<keymaster_tag_t>(key);
        const Bstr* bstr = pair.second.get()->asBstr();
        if (bstr == nullptr) return false;
        size_t blobSize = bstr->value().size();
        keyParam.blob.data = keymaster::dup_buffer(bstr->value().data(), blobSize);
        keyParam.blob.data_length = blobSize;
        keyParams.push_back(keyParam);
        } break;
    default:
        /* Invalid - return error */
        return false;
        break;
    }
    return true;
}
#if 0
bool CborConverter::getKeyParameter(
    const std::pair<const unique_ptr<Item>&, const unique_ptr<Item>&> pair,
    vector<KeyParameter>& keyParams) {
    uint64_t key;
    uint64_t value;
    if (!getUint64(pair.first, key)) {
        return false;
    }
    switch (keymaster_tag_get_type(static_cast<keymaster_tag_t>(key))) {
    case KM_ENUM_REP: {
        /* ENUM_REP contains values encoded in a Binary string */
        const Bstr* bstr = pair.second.get()->asBstr();
        if (bstr == nullptr) return false;
        for (auto bchar : bstr->value()) {
            keymaster_key_param_t keyParam;
            keyParam.tag = static_cast<keymaster_tag_t>(key);
            keyParam.enumerated = bchar;
            keyParams.push_back(km_utils::kmParam2Aidl(keyParam));
        }
    } break;
    case KM_ENUM: {
        keymaster_key_param_t keyParam;
        keyParam.tag = static_cast<keymaster_tag_t>(key);
        if (!getUint64(pair.second, value)) {
            return false;
        }
        keyParam.enumerated = static_cast<uint32_t>(value);
        keyParams.push_back(km_utils::kmParam2Aidl(keyParam));
    } break;
    case KM_UINT: {
        keymaster_key_param_t keyParam;
        keyParam.tag = static_cast<keymaster_tag_t>(key);
        if (!getUint64(pair.second, value)) {
            return false;
        }
        keyParam.integer = static_cast<uint32_t>(value);
        keyParams.push_back(km_utils::kmParam2Aidl(keyParam));
    } break;
    case KM_ULONG: {
        keymaster_key_param_t keyParam;
        keyParam.tag = static_cast<keymaster_tag_t>(key);
        if (!getUint64(pair.second, value)) {
            return false;
        }
        keyParam.long_integer = value;
        keyParams.push_back(km_utils::kmParam2Aidl(keyParam));
    } break;
    case KM_UINT_REP: {
        /* UINT_REP contains values encoded in a Array */
        Array* array = const_cast<Array*>(pair.second.get()->asArray());
        if (array == nullptr) return false;
        for (int i = 0; i < array->size(); i++) {
            keymaster_key_param_t keyParam;
            keyParam.tag = static_cast<keymaster_tag_t>(key);
            std::unique_ptr<Item> item = std::move((*array)[i]);
            if (!getUint64(item, value)) {
                return false;
            }
            keyParam.integer = static_cast<uint32_t>(value);
            keyParams.push_back(km_utils::kmParam2Aidl(keyParam));
        }
    } break;
    case KM_ULONG_REP: {
        /* ULONG_REP contains values encoded in a Array */
        Array* array = const_cast<Array*>(pair.second.get()->asArray());
        if (array == nullptr) return false;
        for (int i = 0; i < array->size(); i++) {
            keymaster_key_param_t keyParam;
            keyParam.tag = static_cast<keymaster_tag_t>(key);
            std::unique_ptr<Item> item = std::move((*array)[i]);
            if (!getUint64(item, keyParam.long_integer)) {
                return false;
            }
            keyParams.push_back(km_utils::kmParam2Aidl(keyParam));
        }
    } break;
    case KM_DATE: {
        keymaster_key_param_t keyParam;
        keyParam.tag = static_cast<keymaster_tag_t>(key);
        if (!getUint64(pair.second, value)) {
            return false;
        }
        keyParam.date_time = value;
        keyParams.push_back(km_utils::kmParam2Aidl(keyParam));
    } break;
    case KM_BOOL: {
        keymaster_key_param_t keyParam;
        keyParam.tag = static_cast<keymaster_tag_t>(key);
        if (!getUint64(pair.second, value)) {
            return false;
        }
        // TODO re-check the logic below
        keyParam.boolean = static_cast<bool>(value);
        keyParams.push_back(km_utils::kmParam2Aidl(keyParam));
    } break;
    case KM_BYTES: {
        keymaster_key_param_t keyParam;
        keyParam.tag = static_cast<keymaster_tag_t>(key);
        const Bstr* bstr = pair.second.get()->asBstr();
        if (bstr == nullptr) return false;
        keyParam.blob.data = bstr->value().data();
        keyParam.blob.data_length = bstr->value().size();
        keyParams.push_back(km_utils::kmParam2Aidl(keyParam));
    } break;
    default:
        /* Invalid - return error */
        return false;
        break;
    }
    return true;
}

// array of a blobs
bool CborConverter::getCertificateChain(const std::unique_ptr<Item>& item, const uint32_t pos,
                                        vector<Certificate>& certChain) {
    std::unique_ptr<Item> arrayItem(nullptr);
    getItemAtPos(item, pos, arrayItem);
    if ((arrayItem == nullptr) || (MajorType::ARRAY != getType(arrayItem))) return false;

    const Array* arr = arrayItem.get()->asArray();
    for (int i = 0; i < arr->size(); i++) {
        Certificate cert;
        if (!getBinaryArray(arrayItem, i, cert.encodedCertificate)) return false;
        certChain.push_back(std::move(cert));
    }
    return true;
}

#endif
bool CborConverter::getMultiBinaryArray(const unique_ptr<Item>& item, const uint32_t pos,
                                        vector<vector<uint8_t>>& data) {
    bool ret = false;
    std::unique_ptr<Item> arrayItem(nullptr);

    getItemAtPos(item, pos, arrayItem);
    if ((arrayItem == nullptr) || (MajorType::ARRAY != getType(arrayItem))) return ret;
    const Array* arr = arrayItem.get()->asArray();
    size_t arrSize = arr->size();
    for (int i = 0; i < arrSize; i++) {
        std::vector<uint8_t> temp;
        if (!getBinaryArray(arrayItem, i, temp)) return ret;
        data.push_back(std::move(temp));
    }
    ret = true;  // success
    return ret;
}

bool CborConverter::getBinaryArray(const unique_ptr<Item>& item, const uint32_t pos,
                                   string& value) {
    vector<uint8_t> vec;
    string str;
    if (!getBinaryArray(item, pos, vec)) {
        return false;
    }
    for (auto ch : vec) {
        str += ch;
    }
    value = str;
    return true;
}

bool CborConverter::getBinaryArray(const unique_ptr<Item>& item, const uint32_t pos,
                                   vector<uint8_t>& value) {
    bool ret = false;
    unique_ptr<Item> strItem(nullptr);
    getItemAtPos(item, pos, strItem);
    if ((strItem == nullptr) || (MajorType::BSTR != getType(strItem))) return ret;

    const Bstr* bstr = strItem.get()->asBstr();
    for (auto bchar : bstr->value()) {
        value.push_back(bchar);
    }
    ret = true;
    return ret;
}

bool CborConverter::getSharedSecretParameters(const unique_ptr<Item>& item, const uint32_t pos,
                                              vector<uint8_t>& seed, vector<uint8_t>& nonce) {
    std::unique_ptr<Item> arrayItem(nullptr);
    // Array [seed, nonce]
    getItemAtPos(item, pos, arrayItem);
    if ((arrayItem == nullptr) || (MajorType::ARRAY != getType(arrayItem)) ||
        !getBinaryArray(arrayItem, 0, seed) || !getBinaryArray(arrayItem, 1, nonce)) {
        return false;
    }
    return true;
}

bool CborConverter::addSharedSecretParameters(Array& array,
                                              vector<HmacSharingParameters> params) {
    Array cborParamsVec;
    for (auto param : params) {
        Array cborParam;
        cborParam.add(param.seed);
        cborParam.add(param.nonce);
        cborParamsVec.add(std::move(cborParam));
    }
    array.add(std::move(cborParamsVec));
    return true;
}

bool CborConverter::addTimeStampToken(Array& array, const TimestampToken& token) {
    vector<uint8_t> mac(token.mac.begin(), token.mac.end());
    Array vToken;
    vToken.add(static_cast<uint64_t>(token.challenge));
    vToken.add(static_cast<uint64_t>(token.timestamp));
    vToken.add(mac);
    array.add(std::move(vToken));
    return true;
}

bool CborConverter::addVerificationToken(Array& vToken, const VerificationToken& token, const vector<uint8_t>& encodedParamsVerified) {
    vector<uint8_t> mac(token.mac.begin(), token.mac.end());
    vToken.add(token.challenge);
    vToken.add(token.timestamp);
    vToken.add(std::move(encodedParamsVerified));
    vToken.add(static_cast<uint64_t>(token.security_level));
    vToken.add(mac);
    return true;
}

bool CborConverter::addHardwareAuthToken(Array& array, const HardwareAuthToken& authToken) {
    vector<uint8_t> mac(authToken.mac.begin(), authToken.mac.end());
    Array hwAuthToken;
    hwAuthToken.add(static_cast<uint64_t>(authToken.challenge));
    hwAuthToken.add(static_cast<uint64_t>(authToken.user_id));
    hwAuthToken.add(static_cast<uint64_t>(authToken.authenticator_id));
    hwAuthToken.add(static_cast<uint64_t>(authToken.authenticator_type));
    hwAuthToken.add(static_cast<uint64_t>(authToken.timestamp));
    hwAuthToken.add(mac);
    array.add(std::move(hwAuthToken));
    return true;
}

bool CborConverter::getHardwareAuthToken(const unique_ptr<Item>& item, const uint32_t pos,
                                         HardwareAuthToken& token) {
    uint64_t authType;
    std::vector<uint8_t> mac;
    // challenge, userId, AuthenticatorId, AuthType, Timestamp, MAC
    if (!getUint64<uint64_t>(item, pos, token.challenge) ||
        !getUint64<uint64_t>(item, pos + 1, token.user_id) ||
        !getUint64<uint64_t>(item, pos + 2, token.authenticator_id) ||
        !getUint64<uint64_t>(item, pos + 3, authType) ||
        !getUint64<uint64_t>(item, pos + 4, token.timestamp) ||
        !getBinaryArray(item, pos + 5, mac)) {
        return false;
    }
    token.authenticator_type = static_cast<hw_authenticator_type_t>(authType);
    token.mac = KeymasterBlob(mac.data(), mac.size());
    return true;
}

bool CborConverter::getTimeStampToken(const unique_ptr<Item>& item, const uint32_t pos,
                                      TimestampToken& token) {
    // {challenge, timestamp, Mac}
    std::vector<uint8_t> mac;
    if (!getUint64<uint64_t>(item, pos, token.challenge) ||
        !getUint64<uint64_t>(item, pos + 1, token.timestamp) ||
        !getBinaryArray(item, pos + 2, mac)) {
        return false;
    }
    token.mac = KeymasterBlob(mac.data(), mac.size());
    return true;
}

bool CborConverter::getVerificationToken(const unique_ptr<Item>& item, const uint32_t pos,
                                      VerificationToken& token) {
    // {challenge, timestamp, parametersVerified, securityLevel, Mac}
    std::vector<uint8_t> mac;
    uint64_t securityLevel;
    if (!getUint64<uint64_t>(item, pos, token.challenge) ||
        !getUint64<uint64_t>(item, pos + 1, token.timestamp) ||
        !getKeyParameters(item, pos + 2, token.parameters_verified) ||
        !getUint64<uint64_t>(item, pos + 3, securityLevel) ||
        !getBinaryArray(item, pos + 4, mac)) {
        return false;
    }
    token.security_level = static_cast<keymaster_security_level_t>(securityLevel);
    token.mac = KeymasterBlob(mac.data(), mac.size());
    return true;
}

bool CborConverter::getArrayItem(const std::unique_ptr<Item>& item, const uint32_t pos,
                             Array& array) {
    unique_ptr<Item> arrayItem(nullptr);
    getItemAtPos(item, pos, arrayItem);
    if ((arrayItem == nullptr) || (MajorType::ARRAY != getType(arrayItem))) return false;
    array = std::move(*arrayItem.get()->asArray());
    return true;
}

bool CborConverter::getMapItem(const std::unique_ptr<Item>& item, const uint32_t pos,
                             Map& map) {
    unique_ptr<Item> mapItem(nullptr);
    getItemAtPos(item, pos, mapItem);
    if ((mapItem == nullptr) || (MajorType::MAP != getType(mapItem))) return false;
    map = std::move(*mapItem.get()->asMap());
    return true;
}

bool CborConverter::getKeyParameters(const unique_ptr<Item>& item, const uint32_t pos,
                                     AuthorizationSet& keyParams) {
    bool ret = false;
    unique_ptr<Item> mapItem(nullptr);
    getItemAtPos(item, pos, mapItem);
    if ((mapItem == nullptr) || (MajorType::MAP != getType(mapItem))) return ret;
    const Map* map = mapItem.get()->asMap();
    size_t mapSize = map->size();
    for (int i = 0; i < mapSize; i++) {
        if (!getKeyParameter((*map)[i], keyParams)) {
            return ret;
        }
    }
    ret = true;
    return ret;
}
/*
bool CborConverter::getKeyParameters(const unique_ptr<Item>& item, const uint32_t pos,
                                     vector<KeyParameter>& keyParams) {
    bool ret = false;
    unique_ptr<Item> mapItem(nullptr);
    vector<KeyParameter> params;
    getItemAtPos(item, pos, mapItem);
    if ((mapItem == nullptr) || (MajorType::MAP != getType(mapItem))) return ret;
    const Map* map = mapItem.get()->asMap();
    size_t mapSize = map->size();
    for (int i = 0; i < mapSize; i++) {
        if (!getKeyParameter((*map)[i], params)) {
            return ret;
        }
    }
    keyParams.resize(params.size());
    keyParams = params;
    ret = true;
    return ret;
}*/

std::tuple<std::unique_ptr<Item>, keymaster_error_t>
CborConverter::decodeData(const std::vector<uint8_t>& response) {
    keymaster_error_t errorCode = KM_ERROR_OK;
    auto [item, pos, message] = parse(response);
    if (!item || MajorType::ARRAY != getType(item) || !getErrorCode(item, 0, errorCode)) {
        return {nullptr, KM_ERROR_UNKNOWN_ERROR};
    }
    return {std::move(item), errorCode};
}

std::unique_ptr<Item>
CborConverter::decodeKeyblob(const KeymasterKeyBlob& keyBlob) {
    std::vector<uint8_t> data(keyBlob.begin(), keyBlob.end());
    auto [item, pos, message] = parse(data);
    if (!item || MajorType::ARRAY != getType(item)) {
        return nullptr;
    }
    return std::move(item);
}

}  // namespace keymint::javacard
