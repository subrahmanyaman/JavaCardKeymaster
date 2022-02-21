/*
 * Copyright(C) 2020 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" (short)0IS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.android.javacard.kmdevice;

import javacard.framework.JCSystem;
import javacard.framework.Util;

// The class encodes strongbox generated amd signed attestation certificate. This only encodes
// required fields of the certificates. It is not meant to be generic X509 cert encoder.
// Whatever fields that are fixed are added as byte arrays. The Extensions are encoded as per
// the values.
// The certificate is assembled with leafs first and then the sequences.

public class KMAttestationCertImpl implements KMAttestationCert {

  private static final byte MAX_PARAMS = 30;
  // DER encoded object identifiers required by the cert.
  // rsaEncryption - 1.2.840.113549.1.1.1
  private static byte[] rsaEncryption;
  // ecPublicKey -  1.2.840.10045.2.1
  private static byte[] eccPubKey;
  // prime256v1 curve - 1.2.840.10045.3.1.7
  private static byte[] prime256v1;
  // Key Usage Extn - 2.5.29.15
  private static byte[] keyUsageExtn;
  // Android Extn - 1.3.6.1.4.1.11129.2.1.17
  private static byte[] androidExtn;
  private static final short RSA_SIG_LEN = 256;
  private static final short ECDSA_MAX_SIG_LEN = 72;
  //Signature algorithm identifier - ecdsaWithSha256 - 1.2.840.10045.4.3.2
  //SEQUENCE of alg OBJ ID and parameters = NULL.
  private static byte[] X509EcdsaSignAlgIdentifier;
  // Signature algorithm identifier - sha256WithRSAEncryption - 1.2.840.113549.1.1.11
  // SEQUENCE of alg OBJ ID and parameters = NULL.
  private static byte[] X509RsaSignAlgIdentifier;

  // Below are the allowed softwareEnforced Authorization tags inside the attestation certificate's extension.
  private static short[] swTagIds;

  // Below are the allowed hardwareEnforced Authorization tags inside the attestation certificate's extension.
  private static short[] hwTagIds;

  // Validity is not fixed field
  // Subject is a fixed field with only CN= Android Keystore Key - same for all the keys
  private static byte[] X509Subject;

  private static final byte keyUsageSign = (byte) 0x80; // 0 bit
  private static final byte keyUsageKeyEncipher = (byte) 0x20; // 2nd- bit
  private static final byte keyUsageDataEncipher = (byte) 0x10; // 3rd- bit
  private static final byte keyUsageKeyAgreement = (byte) 0x08; // 4th- bit
  private static final byte keyUsageCertSign = (byte) 0x04; // 5th- bit

  private static final byte KEYMASTER_VERSION = 100;
  private static final byte ATTESTATION_VERSION = 100;
  private static byte[] pubExponent;
  private static final byte SERIAL_NUM = (byte) 0x01;
  private static final byte X509_VERSION = (byte) 0x02;
  
  // indexes in transient array indexes
  private static final byte CERT_START = (byte) 0;
  private static final byte CERT_LENGTH = (byte) 1;
  private static final byte TBS_START = (byte) 2;
  private static final byte TBS_LENGTH = (byte) 3;
  private static final byte BUF_START = (byte) 4;
  private static final byte BUF_LENGTH = (byte) 5;
  private static final byte SW_PARAM_INDEX = (byte) 6;
  private static final byte HW_PARAM_INDEX = (byte) 7;
  
//indexes in transient array dataIndexes
  private static final byte STACK_PTR = (byte) 0;
  private static final byte UNIQUE_ID = (byte) 1;
  private static final byte ATT_CHALLENGE = (byte) 2;
  private static final byte NOT_BEFORE = (byte) 3;
  private static final byte NOT_AFTER = (byte) 4;
  private static final byte PUB_KEY = (byte) 5;
  private static final byte VERIFIED_BOOT_KEY = (byte) 6;
  private static final byte VERIFIED_HASH = (byte) 7;
  private static final byte ISSUER = (byte) 8;
  private static final byte SUBJECT_NAME = (byte) 9;
  private static final byte SIGN_PRIV = (byte) 10;
  private static final byte SERIAL_NUMBER = (byte) 11;
  private static final byte CERT_ATT_KEY_SECRET = (byte) 12;
  private static final byte CERT_ATT_KEY_RSA_PUB_MOD = (byte) 13;
  
//indexes in transient array stateIndexes
  private static final byte KEY_USAGE = (byte) 0;
  private static final byte UNUSED_BITS = (byte) 1;
  private static final byte DEVICE_LOCKED = (byte) 2;
  private static final byte VERIFIED_STATE = (byte) 3;
  private static final byte CERT_MODE = (byte) 4;
  private static final byte RSA_CERT = (byte) 5;
  private static final byte CERT_RSA_SIGN = (byte) 6;
 
  private static short []indexes;
  private static short []dataIndexes;
  private static byte []stateIndexes;
  
  private static byte[] stack;
  private static short[] swParams; 
  private static short[] hwParams;
 
  private static KMAttestationCert inst;
  private static KMSEProvider seProvider;

  private static KMAttestationKey factoryAttestKey;
  private static final byte SERIAL_NUM_MAX_LEN = 20;
  private static final byte SUBJECT_NAME_MAX_LEN = 32;

  public static void initStatics() {
    rsaEncryption = new byte[]{
        0x06, 0x09, 0x2A, (byte) 0x86, 0x48, (byte) 0x86, (byte) 0xF7, 0x0D, 0x01, 0x01, 0x01
    };
    eccPubKey = new byte[]{
        0x06, 0x07, 0x2A, (byte) 0x86, 0x48, (byte) 0xCE, 0x3D, 0x02, 0x01
    };
    prime256v1 = new byte[]{
        0x06, 0x08, 0x2A, (byte) 0x86, 0x48, (byte) 0xCE, 0x3D, 0x03, 0x01, 0x07
    };
    keyUsageExtn = new byte[]{0x06, 0x03, 0x55, 0x1D, 0x0F};
    androidExtn = new byte[]{
        0x06, 0x0A, 0X2B, 0X06, 0X01, 0X04, 0X01, (byte) 0XD6, 0X79, 0X02, 0X01, 0X11
    };
    X509EcdsaSignAlgIdentifier = new byte[]{
        0x30,
        0x0A,
        0x06,
        0x08,
        0x2A,
        (byte) 0x86,
        0x48,
        (byte) 0xCE,
        (byte) 0x3D,
        0x04,
        0x03,
        0x02
    };
    X509RsaSignAlgIdentifier = new byte[]{
        0x30,
        0x0D,
        0x06,
        0x09,
        0x2A,
        (byte) 0x86,
        0x48,
        (byte) 0x86,
        (byte) 0xF7,
        0x0D,
        0x01,
        0x01,
        0x0B,
        0x05,
        0x00
    };
    swTagIds = new short[]{
        KMType.ATTESTATION_APPLICATION_ID,
        KMType.CREATION_DATETIME,
        KMType.USAGE_EXPIRE_DATETIME,
        KMType.ORIGINATION_EXPIRE_DATETIME,
        KMType.ACTIVE_DATETIME,
        KMType.UNLOCKED_DEVICE_REQUIRED
    };
    hwTagIds = new short[]{
        KMType.BOOT_PATCH_LEVEL, KMType.VENDOR_PATCH_LEVEL,
        KMType.ATTESTATION_ID_MODEL, KMType.ATTESTATION_ID_MANUFACTURER,
        KMType.ATTESTATION_ID_MEID, KMType.ATTESTATION_ID_IMEI,
        KMType.ATTESTATION_ID_SERIAL, KMType.ATTESTATION_ID_PRODUCT,
        KMType.ATTESTATION_ID_DEVICE, KMType.ATTESTATION_ID_BRAND,
        KMType.OS_PATCH_LEVEL, KMType.OS_VERSION, KMType.ROOT_OF_TRUST,
        KMType.ORIGIN, KMType.AUTH_TIMEOUT, KMType.USER_AUTH_TYPE,
        KMType.NO_AUTH_REQUIRED, KMType.USER_SECURE_ID,
        KMType.RSA_PUBLIC_EXPONENT, KMType.ECCURVE, KMType.MIN_MAC_LENGTH,
        KMType.CALLER_NONCE, KMType.PADDING, KMType.DIGEST, KMType.BLOCK_MODE,
        KMType.KEYSIZE, KMType.ALGORITHM, KMType.PURPOSE};
    X509Subject = new byte[]{
        0x30, 0x1F, 0x31, 0x1D, 0x30, 0x1B, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x14, 0x41, 0x6e,
        0x64,
        0x72, 0x6f, 0x69, 0x64, 0x20, 0x4B, 0x65, 0x79, 0x73, 0x74, 0x6f, 0x72, 0x65, 0x20, 0x4B,
        0x65,
        0x79
    };
    pubExponent = new byte[]{0x01, 0x00, 0x01};
  }

  private KMAttestationCertImpl() {
  }

  public static KMAttestationCert instance(boolean rsaCert, KMSEProvider provider) {
    if (inst == null) {
      inst = new KMAttestationCertImpl();
      seProvider = provider;
    }
    init();
    KMAttestationCertImpl.stateIndexes[RSA_CERT] = (byte)((rsaCert == true)? 1: 0);
    return inst;
  }

  private static void init() {
	  
	indexes = JCSystem.makeTransientShortArray((short) 8, JCSystem.CLEAR_ON_RESET);
    for (short i=0; i<8; i++ ) {
      indexes[i] = 0;	
    }
	dataIndexes = JCSystem.makeTransientShortArray((short) 14, JCSystem.CLEAR_ON_RESET);
	for (short i = 0; i < 14; i++ ) {
	  dataIndexes[i] = 0;	
	}
    stateIndexes = JCSystem.makeTransientByteArray((short) 7, JCSystem.CLEAR_ON_RESET);
    Util.arrayFillNonAtomic(stateIndexes, (short) 0, (short) 5, (byte) 0);
    stateIndexes[CERT_MODE] = KMType.NO_CERT;
	stack = null;
    if (swParams == null) {
      swParams = JCSystem.makeTransientShortArray((short) MAX_PARAMS, JCSystem.CLEAR_ON_RESET);
    }
    if (hwParams == null) {
      hwParams = JCSystem.makeTransientShortArray((short) MAX_PARAMS, JCSystem.CLEAR_ON_RESET);
    }
    stateIndexes[UNUSED_BITS] = 8;
    stateIndexes[RSA_CERT] = 1;
    dataIndexes[CERT_ATT_KEY_SECRET] = KMType.INVALID_VALUE;
    stateIndexes[CERT_RSA_SIGN] = 1;
    dataIndexes[ISSUER] = KMType.INVALID_VALUE;
    dataIndexes[SUBJECT_NAME] = KMType.INVALID_VALUE;
    dataIndexes[SERIAL_NUMBER] = KMType.INVALID_VALUE;
    factoryAttestKey = null;
  }

  @Override
  public KMAttestationCert verifiedBootHash(short obj) {
	dataIndexes[VERIFIED_HASH] = obj;
    return this;
  }

  @Override
  public KMAttestationCert verifiedBootKey(short obj) {
	dataIndexes[VERIFIED_BOOT_KEY] = obj;
    return this;
  }

  @Override
  public KMAttestationCert verifiedBootState(byte val) {
    stateIndexes[VERIFIED_STATE] = val;
    return this;
  }

  private KMAttestationCert uniqueId(short obj) {
	  dataIndexes[UNIQUE_ID] = obj;
    return this;
  }

  @Override
  public KMAttestationCert notBefore(short obj, boolean derEncoded, byte[] scratchpad) {
    if (!derEncoded) {
      // convert milliseconds to UTC date
      dataIndexes[NOT_BEFORE] = KMUtils.convertToDate(obj, scratchpad, true);
    } else {
      dataIndexes[NOT_BEFORE] = KMByteBlob.instance(KMByteBlob.getBuffer(obj),
          KMByteBlob.getStartOff(obj), KMByteBlob.length(obj));
    }
    return this;
  }

  @Override
  public KMAttestationCert notAfter(short usageExpiryTimeObj, boolean derEncoded,
      byte[] scratchPad) {
    if (!derEncoded) {
      if (usageExpiryTimeObj != KMType.INVALID_VALUE) {
        // compare if the expiry time is greater then 2051 then use generalized
        // time format else use utc time format.
        short tmpVar = KMInteger.uint_64(KMUtils.firstJan2051, (short) 0);
        if (KMInteger.compare(usageExpiryTimeObj, tmpVar) >= 0) {
          usageExpiryTimeObj = KMUtils.convertToDate(usageExpiryTimeObj, scratchPad,
              false);
        } else {
          usageExpiryTimeObj = KMUtils
              .convertToDate(usageExpiryTimeObj, scratchPad, true);
        }
        dataIndexes[NOT_AFTER] = usageExpiryTimeObj;
      } else {
        //notAfter = certExpirtyTimeObj;
      }
    } else {
      // notAfter = KMKeymasterApplet.instance(KMKeymasterApplet.cast(usageExpiryTimeObj).getBuffer(),
      //     KMKeymasterApplet.cast(usageExpiryTimeObj).getStartOff(),
      //     KMKeymasterApplet.cast(usageExpiryTimeObj).length());
      dataIndexes[NOT_AFTER] = usageExpiryTimeObj;
    }
    return this;
  }

  @Override
  public KMAttestationCert deviceLocked(boolean val) {
    if (val) {
      stateIndexes[DEVICE_LOCKED] = (byte) 0xFF;
    } else {
      stateIndexes[DEVICE_LOCKED] = 0;
    }
    return this;
  }

  @Override
  public KMAttestationCert publicKey(short obj) {
	dataIndexes[PUB_KEY] = obj;
    return this;
  }

  @Override
  public KMAttestationCert attestationChallenge(short obj) {
	dataIndexes[ATT_CHALLENGE] = obj;
    return this;
  }

  @Override
  public KMAttestationCert extensionTag(short tag, boolean hwEnforced) {
    if (hwEnforced) {
      hwParams[indexes[HW_PARAM_INDEX]] = tag;
      indexes[HW_PARAM_INDEX]++;
    } else {
      swParams[indexes[SW_PARAM_INDEX]] = tag;
      indexes[SW_PARAM_INDEX]++;
    }
    if (KMTag.getKMTagKey(tag) == KMType.PURPOSE) {
      createKeyUsage(tag);
    }
    return this;
  }

  @Override
  public KMAttestationCert issuer(short obj) {
	dataIndexes[ISSUER] = obj;
    return this;
  }

  private void createKeyUsage(short tag) {
    short len = KMEnumArrayTag.length(tag);
    byte index = 0;
    while (index < len) {
      if (KMEnumArrayTag.get(tag, index) == KMType.SIGN) {
    	stateIndexes[KEY_USAGE] = (byte) (stateIndexes[KEY_USAGE] | keyUsageSign);
      } else if (KMEnumArrayTag.get(tag, index) == KMType.WRAP_KEY) {
        stateIndexes[KEY_USAGE] = (byte) (stateIndexes[KEY_USAGE] | keyUsageKeyEncipher);
      } else if (KMEnumArrayTag.get(tag, index) == KMType.DECRYPT) {
        stateIndexes[KEY_USAGE] = (byte) (stateIndexes[KEY_USAGE] | keyUsageDataEncipher);
      } else if (KMEnumArrayTag.get(tag, index) == KMType.AGREE_KEY) {
        stateIndexes[KEY_USAGE] = (byte) (stateIndexes[KEY_USAGE] | keyUsageKeyAgreement);
      } else if (KMEnumArrayTag.get(tag, index) == KMType.ATTEST_KEY) {
        stateIndexes[KEY_USAGE] = (byte) (stateIndexes[KEY_USAGE] | keyUsageCertSign);
      }
      index++;
    }
    index = stateIndexes[KEY_USAGE];
    while (index != 0) {
      index = (byte) (index << 1);
      stateIndexes[UNUSED_BITS]--;
    }
  }

  //TODO Serial number, X509Version needa to be passed as parameter
  private void pushTbsCert(boolean rsaCert, boolean rsa) {
    short last = dataIndexes[STACK_PTR];
    if (stateIndexes[CERT_MODE] == KMType.ATTESTATION_CERT || stateIndexes[CERT_MODE] == KMType.FACTORY_PROVISIONED_ATTEST_CERT) {
      pushExtensions();
    }
    // subject public key info
    if (rsaCert) {
      pushRsaSubjectKeyInfo();
    } else {
      pushEccSubjectKeyInfo();
    }
    // subject
    pushBytes(KMByteBlob.getBuffer(dataIndexes[SUBJECT_NAME]), KMByteBlob.getStartOff(dataIndexes[SUBJECT_NAME]),
        KMByteBlob.length(dataIndexes[SUBJECT_NAME]));
    pushValidity();
    // issuer - der encoded
    pushBytes(
        KMByteBlob.getBuffer(dataIndexes[ISSUER]),
        KMByteBlob.getStartOff(dataIndexes[ISSUER]),
        KMByteBlob.length(dataIndexes[ISSUER]));
    // Algorithm Id
    if (rsa) {
      pushAlgorithmId(X509RsaSignAlgIdentifier);
    } else {
      pushAlgorithmId(X509EcdsaSignAlgIdentifier);
    }
    // Serial Number
    pushBytes(KMByteBlob.getBuffer(dataIndexes[SERIAL_NUMBER]), KMByteBlob.getStartOff(dataIndexes[SERIAL_NUMBER]),
        KMByteBlob.length(dataIndexes[SERIAL_NUMBER]));
    pushIntegerHeader(KMByteBlob.length(dataIndexes[SERIAL_NUMBER]));
    // Version
    pushByte(X509_VERSION);
    pushIntegerHeader((short) 1);
    pushByte((byte) 0x03);
    pushByte((byte) 0xA0);
    // Finally sequence header.
    pushSequenceHeader((short) (last - dataIndexes[STACK_PTR]));
  }

  private void pushExtensions() {
    short last = dataIndexes[STACK_PTR];
    if (stateIndexes[KEY_USAGE] != 0) {
      pushKeyUsage(stateIndexes[KEY_USAGE], stateIndexes[UNUSED_BITS]);
    }
    pushKeyDescription();
    pushSequenceHeader((short) (last - dataIndexes[STACK_PTR]));
    // Extensions have explicit tag of [3]
    pushLength((short) (last - dataIndexes[STACK_PTR]));
    pushByte((byte) 0xA3);
  }

  // Time SEQUENCE{UTCTime, UTC or Generalized Time)
  private void pushValidity() {
    short last = dataIndexes[STACK_PTR];
    if (dataIndexes[NOT_AFTER] != 0) {
      pushBytes(
          KMByteBlob.getBuffer(dataIndexes[NOT_AFTER]),
          KMByteBlob.getStartOff(dataIndexes[NOT_AFTER]),
          KMByteBlob.length(dataIndexes[NOT_AFTER]));
    } else {
      KMException.throwIt(KMError.INVALID_DATA);
    }
    pushTimeHeader(KMByteBlob.length(dataIndexes[NOT_AFTER]));
    pushBytes(
        KMByteBlob.getBuffer(dataIndexes[NOT_BEFORE]),
        KMByteBlob.getStartOff(dataIndexes[NOT_BEFORE]),
        KMByteBlob.length(dataIndexes[NOT_BEFORE]));
    pushTimeHeader(KMByteBlob.length(dataIndexes[NOT_BEFORE]));
    pushSequenceHeader((short) (last - dataIndexes[STACK_PTR]));
  }

  private static void pushTimeHeader(short len) {
    if (len == 13) { // UTC Time
      pushLength((short) 0x0D);
      pushByte((byte) 0x17);
    } else if (len == 15) { // Generalized Time
      pushLength((short) 0x0F);
      pushByte((byte) 0x18);
    } else {
      KMException.throwIt(KMError.INVALID_INPUT_LENGTH);
    }
  }

  // SEQUENCE{SEQUENCE{algId, NULL}, bitString{SEQUENCE{ modulus as positive integer, public
  // exponent
  // as positive integer}
  private void pushRsaSubjectKeyInfo() {
    short last = dataIndexes[STACK_PTR];
    pushBytes(pubExponent, (short) 0, (short) pubExponent.length);
    pushIntegerHeader((short) pubExponent.length);
    pushBytes(
        KMByteBlob.getBuffer(dataIndexes[PUB_KEY]),
        KMByteBlob.getStartOff(dataIndexes[PUB_KEY]),
        KMByteBlob.length(dataIndexes[PUB_KEY]));

    // encode modulus as positive if the MSB is 1.
    if (KMByteBlob.get(dataIndexes[PUB_KEY], (short) 0) < 0) {
      pushByte((byte) 0x00);
      pushIntegerHeader((short) (KMByteBlob.length(dataIndexes[PUB_KEY]) + 1));
    } else {
      pushIntegerHeader(KMByteBlob.length(dataIndexes[PUB_KEY]));
    }
    pushSequenceHeader((short) (last - dataIndexes[STACK_PTR]));
    pushBitStringHeader((byte) 0x00, (short) (last - dataIndexes[STACK_PTR]));
    pushRsaEncryption();
    pushSequenceHeader((short) (last - dataIndexes[STACK_PTR]));
  }

  // SEQUENCE{SEQUENCE{ecPubKey, prime256v1}, bitString{pubKey}}
  private void pushEccSubjectKeyInfo() {
    short last = dataIndexes[STACK_PTR];
    pushBytes(
        KMByteBlob.getBuffer(dataIndexes[PUB_KEY]),
        KMByteBlob.getStartOff(dataIndexes[PUB_KEY]),
        KMByteBlob.length(dataIndexes[PUB_KEY]));
    pushBitStringHeader((byte) 0x00, KMByteBlob.length(dataIndexes[PUB_KEY]));
    pushEcDsa();
    pushSequenceHeader((short) (last - dataIndexes[STACK_PTR]));
  }

  private static void pushEcDsa() {
    short last = dataIndexes[STACK_PTR];
    pushBytes(prime256v1, (short) 0, (short) prime256v1.length);
    pushBytes(eccPubKey, (short) 0, (short) eccPubKey.length);
    pushSequenceHeader((short) (last - dataIndexes[STACK_PTR]));
  }

  private static void pushRsaEncryption() {
    short last = dataIndexes[STACK_PTR];
    pushNullHeader();
    pushBytes(rsaEncryption, (short) 0, (short) rsaEncryption.length);
    pushSequenceHeader((short) (last - dataIndexes[STACK_PTR]));
  }

  // KeyDescription ::= SEQUENCE {
  //         attestationVersion         INTEGER, # Value 3
  //         attestationSecurityLevel   SecurityLevel, # See below
  //         keymasterVersion           INTEGER, # Value 4
  //         keymasterSecurityLevel     SecurityLevel, # See below
  //         attestationChallenge       OCTET_STRING, # Tag::ATTESTATION_CHALLENGE from attestParams
  //         uniqueId                   OCTET_STRING, # Empty unless key has Tag::INCLUDE_UNIQUE_ID
  //         softwareEnforced           AuthorizationList, # See below
  //         hardwareEnforced           AuthorizationList, # See below
  //     }
  private void pushKeyDescription() {
    short last = dataIndexes[STACK_PTR];
    pushHWParams();
    pushSWParams();
    if (dataIndexes[UNIQUE_ID] != 0) {
      pushOctetString(
          KMByteBlob.getBuffer(dataIndexes[UNIQUE_ID]),
          KMByteBlob.getStartOff(dataIndexes[UNIQUE_ID]),
          KMByteBlob.length(dataIndexes[UNIQUE_ID]));
    } else {
      pushOctetStringHeader((short) 0);
    }
    pushOctetString(
        KMByteBlob.getBuffer(dataIndexes[ATT_CHALLENGE]),
        KMByteBlob.getStartOff(dataIndexes[ATT_CHALLENGE]),
        KMByteBlob.length(dataIndexes[ATT_CHALLENGE]));
    pushEnumerated(KMType.STRONGBOX);
    pushByte(KEYMASTER_VERSION);
    pushIntegerHeader((short) 1);
    pushEnumerated(KMType.STRONGBOX);
    pushByte(ATTESTATION_VERSION);
    pushIntegerHeader((short) 1);
    pushSequenceHeader((short) (last - dataIndexes[STACK_PTR]));
    pushOctetStringHeader((short) (last - dataIndexes[STACK_PTR]));
    pushBytes(androidExtn, (short) 0, (short) androidExtn.length);
    pushSequenceHeader((short) (last - dataIndexes[STACK_PTR]));
  }

  private void pushSWParams() {
    short last = dataIndexes[STACK_PTR];
    byte index = 0;
    short length = (short) swTagIds.length;
    do {
      pushParams(swParams, indexes[SW_PARAM_INDEX], swTagIds[index]);
    } while (++index < length);
    pushSequenceHeader((short) (last - dataIndexes[STACK_PTR]));
  }

  private void pushHWParams() {
    short last = dataIndexes[STACK_PTR];
    byte index = 0;
    short length = (short) hwTagIds.length;
    do {
      if (hwTagIds[index] == KMType.ROOT_OF_TRUST) {
        pushRoT();
        continue;
      }
      if (pushParams(hwParams, indexes[HW_PARAM_INDEX], hwTagIds[index])) {
        continue;
      }
    } while (++index < length);
    pushSequenceHeader((short) (last - dataIndexes[STACK_PTR]));
  }

  private boolean pushParams(short[] params, short len, short tagId) {
    short index = 0;
    while (index < len) {
      if (tagId == KMTag.getKMTagKey(params[index])) {
        pushTag(params[index]);
        return true;
      }
      index++;
    }
    return false;
  }

  private void pushTag(short tag) {
    short type = KMTag.getKMTagType(tag);
    short tagId = KMTag.getKMTagKey(tag);
    short val;
    switch (type) {
      case KMType.BYTES_TAG:
        val = KMByteTag.getValue(tag);
        pushBytesTag(
            tagId,
            KMByteBlob.getBuffer(val),
            KMByteBlob.getStartOff(val),
            KMByteBlob.length(val));
        break;
      case KMType.ENUM_TAG:
        val = KMEnumTag.getValue(tag);
        pushEnumTag(tagId, (byte) val);
        break;
      case KMType.ENUM_ARRAY_TAG:
        val = KMEnumArrayTag.getValues(tag);
        pushEnumArrayTag(
            tagId,
            KMByteBlob.getBuffer(val),
            KMByteBlob.getStartOff(val),
            KMByteBlob.length(val));
        break;
      case KMType.UINT_TAG:
      case KMType.ULONG_TAG:
      case KMType.DATE_TAG:
        val = KMIntegerTag.getValue(tag);
        pushIntegerTag(
            tagId,
            KMInteger.getBuffer(val),
            KMInteger.getStartOff(val),
            KMInteger.length(val));
        break;
      case KMType.UINT_ARRAY_TAG:
      case KMType.ULONG_ARRAY_TAG:
        // According to keymaster hal only one user secure id is used but this conflicts with
        //  tag type which is ULONG-REP. Currently this is encoded as SET OF INTEGERS
        val = KMIntegerArrayTag.getValues(tag);
        pushIntegerArrayTag(tagId, val);
        break;
      case KMType.BOOL_TAG:
        KMBoolTag.validate(tag);
        pushBoolTag(tagId);
        break;
      default:
        KMException.throwIt(KMError.INVALID_TAG);
        break;
    }
  }

  // RootOfTrust ::= SEQUENCE {
  //          verifiedBootKey            OCTET_STRING,
  //          deviceLocked               BOOLEAN,
  //          verifiedBootState          VerifiedBootState,
  //          verifiedBootHash           OCTET_STRING,
  //      }
  // VerifiedBootState ::= ENUMERATED {
  //          Verified                   (0),
  //          SelfSigned                 (1),
  //          Unverified                 (2),
  //          Failed                     (3),
  //      }
  private void pushRoT() {
    short last = dataIndexes[STACK_PTR];
    // verified boot hash
    pushOctetString(
        KMByteBlob.getBuffer(dataIndexes[VERIFIED_HASH]),
        KMByteBlob.getStartOff(dataIndexes[VERIFIED_HASH]),
        KMByteBlob.length(dataIndexes[VERIFIED_HASH]));

    pushEnumerated(stateIndexes[VERIFIED_STATE]);

    pushBoolean(stateIndexes[DEVICE_LOCKED]);
    // verified boot Key
    pushOctetString(
        KMByteBlob.getBuffer(dataIndexes[VERIFIED_BOOT_KEY]),
        KMByteBlob.getStartOff(dataIndexes[VERIFIED_BOOT_KEY]),
        KMByteBlob.length(dataIndexes[VERIFIED_BOOT_KEY]));

    // Finally sequence header
    pushSequenceHeader((short) (last - dataIndexes[STACK_PTR]));
    // ... and tag Id
    pushTagIdHeader(KMType.ROOT_OF_TRUST, (short) (last - dataIndexes[STACK_PTR]));
  }

  private static void pushOctetString(byte[] buf, short start, short len) {
    pushBytes(buf, start, len);
    pushOctetStringHeader(len);
  }

  private static void pushBoolean(byte val) {
    pushByte(val);
    pushBooleanHeader((short) 1);
  }

  private static void pushBooleanHeader(short len) {
    pushLength(len);
    pushByte((byte) 0x01);
  }

  // Only SET of INTEGERS supported are padding, digest, purpose and blockmode
  // All of these are enum array tags i.e. byte long values
  private static void pushEnumArrayTag(short tagId, byte[] buf, short start, short len) {
    short last = dataIndexes[STACK_PTR];
    short index = 0;
    while (index < len) {
      pushByte(buf[(short) (start + index)]);
      pushIntegerHeader((short) 1);
      index++;
    }
    pushSetHeader((short) (last - dataIndexes[STACK_PTR]));
    pushTagIdHeader(tagId, (short) (last - dataIndexes[STACK_PTR]));
  }

  // Only SET of INTEGERS supported are padding, digest, purpose and blockmode
  // All of these are enum array tags i.e. byte long values
  private void pushIntegerArrayTag(short tagId, short arr) {
    short last = dataIndexes[STACK_PTR];
    short index = 0;
    short len = KMArray.length(arr);
    short ptr;
    while (index < len) {
      ptr = KMArray.get(arr, index);
      pushInteger(
          KMInteger.getBuffer(ptr),
          KMInteger.getStartOff(ptr),
          KMInteger.length(ptr));
      index++;
    }
    pushSetHeader((short) (last - dataIndexes[STACK_PTR]));
    pushTagIdHeader(tagId, (short) (last - dataIndexes[STACK_PTR]));
  }

  private static void pushSetHeader(short len) {
    pushLength(len);
    pushByte((byte) 0x31);
  }

  private static void pushEnumerated(byte val) {
    short last = dataIndexes[STACK_PTR];
    pushByte(val);
    pushEnumeratedHeader((short) (last - dataIndexes[STACK_PTR]));
  }

  private static void pushEnumeratedHeader(short len) {
    pushLength(len);
    pushByte((byte) 0x0A);
  }

  private static void pushBoolTag(short tagId) {
    short last = dataIndexes[STACK_PTR];
    pushNullHeader();
    pushTagIdHeader(tagId, (short) (last - dataIndexes[STACK_PTR]));
  }

  private static void pushNullHeader() {
    pushByte((byte) 0);
    pushByte((byte) 0x05);
  }

  private static void pushEnumTag(short tagId, byte val) {
    short last = dataIndexes[STACK_PTR];
    pushByte(val);
    pushIntegerHeader((short) (last - dataIndexes[STACK_PTR]));
    pushTagIdHeader(tagId, (short) (last - dataIndexes[STACK_PTR]));
  }

  private static void pushIntegerTag(short tagId, byte[] buf, short start, short len) {
    short last = dataIndexes[STACK_PTR];
    pushInteger(buf, start, len);
    //    pushIntegerHeader((short) (last - dataIndexes[STACK_PTR]));
    pushTagIdHeader(tagId, (short) (last - dataIndexes[STACK_PTR]));
  }

  // Ignore leading zeros. Only Unsigned Integers are required hence if MSB is set then add 0x00
  // as most significant byte.
  private static void pushInteger(byte[] buf, short start, short len) {
    short last = dataIndexes[STACK_PTR];
    byte index = 0;
    while (index < (byte) len) {
      if (buf[(short) (start + index)] != 0) {
        break;
      }
      index++;
    }
    if (index == (byte) len) {
      pushByte((byte) 0x00);
    } else {
      pushBytes(buf, (short) (start + index), (short) (len - index));
      if (buf[(short) (start + index)] < 0) { // MSB is 1
        pushByte((byte) 0x00); // always unsigned int
      }
    }
    pushIntegerHeader((short) (last - dataIndexes[STACK_PTR]));
  }

  // Bytes Tag is a octet string and tag id is added explicitly
  private static void pushBytesTag(short tagId, byte[] buf, short start, short len) {
    short last = dataIndexes[STACK_PTR];
    pushBytes(buf, start, len);
    pushOctetStringHeader((short) (last - dataIndexes[STACK_PTR]));
    pushTagIdHeader(tagId, (short) (last - dataIndexes[STACK_PTR]));
  }

  // tag id <= 30 ---> 0xA0 | {tagId}
  // 30 < tagId < 128 ---> 0xBF 0x{tagId}
  // tagId >= 128 ---> 0xBF 0x80+(tagId/128) 0x{tagId - (128*(tagId/128))}
  private static void pushTagIdHeader(short tagId, short len) {
    pushLength(len);
    short count = (short) (tagId / 128);
    if (count > 0) {
      pushByte((byte) (tagId - (128 * count)));
      pushByte((byte) (0x80 + count));
      pushByte((byte) 0xBF);
    } else if (tagId > 30) {
      pushByte((byte) tagId);
      pushByte((byte) 0xBF);
    } else {
      pushByte((byte) (0xA0 | (byte) tagId));
    }
  }

  // SEQUENCE {ObjId, OCTET STRING{BIT STRING{keyUsage}}}
  private static void pushKeyUsage(byte keyUsage, byte unusedBits) {
    short last = dataIndexes[STACK_PTR];
    pushByte(keyUsage);
    pushBitStringHeader(unusedBits, (short) (last - dataIndexes[STACK_PTR]));
    pushOctetStringHeader((short) (last - dataIndexes[STACK_PTR]));
    pushBytes(keyUsageExtn, (short) 0, (short) keyUsageExtn.length);
    pushSequenceHeader((short) (last - dataIndexes[STACK_PTR]));
  }

  private static void pushAlgorithmId(byte[] algId) {
    pushBytes(algId, (short) 0, (short) algId.length);
  }

  private static void pushIntegerHeader(short len) {
    pushLength(len);
    pushByte((byte) 0x02);
  }

  private static void pushOctetStringHeader(short len) {
    pushLength(len);
    pushByte((byte) 0x04);
  }

  private static void pushSequenceHeader(short len) {
    pushLength(len);
    pushByte((byte) 0x30);
  }

  private static void pushBitStringHeader(byte unusedBits, short len) {
    pushByte(unusedBits);
    pushLength((short) (len + 1)); // 1 extra byte for unused bits byte
    pushByte((byte) 0x03);
  }

  private static void pushLength(short len) {
    if (len < 128) {
      pushByte((byte) len);
    } else if (len < 256) {
      pushByte((byte) len);
      pushByte((byte) 0x81);
    } else {
      pushShort(len);
      pushByte((byte) 0x82);
    }
  }

  private static void pushShort(short val) {
    decrementStackPtr((short) 2);
    Util.setShort(stack, dataIndexes[STACK_PTR], val);
  }

  private static void pushByte(byte val) {
    decrementStackPtr((short) 1);
    stack[dataIndexes[STACK_PTR]] = val;
  }

  private static void pushBytes(byte[] buf, short start, short len) {
    decrementStackPtr(len);
    if (buf != null) {
      Util.arrayCopyNonAtomic(buf, start, stack, dataIndexes[STACK_PTR], len);
    }
  }

  private static void decrementStackPtr(short cnt) {
    dataIndexes[STACK_PTR] = (short) (dataIndexes[STACK_PTR] - cnt);
    if (indexes[BUF_START] > dataIndexes[STACK_PTR]) {
      KMException.throwIt(KMError.UNKNOWN_ERROR);
    }
  }

  @Override
  public KMAttestationCert buffer(byte[] buf, short start, short maxLen) {
    stack = buf;
    indexes[BUF_START] = start;
    indexes[BUF_LENGTH] = maxLen;
    dataIndexes[STACK_PTR] = (short) (indexes[BUF_START] + indexes[BUF_LENGTH]);
    return this;
  }

  @Override
  public short getCertStart() {
    return indexes[CERT_START];
  }

  @Override
  public short getCertLength() {
    return indexes[CERT_LENGTH];
  }


  public void build(KMAttestationKey factoryAttestKey, short attSecret, short attMod,
      boolean rsaSign, boolean fakeCert) {
    dataIndexes[STACK_PTR] = (short) (indexes[BUF_START] + indexes[BUF_LENGTH]);
    short last = dataIndexes[STACK_PTR];
    short sigLen = 0;
    if (fakeCert) {
      rsaSign = true;
      pushByte((byte) 0);
      sigLen = 1;
    }
    // Push placeholder signature Bit string header
    // This will potentially change at the end
    else if (rsaSign) {
      decrementStackPtr(RSA_SIG_LEN);
    } else {
      decrementStackPtr(ECDSA_MAX_SIG_LEN);
    }
    short signatureOffset = dataIndexes[STACK_PTR];
    pushBitStringHeader((byte) 0, (short) (last - dataIndexes[STACK_PTR]));
    if (rsaSign) {
      pushAlgorithmId(X509RsaSignAlgIdentifier);
    } else {
      pushAlgorithmId(X509EcdsaSignAlgIdentifier);
    }
    indexes[TBS_LENGTH] = dataIndexes[STACK_PTR];
 
    pushTbsCert((stateIndexes[RSA_CERT] == 0 ? false: true), rsaSign);
    indexes[TBS_START] = dataIndexes[STACK_PTR];
    indexes[TBS_LENGTH] = (short) (indexes[TBS_LENGTH] - indexes[TBS_START]);
    if (attSecret != KMType.INVALID_VALUE || factoryAttestKey != null) {
      // Sign with the attestation key
      // The pubKey is the modulus.
      if (rsaSign) {
        sigLen = seProvider
            .rsaSign256Pkcs1(
                KMByteBlob.getBuffer(attSecret),
                KMByteBlob.getStartOff(attSecret),
                KMByteBlob.length(attSecret),
                KMByteBlob.getBuffer(attMod),
                KMByteBlob.getStartOff(attMod),
                KMByteBlob.length(attMod),
                stack,
                indexes[TBS_START],
                indexes[TBS_LENGTH],
                stack,
                signatureOffset);
        if (sigLen > RSA_SIG_LEN) {
          KMException.throwIt(KMError.UNKNOWN_ERROR);
        }
      } else if (factoryAttestKey != null) {
        sigLen = seProvider
            .ecSign256(
                factoryAttestKey,
                stack,
                indexes[TBS_START],
                indexes[TBS_LENGTH],
                stack,
                signatureOffset);
        if (sigLen > ECDSA_MAX_SIG_LEN) {
          KMException.throwIt(KMError.UNKNOWN_ERROR);
        }
      } else {
        sigLen = seProvider
            .ecSign256(
                KMByteBlob.getBuffer(attSecret),
                KMByteBlob.getStartOff(attSecret),
                KMByteBlob.length(attSecret),
                stack,
                indexes[TBS_START],
                indexes[TBS_LENGTH],
                stack,
                signatureOffset);
        if (sigLen > ECDSA_MAX_SIG_LEN) {
          KMException.throwIt(KMError.UNKNOWN_ERROR);
        }
      }
      // Adjust signature length
      dataIndexes[STACK_PTR] = signatureOffset;
      pushBitStringHeader((byte) 0, sigLen);
    } else if (!fakeCert) { // no attestation key provisioned in the factory
      KMException.throwIt(KMError.ATTESTATION_KEYS_NOT_PROVISIONED);
    }
    last = (short) (signatureOffset + sigLen);
    // Add certificate sequence header
    dataIndexes[STACK_PTR] = indexes[TBS_START];
    pushSequenceHeader((short) (last - dataIndexes[STACK_PTR]));
    indexes[CERT_START] = dataIndexes[STACK_PTR];
    indexes[CERT_LENGTH] = (short) (last - indexes[CERT_START]);
  }


  @Override
  public void build() {
    if (stateIndexes[CERT_MODE] == KMType.FAKE_CERT) {
      build(null, KMType.INVALID_VALUE, KMType.INVALID_VALUE, true, true);
    } else if (stateIndexes[CERT_MODE] == KMType.FACTORY_PROVISIONED_ATTEST_CERT) {
      build(factoryAttestKey, KMType.INVALID_VALUE, KMType.INVALID_VALUE, false, false);
    } else {
      build(null, dataIndexes[CERT_ATT_KEY_SECRET], dataIndexes[CERT_ATT_KEY_RSA_PUB_MOD], (stateIndexes[CERT_RSA_SIGN] == 0 ? false: true), false);
    }
  }

  @Override
  public KMAttestationCert makeUniqueId(byte[] scratchPad, short scratchPadOff,
      byte[] creationTime, short timeOffset, short creationTimeLen,
      byte[] attestAppId, short appIdOff, short attestAppIdLen,
      byte resetSinceIdRotation, KMMasterKey masterKey) {
    // Concatenate T||C||R
    // temporal count T
    short temp = KMUtils.countTemporalCount(creationTime, timeOffset,
        creationTimeLen, scratchPad, scratchPadOff);
    Util.setShort(scratchPad, (short) scratchPadOff, temp);
    temp = scratchPadOff;
    scratchPadOff += 2;

    // Application Id C
    Util.arrayCopyNonAtomic(attestAppId, appIdOff, scratchPad, scratchPadOff,
        attestAppIdLen);
    scratchPadOff += attestAppIdLen;

    // Reset After Rotation R
    scratchPad[scratchPadOff] = resetSinceIdRotation;
    scratchPadOff++;

    //Get the key data from the master key
    KMMasterKey aesKey = masterKey;
    short mKeyData = KMByteBlob.instance((short) (aesKey.getKeySizeBits() / 8));
    aesKey.getKey(
        KMByteBlob.getBuffer(mKeyData), /* Key */
        KMByteBlob.getStartOff(mKeyData)); /* Key start*/
    timeOffset = KMByteBlob.instance((short) 32);
    appIdOff = seProvider.hmacSign(
        KMByteBlob.getBuffer(mKeyData), /* Key */
        KMByteBlob.getStartOff(mKeyData), /* Key start*/
        KMByteBlob.length(mKeyData), /* Key length*/
        scratchPad, /* data */
        temp, /* data start */
        scratchPadOff, /* data length */
        KMByteBlob.getBuffer(timeOffset), /* signature buffer */
        KMByteBlob.getStartOff(timeOffset)); /* signature start */
    if (appIdOff != 32) {
      KMException.throwIt(KMError.UNKNOWN_ERROR);
    }
    return uniqueId(timeOffset);
  }

  @Override
  public boolean serialNumber(short number) {
    short length = KMByteBlob.length(number);
    if (length > SERIAL_NUM_MAX_LEN) {
      return false;
    }
    byte msb = KMByteBlob.get(number, (short) 0);
    if (msb < 0 && length > (SERIAL_NUM_MAX_LEN - 1)) {
      return false;
    }
    dataIndexes[SERIAL_NUMBER] = number;
    return true;
  }

  @Override
  public boolean subjectName(short sub) {
    /*
    short length = KMKeymasterApplet.cast(sub).length();
    if(length > SUBJECT_NAME_MAX_LEN){
      return false;
    }
    Util.arrayCopyNonAtomic(KMKeymasterApplet.cast(sub).getBuffer(), KMKeymasterApplet.cast(sub).getStartOff(),
        subjectName,(short)0,length);
    subjectLen = length;
     */
    if (sub == KMType.INVALID_VALUE || KMByteBlob.length(sub) == 0) {
      return false;
    }
    dataIndexes[SUBJECT_NAME] = sub;
    return true;
  }

  @Override
  public KMAttestationCert ecAttestKey(short attestKey, byte mode) {
    stateIndexes[CERT_MODE] = mode;
    dataIndexes[CERT_ATT_KEY_SECRET] = attestKey;
    dataIndexes[CERT_ATT_KEY_RSA_PUB_MOD] = KMType.INVALID_VALUE;
    stateIndexes[CERT_RSA_SIGN] = 0;
    return this;
  }

  @Override
  public KMAttestationCert rsaAttestKey(short attestPrivExp, short attestMod, byte mode) {
    stateIndexes[CERT_MODE] = mode;
    dataIndexes[CERT_ATT_KEY_SECRET] = attestPrivExp;
    dataIndexes[CERT_ATT_KEY_RSA_PUB_MOD] = attestMod;
    stateIndexes[CERT_RSA_SIGN] = 1;
    return this;
  }

  public KMAttestationCert factoryAttestKey(KMAttestationKey key, byte mode) {
    stateIndexes[CERT_MODE] = mode;
    factoryAttestKey = key;
    return this;
  }
}
