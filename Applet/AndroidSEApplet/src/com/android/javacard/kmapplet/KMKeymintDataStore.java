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
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.android.javacard.kmapplet;

import org.globalplatform.upgrade.Element;

import com.android.javacard.kmdevice.KMAttestationKey;
import com.android.javacard.kmdevice.KMComputedHmacKey;
import com.android.javacard.kmdevice.KMDeviceUniqueKey;
import com.android.javacard.kmdevice.KMError;
import com.android.javacard.kmdevice.KMException;
import com.android.javacard.kmdevice.KMDataStore;
import com.android.javacard.kmdevice.KMMasterKey;
import com.android.javacard.kmdevice.KMPreSharedKey;
import com.android.javacard.kmdevice.KMSEProvider;
import com.android.javacard.kmdevice.KMDataStoreConstants;
import com.android.javacard.kmdevice.KMType;
import com.android.javacard.kmdevice.KMUpgradable;
import com.android.javacard.seprovider.KMConfigurations;

import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Util;

/**
 * KMRepository class manages persistent and volatile memory usage by the
 * applet. Note the repository is only used by applet and it is not intended to
 * be used by seProvider.
 */
public class KMKeymintDataStore implements KMDataStore {
  
 // Magic number version
 private static final byte KM_MAGIC_NUMBER = (byte) 0x82;
 // MSB byte is for Major version and LSB byte is for Minor version.
 private static final short CURRENT_PACKAGE_VERSION = 0x0009; // 0.9

  // Data table configuration
  private static final short DATA_INDEX_SIZE = 19;
  private static final short DATA_INDEX_ENTRY_SIZE = 4;
  private static final short DATA_MEM_SIZE = 300;
  private static final short DATA_INDEX_ENTRY_LENGTH = 0;
  private static final short DATA_INDEX_ENTRY_OFFSET = 2;

  // Data table offsets
  private static final byte HMAC_NONCE = 0;
  private static final byte OS_VERSION = 1;
  private static final byte OS_PATCH_LEVEL = 2;
  private static final byte VENDOR_PATCH_LEVEL = 3;
  private static final byte DEVICE_LOCKED_TIME = 4;
  private static final byte DEVICE_LOCKED = 5;
  private static final byte DEVICE_LOCKED_PASSWORD_ONLY = 6;
  // Total 8 auth tags, so the next offset is AUTH_TAG_1 + 8
  private static final byte AUTH_TAG_1 = 7;
  private static final byte AUTH_TAG_2 = 8;
  private static final byte AUTH_TAG_3 = 9;
  private static final byte AUTH_TAG_4 = 10;
  private static final byte AUTH_TAG_5 = 11;
  private static final byte AUTH_TAG_6 = 12;
  private static final byte AUTH_TAG_7 = 13;
  private static final byte AUTH_TAG_8 = 14;
  private static final byte BOOT_ENDED_STATUS = 15;
  private static final byte EARLY_BOOT_ENDED_STATUS = 16;
  private static final byte PROVISIONED_LOCKED = 17;
  private static final byte PROVISIONED_STATUS = 18;

  // Data Item sizes
  private static final short MASTER_KEY_SIZE = 16;
  private static final short SHARED_SECRET_KEY_SIZE = 32;
  private static final short HMAC_SEED_NONCE_SIZE = 32;
  private static final short COMPUTED_HMAC_KEY_SIZE = 32;
  private static final short SB_PROP_SIZE = 4;
  private static final short DEVICE_LOCK_TS_SIZE = 8;
  private static final short BOOT_DEVICE_LOCK_FLAG_SIZE = 1;
  private static final short DEVICE_LOCKED_FLAG_SIZE = 1;
  private static final short DEVICE_LOCKED_PASSWORD_ONLY_SIZE = 1;
  private static final short BOOT_STATE_SIZE = 1;
  private static final byte BOOT_KEY_MAX_SIZE = 32;
  private static final byte BOOT_HASH_MAX_SIZE = 32;
  private static final short MAX_BLOB_STORAGE = 8;
  private static final short AUTH_TAG_LENGTH = 16;
  private static final short AUTH_TAG_COUNTER_SIZE = 4;
  private static final short AUTH_TAG_ENTRY_SIZE = (AUTH_TAG_LENGTH + AUTH_TAG_COUNTER_SIZE + 1);
  private static final short BOOT_ENDED_FLAG_SIZE = 1;
  private static final short EARLY_BOOT_ENDED_FLAG_SIZE = 1;
  private static final short PROVISIONED_LOCKED_SIZE = 1;
  private static final short PROVISIONED_STATUS_SIZE = 1;

  // certificate data constants.
  private static final short CERT_CHAIN_OFFSET = 0;
  private static final short CERT_ISSUER_OFFSET = KMConfigurations.CERT_CHAIN_MAX_SIZE;
  private static final short CERT_EXPIRY_OFFSET = (short) (CERT_ISSUER_OFFSET + KMConfigurations.CERT_ISSUER_MAX_SIZE);

  // data table
  private byte[] dataTable;
  private short dataIndex;

  // certificate data
  protected byte[] certificateData;

  // Keys
  private KMComputedHmacKey computedHmacKey;
  private KMMasterKey masterKey;
  private KMPreSharedKey preSharedKey;
  private KMAttestationKey attestationKey;
  protected KMSEProvider seProvider;
  // Package version.
  protected short packageVersion;
  
  // Data - originally was in repository
  private byte[] attIdBrand;
  private byte[] attIdDevice;
  private byte[] attIdProduct;
  private byte[] attIdSerial;
  private byte[] attIdImei;
  private byte[] attIdMeId;
  private byte[] attIdManufacturer;
  private byte[] attIdModel;


  // Boot parameters
  private byte[] verifiedHash;
  private byte[] bootKey;
  private byte[] bootPatchLevel;
  private boolean deviceBootLocked;
  private short bootState;

  public KMKeymintDataStore(KMSEProvider provider, boolean factoryAttestSupport) {
    seProvider = provider;
    boolean isUpgrading = provider.isUpgrading();
    initDataTable(isUpgrading);
    initializeCertificateDataBuffer(isUpgrading, factoryAttestSupport);
  }

  private short mapTodataTableId(byte kmStoreId) {
    switch (kmStoreId) {
    case KMDataStoreConstants.HMAC_NONCE:
      return HMAC_NONCE;
    case KMDataStoreConstants.OS_VERSION:
      return OS_VERSION;
    case KMDataStoreConstants.OS_PATCH_LEVEL:
      return OS_PATCH_LEVEL;
    case KMDataStoreConstants.VENDOR_PATCH_LEVEL:
      return VENDOR_PATCH_LEVEL;
    case KMDataStoreConstants.DEVICE_LOCKED_TIME:
      return DEVICE_LOCKED_TIME;
    case KMDataStoreConstants.DEVICE_LOCKED:
      return DEVICE_LOCKED;
    case KMDataStoreConstants.DEVICE_LOCKED_PASSWORD_ONLY:
      return DEVICE_LOCKED_PASSWORD_ONLY;
    case KMDataStoreConstants.BOOT_ENDED_STATUS:
      return BOOT_ENDED_STATUS;
    case KMDataStoreConstants.EARLY_BOOT_ENDED_STATUS:
      return EARLY_BOOT_ENDED_STATUS;
    case KMDataStoreConstants.PROVISIONED_LOCKED:
      return PROVISIONED_LOCKED;
    case KMDataStoreConstants.PROVISIONED_STATUS:
      return PROVISIONED_STATUS;
    case KMDataStoreConstants.AUTH_TAG_1:
      return AUTH_TAG_1;
    case KMDataStoreConstants.AUTH_TAG_2:
      return AUTH_TAG_2;
    case KMDataStoreConstants.AUTH_TAG_3:
      return AUTH_TAG_3;
    case KMDataStoreConstants.AUTH_TAG_4:
      return AUTH_TAG_4;
    case KMDataStoreConstants.AUTH_TAG_5:
      return AUTH_TAG_5;
    case KMDataStoreConstants.AUTH_TAG_6:
      return AUTH_TAG_6;
    case KMDataStoreConstants.AUTH_TAG_7:
      return AUTH_TAG_7;
    case KMDataStoreConstants.AUTH_TAG_8:
      return AUTH_TAG_8;
    default:
      break;
    }
    return KMType.INVALID_VALUE;
  }

  @Override
  public void storeData(byte storeDataIndex, byte[] data, short offset, short length) {
    short maxLen = 0;
    switch (storeDataIndex) {
    case KMDataStoreConstants.ATT_ID_BRAND:
    case KMDataStoreConstants.ATT_ID_DEVICE:
    case KMDataStoreConstants.ATT_ID_PRODUCT:
    case KMDataStoreConstants.ATT_ID_SERIAL:
    case KMDataStoreConstants.ATT_ID_IMEI:
    case KMDataStoreConstants.ATT_ID_MEID:
    case KMDataStoreConstants.ATT_ID_MANUFACTURER:
    case KMDataStoreConstants.ATT_ID_MODEL:
      setAttestationId(storeDataIndex, data, offset, length);
      return;
    case KMDataStoreConstants.COMPUTED_HMAC_KEY:
      persistComputedHmacKey(data, offset, length);
      return;
    case KMDataStoreConstants.MASTER_KEY:
      persistMasterKey(data, offset, length);
      return;
    case KMDataStoreConstants.PRE_SHARED_KEY:
      persistPresharedKey(data, offset, length);
      return;
    case KMDataStoreConstants.ATTESTATION_KEY:
      persistAttestationKey(data, offset, length);
      return;
    case KMDataStoreConstants.HMAC_NONCE:
      maxLen = HMAC_SEED_NONCE_SIZE;
      break;
    case KMDataStoreConstants.OS_VERSION:
    case KMDataStoreConstants.OS_PATCH_LEVEL:
    case KMDataStoreConstants.VENDOR_PATCH_LEVEL:
      maxLen = SB_PROP_SIZE;
      break;
    case KMDataStoreConstants.DEVICE_LOCKED_TIME:
      maxLen = DEVICE_LOCK_TS_SIZE;
      break;
    case KMDataStoreConstants.DEVICE_LOCKED:
      maxLen = DEVICE_LOCKED_FLAG_SIZE;
      break;
    case KMDataStoreConstants.DEVICE_LOCKED_PASSWORD_ONLY:
      maxLen = DEVICE_LOCKED_PASSWORD_ONLY_SIZE;
      break;
    case KMDataStoreConstants.BOOT_ENDED_STATUS:
      maxLen = BOOT_ENDED_FLAG_SIZE;
      break;
    case KMDataStoreConstants.EARLY_BOOT_ENDED_STATUS:
      maxLen = EARLY_BOOT_ENDED_FLAG_SIZE;
      break;
    case KMDataStoreConstants.PROVISIONED_LOCKED:
      maxLen = PROVISIONED_LOCKED_SIZE;
      break;
    case KMDataStoreConstants.PROVISIONED_STATUS:
      maxLen = PROVISIONED_STATUS_SIZE;
      break;
    default:
      KMException.throwIt(KMError.INVALID_ARGUMENT);
      return;
    }
    short dataTableId = mapTodataTableId(storeDataIndex);
    if (dataTableId == KMType.INVALID_VALUE) {
      KMException.throwIt(KMError.INVALID_ARGUMENT);
    }
    if (length != maxLen) {
      KMException.throwIt(KMError.INVALID_INPUT_LENGTH);
    }
    writeDataEntry(dataTableId, data, offset, length);
  }

  @Override
  public short getData(byte storeDataIndex, byte[] data, short offset) {
    switch (storeDataIndex) {
    case KMDataStoreConstants.ATT_ID_BRAND:
    case KMDataStoreConstants.ATT_ID_DEVICE:
    case KMDataStoreConstants.ATT_ID_PRODUCT:
    case KMDataStoreConstants.ATT_ID_SERIAL:
    case KMDataStoreConstants.ATT_ID_IMEI:
    case KMDataStoreConstants.ATT_ID_MEID:
    case KMDataStoreConstants.ATT_ID_MANUFACTURER:
    case KMDataStoreConstants.ATT_ID_MODEL:
      return getAttestationId(storeDataIndex, data, offset);
    default:
      break;
    }
    short dataTableId = mapTodataTableId(storeDataIndex);
    if (dataTableId == KMType.INVALID_VALUE) {
      KMException.throwIt(KMError.INVALID_ARGUMENT);
    }
    return readDataEntry(dataTableId, data, offset);
  }

  @Override
  public void clearData(byte storeDataIndex) {
    switch(storeDataIndex) {
    case KMDataStoreConstants.ATT_ID_BRAND:
      attIdBrand = null;
      return;
    case KMDataStoreConstants.ATT_ID_DEVICE:
      attIdDevice = null;
      return;
    case KMDataStoreConstants.ATT_ID_PRODUCT:
      attIdProduct = null;
      return;
    case KMDataStoreConstants.ATT_ID_SERIAL:
      attIdSerial = null;
      return;
    case KMDataStoreConstants.ATT_ID_IMEI:
      attIdImei = null;
      return;
    case KMDataStoreConstants.ATT_ID_MEID:
      attIdMeId = null;
      return;
    case KMDataStoreConstants.ATT_ID_MANUFACTURER:
      attIdManufacturer = null;
      return;
    case KMDataStoreConstants.ATT_ID_MODEL:
      attIdModel = null;
      return;
    default:
        break;
    }
    short dataTableId = mapTodataTableId(storeDataIndex);
    if (dataTableId == KMType.INVALID_VALUE) {
      KMException.throwIt(KMError.INVALID_ARGUMENT);
    }
    clearDataEntry(dataTableId);
  }

  private short dataAlloc(short length) {
    if (length < 0) {
      ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
    }
    if (((short) (dataIndex + length)) > DATA_MEM_SIZE) {
      ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    }
    JCSystem.beginTransaction();
    dataIndex += length;
    JCSystem.commitTransaction();
    return (short) (dataIndex - length);
  }

  protected void initDataTable(boolean isUpgrading) {
    if (!isUpgrading) {
      if (dataTable == null) {
        dataTable = new byte[DATA_MEM_SIZE];
        dataIndex = (short) (DATA_INDEX_SIZE * DATA_INDEX_ENTRY_SIZE);
      }
    }
  }

  private void initializeCertificateDataBuffer(boolean isUpgrading, boolean isFactoryAttestSupported) {
    if (!isUpgrading) {
      if (isFactoryAttestSupported && certificateData == null) {
        // First 2 bytes is reserved for length for all the 3 buffers.
        short totalLen = (short) (6 + KMConfigurations.CERT_CHAIN_MAX_SIZE + KMConfigurations.CERT_EXPIRY_MAX_SIZE
            + KMConfigurations.CERT_ISSUER_MAX_SIZE);
        certificateData = new byte[totalLen];
      }
    }
  }

  private void clearDataEntry(short id) {
    id = (short) (id * DATA_INDEX_ENTRY_SIZE);
    short dataLen = Util.getShort(dataTable, (short) (id + DATA_INDEX_ENTRY_LENGTH));
    if (dataLen != 0) {
      short dataPtr = Util.getShort(dataTable, (short) (id + DATA_INDEX_ENTRY_OFFSET));
      JCSystem.beginTransaction();
      Util.arrayFillNonAtomic(dataTable, dataPtr, dataLen, (byte) 0);
      JCSystem.commitTransaction();
    }
  }

  private short readDataEntry(short id, byte[] buf, short offset) {
    id = (short) (id * DATA_INDEX_ENTRY_SIZE);
    short len = Util.getShort(dataTable, (short) (id + DATA_INDEX_ENTRY_LENGTH));
    if (len != 0) {
      Util.arrayCopyNonAtomic(dataTable, Util.getShort(dataTable, (short) (id + DATA_INDEX_ENTRY_OFFSET)), buf, offset,
          len);
    }
    return len;
  }

  private void writeDataEntry(short id, byte[] buf, short offset, short len) {
    short dataPtr;
    id = (short) (id * DATA_INDEX_ENTRY_SIZE);
    short dataLen = Util.getShort(dataTable, (short) (id + DATA_INDEX_ENTRY_LENGTH));
    if (dataLen == 0) {
      dataPtr = dataAlloc(len);
      // Begin Transaction
      JCSystem.beginTransaction();
      Util.setShort(dataTable, (short) (id + DATA_INDEX_ENTRY_OFFSET), dataPtr);
      Util.setShort(dataTable, (short) (id + DATA_INDEX_ENTRY_LENGTH), len);
      JCSystem.commitTransaction();
      Util.arrayCopy(buf, offset, dataTable, dataPtr, len);
      // End Transaction
    } else {
      if (len != dataLen) {
        KMException.throwIt(KMError.UNKNOWN_ERROR);
      }
      dataPtr = Util.getShort(dataTable, (short) (id + DATA_INDEX_ENTRY_OFFSET));
      Util.arrayCopy(buf, offset, dataTable, dataPtr, len);
    }
  }

  private short dataLength(short id) {
    id = (short) (id * DATA_INDEX_ENTRY_SIZE);
    return Util.getShort(dataTable, (short) (id + DATA_INDEX_ENTRY_LENGTH));
  }

  public short readData(byte[] dataTable, short id, byte[] buf, short startOff, short bufLen) {
    id = (short) (id * DATA_INDEX_ENTRY_SIZE);
    short len = Util.getShort(dataTable, (short) (id + DATA_INDEX_ENTRY_LENGTH));
    if (len > bufLen) {
      return KMType.INVALID_VALUE;
    }
    if (len != 0) {
      Util.arrayCopyNonAtomic(dataTable, Util.getShort(dataTable, (short) (id + DATA_INDEX_ENTRY_OFFSET)), buf,
          startOff, len);
    }
    return len;
  }

  private boolean isAuthTagSlotAvailable(short tagId, byte[] buf, short offset) {
    readDataEntry(tagId, buf, offset);
    return (0 == buf[offset]);
  }

  private void writeAuthTagState(byte[] buf, short offset, byte state) {
    buf[offset] = state;
  }

  @Override
  public boolean storeAuthTag(byte[] data, short offset, short length, byte[] scratchPad, short scratchPadOff) {
    if (length != AUTH_TAG_LENGTH) {
      KMException.throwIt(KMError.INVALID_INPUT_LENGTH);
    }

    short index = 0;
    while (index < MAX_BLOB_STORAGE) {
      if ((dataLength((short) (index + AUTH_TAG_1)) == 0)
          || isAuthTagSlotAvailable((short) (index + AUTH_TAG_1), scratchPad, scratchPadOff)) {

        // prepare auth tag buffer
        writeAuthTagState(scratchPad, scratchPadOff, (byte) 1);
        Util.arrayCopyNonAtomic(data, offset, scratchPad, (short) (scratchPadOff + 1), AUTH_TAG_LENGTH);
        Util.setShort(scratchPad, (short) (scratchPadOff + AUTH_TAG_LENGTH + 1 + 2), (short) 1);
        // write the auth tag buffer to persistent memroy.
        writeDataEntry((short) (index + AUTH_TAG_1), scratchPad, scratchPadOff, AUTH_TAG_ENTRY_SIZE);
        return true;
      }
      index++;
    }
    return false;
  }

  @Override
  public void clearAllAuthTags() {
    short index = 0;
    while (index < MAX_BLOB_STORAGE) {
      clearDataEntry((short) (index + AUTH_TAG_1));
      index++;
    }
  }

  @Override
  public boolean isAuthTagPersisted(byte[] data, short offset, short length, byte[] scratchPad, short scratchPadOff) {
    return (KMType.INVALID_VALUE != findTag(data, offset, length, scratchPad, scratchPadOff));
  }

  private short findTag(byte[] data, short offset, short length, byte[] scratchPad, short scratchPadOff) {
    if (length != AUTH_TAG_LENGTH) {
      KMException.throwIt(KMError.INVALID_INPUT_LENGTH);
    }
    short index = 0;
    short found;
    // short offset = alloc(AUTH_TAG_ENTRY_SIZE);
    while (index < MAX_BLOB_STORAGE) {
      if (dataLength((short) (index + AUTH_TAG_1)) != 0) {
        readDataEntry((short) (index + AUTH_TAG_1), scratchPad, scratchPadOff);
        found = Util.arrayCompare(scratchPad, (short) (scratchPadOff + 1), data, offset, AUTH_TAG_LENGTH);
        if (found == 0) {
          return (short) (index + AUTH_TAG_1);
        }
      }
      index++;
    }
    return KMType.INVALID_VALUE;
  }

  @Override
  public short getRateLimitedKeyCount(byte[] data, short offset, short length, byte[] scratchPad, short scratchPadOff) {
    short tag = findTag(data, offset, length, scratchPad, scratchPadOff);
    short blob;
    if (tag != KMType.INVALID_VALUE) {
      readDataEntry(tag, scratchPad, scratchPadOff);
      Util.arrayCopyNonAtomic(scratchPad, (short) (scratchPadOff + AUTH_TAG_LENGTH + 1), scratchPad, scratchPadOff,
          AUTH_TAG_COUNTER_SIZE);
      return AUTH_TAG_COUNTER_SIZE;
    }
    return (short) 0;
  }

  @Override
  public void setRateLimitedKeyCount(byte[] data, short dataOffset, short dataLen, byte[] counter, short counterOff,
      short counterLen, byte[] scratchPad, short scratchPadOff) {
    short tag = findTag(data, dataOffset, dataLen, scratchPad, scratchPadOff);
    if (tag != KMType.INVALID_VALUE) {
      short len = readDataEntry(tag, scratchPad, scratchPadOff);
      Util.arrayCopyNonAtomic(counter, counterOff, scratchPad, (short) (scratchPadOff + AUTH_TAG_LENGTH + 1),
          counterLen);
      writeDataEntry(tag, scratchPad, scratchPadOff, len);
    }
  }

  private short getcertificateDataBufferOffset(byte dataType) {
    switch (dataType) {
    case KMDataStoreConstants.CERTIFICATE_CHAIN:
      return CERT_CHAIN_OFFSET;
    case KMDataStoreConstants.CERTIFICATE_ISSUER:
      return CERT_ISSUER_OFFSET;
    case KMDataStoreConstants.CERTIFICATE_EXPIRY:
      return CERT_EXPIRY_OFFSET;
    default:
      KMException.throwIt(KMError.INVALID_ARGUMENT);
    }
    return 0;
  }

  private void persistcertificateData(byte[] buf, short off, short len, short maxSize, short copyToOff) {
    if (len > maxSize) {
      KMException.throwIt(KMError.INVALID_INPUT_LENGTH);
    }
    JCSystem.beginTransaction();
    Util.arrayCopyNonAtomic(buf, off, certificateData, Util.setShort(certificateData, copyToOff, len), len);
    JCSystem.commitTransaction();
  }

  private void persistCertificateChain(byte[] certChain, short certChainOff, short certChainLen) {
    persistcertificateData(certChain, certChainOff, certChainLen, KMConfigurations.CERT_CHAIN_MAX_SIZE,
        CERT_CHAIN_OFFSET);
  }

  private void persistCertficateIssuer(byte[] certIssuer, short certIssuerOff, short certIssuerLen) {
    persistcertificateData(certIssuer, certIssuerOff, certIssuerLen, KMConfigurations.CERT_ISSUER_MAX_SIZE,
        CERT_ISSUER_OFFSET);
  }

  private void persistCertificateExpiryTime(byte[] certExpiry, short certExpiryOff, short certExpiryLen) {
    persistcertificateData(certExpiry, certExpiryOff, certExpiryLen, KMConfigurations.CERT_EXPIRY_MAX_SIZE,
        CERT_EXPIRY_OFFSET);
  }

  @Override
  public void persistCertificateData(byte[] buffer, short certChainOff, short certChainLen, short certIssuerOff,
      short certIssuerLen, short certExpiryOff, short certExpiryLen) {
    // All the buffers uses first two bytes for length. The certificate chain
    // is stored as shown below.
    // _____________________________________________________
    // | 2 Bytes | 1 Byte | 3 Bytes | Cert1 | Cert2 |...
    // |_________|________|_________|_______|________|_______
    // First two bytes holds the length of the total buffer.
    // CBOR format:
    // Next single byte holds the byte string header.
    // Next 3 bytes holds the total length of the certificate chain.
    // clear buffer.
    JCSystem.beginTransaction();
    Util.arrayFillNonAtomic(certificateData, (short) 0, (short) certificateData.length, (byte) 0);
    JCSystem.commitTransaction();
    // Persist data.
    persistCertificateChain(buffer, certChainOff, certChainLen);
    persistCertficateIssuer(buffer, certIssuerOff, certIssuerLen);
    persistCertificateExpiryTime(buffer, certExpiryOff, certExpiryLen);
  }

  @Override
  public short readCertificateData(byte dataType, byte[] buf, short offset) {
    short provisionBufOffset = getcertificateDataBufferOffset(dataType);
    short len = Util.getShort(certificateData, provisionBufOffset);
    Util.arrayCopyNonAtomic(certificateData, (short) (2 + provisionBufOffset), buf, offset, len);
    return len;
  }

  @Override
  public short getCertificateDataLength(byte dataType) {
    short provisionBufOffset = getcertificateDataBufferOffset(dataType);
    return Util.getShort(certificateData, provisionBufOffset);
  }

  private void persistComputedHmacKey(byte[] keydata, short offset, short length) {
    if (length != COMPUTED_HMAC_KEY_SIZE) {
      KMException.throwIt(KMError.INVALID_INPUT_LENGTH);
    }
    if (computedHmacKey == null) {
      computedHmacKey = seProvider.createComputedHmacKey(computedHmacKey, keydata, offset, length);
    } else {
      seProvider.createComputedHmacKey(computedHmacKey, keydata, offset, length);
    }
  }

  private void persistMasterKey(byte[] keydata, short offset, short length) {
    if (length != MASTER_KEY_SIZE) {
      KMException.throwIt(KMError.INVALID_INPUT_LENGTH);
    }
    if (masterKey == null) {
      masterKey = seProvider.createMasterKey(masterKey, keydata, offset, length);
    }
  }

  private void persistPresharedKey(byte[] keydata, short offset, short length) {
    if (length != SHARED_SECRET_KEY_SIZE) {
      KMException.throwIt(KMError.INVALID_INPUT_LENGTH);
    }
    if (preSharedKey == null) {
      preSharedKey = seProvider.createPreSharedKey(preSharedKey, keydata, offset, length);
    }
  }

  private void persistAttestationKey(byte[] privateKey, short privateKeyOff, short privateKeyLen) {
    if (attestationKey == null) {
      attestationKey = seProvider.createAttestationKey(attestationKey, privateKey, privateKeyOff, privateKeyLen);
    } else {
      seProvider.createAttestationKey(attestationKey, privateKey, privateKeyOff, privateKeyLen);
    }
  }

  @Override
  public KMComputedHmacKey getComputedHmacKey() {
    return computedHmacKey;
  }

  @Override
  public KMPreSharedKey getPresharedKey() {
    return preSharedKey;
  }

  @Override
  public KMMasterKey getMasterKey() {
    return masterKey;
  }

  @Override
  public KMAttestationKey getAttestationKey() {
    return attestationKey;
  }

  public short getAttestationId(short id, byte[] buffer, short start) {
    switch (id) {
      // Attestation Id Brand
    case KMDataStoreConstants.ATT_ID_BRAND:
        Util.arrayCopyNonAtomic(attIdBrand, (short) 0, buffer, start, (short) attIdBrand.length);
        return (short) attIdBrand.length;
      // Attestation Id Device
    case KMDataStoreConstants.ATT_ID_DEVICE:
        Util.arrayCopyNonAtomic(attIdDevice, (short) 0, buffer, start, (short) attIdDevice.length);
        return (short) attIdDevice.length;
      // Attestation Id Product
    case KMDataStoreConstants.ATT_ID_PRODUCT:
        Util.arrayCopyNonAtomic(attIdProduct, (short) 0, buffer, start,
            (short) attIdProduct.length);
        return (short) attIdProduct.length;
      // Attestation Id Serial
    case KMDataStoreConstants.ATT_ID_SERIAL:
        Util.arrayCopyNonAtomic(attIdSerial, (short) 0, buffer, start, (short) attIdSerial.length);
        return (short) attIdSerial.length;
      // Attestation Id IMEI
    case KMDataStoreConstants.ATT_ID_IMEI:
        Util.arrayCopyNonAtomic(attIdImei, (short) 0, buffer, start, (short) attIdImei.length);
        return (short) attIdImei.length;
      // Attestation Id MEID
    case KMDataStoreConstants.ATT_ID_MEID:
        Util.arrayCopyNonAtomic(attIdMeId, (short) 0, buffer, start, (short) attIdMeId.length);
        return (short) attIdMeId.length;
      // Attestation Id Manufacturer
    case KMDataStoreConstants.ATT_ID_MANUFACTURER:
        Util.arrayCopyNonAtomic(attIdManufacturer, (short) 0, buffer, start,
            (short) attIdManufacturer.length);
        return (short) attIdManufacturer.length;
      // Attestation Id Model
    case KMDataStoreConstants.ATT_ID_MODEL:
        Util.arrayCopyNonAtomic(attIdModel, (short) 0, buffer, start, (short) attIdModel.length);
        return (short) attIdModel.length;
    }
    return (short) 0;
  }

  public void setAttestationId(short id, byte[] buffer, short start, short length) {
    switch (id) {
      // Attestation Id Brand
      case KMDataStoreConstants.ATT_ID_BRAND:
        attIdBrand = new byte[length];
        Util.arrayCopy(buffer, (short) start, attIdBrand, (short) 0, length);
        break;
      // Attestation Id Device
      case KMDataStoreConstants.ATT_ID_DEVICE:
        attIdDevice = new byte[length];
        Util.arrayCopy(buffer, (short) start, attIdDevice, (short) 0, length);
        break;
      // Attestation Id Product
      case KMDataStoreConstants.ATT_ID_PRODUCT:
        attIdProduct = new byte[length];
        Util.arrayCopy(buffer, (short) start, attIdProduct, (short) 0, length);
        break;
      // Attestation Id Serial
      case KMDataStoreConstants.ATT_ID_SERIAL:
        attIdSerial = new byte[length];
        Util.arrayCopy(buffer, (short) start, attIdSerial, (short) 0, length);
        break;
      // Attestation Id IMEI
      case KMDataStoreConstants.ATT_ID_IMEI:
        attIdImei = new byte[length];
        Util.arrayCopy(buffer, (short) start, attIdImei, (short) 0, length);
        break;
      // Attestation Id MEID
      case KMDataStoreConstants.ATT_ID_MEID:
        attIdMeId = new byte[length];
        Util.arrayCopy(buffer, (short) start, attIdMeId, (short) 0, length);
        break;
      // Attestation Id Manufacturer
      case KMDataStoreConstants.ATT_ID_MANUFACTURER:
        attIdManufacturer = new byte[length];
        Util.arrayCopy(buffer, (short) start, attIdManufacturer, (short) 0, length);
        break;
      // Attestation Id Model
      case KMDataStoreConstants.ATT_ID_MODEL:
        attIdModel = new byte[length];
        Util.arrayCopy(buffer, (short) start, attIdModel, (short) 0, length);
        break;
    }
  }
  
  private boolean isUpgradeAllowed(short version) {
    boolean upgradeAllowed = false;
    short oldMajorVersion = (short) ((version >> 8) & 0x00FF);
    short oldMinorVersion = (short) (version & 0x00FF);
    short currentMajorVersion = (short) (CURRENT_PACKAGE_VERSION >> 8 & 0x00FF);
    short currentMinorVersion = (short) (CURRENT_PACKAGE_VERSION & 0x00FF);
    // Downgrade of the Applet is not allowed.
    // Upgrade is not allowed to a next version which is not immediate.
    if ((short) (currentMajorVersion - oldMajorVersion) == 1) {
      if (currentMinorVersion == 0) {
        upgradeAllowed = true;
      }
    } else if ((short) (currentMajorVersion - oldMajorVersion) == 0) {
      if ((short) (currentMinorVersion - oldMinorVersion) == 1) {
        upgradeAllowed = true;
      }
    }
    return upgradeAllowed;
  }

  @Override
  public void onSave(Element element) {
    // Prmitives
    element.write(KM_MAGIC_NUMBER);
    element.write(packageVersion);
    element.write(dataIndex);
    element.write(deviceBootLocked);
    element.write(bootState);
    // Objects
    element.write(dataTable);
    element.write(certificateData);
    element.write(attIdBrand);
    element.write(attIdDevice);
    element.write(attIdProduct);
    element.write(attIdSerial);
    element.write(attIdImei);
    element.write(attIdMeId);
    element.write(attIdManufacturer);
    element.write(attIdModel);
    element.write(verifiedHash);
    element.write(bootKey);
    element.write(bootPatchLevel);
    // Key Objects
    masterKey.onSave(element);
    computedHmacKey.onSave(element);
    preSharedKey.onSave(element);
    attestationKey.onSave(element);
    
  }

  @Override
  public void onRestore(Element element, short oldVersion, short currentVersion) {
    element.initRead();
    byte magicNumber  = element.readByte();
    if (magicNumber != KM_MAGIC_NUMBER) {
      ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    }
    short packageVersion = element.readShort();
    // Validate version.
    if (0 != packageVersion && !isUpgradeAllowed(packageVersion)) {
      ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    }
    // Read Primitives
    dataIndex = element.readShort();
    deviceBootLocked = element.readBoolean();
    bootState = element.readShort();
    // Read Objects
    dataTable = (byte[]) element.readObject();
    certificateData = (byte[]) element.readObject();
    attIdBrand = (byte[]) element.readObject();
    attIdDevice = (byte[]) element.readObject();
    attIdProduct = (byte[]) element.readObject();
    attIdSerial = (byte[]) element.readObject();
    attIdImei = (byte[]) element.readObject();
    attIdMeId = (byte[]) element.readObject();
    attIdManufacturer = (byte[]) element.readObject();
    attIdModel = (byte[]) element.readObject();
    verifiedHash = (byte[]) element.readObject();
    bootKey = (byte[]) element.readObject();
    bootPatchLevel = (byte[]) element.readObject();
    // Read Key Objects
  }

  @Override
  public short getBackupPrimitiveByteCount() {
    // Magic Number - 1 byte
    // Package Version - 2 bytes
    // dataIndex - 2 bytes
    // deviceLocked - 1 byte
    // deviceState = 2 bytes
    short count = 8;
    count += computedHmacKey.getBackupPrimitiveByteCount() +
        masterKey.getBackupPrimitiveByteCount() +
        preSharedKey.getBackupPrimitiveByteCount() +
        (attestationKey != null ? attestationKey.getBackupPrimitiveByteCount() : 0);
    return count;
  }

  @Override
  public short getBackupObjectCount() {
    // dataTable - 1
    // CertificateData - 1
    // AttestationIds - 8 
    // bootParameters - 3 
    short count = 13;
    count += computedHmacKey.getBackupObjectCount() +
        masterKey.getBackupObjectCount() +
        preSharedKey.getBackupObjectCount() +
        (attestationKey != null ? attestationKey.getBackupObjectCount() : 0);
    return count;
  }
  
  // Below functions are related boot paramters.

  public void setVerifiedBootHash(byte[] buffer, short start, short length) {
    if (verifiedHash == null) {
      verifiedHash = new byte[32];
    }
    if (length != 32) {
      KMException.throwIt(KMError.UNKNOWN_ERROR);
    }
    Util.arrayCopyNonAtomic(buffer, start, verifiedHash, (short) 0, (short) 32);
  }

  public void setBootKey(byte[] buffer, short start, short length) {
    if (bootKey == null) {
      bootKey = new byte[32];
    }
    if (length != 32) {
      KMException.throwIt(KMError.UNKNOWN_ERROR);
    }
    Util.arrayCopyNonAtomic(buffer, start, bootKey, (short) 0, (short) 32);
  }

  public void setBootState(short state) {
    bootState = state;
  }

  public void setDeviceLocked(boolean state) {
    deviceBootLocked = state;
  }

  public void setBootPatchLevel(byte[] buffer, short start, short length) {
    if (bootPatchLevel == null) {
      bootPatchLevel = new byte[4];
    }
    if (length > 4 || length < 0) {
      KMException.throwIt(KMError.UNKNOWN_ERROR);
    }
    Util.arrayCopyNonAtomic(buffer, start, bootPatchLevel, (short) 0, length);
  }

  public short getVerifiedBootHash(byte[] buffer, short start) {
    Util.arrayCopyNonAtomic(verifiedHash, (short) 0, buffer, start, (short) verifiedHash.length);
    return (short) verifiedHash.length;
  }

  public short getBootKey(byte[] buffer, short start) {
    Util.arrayCopyNonAtomic(bootKey, (short) 0, buffer, start, (short) bootKey.length);
    return (short) bootKey.length;
  }

  public short getBootState() {
    return bootState;
  }

  public boolean isDeviceBootLocked() {
    return deviceBootLocked;
  }

  public short getBootPatchLevel(byte[] buffer, short start) {
    Util.arrayCopyNonAtomic(bootPatchLevel, (short) 0, buffer, start, (short) bootPatchLevel.length);
    return (short) bootPatchLevel.length;
  }

}