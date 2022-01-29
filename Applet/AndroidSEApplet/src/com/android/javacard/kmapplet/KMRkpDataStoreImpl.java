package com.android.javacard.kmapplet;

import org.globalplatform.upgrade.Element;

import com.android.javacard.kmdevice.KMDeviceUniqueKey;
import com.android.javacard.kmdevice.KMError;
import com.android.javacard.kmdevice.KMException;
import com.android.javacard.kmdevice.KMRkpDataStore;
import com.android.javacard.kmdevice.KMPreSharedKey;
import com.android.javacard.kmdevice.KMSEProvider;
import com.android.javacard.kmdevice.KMDataStoreConstants;
import com.android.javacard.kmdevice.KMType;

import javacard.framework.JCSystem;
import javacard.framework.Util;

public class KMRkpDataStoreImpl implements KMRkpDataStore {
  
  // Magic number version
  private static final byte KM_MAGIC_NUMBER = (byte) 0x83;
  // MSB byte is for Major version and LSB byte is for Minor version.
  private static final short CURRENT_PACKAGE_VERSION = 0x0009; // 0.9

  private byte[] bcc;
  private byte[] additionalCertData;
  private KMDeviceUniqueKey deviceUniqueKey;
  private KMDeviceUniqueKey testDeviceUniqueKey;
  private KMSEProvider seProvider;
  

  public KMRkpDataStoreImpl(KMSEProvider provider) {
    seProvider = provider;
    initializeAdditionalBuffers(provider.isUpgrading());
  }

  private void initializeAdditionalBuffers(boolean isUpgrading) {
    if (!isUpgrading) {
      // use certificateData as Additional certficate chain.
      if (additionalCertData == null) {
        // First 2 bytes is reserved for length for all the 3 buffers.
        additionalCertData = new byte[(short) (2 + KMConfigurations.ADDITIONAL_CERT_CHAIN_MAX_SIZE)];
      }

      if (bcc == null) {
        bcc = new byte[(short) (2 + KMConfigurations.BOOT_CERT_CHAIN_MAX_SIZE)];
      }
    }
  }

  @Override
  public void storeData(byte storeDataIndex, byte[] data, short offset, short length) {
    switch (storeDataIndex) {
    case KMDataStoreConstants.ADDITIONAL_CERT_CHAIN:
      persistAdditionalCertChain(data, offset, length);
      break;
    case KMDataStoreConstants.BOOT_CERT_CHAIN:
      persistBootCertificateChain(data, offset, length);
      break;
    }
  }

  private void persistAdditionalCertChain(byte[] buf, short offset, short len) {
    // Input buffer contains encoded additional certificate chain as shown below.
    // AdditionalDKSignatures = {
    // + SignerName => DKCertChain
    // }
    // SignerName = tstr
    // DKCertChain = [
    // 2* Certificate // Root -> Leaf. Root is the vendo r
    // // self-signed cert, leaf contains DK_pu b
    // ]
    // Certificate = COSE_Sign1 of a public key
    if ((short) (len + 2) > KMConfigurations.ADDITIONAL_CERT_CHAIN_MAX_SIZE) {
      KMException.throwIt(KMError.INVALID_INPUT_LENGTH);
    }
    JCSystem.beginTransaction();
    Util.setShort(additionalCertData, (short) 0, (short) len);
    JCSystem.commitTransaction();
    Util.arrayCopy(buf, offset, additionalCertData, (short) 2, len);
  }

  private void persistBootCertificateChain(byte[] buf, short offset, short len) {
    if ((short) (len + 2) > KMConfigurations.BOOT_CERT_CHAIN_MAX_SIZE) {
      KMException.throwIt(KMError.INVALID_INPUT_LENGTH);
    }
    JCSystem.beginTransaction();
    Util.setShort(bcc, (short) 0, (short) len);
    JCSystem.commitTransaction();
    Util.arrayCopy(buf, offset, bcc, (short) 2, len);
  }


  @Override
  public void createDeviceUniqueKey(boolean testMode, byte[] pubKey, short pubKeyOff, short pubKeyLen, byte[] privKey,
      short privKeyOff, short privKeyLen) {
    if (testMode) {
      createTestDeviceUniqueKey(pubKey, pubKeyOff, pubKeyLen, privKey, privKeyOff, privKeyLen);
    } else {
      createDeviceUniqueKey(pubKey, pubKeyOff, pubKeyLen, privKey, privKeyOff, privKeyLen);
    }
  }

  @Override
  public KMDeviceUniqueKey getDeviceUniqueKey(boolean testMode) {
    if (testMode) {
      return testDeviceUniqueKey;
    } else {
      return deviceUniqueKey;
    }
  }

  private void createTestDeviceUniqueKey(byte[] pubKey, short pubKeyOff, short pubKeyLen, byte[] privKey,
      short privKeyOff, short privKeyLen) {
    if (testDeviceUniqueKey == null) {
      testDeviceUniqueKey = seProvider.createDeviceUniqueKey(testDeviceUniqueKey, pubKey, pubKeyOff, pubKeyLen, privKey,
          privKeyOff, privKeyLen);
    } else {
      seProvider.createDeviceUniqueKey(testDeviceUniqueKey, pubKey, pubKeyOff, pubKeyLen, privKey, privKeyOff,
          privKeyLen);
    }
  }

  private void createDeviceUniqueKey(byte[] pubKey, short pubKeyOff, short pubKeyLen, byte[] privKey, short privKeyOff,
      short privKeyLen) {
    if (deviceUniqueKey == null) {
      deviceUniqueKey = seProvider.createDeviceUniqueKey(deviceUniqueKey, pubKey, pubKeyOff, pubKeyLen, privKey,
          privKeyOff, privKeyLen);
    } else {
    seProvider.createDeviceUniqueKey(deviceUniqueKey, pubKey, pubKeyOff, pubKeyLen, privKey,
        privKeyOff, privKeyLen);
    }
  }

  @Override
  public void onSave(Element ele) {
    
  }

  @Override
  public void onRestore(Element ele, short oldVersion, short currentVersion) {
    
  }

  @Override
  public short getBackupPrimitiveByteCount() {
    return (deviceUniqueKey.getBackupPrimitiveByteCount());
  }

  @Override
  public short getBackupObjectCount() {
    // AdditionalCertificateChain - 1
    // BCC - 1
    return (short) (2 + deviceUniqueKey.getBackupObjectCount());
  }

  @Override
  public byte[] getData(byte dataStoreId) {
    switch(dataStoreId) {
    case KMDataStoreConstants.ADDITIONAL_CERT_CHAIN:
      return additionalCertData;
    case KMDataStoreConstants.BOOT_CERT_CHAIN:
      return bcc;
    default:
      KMException.throwIt(KMError.INVALID_ARGUMENT);
    }
    return null;
  }

}
