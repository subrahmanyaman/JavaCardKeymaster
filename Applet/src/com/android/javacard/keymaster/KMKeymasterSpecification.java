package com.android.javacard.keymaster;

import static com.android.javacard.keymaster.KMKeymasterApplet.seProvider;

import com.android.javacard.seprovider.KMAttestationCert;
import com.android.javacard.seprovider.KMException;
import com.android.javacard.seprovider.KMSEProvider;
import javacard.framework.Util;

public class KMKeymasterSpecification implements KMSpecification {

  // getHardwareInfo constants.
  private static final byte[] JAVACARD_KEYMASTER_DEVICE = {
      0x4A, 0x61, 0x76, 0x61, 0x63, 0x61, 0x72, 0x64, 0x4B, 0x65, 0x79, 0x6D, 0x61, 0x73, 0x74,
      0x65, 0x72, 0x44, 0x65, 0x76, 0x69, 0x63, 0x65,
  };
  private static final byte[] GOOGLE = {0x47, 0x6F, 0x6F, 0x67, 0x6C, 0x65};
  private static final byte[] X509Subject = {
      0x30, 0x1F, 0x31, 0x1D, 0x30, 0x1B, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x14, 0x41, 0x6e,
      0x64,
      0x72, 0x6f, 0x69, 0x64, 0x20, 0x4B, 0x65, 0x79, 0x73, 0x74, 0x6f, 0x72, 0x65, 0x20, 0x4B,
      0x65,
      0x79
  };
  private static final byte SERIAL_NUM = (byte) 0x01;


  @Override
  public short getHardwareInfo() {
    short respPtr = KMArray.instance((short) 3);
    KMArray resp = KMArray.cast(respPtr);
    resp.add((short) 0, KMEnum.instance(KMType.HARDWARE_TYPE, KMType.STRONGBOX));
    resp.add(
        (short) 1,
        KMByteBlob.instance(
            JAVACARD_KEYMASTER_DEVICE, (short) 0, (short) JAVACARD_KEYMASTER_DEVICE.length));
    resp.add((short) 2, KMByteBlob.instance(GOOGLE, (short) 0, (short) GOOGLE.length));
    return respPtr;
  }

  @Override
  public short makeKeyCharacteristics(short keyParams, short osVersion, short osPatch,
      short vendorPatch, short bootPatch, short origin, byte[] scratchPad) {
    short strongboxParams = KMKeyParameters.makeSbEnforced(
        keyParams, (byte) origin, osVersion, osPatch, vendorPatch, bootPatch, scratchPad);
    short teeParams = KMKeyParameters.makeTeeEnforced(keyParams, scratchPad);
    short swParams = KMKeyParameters.makeKeystoreEnforced(keyParams, scratchPad);
    short hwParams = KMKeyParameters.makeHwEnforced(strongboxParams, teeParams);
    short keyCharacteristics = KMKeyCharacteristics.instance2();
    KMKeyCharacteristics.cast(keyCharacteristics).setStrongboxEnforced(hwParams);
    KMKeyCharacteristics.cast(keyCharacteristics).setKeystoreEnforced(swParams);
    return keyCharacteristics;
  }

  @Override
  public short makeKeyCharacteristicsForKeyblob(short swParams, short sbParams, short teeParams) {
    short keyChars = KMKeyCharacteristics.instance2();
    KMKeyCharacteristics.cast(keyChars).setStrongboxEnforced(sbParams);
    KMKeyCharacteristics.cast(keyChars).setKeystoreEnforced(swParams);
    return keyChars;
  }

  @Override
  public short getKeyCharacteristicsExp() {
    return KMKeyCharacteristics.exp2();
  }

  @Override
  public boolean isProvisionedAttestKeysSupported() {
    return false;
  }

  @Override
  public boolean canCreateEarlyBootKeys() {
    return false;
  }

  @Override
  public short getHardwareParamters(short sbParams, short teeParams) {
    return sbParams;
  }

  @Override
  public short concatParamsForAuthData(short keyBlobPtr, short hwParams, short swParams,
      short hiddenParams, short pubKey) {
    short arrayLen = 3;
    if (pubKey != KMType.INVALID_VALUE) {
      arrayLen = 4;
    }
    short params = KMArray.instance((short) arrayLen);
    KMArray.cast(params).add((short) 0, KMKeyParameters.cast(hwParams).getVals());
    KMArray.cast(params).add((short) 1, KMKeyParameters.cast(swParams).getVals());
    KMArray.cast(params).add((short) 2, KMKeyParameters.cast(hiddenParams).getVals());
    if (4 == arrayLen) {
      KMArray.cast(params).add((short) 3, pubKey);
    }
    return params;
  }

  @Override
  public boolean isFactoryAttestationSupported() {
    return true;
  }

  @Override
  public KMAttestationCert makeCommonCert(short swParams, short hwParams, short keyParams,
      byte[] scratchPad, KMSEProvider seProvider) {
    short alg = KMKeyParameters.findTag(KMType.ENUM_TAG, KMType.ALGORITHM, hwParams);
    boolean rsaCert = KMEnumTag.cast(alg).getValue() == KMType.RSA;
    KMAttestationCert cert = KMAttestationCertImpl.instance(rsaCert, seProvider);
    // notBefore
    short notBefore =
        KMKeyParameters.findTag(KMType.DATE_TAG, KMType.ACTIVE_DATETIME, swParams);
    if (notBefore == KMType.INVALID_VALUE) {
      notBefore =
          KMKeyParameters.findTag(KMType.DATE_TAG, KMType.CREATION_DATETIME, swParams);
      if (notBefore == KMType.INVALID_VALUE) {
        KMException.throwIt(KMError.INVALID_KEY_BLOB);
      }
    }
    notBefore = KMIntegerTag.cast(notBefore).getValue();
    cert.notBefore(notBefore, false, scratchPad);
    // notAfter
    // expiry time - byte blob
    boolean derEncoded = false;
    short notAfter =
        KMKeyParameters.findTag(KMType.DATE_TAG, KMType.USAGE_EXPIRE_DATETIME, swParams);
    if (notAfter == KMType.INVALID_VALUE) {
      notAfter = getProvisionedCertificateData(seProvider, KMSEProvider.CERTIFICATE_EXPIRY);
      derEncoded = true;
    }
    cert.notAfter(notAfter, derEncoded, scratchPad);
    // SubjectName
    cert.subjectName(KMByteBlob.instance(X509Subject, (short) 0, (short) X509Subject.length));
    // Serial
    short serialNumber = KMByteBlob.instance((short) 1);
    KMByteBlob.cast(serialNumber).add((short) 0, SERIAL_NUM);
    cert.serialNumber(serialNumber);
    // Issuer.
    cert.issuer(getProvisionedCertificateData(seProvider, KMSEProvider.CERTIFICATE_ISSUER));
    return cert;
  }

  @Override
  public short getNotAfter(short params) {
    return 0;
  }

  @Override
  public short getNotBefore(short params) {
    return 0;
  }

  @Override
  public short getIssuer() {
    return 0;
  }

  private short getProvisionedCertificateData(KMSEProvider kmseProvider, byte dataType) {
    short len = seProvider.getProvisionedDataLength(dataType);
    if (len == 0) {
      KMException.throwIt(KMError.INVALID_DATA);
    }
    short ptr = KMByteBlob.instance(len);
    seProvider.readProvisionedData(
        dataType,
        KMByteBlob.cast(ptr).getBuffer(),
        KMByteBlob.cast(ptr).getStartOff());
    return ptr;
  }

}
