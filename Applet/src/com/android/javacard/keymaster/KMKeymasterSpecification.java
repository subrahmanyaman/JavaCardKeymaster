package com.android.javacard.keymaster;

import static com.android.javacard.keymaster.KMKeymasterApplet.seProvider;

import com.android.javacard.seprovider.KMAttestationCert;
import com.android.javacard.seprovider.KMException;
import com.android.javacard.seprovider.KMSEProvider;
import javacard.framework.APDU;
import javacard.framework.ISO7816;
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
    short respPtr = KMArray.instance((short) 4);
    KMArray resp = KMArray.cast(respPtr);
    resp.add((short) 0, KMInteger.uint_16(KMError.OK));
    resp.add((short) 1, KMEnum.instance(KMType.HARDWARE_TYPE, KMType.STRONGBOX));
    resp.add(
        (short) 2,
        KMByteBlob.instance(
            JAVACARD_KEYMASTER_DEVICE, (short) 0, (short) JAVACARD_KEYMASTER_DEVICE.length));
    resp.add((short) 3, KMByteBlob.instance(GOOGLE, (short) 0, (short) GOOGLE.length));
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
    short arr = KMArray.instance((short) 0);
    short emptyParams = KMKeyParameters.instance(arr);
    short keyCharacteristics = KMKeyCharacteristics.instance();
    KMKeyCharacteristics.cast(keyCharacteristics).setStrongboxEnforced(hwParams);
    KMKeyCharacteristics.cast(keyCharacteristics).setKeystoreEnforced(swParams);
    KMKeyCharacteristics.cast(keyCharacteristics).setTeeEnforced(emptyParams);
    return keyCharacteristics;
  }

  @Override
  public short makeKeyCharacteristicsForKeyblob(short swParams, short sbParams, short teeParams) {
    short keyChars = KMKeyCharacteristics.instance();
    KMKeyCharacteristics.cast(keyChars).setStrongboxEnforced(sbParams);
    KMKeyCharacteristics.cast(keyChars).setKeystoreEnforced(swParams);
    KMKeyCharacteristics.cast(keyChars).setTeeEnforced(teeParams);
    return keyChars;
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
    boolean rsaCert = (KMEnumTag.getValue(KMType.ALGORITHM, hwParams) == KMType.RSA);
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
  public boolean isKeyAgreementSupported() {
    return false;
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

  @Override
  public short getConfirmationToken(short confToken, short keyParams) {
    short cToken =
        KMKeyParameters.findTag(KMType.BYTES_TAG, KMType.CONFIRMATION_TOKEN, keyParams);
    if (cToken == KMType.INVALID_VALUE) {
      KMException.throwIt(KMError.NO_USER_CONFIRMATION);
    }
    return KMByteTag.cast(cToken).getValue();
  }

  @Override
  public short getKMVerificationTokenExp() {
    return KMVerificationToken.exp2();
  }

  @Override
  public short getMacFromVerificationToken(short verToken) {
    return KMVerificationToken.cast(verToken).getMac((short) 0x04);
  }

  @Override
  public short getMgf1Digest(short keyParams, short hwParams) {
    return KMType.SHA1;
  }

  @Override
  public short generateAttestKeyExp() {
    // Arguments
    short keyParams = KMKeyParameters.expAny();
    short keyBlob = KMByteBlob.exp();
    short argsProto = KMArray.instance((short) 2);
    KMArray.cast(argsProto).add((short) 0, keyBlob);
    KMArray.cast(argsProto).add((short) 1, keyParams);
    return argsProto;
  }

  @Override
  public void getAttestKeyInputParameters(short arrPtr, short[] data, byte keyBlobOff,
      byte keyParametersOff,
      byte attestKeyBlobOff, byte attestKeyParamsOff, byte attestKeyIssuerOff) {
    data[keyBlobOff] = KMArray.cast(arrPtr).get((short) 0);
    data[keyParametersOff] = KMArray.cast(arrPtr).get((short) 1);
    data[attestKeyBlobOff] = KMType.INVALID_VALUE;
    data[attestKeyParamsOff] = KMType.INVALID_VALUE;
    data[attestKeyIssuerOff] = KMType.INVALID_VALUE;
  }

  @Override
  public short prepareBeginResp(short paramsPtr, short opHandlePtr, short bufModPtr,
      short macLengthPtr) {
    short resp = KMArray.instance((short) 3);
    KMArray.cast(resp).add((short) 0, KMInteger.uint_16(KMError.OK));
    KMArray.cast(resp).add((short) 1, paramsPtr);
    KMArray.cast(resp).add((short) 2, opHandlePtr);
    return resp;
  }

  @Override
  public short prepareFinishExp() {
    short byteBlob = KMByteBlob.exp();
    short cmd = KMArray.instance((short) 6);
    KMArray.cast(cmd).add((short) 0, KMInteger.exp());//op handle
    short keyParam = KMKeyParameters.exp();
    KMArray.cast(cmd).add((short) 1, keyParam);// Key Parameters
    KMArray.cast(cmd).add((short) 2, byteBlob);// input data
    KMArray.cast(cmd).add((short) 3, byteBlob); // signature
    short authToken = KMHardwareAuthToken.exp();
    KMArray.cast(cmd).add((short) 4, authToken); // auth token
    short verToken = getKMVerificationTokenExp();
    KMArray.cast(cmd).add((short) 5, verToken); // time stamp token
    return cmd;
  }

  @Override
  public short prepareUpdateExp() {
    short cmd = KMArray.instance((short) 5);
    // Arguments
    short keyParams = KMKeyParameters.exp();
    KMArray.cast(cmd).add((short) 0, KMInteger.exp());
    KMArray.cast(cmd).add((short) 1, keyParams);
    KMArray.cast(cmd).add((short) 2, KMByteBlob.exp());
    short authToken = KMHardwareAuthToken.exp();
    KMArray.cast(cmd).add((short) 3, authToken);
    short verToken = getKMVerificationTokenExp();
    KMArray.cast(cmd).add((short) 4, verToken);
    return cmd;
  }

  @Override
  public void getUpdateInputParameters(short arrPtr, short[] data, byte opHandleOff,
      byte keyParametersOff, byte inputDataOff, byte hwTokenOff,
      byte verToken) {
    data[opHandleOff] = KMArray.cast(arrPtr).get((short) 0);
    data[keyParametersOff] = KMArray.cast(arrPtr).get((short) 1);
    data[inputDataOff] = KMArray.cast(arrPtr).get((short) 2);
    data[hwTokenOff] = KMArray.cast(arrPtr).get((short) 3);
    data[verToken] = KMArray.cast(arrPtr).get((short) 4);
  }

  @Override
  public void getFinishInputParameters(short arrPtr, short[] data, byte opHandleOff,
      byte keyParametersOff, byte inputDataOff, byte signDataOff, byte hwTokenOff, byte verToken,
      byte confToken) {
    data[opHandleOff] = KMArray.cast(arrPtr).get((short) 0);
    data[keyParametersOff] = KMArray.cast(arrPtr).get((short) 1);
    data[inputDataOff] = KMArray.cast(arrPtr).get((short) 2);
    data[signDataOff] = KMArray.cast(arrPtr).get((short) 3);
    data[hwTokenOff] = KMArray.cast(arrPtr).get((short) 4);
    data[verToken] = KMArray.cast(arrPtr).get((short) 5);
    data[confToken] = KMType.INVALID_VALUE;
  }

  @Override
  public short prepareFinishResp(short outputPtr) {
    short keyParam = KMArray.instance((short) 0);
    keyParam = KMKeyParameters.instance(keyParam);
    short resp = KMArray.instance((short) 3);
    KMArray.cast(resp).add((short) 0, KMInteger.uint_16(KMError.OK));
    KMArray.cast(resp).add((short) 1, keyParam);
    KMArray.cast(resp).add((short) 2, outputPtr);
    return resp;
  }

  @Override
  public short prepareUpdateResp(short outputPtr, short inputConsumedPtr) {
    short resp = KMArray.instance((short) 4);
    KMArray.cast(resp).add((short) 0, KMInteger.uint_16(KMError.OK));
    KMArray.cast(resp).add((short) 1, inputConsumedPtr);
    short keyParm = KMKeyParameters.instance(KMArray.instance((short) 0));
    KMArray.cast(resp).add((short) 2, keyParm);
    KMArray.cast(resp).add((short) 3, outputPtr);
    return resp;
  }

  @Override
  public short validateApduHeader(APDU apdu) {
    return KMError.OK;
  }

}
