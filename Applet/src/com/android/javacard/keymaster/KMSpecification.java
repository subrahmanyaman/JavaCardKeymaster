package com.android.javacard.keymaster;

import com.android.javacard.seprovider.KMAttestationCert;
import com.android.javacard.seprovider.KMSEProvider;
import javacard.framework.APDU;

public interface KMSpecification {

  short getHardwareInfo();

  short makeKeyCharacteristics(short keyParams, short osVersion, short osPatch, short vendorPatch,
      short bootPatch, short origin, byte[] scratchPad);

  short makeKeyCharacteristicsForKeyblob(short swParams, short sbParams, short teeParams);

  boolean canCreateEarlyBootKeys();

  short getHardwareParamters(short sbParams, short teeParams);

  short concatParamsForAuthData(short arrPtr, short hwParams, short swParams, short hiddenParams,
      short pubKey);

  boolean isFactoryAttestationSupported();

  KMAttestationCert makeCommonCert(short swParams, short hwParams, short keyParams,
      byte[] scratchPad, KMSEProvider seProvider);

  boolean isKeyAgreementSupported();

  short getConfirmationToken(short confToken, short keyParams);

  short getKMVerificationTokenExp();

  short getMacFromVerificationToken(short verToken);

  short getMgf1Digest(short keyParams, short hwParams);

  short generateAttestKeyExp();

  void getAttestKeyInputParameters(short arrPtr, short[] data, byte keyBlobOff,
      byte keyParametersOff,
      byte attestKeyBlobOff, byte attestKeyParamsOff, byte attestKeyIssuerOff);

  short prepareBeginResp(short paramsPtr, short opHandlePtr, short bufModePtr, short macLengthPtr);

  short prepareFinishExp();

  short prepareUpdateExp();

  void getUpdateInputParameters(short arrPtr, short[] data, byte opHandleOff,
      byte keyParametersOff, byte inputDataOff, byte hwTokenOff,
      byte verToken);

  void getFinishInputParameters(short arrPtr, short[] data, byte opHandleOff,
      byte keyParametersOff, byte inputDataOff, byte signDataOff, byte hwTokenOff,
      byte verToken, byte confToken);

  short prepareFinishResp(short outputPtr);

  public short prepareUpdateResp(short outputPtr, short inputConsumedPtr);

  short validateApduHeader(APDU apdu);
}
