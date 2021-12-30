package com.android.javacard.keymaster;

import com.android.javacard.seprovider.KMAttestationCert;
import com.android.javacard.seprovider.KMSEProvider;

public interface KMSpecification {

  short getHardwareInfo();

  short makeKeyCharacteristics(short keyParams, short osVersion, short osPatch, short vendorPatch,
      short bootPatch, short origin, byte[] scratchPad);

  short makeKeyCharacteristicsForKeyblob(short swParams, short sbParams, short teeParams);

  short getKeyCharacteristicsExp();

  boolean isProvisionedAttestKeysSupported();

  boolean canCreateEarlyBootKeys();

  short getHardwareParamters(short sbParams, short teeParams);

  short concatParamsForAuthData(short arrPtr, short hwParams, short swParams, short hiddenParams, short pubKey);

  boolean isFactoryAttestationSupported();

  KMAttestationCert makeCommonCert(short swParams, short hwParams, short keyParams,
      byte[] scratchPad, KMSEProvider seProvider);

  short getNotAfter(short params);

  short getNotBefore(short params);

  short getIssuer();
  
  boolean isKeyAgreementSupported();
  
  short getConfirmationToken(short confToken, short keyParams);
  
  short getKMVerificationTokenExp();
  
  short getMacFromVerificationToken(short verToken);
}
