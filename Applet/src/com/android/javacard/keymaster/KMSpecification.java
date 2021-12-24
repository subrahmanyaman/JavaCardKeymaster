package com.android.javacard.keymaster;

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

  short getNotAfter(short params);

  short getNotBefore(short params);

  short getIssuer();
}
