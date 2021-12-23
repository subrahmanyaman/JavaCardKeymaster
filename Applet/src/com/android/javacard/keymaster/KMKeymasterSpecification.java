package com.android.javacard.keymaster;

public class KMKeymasterSpecification implements KMSpecification {
  // getHardwareInfo constants.
  private static final byte[] JAVACARD_KEYMASTER_DEVICE = {
      0x4A, 0x61, 0x76, 0x61, 0x63, 0x61, 0x72, 0x64, 0x4B, 0x65, 0x79, 0x6D, 0x61, 0x73, 0x74,
      0x65, 0x72, 0x44, 0x65, 0x76, 0x69, 0x63, 0x65,
  };
  private static final byte[] GOOGLE = {0x47, 0x6F, 0x6F, 0x67, 0x6C, 0x65};


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
    short teeParams = KMKeyParameters.makeTeeEnforced(keyParams,scratchPad);
    short swParams = KMKeyParameters.makeKeystoreEnforced(keyParams,scratchPad);
    short hwParams = KMKeyParameters.makeHwEnforced(strongboxParams, teeParams);
    short keyCharacteristics = KMKeyCharacteristics.instance2();
    KMKeyCharacteristics.cast(keyCharacteristics).setStrongboxEnforced(hwParams);
    KMKeyCharacteristics.cast(keyCharacteristics).setKeystoreEnforced(swParams);
    return keyCharacteristics;
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

}
