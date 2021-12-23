package com.android.javacard.keymaster;

public class KMKeymintSpecification implements KMSpecification {

  public static final byte[] JAVACARD_KEYMINT_DEVICE = {
      0x4a, 0x61, 0x76, 0x61, 0x63, 0x61, 0x72, 0x64,
      0x4b, 0x65, 0x79, 0x6d, 0x69, 0x6e, 0x74,
      0x44, 0x65, 0x76, 0x69, 0x63, 0x65,
  };
  private static final byte[] GOOGLE = {0x47, 0x6F, 0x6F, 0x67, 0x6C, 0x65};

  @Override
  public short getHardwareInfo() {
    final byte version = 1;
    // Make the response
    short respPtr = KMArray.instance((short) 6);
    KMArray resp = KMArray.cast(respPtr);
    resp.add((short) 0, KMInteger.uint_16(KMError.OK));
    resp.add((short) 1, KMInteger.uint_8(version));
    resp.add((short) 2, KMEnum.instance(KMType.HARDWARE_TYPE, KMType.STRONGBOX));
    resp.add(
        (short) 3,
        KMByteBlob.instance(
            JAVACARD_KEYMINT_DEVICE, (short) 0, (short) JAVACARD_KEYMINT_DEVICE.length));
    resp.add((short) 4, KMByteBlob.instance(GOOGLE, (short) 0, (short) GOOGLE.length));
    resp.add((short) 5, KMInteger.uint_8((byte) 1));
    return respPtr;
  }

  @Override
  public short makeKeyCharacteristics(short keyParams, short osVersion, short osPatch,
      short vendorPatch, short bootPatch, short origin, byte[] scratchPad) {
    short strongboxParams = KMKeyParameters.makeSbEnforced(
        keyParams, (byte) origin, osVersion, osPatch, vendorPatch, bootPatch, scratchPad);
    short teeParams = KMKeyParameters.makeTeeEnforced(keyParams, scratchPad);
    short swParams = KMKeyParameters.makeKeystoreEnforced(keyParams, scratchPad);
    short keyCharacteristics = KMKeyCharacteristics.instance();
    KMKeyCharacteristics.cast(keyCharacteristics).setStrongboxEnforced(strongboxParams);
    KMKeyCharacteristics.cast(keyCharacteristics).setKeystoreEnforced(swParams);
    KMKeyCharacteristics.cast(keyCharacteristics).setTeeEnforced(teeParams);
    return keyCharacteristics;
  }

  @Override
  public short getKeyCharacteristicsExp() {
    return KMKeyCharacteristics.exp();
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
