package com.android.javacard.kmdevice;

public interface KMRkpDataStore extends KMUpgradable {

  /**
   * This function stores the data of the corresponding id into the persistent
   * memory.
   *
   * @param id     of the buffer to be stored.
   * @param data   is the buffer that contains the data to be stored.
   * @param offset is the start offset of the buffer.
   * @param length is the length of the buffer.
   */
  void storeData(byte id, byte[] data, short offset, short length);


  byte[] getData(byte id);

  // keys
  void createDeviceUniqueKey(boolean testMode, byte[] pubKey, short pubKeyOff, short pubKeyLen, byte[] privKey,
      short privKeyOff, short privKeyLen);

  KMDeviceUniqueKey getDeviceUniqueKey(boolean testMode);
}
