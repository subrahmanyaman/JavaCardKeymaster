package com.android.javacard.kmdevice;

public interface KMRkpDataStore extends KMUpgradable {

  /**
   * This function stores the data of the corresponding id into the persistent
   * memory.
   *
   * @param id     of the buffer to be stored. @see {@link KMDataStoreConstants}
   * @param data   is the buffer that contains the data to be stored.
   * @param offset is the start offset of the buffer.
   * @param length is the length of the buffer.
   */
  void storeData(byte id, byte[] data, short offset, short length);

  /**
   * This function returns the stored data of the corresponding id.
   *
   * @param id     of the buffer to be stored.@see {@link KMDataStoreConstants}
   * @param data   is the buffer in which the data of the corresponding id is
   *               returned.
   * @param offset is the start offset of the buffer.
   * @return length of the data copied to the buffer.
   */
  byte[] getData(byte id);

  // keys
  /**
   * This function creates an instance device unique key and stores in persitent
   * memory.
   *
   * @param testMode   flag denotes if the key is used test mode or production
   *                   mode.
   * @param pubKey     buffer containing the EC public key.
   * @param pubKeyOff  start offset of the public key buffer.
   * @param pubKeyLen  length of the public key buffer.
   * @param privKey    buffer containing the EC private key.
   * @param privKeyOff start offset of the private key buffer.
   * @param privKeyLen length of the private key buffer.
   */
  void createDeviceUniqueKey(boolean testMode, byte[] pubKey, short pubKeyOff, short pubKeyLen, byte[] privKey,
      short privKeyOff, short privKeyLen);

  /**
   * Returns the device unique key
   * 
   * @param testMode flag denotes if the key is used test mode or production mode.
   * @return KMDeviceUniqueKey instance
   */
  KMDeviceUniqueKey getDeviceUniqueKey(boolean testMode);
}
