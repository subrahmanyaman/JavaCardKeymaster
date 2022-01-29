package com.android.javacard.kmdevice;

public interface KMDataStore extends KMUpgradable {

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

  /**
   * This function returns the stored data of the corresponding id.
   *
   * @param id     of the buffer to be stored.
   * @param data   is the buffer in which the data of the corresponding id is
   *               returned.
   * @param offset is the start offset of the buffer.
   * @return length of the data copied to the buffer.
   */
  short getData(byte id, byte[] data, short offset);

  /**
   * This function clears the data of the corresponding id in persistent memory.
   * 
   * @param id of the buffer to be stored.
   */
  void clearData(byte id);


  // Below functions are used to store and retrieve the auth tags for
  // MAX_USES_PER_BOOT use case.
  boolean storeAuthTag(byte[] data, short offset, short length, byte[] scracthPad, short scratchPadOff);

  boolean isAuthTagPersisted(byte[] data, short offset, short length, byte[] scratchPad, short scratchPadOff);

  void clearAllAuthTags();

  short getRateLimitedKeyCount(byte[] data, short offset, short length, byte[] scratchPad, short scratchPadOff);

  void setRateLimitedKeyCount(byte[] data, short dataOffset, short dataLen, byte[] counter, short counterOff,
      short counterLen, byte[] scratchPad, short scratchPadOff);

  // certificate chain
  void persistCertificateData(byte[] buffer, short certChainOff, short certChainLen, short certIssuerOff,
      short certIssuerLen, short certExpiryOff, short certExpiryLen);

  short readCertificateData(byte dataType, byte[] buf, short offset);

  short getCertificateDataLength(byte dataType);
  
  // keys
  KMComputedHmacKey getComputedHmacKey();
  KMPreSharedKey getPresharedKey();
  KMMasterKey getMasterKey();
  KMAttestationKey getAttestationKey();

}
