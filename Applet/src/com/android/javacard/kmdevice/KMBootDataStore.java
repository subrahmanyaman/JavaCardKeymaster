package com.android.javacard.kmdevice;

public interface KMBootDataStore {

  /**
   * Get Verified Boot hash. Part of RoT. Part of data sent by the aosp
   * bootloader.
   */
  short getVerifiedBootHash(byte[] buffer, short start);

  /**
   * Get Boot Key. Part of RoT. Part of data sent by the aosp bootloader.
   */
  short getBootKey(byte[] buffer, short start);

  /**
   * Get Boot state. Part of RoT. Part of data sent by the aosp bootloader.
   */
  short getBootState();

  /**
   * Returns true if device bootloader is locked. Part of RoT. Part of data sent
   * by the aosp bootloader.
   */
  boolean isDeviceBootLocked();

  /**
   * Get Boot patch level. Part of data sent by the aosp bootloader.
   */
  short getBootPatchLevel(byte[] buffer, short start);
}
