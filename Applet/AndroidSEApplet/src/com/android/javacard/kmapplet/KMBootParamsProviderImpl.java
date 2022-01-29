package com.android.javacard.kmapplet;

import com.android.javacard.kmdevice.KMBootDataStore;

public class KMBootParamsProviderImpl implements KMBootDataStore {

  KMKeymintDataStore kmStoreDataInst;

  public KMBootParamsProviderImpl(KMKeymintDataStore storeData) {
    kmStoreDataInst = storeData;
  }

  @Override
  public short getVerifiedBootHash(byte[] buffer, short start) {
    return kmStoreDataInst.getVerifiedBootHash(buffer, start);
  }

  @Override
  public short getBootKey(byte[] buffer, short start) {
    return kmStoreDataInst.getBootKey(buffer, start);
  }

  @Override
  public short getBootState() {
    return kmStoreDataInst.getBootState();
  }

  @Override
  public boolean isDeviceBootLocked() {
    return kmStoreDataInst.isDeviceBootLocked();
  }

  @Override
  public short getBootPatchLevel(byte[] buffer, short start) {
    return kmStoreDataInst.getBootPatchLevel(buffer, start);
  }

}
