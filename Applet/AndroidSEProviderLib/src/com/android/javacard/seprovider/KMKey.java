package com.android.javacard.seprovider;

public interface KMKey {
  
  short getPublicKey(byte[] buf, short offset);

}
