/*
 * Copyright(C) 2020 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" (short)0IS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.android.javacard.seprovider;

import org.globalplatform.upgrade.Element;

import com.android.javacard.kmdevice.KMAttestationKey;

import javacard.security.AESKey;
import javacard.security.ECPrivateKey;
import javacard.security.KeyPair;

public class KMECPrivateKey implements KMAttestationKey {

  private KeyPair ecKeyPair;

  public KMECPrivateKey(KeyPair ecPair) {
    ecKeyPair = ecPair;
  }

  public void setS(byte[] buffer, short offset, short length) {
    ECPrivateKey ecPriv = (ECPrivateKey) ecKeyPair.getPrivate();
    ecPriv.setS(buffer, offset, length);
  }

  public short getS(byte[] buffer, short offset) {
    ECPrivateKey ecPriv = (ECPrivateKey) ecKeyPair.getPrivate();
    return ecPriv.getS(buffer, offset);
  }

  public ECPrivateKey getPrivateKey() {
    return (ECPrivateKey) ecKeyPair.getPrivate();
  }

  public static void onSave(Element element, KMECPrivateKey kmKey) {
    element.write(kmKey.ecKeyPair);
  }

  public static KMECPrivateKey onRestore(KeyPair ecKey) {
    if (ecKey == null)
      return null;
    return new KMECPrivateKey(ecKey);
  }

  public static short getBackupPrimitiveByteCount() {
    return (short) 0;
  }

  public static short getBackupObjectCount() {
    return (short) 1;
  }

}
