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
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.android.javacard.kmdevice;

import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.Util;

/**
 * KMKeyCharacteristics represents KeyCharacteristics structure from android keymaster hal
 * specifications. It corresponds to CBOR array type. struct{byte KEY_CHAR_TYPE; short length=3;
 * short arrayPtr} where arrayPtr is a pointer to ordered array with 1 or 3 following elements:
 * {KMKeyParameters sb; KMKeyParameters tee; KMKeyParameters keystore}
 */
public class KMKeyCharacteristics extends KMType {

  public static final byte KEYSTORE_ENFORCED = 0x00;
  public static final byte STRONGBOX_ENFORCED = 0x01;
  public static final byte TEE_ENFORCED = 0x02;
  private static KMKeyCharacteristics prototype;

  private KMKeyCharacteristics() {
  }

  public static short exp() {
    short sb = KMKeyParameters.exp();
    short tee = KMKeyParameters.exp();
    short keystore = KMKeyParameters.exp();
    short arrPtr = KMArray.instance((short) 3);

    KMArray.add(arrPtr, STRONGBOX_ENFORCED, sb);
    KMArray.add(arrPtr, TEE_ENFORCED, tee);
    KMArray.add(arrPtr, KEYSTORE_ENFORCED, keystore);
    return instance(arrPtr);
  }

  private static KMKeyCharacteristics proto(short ptr) {
    if (prototype == null) {
      prototype = new KMKeyCharacteristics();
    }
    KMType.instanceTable[KM_KEY_CHARACTERISTICS_OFFSET] = ptr;
    return prototype;
  }

  public static short instance() {
    short arrPtr = KMArray.instance((short) 3);
    return instance(arrPtr);
  }

  public static short instance(short vals) {
    short ptr = KMType.instance(KEY_CHAR_TYPE, (short) 3);
    if (KMArray.length(vals) != 3) {
      ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
    }
    Util.setShort(heap, (short) (ptr + TLV_HEADER_SIZE), vals);
    return ptr;
  }

  private static KMKeyCharacteristics cast(short ptr) {
    if (heap[ptr] != KEY_CHAR_TYPE) {
      ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    }
    short arrPtr = Util.getShort(heap, (short) (ptr + TLV_HEADER_SIZE));
    if (heap[arrPtr] != ARRAY_TYPE) {
      ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    }
    return proto(ptr);
  }

  public short getVals() {
    return Util.getShort(heap,
        (short) (KMType.instanceTable[KM_KEY_CHARACTERISTICS_OFFSET] + TLV_HEADER_SIZE));
  }

  public short length() {
    short arrPtr = getVals();
    return KMArray.length(arrPtr);
  }

  public short getKeystoreEnforced() {
    short arrPtr = getVals();
    return KMArray.get(arrPtr, KEYSTORE_ENFORCED);
  }

  public short getTeeEnforced() {
    short arrPtr = getVals();
    return KMArray.get(arrPtr, TEE_ENFORCED);
  }

  public short getStrongboxEnforced() {
    short arrPtr = getVals();
    return KMArray.get(arrPtr, STRONGBOX_ENFORCED);
  }

  public void setKeystoreEnforced(short ptr) {
    KMKeyParameters.validate(ptr);
    short arrPtr = getVals();
    KMArray.add(arrPtr, KEYSTORE_ENFORCED, ptr);
  }

  public void setTeeEnforced(short ptr) {
    KMKeyParameters.validate(ptr);
    short arrPtr = getVals();
    KMArray.add(arrPtr, TEE_ENFORCED, ptr);
  }

  public void setStrongboxEnforced(short ptr) {
    KMKeyParameters.validate(ptr);
    short arrPtr = getVals();
    KMArray.add(arrPtr, STRONGBOX_ENFORCED, ptr);
  }

  public static short getVals(short bPtr) {
    return KMKeyCharacteristics.cast(bPtr).getVals();
  }

  public static short length(short bPtr) {
    return KMKeyCharacteristics.cast(bPtr).length();
  }

  public static short getKeystoreEnforced(short bPtr) {
    return KMKeyCharacteristics.cast(bPtr).getKeystoreEnforced();
  }

  public static short getTeeEnforced(short bPtr) {
    return KMKeyCharacteristics.cast(bPtr).getTeeEnforced();
  }

  public static short getStrongboxEnforced(short bPtr) {
    return KMKeyCharacteristics.cast(bPtr).getStrongboxEnforced();
  }

  public static void setKeystoreEnforced(short bPtr, short ptr) {
    KMKeyCharacteristics.cast(bPtr).setKeystoreEnforced(ptr);
  }

  public static void setTeeEnforced(short bPtr, short ptr) {
    KMKeyCharacteristics.cast(bPtr).setTeeEnforced(ptr);
  }

  public static void setStrongboxEnforced(short bPtr, short ptr) {
    KMKeyCharacteristics.cast(bPtr).setStrongboxEnforced(ptr);
  }

}
