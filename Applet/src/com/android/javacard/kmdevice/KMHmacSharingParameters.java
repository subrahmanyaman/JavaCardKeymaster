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
 * KMHmacSharingParameters represents HmacSharingParameters structure from android keymaster hal
 * specifications. It corresponds to CBOR array type. struct{byte HMAC_SHARING_PARAM_TYPE; short
 * length=2; short arrayPtr} where arrayPtr is a pointer to ordered array with following elements:
 * {KMByteBlob Seed; KMByteBlob Nonce}
 */
public class KMHmacSharingParameters extends KMType {

  public static final byte SEED = 0x00;
  public static final byte NONCE = 0x01;

  private static KMHmacSharingParameters prototype;

  private KMHmacSharingParameters() {
  }

  public static short exp() {
    short arrPtr = KMArray.instance((short) 2);
    KMArray.add(arrPtr, SEED, KMByteBlob.exp());
    KMArray.add(arrPtr, NONCE, KMByteBlob.exp());
    return instance(arrPtr);
  }

  private static KMHmacSharingParameters proto(short ptr) {
    if (prototype == null) {
      prototype = new KMHmacSharingParameters();
    }
    KMType.instanceTable[KM_HMAC_SHARING_PARAMETERS_OFFSET] = ptr;
    return prototype;
  }

  public static short instance() {
    short arrPtr = KMArray.instance((short) 2);
    return instance(arrPtr);
  }

  public static short instance(short vals) {
    short ptr = KMType.instance(HMAC_SHARING_PARAM_TYPE, (short) 2);
    if (KMArray.length(vals) != 2) {
      ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
    }
    Util.setShort(heap, (short) (ptr + TLV_HEADER_SIZE), vals);
    return ptr;
  }

  private static KMHmacSharingParameters cast(short ptr) {
    if (heap[ptr] != HMAC_SHARING_PARAM_TYPE) {
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
        (short) (KMType.instanceTable[KM_HMAC_SHARING_PARAMETERS_OFFSET] + TLV_HEADER_SIZE));
  }

  public short length() {
    short arrPtr = getVals();
    return KMArray.length(arrPtr);
  }

  public void setSeed(short vals) {
    KMByteBlob.validate(vals);
    short arrPtr = getVals();
    KMArray.add(arrPtr, SEED, vals);
  }

  public void setNonce(short vals) {
    KMByteBlob.validate(vals);
    short arrPtr = getVals();
    KMArray.add(arrPtr, NONCE, vals);
  }

  public short getNonce() {
    short arrPtr = getVals();
    return KMArray.get(arrPtr, NONCE);
  }

  public short getSeed() {
    short arrPtr = getVals();
    return KMArray.get(arrPtr, SEED);
  }

  public static short getVals(short bPtr) {
    return KMHmacSharingParameters.cast(bPtr).getVals();
  }

  public static short length(short bPtr) {
    return KMHmacSharingParameters.cast(bPtr).length();
  }

  public static void setSeed(short bPtr, short vals) {
    KMHmacSharingParameters.cast(bPtr).setSeed(vals);
  }

  public static void setNonce(short bPtr, short vals) {
    KMHmacSharingParameters.cast(bPtr).setNonce(vals);
  }

  public static short getNonce(short bPtr) {
    return KMHmacSharingParameters.cast(bPtr).getNonce();
  }

  public static short getSeed(short bPtr) {
    return KMHmacSharingParameters.cast(bPtr).getSeed();
  }
}
