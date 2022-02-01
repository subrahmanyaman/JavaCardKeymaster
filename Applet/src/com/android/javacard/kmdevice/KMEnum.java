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
 * KMEnum represents an enumeration specified in android keymaster hal specifications. It
 * corresponds to uint CBOR type and it is a byte value. struct{byte ENUM_TYPE; short length;
 * struct{short enumType; byte val}}
 */
public class KMEnum extends KMType {

  private static KMEnum prototype;

  // The allowed enum types.
  private static short[] types;

  private static Object[] enums = null;

  private KMEnum() {
  }

  public static void initStatics() {
    types = new short[]{
        HARDWARE_TYPE,
        KEY_FORMAT,
        KEY_DERIVATION_FUNCTION,
        VERIFIED_BOOT_STATE,
        DEVICE_LOCKED,
        USER_AUTH_TYPE,
        PURPOSE,
        ECCURVE,
        RULE
    };
  }

  private static KMEnum proto(short ptr) {
    if (prototype == null) {
      prototype = new KMEnum();
    }
    KMType.instanceTable[KM_ENUM_OFFSET] = ptr;
    return prototype;
  }

  // pointer to an empty instance used as expression
  public static short exp() {
    return KMType.exp(ENUM_TYPE);
  }

  public short length() {
    return Util.getShort(heap, (short) (KMType.instanceTable[KM_ENUM_OFFSET] + 1));
  }

  private static KMEnum cast(short ptr) {
    validate(ptr);
    return proto(ptr);
  }

  public static void validate(short ptr) {
    if (heap[ptr] != ENUM_TYPE) {
      ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    }
    if (Util.getShort(heap, (short) (ptr + 1)) == INVALID_VALUE) {
      ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    }
  }

  public static short instance(short enumType) {
    if (!validateEnum(enumType, NO_VALUE)) {
      ISOException.throwIt(ISO7816.SW_DATA_INVALID);
    }
    short ptr = KMType.instance(ENUM_TYPE, (short) 2);
    Util.setShort(heap, (short) (ptr + TLV_HEADER_SIZE), enumType);
    return ptr;
  }

  public static short instance(short enumType, byte val) {
    if (!validateEnum(enumType, val)) {
      ISOException.throwIt(ISO7816.SW_DATA_INVALID);
    }
    short ptr = KMType.instance(ENUM_TYPE, (short) 3);
    Util.setShort(heap, (short) (ptr + TLV_HEADER_SIZE), enumType);
    heap[(short) (ptr + TLV_HEADER_SIZE + 2)] = val;
    return ptr;
  }

  private static void create() {
    // The allowed enum values to corresponding enum types in the types array.
    if (enums == null) {
      enums =
          new Object[]{
              new byte[]{SOFTWARE, TRUSTED_ENVIRONMENT, STRONGBOX},
              new byte[]{X509, PKCS8, RAW},
              new byte[]{
                  DERIVATION_NONE,
                  RFC5869_SHA256,
                  ISO18033_2_KDF1_SHA1,
                  ISO18033_2_KDF1_SHA256,
                  ISO18033_2_KDF2_SHA1,
                  ISO18033_2_KDF2_SHA256
              },
              new byte[]{SELF_SIGNED_BOOT, VERIFIED_BOOT, UNVERIFIED_BOOT, FAILED_BOOT},
              new byte[]{DEVICE_LOCKED_TRUE, DEVICE_LOCKED_FALSE},
              new byte[]{USER_AUTH_NONE, PASSWORD, FINGERPRINT, BOTH},
              new byte[]{ENCRYPT, DECRYPT, SIGN, VERIFY, WRAP_KEY, ATTEST_KEY, AGREE_KEY},
              new byte[]{P_224, P_256, P_384, P_521},
              new byte[]{IGNORE_INVALID_TAGS, FAIL_ON_INVALID_TAGS}
          };
    }
  }

  public void setVal(byte val) {
    heap[(short) (KMType.instanceTable[KM_ENUM_OFFSET] + TLV_HEADER_SIZE + 2)] = val;
  }

  public byte getVal() {
    return heap[(short) (KMType.instanceTable[KM_ENUM_OFFSET] + TLV_HEADER_SIZE + 2)];
  }

  public void setEnumType(short type) {
    Util.setShort(heap, (short) (KMType.instanceTable[KM_ENUM_OFFSET] + TLV_HEADER_SIZE), type);
  }

  public short getEnumType() {
    return Util.getShort(heap, (short) (KMType.instanceTable[KM_ENUM_OFFSET] + TLV_HEADER_SIZE));
  }

  // isValidTag enumeration keys and values.
  private static boolean validateEnum(short key, byte value) {
    create();
    byte[] vals;
    short enumInd;
    // check if key exists
    short index = (short) types.length;
    while (--index >= 0) {
      if (types[index] == key) {
        // check if value given
        if (value != NO_VALUE) {
          // check if the value exist
          vals = (byte[]) enums[index];
          enumInd = (short) vals.length;
          while (--enumInd >= 0) {
            if (vals[enumInd] == value) {
              // return true if value exist
              return true;
            }
          }
          // return false if value does not exist
          return false;
        }
        // return true if key exist and value not given
        return true;
      }
    }
    // return false if key does not exist
    return false;
  }

  public static void setVal(short bPtr, byte val) {
    KMEnum.cast(bPtr).setVal(val);
  }

  public static byte getVal(short bPtr) {
    return KMEnum.cast(bPtr).getVal();
  }

  public static void setEnumType(short bPtr, short type) {
    KMEnum.cast(bPtr).setEnumType(type);
  }

  public static short getEnumType(short bPtr) {
    return KMEnum.cast(bPtr).getEnumType();
  }


}
