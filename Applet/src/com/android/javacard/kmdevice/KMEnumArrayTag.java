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
 * KMEnumArrayTag represents ENUM_REP tag type. It has following structure, struct{byte TAG_TYPE;
 * short length; struct{short ENUM_ARRAY_TAG; short tagKey; sequence of byte values}}
 */
public class KMEnumArrayTag extends KMTag {

  private static KMEnumArrayTag prototype;

  // The allowed tag keys of enum array type.
  private static short[] tags;

  // Tag Values.
  private static Object[] enums;

  public static void initStatics() {
    tags = new short[]{PURPOSE, BLOCK_MODE, DIGEST, PADDING, RSA_OAEP_MGF_DIGEST};
    enums = new Object[]{
        new byte[]{ENCRYPT, DECRYPT, SIGN, VERIFY, WRAP_KEY, ATTEST_KEY, AGREE_KEY},
        new byte[]{ECB, CBC, CTR, GCM},
        new byte[]{DIGEST_NONE, MD5, SHA1, SHA2_224, SHA2_256, SHA2_384, SHA2_512},
        new byte[]{
            PADDING_NONE, RSA_OAEP, RSA_PSS, RSA_PKCS1_1_5_ENCRYPT, RSA_PKCS1_1_5_SIGN, PKCS7
        },
        new byte[]{DIGEST_NONE, MD5, SHA1, SHA2_224, SHA2_256, SHA2_384, SHA2_512},

    };
  }

  private KMEnumArrayTag() {
  }

  private static KMEnumArrayTag proto(short ptr) {
    if (prototype == null) {
      prototype = new KMEnumArrayTag();
    }
    KMType.instanceTable[KM_ENUM_ARRAY_TAG_OFFSET] = ptr;
    return prototype;
  }

  // pointer to an empty instance used as expression
  public static short exp() {
    short blobPtr = KMByteBlob.exp();
    short ptr = instance(TAG_TYPE, (short) 6);
    Util.setShort(heap, (short) (ptr + TLV_HEADER_SIZE), ENUM_ARRAY_TAG);
    Util.setShort(heap, (short) (ptr + TLV_HEADER_SIZE + 2), INVALID_TAG);
    Util.setShort(heap, (short) (ptr + TLV_HEADER_SIZE + 4), blobPtr);
    return ptr;
  }

  public static short instance(short key) {
    byte[] vals = getAllowedEnumValues(key);
    if (vals == null) {
      ISOException.throwIt(ISO7816.SW_DATA_INVALID);
    }
    short blobPtr = KMByteBlob.exp();
    return instance(key, blobPtr);
  }

  public static short instance(short key, short byteBlob) {
    byte[] allowedVals = getAllowedEnumValues(key);
    if (allowedVals == null) {
      ISOException.throwIt(ISO7816.SW_DATA_INVALID);
    }
    short byteIndex = 0;
    short enumIndex;
    boolean validValue;
    while (byteIndex < KMByteBlob.length(byteBlob)) {
      enumIndex = 0;
      validValue = false;
      while (enumIndex < allowedVals.length) {
        if (KMByteBlob.get(byteBlob, byteIndex) == allowedVals[enumIndex]) {
          validValue = true;
          break;
        }
        enumIndex++;
      }
      if (!validValue) {
        ISOException.throwIt(ISO7816.SW_DATA_INVALID);
      }
      byteIndex++;
    }
    short ptr = instance(TAG_TYPE, (short) 6);
    Util.setShort(heap, (short) (ptr + TLV_HEADER_SIZE), ENUM_ARRAY_TAG);
    Util.setShort(heap, (short) (ptr + TLV_HEADER_SIZE + 2), key);
    Util.setShort(heap, (short) (ptr + TLV_HEADER_SIZE + 4), byteBlob);
    return ptr;
  }

  private static KMEnumArrayTag cast(short ptr) {
    if (heap[ptr] != TAG_TYPE) {
      ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    }
    if (Util.getShort(heap, (short) (ptr + TLV_HEADER_SIZE)) != ENUM_ARRAY_TAG) {
      ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    }
    return proto(ptr);
  }

  public short getKey() {
    return Util.getShort(heap,
        (short) (KMType.instanceTable[KM_ENUM_ARRAY_TAG_OFFSET] + TLV_HEADER_SIZE + 2));
  }

  public short getTagType() {
    return KMType.ENUM_ARRAY_TAG;
  }

  public short getValues() {
    return Util.getShort(heap,
        (short) (KMType.instanceTable[KM_ENUM_ARRAY_TAG_OFFSET] + TLV_HEADER_SIZE + 4));
  }

  public short length() {
    short blobPtr = Util.getShort(heap,
        (short) (KMType.instanceTable[KM_ENUM_ARRAY_TAG_OFFSET] + TLV_HEADER_SIZE + 4));
    return KMByteBlob.length(blobPtr);
  }

  private static byte[] getAllowedEnumValues(short key) {
    short index = (short) tags.length;
    while (--index >= 0) {
      if (tags[index] == key) {
        return (byte[]) enums[index];
      }
    }
    return null;
  }

  public static short getValues(short tagId, short params, byte[] buf, short start) {
    short tag = KMKeyParameters.findTag(params, KMType.ENUM_ARRAY_TAG, tagId);
    if (tag == KMType.INVALID_VALUE) {
      return KMType.INVALID_VALUE;
    }
    tag = KMEnumArrayTag.cast(tag).getValues();
    return KMByteBlob.getValues(tag, buf, start);
  }

  public short get(short index) {
    return KMByteBlob.get(getValues(), index);
  }

  public static boolean contains(short tagId, short tagValue, short params) {
    short tag = KMKeyParameters.findTag(params, KMType.ENUM_ARRAY_TAG, tagId);
    if (tag != KMType.INVALID_VALUE) {
      short index = 0;
      while (index < KMEnumArrayTag.cast(tag).length()) {
        if (tagValue == KMEnumArrayTag.cast(tag).get(index)) {
          return true;
        }
        index++;
      }
    }
    return false;
  }

  public static short length(short tagId, short params) {
    short tag = KMKeyParameters.findTag(params, KMType.ENUM_ARRAY_TAG, tagId);
    if (tag != KMType.INVALID_VALUE) {
      return KMEnumArrayTag.cast(tag).length();
    }
    return KMType.INVALID_VALUE;
  }

  public boolean contains(short tagValue) {
    short index = 0;
    while (index < length()) {
      if (get(index) == (byte) tagValue) {
        return true;
      }
      index++;
    }
    return false;
  }

  public static short get(short bPtr, short index) {
    return KMEnumArrayTag.cast(bPtr).get(index);
  }

  public static short length(short bPtr) {
    return KMEnumArrayTag.cast(bPtr).length();
  }

  public static short getValues(short bPtr) {
    return KMEnumArrayTag.cast(bPtr).getValues();
  }

  public static short getTagType(short bPtr) {
    return KMType.ENUM_ARRAY_TAG;
  }

  public static short getKey(short bPtr) {
    return KMEnumArrayTag.cast(bPtr).getKey();
  }

  public static boolean contains(short bPtr, short tagValue) {
    return KMEnumArrayTag.cast(bPtr).contains(tagValue);
  }


}
