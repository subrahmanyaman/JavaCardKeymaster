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
package com.android.javacard.kmapplet;

import org.globalplatform.upgrade.Element;
import org.globalplatform.upgrade.OnUpgradeListener;
import org.globalplatform.upgrade.UpgradeManager;

import com.android.javacard.kmdevice.KMArray;
import com.android.javacard.kmdevice.KMBootDataStore;
import com.android.javacard.kmdevice.KMByteBlob;
import com.android.javacard.kmdevice.KMByteTag;
import com.android.javacard.kmdevice.KMCose;
import com.android.javacard.kmdevice.KMCoseHeaders;
import com.android.javacard.kmdevice.KMCoseKey;
import com.android.javacard.kmdevice.KMDecoder;
import com.android.javacard.kmdevice.KMEncoder;
import com.android.javacard.kmdevice.KMEnum;
import com.android.javacard.kmdevice.KMEnumArrayTag;
import com.android.javacard.kmdevice.KMEnumTag;
import com.android.javacard.kmdevice.KMInteger;
import com.android.javacard.kmdevice.KMKeyParameters;
import com.android.javacard.kmdevice.KMKeymasterDevice;
import com.android.javacard.kmdevice.KMKeymintDevice;
import com.android.javacard.kmdevice.KMMap;
import com.android.javacard.kmdevice.KMRepository;
import com.android.javacard.kmdevice.KMRkpDataStore;
import com.android.javacard.kmdevice.KMTag;
import com.android.javacard.kmdevice.KMTextString;
import com.android.javacard.kmdevice.RemotelyProvisionedComponentDevice;
import com.android.javacard.seprovider.KMAndroidSEProvider;
import com.android.javacard.seprovider.KMError;
import com.android.javacard.kmdevice.KMException;
import com.android.javacard.kmdevice.KMDataStore;
import com.android.javacard.seprovider.KMKeymasterProvision;
import com.android.javacard.seprovider.KMKeymintProvision;
import com.android.javacard.kmdevice.KMSEProvider;
import com.android.javacard.kmdevice.KMDataStoreConstants;
import com.android.javacard.seprovider.KMType;

import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.AppletEvent;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.Util;
import javacard.security.CryptoException;
import javacardx.apdu.ExtendedLength;

public class KMAndroidSEApplet extends Applet implements AppletEvent, OnUpgradeListener, ExtendedLength {

  private static final byte KM_BEGIN_STATE = 0x00;
  private static final byte ILLEGAL_STATE = KM_BEGIN_STATE + 1;


  // Provider specific Commands
  private static final byte INS_KEYMINT_PROVIDER_APDU_START = 0x00;
  private static final byte INS_PROVISION_ATTESTATION_KEY_CMD = INS_KEYMINT_PROVIDER_APDU_START + 1; //0x01
  private static final byte INS_PROVISION_ATTESTATION_CERT_DATA_CMD = INS_KEYMINT_PROVIDER_APDU_START + 2; //0x02
  private static final byte INS_PROVISION_ATTEST_IDS_CMD = INS_KEYMINT_PROVIDER_APDU_START + 3;
  private static final byte INS_PROVISION_PRESHARED_SECRET_CMD =
      INS_KEYMINT_PROVIDER_APDU_START + 4;
  private static final byte INS_SET_BOOT_PARAMS_CMD = INS_KEYMINT_PROVIDER_APDU_START + 5;
  private static final byte INS_LOCK_PROVISIONING_CMD = INS_KEYMINT_PROVIDER_APDU_START + 6;
  private static final byte INS_GET_PROVISION_STATUS_CMD = INS_KEYMINT_PROVIDER_APDU_START + 7;
  private static final byte INS_SET_VERSION_PATCHLEVEL_CMD =
      INS_KEYMINT_PROVIDER_APDU_START + 8; //0x08
  private static final byte INS_SET_BOOT_ENDED_CMD = INS_KEYMINT_PROVIDER_APDU_START + 9; //0x09
  private static final byte INS_PROVISION_DEVICE_UNIQUE_KEY_CMD =
      INS_KEYMINT_PROVIDER_APDU_START + 10;
  private static final byte INS_PROVISION_ADDITIONAL_CERT_CHAIN_CMD =
      INS_KEYMINT_PROVIDER_APDU_START + 11;

  // Keymaster versions
  public static final byte KM_40 = 0x00;
  public static final byte KM_41 = 0x01;
  public static final byte KM_100 = 0x03;
  
  private static final byte BOOT_KEY_MAX_SIZE = 32;
  private static final byte BOOT_HASH_MAX_SIZE = 32;
  private static final byte COMPUTED_HMAC_KEY_SIZE = 32;
  
    
  private static byte kmDevice;
  private static KMSEProvider seProvider;
  private static KMKeymasterProvision seProvisionInst;
  private static KMDecoder decoderInst;
  private static KMEncoder encoderInst;
  private static KMRepository repositoryInst;
  private static KMKeymasterDevice kmDeviceInst;
  private static KMDataStore kmDataStore;
  private static KMRkpDataStore kmRkpDataStore;
  private static KMBootDataStore bootParamsProvider;

  KMAndroidSEApplet() {
    seProvider = (KMSEProvider) new KMAndroidSEProvider();
    repositoryInst = new KMRepository(seProvider.isUpgrading());
    kmRkpDataStore = new KMRkpDataStoreImpl(seProvider);
    decoderInst = new KMDecoder();
    encoderInst = new KMEncoder();
    kmDataStore = new KMKeymintDataStore(seProvider, !(kmDevice == KM_100) /* Factory attest flag*/);
    bootParamsProvider = new KMBootParamsProviderImpl((KMKeymintDataStore) kmDataStore);
    if (kmDevice == KM_40 || kmDevice == KM_41) {
      kmDeviceInst = new KMKeymasterDevice(seProvider, repositoryInst, encoderInst, decoderInst, kmDataStore,
          bootParamsProvider);
      seProvisionInst = new KMKeymasterProvision(kmDeviceInst, seProvider, decoderInst, repositoryInst, kmDataStore);
    } else {
      kmDeviceInst = new KMKeymintDevice(seProvider, repositoryInst, encoderInst, decoderInst, kmDataStore,
          bootParamsProvider, kmRkpDataStore);
      seProvisionInst = new KMKeymintProvision(kmDeviceInst, seProvider, decoderInst, repositoryInst, kmDataStore,
          kmRkpDataStore);
    }
  }

  /**
   * Installs this applet.
   *
   * @param bArray the array containing installation parameters
   * @param bOffset the starting offset in bArray
   * @param bLength the length in bytes of the parameter data in bArray
   */
  public static void install(byte[] bArray, short bOffset, byte bLength) {
    // TODO Get the specification correctly.
    byte Li = bArray[bOffset]; // Length of AID
    byte Lc = bArray[(short) (bOffset + Li + 1)]; // Length of ControlInfo
    byte La = bArray[(short) (bOffset + Li + Lc + 2)]; // Length of application data
    if (La != 1) {
      ISOException.throwIt(ISO7816.SW_DATA_INVALID);
    }
    kmDevice = bArray[(short) (bOffset + Li + Lc + 3)];
    new KMAndroidSEApplet().register(bArray, (short) (bOffset + 1), bArray[bOffset]);
  }
  
  private boolean isProvisionLocked() {
    short offset = repositoryInst.alloc((short) 1);
    short len = kmDataStore.getData(KMDataStoreConstants.PROVISIONED_LOCKED,
        repositoryInst.getHeap(), offset);
    if (len == 0) {
      return false;
    }
    return ((byte[]) repositoryInst.getHeap())[offset] == 0x01;
  }


  @Override
  public void process(APDU apdu) {
    try {
      // If this is select applet apdu which is selecting this applet then return
      if (apdu.isISOInterindustryCLA()) {
        if (selectingApplet()) {
          return;
        }
      }
      short apduIns = validateApdu(apdu);
      if (((KMAndroidSEProvider) seProvider).isPowerReset(false)) {
        kmDeviceInst.powerReset();
      }

      if (isProvisionLocked()) {
        switch (apduIns) {
        case INS_SET_BOOT_PARAMS_CMD:
          processSetBootParamsCmd(apdu);
          break;

        case INS_SET_BOOT_ENDED_CMD:
          // set the flag to mark boot ended
          byte[] buffer = apdu.getBuffer();
          buffer[0] = 0x01;
          kmDataStore.storeData(KMDataStoreConstants.BOOT_ENDED_STATUS, buffer, (short) 0, (short) 1);
          kmDeviceInst.sendError(apdu, KMError.OK);
          break;

        default:
          kmDeviceInst.process(apdu);
          break;
        }
        return;
      }

      if (apduIns == KMType.INVALID_VALUE) {
        return;
      }
      switch (apduIns) {
      case INS_PROVISION_ATTESTATION_KEY_CMD: // only keymaster
        seProvisionInst.processProvisionAttestationKey(apdu);
        break;
      case INS_PROVISION_ATTESTATION_CERT_DATA_CMD: // only keymaster
        seProvisionInst.processProvisionAttestationCertDataCmd(apdu);
        break;
      case INS_PROVISION_ATTEST_IDS_CMD:
        seProvisionInst.processProvisionAttestIdsCmd(apdu);
        break;

      case INS_PROVISION_PRESHARED_SECRET_CMD:
        seProvisionInst.processProvisionPreSharedSecretCmd(apdu);
        break;

      case INS_GET_PROVISION_STATUS_CMD:
        seProvisionInst.processGetProvisionStatusCmd(apdu);
        break;

      case INS_LOCK_PROVISIONING_CMD:
        seProvisionInst.processLockProvisioningCmd(apdu);
        break;

      case INS_SET_BOOT_PARAMS_CMD:
        processSetBootParamsCmd(apdu);
        break;

      case INS_PROVISION_DEVICE_UNIQUE_KEY_CMD: // only keymint
        seProvisionInst.processProvisionDeviceUniqueKey(apdu);
        break;

      case INS_PROVISION_ADDITIONAL_CERT_CHAIN_CMD:// only keymint
        seProvisionInst.processProvisionAdditionalCertChain(apdu);
        break;

      default:
        kmDeviceInst.process(apdu);
        break;
      }
    } catch (KMException exception) {
      kmDeviceInst.sendError(apdu, KMException.reason());
    } catch (ISOException exp) {
      kmDeviceInst.sendError(apdu, kmDeviceInst.mapISOErrorToKMError(exp.getReason()));
    } catch (CryptoException e) {
      kmDeviceInst.sendError(apdu, kmDeviceInst.mapCryptoErrorToKMError(e.getReason()));
    } catch (Exception e) {
      kmDeviceInst.sendError(apdu, KMError.GENERIC_UNKNOWN_ERROR);
    } finally {
      kmDeviceInst.clean();
    }
  }
  
  @Override
  public void onCleanup() {
  }

  @Override
  public void onConsolidate() {
  }

  @Override
  public void onRestore(Element element) {
//    element.initRead();
//    keymasterState = element.readByte();
//    repositoryInst.onRestore(element);
//    //seProvider.onRestore(element);
//    seProvisionInst.onSave(element);
  }

  @Override
  public Element onSave() {
    short primitiveCount = kmDataStore.getBackupPrimitiveByteCount();
    short objectCount = kmDataStore.getBackupObjectCount();
    
    primitiveCount += kmRkpDataStore.getBackupPrimitiveByteCount();
    objectCount += kmRkpDataStore.getBackupObjectCount();

    // Create element.
    Element element = UpgradeManager.createElement(Element.TYPE_SIMPLE,
      primitiveCount, objectCount);
    
    kmDataStore.onSave(element);
    kmRkpDataStore.onSave(element);
    return element;
  }

  private short validateApdu(APDU apdu) {
    // Read the apdu header and buffer.
    byte[] apduBuffer = apdu.getBuffer();
    short err = kmDeviceInst.validateApduHeader(apdu);
    if (err != KMError.OK) {
      kmDeviceInst.sendError(apdu, err);
      return KMType.INVALID_VALUE;
    }
    return apduBuffer[ISO7816.OFFSET_INS];
  }
  
  private void processSetBootParamsCmd(APDU apdu) {
    short argsProto = KMArray.instance((short) 5);
    
    byte[] scratchPad = apdu.getBuffer();
    // Array of 4 expected arguments
    // Argument 0 Boot Patch level
    KMArray.add(argsProto, (short) 0, KMInteger.exp());
    // Argument 1 Verified Boot Key
    KMArray.add(argsProto, (short) 1, KMByteBlob.exp());
    // Argument 2 Verified Boot Hash
    KMArray.add(argsProto, (short) 2, KMByteBlob.exp());
    // Argument 3 Verified Boot State
    KMArray.add(argsProto, (short) 3, KMEnum.instance(KMType.VERIFIED_BOOT_STATE));
    // Argument 4 Device Locked
    KMArray.add(argsProto, (short) 4, KMEnum.instance(KMType.DEVICE_LOCKED));

    short args = kmDeviceInst.receiveIncoming(apdu, argsProto);

    short bootParam = KMArray.get(args, (short) 0);

    ((KMKeymintDataStore) kmDataStore).setBootPatchLevel(KMInteger.getBuffer(bootParam),
        KMInteger.getStartOff(bootParam),
        KMInteger.length(bootParam));

    bootParam = KMArray.get(args, (short) 1);
    if (KMByteBlob.length(bootParam) > BOOT_KEY_MAX_SIZE) {
      KMException.throwIt(KMError.INVALID_ARGUMENT);
    }
    ((KMKeymintDataStore) kmDataStore).setBootKey(KMByteBlob.getBuffer(bootParam),
        KMByteBlob.getStartOff(bootParam),
        KMByteBlob.length(bootParam));

    bootParam = KMArray.get(args, (short) 2);
    if (KMByteBlob.length(bootParam) > BOOT_HASH_MAX_SIZE) {
      KMException.throwIt(KMError.INVALID_ARGUMENT);
    }
    ((KMKeymintDataStore) kmDataStore).setVerifiedBootHash(KMByteBlob.getBuffer(bootParam),
        KMByteBlob.getStartOff(bootParam),
        KMByteBlob.length(bootParam));

    bootParam = KMArray.get(args, (short) 3);
    byte enumVal = KMEnum.getVal(bootParam);
    ((KMKeymintDataStore) kmDataStore).setBootState(enumVal);

    bootParam = KMArray.get(args, (short) 4);
    enumVal = KMEnum.getVal(bootParam);
    ((KMKeymintDataStore) kmDataStore).setDeviceLocked(enumVal == KMType.DEVICE_LOCKED_TRUE);

    
    // Clear the Computed SharedHmac and Hmac nonce from persistent memory.
    Util.arrayFillNonAtomic(scratchPad, (short) 0, COMPUTED_HMAC_KEY_SIZE, (byte) 0);
    kmDataStore.storeData(KMDataStoreConstants.COMPUTED_HMAC_KEY, scratchPad, (short) 0, COMPUTED_HMAC_KEY_SIZE);
    
    kmDeviceInst.reboot(scratchPad, (short) 0);
    kmDeviceInst.sendError(apdu, KMError.OK);
  }

  @Override
  public void uninstall() {
	kmDeviceInst.onUninstall();
  }
  
  /**
   * Selects this applet.
   *
   * @return Returns true if the keymaster is in correct state
   */
  @Override
  public boolean select() {
	return kmDeviceInst.onSelect();
    
  }

  /**
   * De-selects this applet.
   */
  @Override
  public void deselect() {
	kmDeviceInst.onDeselect();
  }
}

