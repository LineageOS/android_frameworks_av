/*
 * Copyright (C) 2022 The Android Open Source Project
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
#include <media/NdkMediaCrypto.h>
#include <media/NdkMediaDrm.h>
#include "fuzzer/FuzzedDataProvider.h"

constexpr int32_t kMinBytes = 1;
constexpr int32_t kMaxBytes = 256;
constexpr int32_t kMinParamVal = 0;
constexpr int32_t kMaxParamVal = 3;
constexpr int32_t kMediaUUIdSize = sizeof(AMediaUUID);
constexpr int32_t kMinProvisionResponseSize = 0;
constexpr int32_t kMaxProvisionResponseSize = 16;
constexpr int32_t kMessageSize = 16;
constexpr int32_t kMinAPIcase = 0;
constexpr int32_t kMaxdecryptEncryptAPIs = 10;
constexpr int32_t kMaxpropertyAPIs = 3;
constexpr int32_t kMaxsetListenerAPIs = 2;
constexpr int32_t kMaxndkDrmAPIs = 3;
uint8_t signature[kMessageSize];

enum MediaUUID { INVALID_UUID = 0, PSSH_BOX_UUID, CLEARKEY_UUID, kMaxValue = CLEARKEY_UUID };

constexpr uint8_t kCommonPsshBoxUUID[] = {0x10, 0x77, 0xEF, 0xEC, 0xC0, 0xB2, 0x4D, 0x02,
                                          0xAC, 0xE3, 0x3C, 0x1E, 0x52, 0xE2, 0xFB, 0x4B};

constexpr uint8_t kClearKeyUUID[] = {0xE2, 0x71, 0x9D, 0x58, 0xA9, 0x85, 0xB3, 0xC9,
                                     0x78, 0x1A, 0xB0, 0x30, 0xAF, 0x78, 0xD3, 0x0E};

constexpr uint8_t kInvalidUUID[] = {0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80,
                                    0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80};

uint8_t kClearkeyPssh[] = {
        // BMFF box header (4 bytes size + 'pssh')
        0x00, 0x00, 0x00, 0x34, 0x70, 0x73, 0x73, 0x68,
        // full box header (version = 1 flags = 0)
        0x01, 0x00, 0x00, 0x00,
        // system id
        0x10, 0x77, 0xef, 0xec, 0xc0, 0xb2, 0x4d, 0x02,
        0xac, 0xe3, 0x3c, 0x1e, 0x52, 0xe2, 0xfb, 0x4b,
        // number of key ids
        0x00, 0x00, 0x00, 0x01,
        // key id
        0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
        0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
        // size of data, must be zero
        0x00, 0x00, 0x00, 0x00};

std::string kPropertyName = "clientId";
std::string kMimeType[] = {"video/mp4", "audio/mp4"};
std::string kCipherAlgorithm[] = {"AES/CBC/NoPadding", ""};
std::string kMacAlgorithm[] = {"HmacSHA256", ""};

class NdkMediaDrmFuzzer {
  public:
    NdkMediaDrmFuzzer(const uint8_t* data, size_t size) : mFdp(data, size){};
    void invokeNdkDrm();
    static void KeysChangeListener(AMediaDrm* drm, const AMediaDrmSessionId* sessionId,
                                   const AMediaDrmKeyStatus* keysStatus, size_t numKeys,
                                   bool hasNewUsableKey) {
        (void)drm;
        (void)sessionId;
        (void)keysStatus;
        (void)numKeys;
        (void)hasNewUsableKey;
    };

    static void ExpirationUpdateListener(AMediaDrm* drm, const AMediaDrmSessionId* sessionId,
                                         int64_t expiryTimeInMS) {
        (void)drm;
        (void)sessionId;
        (void)expiryTimeInMS;
    };

    static void listener(AMediaDrm* drm, const AMediaDrmSessionId* sessionId,
                         AMediaDrmEventType eventType, int extra, const uint8_t* data,
                         size_t dataSize) {
        (void)drm;
        (void)sessionId;
        (void)eventType;
        (void)extra;
        (void)data;
        (void)dataSize;
    }

  private:
    FuzzedDataProvider mFdp;
    void invokeDrmCreatePlugin();
    void invokeDrmSetListener();
    void invokeDrmPropertyAPI();
    void invokeDrmDecryptEncryptAPI();
    void invokeDrmSecureStopAPI();
    AMediaDrmSessionId mSessionId = {};
    AMediaDrm* mDrm = nullptr;
};

void NdkMediaDrmFuzzer::invokeDrmCreatePlugin() {
    const uint8_t* mediaUUID = nullptr;
    uint32_t uuidEnum = mFdp.ConsumeEnum<MediaUUID>();
    switch (uuidEnum) {
        case INVALID_UUID: {
            mediaUUID = kInvalidUUID;
            break;
        }
        case PSSH_BOX_UUID: {
            mediaUUID = kCommonPsshBoxUUID;
            break;
        }
        case CLEARKEY_UUID:
        default: {
            mediaUUID = kClearKeyUUID;
            break;
        }
    }
    mDrm = AMediaDrm_createByUUID(mediaUUID);
}

void NdkMediaDrmFuzzer::invokeDrmSecureStopAPI() {
    // get maximum number of secure stops
    AMediaDrmSecureStop secureStops;
    size_t numSecureStops = kMaxParamVal;
    // The API behavior could change based on the drm object (clearkey or
    // psshbox) This API detects secure stops msg and release them.
    AMediaDrm_getSecureStops(mDrm, &secureStops, &numSecureStops);
    AMediaDrm_releaseSecureStops(mDrm, &secureStops);
}

void NdkMediaDrmFuzzer::invokeDrmSetListener() {
    int32_t setListenerAPI = mFdp.ConsumeIntegralInRange<size_t>(kMinAPIcase, kMaxsetListenerAPIs);
    switch (setListenerAPI) {
        case 0: {  // set on key change listener
            AMediaDrm_setOnKeysChangeListener(mDrm, KeysChangeListener);
            break;
        }
        case 1: {  // set on expiration on update listener
            AMediaDrm_setOnExpirationUpdateListener(mDrm, ExpirationUpdateListener);
            break;
        }
        case 2:
        default: {  // set on event listener
            AMediaDrm_setOnEventListener(mDrm, listener);
            break;
        }
    }
}

void NdkMediaDrmFuzzer::invokeDrmPropertyAPI() {
    int32_t propertyAPI = mFdp.ConsumeIntegralInRange<size_t>(kMinAPIcase, kMaxpropertyAPIs);
    switch (propertyAPI) {
        case 0: {  // set property byte array
            uint8_t value[kMediaUUIdSize];
            std::string name =
                    mFdp.ConsumeBool() ? kPropertyName : mFdp.ConsumeRandomLengthString(kMaxBytes);
            const char* propertyName = name.c_str();
            AMediaDrm_setPropertyByteArray(mDrm, propertyName, value, sizeof(value));
            break;
        }
        case 1: {  // get property in byte array
            AMediaDrmByteArray array;
            std::string name =
                    mFdp.ConsumeBool() ? kPropertyName : mFdp.ConsumeRandomLengthString(kMaxBytes);
            const char* propertyName = name.c_str();
            AMediaDrm_getPropertyByteArray(mDrm, propertyName, &array);
            break;
        }
        case 2: {  // set string type property
            std::string propertyName = mFdp.ConsumeRandomLengthString(kMaxBytes);
            std::string value = mFdp.ConsumeRandomLengthString(kMaxBytes);
            AMediaDrm_setPropertyString(mDrm, propertyName.c_str(), value.c_str());
            break;
        }
        case 3:
        default: {  //  get property in string
            const char* stringValue = nullptr;
            std::string propertyName = mFdp.ConsumeRandomLengthString(kMaxBytes);
            AMediaDrm_getPropertyString(mDrm, propertyName.c_str(), &stringValue);
            break;
        }
    }
}

void NdkMediaDrmFuzzer::invokeDrmDecryptEncryptAPI() {
    int32_t decryptEncryptAPI =
            mFdp.ConsumeIntegralInRange<size_t>(kMinAPIcase, kMaxdecryptEncryptAPIs);
    switch (decryptEncryptAPI) {
        case 0: {  // Check if crypto scheme is supported
            std::string mimeType = mFdp.ConsumeBool() ? mFdp.PickValueInArray(kMimeType)
                                                      : mFdp.ConsumeRandomLengthString(kMaxBytes);
            AMediaDrm_isCryptoSchemeSupported(kClearKeyUUID, mimeType.c_str());
            break;
        }
        case 1: {  // get a provision request byte array
            const uint8_t* legacyRequest;
            size_t legacyRequestSize = 1;
            const char* legacyDefaultUrl;
            AMediaDrm_getProvisionRequest(mDrm, &legacyRequest, &legacyRequestSize,
                                          &legacyDefaultUrl);
            break;
        }
        case 2: {  // provide a response to the DRM engine plugin
            const int32_t provisionresponseSize = mFdp.ConsumeIntegralInRange<size_t>(
                    kMinProvisionResponseSize, kMaxProvisionResponseSize);
            uint8_t provisionResponse[provisionresponseSize];
            AMediaDrm_provideProvisionResponse(mDrm, provisionResponse, sizeof(provisionResponse));
            break;
        }
        case 3: {  // get key request
            const uint8_t* keyRequest = nullptr;
            size_t keyRequestSize = 0;
            std::string mimeType = mFdp.ConsumeBool() ? mFdp.PickValueInArray(kMimeType)
                                                      : mFdp.ConsumeRandomLengthString(kMaxBytes);
            size_t numOptionalParameters =
                    mFdp.ConsumeIntegralInRange<size_t>(kMinParamVal, kMaxParamVal);
            AMediaDrmKeyValue optionalParameters[numOptionalParameters];
            std::string keys[numOptionalParameters];
            std::string values[numOptionalParameters];
            for (int i = 0; i < numOptionalParameters; ++i) {
                keys[i] = mFdp.ConsumeRandomLengthString(kMaxBytes);
                values[i] = mFdp.ConsumeRandomLengthString(kMaxBytes);
                optionalParameters[i].mKey = keys[i].c_str();
                optionalParameters[i].mValue = values[i].c_str();
            }
            AMediaDrmKeyType keyType = (AMediaDrmKeyType)mFdp.ConsumeIntegralInRange<int>(
                    KEY_TYPE_STREAMING, KEY_TYPE_RELEASE);
            AMediaDrm_getKeyRequest(mDrm, &mSessionId, kClearkeyPssh, sizeof(kClearkeyPssh),
                                    mimeType.c_str(), keyType, optionalParameters,
                                    numOptionalParameters, &keyRequest, &keyRequestSize);
            break;
        }
        case 4: {  // query key status
            size_t numPairs = mFdp.ConsumeIntegralInRange<size_t>(kMinParamVal, kMaxParamVal);
            AMediaDrmKeyValue keyStatus[numPairs];
            AMediaDrm_queryKeyStatus(mDrm, &mSessionId, keyStatus, &numPairs);
            break;
        }
        case 5: {  // provide key response
            std::string key = mFdp.ConsumeRandomLengthString(kMaxBytes);
            const char* keyResponse = key.c_str();
            AMediaDrmKeySetId keySetId;
            AMediaDrm_provideKeyResponse(mDrm, &mSessionId,
                                         reinterpret_cast<const uint8_t*>(keyResponse),
                                         sizeof(keyResponse), &keySetId);
            break;
        }
        case 6: {  // restore key
            AMediaDrmKeySetId keySetId;
            AMediaDrm_restoreKeys(mDrm, &mSessionId, &keySetId);
            break;
        }

        case 7: {  // Check signature verification using the specified Algorithm
            std::string algorithm = kMacAlgorithm[mFdp.ConsumeBool()];
            std::vector<uint8_t> keyId = mFdp.ConsumeBytes<uint8_t>(
                    mFdp.ConsumeIntegralInRange<size_t>(kMinBytes, kMaxBytes));
            std::vector<uint8_t> message = mFdp.ConsumeBytes<uint8_t>(
                    mFdp.ConsumeIntegralInRange<size_t>(kMinBytes, kMaxBytes));
            AMediaDrm_verify(mDrm, &mSessionId, algorithm.c_str(), keyId.data(), message.data(),
                             message.size(), signature, sizeof(signature));
            break;
        }
        case 8: {  // Generate a signature using the specified Algorithm
            std::string algorithm = kMacAlgorithm[mFdp.ConsumeBool()];
            std::vector<uint8_t> keyId = mFdp.ConsumeBytes<uint8_t>(
                    mFdp.ConsumeIntegralInRange<size_t>(kMinBytes, kMaxBytes));
            std::vector<uint8_t> message = mFdp.ConsumeBytes<uint8_t>(
                    mFdp.ConsumeIntegralInRange<size_t>(kMinBytes, kMaxBytes));
            size_t signatureSize = sizeof(signature);
            AMediaDrm_sign(mDrm, &mSessionId, algorithm.c_str(), keyId.data(), message.data(),
                           message.size(), signature, &signatureSize);
            break;
        }
        case 9: {  // Decrypt the data using algorithm
            std::string algorithm = kCipherAlgorithm[mFdp.ConsumeBool()];
            std::vector<uint8_t> keyId = mFdp.ConsumeBytes<uint8_t>(
                    mFdp.ConsumeIntegralInRange<size_t>(kMinBytes, kMaxBytes));
            std::vector<uint8_t> iv = mFdp.ConsumeBytes<uint8_t>(
                    mFdp.ConsumeIntegralInRange<size_t>(kMinBytes, kMaxBytes));
            std::vector<uint8_t> input = mFdp.ConsumeBytes<uint8_t>(
                    mFdp.ConsumeIntegralInRange<size_t>(kMinBytes, kMaxBytes));
            uint8_t output[kMessageSize];
            AMediaDrm_decrypt(mDrm, &mSessionId, algorithm.c_str(), keyId.data(), iv.data(),
                              input.data(), output, input.size());
            break;
        }
        case 10:
        default: {  // Encrypt the data using algorithm
            std::string algorithm = kCipherAlgorithm[mFdp.ConsumeBool()];
            std::vector<uint8_t> keyId = mFdp.ConsumeBytes<uint8_t>(
                    mFdp.ConsumeIntegralInRange<size_t>(kMinBytes, kMaxBytes));
            std::vector<uint8_t> iv = mFdp.ConsumeBytes<uint8_t>(
                    mFdp.ConsumeIntegralInRange<size_t>(kMinBytes, kMaxBytes));
            std::vector<uint8_t> input = mFdp.ConsumeBytes<uint8_t>(
                    mFdp.ConsumeIntegralInRange<size_t>(kMinBytes, kMaxBytes));
            uint8_t output[kMessageSize];
            AMediaDrm_encrypt(mDrm, &mSessionId, algorithm.c_str(), keyId.data(), iv.data(),
                              input.data(), output, input.size());
            break;
        }
    }
    AMediaDrm_removeKeys(mDrm, &mSessionId);
}

void NdkMediaDrmFuzzer::invokeNdkDrm() {
    while (mFdp.remaining_bytes() > 0) {
        // The API is called at start as it creates a AMediaDrm Object.
        // mDrm AMediaDrm object is used in the below APIs.
        invokeDrmCreatePlugin();
        if (mDrm) {
            // The API opens session and returns "mSessionId" session Id.
            // "mSessionId" is required in the below APIs.
            AMediaDrm_openSession(mDrm, &mSessionId);
            int32_t ndkDrmAPI = mFdp.ConsumeIntegralInRange<size_t>(kMinAPIcase, kMaxndkDrmAPIs);
            switch (ndkDrmAPI) {
                case 0: {
                    invokeDrmDecryptEncryptAPI();
                    break;
                }
                case 1: {
                    invokeDrmPropertyAPI();
                    break;
                }
                case 2: {
                    invokeDrmSetListener();
                    break;
                }
                case 3:
                default: {
                    invokeDrmSecureStopAPI();
                    break;
                }
            }
            AMediaDrm_closeSession(mDrm, &mSessionId);
            AMediaDrm_release(mDrm);
        }
    }
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    NdkMediaDrmFuzzer ndkMediaDrmFuzzer(data, size);
    ndkMediaDrmFuzzer.invokeNdkDrm();
    return 0;
}
