/******************************************************************************
 *
 * Copyright (C) 2020 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 *****************************************************************************
 * Originally developed and contributed by Ittiam Systems Pvt. Ltd, Bangalore
 */

#include <binder/MemoryDealer.h>
#include <hidlmemory/FrameworkUtils.h>
#include <mediadrm/CryptoHal.h>
#include <mediadrm/DrmHal.h>
#include <utils/String8.h>
#include "fuzzer/FuzzedDataProvider.h"

#define AES_BLOCK_SIZE 16
#define UNUSED_PARAM __attribute__((unused))

using namespace std;
using namespace android;
using android::hardware::fromHeap;
using ::android::os::PersistableBundle;
using drm::V1_0::BufferType;

enum {
    INVALID_UUID = 0,
    PSSH_BOX_UUID,
    CLEARKEY_UUID,
};

static const uint8_t kInvalidUUID[16] = {0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80,
                                         0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80};

static const uint8_t kCommonPsshBoxUUID[16] = {0x10, 0x77, 0xEF, 0xEC, 0xC0, 0xB2, 0x4D, 0x02,
                                               0xAC, 0xE3, 0x3C, 0x1E, 0x52, 0xE2, 0xFB, 0x4B};

static const uint8_t kClearKeyUUID[16] = {0xE2, 0x71, 0x9D, 0x58, 0xA9, 0x85, 0xB3, 0xC9,
                                          0x78, 0x1A, 0xB0, 0x30, 0xAF, 0x78, 0xD3, 0x0E};

static const uint32_t kUUID[] = {INVALID_UUID, PSSH_BOX_UUID, CLEARKEY_UUID};

const DrmPlugin::SecurityLevel kSecurityLevel[] = {
    DrmPlugin::kSecurityLevelUnknown,        DrmPlugin::kSecurityLevelMax,
    DrmPlugin::kSecurityLevelSwSecureCrypto, DrmPlugin::kSecurityLevelSwSecureDecode,
    DrmPlugin::kSecurityLevelHwSecureCrypto, DrmPlugin::kSecurityLevelHwSecureDecode,
    DrmPlugin::kSecurityLevelHwSecureAll};

const char *kMimeType[] = {"video/mp4",   "video/mpeg",    "video/x-flv",  "video/mj2",
                           "video/3gp2",  "video/3gpp",    "video/3gpp2",  "audio/mp4",
                           "audio/mpeg",  "audio/aac",     "audio/3gp2",   "audio/3gpp",
                           "audio/3gpp2", "video/unknown", "audio/unknown"};

const DrmPlugin::KeyType kKeyType[] = {DrmPlugin::kKeyType_Offline, DrmPlugin::kKeyType_Streaming,
                                       DrmPlugin::kKeyType_Release};

const CryptoPlugin::Mode kCryptoMode[] = {CryptoPlugin::kMode_Unencrypted,
                                          CryptoPlugin::kMode_AES_CTR, CryptoPlugin::kMode_AES_WV,
                                          CryptoPlugin::kMode_AES_CBC};

const char *kCipherAlgorithm[] = {"AES/CBC/NoPadding", ""};
const char *kMacAlgorithm[] = {"HmacSHA256", ""};
const char *kRSAAlgorithm[] = {"RSASSA-PSS-SHA1", ""};
const size_t kNumSecurityLevel = size(kSecurityLevel);
const size_t kNumMimeType = size(kMimeType);
const size_t kNumKeyType = size(kKeyType);
const size_t kNumCryptoMode = size(kCryptoMode);
const size_t kNumUUID = size(kUUID);
const size_t kMaxStringLength = 100;
const size_t kMaxSubSamples = 10;
const size_t kMaxNumBytes = 1000;

struct DrmListener : virtual public IDrmClient {
   public:
    void sendEvent(DrmPlugin::EventType eventType UNUSED_PARAM,
                   const hardware::hidl_vec<uint8_t> &sessionId UNUSED_PARAM,
                   const hardware::hidl_vec<uint8_t> &data UNUSED_PARAM) override {}

    void sendExpirationUpdate(const hardware::hidl_vec<uint8_t> &sessionId UNUSED_PARAM,
                              int64_t expiryTimeInMS UNUSED_PARAM) override {}

    void sendKeysChange(const hardware::hidl_vec<uint8_t> &sessionId UNUSED_PARAM,
                        const std::vector<DrmKeyStatus> &keyStatusList UNUSED_PARAM,
                        bool hasNewUsableKey UNUSED_PARAM) override {}

    void sendSessionLostState(const hardware::hidl_vec<uint8_t> &) override {}
    DrmListener() {}

   private:
    DISALLOW_EVIL_CONSTRUCTORS(DrmListener);
};

class DrmFuzzer {
   public:
    void process(const uint8_t *data, size_t size);

   private:
    void invokeDrm(const uint8_t *data, size_t size);
    bool initDrm();
    void invokeDrmCreatePlugin();
    void invokeDrmOpenSession();
    void invokeDrmSetListener();
    void invokeDrmSetAlgorithmAPI();
    void invokeDrmPropertyAPI();
    void invokeDrmDecryptEncryptAPI(const uint8_t *data, size_t size);
    void invokeDrmSecureStopAPI();
    void invokeDrmOfflineLicenseAPI();
    void invokeDrmCloseSession();
    void invokeDrmDestroyPlugin();
    void invokeCrypto(const uint8_t *data);
    bool initCrypto();
    void invokeCryptoCreatePlugin();
    void invokeCryptoDecrypt(const uint8_t *data);
    void invokeCryptoDestroyPlugin();
    sp<DrmHal> mDrm = nullptr;
    sp<CryptoHal> mCrypto = nullptr;
    Vector<uint8_t> mSessionId = {};
    FuzzedDataProvider *mFuzzedDataProvider = nullptr;
};

bool DrmFuzzer::initDrm() {
    mDrm = new DrmHal();
    if (!mDrm) {
        return false;
    }
    return true;
}

void DrmFuzzer::invokeDrmCreatePlugin() {
    mDrm->initCheck();
    String8 packageName(mFuzzedDataProvider->ConsumeRandomLengthString(kMaxStringLength).c_str());
    uint32_t uuidEnum = kUUID[mFuzzedDataProvider->ConsumeIntegralInRange<size_t>(0, kNumUUID - 1)];
    switch (uuidEnum) {
        case INVALID_UUID:
            mDrm->createPlugin(kInvalidUUID, packageName);
            break;
        case PSSH_BOX_UUID:
            mDrm->createPlugin(kCommonPsshBoxUUID, packageName);
            break;
        case CLEARKEY_UUID:
            mDrm->createPlugin(kClearKeyUUID, packageName);
            break;
        default:
            break;
    }
}

void DrmFuzzer::invokeDrmDestroyPlugin() { mDrm->destroyPlugin(); }

void DrmFuzzer::invokeDrmOpenSession() {
    DrmPlugin::SecurityLevel securityLevel;
    bool shouldPassRandomSecurityLevel = mFuzzedDataProvider->ConsumeBool();
    if (shouldPassRandomSecurityLevel) {
        securityLevel =
            static_cast<DrmPlugin::SecurityLevel>(mFuzzedDataProvider->ConsumeIntegral<size_t>());
    } else {
        securityLevel = kSecurityLevel[mFuzzedDataProvider->ConsumeIntegralInRange<size_t>(
            0, kNumSecurityLevel - 1)];
    }
    mDrm->openSession(securityLevel, mSessionId);
}

void DrmFuzzer::invokeDrmCloseSession() { mDrm->closeSession(mSessionId); }

void DrmFuzzer::invokeDrmSetListener() {
    sp<DrmListener> listener = new DrmListener();
    mDrm->setListener(listener);
}

void DrmFuzzer::invokeDrmSetAlgorithmAPI() {
    mDrm->setCipherAlgorithm(mSessionId,
                             String8(kCipherAlgorithm[mFuzzedDataProvider->ConsumeBool()]));
    mDrm->setMacAlgorithm(mSessionId, String8(kMacAlgorithm[mFuzzedDataProvider->ConsumeBool()]));
}

void DrmFuzzer::invokeDrmPropertyAPI() {
    mDrm->setPropertyString(String8("property"), String8("value"));
    String8 stringValue;
    mDrm->getPropertyString(String8("property"), stringValue);
    Vector<uint8_t> value = {};
    mDrm->setPropertyByteArray(String8("property"), value);
    Vector<uint8_t> byteValue;
    mDrm->getPropertyByteArray(String8("property"), byteValue);
}

void DrmFuzzer::invokeDrmDecryptEncryptAPI(const uint8_t *data, size_t size) {
    uint32_t openSessions = 0;
    uint32_t maxSessions = 0;
    mDrm->getNumberOfSessions(&openSessions, &maxSessions);

    DrmPlugin::HdcpLevel connected;
    DrmPlugin::HdcpLevel max;
    mDrm->getHdcpLevels(&connected, &max);

    DrmPlugin::SecurityLevel securityLevel;
    mDrm->getSecurityLevel(mSessionId, &securityLevel);

    // isCryptoSchemeSupported() shall fill isSupported
    bool isSupported;
    String8 mimeType(
        kMimeType[mFuzzedDataProvider->ConsumeIntegralInRange<size_t>(0, kNumMimeType - 1)]);
    mDrm->isCryptoSchemeSupported(kClearKeyUUID, mimeType, securityLevel, &isSupported);

    // getProvisionRequest() shall fill legacyRequest and legacyDefaultUrl
    String8 certificateType(
        mFuzzedDataProvider->ConsumeRandomLengthString(kMaxStringLength).c_str());
    String8 certAuthority(mFuzzedDataProvider->ConsumeRandomLengthString(kMaxStringLength).c_str());
    Vector<uint8_t> legacyRequest = {};
    String8 legacyDefaultUrl;
    mDrm->getProvisionRequest(certificateType, certAuthority, legacyRequest, legacyDefaultUrl);

    // provideProvisionResponse() shall fill certificate and wrappedKey
    Vector<uint8_t> provisionResponse = {};
    Vector<uint8_t> certificate = {};
    Vector<uint8_t> wrappedKey = {};
    mDrm->provideProvisionResponse(provisionResponse, certificate, wrappedKey);

    // getKeyRequest() shall fill keyRequest, defaultUrl and keyRequestType
    Vector<uint8_t> initData = {};
    initData.appendArray(data, size);
    DrmPlugin::KeyType keyType;
    bool shouldPassRandomKeyType = mFuzzedDataProvider->ConsumeBool();
    if (shouldPassRandomKeyType) {
        keyType = static_cast<DrmPlugin::KeyType>(mFuzzedDataProvider->ConsumeIntegral<size_t>());
    } else {
        keyType = kKeyType[mFuzzedDataProvider->ConsumeIntegralInRange<size_t>(0, kNumKeyType - 1)];
    }
    KeyedVector<String8, String8> mdOptionalParameters = {};
    Vector<uint8_t> keyRequest = {};
    String8 defaultUrl;
    DrmPlugin::KeyRequestType keyRequestType;
    mDrm->getKeyRequest(mSessionId, initData, mimeType, keyType, mdOptionalParameters, keyRequest,
                        defaultUrl, &keyRequestType);

    // provideKeyResponse() shall fill keySetId
    Vector<uint8_t> keyResponse = {};
    keyResponse.appendArray(data, size);
    Vector<uint8_t> keySetId = {};
    mDrm->provideKeyResponse(mSessionId, keyResponse, keySetId);

    // restoreKeys
    mDrm->restoreKeys(mSessionId, keySetId);

    // queryKeyStatus() shall fill infoMap
    KeyedVector<String8, String8> infoMap = {};
    mDrm->queryKeyStatus(mSessionId, infoMap);

    // decrypt() shall fill outputVec
    Vector<uint8_t> keyIdVec = {};
    keyIdVec.appendArray(data, size);

    Vector<uint8_t> inputVec = {};
    inputVec.appendArray(data, size);

    Vector<uint8_t> ivVec = {};
    ivVec.appendArray(data, size);

    Vector<uint8_t> outputVec = {};
    mDrm->decrypt(mSessionId, keyIdVec, inputVec, ivVec, outputVec);

    // encrypt() shall fill outputVec
    mDrm->encrypt(mSessionId, keyIdVec, inputVec, ivVec, outputVec);

    // sign() shall fill signature
    Vector<uint8_t> message = {};
    message.appendArray(data, size);
    Vector<uint8_t> signature = {};
    mDrm->sign(mSessionId, keyIdVec, message, signature);

    // verify() shall fill match
    bool match;
    mDrm->verify(mSessionId, keyIdVec, message, signature, match);

    // signRSA() shall fill signature
    mDrm->signRSA(mSessionId, String8(kRSAAlgorithm[mFuzzedDataProvider->ConsumeBool()]), message,
                  wrappedKey, signature);

    mDrm->removeKeys(mSessionId);
}

void DrmFuzzer::invokeDrmSecureStopAPI() {
    // getSecureStops() shall fill secureStops
    List<Vector<uint8_t>> secureStops = {};
    mDrm->getSecureStops(secureStops);

    // getSecureStopIds() shall fill secureStopIds
    List<Vector<uint8_t>> secureStopIds = {};
    mDrm->getSecureStopIds(secureStopIds);

    // getSecureStop() shall fill secureStop
    Vector<uint8_t> ssid = {};
    Vector<uint8_t> secureStop = {};
    mDrm->getSecureStop(ssid, secureStop);

    mDrm->removeSecureStop(ssid);

    mDrm->releaseSecureStops(ssid);

    mDrm->removeAllSecureStops();
}

void DrmFuzzer::invokeDrmOfflineLicenseAPI() {
    // getOfflineLicenseKeySetIds() shall keySetIds
    List<Vector<uint8_t>> keySetIds = {};
    mDrm->getOfflineLicenseKeySetIds(keySetIds);

    // getOfflineLicenseState() shall fill state
    Vector<uint8_t> const keySetIdOfflineLicense = {};
    DrmPlugin::OfflineLicenseState state;
    mDrm->getOfflineLicenseState(keySetIdOfflineLicense, &state);

    mDrm->removeOfflineLicense(keySetIdOfflineLicense);
}

bool DrmFuzzer::initCrypto() {
    mCrypto = new CryptoHal();
    if (!mCrypto) {
        return false;
    }
    return true;
}

void DrmFuzzer::invokeCryptoCreatePlugin() {
    mCrypto->initCheck();

    mCrypto->isCryptoSchemeSupported(kClearKeyUUID);
    mCrypto->createPlugin(kClearKeyUUID, NULL, 0);
}

void DrmFuzzer::invokeCryptoDestroyPlugin() { mCrypto->destroyPlugin(); }

void DrmFuzzer::invokeCryptoDecrypt(const uint8_t *data) {
    mCrypto->requiresSecureDecoderComponent(
        kMimeType[mFuzzedDataProvider->ConsumeIntegralInRange<size_t>(0, kNumMimeType - 1)]);

    uint32_t width = mFuzzedDataProvider->ConsumeIntegral<uint32_t>();
    uint32_t height = mFuzzedDataProvider->ConsumeIntegral<uint32_t>();
    mCrypto->notifyResolution(width, height);

    mCrypto->setMediaDrmSession(mSessionId);

    const CryptoPlugin::Pattern pattern = {0, 0};

    size_t totalSize = 0;
    size_t numSubSamples = mFuzzedDataProvider->ConsumeIntegralInRange<size_t>(1, kMaxSubSamples);

    CryptoPlugin::SubSample subSamples[numSubSamples];

    for (size_t i = 0; i < numSubSamples; ++i) {
        uint32_t clearBytes =
            mFuzzedDataProvider->ConsumeIntegralInRange<uint32_t>(1, kMaxNumBytes);
        uint32_t encryptedBytes =
            mFuzzedDataProvider->ConsumeIntegralInRange<uint32_t>(1, kMaxNumBytes);
        subSamples[i].mNumBytesOfClearData = clearBytes;
        subSamples[i].mNumBytesOfEncryptedData = encryptedBytes;
        totalSize += subSamples[i].mNumBytesOfClearData;
        totalSize += subSamples[i].mNumBytesOfEncryptedData;
    }

    size_t heapSize = totalSize * 2;
    sp<MemoryDealer> dealer = new MemoryDealer(heapSize, "DrmFuzzerMemory");
    if (!dealer) {
        return;
    }

    sp<HidlMemory> heap = fromHeap(dealer->getMemoryHeap());
    if (!heap) {
        return;
    }
    int heapSeqNum = mCrypto->setHeap(heap);
    if (heapSeqNum < 0) {
        return;
    }

    const size_t segmentIndex = 0;
    const uint8_t keyId[AES_BLOCK_SIZE] = {};
    memcpy((void *)keyId, data, AES_BLOCK_SIZE);

    const uint8_t iv[AES_BLOCK_SIZE] = {};
    memset((void *)iv, 0, AES_BLOCK_SIZE);

    const SharedBuffer sourceBuffer = {.bufferId = segmentIndex, .offset = 0, .size = totalSize};

    const DestinationBuffer destBuffer = {
        .type = BufferType::SHARED_MEMORY,
        {.bufferId = segmentIndex, .offset = totalSize, .size = totalSize},
        .secureMemory = nullptr};

    const uint64_t offset = 0;
    AString *errorDetailMsg = nullptr;
    CryptoPlugin::Mode mode;
    bool shouldPassRandomCryptoMode = mFuzzedDataProvider->ConsumeBool();
    if (shouldPassRandomCryptoMode) {
        mode = static_cast<CryptoPlugin::Mode>(mFuzzedDataProvider->ConsumeIntegral<size_t>());
    } else {
        mode =
            kCryptoMode[mFuzzedDataProvider->ConsumeIntegralInRange<size_t>(0, kNumCryptoMode - 1)];
    }
    mCrypto->decrypt(keyId, iv, mode, pattern, sourceBuffer, offset, subSamples, numSubSamples,
                     destBuffer, errorDetailMsg);

    if (heapSeqNum >= 0) {
        mCrypto->unsetHeap(heapSeqNum);
    }
    heap.clear();
}

void DrmFuzzer::invokeDrm(const uint8_t *data, size_t size) {
    if (!initDrm()) {
        return;
    }
    invokeDrmCreatePlugin();
    invokeDrmOpenSession();
    invokeDrmSetAlgorithmAPI();
    invokeDrmSetListener();
    invokeDrmPropertyAPI();
    invokeDrmDecryptEncryptAPI(data, size);
    invokeDrmSecureStopAPI();
    invokeDrmOfflineLicenseAPI();
    invokeDrmCloseSession();
    invokeDrmDestroyPlugin();
}

void DrmFuzzer::invokeCrypto(const uint8_t *data) {
    if (!initCrypto()) {
        return;
    }
    invokeCryptoCreatePlugin();
    invokeCryptoDecrypt(data);
    invokeCryptoDestroyPlugin();
}

void DrmFuzzer::process(const uint8_t *data, size_t size) {
    mFuzzedDataProvider = new FuzzedDataProvider(data, size);
    invokeDrm(data, size);
    invokeCrypto(data);
    delete mFuzzedDataProvider;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < AES_BLOCK_SIZE) {
        return 0;
    }
    DrmFuzzer drmFuzzer;
    drmFuzzer.process(data, size);
    return 0;
}
