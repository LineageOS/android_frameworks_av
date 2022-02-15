/*
 * Copyright (C) 2021 The Android Open Source Project
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
 */

#include <include/CreatePluginFactories.h>

#include <android/hidl/allocator/1.0/IAllocator.h>
#include <fuzzer/FuzzedDataProvider.h>
#include <hidlmemory/mapping.h>
#include <include/ClearKeyDrmProperties.h>
#include <include/CryptoFactory.h>
#include <include/CryptoPlugin.h>
#include <include/DrmPlugin.h>
#include <utils/Log.h>
#include <utils/String8.h>

namespace drm = ::android::hardware::drm;
using namespace std;
using namespace android;
using ::android::sp;
using ::android::hardware::hidl_array;
using ::android::hardware::hidl_memory;
using ::android::hardware::hidl_string;
using ::android::hardware::hidl_vec;
using ::android::hardware::Return;
using ::android::hidl::allocator::V1_0::IAllocator;
using ::android::hidl::memory::V1_0::IMemory;
using drm::V1_0::BufferType;
using drm::V1_0::DestinationBuffer;
using drm::V1_0::EventType;
using drm::V1_0::ICryptoPlugin;
using drm::V1_0::IDrmPlugin;
using drm::V1_0::IDrmPluginListener;
using drm::V1_0::KeyedVector;
using drm::V1_0::KeyStatus;
using drm::V1_0::KeyStatusType;
using drm::V1_0::KeyType;
using drm::V1_0::Mode;
using drm::V1_0::Pattern;
using drm::V1_0::SecureStop;
using drm::V1_0::SharedBuffer;
using drm::V1_0::Status;
using drm::V1_0::SubSample;
using drm::V1_1::DrmMetricGroup;
using drm::V1_1::HdcpLevel;
using drm::V1_1::SecureStopRelease;
using drm::V1_1::SecurityLevel;
using drm::V1_2::KeySetId;
using drm::V1_2::OfflineLicenseState;
using drm::V1_4::clearkey::ICryptoFactory;
using drm::V1_4::clearkey::IDrmFactory;
using drm::V1_4::clearkey::kAlgorithmsKey;
using drm::V1_4::clearkey::kClientIdKey;
using drm::V1_4::clearkey::kDeviceIdKey;
using drm::V1_4::clearkey::kDrmErrorTestKey;
using drm::V1_4::clearkey::kListenerTestSupportKey;
using drm::V1_4::clearkey::kMetricsKey;
using drm::V1_4::clearkey::kPluginDescriptionKey;
using drm::V1_4::clearkey::kVendorKey;
using drm::V1_4::clearkey::kVersionKey;

typedef ::android::hardware::hidl_vec<uint8_t> SessionId;
typedef ::android::hardware::hidl_vec<uint8_t> SecureStopId;

static const uint8_t kInvalidUUID[] = {0x10, 0x20, 0x30, 0x40, 0x50, 0x60,
                                       0x70, 0x80, 0x10, 0x20, 0x30, 0x40,
                                       0x50, 0x60, 0x70, 0x80};

static const uint8_t kClearKeyUUID[] = {0xE2, 0x71, 0x9D, 0x58, 0xA9, 0x85,
                                        0xB3, 0xC9, 0x78, 0x1A, 0xB0, 0x30,
                                        0xAF, 0x78, 0xD3, 0x0E};

const SecurityLevel kSecurityLevel[] = {
    SecurityLevel::UNKNOWN,          SecurityLevel::SW_SECURE_CRYPTO,
    SecurityLevel::SW_SECURE_DECODE, SecurityLevel::HW_SECURE_CRYPTO,
    SecurityLevel::HW_SECURE_DECODE, SecurityLevel::HW_SECURE_ALL};

const char *kMimeType[] = {
    "video/mp4",  "video/mpeg",  "video/x-flv",   "video/mj2",    "video/3gp2",
    "video/3gpp", "video/3gpp2", "audio/mp4",     "audio/mpeg",   "audio/aac",
    "audio/3gp2", "audio/3gpp",  "audio/3gpp2",   "audio/webm",   "video/webm",
    "webm",       "cenc",        "video/unknown", "audio/unknown"};

const char *kCipherAlgorithm[] = {"AES/CBC/NoPadding", ""};

const char *kMacAlgorithm[] = {"HmacSHA256", ""};

const char *kRSAAlgorithm[] = {"RSASSA-PSS-SHA1", ""};

const std::string kProperty[] = {kVendorKey,
                                 kVersionKey,
                                 kPluginDescriptionKey,
                                 kAlgorithmsKey,
                                 kListenerTestSupportKey,
                                 kDrmErrorTestKey,
                                 kDeviceIdKey,
                                 kClientIdKey,
                                 kMetricsKey,
                                 "placeholder"};

const KeyType kKeyType[] = {KeyType::OFFLINE, KeyType::STREAMING,
                            KeyType::RELEASE};

const Mode kCryptoMode[] = {Mode::UNENCRYPTED, Mode::AES_CTR, Mode::AES_CBC_CTS,
                            Mode::AES_CBC};

const hidl_vec<uint8_t> validInitData = {
    // BMFF box header (4 bytes size + 'pssh')
    0x00, 0x00, 0x00, 0x34, 0x70, 0x73, 0x73, 0x68,
    // full box header (version = 1 flags = 0)
    0x01, 0x00, 0x00, 0x00,
    // system id
    0x10, 0x77, 0xef, 0xec, 0xc0, 0xb2, 0x4d, 0x02, 0xac, 0xe3, 0x3c, 0x1e,
    0x52, 0xe2, 0xfb, 0x4b,
    // number of key ids
    0x00, 0x00, 0x00, 0x01,
    // key id
    0x60, 0x06, 0x1e, 0x01, 0x7e, 0x47, 0x7e, 0x87, 0x7e, 0x57, 0xd0, 0x0d,
    0x1e, 0xd0, 0x0d, 0x1e,
    // size of data, must be zero
    0x00, 0x00, 0x00, 0x00};

const hidl_vec<uint8_t> validKeyResponse = {
    0x7b, 0x22, 0x6b, 0x65, 0x79, 0x73, 0x22, 0x3a, 0x5b, 0x7b, 0x22,
    0x6b, 0x74, 0x79, 0x22, 0x3a, 0x22, 0x6f, 0x63, 0x74, 0x22, 0x2c,
    0x22, 0x6b, 0x69, 0x64, 0x22, 0x3a, 0x22, 0x59, 0x41, 0x59, 0x65,
    0x41, 0x58, 0x35, 0x48, 0x66, 0x6f, 0x64, 0x2d, 0x56, 0x39, 0x41,
    0x4e, 0x48, 0x74, 0x41, 0x4e, 0x48, 0x67, 0x22, 0x2c, 0x22, 0x6b,
    0x22, 0x3a, 0x22, 0x47, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x54, 0x65,
    0x73, 0x74, 0x4b, 0x65, 0x79, 0x42, 0x61, 0x73, 0x65, 0x36, 0x34,
    0x67, 0x67, 0x67, 0x22, 0x7d, 0x5d, 0x7d, 0x0a};

const size_t kAESBlockSize = 16;
const size_t kMaxStringLength = 100;
const size_t kMaxSubSamples = 10;
const size_t kMaxNumBytes = 1000;
const size_t kSegmentIndex = 0;

template <typename T, size_t size>
T getValueFromArray(FuzzedDataProvider *fdp, const T (&arr)[size]) {
  return arr[fdp->ConsumeIntegralInRange<int32_t>(0, size - 1)];
}

class TestDrmPluginListener : public IDrmPluginListener {
public:
  TestDrmPluginListener() {}
  virtual ~TestDrmPluginListener() {}

  virtual Return<void> sendEvent(EventType /*eventType*/,
                                 const hidl_vec<uint8_t> & /*sessionId*/,
                                 const hidl_vec<uint8_t> & /*data*/) override {
    return Return<void>();
  }

  virtual Return<void>
  sendExpirationUpdate(const hidl_vec<uint8_t> & /*sessionId*/,
                       int64_t /*expiryTimeInMS*/) override {
    return Return<void>();
  }

  virtual Return<void>
  sendKeysChange(const hidl_vec<uint8_t> & /*sessionId*/,
                 const hidl_vec<KeyStatus> & /*keyStatusList*/,
                 bool /*hasNewUsableKey*/) override {
    return Return<void>();
  }
};

class ClearKeyFuzzer {
public:
  ~ClearKeyFuzzer() { deInit(); }
  bool init();
  void process(const uint8_t *data, size_t size);

private:
  void deInit();
  void invokeDrmPlugin(const uint8_t *data, size_t size);
  void invokeCryptoPlugin(const uint8_t *data);
  void invokeDrm(const uint8_t *data, size_t size);
  void invokeCrypto(const uint8_t *data);
  void invokeDrmDecryptEncryptAPI(const uint8_t *data, size_t size);
  bool invokeDrmFactory();
  bool invokeCryptoFactory();
  void invokeDrmV1_4API();
  void invokeDrmSetAlgorithmAPI();
  void invokeDrmPropertyAPI();
  void invokeDrmSecureStopAPI();
  void invokeDrmOfflineLicenseAPI(const uint8_t *data, size_t size);
  SessionId getSessionId();
  SecureStopRelease makeSecureRelease(const SecureStop &stop);
  sp<IDrmFactory> mDrmFactory = nullptr;
  sp<ICryptoFactory> mCryptoFactory = nullptr;
  sp<IDrmPlugin> mDrmPlugin = nullptr;
  sp<drm::V1_1::IDrmPlugin> mDrmPluginV1_1 = nullptr;
  sp<drm::V1_2::IDrmPlugin> mDrmPluginV1_2 = nullptr;
  sp<drm::V1_4::IDrmPlugin> mDrmPluginV1_4 = nullptr;
  sp<drm::V1_4::ICryptoPlugin> mCryptoPluginV1_4 = nullptr;
  sp<ICryptoPlugin> mCryptoPlugin = nullptr;
  FuzzedDataProvider *mFDP = nullptr;
  SessionId mSessionId = {};
  SessionId mSessionIdV1 = {};
};

void ClearKeyFuzzer::deInit() {
  if (mDrmPluginV1_1) {
    mDrmPluginV1_1->closeSession(mSessionIdV1);
  }
  if (mDrmPluginV1_2) {
    mDrmPluginV1_2->closeSession(mSessionId);
  }
  mDrmFactory.clear();
  mCryptoFactory.clear();
  mDrmPlugin.clear();
  mDrmPluginV1_1.clear();
  mDrmPluginV1_2.clear();
  mDrmPluginV1_4.clear();
  mCryptoPlugin.clear();
  mCryptoPluginV1_4.clear();
  mSessionId = {};
  mSessionIdV1 = {};
}

void ClearKeyFuzzer::invokeDrmV1_4API() {
  mDrmPluginV1_4->requiresSecureDecoderDefault(
      getValueFromArray(mFDP, kMimeType));
  mDrmPluginV1_4->requiresSecureDecoder(
      getValueFromArray(mFDP, kMimeType),
      getValueFromArray(mFDP, kSecurityLevel));
  mDrmPluginV1_4->setPlaybackId(
      mSessionId, mFDP->ConsumeRandomLengthString(kMaxStringLength).c_str());
  drm::V1_4::IDrmPlugin::getLogMessages_cb cb =
      [&]([[maybe_unused]] drm::V1_4::Status status,
          [[maybe_unused]] hidl_vec<drm::V1_4::LogMessage> logs) {};
  mDrmPluginV1_4->getLogMessages(cb);
}

void ClearKeyFuzzer::invokeDrmSetAlgorithmAPI() {
  const hidl_string cipherAlgo =
      mFDP->ConsumeBool()
          ? mFDP->ConsumeRandomLengthString(kMaxStringLength).c_str()
          : hidl_string(kCipherAlgorithm[mFDP->ConsumeBool()]);
  mDrmPluginV1_2->setCipherAlgorithm(mSessionId, cipherAlgo);

  const hidl_string macAlgo =
      mFDP->ConsumeBool()
          ? mFDP->ConsumeRandomLengthString(kMaxStringLength).c_str()
          : hidl_string(kMacAlgorithm[mFDP->ConsumeBool()]);
  mDrmPluginV1_2->setMacAlgorithm(mSessionId, macAlgo);
}

void ClearKeyFuzzer::invokeDrmPropertyAPI() {
  mDrmPluginV1_2->setPropertyString(
      hidl_string(getValueFromArray(mFDP, kProperty)), hidl_string("value"));

  hidl_string stringValue;
  mDrmPluginV1_2->getPropertyString(
      getValueFromArray(mFDP, kProperty),
      [&](Status status, const hidl_string &hValue) {
        if (status == Status::OK) {
          stringValue = hValue;
        }
      });

  hidl_vec<uint8_t> value = {};
  mDrmPluginV1_2->setPropertyByteArray(
      hidl_string(getValueFromArray(mFDP, kProperty)), value);

  hidl_vec<uint8_t> byteValue;
  mDrmPluginV1_2->getPropertyByteArray(
      getValueFromArray(mFDP, kProperty),
      [&](Status status, const hidl_vec<uint8_t> &hValue) {
        if (status == Status::OK) {
          byteValue = hValue;
        }
      });
}

SessionId ClearKeyFuzzer::getSessionId() {
  SessionId emptySessionId = {};
  return mFDP->ConsumeBool() ? mSessionId : emptySessionId;
}

void ClearKeyFuzzer::invokeDrmDecryptEncryptAPI(const uint8_t *data,
                                                size_t size) {
  uint32_t currSessions, maximumSessions;
  mDrmPluginV1_2->getNumberOfSessions(
      [&](Status status, uint32_t hCurrentSessions, uint32_t hMaxSessions) {
        if (status == Status::OK) {
          currSessions = hCurrentSessions;
          maximumSessions = hMaxSessions;
        }
      });

  HdcpLevel connected, maximum;
  mDrmPluginV1_2->getHdcpLevels([&](Status status,
                                    const HdcpLevel &hConnectedLevel,
                                    const HdcpLevel &hMaxLevel) {
    if (status == Status::OK) {
      connected = hConnectedLevel;
      maximum = hMaxLevel;
    }
  });

  drm::V1_2::HdcpLevel connectedV1_2, maximumV1_2;
  mDrmPluginV1_2->getHdcpLevels_1_2(
      [&](drm::V1_2::Status status, const drm::V1_2::HdcpLevel &connectedLevel,
          const drm::V1_2::HdcpLevel &maxLevel) {
        if (status == drm::V1_2::Status::OK) {
          connectedV1_2 = connectedLevel;
          maximumV1_2 = maxLevel;
        }
      });

  SecurityLevel securityLevel;
  mDrmPluginV1_2->getSecurityLevel(mSessionId,
                                   [&](Status status, SecurityLevel hLevel) {
                                     if (status == Status::OK) {
                                       securityLevel = hLevel;
                                     }
                                   });

  hidl_vec<DrmMetricGroup> metrics;
  mDrmPluginV1_2->getMetrics(
      [&](Status status, hidl_vec<DrmMetricGroup> hMetricGroups) {
        if (status == Status::OK) {
          metrics = hMetricGroups;
        }
      });

  hidl_string certificateType;
  hidl_string certificateAuthority;
  mDrmPluginV1_2->getProvisionRequest(certificateType, certificateAuthority,
                                      [&]([[maybe_unused]] Status status,
                                          const hidl_vec<uint8_t> &,
                                          const hidl_string &) {});

  mDrmPluginV1_2->getProvisionRequest_1_2(
      certificateType, certificateAuthority,
      [&]([[maybe_unused]] drm::V1_2::Status status, const hidl_vec<uint8_t> &,
          const hidl_string &) {});

  hidl_vec<uint8_t> response;
  mDrmPluginV1_2->provideProvisionResponse(
      response, [&]([[maybe_unused]] Status status, const hidl_vec<uint8_t> &,
                    const hidl_vec<uint8_t> &) {});

  hidl_vec<uint8_t> initData = {};
  if (mFDP->ConsumeBool()) {
    initData = validInitData;
  } else {
    initData.setToExternal(const_cast<uint8_t *>(data), kAESBlockSize);
  }
  hidl_string mimeType = getValueFromArray(mFDP, kMimeType);
  KeyType keyType = mFDP->ConsumeBool()
                        ? static_cast<KeyType>(mFDP->ConsumeIntegral<size_t>())
                        : getValueFromArray(mFDP, kKeyType);
  KeyedVector optionalParameters;
  mDrmPluginV1_2->getKeyRequest_1_2(
      mSessionId, initData, mimeType, keyType, optionalParameters,
      [&]([[maybe_unused]] drm::V1_2::Status status, const hidl_vec<uint8_t> &,
          drm::V1_1::KeyRequestType, const hidl_string &) {});
  mDrmPluginV1_1->getKeyRequest_1_1(
      mSessionIdV1, initData, mimeType, keyType, optionalParameters,
      [&]([[maybe_unused]] drm::V1_0::Status status, const hidl_vec<uint8_t> &,
          drm::V1_1::KeyRequestType, const hidl_string &) {});
  hidl_vec<uint8_t> emptyInitData = {};
  mDrmPlugin->getKeyRequest(
      mSessionId, mFDP->ConsumeBool() ? initData : emptyInitData, mimeType,
      keyType, optionalParameters,
      [&]([[maybe_unused]] drm::V1_0::Status status, const hidl_vec<uint8_t> &,
          drm::V1_0::KeyRequestType, const hidl_string &) {});

  hidl_vec<uint8_t> keyResponse = {};
  if (mFDP->ConsumeBool()) {
    keyResponse = validKeyResponse;
  } else {
    keyResponse.setToExternal(const_cast<uint8_t *>(data), size);
  }
  hidl_vec<uint8_t> keySetId;
  hidl_vec<uint8_t> emptyKeyResponse = {};
  mDrmPluginV1_2->provideKeyResponse(
      getSessionId(), mFDP->ConsumeBool() ? keyResponse : emptyKeyResponse,
      [&](Status status, const hidl_vec<uint8_t> &hKeySetId) {
        if (status == Status::OK) {
          keySetId = hKeySetId;
        }
      });

  mDrmPluginV1_2->restoreKeys(getSessionId(), keySetId);

  mDrmPluginV1_2->queryKeyStatus(
      getSessionId(),
      [&]([[maybe_unused]] Status status, KeyedVector /* info */) {});

  hidl_vec<uint8_t> keyId, input, iv;
  keyId.setToExternal(const_cast<uint8_t *>(data), size);
  input.setToExternal(const_cast<uint8_t *>(data), size);
  iv.setToExternal(const_cast<uint8_t *>(data), size);
  mDrmPluginV1_2->encrypt(
      getSessionId(), keyId, input, iv,
      [&]([[maybe_unused]] Status status, const hidl_vec<uint8_t> &) {});

  mDrmPluginV1_2->decrypt(
      getSessionId(), keyId, input, iv,
      [&]([[maybe_unused]] Status status, const hidl_vec<uint8_t> &) {});

  hidl_vec<uint8_t> message;
  message.setToExternal(const_cast<uint8_t *>(data), size);
  mDrmPluginV1_2->sign(
      getSessionId(), keyId, message,
      [&]([[maybe_unused]] Status status, const hidl_vec<uint8_t> &) {});

  hidl_vec<uint8_t> signature;
  signature.setToExternal(const_cast<uint8_t *>(data), size);
  mDrmPluginV1_2->verify(getSessionId(), keyId, message, signature,
                         [&]([[maybe_unused]] Status status, bool) {});

  hidl_vec<uint8_t> wrappedKey;
  signature.setToExternal(const_cast<uint8_t *>(data), size);
  mDrmPluginV1_2->signRSA(
      getSessionId(), kRSAAlgorithm[mFDP->ConsumeBool()], message, wrappedKey,
      [&]([[maybe_unused]] Status status, const hidl_vec<uint8_t> &) {});

  mDrmPluginV1_2->removeKeys(getSessionId());
}

/**
 * Helper function to create a secure release message for
 * a secure stop. The clearkey secure stop release format
 * is just a count followed by the secure stop opaque data.
 */
SecureStopRelease ClearKeyFuzzer::makeSecureRelease(const SecureStop &stop) {
  std::vector<uint8_t> stopData = stop.opaqueData;
  std::vector<uint8_t> buffer;
  std::string count = "0001";

  auto it = buffer.insert(buffer.begin(), count.begin(), count.end());
  buffer.insert(it + count.size(), stopData.begin(), stopData.end());
  SecureStopRelease release = {.opaqueData = hidl_vec<uint8_t>(buffer)};
  return release;
}

void ClearKeyFuzzer::invokeDrmSecureStopAPI() {
  SecureStopId ssid;
  mDrmPluginV1_2->getSecureStop(
      ssid, [&]([[maybe_unused]] Status status, const SecureStop &) {});

  mDrmPluginV1_2->getSecureStopIds(
      [&]([[maybe_unused]] Status status,
          [[maybe_unused]] const hidl_vec<SecureStopId> &secureStopIds) {});

  SecureStopRelease release;
  mDrmPluginV1_2->getSecureStops(
      [&]([[maybe_unused]] Status status, const hidl_vec<SecureStop> &stops) {
        if (stops.size() > 0) {
          release = makeSecureRelease(
              stops[mFDP->ConsumeIntegralInRange<size_t>(0, stops.size() - 1)]);
        }
      });

  mDrmPluginV1_2->releaseSecureStops(release);

  mDrmPluginV1_2->removeSecureStop(ssid);

  mDrmPluginV1_2->removeAllSecureStops();

  mDrmPluginV1_2->releaseSecureStop(ssid);

  mDrmPluginV1_2->releaseAllSecureStops();
}

void ClearKeyFuzzer::invokeDrmOfflineLicenseAPI(const uint8_t *data,
                                                size_t size) {
  hidl_vec<KeySetId> keySetIds = {};
  mDrmPluginV1_2->getOfflineLicenseKeySetIds(
      [&](Status status, const hidl_vec<KeySetId> &hKeySetIds) {
        if (status == Status::OK) {
          keySetIds = hKeySetIds;
        }
      });

  OfflineLicenseState licenseState;
  KeySetId keySetId = {};
  if (keySetIds.size() > 0) {
    keySetId = keySetIds[mFDP->ConsumeIntegralInRange<size_t>(
        0, keySetIds.size() - 1)];
  } else {
    keySetId.setToExternal(const_cast<uint8_t *>(data), size);
  }
  mDrmPluginV1_2->getOfflineLicenseState(
      keySetId, [&](Status status, OfflineLicenseState hLicenseState) {
        if (status == Status::OK) {
          licenseState = hLicenseState;
        }
      });

  mDrmPluginV1_2->removeOfflineLicense(keySetId);
}

void ClearKeyFuzzer::invokeDrmPlugin(const uint8_t *data, size_t size) {
  SecurityLevel secLevel =
      mFDP->ConsumeBool()
          ? getValueFromArray(mFDP, kSecurityLevel)
          : static_cast<SecurityLevel>(mFDP->ConsumeIntegral<uint32_t>());
  mDrmPluginV1_1->openSession_1_1(
      secLevel, [&]([[maybe_unused]] Status status, const SessionId &id) {
        mSessionIdV1 = id;
      });
  mDrmPluginV1_2->openSession([&]([[maybe_unused]] Status status,
                                  const SessionId &id) { mSessionId = id; });

  sp<TestDrmPluginListener> listener = new TestDrmPluginListener();
  mDrmPluginV1_2->setListener(listener);
  const hidl_vec<KeyStatus> keyStatusList = {
      {{1}, KeyStatusType::USABLE},
      {{2}, KeyStatusType::EXPIRED},
      {{3}, KeyStatusType::OUTPUTNOTALLOWED},
      {{4}, KeyStatusType::STATUSPENDING},
      {{5}, KeyStatusType::INTERNALERROR},
  };
  mDrmPluginV1_2->sendKeysChange(mSessionId, keyStatusList, true);

  invokeDrmV1_4API();
  invokeDrmSetAlgorithmAPI();
  invokeDrmPropertyAPI();
  invokeDrmDecryptEncryptAPI(data, size);
  invokeDrmSecureStopAPI();
  invokeDrmOfflineLicenseAPI(data, size);
}

void ClearKeyFuzzer::invokeCryptoPlugin(const uint8_t *data) {
  mCryptoPlugin->requiresSecureDecoderComponent(
      getValueFromArray(mFDP, kMimeType));

  const uint32_t width = mFDP->ConsumeIntegral<uint32_t>();
  const uint32_t height = mFDP->ConsumeIntegral<uint32_t>();
  mCryptoPlugin->notifyResolution(width, height);

  mCryptoPlugin->setMediaDrmSession(mSessionId);

  size_t totalSize = 0;
  const size_t numSubSamples =
      mFDP->ConsumeIntegralInRange<size_t>(1, kMaxSubSamples);

  const Pattern pattern = {0, 0};
  hidl_vec<SubSample> subSamples;
  subSamples.resize(numSubSamples);

  for (size_t i = 0; i < numSubSamples; ++i) {
    const uint32_t clearBytes =
        mFDP->ConsumeIntegralInRange<uint32_t>(0, kMaxNumBytes);
    const uint32_t encryptedBytes =
        mFDP->ConsumeIntegralInRange<uint32_t>(0, kMaxNumBytes);
    subSamples[i].numBytesOfClearData = clearBytes;
    subSamples[i].numBytesOfEncryptedData = encryptedBytes;
    totalSize += subSamples[i].numBytesOfClearData;
    totalSize += subSamples[i].numBytesOfEncryptedData;
  }

  // The first totalSize bytes of shared memory is the encrypted
  // input, the second totalSize bytes is the decrypted output.
  size_t memoryBytes = totalSize * 2;

  sp<IAllocator> ashmemAllocator = IAllocator::getService("ashmem");
  if (!ashmemAllocator.get()) {
    return;
  }

  hidl_memory hidlMemory;
  ashmemAllocator->allocate(memoryBytes, [&]([[maybe_unused]] bool success,
                                             const hidl_memory &memory) {
    mCryptoPlugin->setSharedBufferBase(memory, kSegmentIndex);
    hidlMemory = memory;
  });

  sp<IMemory> mappedMemory = mapMemory(hidlMemory);
  if (!mappedMemory.get()) {
    return;
  }
  mCryptoPlugin->setSharedBufferBase(hidlMemory, kSegmentIndex);

  uint32_t srcBufferId =
      mFDP->ConsumeBool() ? kSegmentIndex : mFDP->ConsumeIntegral<uint32_t>();
  const SharedBuffer sourceBuffer = {
      .bufferId = srcBufferId, .offset = 0, .size = totalSize};

  BufferType type = mFDP->ConsumeBool() ? BufferType::SHARED_MEMORY
                                        : BufferType::NATIVE_HANDLE;
  uint32_t destBufferId =
      mFDP->ConsumeBool() ? kSegmentIndex : mFDP->ConsumeIntegral<uint32_t>();
  const DestinationBuffer destBuffer = {
      .type = type,
      {.bufferId = destBufferId, .offset = totalSize, .size = totalSize},
      .secureMemory = nullptr};

  const uint64_t offset = 0;
  uint32_t bytesWritten = 0;
  hidl_array<uint8_t, kAESBlockSize> keyId =
      hidl_array<uint8_t, kAESBlockSize>(data);
  hidl_array<uint8_t, kAESBlockSize> iv =
      hidl_array<uint8_t, kAESBlockSize>(data);
  Mode mode = getValueFromArray(mFDP, kCryptoMode);
  mCryptoPlugin->decrypt(
      mFDP->ConsumeBool(), keyId, iv, mode, pattern, subSamples, sourceBuffer,
      offset, destBuffer,
      [&]([[maybe_unused]] Status status, uint32_t count,
          [[maybe_unused]] string detailedError) { bytesWritten = count; });
  drm::V1_4::IDrmPlugin::getLogMessages_cb cb =
      [&]([[maybe_unused]] drm::V1_4::Status status,
          [[maybe_unused]] hidl_vec<drm::V1_4::LogMessage> logs) {};
  mCryptoPluginV1_4->getLogMessages(cb);
}

bool ClearKeyFuzzer::invokeDrmFactory() {
  hidl_string packageName(
      mFDP->ConsumeRandomLengthString(kMaxStringLength).c_str());
  hidl_string mimeType(getValueFromArray(mFDP, kMimeType));
  SecurityLevel securityLevel =
      mFDP->ConsumeBool()
          ? getValueFromArray(mFDP, kSecurityLevel)
          : static_cast<SecurityLevel>(mFDP->ConsumeIntegral<uint32_t>());
  const hidl_array<uint8_t, 16> uuid =
      mFDP->ConsumeBool() ? kClearKeyUUID : kInvalidUUID;
  mDrmFactory->isCryptoSchemeSupported_1_2(uuid, mimeType, securityLevel);
  mDrmFactory->createPlugin(
      uuid, packageName, [&](Status status, const sp<IDrmPlugin> &plugin) {
        if (status == Status::OK) {
          mDrmPlugin = plugin.get();
          mDrmPluginV1_1 = drm::V1_1::IDrmPlugin::castFrom(mDrmPlugin);
          mDrmPluginV1_2 = drm::V1_2::IDrmPlugin::castFrom(mDrmPlugin);
          mDrmPluginV1_4 = drm::V1_4::IDrmPlugin::castFrom(mDrmPlugin);
        }
      });

  std::vector<hidl_array<uint8_t, 16>> supportedSchemes;
  mDrmFactory->getSupportedCryptoSchemes(
      [&](const hidl_vec<hidl_array<uint8_t, 16>> &schemes) {
        for (const auto &scheme : schemes) {
          supportedSchemes.push_back(scheme);
        }
      });

  if (!(mDrmPlugin && mDrmPluginV1_1 && mDrmPluginV1_2 && mDrmPluginV1_4)) {
    return false;
  }
  return true;
}

bool ClearKeyFuzzer::invokeCryptoFactory() {
  const hidl_array<uint8_t, 16> uuid =
      mFDP->ConsumeBool() ? kClearKeyUUID : kInvalidUUID;
  mCryptoFactory->createPlugin(
      uuid, mSessionId, [this](Status status, const sp<ICryptoPlugin> &plugin) {
        if (status == Status::OK) {
          mCryptoPlugin = plugin;
          mCryptoPluginV1_4 = drm::V1_4::ICryptoPlugin::castFrom(mCryptoPlugin);
        }
      });

  if (!mCryptoPlugin && !mCryptoPluginV1_4) {
    return false;
  }
  return true;
}

void ClearKeyFuzzer::invokeDrm(const uint8_t *data, size_t size) {
  if (!invokeDrmFactory()) {
    return;
  }
  invokeDrmPlugin(data, size);
}

void ClearKeyFuzzer::invokeCrypto(const uint8_t *data) {
  if (!invokeCryptoFactory()) {
    return;
  }
  invokeCryptoPlugin(data);
}

void ClearKeyFuzzer::process(const uint8_t *data, size_t size) {
  mFDP = new FuzzedDataProvider(data, size);
  invokeDrm(data, size);
  invokeCrypto(data);
  delete mFDP;
}

bool ClearKeyFuzzer::init() {
  mCryptoFactory =
      android::hardware::drm::V1_4::clearkey::createCryptoFactory();
  mDrmFactory = android::hardware::drm::V1_4::clearkey::createDrmFactory();
  if (!mDrmFactory && !mCryptoFactory) {
    return false;
  }
  return true;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size < kAESBlockSize) {
    return 0;
  }
  ClearKeyFuzzer clearKeyFuzzer;
  if (clearKeyFuzzer.init()) {
    clearKeyFuzzer.process(data, size);
  }
  return 0;
}
