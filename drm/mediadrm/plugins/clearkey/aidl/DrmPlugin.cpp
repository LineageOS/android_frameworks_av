/*
 * Copyright (C) 2021 The Android Open Source Project
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
#define LOG_TAG "clearkey-DrmPlugin"

#include <aidl/android/hardware/drm/DrmMetric.h>
#include <android-base/parseint.h>
#include <utils/Log.h>

#include <inttypes.h>
#include <stdio.h>
#include <chrono>
#include <set>

#include "AidlUtils.h"
#include "ClearKeyDrmProperties.h"
#include "DrmPlugin.h"
#include "Session.h"
#include "Utils.h"
#include "AidlClearKeryProperties.h"

namespace {
const std::string kKeySetIdPrefix("ckid");
const int kKeySetIdLength = 16;
const int kSecureStopIdStart = 100;
const std::string kOfflineLicense("\"type\":\"persistent-license\"");
const std::string kStreaming("Streaming");
const std::string kTemporaryLicense("\"type\":\"temporary\"");
const std::string kTrue("True");

const std::string kQueryKeyLicenseType("LicenseType");
// Value: "Streaming" or "Offline"
const std::string kQueryKeyPlayAllowed("PlayAllowed");
// Value: "True" or "False"
const std::string kQueryKeyRenewAllowed("RenewAllowed");
// Value: "True" or "False"

const int kSecureStopIdSize = 10;

std::vector<uint8_t> uint32ToVector(uint32_t value) {
    // 10 bytes to display max value 4294967295 + one byte null terminator
    char buffer[kSecureStopIdSize];
    memset(buffer, 0, kSecureStopIdSize);
    snprintf(buffer, kSecureStopIdSize, "%" PRIu32, value);
    return std::vector<uint8_t>(buffer, buffer + sizeof(buffer));
}

};  // unnamed namespace

namespace aidl {
namespace android {
namespace hardware {
namespace drm {
namespace clearkey {

using ::android::Mutex;

DrmPlugin::DrmPlugin(SessionLibrary* sessionLibrary)
    : mSessionLibrary(sessionLibrary),
      mOpenSessionOkCount(0),
      mCloseSessionOkCount(0),
      mCloseSessionNotOpenedCount(0),
      mNextSecureStopId(kSecureStopIdStart),
      mMockError(Status::OK) {
    mPlayPolicy.clear();
    initProperties();
    mSecureStops.clear();
    mReleaseKeysMap.clear();
    std::srand(std::time(nullptr));
}

void DrmPlugin::initProperties() {
    mStringProperties.clear();
    mStringProperties[kVendorKey] = kAidlVendorValue;
    mStringProperties[kVersionKey] = kVersionValue;
    mStringProperties[kPluginDescriptionKey] = kAidlPluginDescriptionValue;
    mStringProperties[kAlgorithmsKey] = kAidlAlgorithmsValue;
    mStringProperties[kListenerTestSupportKey] = kAidlListenerTestSupportValue;
    mStringProperties[kDrmErrorTestKey] = kAidlDrmErrorTestValue;
    mStringProperties[kAidlVersionKey] = kAidlVersionValue;
    mStringProperties[kOemErrorKey] = "0";
    mStringProperties[kErrorContextKey] = "0";

    std::vector<uint8_t> valueVector;
    valueVector.clear();
    valueVector.insert(valueVector.end(), kTestDeviceIdData,
                       kTestDeviceIdData + sizeof(kTestDeviceIdData) / sizeof(uint8_t));
    mByteArrayProperties[kDeviceIdKey] = valueVector;

    valueVector.clear();
    valueVector.insert(valueVector.end(), kMetricsData,
                       kMetricsData + sizeof(kMetricsData) / sizeof(uint8_t));
    mByteArrayProperties[kMetricsKey] = valueVector;
}

int32_t DrmPlugin::getIntProperty(const std::string& prop, int32_t defaultVal) const {
    if (!mStringProperties.count(prop)) {
        return defaultVal;
    }
    int32_t out = defaultVal;
    if (!::android::base::ParseInt(mStringProperties.at(prop), &out)) {
        return defaultVal;
    }
    return out;
}

int32_t DrmPlugin::getOemError() const {
    return getIntProperty(kOemErrorKey);
}

int32_t DrmPlugin::getErrorContext() const {
    return getIntProperty(kErrorContextKey);
}

//
// The secure stop in ClearKey implementation is not installed securely.
// This function merely creates a test environment for testing secure stops APIs.
// The content in this secure stop is implementation dependent, the clearkey
// secureStop does not serve as a reference implementation.
void DrmPlugin::installSecureStop(const std::vector<uint8_t>& sessionId) {
    ::android::Mutex::Autolock lock(mSecureStopLock);

    ClearkeySecureStop clearkeySecureStop;
    clearkeySecureStop.id = uint32ToVector(++mNextSecureStopId);
    clearkeySecureStop.data.assign(sessionId.begin(), sessionId.end());

    mSecureStops.insert(std::pair<std::vector<uint8_t>, ClearkeySecureStop>(clearkeySecureStop.id,
                                                                            clearkeySecureStop));
}

::ndk::ScopedAStatus DrmPlugin::closeSession(const std::vector<uint8_t>& in_sessionId) {
    if (in_sessionId.size() == 0) {
        return toNdkScopedAStatus(Status::BAD_VALUE);
    }

    ::android::sp<Session> session = mSessionLibrary->findSession(in_sessionId);
    if (session.get()) {
        mSessionLibrary->destroySession(session);
        if (session->getMockError() != clearkeydrm::OK) {
            sendSessionLostState(in_sessionId);
            return toNdkScopedAStatus(Status::ERROR_DRM_INVALID_STATE,
                                      nullptr,
                                      getOemError(),
                                      getErrorContext());
        }
        mCloseSessionOkCount++;
        return toNdkScopedAStatus(Status::OK);
    }
    mCloseSessionNotOpenedCount++;
    return toNdkScopedAStatus(Status::ERROR_DRM_SESSION_NOT_OPENED);
}

::ndk::ScopedAStatus DrmPlugin::decrypt(const std::vector<uint8_t>& in_sessionId,
                                        const std::vector<uint8_t>& in_keyId,
                                        const std::vector<uint8_t>& in_input,
                                        const std::vector<uint8_t>& in_iv,
                                        std::vector<uint8_t>* _aidl_return) {
    *_aidl_return = {};
    if (in_sessionId.size() == 0 || in_keyId.size() == 0 || in_input.size() == 0 ||
        in_iv.size() == 0) {
        return toNdkScopedAStatus(Status::BAD_VALUE);
    }
    return toNdkScopedAStatus(Status::ERROR_DRM_CANNOT_HANDLE);
}

::ndk::ScopedAStatus DrmPlugin::encrypt(const std::vector<uint8_t>& in_sessionId,
                                        const std::vector<uint8_t>& in_keyId,
                                        const std::vector<uint8_t>& in_input,
                                        const std::vector<uint8_t>& in_iv,
                                        std::vector<uint8_t>* _aidl_return) {
    *_aidl_return = {};
    if (in_sessionId.size() == 0 || in_keyId.size() == 0 || in_input.size() == 0 ||
        in_iv.size() == 0) {
        return toNdkScopedAStatus(Status::BAD_VALUE);
    }
    return toNdkScopedAStatus(Status::ERROR_DRM_CANNOT_HANDLE);
}

::ndk::ScopedAStatus DrmPlugin::getHdcpLevels(
        ::aidl::android::hardware::drm::HdcpLevels* _aidl_return) {
    _aidl_return->connectedLevel = HdcpLevel::HDCP_NONE;
    _aidl_return->maxLevel = HdcpLevel::HDCP_NO_OUTPUT;
    return toNdkScopedAStatus(Status::OK);
}

::ndk::ScopedAStatus DrmPlugin::getKeyRequest(
        const std::vector<uint8_t>& in_scope, const std::vector<uint8_t>& in_initData,
        const std::string& in_mimeType, ::aidl::android::hardware::drm::KeyType in_keyType,
        const std::vector<::aidl::android::hardware::drm::KeyValue>& in_optionalParameters,
        ::aidl::android::hardware::drm::KeyRequest* _aidl_return) {
    UNUSED(in_optionalParameters);

    KeyRequestType keyRequestType = KeyRequestType::UNKNOWN;
    std::string defaultUrl("");

    _aidl_return->request = {};
    _aidl_return->requestType = keyRequestType;
    _aidl_return->defaultUrl = defaultUrl;

    if (in_scope.size() == 0 ||
        (in_keyType != KeyType::STREAMING && in_keyType != KeyType::OFFLINE &&
         in_keyType != KeyType::RELEASE)) {
        return toNdkScopedAStatus(Status::BAD_VALUE);
    }

    const std::vector<uint8_t> scopeId = in_scope;
    ::android::sp<Session> session;
    std::set<KeyType> init_types{KeyType::STREAMING, KeyType::OFFLINE};
    if (init_types.count(in_keyType)) {
        std::vector<uint8_t> sessionId(scopeId.begin(), scopeId.end());
        session = mSessionLibrary->findSession(sessionId);
        if (!session.get()) {
            return toNdkScopedAStatus(Status::ERROR_DRM_SESSION_NOT_OPENED);
        } else if (session->getMockError() != clearkeydrm::OK) {
            auto err = static_cast<Status>(session->getMockError());
            return toNdkScopedAStatus(err, nullptr, getOemError(), getErrorContext());
        }
        keyRequestType = KeyRequestType::INITIAL;
    }

    std::vector<uint8_t> request = {};
    auto keyType = static_cast<CdmKeyType>(in_keyType);
    auto status = session->getKeyRequest(in_initData, in_mimeType, keyType, &request);

    if (in_keyType == KeyType::RELEASE) {
        std::vector<uint8_t> keySetId(scopeId.begin(), scopeId.end());
        std::string requestString(request.begin(), request.end());
        if (requestString.find(kOfflineLicense) != std::string::npos) {
            std::string emptyResponse;
            std::string keySetIdString(keySetId.begin(), keySetId.end());
            if (!mFileHandle.StoreLicense(keySetIdString, DeviceFiles::kLicenseStateReleasing,
                                          emptyResponse)) {
                ALOGE("Problem releasing offline license");
                return toNdkScopedAStatus(Status::ERROR_DRM_UNKNOWN);
            }
            if (mReleaseKeysMap.find(keySetIdString) == mReleaseKeysMap.end()) {
                ::android::sp<Session> session = mSessionLibrary->createSession();
                mReleaseKeysMap[keySetIdString] = session->sessionId();
            } else {
                ALOGI("key is in use, ignore release request");
            }
        } else {
            ALOGE("Offline license not found, nothing to release");
        }
        keyRequestType = KeyRequestType::RELEASE;
    }
    _aidl_return->request = request;
    _aidl_return->requestType = keyRequestType;
    _aidl_return->defaultUrl = defaultUrl;
    return toNdkScopedAStatus(status);
}

::ndk::ScopedAStatus DrmPlugin::getLogMessages(
        std::vector<::aidl::android::hardware::drm::LogMessage>* _aidl_return) {
    using std::chrono::duration_cast;
    using std::chrono::milliseconds;
    using std::chrono::system_clock;

    auto timeMillis = duration_cast<milliseconds>(system_clock::now().time_since_epoch()).count();

    std::vector<::aidl::android::hardware::drm::LogMessage> logs = {
            {timeMillis, ::aidl::android::hardware::drm::LogPriority::ERROR,
             std::string("Not implemented")}};
    *_aidl_return = logs;
    return toNdkScopedAStatus(Status::OK);
}

::ndk::ScopedAStatus DrmPlugin::getMetrics(
        std::vector<::aidl::android::hardware::drm::DrmMetricGroup>* _aidl_return) {
    // Set the open session count metric.
    DrmMetricNamedValue openSessionOkAttribute = {"status", static_cast<int64_t>(Status::OK)};
    DrmMetricNamedValue openSessionMetricValue = {"count", mOpenSessionOkCount};
    DrmMetric openSessionMetric = {
            "open_session", {openSessionOkAttribute}, {openSessionMetricValue}};

    // Set the close session count metric.
    DrmMetricNamedValue closeSessionOkAttribute = {"status", static_cast<int64_t>(Status::OK)};
    DrmMetricNamedValue closeSessionMetricValue = {"count", mCloseSessionOkCount};
    DrmMetric closeSessionMetric = {
            "close_session", {closeSessionOkAttribute}, {closeSessionMetricValue}};

    // Set the close session, not opened metric.
    DrmMetricNamedValue closeSessionNotOpenedAttribute = {"status",
            static_cast<int64_t>(Status::ERROR_DRM_SESSION_NOT_OPENED)};
    DrmMetricNamedValue closeSessionNotOpenedMetricValue = {"count", mCloseSessionNotOpenedCount};
    DrmMetric closeSessionNotOpenedMetric = {
            "close_session", {closeSessionNotOpenedAttribute}, {closeSessionNotOpenedMetricValue}};

    // Set the setPlaybackId metric.
    std::vector<DrmMetricNamedValue> sids = {};
    std::vector<DrmMetricNamedValue> playbackIds = {};
    for (const auto& [key, value] : mPlaybackId) {
        std::string sid(key.begin(), key.end());
        DrmMetricNamedValue sessionIdAttribute = {"sid", sid};
        sids.push_back(sessionIdAttribute);

        DrmMetricNamedValue playbackIdMetricValue = {"playbackId", value};
        playbackIds.push_back(playbackIdMetricValue);
    }
    DrmMetric setPlaybackIdMetric = {"set_playback_id", sids, playbackIds};

    DrmMetricGroup metrics = {{openSessionMetric, closeSessionMetric, closeSessionNotOpenedMetric,
            setPlaybackIdMetric}};

    *_aidl_return = {metrics};
    return toNdkScopedAStatus(Status::OK);
}

::ndk::ScopedAStatus DrmPlugin::getNumberOfSessions(
        ::aidl::android::hardware::drm::NumberOfSessions* _aidl_return) {
    _aidl_return->currentSessions = mSessionLibrary->numOpenSessions();
    _aidl_return->maxSessions = 10;
    return toNdkScopedAStatus(Status::OK);
}

::ndk::ScopedAStatus DrmPlugin::getOfflineLicenseKeySetIds(
        std::vector<::aidl::android::hardware::drm::KeySetId>* _aidl_return) {
    std::vector<std::string> licenseNames = mFileHandle.ListLicenses();
    std::vector<KeySetId> keySetIds = {};
    if (mMockError != Status::OK) {
        *_aidl_return = keySetIds;
        return toNdkScopedAStatus(toMockStatus(mMockError));
    }
    for (const auto& name : licenseNames) {
        std::vector<uint8_t> keySetId(name.begin(), name.end());
        KeySetId id = {};
        id.keySetId = keySetId;
        keySetIds.push_back(id);
    }
    *_aidl_return = keySetIds;
    return toNdkScopedAStatus(Status::OK);
}

::ndk::ScopedAStatus DrmPlugin::getOfflineLicenseState(
        const ::aidl::android::hardware::drm::KeySetId& in_keySetId,
        ::aidl::android::hardware::drm::OfflineLicenseState* _aidl_return) {
    std::string licenseName(in_keySetId.keySetId.begin(), in_keySetId.keySetId.end());
    DeviceFiles::LicenseState state;
    std::string license;
    OfflineLicenseState licenseState = OfflineLicenseState::UNKNOWN;
    Status status = Status::OK;
    if (mMockError != Status::OK) {
        *_aidl_return = licenseState;
        return toNdkScopedAStatus(toMockStatus(mMockError));
    } else if (mFileHandle.RetrieveLicense(licenseName, &state, &license)) {
        switch (state) {
            case DeviceFiles::kLicenseStateActive:
                licenseState = OfflineLicenseState::USABLE;
                break;
            case DeviceFiles::kLicenseStateReleasing:
                licenseState = OfflineLicenseState::INACTIVE;
                break;
            case DeviceFiles::kLicenseStateUnknown:
                licenseState = OfflineLicenseState::UNKNOWN;
                break;
        }
    } else {
        status = Status::BAD_VALUE;
    }
    *_aidl_return = licenseState;
    return toNdkScopedAStatus(status);
}

::ndk::ScopedAStatus DrmPlugin::getPropertyByteArray(const std::string& in_propertyName,
                                                     std::vector<uint8_t>* _aidl_return) {
    std::map<std::string, std::vector<uint8_t>>::iterator itr =
            mByteArrayProperties.find(std::string(in_propertyName.c_str()));
    Status status = Status::OK;
    if (itr != mByteArrayProperties.end()) {
        *_aidl_return = itr->second;
    } else {
        ALOGE("App requested unknown property: %s", in_propertyName.c_str());
        status = Status::BAD_VALUE;
        *_aidl_return = {};
    }
    return toNdkScopedAStatus(status);
}

::ndk::ScopedAStatus DrmPlugin::getPropertyString(const std::string& in_propertyName,
                                                  std::string* _aidl_return) {
    std::string name(in_propertyName.c_str());
    std::string value;
    Status status = Status::OK;

    if (name == kVendorKey) {
        value = mStringProperties[kVendorKey];
    } else if (name == kVersionKey) {
        value = mStringProperties[kVersionKey];
    } else if (name == kPluginDescriptionKey) {
        value = mStringProperties[kPluginDescriptionKey];
    } else if (name == kAlgorithmsKey) {
        value = mStringProperties[kAlgorithmsKey];
    } else if (name == kListenerTestSupportKey) {
        value = mStringProperties[kListenerTestSupportKey];
    } else if (name == kDrmErrorTestKey) {
        value = mStringProperties[kDrmErrorTestKey];
    } else if (name == kAidlVersionKey) {
        value = mStringProperties[kAidlVersionKey];
    } else if (name == kOemErrorKey) {
        value = mStringProperties[kOemErrorKey];
    } else if (name == kErrorContextKey) {
        value = mStringProperties[kErrorContextKey];
    } else {
        ALOGE("App requested unknown string property %s", name.c_str());
        status = Status::ERROR_DRM_CANNOT_HANDLE;
    }
    *_aidl_return = value;
    return toNdkScopedAStatus(status);
}

::ndk::ScopedAStatus DrmPlugin::getProvisionRequest(
        const std::string& in_certificateType, const std::string& in_certificateAuthority,
        ::aidl::android::hardware::drm::ProvisionRequest* _aidl_return) {
    UNUSED(in_certificateType);
    UNUSED(in_certificateAuthority);
    _aidl_return->request = {};
    _aidl_return->defaultUrl = {};
    return toNdkScopedAStatus(Status::ERROR_DRM_CANNOT_HANDLE);
}

::ndk::ScopedAStatus DrmPlugin::getSecureStop(
        const ::aidl::android::hardware::drm::SecureStopId& in_secureStopId,
        ::aidl::android::hardware::drm::SecureStop* _aidl_return) {
    std::vector<uint8_t> stop = {};

    mSecureStopLock.lock();
    auto itr = mSecureStops.find(in_secureStopId.secureStopId);
    if (itr != mSecureStops.end()) {
        ClearkeySecureStop clearkeyStop = itr->second;
        stop.insert(stop.end(), clearkeyStop.id.begin(), clearkeyStop.id.end());
        stop.insert(stop.end(), clearkeyStop.data.begin(), clearkeyStop.data.end());
    }
    mSecureStopLock.unlock();

    SecureStop secureStop = {};
    Status status = Status::OK;
    if (!stop.empty()) {
        secureStop.opaqueData = stop;
    } else {
        status = Status::BAD_VALUE;
    }
    *_aidl_return = secureStop;
    return toNdkScopedAStatus(status);
}

::ndk::ScopedAStatus DrmPlugin::getSecureStopIds(
        std::vector<::aidl::android::hardware::drm::SecureStopId>* _aidl_return) {
    mSecureStopLock.lock();
    std::vector<::aidl::android::hardware::drm::SecureStopId> ids;
    for (auto itr = mSecureStops.begin(); itr != mSecureStops.end(); ++itr) {
        SecureStopId id;
        id.secureStopId = itr->first;
        ids.push_back(id);
    }
    mSecureStopLock.unlock();

    *_aidl_return = ids;
    return toNdkScopedAStatus(Status::OK);
}

::ndk::ScopedAStatus DrmPlugin::getSecureStops(
        std::vector<::aidl::android::hardware::drm::SecureStop>* _aidl_return) {
    mSecureStopLock.lock();
    std::vector<::aidl::android::hardware::drm::SecureStop> stops;
    for (auto itr = mSecureStops.begin(); itr != mSecureStops.end(); ++itr) {
        ClearkeySecureStop clearkeyStop = itr->second;
        std::vector<uint8_t> stop{};
        stop.insert(stop.end(), clearkeyStop.id.begin(), clearkeyStop.id.end());
        stop.insert(stop.end(), clearkeyStop.data.begin(), clearkeyStop.data.end());

        SecureStop secureStop;
        secureStop.opaqueData = stop;
        stops.push_back(secureStop);
    }
    mSecureStopLock.unlock();

    *_aidl_return = stops;
    return toNdkScopedAStatus(Status::OK);
}

::ndk::ScopedAStatus DrmPlugin::getSecurityLevel(
        const std::vector<uint8_t>& in_sessionId,
        ::aidl::android::hardware::drm::SecurityLevel* _aidl_return) {
    if (in_sessionId.size() == 0) {
        *_aidl_return = ::aidl::android::hardware::drm::SecurityLevel::UNKNOWN;
        return toNdkScopedAStatus(Status::BAD_VALUE);
    }

    std::vector<uint8_t> sid = in_sessionId;
    ::android::sp<Session> session = mSessionLibrary->findSession(sid);
    if (!session.get()) {
        *_aidl_return = SecurityLevel::UNKNOWN;
        return toNdkScopedAStatus(Status::ERROR_DRM_SESSION_NOT_OPENED);
    }

    Mutex::Autolock lock(mSecurityLevelLock);
    std::map<std::vector<uint8_t>, ::aidl::android::hardware::drm::SecurityLevel>::iterator itr =
            mSecurityLevel.find(sid);
    if (itr == mSecurityLevel.end()) {
        ALOGE("Session id not found");
        *_aidl_return = SecurityLevel::UNKNOWN;
        return toNdkScopedAStatus(Status::ERROR_DRM_INVALID_STATE);
    }

    *_aidl_return = SecurityLevel::SW_SECURE_CRYPTO;
    return toNdkScopedAStatus(Status::OK);
}

::ndk::ScopedAStatus DrmPlugin::openSession(
        ::aidl::android::hardware::drm::SecurityLevel in_securityLevel,
        std::vector<uint8_t>* _aidl_return) {
    ::android::sp<Session> session = mSessionLibrary->createSession();
    processMockError(session);
    std::vector<uint8_t> sessionId = session->sessionId();

    Status status = setSecurityLevel(sessionId, in_securityLevel);
    if (status == Status::OK) {
        mOpenSessionOkCount++;
    } else {
        mSessionLibrary->destroySession(session);
        sessionId.clear();
    }
    *_aidl_return = sessionId;
    return toNdkScopedAStatus(status);
}

::ndk::ScopedAStatus DrmPlugin::provideKeyResponse(
        const std::vector<uint8_t>& in_scope, const std::vector<uint8_t>& in_response,
        ::aidl::android::hardware::drm::KeySetId* _aidl_return) {
    if (in_scope.size() == 0 || in_response.size() == 0) {
        // Returns empty keySetId
        *_aidl_return = {};
        return toNdkScopedAStatus(Status::BAD_VALUE);
    }

    std::string responseString(reinterpret_cast<const char*>(in_response.data()),
                               in_response.size());
    const std::vector<uint8_t> scopeId = in_scope;
    std::vector<uint8_t> sessionId = {};
    std::string keySetId;

    bool isOfflineLicense = responseString.find(kOfflineLicense) != std::string::npos;
    if (scopeId.size() < kKeySetIdPrefix.size()) {
        android_errorWriteLog(0x534e4554, "144507096");
        *_aidl_return = {};
        return toNdkScopedAStatus(Status::ERROR_DRM_CANNOT_HANDLE);
    }
    bool isRelease = (memcmp(scopeId.data(), kKeySetIdPrefix.data(), kKeySetIdPrefix.size()) == 0);
    if (isRelease) {
        keySetId.assign(scopeId.begin(), scopeId.end());

        auto iter = mReleaseKeysMap.find(std::string(keySetId.begin(), keySetId.end()));
        if (iter != mReleaseKeysMap.end()) {
            sessionId.assign(iter->second.begin(), iter->second.end());
        }
    } else {
        sessionId.assign(scopeId.begin(), scopeId.end());
        // non offline license returns empty keySetId
        keySetId.clear();
    }

    ::android::sp<Session> session = mSessionLibrary->findSession(sessionId);
    if (!session.get()) {
        *_aidl_return = {};
        return toNdkScopedAStatus(Status::ERROR_DRM_SESSION_NOT_OPENED);
    }
    setPlayPolicy();

    auto res = session->provideKeyResponse(in_response);
    if (res == clearkeydrm::OK) {
        if (isOfflineLicense) {
            if (isRelease) {
                mFileHandle.DeleteLicense(keySetId);
                mSessionLibrary->destroySession(session);
            } else {
                if (!makeKeySetId(&keySetId)) {
                    *_aidl_return = {};
                    return toNdkScopedAStatus(Status::ERROR_DRM_UNKNOWN);
                }

                bool ok = mFileHandle.StoreLicense(
                        keySetId, DeviceFiles::kLicenseStateActive,
                        std::string(in_response.begin(), in_response.end()));
                if (!ok) {
                    ALOGE("Failed to store offline license");
                }
            }
        }

        // Test calling AMediaDrm listeners.
        sendEvent(EventType::VENDOR_DEFINED, sessionId, sessionId);

        sendExpirationUpdate(sessionId, 100);

        std::vector<KeyStatus> keysStatus = {};
        KeyStatus keyStatus;

        std::vector<uint8_t> keyId1 = {0xA, 0xB, 0xC};
        keyStatus.keyId = keyId1;
        keyStatus.type = KeyStatusType::USABLE;
        keysStatus.push_back(keyStatus);

        std::vector<uint8_t> keyId2 = {0xD, 0xE, 0xF};
        keyStatus.keyId = keyId2;
        keyStatus.type = KeyStatusType::EXPIRED;
        keysStatus.push_back(keyStatus);

        std::vector<uint8_t> keyId3 = {0x0, 0x1, 0x2};
        keyStatus.keyId = keyId3;
        keyStatus.type = KeyStatusType::USABLE_IN_FUTURE;
        keysStatus.push_back(keyStatus);

        sendKeysChange(sessionId, keysStatus, true);

        installSecureStop(sessionId);
    } else {
        ALOGE("provideKeyResponse returns error=%d", res);
    }

    std::vector<uint8_t> keySetIdVec(keySetId.begin(), keySetId.end());
    _aidl_return->keySetId = keySetIdVec;
    return toNdkScopedAStatus(res);
}

::ndk::ScopedAStatus DrmPlugin::provideProvisionResponse(
        const std::vector<uint8_t>& in_response,
        ::aidl::android::hardware::drm::ProvideProvisionResponseResult* _aidl_return) {
    Status status = Status::ERROR_DRM_CANNOT_HANDLE;
    _aidl_return->certificate = {};
    _aidl_return->wrappedKey = {};
    if (in_response.size() == 0) {
        status = Status::BAD_VALUE;
    }
    return toNdkScopedAStatus(status);
}

::ndk::ScopedAStatus DrmPlugin::queryKeyStatus(
        const std::vector<uint8_t>& in_sessionId,
        std::vector<::aidl::android::hardware::drm::KeyValue>* _aidl_return) {
    if (in_sessionId.size() == 0) {
        // Returns empty key status KeyValue pair
        *_aidl_return = {};
        return toNdkScopedAStatus(Status::BAD_VALUE);
    }

    std::vector<KeyValue> infoMap = {};
    mPlayPolicyLock.lock();
    KeyValue keyValuePair;
    for (size_t i = 0; i < mPlayPolicy.size(); ++i) {
        keyValuePair.key = mPlayPolicy[i].key;
        keyValuePair.value = mPlayPolicy[i].value;
        infoMap.push_back(keyValuePair);
    }
    mPlayPolicyLock.unlock();
    *_aidl_return = infoMap;
    return toNdkScopedAStatus(Status::OK);
}

::ndk::ScopedAStatus DrmPlugin::releaseAllSecureStops() {
    Status status = Status::OK;
    const auto res = removeAllSecureStops();
    if (!res.isOk() && res.getExceptionCode() == EX_SERVICE_SPECIFIC) {
        status = static_cast<Status>(res.getServiceSpecificError());
    }
    return toNdkScopedAStatus(status);
}

::ndk::ScopedAStatus DrmPlugin::releaseSecureStop(
        const ::aidl::android::hardware::drm::SecureStopId& in_secureStopId) {
    Status status = Status::OK;
    const auto res = removeSecureStop(in_secureStopId);
    if (!res.isOk() && res.getExceptionCode() == EX_SERVICE_SPECIFIC) {
        status = static_cast<Status>(res.getServiceSpecificError());
    }
    return toNdkScopedAStatus(status);
}

::ndk::ScopedAStatus DrmPlugin::releaseSecureStops(
        const ::aidl::android::hardware::drm::OpaqueData& in_ssRelease) {
    // OpaqueData starts with 4 byte decimal integer string
    const size_t kFourBytesOffset = 4;
    if (in_ssRelease.opaqueData.size() < kFourBytesOffset) {
        ALOGE("Invalid secureStopRelease length");
        return toNdkScopedAStatus(Status::BAD_VALUE);
    }

    Status status = Status::OK;
    std::vector<uint8_t> input = in_ssRelease.opaqueData;

    if (input.size() < kSecureStopIdSize + kFourBytesOffset) {
        // The minimum size of secure stop has to contain
        // a 4 bytes count and one secureStop id
        ALOGE("Total size of secureStops is too short");
        return toNdkScopedAStatus(Status::BAD_VALUE);
    }

    // The format of opaqueData is shared between the server
    // and the drm service. The clearkey implementation consists of:
    //    count - number of secure stops
    //    list of fixed length secure stops
    size_t countBufferSize = sizeof(uint32_t);
    if (input.size() < countBufferSize) {
        // SafetyNet logging
        android_errorWriteLog(0x534e4554, "144766455");
        return toNdkScopedAStatus(Status::BAD_VALUE);
    }
    uint32_t count = 0;
    sscanf(reinterpret_cast<char*>(input.data()), "%04" PRIu32, &count);

    // Avoid divide by 0 below.
    if (count == 0) {
        ALOGE("Invalid 0 secureStop count");
        return toNdkScopedAStatus(Status::BAD_VALUE);
    }

    // Computes the fixed length secureStop size
    size_t secureStopSize = (input.size() - kFourBytesOffset) / count;
    if (secureStopSize < kSecureStopIdSize) {
        // A valid secureStop contains the id plus data
        ALOGE("Invalid secureStop size");
        return toNdkScopedAStatus(Status::BAD_VALUE);
    }
    uint8_t* buffer = new uint8_t[secureStopSize];
    size_t offset = kFourBytesOffset;  // skip the count
    for (size_t i = 0; i < count; ++i, offset += secureStopSize) {
        memcpy(buffer, input.data() + offset, secureStopSize);

        // A secureStop contains id+data, we only use the id for removal
        std::vector<uint8_t> id(buffer, buffer + kSecureStopIdSize);
        ::aidl::android::hardware::drm::SecureStopId secureStopId{id};
        const auto res = removeSecureStop(secureStopId);
        if (!res.isOk() && res.getExceptionCode() == EX_SERVICE_SPECIFIC) {
            status = static_cast<Status>(res.getServiceSpecificError());
        }
        if (Status::OK != status) break;
    }

    delete[] buffer;
    return toNdkScopedAStatus(status);
}

::ndk::ScopedAStatus DrmPlugin::removeAllSecureStops() {
    Mutex::Autolock lock(mSecureStopLock);

    mSecureStops.clear();
    mNextSecureStopId = kSecureStopIdStart;
    return toNdkScopedAStatus(Status::OK);
}

::ndk::ScopedAStatus DrmPlugin::removeKeys(const std::vector<uint8_t>& in_sessionId) {
    Status status = Status::ERROR_DRM_CANNOT_HANDLE;
    if (in_sessionId.size() == 0) {
        status = Status::BAD_VALUE;
    }
    return toNdkScopedAStatus(status);
}

::ndk::ScopedAStatus DrmPlugin::removeOfflineLicense(
        const ::aidl::android::hardware::drm::KeySetId& in_keySetId) {
    if (mMockError != Status::OK) {
        return toNdkScopedAStatus(toMockStatus(mMockError));
    }
    Status status = Status::BAD_VALUE;
    std::string licenseName(in_keySetId.keySetId.begin(), in_keySetId.keySetId.end());
    if (mFileHandle.DeleteLicense(licenseName)) {
        status = Status::OK;
    }
    return toNdkScopedAStatus(status);
}

::ndk::ScopedAStatus DrmPlugin::removeSecureStop(
        const ::aidl::android::hardware::drm::SecureStopId& in_secureStopId) {
    Mutex::Autolock lock(mSecureStopLock);

    Status status = Status::OK;
    if (1 != mSecureStops.erase(in_secureStopId.secureStopId)) {
        status = Status::BAD_VALUE;
    }
    return toNdkScopedAStatus(status);
}

::ndk::ScopedAStatus DrmPlugin::requiresSecureDecoder(
        const std::string& in_mime, ::aidl::android::hardware::drm::SecurityLevel in_level,
        bool* _aidl_return) {
    UNUSED(in_mime);
    UNUSED(in_level);
    *_aidl_return = false;
    return ::ndk::ScopedAStatus::ok();
}

::ndk::ScopedAStatus DrmPlugin::restoreKeys(
        const std::vector<uint8_t>& in_sessionId,
        const ::aidl::android::hardware::drm::KeySetId& in_keySetId) {
    if (in_sessionId.size() == 0 || in_keySetId.keySetId.size() == 0) {
        return toNdkScopedAStatus(Status::BAD_VALUE);
    }

    DeviceFiles::LicenseState licenseState;
    std::string offlineLicense;
    if (!mFileHandle.RetrieveLicense(
                std::string(in_keySetId.keySetId.begin(), in_keySetId.keySetId.end()),
                &licenseState, &offlineLicense)) {
        ALOGE("Failed to restore offline license");
        return toNdkScopedAStatus(Status::ERROR_DRM_NO_LICENSE);
    }

    if (DeviceFiles::kLicenseStateUnknown == licenseState ||
        DeviceFiles::kLicenseStateReleasing == licenseState) {
        ALOGE("Invalid license state=%d", licenseState);
        return toNdkScopedAStatus(Status::ERROR_DRM_NO_LICENSE);
    }

    ::android::sp<Session> session = mSessionLibrary->findSession(in_sessionId);
    if (!session.get()) {
        return toNdkScopedAStatus(Status::ERROR_DRM_SESSION_NOT_OPENED);
    }
    auto res = session->provideKeyResponse(
            std::vector<uint8_t>(offlineLicense.begin(), offlineLicense.end()));
    if (res != clearkeydrm::OK) {
        ALOGE("Failed to restore keys");
    }
    return toNdkScopedAStatus(res);
}

void DrmPlugin::sendEvent(::aidl::android::hardware::drm::EventType in_eventType,
                                          const std::vector<uint8_t>& in_sessionId,
                                          const std::vector<uint8_t>& in_data) {
    if (mListener != nullptr) {
        mListener->onEvent(in_eventType, in_sessionId, in_data);
    } else {
        ALOGE("Null event listener, event not sent");
    }
    return;
}

void DrmPlugin::sendExpirationUpdate(const std::vector<uint8_t>& in_sessionId,
                                                     int64_t in_expiryTimeInMS) {
    if (mListener != nullptr) {
        mListener->onExpirationUpdate(in_sessionId, in_expiryTimeInMS);
    } else {
        ALOGE("Null event listener, event not sent");
    }
    return;
}

void DrmPlugin::sendKeysChange(
        const std::vector<uint8_t>& in_sessionId,
        const std::vector<::aidl::android::hardware::drm::KeyStatus>& in_keyStatusList,
        bool in_hasNewUsableKey) {
    if (mListener != nullptr) {
        mListener->onKeysChange(in_sessionId, in_keyStatusList, in_hasNewUsableKey);
    } else {
        ALOGE("Null event listener, event not sent");
    }
    return;
}

void DrmPlugin::sendSessionLostState(const std::vector<uint8_t>& in_sessionId) {
    if (mListener != nullptr) {
        mListener->onSessionLostState(in_sessionId);
    }
    return;
}

::ndk::ScopedAStatus DrmPlugin::setCipherAlgorithm(const std::vector<uint8_t>& /*in_sessionId*/,
                                                   const std::string& /*in_algorithm*/) {
    return toNdkScopedAStatus(Status::ERROR_DRM_CANNOT_HANDLE);
}

::ndk::ScopedAStatus DrmPlugin::setListener(
        const std::shared_ptr<
                ::aidl::android::hardware::drm::IDrmPluginListener>& in_listener) {
    mListener = in_listener;
    return toNdkScopedAStatus(Status::OK);
}

::ndk::ScopedAStatus DrmPlugin::setMacAlgorithm(const std::vector<uint8_t>& /*in_sessionId*/,
                                                const std::string& /*in_algorithm*/) {
    return toNdkScopedAStatus(Status::ERROR_DRM_CANNOT_HANDLE);
}

::ndk::ScopedAStatus DrmPlugin::setPlaybackId(const std::vector<uint8_t>& in_sessionId,
                                              const std::string& in_playbackId) {
    if (in_sessionId.size() == 0) {
        ALOGE("Invalid empty session id");
        return toNdkScopedAStatus(Status::BAD_VALUE);
    }

    std::vector<uint8_t> sid = in_sessionId;
    mPlaybackId[sid] = in_playbackId;
    return toNdkScopedAStatus(Status::OK);
}

::ndk::ScopedAStatus DrmPlugin::setPropertyByteArray(const std::string& in_propertyName,
                                                     const std::vector<uint8_t>& in_value) {
    if (in_propertyName == kDeviceIdKey) {
        ALOGD("Cannot set immutable property: %s", in_propertyName.c_str());
        return toNdkScopedAStatus(Status::BAD_VALUE);
    } else if (in_propertyName == kClientIdKey) {
        mByteArrayProperties[kClientIdKey] = in_value;
        return toNdkScopedAStatus(Status::OK);
    }

    // Setting of undefined properties is not supported
    ALOGE("Failed to set property byte array, key=%s", in_propertyName.c_str());
    return toNdkScopedAStatus(Status::ERROR_DRM_CANNOT_HANDLE);
}

::ndk::ScopedAStatus DrmPlugin::setPropertyString(const std::string& in_propertyName,
                                                  const std::string& in_value) {
    std::string immutableKeys;
    immutableKeys.append(kAlgorithmsKey + ",");
    immutableKeys.append(kPluginDescriptionKey + ",");
    immutableKeys.append(kVendorKey + ",");
    immutableKeys.append(kVersionKey + ",");

    std::string key = std::string(in_propertyName.c_str());
    if (immutableKeys.find(key) != std::string::npos) {
        ALOGD("Cannot set immutable property: %s", key.c_str());
        return toNdkScopedAStatus(Status::BAD_VALUE);
    }

    std::map<std::string, std::string>::iterator itr = mStringProperties.find(key);
    if (itr == mStringProperties.end()) {
        ALOGE("Cannot set undefined property string, key=%s", key.c_str());
        return toNdkScopedAStatus(Status::BAD_VALUE);
    }

    if (in_propertyName == kDrmErrorTestKey) {
        if (in_value == kResourceContentionValue) {
            mMockError = Status::ERROR_DRM_RESOURCE_CONTENTION;
        } else if (in_value == kLostStateValue) {
            mMockError = Status::ERROR_DRM_SESSION_LOST_STATE;
        } else if (in_value == kFrameTooLargeValue) {
            mMockError = Status::ERROR_DRM_FRAME_TOO_LARGE;
        } else if (in_value == kInvalidStateValue) {
            mMockError = Status::ERROR_DRM_INVALID_STATE;
        } else {
            mMockError = Status::ERROR_DRM_UNKNOWN;
        }
    }

    if (in_propertyName == kOemErrorKey || in_propertyName == kErrorContextKey) {
        int32_t err = 0;
        if (!::android::base::ParseInt(in_value, &err)) {
            return toNdkScopedAStatus(Status::BAD_VALUE);
        }
    }

    mStringProperties[key] = std::string(in_value.c_str());
    return toNdkScopedAStatus(Status::OK);
}

::ndk::ScopedAStatus DrmPlugin::sign(const std::vector<uint8_t>& /*in_sessionId*/,
                                     const std::vector<uint8_t>& /*in_keyId*/,
                                     const std::vector<uint8_t>& /*in_message*/,
                                     std::vector<uint8_t>* _aidl_return) {
    *_aidl_return = {};
    return toNdkScopedAStatus(Status::ERROR_DRM_CANNOT_HANDLE);
}

::ndk::ScopedAStatus DrmPlugin::signRSA(const std::vector<uint8_t>& /*in_sessionId*/,
                                        const std::string& /*in_algorithm*/,
                                        const std::vector<uint8_t>& /*in_message*/,
                                        const std::vector<uint8_t>& /*in_wrappedkey*/,
                                        std::vector<uint8_t>* _aidl_return) {
    *_aidl_return = {};
    return toNdkScopedAStatus(Status::ERROR_DRM_CANNOT_HANDLE);
}

::ndk::ScopedAStatus DrmPlugin::verify(const std::vector<uint8_t>& /*in_sessionId*/,
                                       const std::vector<uint8_t>& /*in_keyId*/,
                                       const std::vector<uint8_t>& /*in_message*/,
                                       const std::vector<uint8_t>& /*in_signature*/,
                                       bool* _aidl_return) {
    *_aidl_return = false;
    return toNdkScopedAStatus(Status::ERROR_DRM_CANNOT_HANDLE);
}

// Private methods below.
void DrmPlugin::setPlayPolicy() {
    ::android::Mutex::Autolock lock(mPlayPolicyLock);
    mPlayPolicy.clear();

    KeyValue policy;
    policy.key = kQueryKeyLicenseType;
    policy.value = kStreaming;
    mPlayPolicy.push_back(policy);

    policy.key = kQueryKeyPlayAllowed;
    policy.value = kTrue;
    mPlayPolicy.push_back(policy);

    policy.key = kQueryKeyRenewAllowed;
    mPlayPolicy.push_back(policy);
}

bool DrmPlugin::makeKeySetId(std::string* keySetId) {
    if (!keySetId) {
        ALOGE("keySetId destination not provided");
        return false;
    }
    std::vector<uint8_t> ksid(kKeySetIdPrefix.begin(), kKeySetIdPrefix.end());
    ksid.resize(kKeySetIdLength);
    std::vector<uint8_t> randomData((kKeySetIdLength - kKeySetIdPrefix.size()) / 2, 0);

    while (keySetId->empty()) {
        for (auto itr = randomData.begin(); itr != randomData.end(); ++itr) {
            *itr = std::rand() % 0xff;
        }
        auto id = reinterpret_cast<const uint8_t*>(randomData.data());
        *keySetId = kKeySetIdPrefix + ::android::ByteArrayToHexString(id, randomData.size());
        if (mFileHandle.LicenseExists(*keySetId)) {
            // collision, regenerate
            ALOGV("Retry generating KeySetId");
            keySetId->clear();
        }
    }
    return true;
}

Status DrmPlugin::setSecurityLevel(const std::vector<uint8_t>& sessionId, SecurityLevel level) {
    if (sessionId.size() == 0) {
        ALOGE("Invalid empty session id");
        return Status::BAD_VALUE;
    }

    if (level != SecurityLevel::DEFAULT && level != SecurityLevel::SW_SECURE_CRYPTO) {
        ALOGE("Cannot set security level > max");
        return Status::ERROR_DRM_CANNOT_HANDLE;
    }

    std::vector<uint8_t> sid = sessionId;
    ::android::sp<Session> session = mSessionLibrary->findSession(sid);
    if (!session.get()) {
        return Status::ERROR_DRM_SESSION_NOT_OPENED;
    }

    Mutex::Autolock lock(mSecurityLevelLock);
    std::map<std::vector<uint8_t>, SecurityLevel>::iterator itr = mSecurityLevel.find(sid);
    if (itr != mSecurityLevel.end()) {
        mSecurityLevel[sid] = level;
    } else {
        if (!mSecurityLevel.insert(std::pair<std::vector<uint8_t>, SecurityLevel>(sid, level))
                     .second) {
            ALOGE("Failed to set security level");
            return Status::ERROR_DRM_INVALID_STATE;
        }
    }
    return Status::OK;
}

}  // namespace clearkey
}  // namespace drm
}  // namespace hardware
}  // namespace android
}  // namespace aidl
