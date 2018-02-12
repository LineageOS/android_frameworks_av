/*
 * Copyright (C) 2018 The Android Open Source Project
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

//#define LOG_NDEBUG 0
#define LOG_TAG "hidl_ClearKeyPlugin"
#include <utils/Log.h>

#include <stdio.h>

#include "DrmPlugin.h"
#include "ClearKeyDrmProperties.h"
#include "Session.h"
#include "TypeConvert.h"

namespace {
const std::string kStreaming("Streaming");
const std::string kOffline("Offline");
const std::string kTrue("True");

const std::string kQueryKeyLicenseType("LicenseType");
    // Value: "Streaming" or "Offline"
const std::string kQueryKeyPlayAllowed("PlayAllowed");
    // Value: "True" or "False"
const std::string kQueryKeyRenewAllowed("RenewAllowed");
    // Value: "True" or "False"
};

namespace android {
namespace hardware {
namespace drm {
namespace V1_1 {
namespace clearkey {

DrmPlugin::DrmPlugin(SessionLibrary* sessionLibrary)
        : mSessionLibrary(sessionLibrary),
          mOpenSessionOkCount(0),
          mCloseSessionOkCount(0),
          mCloseSessionNotOpenedCount(0) {
    mPlayPolicy.clear();
    initProperties();
}

void DrmPlugin::initProperties() {
    mStringProperties.clear();
    mStringProperties[kVendorKey] = kVendorValue;
    mStringProperties[kVersionKey] = kVersionValue;
    mStringProperties[kPluginDescriptionKey] = kPluginDescriptionValue;
    mStringProperties[kAlgorithmsKey] = kAlgorithmsValue;
    mStringProperties[kListenerTestSupportKey] = kListenerTestSupportValue;

    std::vector<uint8_t> valueVector;
    valueVector.clear();
    valueVector.insert(valueVector.end(),
            kTestDeviceIdData, kTestDeviceIdData + sizeof(kTestDeviceIdData) / sizeof(uint8_t));
    mByteArrayProperties[kDeviceIdKey] = valueVector;

    valueVector.clear();
    valueVector.insert(valueVector.end(),
            kMetricsData, kMetricsData + sizeof(kMetricsData) / sizeof(uint8_t));
    mByteArrayProperties[kMetricsKey] = valueVector;
}

Return<void> DrmPlugin::openSession(openSession_cb _hidl_cb) {
    sp<Session> session = mSessionLibrary->createSession();
    std::vector<uint8_t> sessionId = session->sessionId();

    setSecurityLevel(sessionId, SecurityLevel::SW_SECURE_CRYPTO);
    _hidl_cb(Status::OK, toHidlVec(sessionId));
    mOpenSessionOkCount++;
    return Void();
}

Return<Status> DrmPlugin::closeSession(const hidl_vec<uint8_t>& sessionId) {
    if (sessionId.size() == 0) {
        return Status::BAD_VALUE;
    }

    sp<Session> session = mSessionLibrary->findSession(toVector(sessionId));
    if (session.get()) {
        mCloseSessionOkCount++;
        mSessionLibrary->destroySession(session);
        return Status::OK;
    }
    mCloseSessionNotOpenedCount++;
    return Status::ERROR_DRM_SESSION_NOT_OPENED;
}

Return<void> DrmPlugin::getKeyRequest(
        const hidl_vec<uint8_t>& scope,
        const hidl_vec<uint8_t>& initData,
        const hidl_string& mimeType,
        KeyType keyType,
        const hidl_vec<KeyValue>& optionalParameters,
        getKeyRequest_cb _hidl_cb) {
    UNUSED(optionalParameters);

    if (scope.size() == 0) {
        // Returns empty keyRequest, unknown keyType and empty defaultUrl
        _hidl_cb(Status::BAD_VALUE, hidl_vec<uint8_t>(),
                KeyRequestType::UNKNOWN, "");
        return Void();
    }

    if (keyType != KeyType::STREAMING) {
        _hidl_cb(Status::ERROR_DRM_CANNOT_HANDLE, hidl_vec<uint8_t>(),
                KeyRequestType::UNKNOWN, "");
        return Void();
    }

    sp<Session> session = mSessionLibrary->findSession(toVector(scope));
    if (!session.get()) {
        _hidl_cb(Status::ERROR_DRM_SESSION_NOT_OPENED, hidl_vec<uint8_t>(),
                KeyRequestType::UNKNOWN, "");
        return Void();
    }

    std::vector<uint8_t> request;
    Status status = session->getKeyRequest(initData, mimeType, &request);
    _hidl_cb(status, toHidlVec(request), KeyRequestType::INITIAL, "");
    return Void();
}

Return<void> DrmPlugin::getKeyRequest_1_1(
        const hidl_vec<uint8_t>& scope,
        const hidl_vec<uint8_t>& initData,
        const hidl_string& mimeType,
        KeyType keyType,
        const hidl_vec<KeyValue>& optionalParameters,
        getKeyRequest_1_1_cb _hidl_cb) {
    hidl_string defaultUrl;
    hidl_vec<uint8_t> request;
    ::android::hardware::drm::V1_1::KeyRequestType requestType =
            static_cast<::android::hardware::drm::V1_1::KeyRequestType>(KeyRequestType::UNKNOWN);
    Status status = Status::OK;

    defaultUrl.clear();
    getKeyRequest(scope, initData, mimeType, keyType, optionalParameters,
            [&](Status statusCode, const hidl_vec<uint8_t>& hResult,
            KeyRequestType hKeyRequestType,
            const hidl_string& hDefaultUrl) {
        defaultUrl = hDefaultUrl;
        request = hResult;
        requestType = static_cast<::android::hardware::drm::V1_1::KeyRequestType>(hKeyRequestType);
        status = statusCode;
    });
    _hidl_cb(status, request, requestType, defaultUrl);
    return Void();
}

void DrmPlugin::setPlayPolicy() {
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

Return<void> DrmPlugin::provideKeyResponse(
        const hidl_vec<uint8_t>& scope,
        const hidl_vec<uint8_t>& response,
        provideKeyResponse_cb _hidl_cb) {
    if (scope.size() == 0 || response.size() == 0) {
        // Returns empty keySetId
        _hidl_cb(Status::BAD_VALUE, hidl_vec<uint8_t>());
        return Void();
    }
    sp<Session> session = mSessionLibrary->findSession(toVector(scope));
    if (!session.get()) {
        _hidl_cb(Status::ERROR_DRM_SESSION_NOT_OPENED, hidl_vec<uint8_t>());
        return Void();
    }

    setPlayPolicy();
    std::vector<uint8_t> keySetId;
    Status status = session->provideKeyResponse(response);
    if (status == Status::OK) {
        // This is for testing AMediaDrm_setOnEventListener only.
        sendEvent(EventType::VENDOR_DEFINED, 0, scope);
        keySetId.clear();
    }

    // Returns status and empty keySetId
    _hidl_cb(status, toHidlVec(keySetId));
    return Void();
}

Return<void> DrmPlugin::getPropertyString(
        const hidl_string& propertyName, getPropertyString_cb _hidl_cb) {
    std::string name(propertyName.c_str());
    std::string value;

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
    } else {
        ALOGE("App requested unknown string property %s", name.c_str());
        _hidl_cb(Status::ERROR_DRM_CANNOT_HANDLE, "");
        return Void();
    }
    _hidl_cb(Status::OK, value.c_str());
    return Void();
}

Return<void> DrmPlugin::getPropertyByteArray(
        const hidl_string& propertyName, getPropertyByteArray_cb _hidl_cb) {
    std::map<std::string, std::vector<uint8_t> >::iterator itr =
            mByteArrayProperties.find(std::string(propertyName.c_str()));
    if (itr == mByteArrayProperties.end()) {
        ALOGE("App requested unknown property: %s", propertyName.c_str());
        _hidl_cb(Status::BAD_VALUE, std::vector<uint8_t>());
        return Void();
    }
    _hidl_cb(Status::OK, itr->second);
    return Void();

}

Return<Status> DrmPlugin::setPropertyString(
    const hidl_string& name, const hidl_string& value) {
    std::string immutableKeys;
    immutableKeys.append(kAlgorithmsKey + ",");
    immutableKeys.append(kPluginDescriptionKey + ",");
    immutableKeys.append(kVendorKey + ",");
    immutableKeys.append(kVersionKey + ",");

    std::string key = std::string(name.c_str());
    if (immutableKeys.find(key) != std::string::npos) {
        ALOGD("Cannot set immutable property: %s", key.c_str());
        return Status::BAD_VALUE;
    }

    std::map<std::string, std::string>::iterator itr =
            mStringProperties.find(key);
    if (itr == mStringProperties.end()) {
        ALOGE("Cannot set undefined property string, key=%s", key.c_str());
        return Status::BAD_VALUE;
    }

    mStringProperties[key] = std::string(value.c_str());
    return Status::OK;
}

Return<Status> DrmPlugin::setPropertyByteArray(
    const hidl_string& name, const hidl_vec<uint8_t>& value) {
   UNUSED(value);
   if (name == kDeviceIdKey) {
      ALOGD("Cannot set immutable property: %s", name.c_str());
      return Status::BAD_VALUE;
   }

   // Setting of undefined properties is not supported
   ALOGE("Failed to set property byte array, key=%s", name.c_str());
   return Status::ERROR_DRM_CANNOT_HANDLE;
}

Return<void> DrmPlugin::queryKeyStatus(
        const hidl_vec<uint8_t>& sessionId,
        queryKeyStatus_cb _hidl_cb) {

    if (sessionId.size() == 0) {
        // Returns empty key status KeyValue pair
        _hidl_cb(Status::BAD_VALUE, hidl_vec<KeyValue>());
        return Void();
    }

    std::vector<KeyValue> infoMapVec;
    infoMapVec.clear();

    KeyValue keyValuePair;
    for (size_t i = 0; i < mPlayPolicy.size(); ++i) {
        keyValuePair.key = mPlayPolicy[i].key;
        keyValuePair.value = mPlayPolicy[i].value;
        infoMapVec.push_back(keyValuePair);
    }
    _hidl_cb(Status::OK, toHidlVec(infoMapVec));
    return Void();
}

Return<void> DrmPlugin::getNumberOfSessions(getNumberOfSessions_cb _hidl_cb) {
        uint32_t currentSessions = mSessionLibrary->numOpenSessions();
        uint32_t maxSessions = 10;
        _hidl_cb(Status::OK, currentSessions, maxSessions);
        return Void();
}

Return<void> DrmPlugin::getSecurityLevel(const hidl_vec<uint8_t>& sessionId,
            getSecurityLevel_cb _hidl_cb) {
    if (sessionId.size() == 0) {
        _hidl_cb(Status::BAD_VALUE, SecurityLevel::UNKNOWN);
        return Void();
    }

    std::vector<uint8_t> sid = toVector(sessionId);
    sp<Session> session = mSessionLibrary->findSession(sid);
    if (!session.get()) {
        _hidl_cb(Status::ERROR_DRM_SESSION_NOT_OPENED, SecurityLevel::UNKNOWN);
        return Void();
    }

    std::map<std::vector<uint8_t>, SecurityLevel>::iterator itr =
            mSecurityLevel.find(sid);
    if (itr == mSecurityLevel.end()) {
        ALOGE("Session id not found");
        _hidl_cb(Status::ERROR_DRM_INVALID_STATE, SecurityLevel::UNKNOWN);
        return Void();
    }

    _hidl_cb(Status::OK, itr->second);
    return Void();
}

Return<Status> DrmPlugin::setSecurityLevel(const hidl_vec<uint8_t>& sessionId,
            SecurityLevel level) {
    if (sessionId.size() == 0) {
        ALOGE("Invalid empty session id");
        return Status::BAD_VALUE;
    }

    if (level > SecurityLevel::HW_SECURE_ALL) {
        ALOGE("Cannot set invalid security level");
        return Status::BAD_VALUE;
    }

    std::vector<uint8_t> sid = toVector(sessionId);
    sp<Session> session = mSessionLibrary->findSession(sid);
    if (!session.get()) {
        return Status::ERROR_DRM_SESSION_NOT_OPENED;
    }

    std::map<std::vector<uint8_t>, SecurityLevel>::iterator itr =
            mSecurityLevel.find(sid);
    if (itr != mSecurityLevel.end()) {
        mSecurityLevel[sid] = level;
    } else {
        if (!mSecurityLevel.insert(
                std::pair<std::vector<uint8_t>, SecurityLevel>(sid, level)).second) {
            ALOGE("Failed to set security level");
            return Status::ERROR_DRM_INVALID_STATE;
        }
    }
    return Status::OK;
}

Return<void> DrmPlugin::getMetrics(getMetrics_cb _hidl_cb) {
    // Set the open session count metric.
    DrmMetricGroup::Attribute openSessionOkAttribute = {
      "status", DrmMetricGroup::ValueType::INT64_TYPE, (int64_t) Status::OK, 0.0, ""
    };
    DrmMetricGroup::Value openSessionMetricValue = {
      "count", DrmMetricGroup::ValueType::INT64_TYPE, mOpenSessionOkCount, 0.0, ""
    };
    DrmMetricGroup::Metric openSessionMetric = {
      "open_session", { openSessionOkAttribute }, { openSessionMetricValue }
    };

    // Set the close session count metric.
    DrmMetricGroup::Attribute closeSessionOkAttribute = {
      "status", DrmMetricGroup::ValueType::INT64_TYPE, (int64_t) Status::OK, 0.0, ""
    };
    DrmMetricGroup::Value closeSessionMetricValue = {
      "count", DrmMetricGroup::ValueType::INT64_TYPE, mCloseSessionOkCount, 0.0, ""
    };
    DrmMetricGroup::Metric closeSessionMetric = {
      "close_session", { closeSessionOkAttribute }, { closeSessionMetricValue }
    };

    // Set the close session, not opened metric.
    DrmMetricGroup::Attribute closeSessionNotOpenedAttribute = {
      "status", DrmMetricGroup::ValueType::INT64_TYPE,
      (int64_t) Status::ERROR_DRM_SESSION_NOT_OPENED, 0.0, ""
    };
    DrmMetricGroup::Value closeSessionNotOpenedMetricValue = {
      "count", DrmMetricGroup::ValueType::INT64_TYPE, mCloseSessionNotOpenedCount, 0.0, ""
    };
    DrmMetricGroup::Metric closeSessionNotOpenedMetric = {
      "close_session", { closeSessionNotOpenedAttribute }, { closeSessionNotOpenedMetricValue }
    };

    DrmMetricGroup metrics = { { openSessionMetric, closeSessionMetric,
                                closeSessionNotOpenedMetric } };

    _hidl_cb(Status::OK, hidl_vec<DrmMetricGroup>({metrics}));
    return Void();
}



}  // namespace clearkey
}  // namespace V1_1
}  // namespace drm
}  // namespace hardware
}  // namespace android
