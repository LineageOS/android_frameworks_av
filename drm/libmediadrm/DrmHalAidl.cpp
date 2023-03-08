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

//#define LOG_NDEBUG 0
#define LOG_TAG "DrmHalAidl"

#include <array>
#include <algorithm>
#include <map>
#include <android/binder_auto_utils.h>
#include <android/binder_manager.h>
#include <media/PluginMetricsReporting.h>
#include <media/stagefright/foundation/ADebug.h>
#include <media/stagefright/foundation/AString.h>
#include <media/stagefright/foundation/base64.h>
#include <media/stagefright/foundation/hexdump.h>
#include <mediadrm/DrmHalAidl.h>
#include <mediadrm/DrmSessionManager.h>
#include <mediadrm/DrmStatus.h>
#include <mediadrm/DrmUtils.h>

using ::aidl::android::hardware::drm::CryptoSchemes;
using ::aidl::android::hardware::drm::DrmMetricNamedValue;
using ::aidl::android::hardware::drm::DrmMetricValue;
using ::aidl::android::hardware::drm::HdcpLevel;
using ::aidl::android::hardware::drm::HdcpLevels;
using ::aidl::android::hardware::drm::KeyRequest;
using ::aidl::android::hardware::drm::KeyRequestType;
using ::aidl::android::hardware::drm::KeySetId;
using ::aidl::android::hardware::drm::KeyStatus;
using ::aidl::android::hardware::drm::KeyStatusType;
using ::aidl::android::hardware::drm::KeyType;
using ::aidl::android::hardware::drm::KeyValue;
using ::aidl::android::hardware::drm::NumberOfSessions;
using ::aidl::android::hardware::drm::OfflineLicenseState;
using ::aidl::android::hardware::drm::OpaqueData;
using ::aidl::android::hardware::drm::ProvideProvisionResponseResult;
using ::aidl::android::hardware::drm::ProvisionRequest;
using ::aidl::android::hardware::drm::SecureStop;
using ::aidl::android::hardware::drm::SecureStopId;
using ::aidl::android::hardware::drm::SecurityLevel;
using ::aidl::android::hardware::drm::Status;
using ::aidl::android::hardware::drm::SupportedContentType;
using ::aidl::android::hardware::drm::Uuid;
using ::android::DrmUtils::statusAidlToDrmStatus;
using DrmMetricGroupAidl = ::aidl::android::hardware::drm::DrmMetricGroup;
using DrmMetricGroupHidl = ::android::hardware::drm::V1_1::DrmMetricGroup;
using DrmMetricAidl = ::aidl::android::hardware::drm::DrmMetric;
using DrmMetricHidl = ::android::hardware::drm::V1_1::DrmMetricGroup::Metric;
using ValueHidl = ::android::hardware::drm::V1_1::DrmMetricGroup::Value;
using AttributeHidl = ::android::hardware::drm::V1_1::DrmMetricGroup::Attribute;
using IDrmPluginAidl = ::aidl::android::hardware::drm::IDrmPlugin;
using EventTypeAidl = ::aidl::android::hardware::drm::EventType;
using ::android::hardware::hidl_vec;

namespace {

constexpr char kPropertyDeviceUniqueId[] = "deviceUniqueId";
constexpr char kEqualsSign[] = "=";

template <typename T>
std::string toBase64StringNoPad(const T* data, size_t size) {
    // Note that the base 64 conversion only works with arrays of single-byte
    // values. If the source is empty or is not an array of single-byte values,
    // return empty string.
    if (size == 0 || sizeof(data[0]) != 1) {
        return "";
    }

    android::AString outputString;
    encodeBase64(data, size, &outputString);
    // Remove trailing equals padding if it exists.
    while (outputString.size() > 0 && outputString.endsWith(kEqualsSign)) {
        outputString.erase(outputString.size() - 1, 1);
    }

    return std::string(outputString.c_str(), outputString.size());
}

}  // anonymous namespace

namespace android {

#define INIT_CHECK()                             \
    {                                            \
        if (mInitCheck != OK) return mInitCheck; \
    }

template <typename Byte = uint8_t>
static std::vector<Byte> toStdVec(const Vector<uint8_t>& vector) {
    auto v = reinterpret_cast<const Byte*>(vector.array());
    std::vector<Byte> vec(v, v + vector.size());
    return vec;
}

static const Vector<uint8_t> toVector(const std::vector<uint8_t>& vec) {
    Vector<uint8_t> vector;
    vector.appendArray(vec.data(), vec.size());
    return *const_cast<const Vector<uint8_t>*>(&vector);
}

static String8 toString8(const std::string& string) {
    return String8(string.c_str());
}

static std::string toStdString(const String8& string8) {
    return std::string(string8.string());
}

static std::vector<KeyValue> toKeyValueVector(const KeyedVector<String8, String8>& keyedVector) {
    std::vector<KeyValue> stdKeyedVector;
    for (size_t i = 0; i < keyedVector.size(); i++) {
        KeyValue keyValue;
        keyValue.key = toStdString(keyedVector.keyAt(i));
        keyValue.value = toStdString(keyedVector.valueAt(i));
        stdKeyedVector.push_back(keyValue);
    }
    return stdKeyedVector;
}

static KeyedVector<String8, String8> toKeyedVector(const std::vector<KeyValue>& keyValueVec) {
    KeyedVector<String8, String8> keyedVector;
    for (size_t i = 0; i < keyValueVec.size(); i++) {
        keyedVector.add(toString8(keyValueVec[i].key), toString8(keyValueVec[i].value));
    }
    return keyedVector;
}

static DrmPlugin::KeyRequestType toKeyRequestType(KeyRequestType keyRequestType) {
    switch (keyRequestType) {
        case KeyRequestType::INITIAL:
            return DrmPlugin::kKeyRequestType_Initial;
            break;
        case KeyRequestType::RENEWAL:
            return DrmPlugin::kKeyRequestType_Renewal;
            break;
        case KeyRequestType::RELEASE:
            return DrmPlugin::kKeyRequestType_Release;
            break;
        case KeyRequestType::NONE:
            return DrmPlugin::kKeyRequestType_None;
            break;
        case KeyRequestType::UPDATE:
            return DrmPlugin::kKeyRequestType_Update;
            break;
        default:
            return DrmPlugin::kKeyRequestType_Unknown;
            break;
    }
}

static List<Vector<uint8_t>> toSecureStops(const std::vector<SecureStop>& aSecureStops) {
    List<Vector<uint8_t>> secureStops;
    for (size_t i = 0; i < aSecureStops.size(); i++) {
        secureStops.push_back(toVector(aSecureStops[i].opaqueData));
    }
    return secureStops;
}

static List<Vector<uint8_t>> toSecureStopIds(const std::vector<SecureStopId>& aSecureStopIds) {
    List<Vector<uint8_t>> secureStopIds;
    for (size_t i = 0; i < aSecureStopIds.size(); i++) {
        secureStopIds.push_back(toVector(aSecureStopIds[i].secureStopId));
    }
    return secureStopIds;
}

static DrmPlugin::HdcpLevel toHdcpLevel(HdcpLevel level) {
    switch (level) {
        case HdcpLevel::HDCP_NONE:
            return DrmPlugin::kHdcpNone;
        case HdcpLevel::HDCP_V1:
            return DrmPlugin::kHdcpV1;
        case HdcpLevel::HDCP_V2:
            return DrmPlugin::kHdcpV2;
        case HdcpLevel::HDCP_V2_1:
            return DrmPlugin::kHdcpV2_1;
        case HdcpLevel::HDCP_V2_2:
            return DrmPlugin::kHdcpV2_2;
        case HdcpLevel::HDCP_V2_3:
            return DrmPlugin::kHdcpV2_3;
        case HdcpLevel::HDCP_NO_OUTPUT:
            return DrmPlugin::kHdcpNoOutput;
        default:
            return DrmPlugin::kHdcpLevelUnknown;
    }
}

static DrmPlugin::SecurityLevel toSecurityLevel(SecurityLevel level) {
    switch (level) {
        case SecurityLevel::SW_SECURE_CRYPTO:
            return DrmPlugin::kSecurityLevelSwSecureCrypto;
        case SecurityLevel::SW_SECURE_DECODE:
            return DrmPlugin::kSecurityLevelSwSecureDecode;
        case SecurityLevel::HW_SECURE_CRYPTO:
            return DrmPlugin::kSecurityLevelHwSecureCrypto;
        case SecurityLevel::HW_SECURE_DECODE:
            return DrmPlugin::kSecurityLevelHwSecureDecode;
        case SecurityLevel::HW_SECURE_ALL:
            return DrmPlugin::kSecurityLevelHwSecureAll;
        case SecurityLevel::DEFAULT:
            return DrmPlugin::kSecurityLevelMax;
        default:
            return DrmPlugin::kSecurityLevelUnknown;
    }
}

static SecurityLevel toAidlSecurityLevel(DrmPlugin::SecurityLevel level) {
    switch (level) {
        case DrmPlugin::kSecurityLevelSwSecureCrypto:
            return SecurityLevel::SW_SECURE_CRYPTO;
        case DrmPlugin::kSecurityLevelSwSecureDecode:
            return SecurityLevel::SW_SECURE_DECODE;
        case DrmPlugin::kSecurityLevelHwSecureCrypto:
            return SecurityLevel::HW_SECURE_CRYPTO;
        case DrmPlugin::kSecurityLevelHwSecureDecode:
            return SecurityLevel::HW_SECURE_DECODE;
        case DrmPlugin::kSecurityLevelHwSecureAll:
            return SecurityLevel::HW_SECURE_ALL;
        case DrmPlugin::kSecurityLevelMax:
            return SecurityLevel::DEFAULT;
        default:
            return SecurityLevel::UNKNOWN;
    }
}

static List<Vector<uint8_t>> toKeySetIds(const std::vector<KeySetId>& hKeySetIds) {
    List<Vector<uint8_t>> keySetIds;
    for (size_t i = 0; i < hKeySetIds.size(); i++) {
        keySetIds.push_back(toVector(hKeySetIds[i].keySetId));
    }
    return keySetIds;
}

static hidl_vec<uint8_t> toHidlVec(const Vector<uint8_t>& vector) {
    hidl_vec<uint8_t> vec;
    vec.setToExternal(const_cast<uint8_t*>(vector.array()), vector.size());
    return vec;
}

static DrmPlugin::OfflineLicenseState toOfflineLicenseState(OfflineLicenseState licenseState) {
    switch (licenseState) {
        case OfflineLicenseState::USABLE:
            return DrmPlugin::kOfflineLicenseStateUsable;
        case OfflineLicenseState::INACTIVE:
            return DrmPlugin::kOfflineLicenseStateReleased;
        default:
            return DrmPlugin::kOfflineLicenseStateUnknown;
    }
}

Mutex DrmHalAidl::mLock;

static hidl_vec<DrmMetricGroupHidl> toDrmMetricGroupHidl(std::vector<DrmMetricGroupAidl> result) {
    std::vector<DrmMetricGroupHidl> resultHidl;
    for (auto r : result) {
        DrmMetricGroupHidl re;
        std::vector<DrmMetricHidl> tmpMetric;
        for (auto m : r.metrics) {
            DrmMetricHidl me;
            me.name = m.name;
            std::vector<AttributeHidl> aTmp;
            for (auto attr : m.attributes) {
                AttributeHidl attrHidl;
                attrHidl.name = attr.name;

                switch (attr.value.getTag()) {
                    case DrmMetricValue::Tag::int64Value:
                        attrHidl.type = DrmMetricGroupHidl::ValueType::INT64_TYPE;
                        attrHidl.int64Value = attr.value.get<DrmMetricValue::Tag::int64Value>();
                        break;
                    case DrmMetricValue::Tag::doubleValue:
                        attrHidl.type = DrmMetricGroupHidl::ValueType::DOUBLE_TYPE;
                        attrHidl.doubleValue = attr.value.get<DrmMetricValue::Tag::doubleValue>();
                        break;
                    case DrmMetricValue::Tag::stringValue:
                        attrHidl.type = DrmMetricGroupHidl::ValueType::STRING_TYPE;
                        attrHidl.stringValue = attr.value.get<DrmMetricValue::Tag::stringValue>();
                        break;
                    default:
                        break;
                }

                aTmp.push_back(attrHidl);
            }

            me.attributes = aTmp;

            std::vector<ValueHidl> vTmp;
            for (auto value : m.values) {
                ValueHidl valueHidl;
                valueHidl.componentName = value.name;
                switch (value.value.getTag()) {
                    case DrmMetricValue::Tag::int64Value:
                        valueHidl.type = DrmMetricGroupHidl::ValueType::INT64_TYPE;
                        valueHidl.int64Value = value.value.get<DrmMetricValue::Tag::int64Value>();
                        break;
                    case DrmMetricValue::Tag::doubleValue:
                        valueHidl.type = DrmMetricGroupHidl::ValueType::DOUBLE_TYPE;
                        valueHidl.doubleValue = value.value.get<DrmMetricValue::Tag::doubleValue>();
                        break;
                    case DrmMetricValue::Tag::stringValue:
                        valueHidl.type = DrmMetricGroupHidl::ValueType::STRING_TYPE;
                        valueHidl.stringValue = value.value.get<DrmMetricValue::Tag::stringValue>();
                        break;
                    default:
                        break;
                }

                vTmp.push_back(valueHidl);
            }

            me.values = vTmp;
            tmpMetric.push_back(me);
        }

        re.metrics = tmpMetric;
        resultHidl.push_back(re);
    }

    return resultHidl;
}

// DrmSessionClient Definition

struct DrmHalAidl::DrmSessionClient : public aidl::android::media::BnResourceManagerClient {
    explicit DrmSessionClient(DrmHalAidl* drm, const Vector<uint8_t>& sessionId)
        : mSessionId(sessionId), mDrm(drm) {}

    ::ndk::ScopedAStatus reclaimResource(bool* _aidl_return) override;
    ::ndk::ScopedAStatus getName(::std::string* _aidl_return) override;

    const Vector<uint8_t> mSessionId;

    virtual ~DrmSessionClient();

  private:
    wp<DrmHalAidl> mDrm;

    DISALLOW_EVIL_CONSTRUCTORS(DrmSessionClient);
};

::ndk::ScopedAStatus DrmHalAidl::DrmSessionClient::reclaimResource(bool* _aidl_return) {
    auto sessionId = mSessionId;
    sp<DrmHalAidl> drm = mDrm.promote();
    if (drm == NULL) {
        *_aidl_return = true;
        return ::ndk::ScopedAStatus::ok();
    }
    status_t err = drm->closeSession(sessionId);
    if (err != OK) {
        *_aidl_return = false;
        return ::ndk::ScopedAStatus::ok();
    }
    drm->onEvent(EventTypeAidl::SESSION_RECLAIMED, toHidlVec(sessionId), hidl_vec<uint8_t>());
    *_aidl_return = true;
    return ::ndk::ScopedAStatus::ok();
}

::ndk::ScopedAStatus DrmHalAidl::DrmSessionClient::getName(::std::string* _aidl_return) {
    String8 name;
    sp<DrmHalAidl> drm = mDrm.promote();
    if (drm == NULL) {
        name.append("<deleted>");
    } else if (drm->getPropertyStringInternal(String8("vendor"), name) != OK || name.isEmpty()) {
        name.append("<Get vendor failed or is empty>");
    }
    name.append("[");
    for (size_t i = 0; i < mSessionId.size(); ++i) {
        name.appendFormat("%02x", mSessionId[i]);
    }
    name.append("]");
    *_aidl_return = name;
    return ::ndk::ScopedAStatus::ok();
}

DrmHalAidl::DrmSessionClient::~DrmSessionClient() {
    DrmSessionManager::Instance()->removeSession(mSessionId);
}

// DrmHalAidl methods
DrmHalAidl::DrmHalAidl()
    : mMetrics(std::make_shared<MediaDrmMetrics>()),
      mListener(::ndk::SharedRefBase::make<DrmHalListener>(mMetrics)),
      mFactories(DrmUtils::makeDrmFactoriesAidl()),
      mInitCheck((mFactories.size() == 0) ? ERROR_UNSUPPORTED : NO_INIT) {}

DrmStatus DrmHalAidl::initCheck() const {
    return DrmStatus(mInitCheck);
}

DrmHalAidl::~DrmHalAidl() {}

DrmStatus DrmHalAidl::setListener(const sp<IDrmClient>& listener) {
    mListener->setListener(listener);
    return DrmStatus(NO_ERROR);
}

DrmStatus DrmHalAidl::isCryptoSchemeSupported(const uint8_t uuid[16], const String8& mimeType,
                                              DrmPlugin::SecurityLevel level, bool* isSupported) {
    Mutex::Autolock autoLock(mLock);
    *isSupported = false;
    Uuid uuidAidl = DrmUtils::toAidlUuid(uuid);
    SecurityLevel levelAidl = toAidlSecurityLevel(level);
    std::string mimeTypeStr = mimeType.string();

    for (ssize_t i = mFactories.size() - 1; i >= 0; i--) {
        CryptoSchemes schemes{};
        auto err = mFactories[i]->getSupportedCryptoSchemes(&schemes);
        if (!err.isOk() || !std::count(schemes.uuids.begin(), schemes.uuids.end(), uuidAidl)) {
            continue;
        }

        ALOGV("supported schemes: %s; query: level %d mime %s",
              schemes.toString().c_str(), levelAidl, mimeType.c_str());
        std::map<std::string, SupportedContentType> contentTypes;
        for (auto ct : schemes.mimeTypes) {
            contentTypes[ct.mime] = ct;
        }

        // handle default value cases
        if (levelAidl == SecurityLevel::DEFAULT || levelAidl == SecurityLevel::UNKNOWN) {
            if (mimeType == "") {
                // isCryptoSchemeSupported(uuid)
                *isSupported = true;
            } else {
                // isCryptoSchemeSupported(uuid, mimeType)
                *isSupported = contentTypes.count(mimeTypeStr);
            }
            return DrmStatus(OK);
        } else if (mimeType == "") {
            return DrmStatus(BAD_VALUE);
        }

        auto ct = contentTypes[mimeTypeStr];
        if (levelAidl > ct.maxLevel || levelAidl < ct.minLevel) {
              continue;
        }

        *isSupported = true;
        break;
    }

    return DrmStatus(OK);
}

DrmStatus DrmHalAidl::createPlugin(const uint8_t uuid[16], const String8& appPackageName) {
    Mutex::Autolock autoLock(mLock);
    if (mInitCheck == ERROR_UNSUPPORTED) return mInitCheck;
    Uuid uuidAidl = DrmUtils::toAidlUuid(uuid);
    std::string appPackageNameAidl = toStdString(appPackageName);
    std::shared_ptr<IDrmPluginAidl> pluginAidl;
    mMetrics->SetAppPackageName(appPackageName);
    mMetrics->SetAppUid(AIBinder_getCallingUid());
    for (ssize_t i = mFactories.size() - 1; i >= 0; i--) {
        ::ndk::ScopedAStatus status =
                mFactories[i]->createDrmPlugin(uuidAidl, appPackageNameAidl, &pluginAidl);
        if (status.isOk()) {
            if (pluginAidl != NULL) {
                mPlugin = pluginAidl;
                break;
            }
        } else {
            DrmUtils::LOG2BE(uuid, "Failed to make drm plugin: %d",
                             status.getServiceSpecificError());
        }
    }

    if (mPlugin == NULL) {
        DrmUtils::LOG2BE(uuid, "No supported hal instance found");
        mInitCheck = ERROR_UNSUPPORTED;
    } else {
        mInitCheck = OK;
        // Stored pointer mListener upcast to base BnDrmPluginListener
        ::ndk::ScopedAStatus status = mPlugin
            ->setListener(std::static_pointer_cast<BnDrmPluginListener>(mListener));
        if (!status.isOk()) {
            mInitCheck = DEAD_OBJECT;
            ALOGE("setListener failed: ex %d svc err %d",
                status.getExceptionCode(),
                status.getServiceSpecificError());
        }

        if (mInitCheck != OK) {
            mPlugin.reset();
        }
    }

    return DrmStatus(mInitCheck);
}

DrmStatus DrmHalAidl::openSession(DrmPlugin::SecurityLevel level, Vector<uint8_t>& sessionId) {
    Mutex::Autolock autoLock(mLock);
    INIT_CHECK();

    SecurityLevel aSecurityLevel = toAidlSecurityLevel(level);

    if (aSecurityLevel == SecurityLevel::UNKNOWN) {
        return ERROR_DRM_CANNOT_HANDLE;
    }

    DrmStatus err = UNKNOWN_ERROR;
    bool retry = true;
    do {
        std::vector<uint8_t> aSessionId;

        ::ndk::ScopedAStatus status = mPlugin->openSession(aSecurityLevel, &aSessionId);
        if (status.isOk()) sessionId = toVector(aSessionId);
        err = statusAidlToDrmStatus(status);

        if (err == ERROR_DRM_RESOURCE_BUSY && retry) {
            mLock.unlock();
            // reclaimSession may call back to closeSession, since mLock is
            // shared between Drm instances, we should unlock here to avoid
            // deadlock.
            retry = DrmSessionManager::Instance()->reclaimSession(AIBinder_getCallingPid());
            mLock.lock();
        } else {
            retry = false;
        }
    } while (retry);

    if (err == OK) {
        std::shared_ptr<DrmSessionClient> client =
                ndk::SharedRefBase::make<DrmSessionClient>(this, sessionId);
        DrmSessionManager::Instance()->addSession(
                AIBinder_getCallingPid(), std::static_pointer_cast<IResourceManagerClient>(client),
                sessionId);
        mOpenSessions.push_back(client);
        mMetrics->SetSessionStart(sessionId);
    }

    mMetrics->mOpenSessionCounter.Increment(err);
    return err;
}

DrmStatus DrmHalAidl::closeSession(Vector<uint8_t> const& sessionId) {
    Mutex::Autolock autoLock(mLock);
    INIT_CHECK();

    std::vector<uint8_t> sessionIdAidl = toStdVec(sessionId);
    ::ndk::ScopedAStatus status = mPlugin->closeSession(sessionIdAidl);
    DrmStatus response = statusAidlToDrmStatus(status);
    if (status.isOk()) {
        DrmSessionManager::Instance()->removeSession(sessionId);
        for (auto i = mOpenSessions.begin(); i != mOpenSessions.end(); i++) {
            if (isEqualSessionId((*i)->mSessionId, sessionId)) {
                mOpenSessions.erase(i);
                break;
            }
        }

        mMetrics->SetSessionEnd(sessionId);
    }

    mMetrics->mCloseSessionCounter.Increment(response);
    return response;
}

DrmStatus DrmHalAidl::getKeyRequest(Vector<uint8_t> const& sessionId,
                                    Vector<uint8_t> const& initData, String8 const& mimeType,
                                    DrmPlugin::KeyType keyType,
                                    KeyedVector<String8, String8> const& optionalParameters,
                                    Vector<uint8_t>& request, String8& defaultUrl,
                                    DrmPlugin::KeyRequestType* keyRequestType) {
    Mutex::Autolock autoLock(mLock);
    INIT_CHECK();
    EventTimer<status_t> keyRequestTimer(&mMetrics->mGetKeyRequestTimeUs);

    DrmSessionManager::Instance()->useSession(sessionId);

    KeyType aKeyType;
    if (keyType == DrmPlugin::kKeyType_Streaming) {
        aKeyType = KeyType::STREAMING;
    } else if (keyType == DrmPlugin::kKeyType_Offline) {
        aKeyType = KeyType::OFFLINE;
    } else if (keyType == DrmPlugin::kKeyType_Release) {
        aKeyType = KeyType::RELEASE;
    } else {
        keyRequestTimer.SetAttribute(BAD_VALUE);
        return BAD_VALUE;
    }

    DrmStatus err = UNKNOWN_ERROR;

    std::vector<uint8_t> sessionIdAidl = toStdVec(sessionId);
    std::vector<uint8_t> initDataAidl = toStdVec(initData);
    KeyRequest keyRequest;

    ::ndk::ScopedAStatus status =
            mPlugin->getKeyRequest(sessionIdAidl, initDataAidl, toStdString(mimeType), aKeyType,
                                   toKeyValueVector(optionalParameters), &keyRequest);
    if (status.isOk()) {
        request = toVector(keyRequest.request);
        defaultUrl = toString8(keyRequest.defaultUrl);
        *keyRequestType = toKeyRequestType(keyRequest.requestType);
    }

    err = statusAidlToDrmStatus(status);
    keyRequestTimer.SetAttribute(err);
    return err;
}

DrmStatus DrmHalAidl::provideKeyResponse(Vector<uint8_t> const& sessionId,
                                         Vector<uint8_t> const& response,
                                         Vector<uint8_t>& keySetId) {
    Mutex::Autolock autoLock(mLock);
    INIT_CHECK();
    EventTimer<status_t> keyResponseTimer(&mMetrics->mProvideKeyResponseTimeUs);

    DrmSessionManager::Instance()->useSession(sessionId);

    DrmStatus err = UNKNOWN_ERROR;

    std::vector<uint8_t> sessionIdAidl = toStdVec(sessionId);
    std::vector<uint8_t> responseAidl = toStdVec(response);
    KeySetId keySetIdsAidl;
    ::ndk::ScopedAStatus status =
            mPlugin->provideKeyResponse(sessionIdAidl, responseAidl, &keySetIdsAidl);

    if (status.isOk()) keySetId = toVector(keySetIdsAidl.keySetId);
    err = statusAidlToDrmStatus(status);
    keyResponseTimer.SetAttribute(err);
    return err;
}

DrmStatus DrmHalAidl::removeKeys(Vector<uint8_t> const& keySetId) {
    Mutex::Autolock autoLock(mLock);
    INIT_CHECK();

    ::ndk::ScopedAStatus status = mPlugin->removeKeys(toStdVec(keySetId));
    return statusAidlToDrmStatus(status);
}

DrmStatus DrmHalAidl::restoreKeys(Vector<uint8_t> const& sessionId,
                                  Vector<uint8_t> const& keySetId) {
    Mutex::Autolock autoLock(mLock);
    INIT_CHECK();

    DrmSessionManager::Instance()->useSession(sessionId);

    KeySetId keySetIdsAidl;
    keySetIdsAidl.keySetId = toStdVec(keySetId);
    ::ndk::ScopedAStatus status = mPlugin->restoreKeys(toStdVec(sessionId), keySetIdsAidl);
    return statusAidlToDrmStatus(status);
}

DrmStatus DrmHalAidl::queryKeyStatus(Vector<uint8_t> const& sessionId,
                                     KeyedVector<String8, String8>& infoMap) const {
    Mutex::Autolock autoLock(mLock);
    INIT_CHECK();

    DrmSessionManager::Instance()->useSession(sessionId);

    std::vector<KeyValue> infoMapAidl;
    ::ndk::ScopedAStatus status = mPlugin->queryKeyStatus(toStdVec(sessionId), &infoMapAidl);

    infoMap = toKeyedVector(infoMapAidl);

    return statusAidlToDrmStatus(status);
}

DrmStatus DrmHalAidl::getProvisionRequest(String8 const& certType, String8 const& certAuthority,
                                          Vector<uint8_t>& request, String8& defaultUrl) {
    Mutex::Autolock autoLock(mLock);
    INIT_CHECK();

    DrmStatus err = UNKNOWN_ERROR;

    ProvisionRequest requestAidl;
    ::ndk::ScopedAStatus status = mPlugin->getProvisionRequest(
            toStdString(certType), toStdString(certAuthority), &requestAidl);

    request = toVector(requestAidl.request);
    defaultUrl = toString8(requestAidl.defaultUrl);

    err = statusAidlToDrmStatus(status);
    mMetrics->mGetProvisionRequestCounter.Increment(err);
    return err;
}

DrmStatus DrmHalAidl::provideProvisionResponse(Vector<uint8_t> const& response,
                                               Vector<uint8_t>& certificate,
                                               Vector<uint8_t>& wrappedKey) {
    Mutex::Autolock autoLock(mLock);
    INIT_CHECK();

    DrmStatus err = UNKNOWN_ERROR;
    ProvideProvisionResponseResult result;
    ::ndk::ScopedAStatus status = mPlugin->provideProvisionResponse(toStdVec(response), &result);

    certificate = toVector(result.certificate);
    wrappedKey = toVector(result.wrappedKey);
    err = statusAidlToDrmStatus(status);
    mMetrics->mProvideProvisionResponseCounter.Increment(err);
    return err;
}

DrmStatus DrmHalAidl::getSecureStops(List<Vector<uint8_t>>& secureStops) {
    Mutex::Autolock autoLock(mLock);
    INIT_CHECK();

    std::vector<SecureStop> result;
    ::ndk::ScopedAStatus status = mPlugin->getSecureStops(&result);

    secureStops = toSecureStops(result);

    return statusAidlToDrmStatus(status);
}

DrmStatus DrmHalAidl::getSecureStopIds(List<Vector<uint8_t>>& secureStopIds) {
    Mutex::Autolock autoLock(mLock);
    INIT_CHECK();

    std::vector<SecureStopId> result;
    ::ndk::ScopedAStatus status = mPlugin->getSecureStopIds(&result);

    secureStopIds = toSecureStopIds(result);

    return statusAidlToDrmStatus(status);
}

DrmStatus DrmHalAidl::getSecureStop(Vector<uint8_t> const& ssid, Vector<uint8_t>& secureStop) {
    Mutex::Autolock autoLock(mLock);
    INIT_CHECK();

    SecureStopId ssidAidl;
    ssidAidl.secureStopId = toStdVec(ssid);

    SecureStop result;
    ::ndk::ScopedAStatus status = mPlugin->getSecureStop(ssidAidl, &result);

    secureStop = toVector(result.opaqueData);

    return statusAidlToDrmStatus(status);
}

DrmStatus DrmHalAidl::releaseSecureStops(Vector<uint8_t> const& ssRelease) {
    Mutex::Autolock autoLock(mLock);
    INIT_CHECK();

    OpaqueData ssId;
    ssId.opaqueData = toStdVec(ssRelease);
    ::ndk::ScopedAStatus status = mPlugin->releaseSecureStops(ssId);

    return statusAidlToDrmStatus(status);
}

DrmStatus DrmHalAidl::removeSecureStop(Vector<uint8_t> const& ssid) {
    Mutex::Autolock autoLock(mLock);

    INIT_CHECK();

    SecureStopId ssidAidl;
    ssidAidl.secureStopId = toStdVec(ssid);
    ::ndk::ScopedAStatus status = mPlugin->removeSecureStop(ssidAidl);
    return statusAidlToDrmStatus(status);
}

DrmStatus DrmHalAidl::removeAllSecureStops() {
    Mutex::Autolock autoLock(mLock);
    INIT_CHECK();

    ::ndk::ScopedAStatus status = mPlugin->releaseAllSecureStops();
    return statusAidlToDrmStatus(status);
}

DrmStatus DrmHalAidl::getHdcpLevels(DrmPlugin::HdcpLevel* connected,
                                    DrmPlugin::HdcpLevel* max) const {
    Mutex::Autolock autoLock(mLock);
    INIT_CHECK();

    if (connected == NULL || max == NULL) {
        return BAD_VALUE;
    }

    *connected = DrmPlugin::kHdcpLevelUnknown;
    *max = DrmPlugin::kHdcpLevelUnknown;

    HdcpLevels lvlsAidl;
    ::ndk::ScopedAStatus status = mPlugin->getHdcpLevels(&lvlsAidl);

    *connected = toHdcpLevel(lvlsAidl.connectedLevel);
    *max = toHdcpLevel(lvlsAidl.maxLevel);

    return statusAidlToDrmStatus(status);
}

DrmStatus DrmHalAidl::getNumberOfSessions(uint32_t* open, uint32_t* max) const {
    Mutex::Autolock autoLock(mLock);
    INIT_CHECK();

    if (open == NULL || max == NULL) {
        return BAD_VALUE;
    }

    *open = 0;
    *max = 0;

    NumberOfSessions result;
    ::ndk::ScopedAStatus status = mPlugin->getNumberOfSessions(&result);

    *open = result.currentSessions;
    *max = result.maxSessions;

    return statusAidlToDrmStatus(status);
}

DrmStatus DrmHalAidl::getSecurityLevel(Vector<uint8_t> const& sessionId,
                                       DrmPlugin::SecurityLevel* level) const {
    Mutex::Autolock autoLock(mLock);
    INIT_CHECK();

    if (level == NULL) {
        return BAD_VALUE;
    }

    *level = DrmPlugin::kSecurityLevelUnknown;

    SecurityLevel result;
    ::ndk::ScopedAStatus status = mPlugin->getSecurityLevel(toStdVec(sessionId), &result);

    *level = toSecurityLevel(result);

    return statusAidlToDrmStatus(status);
}

DrmStatus DrmHalAidl::getOfflineLicenseKeySetIds(List<Vector<uint8_t>>& keySetIds) const {
    Mutex::Autolock autoLock(mLock);
    INIT_CHECK();

    std::vector<KeySetId> result;
    ::ndk::ScopedAStatus status = mPlugin->getOfflineLicenseKeySetIds(&result);

    keySetIds = toKeySetIds(result);

    return statusAidlToDrmStatus(status);
}

DrmStatus DrmHalAidl::removeOfflineLicense(Vector<uint8_t> const& keySetId) {
    Mutex::Autolock autoLock(mLock);
    INIT_CHECK();

    KeySetId keySetIdAidl;
    keySetIdAidl.keySetId = toStdVec(keySetId);
    ::ndk::ScopedAStatus status = mPlugin->removeOfflineLicense(keySetIdAidl);
    return statusAidlToDrmStatus(status);
}

DrmStatus DrmHalAidl::getOfflineLicenseState(Vector<uint8_t> const& keySetId,
                                             DrmPlugin::OfflineLicenseState* licenseState) const {
    Mutex::Autolock autoLock(mLock);

    INIT_CHECK();
    *licenseState = DrmPlugin::kOfflineLicenseStateUnknown;

    KeySetId keySetIdAidl;
    keySetIdAidl.keySetId = toStdVec(keySetId);

    OfflineLicenseState result;
    ::ndk::ScopedAStatus status = mPlugin->getOfflineLicenseState(keySetIdAidl, &result);

    *licenseState = toOfflineLicenseState(result);

    return statusAidlToDrmStatus(status);
}

DrmStatus DrmHalAidl::getPropertyString(String8 const& name, String8& value) const {
    Mutex::Autolock autoLock(mLock);
    return DrmStatus(getPropertyStringInternal(name, value));
}

DrmStatus DrmHalAidl::getPropertyStringInternal(String8 const& name, String8& value) const {
    // This function is internal to the class and should only be called while
    // mLock is already held.
    INIT_CHECK();

    std::string result;
    ::ndk::ScopedAStatus status = mPlugin->getPropertyString(toStdString(name), &result);

    value = toString8(result);

    return statusAidlToDrmStatus(status);
}

DrmStatus DrmHalAidl::getPropertyByteArray(String8 const& name, Vector<uint8_t>& value) const {
    Mutex::Autolock autoLock(mLock);
    return DrmStatus(getPropertyByteArrayInternal(name, value));
}

DrmStatus DrmHalAidl::getPropertyByteArrayInternal(String8 const& name,
                                                   Vector<uint8_t>& value) const {
    // This function is internal to the class and should only be called while
    // mLock is already held.
    INIT_CHECK();

    DrmStatus err = UNKNOWN_ERROR;

    std::vector<uint8_t> result;
    ::ndk::ScopedAStatus status = mPlugin->getPropertyByteArray(toStdString(name), &result);

    value = toVector(result);
    err = statusAidlToDrmStatus(status);
    if (name == kPropertyDeviceUniqueId) {
        mMetrics->mGetDeviceUniqueIdCounter.Increment(err);
    }
    return err;
}

DrmStatus DrmHalAidl::setPropertyString(String8 const& name, String8 const& value) const {
    Mutex::Autolock autoLock(mLock);
    INIT_CHECK();

    ::ndk::ScopedAStatus status = mPlugin->setPropertyString(toStdString(name), toStdString(value));
    return statusAidlToDrmStatus(status);
}

DrmStatus DrmHalAidl::setPropertyByteArray(String8 const& name,
                                           Vector<uint8_t> const& value) const {
    Mutex::Autolock autoLock(mLock);
    INIT_CHECK();

    ::ndk::ScopedAStatus status = mPlugin->setPropertyByteArray(toStdString(name), toStdVec(value));
    return statusAidlToDrmStatus(status);
}

DrmStatus DrmHalAidl::getMetrics(const sp<IDrmMetricsConsumer>& consumer) {
    if (consumer == nullptr) {
        return DrmStatus(UNEXPECTED_NULL);
    }
    consumer->consumeFrameworkMetrics(*mMetrics.get());

    // Append vendor metrics if they are supported.

    String8 vendor;
    String8 description;
    if (getPropertyStringInternal(String8("vendor"), vendor) != OK || vendor.isEmpty()) {
        ALOGE("Get vendor failed or is empty");
        vendor = "NONE";
    }
    if (getPropertyStringInternal(String8("description"), description) != OK ||
        description.isEmpty()) {
        ALOGE("Get description failed or is empty.");
        description = "NONE";
    }
    vendor += ".";
    vendor += description;

    hidl_vec<DrmMetricGroupHidl> pluginMetrics;
    DrmStatus err = UNKNOWN_ERROR;

    std::vector<DrmMetricGroupAidl> result;
    ::ndk::ScopedAStatus status = mPlugin->getMetrics(&result);

    if (status.isOk()) {
        pluginMetrics = toDrmMetricGroupHidl(result);
        consumer->consumeHidlMetrics(vendor, pluginMetrics);
    }

    err = statusAidlToDrmStatus(status);

    return err;
}

DrmStatus DrmHalAidl::setCipherAlgorithm(Vector<uint8_t> const& sessionId,
                                         String8 const& algorithm) {
    Mutex::Autolock autoLock(mLock);
    INIT_CHECK();

    DrmSessionManager::Instance()->useSession(sessionId);

    ::ndk::ScopedAStatus status =
            mPlugin->setCipherAlgorithm(toStdVec(sessionId), toStdString(algorithm));
    return statusAidlToDrmStatus(status);
}

DrmStatus DrmHalAidl::setMacAlgorithm(Vector<uint8_t> const& sessionId, String8 const& algorithm) {
    Mutex::Autolock autoLock(mLock);
    INIT_CHECK();

    DrmSessionManager::Instance()->useSession(sessionId);

    ::ndk::ScopedAStatus status =
            mPlugin->setMacAlgorithm(toStdVec(sessionId), toStdString(algorithm));
    return statusAidlToDrmStatus(status);
}

DrmStatus DrmHalAidl::encrypt(Vector<uint8_t> const& sessionId, Vector<uint8_t> const& keyId,
                              Vector<uint8_t> const& input, Vector<uint8_t> const& iv,
                              Vector<uint8_t>& output) {
    Mutex::Autolock autoLock(mLock);
    INIT_CHECK();

    DrmSessionManager::Instance()->useSession(sessionId);

    std::vector<uint8_t> result;
    ::ndk::ScopedAStatus status = mPlugin->encrypt(toStdVec(sessionId), toStdVec(keyId),
                                                   toStdVec(input), toStdVec(iv), &result);

    output = toVector(result);

    return statusAidlToDrmStatus(status);
}

DrmStatus DrmHalAidl::decrypt(Vector<uint8_t> const& sessionId, Vector<uint8_t> const& keyId,
                              Vector<uint8_t> const& input, Vector<uint8_t> const& iv,
                              Vector<uint8_t>& output) {
    Mutex::Autolock autoLock(mLock);
    INIT_CHECK();

    DrmSessionManager::Instance()->useSession(sessionId);

    std::vector<uint8_t> result;
    ::ndk::ScopedAStatus status = mPlugin->decrypt(toStdVec(sessionId), toStdVec(keyId),
                                                   toStdVec(input), toStdVec(iv), &result);

    output = toVector(result);

    return statusAidlToDrmStatus(status);
}

DrmStatus DrmHalAidl::sign(Vector<uint8_t> const& sessionId, Vector<uint8_t> const& keyId,
                           Vector<uint8_t> const& message, Vector<uint8_t>& signature) {
    Mutex::Autolock autoLock(mLock);
    INIT_CHECK();

    DrmSessionManager::Instance()->useSession(sessionId);

    std::vector<uint8_t> result;
    ::ndk::ScopedAStatus status =
            mPlugin->sign(toStdVec(sessionId), toStdVec(keyId), toStdVec(message), &result);

    signature = toVector(result);

    return statusAidlToDrmStatus(status);
}

DrmStatus DrmHalAidl::verify(Vector<uint8_t> const& sessionId, Vector<uint8_t> const& keyId,
                             Vector<uint8_t> const& message, Vector<uint8_t> const& signature,
                             bool& match) {
    Mutex::Autolock autoLock(mLock);
    INIT_CHECK();

    DrmSessionManager::Instance()->useSession(sessionId);

    ::ndk::ScopedAStatus status = mPlugin->verify(toStdVec(sessionId), toStdVec(keyId),
                                                  toStdVec(message), toStdVec(signature), &match);

    return statusAidlToDrmStatus(status);
}

DrmStatus DrmHalAidl::signRSA(Vector<uint8_t> const& sessionId, String8 const& algorithm,
                              Vector<uint8_t> const& message, Vector<uint8_t> const& wrappedKey,
                              Vector<uint8_t>& signature) {
    Mutex::Autolock autoLock(mLock);
    INIT_CHECK();

    DrmSessionManager::Instance()->useSession(sessionId);

    std::vector<uint8_t> result;
    ::ndk::ScopedAStatus status =
            mPlugin->signRSA(toStdVec(sessionId), toStdString(algorithm), toStdVec(message),
                             toStdVec(wrappedKey), &result);

    signature = toVector(result);

    return statusAidlToDrmStatus(status);
}

DrmStatus DrmHalAidl::requiresSecureDecoder(const char* mime, bool* required) const {
    Mutex::Autolock autoLock(mLock);
    INIT_CHECK();

    std::string mimeAidl(mime);
    ::ndk::ScopedAStatus status =
        mPlugin->requiresSecureDecoder(mimeAidl, SecurityLevel::DEFAULT, required);
    if (!status.isOk()) {
        DrmUtils::LOG2BE("requiresSecureDecoder txn failed: %d", status.getServiceSpecificError());
        return DrmStatus(DEAD_OBJECT);
    }

    return DrmStatus(OK);
}

DrmStatus DrmHalAidl::requiresSecureDecoder(const char* mime,
                                            DrmPlugin::SecurityLevel securityLevel,
                                            bool* required) const {
    Mutex::Autolock autoLock(mLock);
    INIT_CHECK();

    auto aLevel = toAidlSecurityLevel(securityLevel);
    std::string mimeAidl(mime);
    ::ndk::ScopedAStatus status = mPlugin->requiresSecureDecoder(mimeAidl, aLevel, required);

    DrmStatus err = statusAidlToDrmStatus(status);
    if (!status.isOk()) {
        DrmUtils::LOG2BE("requiresSecureDecoder txn failed: %d", status.getServiceSpecificError());
    }

    return err;
}

DrmStatus DrmHalAidl::setPlaybackId(Vector<uint8_t> const& sessionId, const char* playbackId) {
    Mutex::Autolock autoLock(mLock);
    INIT_CHECK();
    std::string playbackIdAidl(playbackId);
    ::ndk::ScopedAStatus status = mPlugin->setPlaybackId(toStdVec(sessionId), playbackIdAidl);
    return statusAidlToDrmStatus(status);
}

DrmStatus DrmHalAidl::getLogMessages(Vector<drm::V1_4::LogMessage>& logs) const {
    Mutex::Autolock autoLock(mLock);
    return DrmStatus(DrmUtils::GetLogMessagesAidl<IDrmPluginAidl>(mPlugin, logs));
}

void DrmHalAidl::closeOpenSessions() {
    Mutex::Autolock autoLock(mLock);
    auto openSessions = mOpenSessions;
    for (size_t i = 0; i < openSessions.size(); i++) {
        mLock.unlock();
        closeSession(openSessions[i]->mSessionId);
        mLock.lock();
    }
    mOpenSessions.clear();
}

std::string DrmHalAidl::reportPluginMetrics() const {
    Vector<uint8_t> metricsVector;
    String8 vendor;
    String8 description;
    std::string metricsString;
    if (getPropertyStringInternal(String8("vendor"), vendor) == OK &&
        getPropertyStringInternal(String8("description"), description) == OK &&
        getPropertyByteArrayInternal(String8("metrics"), metricsVector) == OK) {
        metricsString = toBase64StringNoPad(metricsVector.array(), metricsVector.size());
        status_t res = android::reportDrmPluginMetrics(metricsString, vendor, description,
                                                       mMetrics->GetAppUid());
        if (res != OK) {
            ALOGE("Metrics were retrieved but could not be reported: %d", res);
        }
    }
    return metricsString;
}

std::string DrmHalAidl::reportFrameworkMetrics(const std::string& pluginMetrics) const {
    mediametrics_handle_t item(mediametrics_create("mediadrm"));
    mediametrics_setUid(item, mMetrics->GetAppUid());
    String8 vendor;
    String8 description;
    status_t result = getPropertyStringInternal(String8("vendor"), vendor);
    if (result != OK) {
        ALOGE("Failed to get vendor from drm plugin: %d", result);
    } else {
        mediametrics_setCString(item, "vendor", vendor.c_str());
    }
    result = getPropertyStringInternal(String8("description"), description);
    if (result != OK) {
        ALOGE("Failed to get description from drm plugin: %d", result);
    } else {
        mediametrics_setCString(item, "description", description.c_str());
    }

    std::string serializedMetrics;
    result = mMetrics->GetSerializedMetrics(&serializedMetrics);
    if (result != OK) {
        ALOGE("Failed to serialize framework metrics: %d", result);
    }
    std::string b64EncodedMetrics =
            toBase64StringNoPad(serializedMetrics.data(), serializedMetrics.size());
    if (!b64EncodedMetrics.empty()) {
        mediametrics_setCString(item, "serialized_metrics", b64EncodedMetrics.c_str());
    }
    if (!pluginMetrics.empty()) {
        mediametrics_setCString(item, "plugin_metrics", pluginMetrics.c_str());
    }
    if (!mediametrics_selfRecord(item)) {
        ALOGE("Failed to self record framework metrics");
    }
    mediametrics_delete(item);
    return serializedMetrics;
}

DrmStatus DrmHalAidl::getSupportedSchemes(std::vector<uint8_t>& schemes) const {
    Mutex::Autolock autoLock(mLock);

    if (mFactories.empty()) return UNKNOWN_ERROR;
    for (ssize_t i = mFactories.size() - 1; i >= 0; i--) {
        CryptoSchemes curSchemes{};
        auto err = mFactories[i]->getSupportedCryptoSchemes(&curSchemes);
        if (!err.isOk()) {
            continue;
        }

        for (auto uuidObj : curSchemes.uuids) {
            schemes.insert(schemes.end(), uuidObj.uuid.begin(), uuidObj.uuid.end());
        }
    }

    return DrmStatus(OK);
}

void DrmHalAidl::cleanup() {
    closeOpenSessions();

    Mutex::Autolock autoLock(mLock);
    if (mInitCheck == OK) reportFrameworkMetrics(reportPluginMetrics());

    setListener(NULL);
    mInitCheck = NO_INIT;
    if (mPlugin != NULL) {
        if (!mPlugin->setListener(NULL).isOk()) {
            mInitCheck = DEAD_OBJECT;
        }
    }

    mPlugin.reset();
}

DrmStatus DrmHalAidl::destroyPlugin() {
    cleanup();
    return DrmStatus(OK);
}

::ndk::ScopedAStatus DrmHalAidl::onEvent(EventTypeAidl eventTypeAidl,
                                         const std::vector<uint8_t>& sessionId,
                                         const std::vector<uint8_t>& data) {
    return mListener->onEvent(eventTypeAidl, sessionId, data);
}

::ndk::ScopedAStatus DrmHalAidl::onExpirationUpdate(const std::vector<uint8_t>& sessionId,
                                                    int64_t expiryTimeInMS) {
    return mListener->onExpirationUpdate(sessionId, expiryTimeInMS);
}

::ndk::ScopedAStatus DrmHalAidl::onKeysChange(const std::vector<uint8_t>& sessionId,
                                              const std::vector<KeyStatus>& keyStatusListAidl,
                                              bool hasNewUsableKey) {
    return mListener->onKeysChange(sessionId, keyStatusListAidl, hasNewUsableKey);
}

::ndk::ScopedAStatus DrmHalAidl::onSessionLostState(const std::vector<uint8_t>& sessionId) {
    return mListener->onSessionLostState(sessionId);
}

}  // namespace android