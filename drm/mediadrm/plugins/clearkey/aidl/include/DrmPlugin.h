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
#pragma once

#include <aidl/android/hardware/drm/BnDrmPlugin.h>
#include <aidl/android/hardware/drm/IDrmPluginListener.h>
#include <aidl/android/hardware/drm/Status.h>

#include <stdio.h>
#include <map>

#include <utils/List.h>

#include "DeviceFiles.h"
#include "SessionLibrary.h"

namespace aidl {
namespace android {
namespace hardware {
namespace drm {
namespace clearkey {

using namespace clearkeydrm;
using ::aidl::android::hardware::drm::KeyType;
using ::aidl::android::hardware::drm::Status;

struct DrmPlugin : public BnDrmPlugin {
  public:
    explicit DrmPlugin(SessionLibrary* sessionLibrary);
    virtual ~DrmPlugin() { mFileHandle.DeleteAllLicenses(); }

    ::ndk::ScopedAStatus closeSession(const std::vector<uint8_t>& in_sessionId) override;
    ::ndk::ScopedAStatus decrypt(const std::vector<uint8_t>& in_sessionId,
                                 const std::vector<uint8_t>& in_keyId,
                                 const std::vector<uint8_t>& in_input,
                                 const std::vector<uint8_t>& in_iv,
                                 std::vector<uint8_t>* _aidl_return) override;
    ::ndk::ScopedAStatus encrypt(const std::vector<uint8_t>& in_sessionId,
                                 const std::vector<uint8_t>& in_keyId,
                                 const std::vector<uint8_t>& in_input,
                                 const std::vector<uint8_t>& in_iv,
                                 std::vector<uint8_t>* _aidl_return) override;
    ::ndk::ScopedAStatus getHdcpLevels(
            ::aidl::android::hardware::drm::HdcpLevels* _aidl_return) override;
    ::ndk::ScopedAStatus getKeyRequest(
            const std::vector<uint8_t>& in_scope, const std::vector<uint8_t>& in_initData,
            const std::string& in_mimeType, ::aidl::android::hardware::drm::KeyType in_keyType,
            const std::vector<::aidl::android::hardware::drm::KeyValue>& in_optionalParameters,
            ::aidl::android::hardware::drm::KeyRequest* _aidl_return) override;
    ::ndk::ScopedAStatus getLogMessages(
            std::vector<::aidl::android::hardware::drm::LogMessage>* _aidl_return) override;

    ::ndk::ScopedAStatus getMetrics(
            std::vector<::aidl::android::hardware::drm::DrmMetricGroup>* _aidl_return) override;
    ::ndk::ScopedAStatus getNumberOfSessions(
            ::aidl::android::hardware::drm::NumberOfSessions* _aidl_return) override;
    ::ndk::ScopedAStatus getOfflineLicenseKeySetIds(
            std::vector<::aidl::android::hardware::drm::KeySetId>* _aidl_return) override;
    ::ndk::ScopedAStatus getOfflineLicenseState(
            const ::aidl::android::hardware::drm::KeySetId& in_keySetId,
            ::aidl::android::hardware::drm::OfflineLicenseState* _aidl_return) override;
    ::ndk::ScopedAStatus getPropertyByteArray(const std::string& in_propertyName,
                                              std::vector<uint8_t>* _aidl_return) override;
    ::ndk::ScopedAStatus getPropertyString(const std::string& in_propertyName,
                                           std::string* _aidl_return) override;
    ::ndk::ScopedAStatus getProvisionRequest(
            const std::string& in_certificateType, const std::string& in_certificateAuthority,
            ::aidl::android::hardware::drm::ProvisionRequest* _aidl_return) override;
    ::ndk::ScopedAStatus getSecureStop(
            const ::aidl::android::hardware::drm::SecureStopId& in_secureStopId,
            ::aidl::android::hardware::drm::SecureStop* _aidl_return) override;
    ::ndk::ScopedAStatus getSecureStopIds(
            std::vector<::aidl::android::hardware::drm::SecureStopId>* _aidl_return) override;
    ::ndk::ScopedAStatus getSecureStops(
            std::vector<::aidl::android::hardware::drm::SecureStop>* _aidl_return) override;
    ::ndk::ScopedAStatus getSecurityLevel(
            const std::vector<uint8_t>& in_sessionId,
            ::aidl::android::hardware::drm::SecurityLevel* _aidl_return) override;
    ::ndk::ScopedAStatus openSession(::aidl::android::hardware::drm::SecurityLevel in_securityLevel,
                                     std::vector<uint8_t>* _aidl_return) override;
    ::ndk::ScopedAStatus provideKeyResponse(
            const std::vector<uint8_t>& in_scope, const std::vector<uint8_t>& in_response,
            ::aidl::android::hardware::drm::KeySetId* _aidl_return) override;
    ::ndk::ScopedAStatus provideProvisionResponse(
            const std::vector<uint8_t>& in_response,
            ::aidl::android::hardware::drm::ProvideProvisionResponseResult* _aidl_return) override;
    ::ndk::ScopedAStatus queryKeyStatus(
            const std::vector<uint8_t>& in_sessionId,
            std::vector<::aidl::android::hardware::drm::KeyValue>* _aidl_return) override;
    ::ndk::ScopedAStatus releaseAllSecureStops() override;
    ::ndk::ScopedAStatus releaseSecureStop(
            const ::aidl::android::hardware::drm::SecureStopId& in_secureStopId) override;
    ::ndk::ScopedAStatus releaseSecureStops(
            const ::aidl::android::hardware::drm::OpaqueData& in_ssRelease) override;
    ::ndk::ScopedAStatus removeAllSecureStops() override;
    ::ndk::ScopedAStatus removeKeys(const std::vector<uint8_t>& in_sessionId) override;
    ::ndk::ScopedAStatus removeOfflineLicense(
            const ::aidl::android::hardware::drm::KeySetId& in_keySetId) override;
    ::ndk::ScopedAStatus removeSecureStop(
            const ::aidl::android::hardware::drm::SecureStopId& in_secureStopId) override;
    ::ndk::ScopedAStatus requiresSecureDecoder(
            const std::string& in_mime, ::aidl::android::hardware::drm::SecurityLevel in_level,
            bool* _aidl_return) override;
    ::ndk::ScopedAStatus restoreKeys(
            const std::vector<uint8_t>& in_sessionId,
            const ::aidl::android::hardware::drm::KeySetId& in_keySetId) override;
    ::ndk::ScopedAStatus setCipherAlgorithm(const std::vector<uint8_t>& in_sessionId,
                                            const std::string& in_algorithm) override;
    ::ndk::ScopedAStatus setListener(
            //            const ::android::sp<::aidl::android::hardware::drm::IDrmPluginListener>&
            //            in_listener)
            const std::shared_ptr<IDrmPluginListener>& in_listener) override;
    ::ndk::ScopedAStatus setMacAlgorithm(const std::vector<uint8_t>& in_sessionId,
                                         const std::string& in_algorithm) override;
    ::ndk::ScopedAStatus setPlaybackId(const std::vector<uint8_t>& in_sessionId,
                                       const std::string& in_playbackId) override;
    ::ndk::ScopedAStatus setPropertyByteArray(const std::string& in_propertyName,
                                              const std::vector<uint8_t>& in_value) override;
    ::ndk::ScopedAStatus setPropertyString(const std::string& in_propertyName,
                                           const std::string& in_value) override;
    ::ndk::ScopedAStatus sign(const std::vector<uint8_t>& in_sessionId,
                              const std::vector<uint8_t>& in_keyId,
                              const std::vector<uint8_t>& in_message,
                              std::vector<uint8_t>* _aidl_return) override;
    ::ndk::ScopedAStatus signRSA(const std::vector<uint8_t>& in_sessionId,
                                 const std::string& in_algorithm,
                                 const std::vector<uint8_t>& in_message,
                                 const std::vector<uint8_t>& in_wrappedkey,
                                 std::vector<uint8_t>* _aidl_return) override;
    ::ndk::ScopedAStatus verify(const std::vector<uint8_t>& in_sessionId,
                                const std::vector<uint8_t>& in_keyId,
                                const std::vector<uint8_t>& in_message,
                                const std::vector<uint8_t>& in_signature,
                                bool* _aidl_return) override;

  private:
    void initProperties();
    int32_t getIntProperty(const std::string& prop, int32_t defaultVal = 0) const;
    int32_t getOemError() const;
    int32_t getErrorContext() const;
    void installSecureStop(const std::vector<uint8_t>& sessionId);
    bool makeKeySetId(std::string* keySetId);
    void setPlayPolicy();

    void sendEvent(::aidl::android::hardware::drm::EventType in_eventType,
                   const std::vector<uint8_t>& in_sessionId,
                   const std::vector<uint8_t>& in_data);
    void sendExpirationUpdate(const std::vector<uint8_t>& in_sessionId,
                              int64_t in_expiryTimeInMS);
    void sendKeysChange(
            const std::vector<uint8_t>& in_sessionId,
            const std::vector<::aidl::android::hardware::drm::KeyStatus>& in_keyStatusList,
            bool in_hasNewUsableKey);
    void sendSessionLostState(const std::vector<uint8_t>& in_sessionId);

    Status setSecurityLevel(const std::vector<uint8_t>& sessionId, SecurityLevel level);

    Status getKeyRequestCommon(const std::vector<uint8_t>& scope,
                               const std::vector<uint8_t>& initData, const std::string& mimeType,
                               KeyType keyType, const std::vector<KeyValue>& optionalParameters,
                               std::vector<uint8_t>* request, KeyRequestType* getKeyRequestType,
                               std::string* defaultUrl);

    struct ClearkeySecureStop {
        std::vector<uint8_t> id;
        std::vector<uint8_t> data;
    };

    std::map<std::vector<uint8_t>, ClearkeySecureStop> mSecureStops;
    std::vector<KeyValue> mPlayPolicy;
    std::map<std::string, std::string> mStringProperties;
    std::map<std::string, std::vector<uint8_t>> mByteArrayProperties;
    std::map<std::string, std::vector<uint8_t>> mReleaseKeysMap;
    std::map<std::vector<uint8_t>, std::string> mPlaybackId;
    std::map<std::vector<uint8_t>, SecurityLevel> mSecurityLevel
        GUARDED_BY(mSecurityLevelLock);
    ::std::shared_ptr<IDrmPluginListener> mListener;
    SessionLibrary* mSessionLibrary;
    int64_t mOpenSessionOkCount;
    int64_t mCloseSessionOkCount;
    int64_t mCloseSessionNotOpenedCount;
    uint32_t mNextSecureStopId;
    ::android::Mutex mPlayPolicyLock;

    // set by property to mock error scenarios
    Status mMockError;

    void processMockError(const ::android::sp<Session>& session) {
        session->setMockError(static_cast<CdmResponseType>(mMockError));
        mMockError = Status::OK;
    }

    DeviceFiles mFileHandle;
    ::android::Mutex mSecureStopLock;
    ::android::Mutex mSecurityLevelLock;

    CLEARKEY_DISALLOW_COPY_AND_ASSIGN_AND_NEW(DrmPlugin);
};

}  // namespace clearkey
}  // namespace drm
}  // namespace hardware
}  // namespace android
}  // namespace aidl
