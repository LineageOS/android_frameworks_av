/*
 * Copyright (C) 2013 The Android Open Source Project
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

#include <media/stagefright/foundation/ABase.h>
#include <media/drm/DrmAPI.h>
#include <mediadrm/DrmStatus.h>
#include <mediadrm/IDrmClient.h>
#include <mediadrm/IDrmMetricsConsumer.h>

#ifndef ANDROID_IDRM_H_

#define ANDROID_IDRM_H_

namespace android {
namespace hardware {
namespace drm {
namespace V1_4 {
struct LogMessage;
}  // namespace V1_4
}  // namespace drm
}  // namespace hardware

namespace drm = ::android::hardware::drm;

struct AString;

struct IDrm : public virtual RefBase {

    virtual ~IDrm() {}

    virtual DrmStatus initCheck() const = 0;

    virtual DrmStatus isCryptoSchemeSupported(const uint8_t uuid[16], const String8& mimeType,
                                              DrmPlugin::SecurityLevel securityLevel,
                                              bool* result) = 0;

    virtual DrmStatus createPlugin(const uint8_t uuid[16],
                                   const String8 &appPackageName) = 0;

    virtual DrmStatus destroyPlugin() = 0;

    virtual DrmStatus openSession(DrmPlugin::SecurityLevel securityLevel,
            Vector<uint8_t> &sessionId) = 0;

    virtual DrmStatus closeSession(Vector<uint8_t> const &sessionId) = 0;

    virtual DrmStatus
        getKeyRequest(Vector<uint8_t> const &sessionId,
                      Vector<uint8_t> const &initData,
                      String8 const &mimeType, DrmPlugin::KeyType keyType,
                      KeyedVector<String8, String8> const &optionalParameters,
                      Vector<uint8_t> &request, String8 &defaultUrl,
                      DrmPlugin::KeyRequestType *keyRequestType) = 0;

    virtual DrmStatus provideKeyResponse(Vector<uint8_t> const &sessionId,
                                         Vector<uint8_t> const &response,
                                         Vector<uint8_t> &keySetId) = 0;

    virtual DrmStatus removeKeys(Vector<uint8_t> const &keySetId) = 0;

    virtual DrmStatus restoreKeys(Vector<uint8_t> const &sessionId,
                                  Vector<uint8_t> const &keySetId) = 0;

    virtual DrmStatus queryKeyStatus(Vector<uint8_t> const &sessionId,
                                     KeyedVector<String8, String8> &infoMap) const = 0;

    virtual DrmStatus getProvisionRequest(String8 const &certType,
                                          String8 const &certAuthority,
                                          Vector<uint8_t> &request,
                                          String8 &defaultUrl) = 0;

    virtual DrmStatus provideProvisionResponse(Vector<uint8_t> const &response,
                                               Vector<uint8_t> &certificate,
                                               Vector<uint8_t> &wrappedKey) = 0;

    virtual DrmStatus getSecureStops(List<Vector<uint8_t>> &secureStops) = 0;
    virtual DrmStatus getSecureStopIds(List<Vector<uint8_t>> &secureStopIds) = 0;
    virtual DrmStatus getSecureStop(Vector<uint8_t> const &ssid, Vector<uint8_t> &secureStop) = 0;

    virtual DrmStatus releaseSecureStops(Vector<uint8_t> const &ssRelease) = 0;
    virtual DrmStatus removeSecureStop(Vector<uint8_t> const &ssid) = 0;
    virtual DrmStatus removeAllSecureStops() = 0;

    virtual DrmStatus getHdcpLevels(DrmPlugin::HdcpLevel *connectedLevel,
            DrmPlugin::HdcpLevel *maxLevel)
            const = 0;
    virtual DrmStatus getNumberOfSessions(uint32_t *currentSessions,
            uint32_t *maxSessions) const = 0;
    virtual DrmStatus getSecurityLevel(Vector<uint8_t> const &sessionId,
            DrmPlugin::SecurityLevel *level) const = 0;

    virtual DrmStatus getOfflineLicenseKeySetIds(List<Vector<uint8_t>> &keySetIds) const = 0;
    virtual DrmStatus removeOfflineLicense(Vector<uint8_t> const &keySetId) = 0;
    virtual DrmStatus getOfflineLicenseState(Vector<uint8_t> const &keySetId,
            DrmPlugin::OfflineLicenseState *licenseState) const = 0;

    virtual DrmStatus getPropertyString(String8 const &name, String8 &value) const = 0;
    virtual DrmStatus getPropertyByteArray(String8 const &name,
                                           Vector<uint8_t> &value) const = 0;
    virtual DrmStatus setPropertyString(String8 const &name,
                                        String8 const &value ) const = 0;
    virtual DrmStatus setPropertyByteArray(String8 const &name,
                                           Vector<uint8_t> const &value) const = 0;

    virtual DrmStatus getMetrics(const sp<IDrmMetricsConsumer> &consumer) = 0;

    virtual DrmStatus setCipherAlgorithm(Vector<uint8_t> const &sessionId,
                                         String8 const &algorithm) = 0;

    virtual DrmStatus setMacAlgorithm(Vector<uint8_t> const &sessionId,
                                      String8 const &algorithm) = 0;

    virtual DrmStatus encrypt(Vector<uint8_t> const &sessionId,
                              Vector<uint8_t> const &keyId,
                              Vector<uint8_t> const &input,
                              Vector<uint8_t> const &iv,
                              Vector<uint8_t> &output) = 0;

    virtual DrmStatus decrypt(Vector<uint8_t> const &sessionId,
                              Vector<uint8_t> const &keyId,
                              Vector<uint8_t> const &input,
                              Vector<uint8_t> const &iv,
                              Vector<uint8_t> &output) = 0;

    virtual DrmStatus sign(Vector<uint8_t> const &sessionId,
                           Vector<uint8_t> const &keyId,
                           Vector<uint8_t> const &message,
                           Vector<uint8_t> &signature) = 0;

    virtual DrmStatus verify(Vector<uint8_t> const &sessionId,
                             Vector<uint8_t> const &keyId,
                             Vector<uint8_t> const &message,
                             Vector<uint8_t> const &signature,
                             bool &match) = 0;

    virtual DrmStatus signRSA(Vector<uint8_t> const &sessionId,
                              String8 const &algorithm,
                              Vector<uint8_t> const &message,
                              Vector<uint8_t> const &wrappedKey,
                              Vector<uint8_t> &signature) = 0;

    virtual DrmStatus setListener(const sp<IDrmClient>& listener) = 0;

    virtual DrmStatus requiresSecureDecoder(const char *mime, bool *required) const = 0;

    virtual DrmStatus requiresSecureDecoder(const char *mime,
                                            DrmPlugin::SecurityLevel securityLevel,
                                            bool *required) const = 0;

    virtual DrmStatus setPlaybackId(
            Vector<uint8_t> const &sessionId,
            const char *playbackId) = 0;

    virtual DrmStatus getLogMessages(Vector<drm::V1_4::LogMessage> &logs) const = 0;

    virtual DrmStatus getSupportedSchemes(std::vector<uint8_t> &schemes) const = 0;

protected:
    IDrm() {}

private:
    DISALLOW_EVIL_CONSTRUCTORS(IDrm);
};

}  // namespace android

#endif // ANDROID_IDRM_H_
