/*
 * Copyright (C) 2017 The Android Open Source Project
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

#include <mediadrm/IDrm.h>

#ifndef DRM_HAL_H_
#define DRM_HAL_H_

namespace android {

struct DrmHal : public IDrm {
    DrmHal();
    virtual ~DrmHal();
    virtual status_t initCheck() const;
    virtual status_t isCryptoSchemeSupported(const uint8_t uuid[16],
                                             const String8 &mimeType,
                                             DrmPlugin::SecurityLevel securityLevel,
                                             bool *result);
    virtual status_t createPlugin(const uint8_t uuid[16],
                                  const String8 &appPackageName);
    virtual status_t destroyPlugin();
    virtual status_t openSession(DrmPlugin::SecurityLevel securityLevel,
            Vector<uint8_t> &sessionId);
    virtual status_t closeSession(Vector<uint8_t> const &sessionId);
    virtual status_t
        getKeyRequest(Vector<uint8_t> const &sessionId,
                      Vector<uint8_t> const &initData,
                      String8 const &mimeType, DrmPlugin::KeyType keyType,
                      KeyedVector<String8, String8> const &optionalParameters,
                      Vector<uint8_t> &request, String8 &defaultUrl,
                      DrmPlugin::KeyRequestType *keyRequestType);
    virtual status_t provideKeyResponse(Vector<uint8_t> const &sessionId,
                                        Vector<uint8_t> const &response,
                                        Vector<uint8_t> &keySetId);
    virtual status_t removeKeys(Vector<uint8_t> const &keySetId);
    virtual status_t restoreKeys(Vector<uint8_t> const &sessionId,
                                 Vector<uint8_t> const &keySetId);
    virtual status_t queryKeyStatus(Vector<uint8_t> const &sessionId,
                                    KeyedVector<String8, String8> &infoMap) const;
    virtual status_t getProvisionRequest(String8 const &certType,
                                         String8 const &certAuthority,
                                         Vector<uint8_t> &request,
                                         String8 &defaultUrl);
    virtual status_t provideProvisionResponse(Vector<uint8_t> const &response,
                                              Vector<uint8_t> &certificate,
                                              Vector<uint8_t> &wrappedKey);
    virtual status_t getSecureStops(List<Vector<uint8_t>> &secureStops);
    virtual status_t getSecureStopIds(List<Vector<uint8_t>> &secureStopIds);
    virtual status_t getSecureStop(Vector<uint8_t> const &ssid, Vector<uint8_t> &secureStop);
    virtual status_t releaseSecureStops(Vector<uint8_t> const &ssRelease);
    virtual status_t removeSecureStop(Vector<uint8_t> const &ssid);
    virtual status_t removeAllSecureStops();
    virtual status_t getHdcpLevels(DrmPlugin::HdcpLevel *connectedLevel,
            DrmPlugin::HdcpLevel *maxLevel) const;
    virtual status_t getNumberOfSessions(uint32_t *currentSessions,
            uint32_t *maxSessions) const;
    virtual status_t getSecurityLevel(Vector<uint8_t> const &sessionId,
            DrmPlugin::SecurityLevel *level) const;
    virtual status_t getOfflineLicenseKeySetIds(List<Vector<uint8_t>> &keySetIds) const;
    virtual status_t removeOfflineLicense(Vector<uint8_t> const &keySetId);
    virtual status_t getOfflineLicenseState(Vector<uint8_t> const &keySetId,
            DrmPlugin::OfflineLicenseState *licenseState) const;
    virtual status_t getPropertyString(String8 const &name, String8 &value) const;
    virtual status_t getPropertyByteArray(String8 const &name,
                                          Vector<uint8_t> &value) const;
    virtual status_t setPropertyString(String8 const &name,
                                       String8 const &value ) const;
    virtual status_t setPropertyByteArray(String8 const &name,
                                          Vector<uint8_t> const &value) const;
    virtual status_t getMetrics(const sp<IDrmMetricsConsumer> &consumer);
    virtual status_t setCipherAlgorithm(Vector<uint8_t> const &sessionId,
                                        String8 const &algorithm);
    virtual status_t setMacAlgorithm(Vector<uint8_t> const &sessionId,
                                     String8 const &algorithm);
    virtual status_t encrypt(Vector<uint8_t> const &sessionId,
                             Vector<uint8_t> const &keyId,
                             Vector<uint8_t> const &input,
                             Vector<uint8_t> const &iv,
                             Vector<uint8_t> &output);
    virtual status_t decrypt(Vector<uint8_t> const &sessionId,
                             Vector<uint8_t> const &keyId,
                             Vector<uint8_t> const &input,
                             Vector<uint8_t> const &iv,
                             Vector<uint8_t> &output);
    virtual status_t sign(Vector<uint8_t> const &sessionId,
                          Vector<uint8_t> const &keyId,
                          Vector<uint8_t> const &message,
                          Vector<uint8_t> &signature);
    virtual status_t verify(Vector<uint8_t> const &sessionId,
                            Vector<uint8_t> const &keyId,
                            Vector<uint8_t> const &message,
                            Vector<uint8_t> const &signature,
                            bool &match);
    virtual status_t signRSA(Vector<uint8_t> const &sessionId,
                             String8 const &algorithm,
                             Vector<uint8_t> const &message,
                             Vector<uint8_t> const &wrappedKey,
                             Vector<uint8_t> &signature);
    virtual status_t setListener(const sp<IDrmClient>& listener);
    virtual status_t requiresSecureDecoder(const char *mime, bool *required) const;
    virtual status_t requiresSecureDecoder(const char *mime, DrmPlugin::SecurityLevel securityLevel,
                                           bool *required) const;
    virtual status_t setPlaybackId(
            Vector<uint8_t> const &sessionId,
            const char *playbackId);
    virtual status_t getLogMessages(Vector<drm::V1_4::LogMessage> &logs) const;
    virtual status_t getSupportedSchemes(std::vector<uint8_t> &schemes) const;

private:
    sp<IDrm> mDrmHalHidl;
    sp<IDrm> mDrmHalAidl;
    DISALLOW_EVIL_CONSTRUCTORS(DrmHal);
};

} // namespace android

#endif  // DRM_HAL_H_