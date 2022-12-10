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

//#define LOG_NDEBUG 0
#define LOG_TAG "DrmHal"

#include <mediadrm/DrmHal.h>
#include <mediadrm/DrmHalAidl.h>
#include <mediadrm/DrmHalHidl.h>
#include <mediadrm/DrmStatus.h>
#include <mediadrm/DrmUtils.h>

namespace android {

DrmHal::DrmHal() {
    mDrmHalHidl = sp<DrmHalHidl>::make();
    mDrmHalAidl = sp<DrmHalAidl>::make();
}

DrmHal::~DrmHal() {}

DrmStatus DrmHal::initCheck() const {
    if (mDrmHalAidl->initCheck() == OK || mDrmHalHidl->initCheck() == OK) return DrmStatus(OK);
    if (mDrmHalAidl->initCheck() == NO_INIT || mDrmHalHidl->initCheck() == NO_INIT)
        return DrmStatus(NO_INIT);
    return mDrmHalHidl->initCheck();
}

DrmStatus DrmHal::isCryptoSchemeSupported(const uint8_t uuid[16], const String8& mimeType,
                                          DrmPlugin::SecurityLevel securityLevel, bool* result) {
    DrmStatus statusResult =
            mDrmHalAidl->isCryptoSchemeSupported(uuid, mimeType, securityLevel, result);
    if (*result) return statusResult;
    return mDrmHalHidl->isCryptoSchemeSupported(uuid, mimeType, securityLevel, result);
}

DrmStatus DrmHal::createPlugin(const uint8_t uuid[16], const String8& appPackageName) {
    return mDrmHalAidl->createPlugin(uuid, appPackageName) == OK
                   ? DrmStatus(OK)
                   : mDrmHalHidl->createPlugin(uuid, appPackageName);
}

DrmStatus DrmHal::destroyPlugin() {
    DrmStatus statusResult = mDrmHalAidl->destroyPlugin();
    DrmStatus statusResultHidl = mDrmHalHidl->destroyPlugin();
    if (statusResult != OK) return statusResult;
    return statusResultHidl;
}

DrmStatus DrmHal::openSession(DrmPlugin::SecurityLevel securityLevel, Vector<uint8_t>& sessionId) {
    if (mDrmHalAidl->initCheck() == OK) return mDrmHalAidl->openSession(securityLevel, sessionId);
    return mDrmHalHidl->openSession(securityLevel, sessionId);
}

DrmStatus DrmHal::closeSession(Vector<uint8_t> const& sessionId) {
    if (mDrmHalAidl->initCheck() == OK) return mDrmHalAidl->closeSession(sessionId);
    return mDrmHalHidl->closeSession(sessionId);
}

DrmStatus DrmHal::getKeyRequest(Vector<uint8_t> const& sessionId, Vector<uint8_t> const& initData,
                                String8 const& mimeType, DrmPlugin::KeyType keyType,
                                KeyedVector<String8, String8> const& optionalParameters,
                                Vector<uint8_t>& request, String8& defaultUrl,
                                DrmPlugin::KeyRequestType* keyRequestType) {
    if (mDrmHalAidl->initCheck() == OK)
        return mDrmHalAidl->getKeyRequest(sessionId, initData, mimeType, keyType,
                                          optionalParameters, request, defaultUrl, keyRequestType);
    return mDrmHalHidl->getKeyRequest(sessionId, initData, mimeType, keyType, optionalParameters,
                                      request, defaultUrl, keyRequestType);
}

DrmStatus DrmHal::provideKeyResponse(Vector<uint8_t> const& sessionId,
                                     Vector<uint8_t> const& response, Vector<uint8_t>& keySetId) {
    if (mDrmHalAidl->initCheck() == OK)
        return mDrmHalAidl->provideKeyResponse(sessionId, response, keySetId);
    return mDrmHalHidl->provideKeyResponse(sessionId, response, keySetId);
}

DrmStatus DrmHal::removeKeys(Vector<uint8_t> const& keySetId) {
    if (mDrmHalAidl->initCheck() == OK) return mDrmHalAidl->removeKeys(keySetId);
    return mDrmHalHidl->removeKeys(keySetId);
}

DrmStatus DrmHal::restoreKeys(Vector<uint8_t> const& sessionId, Vector<uint8_t> const& keySetId) {
    if (mDrmHalAidl->initCheck() == OK) return mDrmHalAidl->restoreKeys(sessionId, keySetId);
    return mDrmHalHidl->restoreKeys(sessionId, keySetId);
}

DrmStatus DrmHal::queryKeyStatus(Vector<uint8_t> const& sessionId,
                                 KeyedVector<String8, String8>& infoMap) const {
    if (mDrmHalAidl->initCheck() == OK) return mDrmHalAidl->queryKeyStatus(sessionId, infoMap);
    return mDrmHalHidl->queryKeyStatus(sessionId, infoMap);
}

DrmStatus DrmHal::getProvisionRequest(String8 const& certType, String8 const& certAuthority,
                                      Vector<uint8_t>& request, String8& defaultUrl) {
    if (mDrmHalAidl->initCheck() == OK)
        return mDrmHalAidl->getProvisionRequest(certType, certAuthority, request, defaultUrl);
    return mDrmHalHidl->getProvisionRequest(certType, certAuthority, request, defaultUrl);
}

DrmStatus DrmHal::provideProvisionResponse(Vector<uint8_t> const& response,
                                           Vector<uint8_t>& certificate,
                                           Vector<uint8_t>& wrappedKey) {
    if (mDrmHalAidl->initCheck() == OK)
        return mDrmHalAidl->provideProvisionResponse(response, certificate, wrappedKey);
    return mDrmHalHidl->provideProvisionResponse(response, certificate, wrappedKey);
}

DrmStatus DrmHal::getSecureStops(List<Vector<uint8_t>>& secureStops) {
    if (mDrmHalAidl->initCheck() == OK) return mDrmHalAidl->getSecureStops(secureStops);
    return mDrmHalHidl->getSecureStops(secureStops);
}

DrmStatus DrmHal::getSecureStopIds(List<Vector<uint8_t>>& secureStopIds) {
    if (mDrmHalAidl->initCheck() == OK) return mDrmHalAidl->getSecureStopIds(secureStopIds);
    return mDrmHalHidl->getSecureStopIds(secureStopIds);
}

DrmStatus DrmHal::getSecureStop(Vector<uint8_t> const& ssid, Vector<uint8_t>& secureStop) {
    if (mDrmHalAidl->initCheck() == OK) return mDrmHalAidl->getSecureStop(ssid, secureStop);
    return mDrmHalHidl->getSecureStop(ssid, secureStop);
}

DrmStatus DrmHal::releaseSecureStops(Vector<uint8_t> const& ssRelease) {
    if (mDrmHalAidl->initCheck() == OK) return mDrmHalAidl->releaseSecureStops(ssRelease);
    return mDrmHalHidl->releaseSecureStops(ssRelease);
}

DrmStatus DrmHal::removeSecureStop(Vector<uint8_t> const& ssid) {
    if (mDrmHalAidl->initCheck() == OK) return mDrmHalAidl->removeSecureStop(ssid);
    return mDrmHalHidl->removeSecureStop(ssid);
}

DrmStatus DrmHal::removeAllSecureStops() {
    if (mDrmHalAidl->initCheck() == OK) return mDrmHalAidl->removeAllSecureStops();
    return mDrmHalHidl->removeAllSecureStops();
}

DrmStatus DrmHal::getHdcpLevels(DrmPlugin::HdcpLevel* connectedLevel,
                                DrmPlugin::HdcpLevel* maxLevel) const {
    if (mDrmHalAidl->initCheck() == OK) return mDrmHalAidl->getHdcpLevels(connectedLevel, maxLevel);
    return mDrmHalHidl->getHdcpLevels(connectedLevel, maxLevel);
}

DrmStatus DrmHal::getNumberOfSessions(uint32_t* currentSessions, uint32_t* maxSessions) const {
    if (mDrmHalAidl->initCheck() == OK)
        return mDrmHalAidl->getNumberOfSessions(currentSessions, maxSessions);
    return mDrmHalHidl->getNumberOfSessions(currentSessions, maxSessions);
}

DrmStatus DrmHal::getSecurityLevel(Vector<uint8_t> const& sessionId,
                                   DrmPlugin::SecurityLevel* level) const {
    if (mDrmHalAidl->initCheck() == OK) return mDrmHalAidl->getSecurityLevel(sessionId, level);
    return mDrmHalHidl->getSecurityLevel(sessionId, level);
}

DrmStatus DrmHal::getOfflineLicenseKeySetIds(List<Vector<uint8_t>>& keySetIds) const {
    if (mDrmHalAidl->initCheck() == OK) return mDrmHalAidl->getOfflineLicenseKeySetIds(keySetIds);
    return mDrmHalHidl->getOfflineLicenseKeySetIds(keySetIds);
}

DrmStatus DrmHal::removeOfflineLicense(Vector<uint8_t> const& keySetId) {
    if (mDrmHalAidl->initCheck() == OK) return mDrmHalAidl->removeOfflineLicense(keySetId);
    return mDrmHalHidl->removeOfflineLicense(keySetId);
}

DrmStatus DrmHal::getOfflineLicenseState(Vector<uint8_t> const& keySetId,
                                         DrmPlugin::OfflineLicenseState* licenseState) const {
    if (mDrmHalAidl->initCheck() == OK)
        return mDrmHalAidl->getOfflineLicenseState(keySetId, licenseState);
    return mDrmHalHidl->getOfflineLicenseState(keySetId, licenseState);
}

DrmStatus DrmHal::getPropertyString(String8 const& name, String8& value) const {
    if (mDrmHalAidl->initCheck() == OK) return mDrmHalAidl->getPropertyString(name, value);
    return mDrmHalHidl->getPropertyString(name, value);
}

DrmStatus DrmHal::getPropertyByteArray(String8 const& name, Vector<uint8_t>& value) const {
    if (mDrmHalAidl->initCheck() == OK) return mDrmHalAidl->getPropertyByteArray(name, value);
    return mDrmHalHidl->getPropertyByteArray(name, value);
}

DrmStatus DrmHal::setPropertyString(String8 const& name, String8 const& value) const {
    if (mDrmHalAidl->initCheck() == OK) return mDrmHalAidl->setPropertyString(name, value);
    return mDrmHalHidl->setPropertyString(name, value);
}

DrmStatus DrmHal::setPropertyByteArray(String8 const& name, Vector<uint8_t> const& value) const {
    if (mDrmHalAidl->initCheck() == OK) return mDrmHalAidl->setPropertyByteArray(name, value);
    return mDrmHalHidl->setPropertyByteArray(name, value);
}

DrmStatus DrmHal::getMetrics(const sp<IDrmMetricsConsumer>& consumer) {
    if (mDrmHalAidl->initCheck() == OK) return mDrmHalAidl->getMetrics(consumer);
    return mDrmHalHidl->getMetrics(consumer);
}

DrmStatus DrmHal::setCipherAlgorithm(Vector<uint8_t> const& sessionId, String8 const& algorithm) {
    if (mDrmHalAidl->initCheck() == OK)
        return mDrmHalAidl->setCipherAlgorithm(sessionId, algorithm);
    return mDrmHalHidl->setCipherAlgorithm(sessionId, algorithm);
}

DrmStatus DrmHal::setMacAlgorithm(Vector<uint8_t> const& sessionId, String8 const& algorithm) {
    if (mDrmHalAidl->initCheck() == OK) return mDrmHalAidl->setMacAlgorithm(sessionId, algorithm);
    return mDrmHalHidl->setMacAlgorithm(sessionId, algorithm);
}

DrmStatus DrmHal::encrypt(Vector<uint8_t> const& sessionId, Vector<uint8_t> const& keyId,
                          Vector<uint8_t> const& input, Vector<uint8_t> const& iv,
                          Vector<uint8_t>& output) {
    if (mDrmHalAidl->initCheck() == OK)
        return mDrmHalAidl->encrypt(sessionId, keyId, input, iv, output);
    return mDrmHalHidl->encrypt(sessionId, keyId, input, iv, output);
}

DrmStatus DrmHal::decrypt(Vector<uint8_t> const& sessionId, Vector<uint8_t> const& keyId,
                          Vector<uint8_t> const& input, Vector<uint8_t> const& iv,
                          Vector<uint8_t>& output) {
    if (mDrmHalAidl->initCheck() == OK)
        return mDrmHalAidl->decrypt(sessionId, keyId, input, iv, output);
    return mDrmHalHidl->decrypt(sessionId, keyId, input, iv, output);
}

DrmStatus DrmHal::sign(Vector<uint8_t> const& sessionId, Vector<uint8_t> const& keyId,
                       Vector<uint8_t> const& message, Vector<uint8_t>& signature) {
    if (mDrmHalAidl->initCheck() == OK)
        return mDrmHalAidl->sign(sessionId, keyId, message, signature);
    return mDrmHalHidl->sign(sessionId, keyId, message, signature);
}

DrmStatus DrmHal::verify(Vector<uint8_t> const& sessionId, Vector<uint8_t> const& keyId,
                         Vector<uint8_t> const& message, Vector<uint8_t> const& signature,
                         bool& match) {
    if (mDrmHalAidl->initCheck() == OK)
        return mDrmHalAidl->verify(sessionId, keyId, message, signature, match);
    return mDrmHalHidl->verify(sessionId, keyId, message, signature, match);
}

DrmStatus DrmHal::signRSA(Vector<uint8_t> const& sessionId, String8 const& algorithm,
                          Vector<uint8_t> const& message, Vector<uint8_t> const& wrappedKey,
                          Vector<uint8_t>& signature) {
    if (mDrmHalAidl->initCheck() == OK)
        return mDrmHalAidl->signRSA(sessionId, algorithm, message, wrappedKey, signature);
    return mDrmHalHidl->signRSA(sessionId, algorithm, message, wrappedKey, signature);
}

DrmStatus DrmHal::setListener(const sp<IDrmClient>& listener) {
    if (mDrmHalAidl->initCheck() == OK) return mDrmHalAidl->setListener(listener);
    return mDrmHalHidl->setListener(listener);
}

DrmStatus DrmHal::requiresSecureDecoder(const char* mime, bool* required) const {
    if (mDrmHalAidl->initCheck() == OK) return mDrmHalAidl->requiresSecureDecoder(mime, required);
    return mDrmHalHidl->requiresSecureDecoder(mime, required);
}

DrmStatus DrmHal::requiresSecureDecoder(const char* mime, DrmPlugin::SecurityLevel securityLevel,
                                        bool* required) const {
    if (mDrmHalAidl->initCheck() == OK)
        return mDrmHalAidl->requiresSecureDecoder(mime, securityLevel, required);
    return mDrmHalHidl->requiresSecureDecoder(mime, securityLevel, required);
}

DrmStatus DrmHal::setPlaybackId(Vector<uint8_t> const& sessionId, const char* playbackId) {
    if (mDrmHalAidl->initCheck() == OK) return mDrmHalAidl->setPlaybackId(sessionId, playbackId);
    return mDrmHalHidl->setPlaybackId(sessionId, playbackId);
}

DrmStatus DrmHal::getLogMessages(Vector<drm::V1_4::LogMessage>& logs) const {
    if (mDrmHalAidl->initCheck() == OK) return mDrmHalAidl->getLogMessages(logs);
    return mDrmHalHidl->getLogMessages(logs);
}

DrmStatus DrmHal::getSupportedSchemes(std::vector<uint8_t>& schemes) const {
    status_t statusResult;
    statusResult = mDrmHalAidl->getSupportedSchemes(schemes);
    if (statusResult == OK) return statusResult;
    return mDrmHalHidl->getSupportedSchemes(schemes);
}

}  // namespace android
