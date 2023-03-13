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

// #define LOG_NDEBUG 0
#define LOG_TAG "DrmMetricsLogger"

#include <media/MediaMetrics.h>
#include <media/stagefright/foundation/AString.h>
#include <media/stagefright/foundation/base64.h>
#include <mediadrm/DrmHal.h>
#include <mediadrm/DrmMetricsLogger.h>
#include <mediadrm/DrmUtils.h>

namespace android {

namespace {

std::vector<uint8_t> toStdVec(Vector<uint8_t> const& sessionId) {
    auto sessionKey = sessionId.array();
    std::vector<uint8_t> vec(sessionKey, sessionKey + sessionId.size());
    return vec;
}

}  // namespace

DrmMetricsLogger::DrmMetricsLogger(IDrmFrontend frontend)
    : mImpl(sp<DrmHal>::make()), mUuid(), mObjNonce(), mFrontend(frontend) {}

DrmMetricsLogger::~DrmMetricsLogger() {}

DrmStatus DrmMetricsLogger::initCheck() const {
    DrmStatus status = mImpl->initCheck();
    if (status != OK) {
        reportMediaDrmErrored(status, __func__);
    }
    return status;
}

DrmStatus DrmMetricsLogger::isCryptoSchemeSupported(const uint8_t uuid[IDRM_UUID_SIZE],
                                                    const String8& mimeType,
                                                    DrmPlugin::SecurityLevel securityLevel,
                                                    bool* result) {
    DrmStatus status = mImpl->isCryptoSchemeSupported(uuid, mimeType, securityLevel, result);
    if (status != OK) {
        reportMediaDrmErrored(status, __func__);
    }
    return status;
}

DrmStatus DrmMetricsLogger::createPlugin(const uint8_t uuid[IDRM_UUID_SIZE],
                                         const String8& appPackageName) {
    std::memcpy(mUuid.data(), uuid, IDRM_UUID_SIZE);
    mUuid[0] = betoh64(mUuid[0]);
    mUuid[1] = betoh64(mUuid[1]);
    if (kUuidSchemeMap.count(mUuid)) {
        mScheme = kUuidSchemeMap.at(mUuid);
    } else {
        mScheme = "Other";
    }
    if (generateNonce(&mObjNonce, kNonceSize, __func__) != OK) {
        return ERROR_DRM_RESOURCE_BUSY;
    }
    DrmStatus status = mImpl->createPlugin(uuid, appPackageName);
    if (status == OK) {
        String8 version8;
        if (getPropertyString(String8("version"), version8) == OK) {
            mVersion = version8.string();
        }
        reportMediaDrmCreated();
    } else {
        reportMediaDrmErrored(status, __func__);
    }
    return status;
}

DrmStatus DrmMetricsLogger::destroyPlugin() {
    DrmStatus status = mImpl->destroyPlugin();
    if (status != OK) {
        reportMediaDrmErrored(status, __func__);
    }
    return status;
}

DrmStatus DrmMetricsLogger::openSession(DrmPlugin::SecurityLevel securityLevel,
                                        Vector<uint8_t>& sessionId) {
    SessionContext ctx{};
    if (generateNonce(&ctx.mNonce, kNonceSize, __func__) != OK) {
        return ERROR_DRM_RESOURCE_BUSY;
    }
    DrmStatus status = mImpl->openSession(securityLevel, sessionId);
    if (status == OK) {
        std::vector<uint8_t> sessionKey = toStdVec(sessionId);
        ctx.mTargetSecurityLevel = securityLevel;
        if (getSecurityLevel(sessionId, &ctx.mActualSecurityLevel) != OK) {
            ctx.mActualSecurityLevel = DrmPlugin::kSecurityLevelUnknown;
        }
        if (!mVersion.empty()) {
            ctx.mVersion = mVersion;
        }
        {
            const std::lock_guard<std::mutex> lock(mSessionMapMutex);
            mSessionMap.insert({sessionKey, ctx});
        }
        reportMediaDrmSessionOpened(sessionKey);
    } else {
        reportMediaDrmErrored(status, __func__);
    }
    return status;
}

DrmStatus DrmMetricsLogger::closeSession(Vector<uint8_t> const& sessionId) {
    std::vector<uint8_t> sid = toStdVec(sessionId);
    {
        const std::lock_guard<std::mutex> lock(mSessionMapMutex);
        mSessionMap.erase(sid);
    }
    DrmStatus status = mImpl->closeSession(sessionId);
    if (status != OK) {
        reportMediaDrmErrored(status, __func__, sid);
    }
    return status;
}

DrmStatus DrmMetricsLogger::getKeyRequest(Vector<uint8_t> const& sessionId,
                                          Vector<uint8_t> const& initData, String8 const& mimeType,
                                          DrmPlugin::KeyType keyType,
                                          KeyedVector<String8, String8> const& optionalParameters,
                                          Vector<uint8_t>& request, String8& defaultUrl,
                                          DrmPlugin::KeyRequestType* keyRequestType) {
    DrmStatus status =
            mImpl->getKeyRequest(sessionId, initData, mimeType, keyType, optionalParameters,
                                 request, defaultUrl, keyRequestType);
    if (status != OK) {
        reportMediaDrmErrored(status, __func__, toStdVec(sessionId));
    }
    return status;
}

DrmStatus DrmMetricsLogger::provideKeyResponse(Vector<uint8_t> const& sessionId,
                                               Vector<uint8_t> const& response,
                                               Vector<uint8_t>& keySetId) {
    DrmStatus status = mImpl->provideKeyResponse(sessionId, response, keySetId);
    if (status != OK) {
        reportMediaDrmErrored(status, __func__, toStdVec(sessionId));
    }
    return status;
}

DrmStatus DrmMetricsLogger::removeKeys(Vector<uint8_t> const& keySetId) {
    DrmStatus status = mImpl->removeKeys(keySetId);
    if (status != OK) {
        reportMediaDrmErrored(status, __func__);
    }
    return status;
}

DrmStatus DrmMetricsLogger::restoreKeys(Vector<uint8_t> const& sessionId,
                                        Vector<uint8_t> const& keySetId) {
    DrmStatus status = mImpl->restoreKeys(sessionId, keySetId);
    if (status != OK) {
        reportMediaDrmErrored(status, __func__, toStdVec(sessionId));
    }
    return status;
}

DrmStatus DrmMetricsLogger::queryKeyStatus(Vector<uint8_t> const& sessionId,
                                           KeyedVector<String8, String8>& infoMap) const {
    DrmStatus status = mImpl->queryKeyStatus(sessionId, infoMap);
    if (status != OK) {
        reportMediaDrmErrored(status, __func__, toStdVec(sessionId));
    }
    return status;
}

DrmStatus DrmMetricsLogger::getProvisionRequest(String8 const& certType,
                                                String8 const& certAuthority,
                                                Vector<uint8_t>& request, String8& defaultUrl) {
    DrmStatus status = mImpl->getProvisionRequest(certType, certAuthority, request, defaultUrl);
    if (status != OK) {
        reportMediaDrmErrored(status, __func__);
    }
    return status;
}

DrmStatus DrmMetricsLogger::provideProvisionResponse(Vector<uint8_t> const& response,
                                                     Vector<uint8_t>& certificate,
                                                     Vector<uint8_t>& wrappedKey) {
    DrmStatus status = mImpl->provideProvisionResponse(response, certificate, wrappedKey);
    if (status != OK) {
        reportMediaDrmErrored(status, __func__);
    }
    return status;
}

DrmStatus DrmMetricsLogger::getSecureStops(List<Vector<uint8_t>>& secureStops) {
    DrmStatus status = mImpl->getSecureStops(secureStops);
    if (status != OK) {
        reportMediaDrmErrored(status, __func__);
    }
    return status;
}

DrmStatus DrmMetricsLogger::getSecureStopIds(List<Vector<uint8_t>>& secureStopIds) {
    DrmStatus status = mImpl->getSecureStopIds(secureStopIds);
    if (status != OK) {
        reportMediaDrmErrored(status, __func__);
    }
    return status;
}

DrmStatus DrmMetricsLogger::getSecureStop(Vector<uint8_t> const& ssid,
                                          Vector<uint8_t>& secureStop) {
    DrmStatus status = mImpl->getSecureStop(ssid, secureStop);
    if (status != OK) {
        reportMediaDrmErrored(status, __func__);
    }
    return status;
}

DrmStatus DrmMetricsLogger::releaseSecureStops(Vector<uint8_t> const& ssRelease) {
    DrmStatus status = mImpl->releaseSecureStops(ssRelease);
    if (status != OK) {
        reportMediaDrmErrored(status, __func__);
    }
    return status;
}

DrmStatus DrmMetricsLogger::removeSecureStop(Vector<uint8_t> const& ssid) {
    DrmStatus status = mImpl->removeSecureStop(ssid);
    if (status != OK) {
        reportMediaDrmErrored(status, __func__);
    }
    return status;
}

DrmStatus DrmMetricsLogger::removeAllSecureStops() {
    DrmStatus status = mImpl->removeAllSecureStops();
    if (status != OK) {
        reportMediaDrmErrored(status, __func__);
    }
    return status;
}

DrmStatus DrmMetricsLogger::getHdcpLevels(DrmPlugin::HdcpLevel* connectedLevel,
                                          DrmPlugin::HdcpLevel* maxLevel) const {
    DrmStatus status = mImpl->getHdcpLevels(connectedLevel, maxLevel);
    if (status != OK) {
        reportMediaDrmErrored(status, __func__);
    }
    return status;
}

DrmStatus DrmMetricsLogger::getNumberOfSessions(uint32_t* currentSessions,
                                                uint32_t* maxSessions) const {
    DrmStatus status = mImpl->getNumberOfSessions(currentSessions, maxSessions);
    if (status != OK) {
        reportMediaDrmErrored(status, __func__);
    }
    return status;
}

DrmStatus DrmMetricsLogger::getSecurityLevel(Vector<uint8_t> const& sessionId,
                                             DrmPlugin::SecurityLevel* level) const {
    DrmStatus status = mImpl->getSecurityLevel(sessionId, level);
    if (status != OK) {
        reportMediaDrmErrored(status, __func__, toStdVec(sessionId));
    }
    return status;
}

DrmStatus DrmMetricsLogger::getOfflineLicenseKeySetIds(List<Vector<uint8_t>>& keySetIds) const {
    DrmStatus status = mImpl->getOfflineLicenseKeySetIds(keySetIds);
    if (status != OK) {
        reportMediaDrmErrored(status, __func__);
    }
    return status;
}

DrmStatus DrmMetricsLogger::removeOfflineLicense(Vector<uint8_t> const& keySetId) {
    DrmStatus status = mImpl->removeOfflineLicense(keySetId);
    if (status != OK) {
        reportMediaDrmErrored(status, __func__);
    }
    return status;
}

DrmStatus DrmMetricsLogger::getOfflineLicenseState(
        Vector<uint8_t> const& keySetId, DrmPlugin::OfflineLicenseState* licenseState) const {
    DrmStatus status = mImpl->getOfflineLicenseState(keySetId, licenseState);
    if (status != OK) {
        reportMediaDrmErrored(status, __func__);
    }
    return status;
}

DrmStatus DrmMetricsLogger::getPropertyString(String8 const& name, String8& value) const {
    DrmStatus status = mImpl->getPropertyString(name, value);
    if (status != OK) {
        reportMediaDrmErrored(status, __func__);
    }
    return status;
}

DrmStatus DrmMetricsLogger::getPropertyByteArray(String8 const& name,
                                                 Vector<uint8_t>& value) const {
    DrmStatus status = mImpl->getPropertyByteArray(name, value);
    if (status != OK) {
        reportMediaDrmErrored(status, __func__);
    }
    return status;
}

DrmStatus DrmMetricsLogger::setPropertyString(String8 const& name, String8 const& value) const {
    DrmStatus status = mImpl->setPropertyString(name, value);
    if (status != OK) {
        reportMediaDrmErrored(status, __func__);
    }
    return status;
}

DrmStatus DrmMetricsLogger::setPropertyByteArray(String8 const& name,
                                                 Vector<uint8_t> const& value) const {
    DrmStatus status = mImpl->setPropertyByteArray(name, value);
    if (status != OK) {
        reportMediaDrmErrored(status, __func__);
    }
    return status;
}

DrmStatus DrmMetricsLogger::getMetrics(const sp<IDrmMetricsConsumer>& consumer) {
    DrmStatus status = mImpl->getMetrics(consumer);
    if (status != OK) {
        reportMediaDrmErrored(status, __func__);
    }
    return status;
}

DrmStatus DrmMetricsLogger::setCipherAlgorithm(Vector<uint8_t> const& sessionId,
                                               String8 const& algorithm) {
    DrmStatus status = mImpl->setCipherAlgorithm(sessionId, algorithm);
    if (status != OK) {
        reportMediaDrmErrored(status, __func__, toStdVec(sessionId));
    }
    return status;
}

DrmStatus DrmMetricsLogger::setMacAlgorithm(Vector<uint8_t> const& sessionId,
                                            String8 const& algorithm) {
    DrmStatus status = mImpl->setMacAlgorithm(sessionId, algorithm);
    if (status != OK) {
        reportMediaDrmErrored(status, __func__, toStdVec(sessionId));
    }
    return status;
}

DrmStatus DrmMetricsLogger::encrypt(Vector<uint8_t> const& sessionId, Vector<uint8_t> const& keyId,
                                    Vector<uint8_t> const& input, Vector<uint8_t> const& iv,
                                    Vector<uint8_t>& output) {
    DrmStatus status = mImpl->encrypt(sessionId, keyId, input, iv, output);
    if (status != OK) {
        reportMediaDrmErrored(status, __func__, toStdVec(sessionId));
    }
    return status;
}

DrmStatus DrmMetricsLogger::decrypt(Vector<uint8_t> const& sessionId, Vector<uint8_t> const& keyId,
                                    Vector<uint8_t> const& input, Vector<uint8_t> const& iv,
                                    Vector<uint8_t>& output) {
    DrmStatus status = mImpl->decrypt(sessionId, keyId, input, iv, output);
    if (status != OK) {
        reportMediaDrmErrored(status, __func__, toStdVec(sessionId));
    }
    return status;
}

DrmStatus DrmMetricsLogger::sign(Vector<uint8_t> const& sessionId, Vector<uint8_t> const& keyId,
                                 Vector<uint8_t> const& message, Vector<uint8_t>& signature) {
    DrmStatus status = mImpl->sign(sessionId, keyId, message, signature);
    if (status != OK) {
        reportMediaDrmErrored(status, __func__, toStdVec(sessionId));
    }
    return status;
}

DrmStatus DrmMetricsLogger::verify(Vector<uint8_t> const& sessionId, Vector<uint8_t> const& keyId,
                                   Vector<uint8_t> const& message, Vector<uint8_t> const& signature,
                                   bool& match) {
    DrmStatus status = mImpl->verify(sessionId, keyId, message, signature, match);
    if (status != OK) {
        reportMediaDrmErrored(status, __func__, toStdVec(sessionId));
    }
    return status;
}

DrmStatus DrmMetricsLogger::signRSA(Vector<uint8_t> const& sessionId, String8 const& algorithm,
                                    Vector<uint8_t> const& message,
                                    Vector<uint8_t> const& wrappedKey, Vector<uint8_t>& signature) {
    DrmStatus status = mImpl->signRSA(sessionId, algorithm, message, wrappedKey, signature);
    if (status != OK) {
        reportMediaDrmErrored(status, __func__, toStdVec(sessionId));
    }
    return status;
}

DrmStatus DrmMetricsLogger::setListener(const sp<IDrmClient>& listener) {
    DrmStatus status = mImpl->setListener(listener);
    if (status != OK) {
        reportMediaDrmErrored(status, __func__);
    }
    return status;
}

DrmStatus DrmMetricsLogger::requiresSecureDecoder(const char* mime, bool* required) const {
    DrmStatus status = mImpl->requiresSecureDecoder(mime, required);
    if (status != OK) {
        reportMediaDrmErrored(status, __func__);
    }
    return status;
}

DrmStatus DrmMetricsLogger::requiresSecureDecoder(const char* mime,
                                                  DrmPlugin::SecurityLevel securityLevel,
                                                  bool* required) const {
    DrmStatus status = mImpl->requiresSecureDecoder(mime, securityLevel, required);
    if (status != OK) {
        reportMediaDrmErrored(status, "requiresSecureDecoderLevel");
    }
    return status;
}

DrmStatus DrmMetricsLogger::setPlaybackId(Vector<uint8_t> const& sessionId,
                                          const char* playbackId) {
    DrmStatus status = mImpl->setPlaybackId(sessionId, playbackId);
    if (status != OK) {
        reportMediaDrmErrored(status, __func__, toStdVec(sessionId));
    }
    return status;
}

DrmStatus DrmMetricsLogger::getLogMessages(Vector<drm::V1_4::LogMessage>& logs) const {
    DrmStatus status = mImpl->getLogMessages(logs);
    if (status != OK) {
        reportMediaDrmErrored(status, __func__);
    }
    return status;
}

DrmStatus DrmMetricsLogger::getSupportedSchemes(std::vector<uint8_t>& schemes) const {
    DrmStatus status = mImpl->getSupportedSchemes(schemes);
    if (status != OK) {
        reportMediaDrmErrored(status, __func__);
    }
    return status;
}

void DrmMetricsLogger::reportMediaDrmCreated() const {
    mediametrics_handle_t handle(mediametrics_create("mediadrm.created"));
    mediametrics_setCString(handle, "scheme", mScheme.c_str());
    mediametrics_setInt64(handle, "uuid_msb", mUuid[0]);
    mediametrics_setInt64(handle, "uuid_lsb", mUuid[1]);
    mediametrics_setInt32(handle, "frontend", mFrontend);
    mediametrics_setCString(handle, "object_nonce", mObjNonce.c_str());
    mediametrics_setCString(handle, "version", mVersion.c_str());
    mediametrics_selfRecord(handle);
    mediametrics_delete(handle);
}

void DrmMetricsLogger::reportMediaDrmSessionOpened(const std::vector<uint8_t>& sessionId) const {
    mediametrics_handle_t handle(mediametrics_create("mediadrm.session_opened"));
    mediametrics_setCString(handle, "scheme", mScheme.c_str());
    mediametrics_setInt64(handle, "uuid_msb", mUuid[0]);
    mediametrics_setInt64(handle, "uuid_lsb", mUuid[1]);
    mediametrics_setInt32(handle, "frontend", mFrontend);
    mediametrics_setCString(handle, "version", mVersion.c_str());
    mediametrics_setCString(handle, "object_nonce", mObjNonce.c_str());
    const std::lock_guard<std::mutex> lock(mSessionMapMutex);
    auto it = mSessionMap.find(sessionId);
    if (it != mSessionMap.end()) {
        mediametrics_setCString(handle, "session_nonce", it->second.mNonce.c_str());
        mediametrics_setInt64(handle, "requested_seucrity_level", it->second.mTargetSecurityLevel);
        mediametrics_setInt64(handle, "opened_seucrity_level", it->second.mActualSecurityLevel);
    }
    mediametrics_selfRecord(handle);
    mediametrics_delete(handle);
}

void DrmMetricsLogger::reportMediaDrmErrored(const DrmStatus& error_code, const char* api,
                                             const std::vector<uint8_t>& sessionId) const {
    mediametrics_handle_t handle(mediametrics_create("mediadrm.errored"));
    mediametrics_setCString(handle, "scheme", mScheme.c_str());
    mediametrics_setInt64(handle, "uuid_msb", mUuid[0]);
    mediametrics_setInt64(handle, "uuid_lsb", mUuid[1]);
    mediametrics_setInt32(handle, "frontend", mFrontend);
    mediametrics_setCString(handle, "version", mVersion.c_str());
    mediametrics_setCString(handle, "object_nonce", mObjNonce.c_str());
    if (!sessionId.empty()) {
        const std::lock_guard<std::mutex> lock(mSessionMapMutex);
        auto it = mSessionMap.find(sessionId);
        if (it != mSessionMap.end()) {
            mediametrics_setCString(handle, "session_nonce", it->second.mNonce.c_str());
            mediametrics_setInt64(handle, "seucrity_level", it->second.mActualSecurityLevel);
        }
    }
    mediametrics_setCString(handle, "api", api);
    mediametrics_setInt32(handle, "error_code", error_code);
    mediametrics_setInt32(handle, "cdm_err", error_code.getCdmErr());
    mediametrics_setInt32(handle, "oem_err", error_code.getOemErr());
    mediametrics_setInt32(handle, "error_context", error_code.getContext());
    mediametrics_selfRecord(handle);
    mediametrics_delete(handle);
}

DrmStatus DrmMetricsLogger::generateNonce(std::string* out, size_t size, const char* api) {
    std::vector<uint8_t> buf(size);
    ssize_t bytes = getrandom(buf.data(), size, GRND_NONBLOCK);
    if (bytes < size) {
        ALOGE("getrandom failed: %d", errno);
        reportMediaDrmErrored(ERROR_DRM_RESOURCE_BUSY, api);
        return ERROR_DRM_RESOURCE_BUSY;
    }
    android::AString tmp;
    encodeBase64(buf.data(), size, &tmp);
    out->assign(tmp.c_str());
    return OK;
}

const std::map<std::array<int64_t, 2>, std::string> DrmMetricsLogger::kUuidSchemeMap {
        {{(int64_t)0x6DD8B3C345F44A68, (int64_t)0xBF3A64168D01A4A6}, "ABV DRM (MoDRM)"},
        {{(int64_t)0xF239E769EFA34850, (int64_t)0x9C16A903C6932EFB},
         "Adobe Primetime DRM version 4"},
        {{(int64_t)0x616C746963617374, (int64_t)0x2D50726F74656374}, "Alticast"},
        {{(int64_t)0x94CE86FB07FF4F43, (int64_t)0xADB893D2FA968CA2}, "Apple FairPlay"},
        {{(int64_t)0x279FE473512C48FE, (int64_t)0xADE8D176FEE6B40F}, "Arris Titanium"},
        {{(int64_t)0x3D5E6D359B9A41E8, (int64_t)0xB843DD3C6E72C42C}, "ChinaDRM"},
        {{(int64_t)0x3EA8778F77424BF9, (int64_t)0xB18BE834B2ACBD47}, "Clear Key AES-128"},
        {{(int64_t)0xBE58615B19C44684, (int64_t)0x88B3C8C57E99E957}, "Clear Key SAMPLE-AES"},
        {{(int64_t)0xE2719D58A985B3C9, (int64_t)0x781AB030AF78D30E}, "Clear Key DASH-IF"},
        {{(int64_t)0x644FE7B5260F4FAD, (int64_t)0x949A0762FFB054B4}, "CMLA (OMA DRM)"},
        {{(int64_t)0x37C332587B994C7E, (int64_t)0xB15D19AF74482154}, "Commscope Titanium V3"},
        {{(int64_t)0x45D481CB8FE049C0, (int64_t)0xADA9AB2D2455B2F2}, "CoreCrypt"},
        {{(int64_t)0xDCF4E3E362F15818, (int64_t)0x7BA60A6FE33FF3DD}, "DigiCAP SmartXess"},
        {{(int64_t)0x35BF197B530E42D7, (int64_t)0x8B651B4BF415070F}, "DivX DRM Series 5"},
        {{(int64_t)0x80A6BE7E14484C37, (int64_t)0x9E70D5AEBE04C8D2}, "Irdeto Content Protection"},
        {{(int64_t)0x5E629AF538DA4063, (int64_t)0x897797FFBD9902D4},
         "Marlin Adaptive Streaming Simple Profile V1.0"},
        {{(int64_t)0x9A04F07998404286, (int64_t)0xAB92E65BE0885F95}, "Microsoft PlayReady"},
        {{(int64_t)0x6A99532D869F5922, (int64_t)0x9A91113AB7B1E2F3}, "MobiTV DRM"},
        {{(int64_t)0xADB41C242DBF4A6D, (int64_t)0x958B4457C0D27B95}, "Nagra MediaAccess PRM 3.0"},
        {{(int64_t)0x1F83E1E86EE94F0D, (int64_t)0xBA2F5EC4E3ED1A66}, "SecureMedia"},
        {{(int64_t)0x992C46E6C4374899, (int64_t)0xB6A050FA91AD0E39}, "SecureMedia SteelKnot"},
        {{(int64_t)0xA68129D3575B4F1A, (int64_t)0x9CBA3223846CF7C3},
         "Synamedia/Cisco/NDS VideoGuard DRM"},
        {{(int64_t)0xAA11967FCC014A4A, (int64_t)0x8E99C5D3DDDFEA2D}, "Unitend DRM (UDRM)"},
        {{(int64_t)0x9A27DD82FDE24725, (int64_t)0x8CBC4234AA06EC09}, "Verimatrix VCAS"},
        {{(int64_t)0xB4413586C58CFFB0, (int64_t)0x94A5D4896C1AF6C3}, "Viaccess-Orca DRM (VODRM)"},
        {{(int64_t)0x793B79569F944946, (int64_t)0xA94223E7EF7E44B4}, "VisionCrypt"},
        {{(int64_t)0x1077EFECC0B24D02, (int64_t)0xACE33C1E52E2FB4B}, "W3C Common PSSH box"},
        {{(int64_t)0xEDEF8BA979D64ACE, (int64_t)0xA3C827DCD51D21ED}, "Widevine Content Protection"},
};

}  // namespace android