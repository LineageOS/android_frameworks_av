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
#define LOG_TAG "CryptoHal"
#include <mediadrm/CryptoHal.h>
#include <mediadrm/CryptoHalHidl.h>
#include <mediadrm/CryptoHalAidl.h>
#include <mediadrm/DrmUtils.h>

namespace android {

CryptoHal::CryptoHal() {
    mCryptoHalAidl = sp<CryptoHalAidl>::make();
    mCryptoHalHidl = sp<CryptoHalHidl>::make();
}

CryptoHal::~CryptoHal() {}

status_t CryptoHal::initCheck() const {
    if (mCryptoHalAidl->initCheck() == OK || mCryptoHalHidl->initCheck() == OK) return OK;
    if (mCryptoHalAidl->initCheck() == NO_INIT || mCryptoHalHidl->initCheck() == NO_INIT)
        return NO_INIT;
    return mCryptoHalHidl->initCheck();
}

bool CryptoHal::isCryptoSchemeSupported(const uint8_t uuid[16]) {
    return mCryptoHalAidl->isCryptoSchemeSupported(uuid) ||
           mCryptoHalHidl->isCryptoSchemeSupported(uuid);
}

status_t CryptoHal::createPlugin(const uint8_t uuid[16], const void* data, size_t size) {
    if (mCryptoHalAidl->createPlugin(uuid, data, size) != OK)
        return mCryptoHalHidl->createPlugin(uuid, data, size);
    return OK;
}

status_t CryptoHal::destroyPlugin() {
    // This requires plugin to be created.
    if (mCryptoHalAidl->initCheck() == OK) return mCryptoHalAidl->destroyPlugin();
    return mCryptoHalHidl->destroyPlugin();
}

bool CryptoHal::requiresSecureDecoderComponent(const char* mime) const {
    // This requires plugin to be created.
    if (mCryptoHalAidl->initCheck() == OK)
        return mCryptoHalAidl->requiresSecureDecoderComponent(mime);
    return mCryptoHalHidl->requiresSecureDecoderComponent(mime);
}

void CryptoHal::notifyResolution(uint32_t width, uint32_t height) {
    // This requires plugin to be created.
    if (mCryptoHalAidl->initCheck() == OK) {
        mCryptoHalAidl->notifyResolution(width, height);
        return;
    }

    mCryptoHalHidl->notifyResolution(width, height);
}

DrmStatus CryptoHal::setMediaDrmSession(const Vector<uint8_t>& sessionId) {
    // This requires plugin to be created.
    if (mCryptoHalAidl->initCheck() == OK) return mCryptoHalAidl->setMediaDrmSession(sessionId);
    return mCryptoHalHidl->setMediaDrmSession(sessionId);
}

ssize_t CryptoHal::decrypt(const uint8_t key[16], const uint8_t iv[16], CryptoPlugin::Mode mode,
                           const CryptoPlugin::Pattern& pattern, const ::SharedBuffer& source,
                           size_t offset, const CryptoPlugin::SubSample* subSamples,
                           size_t numSubSamples, const ::DestinationBuffer& destination,
                           AString* errorDetailMsg) {
    // This requires plugin to be created.
    if (mCryptoHalAidl->initCheck() == OK)
        return mCryptoHalAidl->decrypt(key, iv, mode, pattern, source, offset, subSamples,
                                       numSubSamples, destination, errorDetailMsg);
    return mCryptoHalHidl->decrypt(key, iv, mode, pattern, source, offset, subSamples,
                                   numSubSamples, destination, errorDetailMsg);
}

int32_t CryptoHal::setHeap(const sp<HidlMemory>& heap) {
    // This requires plugin to be created.
    if (mCryptoHalAidl->initCheck() == OK) return mCryptoHalAidl->setHeap(heap);
    return mCryptoHalHidl->setHeap(heap);
}

void CryptoHal::unsetHeap(int32_t seqNum) {
    // This requires plugin to be created.
    if (mCryptoHalAidl->initCheck() == OK) {
        mCryptoHalAidl->unsetHeap(seqNum);
        return;
    }

    mCryptoHalHidl->unsetHeap(seqNum);
}

status_t CryptoHal::getLogMessages(Vector<drm::V1_4::LogMessage>& logs) const {
    // This requires plugin to be created.
    if (mCryptoHalAidl->initCheck() == OK) return mCryptoHalAidl->getLogMessages(logs);
    return mCryptoHalHidl->getLogMessages(logs);
}

}  // namespace android