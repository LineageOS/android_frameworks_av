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

#ifndef CRYPTO_HAL_H_
#define CRYPTO_HAL_H_

#include <mediadrm/ICrypto.h>
#include <utils/KeyedVector.h>
#include <utils/threads.h>

using ::android::hardware::HidlMemory;

class IMemoryHeap;

namespace android {

struct CryptoHal : public ICrypto {
    CryptoHal();
    virtual ~CryptoHal();
    virtual status_t initCheck() const;
    virtual bool isCryptoSchemeSupported(const uint8_t uuid[16]);
    virtual status_t createPlugin(
            const uint8_t uuid[16], const void *data, size_t size);
    virtual status_t destroyPlugin();
    virtual bool requiresSecureDecoderComponent(
            const char *mime) const;
    virtual void notifyResolution(uint32_t width, uint32_t height);
    virtual DrmStatus setMediaDrmSession(const Vector<uint8_t> &sessionId);
    virtual ssize_t decrypt(const uint8_t key[16], const uint8_t iv[16],
            CryptoPlugin::Mode mode, const CryptoPlugin::Pattern &pattern,
            const drm::V1_0::SharedBuffer &source, size_t offset,
            const CryptoPlugin::SubSample *subSamples, size_t numSubSamples,
            const drm::V1_0::DestinationBuffer &destination,
            AString *errorDetailMsg);
    virtual int32_t setHeap(const sp<HidlMemory>& heap);
    virtual void unsetHeap(int32_t seqNum);
    virtual status_t getLogMessages(Vector<drm::V1_4::LogMessage> &logs) const;
private:
    sp<ICrypto> mCryptoHalHidl;
    sp<ICrypto> mCryptoHalAidl;
    DISALLOW_EVIL_CONSTRUCTORS(CryptoHal);
};

}  // namespace android

#endif  // CRYPTO_HAL_H_