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

#ifndef CRYPTO_HAL_AIDL_H_
#define CRYPTO_HAL_AIDL_H_

#include <aidl/android/hardware/drm/ICryptoPlugin.h>
#include <aidl/android/hardware/drm/IDrmFactory.h>
#include <mediadrm/ICrypto.h>
#include <utils/KeyedVector.h>
#include <utils/threads.h>

using IDrmFactoryAidl = ::aidl::android::hardware::drm::IDrmFactory;
using ICryptoPluginAidl = ::aidl::android::hardware::drm::ICryptoPlugin;
using ::aidl::android::hardware::drm::Uuid;

// -------Hidl interface related-----------------
// TODO: replace before removing hidl interface
using ::android::hardware::drm::V1_0::DestinationBuffer;
using ::android::hardware::drm::V1_0::SharedBuffer;

using ::android::hardware::HidlMemory;

// -------Hidl interface related end-------------

class IMemoryHeap;

namespace android {

struct CryptoHalAidl : public ICrypto {
    CryptoHalAidl();
    virtual ~CryptoHalAidl();
    virtual status_t initCheck() const;
    virtual bool isCryptoSchemeSupported(const uint8_t uuid[16]);
    virtual status_t createPlugin(const uint8_t uuid[16], const void* data, size_t size);
    virtual status_t destroyPlugin();
    virtual bool requiresSecureDecoderComponent(const char* mime) const;
    virtual void notifyResolution(uint32_t width, uint32_t height);
    virtual DrmStatus setMediaDrmSession(const Vector<uint8_t>& sessionId);
    virtual ssize_t decrypt(const uint8_t key[16], const uint8_t iv[16], CryptoPlugin::Mode mode,
                            const CryptoPlugin::Pattern& pattern, const ::SharedBuffer& source,
                            size_t offset, const CryptoPlugin::SubSample* subSamples,
                            size_t numSubSamples, const ::DestinationBuffer& destination,
                            AString* errorDetailMsg);
    virtual int32_t setHeap(const sp<HidlMemory>& heap);
    virtual void unsetHeap(int32_t seqNum);
    virtual status_t getLogMessages(Vector<drm::V1_4::LogMessage>& logs) const;

  private:
    mutable Mutex mLock;

    const std::vector<std::shared_ptr<IDrmFactoryAidl>> mFactories;
    std::shared_ptr<ICryptoPluginAidl> mPlugin;

    /**
     * mInitCheck is:
     *   NO_INIT if a plugin hasn't been created yet
     *   ERROR_UNSUPPORTED if a plugin can't be created for the uuid
     *   OK after a plugin has been created and mPlugin is valid
     */
    status_t mInitCheck;

    KeyedVector<int32_t, size_t> mHeapSizes;
    int32_t mHeapSeqNum;

    std::shared_ptr<ICryptoPluginAidl> makeCryptoPlugin(
            const std::shared_ptr<IDrmFactoryAidl>& factory, const Uuid& uuidAidl,
            const std::vector<uint8_t> initData);

    status_t checkSharedBuffer(const ::SharedBuffer& buffer);
    bool isCryptoSchemeSupportedInternal(const uint8_t uuid[16], int* factoryIdx);

    DISALLOW_EVIL_CONSTRUCTORS(CryptoHalAidl);
};

}  // namespace android

#endif // CRYPTO_HAL_AIDL_H_
