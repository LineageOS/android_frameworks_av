/*
 * Copyright (C) 2012 The Android Open Source Project
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

#include <cutils/native_handle.h>
#include <media/hardware/CryptoAPI.h>
#include <media/stagefright/foundation/ABase.h>
#include <utils/RefBase.h>
#include <utils/StrongPointer.h>

#ifndef ANDROID_ICRYPTO_H_

#define ANDROID_ICRYPTO_H_

namespace android {
namespace hardware {
class HidlMemory;
namespace drm {
namespace V1_0 {
struct SharedBuffer;
struct DestinationBuffer;
}  // namespace V1_0
}  // namespace drm
}  // namespace hardware
}  // namespace android

namespace drm = ::android::hardware::drm;
using drm::V1_0::SharedBuffer;

namespace android {

struct AString;

struct ICrypto : public RefBase {

    virtual ~ICrypto() {}

    virtual status_t initCheck() const = 0;

    virtual bool isCryptoSchemeSupported(const uint8_t uuid[16]) = 0;

    virtual status_t createPlugin(
            const uint8_t uuid[16], const void *data, size_t size) = 0;

    virtual status_t destroyPlugin() = 0;

    virtual bool requiresSecureDecoderComponent(
            const char *mime) const = 0;

    virtual void notifyResolution(uint32_t width, uint32_t height) = 0;

    virtual status_t setMediaDrmSession(const Vector<uint8_t> &sessionId) = 0;

    enum DestinationType {
        kDestinationTypeSharedMemory, // non-secure
        kDestinationTypeNativeHandle  // secure
    };

    virtual ssize_t decrypt(const uint8_t /*key*/[16], const uint8_t /*iv*/[16],
            CryptoPlugin::Mode /*mode*/, const CryptoPlugin::Pattern &/*pattern*/,
            const drm::V1_0::SharedBuffer &/*source*/, size_t /*offset*/,
            const CryptoPlugin::SubSample * /*subSamples*/, size_t /*numSubSamples*/,
            const drm::V1_0::DestinationBuffer &/*destination*/, AString * /*errorDetailMsg*/) = 0;

    /**
     * Declare the heap that the shared memory source buffers passed
     * to decrypt will be allocated from. Returns a sequence number
     * that subsequent decrypt calls can use to refer to the heap,
     * with -1 indicating failure.
     */
    virtual int32_t setHeap(const sp<hardware::HidlMemory>& heap) = 0;
    virtual void unsetHeap(int32_t seqNum) = 0;

protected:
    ICrypto() {}

private:
    DISALLOW_EVIL_CONSTRUCTORS(ICrypto);
};

}  // namespace android

#endif // ANDROID_ICRYPTO_H_
