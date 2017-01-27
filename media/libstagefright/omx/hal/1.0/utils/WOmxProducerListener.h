/*
 * Copyright 2016, The Android Open Source Project
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

#ifndef ANDROID_HARDWARE_MEDIA_OMX_V1_0_WOMXPRODUCERLISTENER_H
#define ANDROID_HARDWARE_MEDIA_OMX_V1_0_WOMXPRODUCERLISTENER_H

#include <android/hardware/media/omx/1.0/IOmxProducerListener.h>
#include <hidl/MQDescriptor.h>
#include <hidl/Status.h>

#include <binder/IBinder.h>
#include <gui/IProducerListener.h>

namespace android {
namespace hardware {
namespace media {
namespace omx {
namespace V1_0 {
namespace utils {

using ::android::hardware::media::omx::V1_0::IOmxProducerListener;
using ::android::hidl::base::V1_0::IBase;
using ::android::hardware::hidl_array;
using ::android::hardware::hidl_memory;
using ::android::hardware::hidl_string;
using ::android::hardware::hidl_vec;
using ::android::hardware::Return;
using ::android::hardware::Void;
using ::android::sp;

using ::android::IProducerListener;

struct TWOmxProducerListener : public IOmxProducerListener {
    sp<IProducerListener> mBase;
    TWOmxProducerListener(sp<IProducerListener> const& base);
    Return<void> onBufferReleased() override;
    Return<bool> needsReleaseNotify() override;
};

class LWOmxProducerListener : public IProducerListener {
public:
    sp<IOmxProducerListener> mBase;
    LWOmxProducerListener(sp<IOmxProducerListener> const& base);
    void onBufferReleased() override;
    bool needsReleaseNotify() override;
protected:
    ::android::IBinder* onAsBinder() override;
};

}  // namespace utils
}  // namespace V1_0
}  // namespace omx
}  // namespace media
}  // namespace hardware
}  // namespace android

#endif  // ANDROID_HARDWARE_MEDIA_OMX_V1_0_WOMXPRODUCERLISTENER_H
