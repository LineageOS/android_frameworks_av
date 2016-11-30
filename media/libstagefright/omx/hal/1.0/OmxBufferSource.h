#ifndef ANDROID_HARDWARE_MEDIA_OMX_V1_0__OMXBUFFERSOURCE_H
#define ANDROID_HARDWARE_MEDIA_OMX_V1_0__OMXBUFFERSOURCE_H

#include <android/hardware/media/omx/1.0/IOmxBufferSource.h>
#include <hidl/MQDescriptor.h>
#include <hidl/Status.h>

namespace android {
namespace hardware {
namespace media {
namespace omx {
namespace V1_0 {
namespace implementation {

using ::android::hardware::media::omx::V1_0::IOmxBufferSource;
using ::android::hardware::hidl_array;
using ::android::hardware::hidl_string;
using ::android::hardware::hidl_vec;
using ::android::hardware::Return;
using ::android::hardware::Void;
using ::android::sp;

struct OmxBufferSource : public IOmxBufferSource {
    // Methods from ::android::hardware::media::omx::V1_0::IOmxBufferSource follow.
    Return<void> onOmxExecuting() override;
    Return<void> onOmxIdle() override;
    Return<void> onOmxLoaded() override;
    Return<void> onInputBufferAdded(uint32_t buffer) override;
    Return<void> onInputBufferEmptied(uint32_t buffer, const hidl_handle& fence) override;

};

extern "C" IOmxBufferSource* HIDL_FETCH_IOmxBufferSource(const char* name);

}  // namespace implementation
}  // namespace V1_0
}  // namespace omx
}  // namespace media
}  // namespace hardware
}  // namespace android

#endif  // ANDROID_HARDWARE_MEDIA_OMX_V1_0__OMXBUFFERSOURCE_H
