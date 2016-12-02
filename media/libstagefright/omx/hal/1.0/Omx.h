#ifndef ANDROID_HARDWARE_MEDIA_OMX_V1_0__OMX_H
#define ANDROID_HARDWARE_MEDIA_OMX_V1_0__OMX_H

#include <android/hardware/media/omx/1.0/IOmx.h>
#include <hidl/MQDescriptor.h>
#include <hidl/Status.h>

namespace android {
namespace hardware {
namespace media {
namespace omx {
namespace V1_0 {
namespace implementation {

using ::android::hardware::media::omx::V1_0::IOmx;
using ::android::hardware::media::omx::V1_0::IOmxNode;
using ::android::hardware::media::omx::V1_0::IOmxObserver;
using ::android::hardware::media::omx::V1_0::Status;
using ::android::hardware::hidl_array;
using ::android::hardware::hidl_string;
using ::android::hardware::hidl_vec;
using ::android::hardware::Return;
using ::android::hardware::Void;
using ::android::sp;

struct Omx : public IOmx {
    // Methods from ::android::hardware::media::omx::V1_0::IOmx follow.
    Return<void> listNodes(listNodes_cb _hidl_cb) override;
    Return<void> allocateNode(const hidl_string& name, const sp<IOmxObserver>& observer, allocateNode_cb _hidl_cb) override;

};

extern "C" IOmx* HIDL_FETCH_IOmx(const char* name);

}  // namespace implementation
}  // namespace V1_0
}  // namespace omx
}  // namespace media
}  // namespace hardware
}  // namespace android

#endif  // ANDROID_HARDWARE_MEDIA_OMX_V1_0__OMX_H
