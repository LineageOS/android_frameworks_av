#ifndef ANDROID_HARDWARE_MEDIA_OMX_V1_0__OMXOBSERVER_H
#define ANDROID_HARDWARE_MEDIA_OMX_V1_0__OMXOBSERVER_H

#include <android/hardware/media/omx/1.0/IOmxObserver.h>
#include <hidl/MQDescriptor.h>
#include <hidl/Status.h>

namespace android {
namespace hardware {
namespace media {
namespace omx {
namespace V1_0 {
namespace implementation {

using ::android::hardware::media::omx::V1_0::IOmxObserver;
using ::android::hardware::media::omx::V1_0::Message;
using ::android::hardware::hidl_array;
using ::android::hardware::hidl_string;
using ::android::hardware::hidl_vec;
using ::android::hardware::Return;
using ::android::hardware::Void;
using ::android::sp;

struct OmxObserver : public IOmxObserver {
    // Methods from ::android::hardware::media::omx::V1_0::IOmxObserver follow.
    Return<void> onMessages(const hidl_vec<Message>& messages) override;

};

extern "C" IOmxObserver* HIDL_FETCH_IOmxObserver(const char* name);

}  // namespace implementation
}  // namespace V1_0
}  // namespace omx
}  // namespace media
}  // namespace hardware
}  // namespace android

#endif  // ANDROID_HARDWARE_MEDIA_OMX_V1_0__OMXOBSERVER_H
