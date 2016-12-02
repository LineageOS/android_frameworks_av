#include "Omx.h"

namespace android {
namespace hardware {
namespace media {
namespace omx {
namespace V1_0 {
namespace implementation {

// Methods from ::android::hardware::media::omx::V1_0::IOmx follow.
Return<void> Omx::listNodes(listNodes_cb _hidl_cb) {
    // TODO implement
    return Void();
}

Return<void> Omx::allocateNode(const hidl_string& name, const sp<IOmxObserver>& observer, allocateNode_cb _hidl_cb) {
    // TODO implement
    return Void();
}


IOmx* HIDL_FETCH_IOmx(const char* /* name */) {
    return new Omx();
}

} // namespace implementation
}  // namespace V1_0
}  // namespace omx
}  // namespace media
}  // namespace hardware
}  // namespace android
