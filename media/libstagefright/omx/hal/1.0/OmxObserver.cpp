#include "OmxObserver.h"

namespace android {
namespace hardware {
namespace media {
namespace omx {
namespace V1_0 {
namespace implementation {

// Methods from ::android::hardware::media::omx::V1_0::IOmxObserver follow.
Return<void> OmxObserver::onMessages(const hidl_vec<Message>& messages) {
    // TODO implement
    return Void();
}


IOmxObserver* HIDL_FETCH_IOmxObserver(const char* /* name */) {
    return new OmxObserver();
}

} // namespace implementation
}  // namespace V1_0
}  // namespace omx
}  // namespace media
}  // namespace hardware
}  // namespace android
