#include "OmxBufferSource.h"

namespace android {
namespace hardware {
namespace media {
namespace omx {
namespace V1_0 {
namespace implementation {

// Methods from ::android::hardware::media::omx::V1_0::IOmxBufferSource follow.
Return<void> OmxBufferSource::onOmxExecuting() {
    // TODO implement
    return Void();
}

Return<void> OmxBufferSource::onOmxIdle() {
    // TODO implement
    return Void();
}

Return<void> OmxBufferSource::onOmxLoaded() {
    // TODO implement
    return Void();
}

Return<void> OmxBufferSource::onInputBufferAdded(uint32_t buffer) {
    // TODO implement
    return Void();
}

Return<void> OmxBufferSource::onInputBufferEmptied(uint32_t buffer, const hidl_handle& fence) {
    // TODO implement
    return Void();
}


IOmxBufferSource* HIDL_FETCH_IOmxBufferSource(const char* /* name */) {
    return new OmxBufferSource();
}

} // namespace implementation
}  // namespace V1_0
}  // namespace omx
}  // namespace media
}  // namespace hardware
}  // namespace android
