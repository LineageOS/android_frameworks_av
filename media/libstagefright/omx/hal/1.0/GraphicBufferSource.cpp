#include "GraphicBufferSource.h"

namespace android {
namespace hardware {
namespace media {
namespace omx {
namespace V1_0 {
namespace implementation {

// Methods from ::android::hardware::media::omx::V1_0::IGraphicBufferSource follow.
Return<Status> GraphicBufferSource::configure(const sp<IOmxNode>& omxNode, Dataspace dataspace) {
    // TODO implement
    return ::android::hardware::media::omx::V1_0::Status {};
}

Return<Status> GraphicBufferSource::setSuspend(bool suspend) {
    // TODO implement
    return ::android::hardware::media::omx::V1_0::Status {};
}

Return<Status> GraphicBufferSource::setRepeatPreviousFrameDelayUs(int64_t repeatAfterUs) {
    // TODO implement
    return ::android::hardware::media::omx::V1_0::Status {};
}

Return<Status> GraphicBufferSource::setMaxFps(float maxFps) {
    // TODO implement
    return ::android::hardware::media::omx::V1_0::Status {};
}

Return<Status> GraphicBufferSource::setTimeLapseConfig(int64_t timePerFrameUs, int64_t timePerCaptureUs) {
    // TODO implement
    return ::android::hardware::media::omx::V1_0::Status {};
}

Return<Status> GraphicBufferSource::setStartTimeUs(int64_t startTimeUs) {
    // TODO implement
    return ::android::hardware::media::omx::V1_0::Status {};
}

Return<Status> GraphicBufferSource::setColorAspects(const ColorAspects& aspects) {
    // TODO implement
    return ::android::hardware::media::omx::V1_0::Status {};
}

Return<Status> GraphicBufferSource::setTimeOffsetUs(int64_t timeOffsetUs) {
    // TODO implement
    return ::android::hardware::media::omx::V1_0::Status {};
}

Return<Status> GraphicBufferSource::signalEndOfInputStream() {
    // TODO implement
    return ::android::hardware::media::omx::V1_0::Status {};
}


IGraphicBufferSource* HIDL_FETCH_IGraphicBufferSource(const char* /* name */) {
    return new GraphicBufferSource();
}

} // namespace implementation
}  // namespace V1_0
}  // namespace omx
}  // namespace media
}  // namespace hardware
}  // namespace android
