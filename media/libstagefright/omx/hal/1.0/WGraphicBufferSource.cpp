#include "WGraphicBufferSource.h"
#include "Conversion.h"
#include "WOmxNode.h"
#include <stagefright/foundation/ColorUtils.h>

namespace android {
namespace hardware {
namespace media {
namespace omx {
namespace V1_0 {
namespace implementation {

using android::ColorUtils;

// LWGraphicBufferSource
LWGraphicBufferSource::LWGraphicBufferSource(
        sp<TGraphicBufferSource> const& base) : mBase(base) {
}

::android::binder::Status LWGraphicBufferSource::configure(
        const sp<IOMXNode>& omxNode, int32_t dataSpace) {
    return toBinderStatus(mBase->configure(
            new TWOmxNode(omxNode), toHardwareDataspace(dataSpace)));
}

::android::binder::Status LWGraphicBufferSource::setSuspend(bool suspend) {
    return toBinderStatus(mBase->setSuspend(suspend));
}

::android::binder::Status LWGraphicBufferSource::setRepeatPreviousFrameDelayUs(
        int64_t repeatAfterUs) {
    return toBinderStatus(mBase->setRepeatPreviousFrameDelayUs(repeatAfterUs));
}

::android::binder::Status LWGraphicBufferSource::setMaxFps(float maxFps) {
    return toBinderStatus(mBase->setMaxFps(maxFps));
}

::android::binder::Status LWGraphicBufferSource::setTimeLapseConfig(
        int64_t timePerFrameUs, int64_t timePerCaptureUs) {
    return toBinderStatus(mBase->setTimeLapseConfig(
            timePerFrameUs, timePerCaptureUs));
}

::android::binder::Status LWGraphicBufferSource::setStartTimeUs(
        int64_t startTimeUs) {
    return toBinderStatus(mBase->setStartTimeUs(startTimeUs));
}

::android::binder::Status LWGraphicBufferSource::setColorAspects(
        int32_t aspects) {
    return toBinderStatus(mBase->setColorAspects(
            toHardwareColorAspects(aspects)));
}

::android::binder::Status LWGraphicBufferSource::setTimeOffsetUs(
        int64_t timeOffsetsUs) {
    return toBinderStatus(mBase->setTimeOffsetUs(timeOffsetsUs));
}

::android::binder::Status LWGraphicBufferSource::signalEndOfInputStream() {
    return toBinderStatus(mBase->signalEndOfInputStream());
}

::android::IBinder* LWGraphicBufferSource::onAsBinder() {
    return nullptr;
}

// TWGraphicBufferSource
TWGraphicBufferSource::TWGraphicBufferSource(
        sp<LGraphicBufferSource> const& base) : mBase(base) {
}

Return<void> TWGraphicBufferSource::configure(
        const sp<IOmxNode>& omxNode, Dataspace dataspace) {
    return toHardwareStatus(mBase->configure(
            new LWOmxNode(omxNode),
            toRawDataspace(dataspace)));
}

Return<void> TWGraphicBufferSource::setSuspend(bool suspend) {
    return toHardwareStatus(mBase->setSuspend(suspend));
}

Return<void> TWGraphicBufferSource::setRepeatPreviousFrameDelayUs(
        int64_t repeatAfterUs) {
    return toHardwareStatus(mBase->setRepeatPreviousFrameDelayUs(
            repeatAfterUs));
}

Return<void> TWGraphicBufferSource::setMaxFps(float maxFps) {
    return toHardwareStatus(mBase->setMaxFps(maxFps));
}

Return<void> TWGraphicBufferSource::setTimeLapseConfig(
        int64_t timePerFrameUs, int64_t timePerCaptureUs) {
    return toHardwareStatus(mBase->setTimeLapseConfig(
            timePerFrameUs, timePerCaptureUs));
}

Return<void> TWGraphicBufferSource::setStartTimeUs(int64_t startTimeUs) {
    return toHardwareStatus(mBase->setStartTimeUs(startTimeUs));
}

Return<void> TWGraphicBufferSource::setColorAspects(
        const ColorAspects& aspects) {
    return toHardwareStatus(mBase->setColorAspects(toCompactColorAspects(
            aspects)));
}

Return<void> TWGraphicBufferSource::setTimeOffsetUs(int64_t timeOffsetUs) {
    return toHardwareStatus(mBase->setTimeOffsetUs(timeOffsetUs));
}

Return<void> TWGraphicBufferSource::signalEndOfInputStream() {
    return toHardwareStatus(mBase->signalEndOfInputStream());
}

}  // namespace implementation
}  // namespace V1_0
}  // namespace omx
}  // namespace media
}  // namespace hardware
}  // namespace android
