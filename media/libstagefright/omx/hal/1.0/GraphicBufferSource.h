#ifndef ANDROID_HARDWARE_MEDIA_OMX_V1_0__GRAPHICBUFFERSOURCE_H
#define ANDROID_HARDWARE_MEDIA_OMX_V1_0__GRAPHICBUFFERSOURCE_H

#include <android/hardware/media/omx/1.0/IGraphicBufferSource.h>
#include <hidl/MQDescriptor.h>
#include <hidl/Status.h>

namespace android {
namespace hardware {
namespace media {
namespace omx {
namespace V1_0 {
namespace implementation {

using ::android::hardware::graphics::common::V1_0::Dataspace;
using ::android::hardware::media::omx::V1_0::ColorAspects;
using ::android::hardware::media::omx::V1_0::IGraphicBufferSource;
using ::android::hardware::media::omx::V1_0::IOmxNode;
using ::android::hardware::media::omx::V1_0::Status;
using ::android::hardware::hidl_array;
using ::android::hardware::hidl_string;
using ::android::hardware::hidl_vec;
using ::android::hardware::Return;
using ::android::hardware::Void;
using ::android::sp;

struct GraphicBufferSource : public IGraphicBufferSource {
    // Methods from ::android::hardware::media::omx::V1_0::IGraphicBufferSource follow.
    Return<Status> configure(const sp<IOmxNode>& omxNode, Dataspace dataspace) override;
    Return<Status> setSuspend(bool suspend) override;
    Return<Status> setRepeatPreviousFrameDelayUs(int64_t repeatAfterUs) override;
    Return<Status> setMaxFps(float maxFps) override;
    Return<Status> setTimeLapseConfig(int64_t timePerFrameUs, int64_t timePerCaptureUs) override;
    Return<Status> setStartTimeUs(int64_t startTimeUs) override;
    Return<Status> setColorAspects(const ColorAspects& aspects) override;
    Return<Status> setTimeOffsetUs(int64_t timeOffsetUs) override;
    Return<Status> signalEndOfInputStream() override;

};

extern "C" IGraphicBufferSource* HIDL_FETCH_IGraphicBufferSource(const char* name);

}  // namespace implementation
}  // namespace V1_0
}  // namespace omx
}  // namespace media
}  // namespace hardware
}  // namespace android

#endif  // ANDROID_HARDWARE_MEDIA_OMX_V1_0__GRAPHICBUFFERSOURCE_H
