#ifndef ANDROID_HARDWARE_MEDIA_OMX_V1_0_WOMXBUFFERSOURCE_H
#define ANDROID_HARDWARE_MEDIA_OMX_V1_0_WOMXBUFFERSOURCE_H

#include <android/hardware/media/omx/1.0/IOmxBufferSource.h>
#include <hidl/MQDescriptor.h>
#include <hidl/Status.h>

#include <frameworks/native/include/binder/Binder.h>
#include <android/IOMXBufferSource.h>
#include <OMXFenceParcelable.h>

namespace android {
namespace hardware {
namespace media {
namespace omx {
namespace V1_0 {
namespace implementation {

using ::android::hardware::media::omx::V1_0::IOmxBufferSource;
using ::android::hidl::base::V1_0::IBase;
using ::android::hardware::hidl_array;
using ::android::hardware::hidl_memory;
using ::android::hardware::hidl_string;
using ::android::hardware::hidl_vec;
using ::android::hardware::hidl_handle;
using ::android::hardware::Return;
using ::android::hardware::Void;
using ::android::sp;

using ::android::OMXFenceParcelable;
using ::android::IOMXBufferSource;

/**
 * Wrapper classes for conversion
 * ==============================
 *
 * Naming convention:
 * - LW = Legacy Wrapper --- It wraps a Treble object inside a legacy object.
 * - TW = Treble Wrapper --- It wraps a legacy object inside a Treble object.
 */

struct LWOmxBufferSource : public IOMXBufferSource {
    sp<IOmxBufferSource> mBase;
    LWOmxBufferSource(sp<IOmxBufferSource> const& base);
    ::android::binder::Status onOmxExecuting() override;
    ::android::binder::Status onOmxIdle() override;
    ::android::binder::Status onOmxLoaded() override;
    ::android::binder::Status onInputBufferAdded(int32_t bufferID) override;
    ::android::binder::Status onInputBufferEmptied(
            int32_t bufferID, OMXFenceParcelable const& fenceParcel) override;
protected:
    ::android::IBinder* onAsBinder() override;
};

struct TWOmxBufferSource : public IOmxBufferSource {
    sp<IOMXBufferSource> mBase;
    TWOmxBufferSource(sp<IOMXBufferSource> const& base);
    Return<void> onOmxExecuting() override;
    Return<void> onOmxIdle() override;
    Return<void> onOmxLoaded() override;
    Return<void> onInputBufferAdded(uint32_t buffer) override;
    Return<void> onInputBufferEmptied(
            uint32_t buffer, hidl_handle const& fence) override;
};


}  // namespace implementation
}  // namespace V1_0
}  // namespace omx
}  // namespace media
}  // namespace hardware
}  // namespace android

#endif  // ANDROID_HARDWARE_MEDIA_OMX_V1_0_WOMXBUFFERSOURCE_H
