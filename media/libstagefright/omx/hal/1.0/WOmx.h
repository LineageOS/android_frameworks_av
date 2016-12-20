#ifndef ANDROID_HARDWARE_MEDIA_OMX_V1_0_WOMX_H
#define ANDROID_HARDWARE_MEDIA_OMX_V1_0_WOMX_H

#include <android/hardware/media/omx/1.0/IOmx.h>
#include <hidl/MQDescriptor.h>
#include <hidl/Status.h>

#include <IOMX.h>

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
using ::android::hidl::base::V1_0::IBase;
using ::android::hardware::hidl_array;
using ::android::hardware::hidl_memory;
using ::android::hardware::hidl_string;
using ::android::hardware::hidl_vec;
using ::android::hardware::Return;
using ::android::hardware::Void;
using ::android::sp;

using ::android::List;
using ::android::IOMX;

/**
 * Wrapper classes for conversion
 * ==============================
 *
 * Naming convention:
 * - LW = Legacy Wrapper --- It wraps a Treble object inside a legacy object.
 * - TW = Treble Wrapper --- It wraps a legacy object inside a Treble object.
 */

struct LWOmx : public IOMX {
    sp<IOmx> mBase;
    LWOmx(sp<IOmx> const& base);
    status_t listNodes(List<IOMX::ComponentInfo>* list) override;
    status_t allocateNode(
            char const* name,
            sp<IOMXObserver> const& observer,
            sp<IOMXNode>* omxNode) override;
    status_t createInputSurface(
            sp<::android::IGraphicBufferProducer>* bufferProducer,
            sp<::android::IGraphicBufferSource>* bufferSource) override;
protected:
    ::android::IBinder* onAsBinder() override;
};

struct TWOmx : public IOmx {
    sp<IOMX> mBase;
    TWOmx(sp<IOMX> const& base);
    Return<void> listNodes(listNodes_cb _hidl_cb) override;
    Return<void> allocateNode(
            const hidl_string& name,
            const sp<IOmxObserver>& observer,
            allocateNode_cb _hidl_cb) override;

};

}  // namespace implementation
}  // namespace V1_0
}  // namespace omx
}  // namespace media
}  // namespace hardware
}  // namespace android

#endif  // ANDROID_HARDWARE_MEDIA_OMX_V1_0_WOMX_H
