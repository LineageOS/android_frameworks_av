#ifndef ANDROID_HARDWARE_MEDIA_OMX_V1_0_WOMXOBSERVER_H
#define ANDROID_HARDWARE_MEDIA_OMX_V1_0_WOMXOBSERVER_H

#include <android/hardware/media/omx/1.0/IOmxObserver.h>
#include <hidl/MQDescriptor.h>
#include <hidl/Status.h>

#include <IOMX.h>
#include <list>

namespace android {
namespace hardware {
namespace media {
namespace omx {
namespace V1_0 {
namespace implementation {

using ::android::hardware::media::omx::V1_0::IOmxObserver;
using ::android::hardware::media::omx::V1_0::Message;
using ::android::hidl::base::V1_0::IBase;
using ::android::hardware::hidl_array;
using ::android::hardware::hidl_memory;
using ::android::hardware::hidl_string;
using ::android::hardware::hidl_vec;
using ::android::hardware::Return;
using ::android::hardware::Void;
using ::android::sp;

using ::android::IOMXObserver;
using ::android::omx_message;

/**
 * Wrapper classes for conversion
 * ==============================
 *
 * Naming convention:
 * - LW = Legacy Wrapper --- It wraps a Treble object inside a legacy object.
 * - TW = Treble Wrapper --- It wraps a legacy object inside a Treble object.
 */

struct LWOmxObserver : public IOMXObserver {
    sp<IOmxObserver> mBase;
    LWOmxObserver(sp<IOmxObserver> const& base);
    void onMessages(std::list<omx_message> const& lMessages) override;
protected:
    ::android::IBinder* onAsBinder() override;
};

struct TWOmxObserver : public IOmxObserver {
    sp<IOMXObserver> mBase;
    TWOmxObserver(sp<IOMXObserver> const& base);
    Return<void> onMessages(const hidl_vec<Message>& tMessages) override;
};

}  // namespace implementation
}  // namespace V1_0
}  // namespace omx
}  // namespace media
}  // namespace hardware
}  // namespace android

#endif  // ANDROID_HARDWARE_MEDIA_OMX_V1_0_WOMXOBSERVER_H
