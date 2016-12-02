#include "WOmxBufferSource.h"
#include "Conversion.h"
#include <utils/String8.h>
#include <cutils/native_handle.h>

namespace android {
namespace hardware {
namespace media {
namespace omx {
namespace V1_0 {
namespace implementation {

// LWOmxBufferSource
LWOmxBufferSource::LWOmxBufferSource(sp<IOmxBufferSource> const& base) :
    mBase(base) {
}

::android::binder::Status LWOmxBufferSource::onOmxExecuting() {
    return toBinderStatus(mBase->onOmxExecuting());
}

::android::binder::Status LWOmxBufferSource::onOmxIdle() {
    return toBinderStatus(mBase->onOmxIdle());
}

::android::binder::Status LWOmxBufferSource::onOmxLoaded() {
    return toBinderStatus(mBase->onOmxLoaded());
}

::android::binder::Status LWOmxBufferSource::onInputBufferAdded(
        int32_t bufferId) {
    return toBinderStatus(mBase->onInputBufferAdded(
            static_cast<uint32_t>(bufferId)));
}

::android::binder::Status LWOmxBufferSource::onInputBufferEmptied(
        int32_t bufferId, OMXFenceParcelable const& fenceParcel) {
    hidl_handle fence;
    native_handle_t* fenceNh;
    if (!wrapAs(&fence, &fenceNh, fenceParcel)) {
        return ::android::binder::Status::fromExceptionCode(
                ::android::binder::Status::EX_BAD_PARCELABLE,
                "Invalid fence");
    }
    ::android::binder::Status status = toBinderStatus(
            mBase->onInputBufferEmptied(
            static_cast<uint32_t>(bufferId), fence));
    if (native_handle_delete(fenceNh) != 0) {
        return ::android::binder::Status::fromExceptionCode(
                ::android::binder::Status::EX_NULL_POINTER,
                "Cannot delete native handle");
    }
    return status;
}

::android::IBinder* LWOmxBufferSource::onAsBinder() {
    return nullptr;
}

// TWOmxBufferSource
TWOmxBufferSource::TWOmxBufferSource(sp<IOMXBufferSource> const& base) :
    mBase(base) {
}

Return<void> TWOmxBufferSource::onOmxExecuting() {
    return toHardwareStatus(mBase->onOmxExecuting());
}

Return<void> TWOmxBufferSource::onOmxIdle() {
    return toHardwareStatus(mBase->onOmxIdle());
}

Return<void> TWOmxBufferSource::onOmxLoaded() {
    return toHardwareStatus(mBase->onOmxLoaded());
}

Return<void> TWOmxBufferSource::onInputBufferAdded(uint32_t buffer) {
    return toHardwareStatus(mBase->onInputBufferAdded(
            static_cast<int32_t>(buffer)));
}

Return<void> TWOmxBufferSource::onInputBufferEmptied(
        uint32_t buffer, hidl_handle const& fence) {
    OMXFenceParcelable fenceParcelable;
    wrapAs(&fenceParcelable, fence);
    return toHardwareStatus(mBase->onInputBufferEmptied(
            static_cast<int32_t>(buffer), fenceParcelable));
}

}  // namespace implementation
}  // namespace V1_0
}  // namespace omx
}  // namespace media
}  // namespace hardware
}  // namespace android
