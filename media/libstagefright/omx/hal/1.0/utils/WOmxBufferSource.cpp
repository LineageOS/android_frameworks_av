/*
 * Copyright 2016, The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "WOmxBufferSource.h"
#include "Conversion.h"
#include <utils/String8.h>
#include <cutils/native_handle.h>

namespace android {
namespace hardware {
namespace media {
namespace omx {
namespace V1_0 {
namespace utils {

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
    if (!convertTo(&fenceParcelable, fence)) {
      return ::android::hardware::Status::fromExceptionCode(
              ::android::hardware::Status::EX_BAD_PARCELABLE);
    }
    return toHardwareStatus(mBase->onInputBufferEmptied(
            static_cast<int32_t>(buffer), fenceParcelable));
}

}  // namespace utils
}  // namespace V1_0
}  // namespace omx
}  // namespace media
}  // namespace hardware
}  // namespace android
