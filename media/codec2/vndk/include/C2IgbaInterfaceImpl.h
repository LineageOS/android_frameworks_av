/*
 * Copyright 2025 The Android Open Source Project
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
#pragma once

#include <memory>
#include <C2IgbaInterface.h>

#include <vndk/hardware_buffer.h>
#include <aidl/android/hardware/media/c2/IGraphicBufferAllocator.h>

namespace android {

/**
 *  c2aidl IGraphicBufferAllocator interface wrapper implementation class.
 *
 *  The implementation is provided in order for the library which uses this
 *  class to specify dependency directly including media.c2 aidl HAL.
 *
 *  The purpose of the interface and this implementation is minimizing
 *  media.c2 aidl HAL dependency to existing libraries.
 *
 *  This implementation must not be used other than libcodec2_aidl and
 *  libcodec2_aidl_client.
 */
class C2IgbaInterfaceImpl : public C2IgbaInterface {
public:
    using C2IGBA = ::aidl::android::hardware::media::c2::IGraphicBufferAllocator;

    int32_t static inline ToAidl(uint32_t u) {return static_cast<int32_t>(u);}
    int64_t static inline ToAidl(uint64_t u) {return static_cast<int64_t>(u);}

    static constexpr c2_status_t C2_TRANSACTION_FAILED = C2_CORRUPTED;

    C2IgbaInterfaceImpl(
            const std::shared_ptr<C2IGBA> &igba) : mIgba(igba) {}

    virtual ~C2IgbaInterfaceImpl() override = default;

    virtual c2_status_t allocate(
            uint32_t width, uint32_t height, uint32_t format, uint64_t usage,
            AHardwareBuffer **pBuf,  int *syncFenceFd) override {
        C2IGBA::Description desc{
            ToAidl(width), ToAidl(height), ToAidl(format), ToAidl(usage)};
        C2IGBA::Allocation allocation;
        ::ndk::ScopedAStatus status = mIgba->allocate(desc, &allocation);
        if (!status.isOk()) {
            binder_exception_t ex = status.getExceptionCode();
            if (ex == EX_SERVICE_SPECIFIC) {
                c2_status_t err = static_cast<c2_status_t>(status.getServiceSpecificError());
                return err;
            } else {
                ALOGW("igba::allocate transaction failed: %d", ex);
                return C2_TRANSACTION_FAILED;
            }
        }
        *pBuf = allocation.buffer.release();
        *syncFenceFd = allocation.fence.release();
        return C2_OK;
    }

    virtual c2_status_t deallocate(uint64_t ahwbId, bool *deallocated) override {
        bool aidlRet = true;
        ::ndk::ScopedAStatus status = mIgba->deallocate(ToAidl(ahwbId), &aidlRet);
        if (!status.isOk()) {
            return C2_TRANSACTION_FAILED;
        }
        *deallocated = aidlRet;
        return C2_OK;
    }

private:
    const std::shared_ptr<C2IGBA> mIgba;
};

}  // namespace android
