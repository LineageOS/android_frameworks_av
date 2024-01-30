/*
 * Copyright (C) 2023 The Android Open Source Project
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
//#define LOG_NDEBUG 0
#define LOG_TAG "C2IgbaBuffer"
#include <android-base/logging.h>
#include <aidl/android/hardware/media/c2/IGraphicBufferAllocator.h>
#include <vndk/hardware_buffer.h>
#include <utils/Log.h>

#include <C2AllocatorGralloc.h>
#include <C2BlockInternal.h>
#include <C2FenceFactory.h>
#include <C2IgbaBufferPriv.h>
#include <C2PlatformSupport.h>

using ::android::C2AllocatorAhwb;
using C2IGBA = ::aidl::android::hardware::media::c2::IGraphicBufferAllocator;

namespace {
int32_t static inline ToAidl(uint32_t u) {return static_cast<int32_t>(u);}
int64_t static inline ToAidl(uint64_t u) {return static_cast<int64_t>(u);}

c2_nsecs_t static constexpr kBlockingFetchTimeoutNs = 5000000000LL; // 5 secs
c2_nsecs_t static constexpr kSyncFenceWaitNs = (1000000000LL / 60LL); // 60 fps frame secs

c2_status_t static CreateGraphicBlockFromAhwb(AHardwareBuffer *ahwb,
                                            const std::shared_ptr<C2Allocator> &allocator,
                                            const std::shared_ptr<C2IGBA> &igba,
                                            std::shared_ptr<C2GraphicBlock> *block) {
    if (__builtin_available(android __ANDROID_API_T__, *)) {
        uint64_t origId = 0;
        CHECK(AHardwareBuffer_getId(ahwb, &origId) == ::android::OK);

        AHardwareBuffer_Desc desc;
        AHardwareBuffer_describe(ahwb, &desc);
        const native_handle_t *handle = AHardwareBuffer_getNativeHandle(ahwb);
        // cloned handle with wrapped data.(independent lifecycle with Ahwb)
        C2Handle *c2Handle = android::WrapNativeCodec2AhwbHandle(
                handle,
                desc.width,
                desc.height,
                desc.format,
                desc.usage,
                desc.stride,
                origId);
        if (!c2Handle) {
            return C2_NO_MEMORY;
        }
        std::shared_ptr<C2GraphicAllocation> alloc;
        c2_status_t err = allocator->priorGraphicAllocation(c2Handle, &alloc);
        if (err != C2_OK) {
            native_handle_close(c2Handle);
            native_handle_delete(c2Handle);
            return err;
        }
        std::shared_ptr<C2IgbaBlockPoolData> poolData =
                std::make_shared<C2IgbaBlockPoolData>(
                        ahwb, const_cast<std::shared_ptr<C2IGBA>&>(igba));
        *block = _C2BlockFactory::CreateGraphicBlock(alloc, poolData);
        return C2_OK;
    } else {
        return C2_OMITTED;
    }
}

} // anonymous namespace

C2IgbaBlockPoolData::C2IgbaBlockPoolData(
        const AHardwareBuffer *buffer,
        std::shared_ptr<C2IGBA> &igba) : mOwned(true), mBuffer(buffer), mIgba(igba) {
    CHECK(mBuffer);
    AHardwareBuffer_acquire(const_cast<AHardwareBuffer *>(mBuffer));
}

C2IgbaBlockPoolData::~C2IgbaBlockPoolData() {
    CHECK(mBuffer);
    if (mOwned) {
        if (__builtin_available(android __ANDROID_API_T__, *)) {
            auto igba = mIgba.lock();
            if (igba) {
                uint64_t origId;
                CHECK(AHardwareBuffer_getId(mBuffer, &origId) == ::android::OK);
                bool aidlRet = true;
                ::ndk::ScopedAStatus status = igba->deallocate(origId, &aidlRet);
                if (!status.isOk() || !aidlRet) {
                    ALOGW("AHwb destruction notifying failure %d(%d)", status.isOk(), aidlRet);
                }
            }
        }
    }
    AHardwareBuffer_release(const_cast<AHardwareBuffer *>(mBuffer));
}

C2IgbaBlockPoolData::type_t C2IgbaBlockPoolData::getType() const {
    return TYPE_AHWBUFFER;
}

void C2IgbaBlockPoolData::getAHardwareBuffer(AHardwareBuffer **pBuf) const {
    *pBuf = const_cast<AHardwareBuffer *>(mBuffer);
}

void C2IgbaBlockPoolData::disown() {
    mOwned = false;
}

void C2IgbaBlockPoolData::registerIgba(std::shared_ptr<C2IGBA> &igba) {
    mIgba = igba;
}

std::shared_ptr<C2GraphicBlock> _C2BlockFactory::CreateGraphicBlock(AHardwareBuffer *ahwb) {
    // TODO: get proper allocator? and synchronization? or allocator-less?
    static std::shared_ptr<C2AllocatorAhwb> sAllocator = std::make_shared<C2AllocatorAhwb>(0);
    std::shared_ptr<C2GraphicBlock> block;
    c2_status_t res = CreateGraphicBlockFromAhwb(
            ahwb, std::static_pointer_cast<C2Allocator>(sAllocator), nullptr, &block);
    if (res != C2_OK) {
        return nullptr;
    }
    return block;
}

bool _C2BlockFactory::GetAHardwareBuffer(
        const std::shared_ptr<const _C2BlockPoolData>& data,
        AHardwareBuffer **pBuf) {
    if (data && data->getType() == _C2BlockPoolData::TYPE_AHWBUFFER) {
        const std::shared_ptr<const C2IgbaBlockPoolData> poolData =
                std::static_pointer_cast<const C2IgbaBlockPoolData>(data);
        poolData->getAHardwareBuffer(pBuf);
        return true;
    }
    return false;
}

void _C2BlockFactory::DisownIgbaBlock(
        const std::shared_ptr<_C2BlockPoolData>& data) {
    if (data && data->getType() == _C2BlockPoolData::TYPE_AHWBUFFER) {
        const std::shared_ptr<C2IgbaBlockPoolData> poolData =
                std::static_pointer_cast<C2IgbaBlockPoolData>(data);
        poolData->disown();
    }
}

void _C2BlockFactory::RegisterIgba(
        const std::shared_ptr<_C2BlockPoolData>& data,
        std::shared_ptr<C2IGBA> &igba) {
    if (data && data->getType() == _C2BlockPoolData::TYPE_AHWBUFFER) {
        const std::shared_ptr<C2IgbaBlockPoolData> poolData =
                std::static_pointer_cast<C2IgbaBlockPoolData>(data);
        poolData->registerIgba(igba);
    }
}

C2IgbaBlockPool::C2IgbaBlockPool(
        const std::shared_ptr<C2Allocator> &allocator,
        const std::shared_ptr<C2IGBA> &igba,
        ::android::base::unique_fd &&ufd,
        const local_id_t localId) : mAllocator(allocator), mIgba(igba), mLocalId(localId) {
    if (!mIgba) {
        mValid = false;
        return;
    }
    if (ufd.get() < 0) {
        mValid = false;
        return;
    }
    mWaitFence = _C2FenceFactory::CreatePipeFence(std::move(ufd));
    if (!mWaitFence.valid()) {
        mValid = false;
        return;
    }
    mValid = true;
}

c2_status_t C2IgbaBlockPool::fetchGraphicBlock(
        uint32_t width, uint32_t height, uint32_t format,
        C2MemoryUsage usage, std::shared_ptr<C2GraphicBlock> *block) {
    uint64_t origId;
    C2Fence fence;
    c2_status_t res = _fetchGraphicBlock(
            width, height, format, usage, kBlockingFetchTimeoutNs, &origId, block, &fence);

    if (res == C2_TIMED_OUT) {
        // SyncFence waiting timeout.
        // Usually HAL treats C2_TIMED_OUT as an irrecoverable error.
        // We want HAL to re-try.
        return C2_BLOCKING;
    }
    return res;
}

c2_status_t C2IgbaBlockPool::fetchGraphicBlock(
        uint32_t width, uint32_t height, uint32_t format, C2MemoryUsage usage,
        std::shared_ptr<C2GraphicBlock> *block, C2Fence *fence) {
    uint64_t origId;
    c2_status_t res = _fetchGraphicBlock(width, height, format, usage, 0LL, &origId, block, fence);
    if (res == C2_TIMED_OUT) {
        *fence = C2Fence();
        return C2_BLOCKING;
    }
    return res;
}

c2_status_t C2IgbaBlockPool::_fetchGraphicBlock(
        uint32_t width, uint32_t height, uint32_t format, C2MemoryUsage usage,
        c2_nsecs_t timeoutNs,
        uint64_t *origId,
        std::shared_ptr<C2GraphicBlock> *block,
        C2Fence *fence) {
    if (!mValid) {
        return C2_BAD_STATE;
    }
    if (__builtin_available(android __ANDROID_API_T__, *)) {
        c2_status_t waitRes = mWaitFence.wait(timeoutNs);
        switch (waitRes) {
            case C2_CANCELED: {
                *fence = mWaitFence;
                return C2_BLOCKING;
            }
            case C2_TIMED_OUT: {
                *fence = mWaitFence;
                return C2_BLOCKING;
            }
            case C2_OK:
                break;
            default: { // C2_BAD_STATE
                mValid = false;
                return C2_BAD_STATE;
            }
        }

        ::android::C2AndroidMemoryUsage memUsage{usage};
        C2IGBA::Description desc{
            ToAidl(width), ToAidl(height), ToAidl(format), ToAidl(memUsage.asGrallocUsage())};
        C2IGBA::Allocation allocation;
        ::ndk::ScopedAStatus status = mIgba->allocate(desc, &allocation);
        if (!status.isOk()) {
            binder_exception_t ex = status.getExceptionCode();
            if (ex == EX_SERVICE_SPECIFIC) {
                c2_status_t err = static_cast<c2_status_t>(status.getServiceSpecificError());
                if (err == C2_BLOCKING) {
                    *fence = mWaitFence;
                }
                return err;
            } else {
                ALOGW("igba::allocate transaction failed: %d", ex);
                return C2_CORRUPTED;
            }
        }

        C2Fence syncFence  = _C2FenceFactory::CreateSyncFence(allocation.fence.release());
        AHardwareBuffer *ahwb = allocation.buffer.release(); // This is acquired.
        CHECK(AHardwareBuffer_getId(ahwb, origId) == ::android::OK);

        // We are waiting for SyncFence here for backward compatibility.
        // H/W based Sync Fence could be returned to improve pipeline latency.
        //
        // TODO: Add a component configuration for returning sync fence
        // from fetchGraphicBlock() as the C2Fence output param(b/322283520).
        // In the case C2_OK along with GraphicBlock must be returned together.
        c2_status_t res = syncFence.wait(kSyncFenceWaitNs);
        if (res != C2_OK) {
            AHardwareBuffer_release(ahwb);
            bool aidlRet = true;
            ::ndk::ScopedAStatus status = mIgba->deallocate(*origId, &aidlRet);
            ALOGE("Waiting a sync fence failed %d aidl(%d: %d)",
                  res, status.isOk(), aidlRet);
            return C2_TIMED_OUT;
        }

        res = CreateGraphicBlockFromAhwb(ahwb, mAllocator, mIgba, block);
        AHardwareBuffer_release(ahwb);
        if (res != C2_OK) {
            bool aidlRet = true;
            ::ndk::ScopedAStatus status = mIgba->deallocate(*origId, &aidlRet);
            ALOGE("We got AHWB via AIDL but failed to created C2GraphicBlock err(%d) aidl(%d, %d)",
                  res, status.isOk(), aidlRet);
        }
        return res;
    } else {
        return C2_OMITTED;
    }
}

void C2IgbaBlockPool::invalidate() {
    mValid = false;
}
