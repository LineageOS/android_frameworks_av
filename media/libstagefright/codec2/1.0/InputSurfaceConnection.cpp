/*
 * Copyright 2018, The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

//#define LOG_NDEBUG 0
#define LOG_TAG "InputSurfaceConnection"
#include <utils/Log.h>

#include <C2AllocatorGralloc.h>
#include <C2BlockInternal.h>
#include <C2PlatformSupport.h>

#include <gui/Surface.h>
#include <media/stagefright/codec2/1.0/InputSurfaceConnection.h>
#include <system/window.h>

namespace android {
namespace hardware {
namespace media {
namespace c2 {
namespace V1_0 {
namespace implementation {

using ::android::status_t;

namespace {

class Buffer2D : public C2Buffer {
public:
    explicit Buffer2D(C2ConstGraphicBlock block) : C2Buffer({ block }) {}
};

}  // namespace

constexpr int32_t kBufferCount = 16;

class InputSurfaceConnection::Impl : public ComponentWrapper {
public:
    Impl(const sp<GraphicBufferSource> &source, const std::shared_ptr<C2Component> &comp)
        : mSource(source), mComp(comp) {
    }

    virtual ~Impl() = default;

    bool init() {
        sp<GraphicBufferSource> source = mSource.promote();
        if (source == nullptr) {
            return false;
        }
        status_t err = source->initCheck();
        if (err != OK) {
            ALOGE("Impl::init: GBS init failed: %d", err);
            return false;
        }
        // TODO: proper color aspect & dataspace
        android_dataspace dataSpace = HAL_DATASPACE_BT709;
        // TODO: read settings properly from the interface
        err = source->configure(
                this, dataSpace, kBufferCount, 1080, 1920, GRALLOC_USAGE_SW_READ_OFTEN);
        if (err != OK) {
            ALOGE("Impl::init: GBS configure failed: %d", err);
            return false;
        }
        for (int32_t i = 0; i < kBufferCount; ++i) {
            if (!source->onInputBufferAdded(i).isOk()) {
                ALOGE("Impl::init: population GBS slots failed");
                return false;
            }
        }
        if (!source->start().isOk()) {
            ALOGE("Impl::init: GBS start failed");
            return false;
        }
        c2_status_t c2err = GetCodec2PlatformAllocatorStore()->fetchAllocator(
                C2AllocatorStore::PLATFORM_START + 1,  // GRALLOC
                &mAllocator);
        if (c2err != OK) {
            ALOGE("Impl::init: failed to fetch gralloc allocator: %d", c2err);
            return false;
        }
        return true;
    }

    // From ComponentWrapper
    status_t submitBuffer(
            int32_t bufferId, const sp<GraphicBuffer> &buffer,
            int64_t timestamp, int fenceFd) override {
        ALOGV("Impl::submitBuffer bufferId = %d", bufferId);
        // TODO: Use fd to construct fence
        (void)fenceFd;

        std::shared_ptr<C2Component> comp = mComp.lock();
        if (!comp) {
            return NO_INIT;
        }

        std::shared_ptr<C2GraphicAllocation> alloc;
        C2Handle *handle = WrapNativeCodec2GrallocHandle(
                buffer->handle, buffer->width, buffer->height,
                buffer->format, buffer->usage, buffer->stride);
        c2_status_t err = mAllocator->priorGraphicAllocation(handle, &alloc);
        if (err != OK) {
            return UNKNOWN_ERROR;
        }
        std::shared_ptr<C2GraphicBlock> block = _C2BlockFactory::CreateGraphicBlock(alloc);

        std::unique_ptr<C2Work> work(new C2Work);
        work->input.flags = (C2FrameData::flags_t)0;
        work->input.ordinal.timestamp = timestamp;
        work->input.ordinal.frameIndex = mFrameIndex++;
        work->input.buffers.clear();
        std::shared_ptr<C2Buffer> c2Buffer(
                // TODO: fence
                new Buffer2D(block->share(
                        C2Rect(block->width(), block->height()), ::android::C2Fence())),
                [handle, bufferId, src = mSource](C2Buffer *ptr) {
                    delete ptr;
                    native_handle_delete(handle);
                    sp<GraphicBufferSource> source = src.promote();
                    if (source != nullptr) {
                        // TODO: fence
                        (void)source->onInputBufferEmptied(bufferId, -1);
                    }
                });
        work->input.buffers.push_back(c2Buffer);
        work->worklets.clear();
        work->worklets.emplace_back(new C2Worklet);
        std::list<std::unique_ptr<C2Work>> items;
        items.push_back(std::move(work));

        err = comp->queue_nb(&items);
        if (err != C2_OK) {
            return UNKNOWN_ERROR;
        }

        mLastTimestamp = timestamp;

        return OK;
    }

    status_t submitEos(int32_t) override {
        std::shared_ptr<C2Component> comp = mComp.lock();
        if (!comp) {
            return NO_INIT;
        }

        std::unique_ptr<C2Work> work(new C2Work);
        work->input.flags = C2FrameData::FLAG_END_OF_STREAM;
        work->input.ordinal.timestamp = mLastTimestamp;
        work->input.ordinal.frameIndex = mFrameIndex++;
        work->input.buffers.clear();
        work->worklets.clear();
        work->worklets.emplace_back(new C2Worklet);
        std::list<std::unique_ptr<C2Work>> items;
        items.push_back(std::move(work));

        c2_status_t err = comp->queue_nb(&items);
        return (err == C2_OK) ? OK : UNKNOWN_ERROR;
    }

    void dispatchDataSpaceChanged(
            int32_t dataSpace, int32_t aspects, int32_t pixelFormat) override {
        // TODO
        (void)dataSpace;
        (void)aspects;
        (void)pixelFormat;
    }

private:
    wp<GraphicBufferSource> mSource;
    std::weak_ptr<C2Component> mComp;

    // Needed for ComponentWrapper implementation
    int64_t mLastTimestamp;
    std::shared_ptr<C2Allocator> mAllocator;
    std::atomic_uint64_t mFrameIndex;
};

InputSurfaceConnection::InputSurfaceConnection(
        const sp<GraphicBufferSource> &source,
        const std::shared_ptr<C2Component> &comp)
    : mSource(source),
      mImpl(new Impl(source, comp)) {
}

InputSurfaceConnection::~InputSurfaceConnection() {
    disconnect();
}

bool InputSurfaceConnection::init() {
    if (mImpl == nullptr) {
        return false;
    }
    return mImpl->init();
}

void InputSurfaceConnection::disconnect() {
    ALOGV("disconnect");
    if (mSource != nullptr) {
        (void)mSource->stop();
        (void)mSource->release();
    }
    mImpl.clear();
    mSource.clear();
    ALOGV("disconnected");
}

}  // namespace implementation
}  // namespace V1_0
}  // namespace c2
}  // namespace media
}  // namespace hardware
}  // namespace android
