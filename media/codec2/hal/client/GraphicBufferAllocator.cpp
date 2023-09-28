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

#include <gui/IProducerListener.h>
#include <media/stagefright/foundation/ADebug.h>

#include <codec2/aidl/GraphicBufferAllocator.h>
#include <codec2/aidl/GraphicsTracker.h>

namespace aidl::android::hardware::media::c2::implementation {

class OnBufferReleasedListener : public ::android::BnProducerListener {
private:
    uint32_t mGeneration;
    std::weak_ptr<GraphicBufferAllocator> mAllocator;
public:
    OnBufferReleasedListener(
            uint32_t generation,
            const std::shared_ptr<GraphicBufferAllocator> &allocator)
            : mGeneration(generation), mAllocator(allocator) {}
    virtual ~OnBufferReleasedListener() = default;
    virtual void onBufferReleased() {
        auto p = mAllocator.lock();
        if (p) {
            p->onBufferReleased(mGeneration);
        }
    }
    virtual bool needsReleaseNotify() { return true; }
};

::ndk::ScopedAStatus GraphicBufferAllocator::allocate(
        const IGraphicBufferAllocator::Description& in_desc,
        IGraphicBufferAllocator::Allocation* _aidl_return) {
    AHardwareBuffer *buf;
    ::android::sp<::android::Fence> fence;
    c2_status_t ret = allocate(
            in_desc.width, in_desc.height, in_desc.format, in_desc.usage,
            &buf, &fence);
    if (ret == C2_OK) {
        _aidl_return->buffer.reset(buf);
        _aidl_return->fence = ::ndk::ScopedFileDescriptor(fence->dup());
        return ::ndk::ScopedAStatus::ok();
    }
    return ::ndk::ScopedAStatus::fromServiceSpecificError(ret);
}

::ndk::ScopedAStatus GraphicBufferAllocator::deallocate(int64_t in_id, bool* _aidl_return) {
    *_aidl_return = deallocate(in_id, ::android::Fence::NO_FENCE);
    return ::ndk::ScopedAStatus::ok();
}

::ndk::ScopedAStatus GraphicBufferAllocator::getWaitableFd(
        ::ndk::ScopedFileDescriptor* _aidl_return) {
    int pipeFd;
    c2_status_t ret = mGraphicsTracker->getWaitableFd(&pipeFd);
    if (ret == C2_OK) {
        _aidl_return->set(pipeFd);
        return ::ndk::ScopedAStatus::ok();
    }
    return ::ndk::ScopedAStatus::fromServiceSpecificError(ret);
}

bool GraphicBufferAllocator::configure(
        const ::android::sp<IGraphicBufferProducer>& igbp,
        uint32_t generation,
        int maxDequeueBufferCount) {
    c2_status_t ret = C2_OK;

    ret = mGraphicsTracker->configureGraphics(igbp, generation);
    if (ret != C2_OK) {
        ALOGE("configuring igbp failed gen #(%d), configuring max dequeue count didn't happen",
              (unsigned int)generation);
        return false;
    }

    ret = mGraphicsTracker->configureMaxDequeueCount(maxDequeueBufferCount);
    if (ret != C2_OK) {
        ALOGE("configuring max dequeue count to %d failed", maxDequeueBufferCount);
        return false;
    }
    return true;
}

void GraphicBufferAllocator::updateMaxDequeueBufferCount(int count) {
    c2_status_t ret = mGraphicsTracker->configureMaxDequeueCount(count);
    if (ret != C2_OK) {
        ALOGE("updating max dequeue buffer count failed %d", ret);
    }
}

void GraphicBufferAllocator::reset() {
    mGraphicsTracker->stop();
}

const ::android::sp<::android::IProducerListener> GraphicBufferAllocator::createReleaseListener(
      uint32_t generation) {
    return new OnBufferReleasedListener(generation, ref<GraphicBufferAllocator>());
}

void GraphicBufferAllocator::onBufferReleased(uint32_t generation) {
    mGraphicsTracker->onReleased(generation);
}

c2_status_t GraphicBufferAllocator::allocate(
        uint32_t width, uint32_t height, ::android::PixelFormat format, uint64_t usage,
        AHardwareBuffer **buf, ::android::sp<::android::Fence> *fence) {
    return mGraphicsTracker->allocate(width, height, format, usage, buf, fence);
}

bool GraphicBufferAllocator::deallocate(const uint64_t id,
                                        const ::android::sp<::android::Fence> &fence) {
    c2_status_t ret = mGraphicsTracker->deallocate(id, fence);
    if (ret != C2_OK) {
        ALOGW("deallocate() %llu was not successful %d", (unsigned long long)id, ret);
        return false;
    }
    return true;
}

c2_status_t GraphicBufferAllocator::displayBuffer(
        const C2ConstGraphicBlock& block,
        const IGraphicBufferProducer::QueueBufferInput& input,
        IGraphicBufferProducer::QueueBufferOutput *output) {
    return mGraphicsTracker->render(block, input, output);
}

GraphicBufferAllocator::~GraphicBufferAllocator() {}

std::shared_ptr<GraphicBufferAllocator> GraphicBufferAllocator::CreateGraphicBufferAllocator(
        int maxDequeueCount) {
    return ::ndk::SharedRefBase::make<GraphicBufferAllocator>(maxDequeueCount);
}

GraphicBufferAllocator::GraphicBufferAllocator(int maxDequeueCount)
        : mGraphicsTracker(GraphicsTracker::CreateGraphicsTracker(maxDequeueCount)) {}

} // namespace aidl::android::hardware::media::c2::implementation
