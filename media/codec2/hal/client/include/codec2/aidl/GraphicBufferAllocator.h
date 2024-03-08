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

#pragma once

#include <aidl/android/hardware/media/c2/BnGraphicBufferAllocator.h>

#include <android-base/unique_fd.h>
#include <gui/IGraphicBufferProducer.h>

#include <memory>

#include <C2Buffer.h>

namespace aidl::android::hardware::media::c2::implementation {

// forward declarations
class GraphicsTracker;

struct GraphicBufferAllocator : public BnGraphicBufferAllocator {
public:
    // HAL interfaces
    ::ndk::ScopedAStatus allocate(const IGraphicBufferAllocator::Description& in_desc,
                                  IGraphicBufferAllocator::Allocation* _aidl_return) override;

    ::ndk::ScopedAStatus deallocate(int64_t in_id, bool* _aidl_return) override;

    ::ndk::ScopedAStatus getWaitableFd(
            ::ndk::ScopedFileDescriptor* _aidl_return) override;

    /**
     * Configuring Surface/BufferQueue for the interface.
     *
     * Configure Surface, generation # and max dequeueBuffer() count for
     * allocate interface.
     *
     * @param   igbp              Surface where to allocate.
     * @param   generation        Generation # for allocations.
     * @param   maxDequeueBufferCount
     *                            Maximum # of pending allocations.
     */
    bool configure(const ::android::sp<::android::IGraphicBufferProducer>& igbp,
                   uint32_t generation,
                   int maxDequeueBufferCount);

    /**
     * Update max dequeue buffer count of BufferQueue.
     *
     * BufferQueue does not update this value if count is smaller
     * than the currently dequeued count.
     * TODO: better to update the value inside this interface.
     * for return value inspection from BQ, also for delayed updates.
     *
     * @param   count             the new value to update
     */
    void updateMaxDequeueBufferCount(int count);

    void reset();

    /**
     * Create a listener for buffer being released.
     *
     * Surface will register this listener and notify whenever the consumer
     * releases a buffer.
     *
     * @param   generation        generation # for the BufferQueue.
     * @return  IProducerListener can be used when connect# to Surface.
     */
    const ::android::sp<::android::IProducerListener> createReleaseListener(
            uint32_t generation);

    /**
     * Notifies a buffer being released.
     *
     * @param   generation        generation # for the BufferQueue.
     */
    void onBufferReleased(uint32_t generation);

    /**
     * Allocates a buffer.
     *
     * @param   width             width of the requested buffer.
     * @param   height            height of the requested buffer.
     * @param   format            format of the requested buffer.
     * @param   usage             usage of the requested buffer.
     * @param   buf               out param for created buffer.
     * @param   fence             out param for a pending fence.
     *
     * @return  OK                When an allocation was created.
     *          C2_BAD_STATE      Client is not in the state for allocating
     *          C2_BLOCKING       operation is blocked. Waitable fds can be
     *                            used to know when it unblocks.
     *          C2_CORRUPTED      Failed with a serious reason.
     */
    c2_status_t allocate(uint32_t width, uint32_t height,
                         ::android::PixelFormat format, uint64_t usage,
                         AHardwareBuffer **buf, ::android::sp<::android::Fence> *fence);

    /**
     * De-allocate a buffer.
     *
     * @param   id                unique id for a buffer.
     * @param   fence             write fence if it's deallocated due to
     *                            cancellation of displaying
     */
    bool deallocate(const uint64_t id, const ::android::sp<::android::Fence> &fence);

    /**
     * Display a graphic buffer to BufferQueue.
     *
     * @param   block             block to display to Surface.
     * @param   input             input parameter for displaying.
     * @param   output            out parameter from Surface.
     */
    c2_status_t displayBuffer(
            const C2ConstGraphicBlock& block,
            const ::android::IGraphicBufferProducer::QueueBufferInput& input,
            ::android::IGraphicBufferProducer::QueueBufferOutput *output);

    ~GraphicBufferAllocator();

    /**
     * Create the interface.
     *
     * The interface and codec instance's relationship is 1 to 1.
     * The interface will be cretaed in the beginning of Codec createion. And
     * lives until the instance destroyed.
     *
     * @param   maxDequeueCount   Initial max allocatable count
     */
    static std::shared_ptr<GraphicBufferAllocator> CreateGraphicBufferAllocator(
            int maxDequeueCount);
private:
    GraphicBufferAllocator(int maxDequeueCount);

    std::shared_ptr<GraphicsTracker> mGraphicsTracker;

    friend class ::ndk::SharedRefBase;
};

} // namespace aidl::android::hardware::media::c2::implementation
