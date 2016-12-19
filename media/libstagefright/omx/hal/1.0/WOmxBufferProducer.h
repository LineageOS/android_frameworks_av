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

#ifndef ANDROID_HARDWARE_MEDIA_OMX_V1_0_WOMXBUFFERPRODUCER_H
#define ANDROID_HARDWARE_MEDIA_OMX_V1_0_WOMXBUFFERPRODUCER_H

#include <android/hardware/media/omx/1.0/IOmxBufferProducer.h>
#include <binder/Binder.h>
#include <hidl/MQDescriptor.h>
#include <hidl/Status.h>
#include <gui/IGraphicBufferProducer.h>
#include <gui/IProducerListener.h>
#include "Conversion.h"

namespace android {
namespace hardware {
namespace media {
namespace omx {
namespace V1_0 {
namespace implementation {

using ::android::hardware::graphics::common::V1_0::PixelFormat;
using ::android::hardware::media::omx::V1_0::IOmxBufferProducer;
using ::android::hardware::media::omx::V1_0::IOmxProducerListener;
using ::android::hardware::media::omx::V1_0::Status;
using ::android::hardware::media::V1_0::AnwBuffer;
using ::android::hidl::base::V1_0::IBase;
using ::android::hardware::hidl_array;
using ::android::hardware::hidl_memory;
using ::android::hardware::hidl_string;
using ::android::hardware::hidl_vec;
using ::android::hardware::Return;
using ::android::hardware::Void;
using ::android::sp;

using ::android::IGraphicBufferProducer;
using ::android::IProducerListener;

struct TWOmxBufferProducer : public IOmxBufferProducer {
    sp<IGraphicBufferProducer> mBase;
    TWOmxBufferProducer(sp<IGraphicBufferProducer> const& base);
    Return<void> requestBuffer(int32_t slot, requestBuffer_cb _hidl_cb)
            override;
    Return<Status> setMaxDequeuedBufferCount(int32_t maxDequeuedBuffers)
            override;
    Return<Status> setAsyncMode(bool async) override;
    Return<void> dequeueBuffer(
            uint32_t width, uint32_t height, PixelFormat format, uint32_t usage,
            bool getFrameTimestamps, dequeueBuffer_cb _hidl_cb) override;
    Return<Status> detachBuffer(int32_t slot) override;
    Return<void> detachNextBuffer(detachNextBuffer_cb _hidl_cb) override;
    Return<void> attachBuffer(const AnwBuffer& buffer, attachBuffer_cb _hidl_cb)
            override;
    Return<void> queueBuffer(
            int32_t slot, const IOmxBufferProducer::QueueBufferInput& input,
            queueBuffer_cb _hidl_cb) override;
    Return<Status> cancelBuffer(int32_t slot, const hidl_handle& fence)
            override;
    Return<void> query(int32_t what, query_cb _hidl_cb) override;
    Return<void> connect(const sp<IOmxProducerListener>& listener,
            int32_t api, bool producerControlledByApp,
            connect_cb _hidl_cb) override;
    Return<Status> disconnect(
            int32_t api,
            IOmxBufferProducer::DisconnectMode mode) override;
    Return<Status> setSidebandStream(const hidl_handle& stream) override;
    Return<void> allocateBuffers(
            uint32_t width, uint32_t height,
            PixelFormat format, uint32_t usage) override;
    Return<Status> allowAllocation(bool allow) override;
    Return<Status> setGenerationNumber(uint32_t generationNumber) override;
    Return<void> getConsumerName(getConsumerName_cb _hidl_cb) override;
    Return<Status> setSharedBufferMode(bool sharedBufferMode) override;
    Return<Status> setAutoRefresh(bool autoRefresh) override;
    Return<Status> setDequeueTimeout(int64_t timeoutNs) override;
    Return<void> getLastQueuedBuffer(getLastQueuedBuffer_cb _hidl_cb) override;
    Return<void> getFrameTimestamps(getFrameTimestamps_cb _hidl_cb) override;
    Return<void> getUniqueId(getUniqueId_cb _hidl_cb) override;
};

struct LWOmxBufferProducer : public IGraphicBufferProducer {
    sp<IOmxBufferProducer> mBase;
    LWOmxBufferProducer(sp<IOmxBufferProducer> const& base);

    status_t requestBuffer(int slot, sp<GraphicBuffer>* buf) override;
    status_t setMaxDequeuedBufferCount(int maxDequeuedBuffers) override;
    status_t setAsyncMode(bool async) override;
    status_t dequeueBuffer(int* slot, sp<Fence>* fence, uint32_t w,
            uint32_t h, ::android::PixelFormat format, uint32_t usage,
            FrameEventHistoryDelta* outTimestamps) override;
    status_t detachBuffer(int slot) override;
    status_t detachNextBuffer(sp<GraphicBuffer>* outBuffer, sp<Fence>* outFence)
            override;
    status_t attachBuffer(int* outSlot, const sp<GraphicBuffer>& buffer)
            override;
    status_t queueBuffer(int slot,
            const QueueBufferInput& input,
            QueueBufferOutput* output) override;
    status_t cancelBuffer(int slot, const sp<Fence>& fence) override;
    int query(int what, int* value) override;
    status_t connect(const sp<IProducerListener>& listener, int api,
            bool producerControlledByApp, QueueBufferOutput* output) override;
    status_t disconnect(int api, DisconnectMode mode = DisconnectMode::Api)
            override;
    status_t setSidebandStream(const sp<NativeHandle>& stream) override;
    void allocateBuffers(uint32_t width, uint32_t height,
            ::android::PixelFormat format, uint32_t usage) override;
    status_t allowAllocation(bool allow) override;
    status_t setGenerationNumber(uint32_t generationNumber) override;
    String8 getConsumerName() const override;
    status_t setSharedBufferMode(bool sharedBufferMode) override;
    status_t setAutoRefresh(bool autoRefresh) override;
    status_t setDequeueTimeout(nsecs_t timeout) override;
    status_t getLastQueuedBuffer(sp<GraphicBuffer>* outBuffer,
          sp<Fence>* outFence, float outTransformMatrix[16]) override;
    void getFrameTimestamps(FrameEventHistoryDelta* outDelta) override;
    status_t getUniqueId(uint64_t* outId) const override;
protected:
    ::android::IBinder* onAsBinder() override;
};

}  // namespace implementation
}  // namespace V1_0
}  // namespace omx
}  // namespace media
}  // namespace hardware
}  // namespace android

#endif  // ANDROID_HARDWARE_MEDIA_OMX_V1_0_WOMXBUFFERPRODUCER_H
