/*
 * Copyright (C) 2018 The Android Open Source Project
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

#ifndef HARDWARE_GOOGLE_MEDIA_C2_V1_0_UTILS_INPUTSURFACE_H
#define HARDWARE_GOOGLE_MEDIA_C2_V1_0_UTILS_INPUTSURFACE_H

#include <codec2/hidl/1.0/ComponentStore.h>

#include <hardware/google/media/c2/1.0/IInputSurface.h>
#include <hardware/google/media/c2/1.0/IComponent.h>

#include <android/hardware/graphics/bufferqueue/1.0/IGraphicBufferProducer.h>
#include <android/hardware/graphics/bufferqueue/1.0/IProducerListener.h>
#include <android/hardware/graphics/common/1.0/types.h>
#include <android/hardware/media/1.0/types.h>

#include <gui/IGraphicBufferProducer.h>
#include <media/stagefright/bqhelper/GraphicBufferSource.h>

#include <hidl/HidlSupport.h>
#include <hidl/Status.h>

class C2ReflectorHelper;

namespace hardware {
namespace google {
namespace media {
namespace c2 {
namespace V1_0 {
namespace utils {

using ::android::hardware::hidl_handle;
using ::android::hardware::hidl_string;
using ::android::hardware::hidl_vec;
using ::android::hardware::Return;
using ::android::hardware::Void;
using ::android::sp;

using ::android::hardware::graphics::common::V1_0::PixelFormat;
using ::android::hardware::media::V1_0::AnwBuffer;

struct InputSurface : public IInputSurface {

    typedef ::android::hidl::base::V1_0::IBase IBase;

    typedef ::android::hardware::graphics::bufferqueue::V1_0::
            IProducerListener HProducerListener;

    typedef ::android::
            IGraphicBufferProducer BGraphicBufferProducer;

    typedef ::android::hardware::graphics::bufferqueue::V1_0::
            IGraphicBufferProducer HGraphicBufferProducer;

    typedef ::android::
            GraphicBufferSource GraphicBufferSource;

// Type disambiguation

    typedef ::hardware::google::media::c2::V1_0::Status Status;

// New methods from IInputSurface

    virtual Return<void> connectToComponent(
            const sp<IComponent>& component,
            connectToComponent_cb _hidl_cb) override;

    virtual Return<sp<IConfigurable>> getConfigurable() override;

// Methods derived from IGraphicBufferProducer

    virtual Return<void> requestBuffer(
            int32_t slot,
            requestBuffer_cb _hidl_cb) override;

    virtual Return<int32_t> setMaxDequeuedBufferCount(
            int32_t maxDequeuedBuffers) override;

    virtual Return<int32_t> setAsyncMode(
            bool async) override;

    virtual Return<void> dequeueBuffer(
            uint32_t width,
            uint32_t height,
            PixelFormat format,
            uint32_t usage,
            bool getFrameTimestamps,
            dequeueBuffer_cb _hidl_cb) override;

    virtual Return<int32_t> detachBuffer(
            int32_t slot) override;

    virtual Return<void> detachNextBuffer(
            detachNextBuffer_cb _hidl_cb) override;

    virtual Return<void> attachBuffer(
            const AnwBuffer& buffer,
            attachBuffer_cb _hidl_cb) override;

    virtual Return<void> queueBuffer(
            int32_t slot,
            const QueueBufferInput& input,
            queueBuffer_cb _hidl_cb) override;

    virtual Return<int32_t> cancelBuffer(
            int32_t slot,
            const hidl_handle& fence) override;

    virtual Return<void> query(
            int32_t what,
            query_cb _hidl_cb) override;

    virtual Return<void> connect(
            const sp<HProducerListener>& listener,
            int32_t api,
            bool producerControlledByApp,
            connect_cb _hidl_cb) override;

    virtual Return<int32_t> disconnect(
            int32_t api,
            DisconnectMode mode) override;

    virtual Return<int32_t> setSidebandStream(
            const hidl_handle& stream) override;

    virtual Return<void> allocateBuffers(
            uint32_t width,
            uint32_t height,
            PixelFormat format,
            uint32_t usage) override;

    virtual Return<int32_t> allowAllocation(
            bool allow) override;

    virtual Return<int32_t> setGenerationNumber(
            uint32_t generationNumber) override;

    virtual Return<void> getConsumerName(
            getConsumerName_cb _hidl_cb) override;

    virtual Return<int32_t> setSharedBufferMode(
            bool sharedBufferMode) override;

    virtual Return<int32_t> setAutoRefresh(
            bool autoRefresh) override;

    virtual Return<int32_t> setDequeueTimeout(
            int64_t timeoutNs) override;

    virtual Return<void> getLastQueuedBuffer(
            getLastQueuedBuffer_cb _hidl_cb) override;

    virtual Return<void> getFrameTimestamps(
            getFrameTimestamps_cb _hidl_cb) override;

    virtual Return<void> getUniqueId(
            getUniqueId_cb _hidl_cb) override;

    class ConfigurableImpl;

protected:
    sp<ComponentStore> mStore;
    sp<HGraphicBufferProducer> mBase;
    sp<GraphicBufferSource> mSource;
    std::shared_ptr<ConfigurableImpl> mHelper;
    sp<CachedConfigurable> mConfigurable;

    InputSurface(
            const sp<ComponentStore>& store,
            const std::shared_ptr<C2ReflectorHelper>& reflector,
            const sp<HGraphicBufferProducer>& base,
            const sp<GraphicBufferSource>& source);

    virtual ~InputSurface() override = default;

    friend struct ComponentStore;
};


}  // namespace utils
}  // namespace V1_0
}  // namespace c2
}  // namespace media
}  // namespace google
}  // namespace hardware

#endif  // HARDWARE_GOOGLE_MEDIA_C2_V1_0_UTILS_INPUTSURFACE_H
