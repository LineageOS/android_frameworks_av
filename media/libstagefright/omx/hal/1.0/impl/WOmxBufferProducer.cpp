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

#include "WOmxBufferProducer.h"
#include "WOmxProducerListener.h"

namespace android {
namespace hardware {
namespace media {
namespace omx {
namespace V1_0 {
namespace implementation {

// TWOmxBufferProducer
TWOmxBufferProducer::TWOmxBufferProducer(
        sp<IGraphicBufferProducer> const& base):
    mBase(base) {
}

Return<void> TWOmxBufferProducer::requestBuffer(
        int32_t slot, requestBuffer_cb _hidl_cb) {
    sp<GraphicBuffer> buf;
    status_t status = mBase->requestBuffer(slot, &buf);
    AnwBuffer anwBuffer;
    wrapAs(&anwBuffer, *buf);
    _hidl_cb(toStatus(status), anwBuffer);
    return Void();
}

Return<Status> TWOmxBufferProducer::setMaxDequeuedBufferCount(
        int32_t maxDequeuedBuffers) {
    return toStatus(mBase->setMaxDequeuedBufferCount(
            static_cast<int>(maxDequeuedBuffers)));
}

Return<Status> TWOmxBufferProducer::setAsyncMode(bool async) {
    return toStatus(mBase->setAsyncMode(async));
}

Return<void> TWOmxBufferProducer::dequeueBuffer(
        uint32_t width, uint32_t height,
        PixelFormat format, uint32_t usage,
        bool getFrameTimestamps, dequeueBuffer_cb _hidl_cb) {
    int slot;
    sp<Fence> fence;
    ::android::FrameEventHistoryDelta outTimestamps;
    status_t status = mBase->dequeueBuffer(
            &slot, &fence,
            width, height,
            static_cast<::android::PixelFormat>(format), usage,
            getFrameTimestamps ? &outTimestamps : nullptr);

    hidl_handle tFence;
    native_handle_t* nh;
    if (!wrapAs(&tFence, &nh, *fence)) {
        return ::android::hardware::Status::fromExceptionCode(
                ::android::hardware::Status::EX_BAD_PARCELABLE,
                String8("TWOmxBufferProducer::dequeueBuffer(): "
                "Cannot wrap Fence in hidl_handle"));
    }
    FrameEventHistoryDelta tOutTimestamps;
    std::vector<std::vector<native_handle_t*> > nhAA;
    if (getFrameTimestamps && !wrapAs(&tOutTimestamps, &nhAA, outTimestamps)) {
        native_handle_delete(nh);
        return ::android::hardware::Status::fromExceptionCode(
                ::android::hardware::Status::EX_BAD_PARCELABLE,
                String8("TWOmxBufferProducer::dequeueBuffer(): "
                "Cannot wrap Fence in hidl_handle"));
    }

    _hidl_cb(toStatus(status),
            static_cast<int32_t>(slot),
            tFence,
            tOutTimestamps);
    native_handle_delete(nh);
    if (getFrameTimestamps) {
        for (auto& nhA : nhAA) {
            for (auto& handle : nhA) {
                if (handle != nullptr) {
                    native_handle_delete(handle);
                }
            }
        }
    }
    return Void();
}

Return<Status> TWOmxBufferProducer::detachBuffer(int32_t slot) {
    return toStatus(mBase->detachBuffer(slot));
}

Return<void> TWOmxBufferProducer::detachNextBuffer(
        detachNextBuffer_cb _hidl_cb) {
    sp<GraphicBuffer> outBuffer;
    sp<Fence> outFence;
    status_t status = mBase->detachNextBuffer(&outBuffer, &outFence);

    AnwBuffer tBuffer;
    wrapAs(&tBuffer, *outBuffer);
    hidl_handle tFence;
    native_handle_t* nh;
    if (!wrapAs(&tFence, &nh, *outFence)) {
        return ::android::hardware::Status::fromExceptionCode(
                ::android::hardware::Status::EX_BAD_PARCELABLE,
                String8("TWOmxBufferProducer::detachNextBuffer(): "
                "Cannot wrap Fence in hidl_handle"));
    }

    _hidl_cb(toStatus(status), tBuffer, tFence);
    native_handle_delete(nh);
    return Void();
}

Return<void> TWOmxBufferProducer::attachBuffer(
        const AnwBuffer& buffer,
        attachBuffer_cb _hidl_cb) {
    int outSlot;
    sp<GraphicBuffer> lBuffer = new GraphicBuffer();
    if (!convertTo(lBuffer.get(), buffer)) {
        return ::android::hardware::Status::fromExceptionCode(
                ::android::hardware::Status::EX_BAD_PARCELABLE,
                String8("TWOmxBufferProducer::attachBuffer(): "
                "Cannot convert AnwBuffer to GraphicBuffer"));
    }
    status_t status = mBase->attachBuffer(&outSlot, lBuffer);

    _hidl_cb(toStatus(status), static_cast<int32_t>(outSlot));
    return Void();
}

Return<void> TWOmxBufferProducer::queueBuffer(
        int32_t slot, const QueueBufferInput& input,
        queueBuffer_cb _hidl_cb) {
    IGraphicBufferProducer::QueueBufferInput lInput(
            0, false, HAL_DATASPACE_UNKNOWN,
            ::android::Rect(0, 0, 1, 1),
            NATIVE_WINDOW_SCALING_MODE_FREEZE,
            0, ::android::Fence::NO_FENCE);
    if (!convertTo(&lInput, input)) {
        return ::android::hardware::Status::fromExceptionCode(
                ::android::hardware::Status::EX_BAD_PARCELABLE,
                String8("TWOmxBufferProducer::queueBuffer(): "
                "Cannot convert IOmxBufferProducer::QueueBufferInput "
                "to IGraphicBufferProducer::QueueBufferInput"));
    }
    IGraphicBufferProducer::QueueBufferOutput lOutput;
    status_t status = mBase->queueBuffer(
            static_cast<int>(slot), lInput, &lOutput);

    QueueBufferOutput tOutput;
    std::vector<std::vector<native_handle_t*> > nhAA;
    if (!wrapAs(&tOutput, &nhAA, lOutput)) {
        return ::android::hardware::Status::fromExceptionCode(
                ::android::hardware::Status::EX_BAD_PARCELABLE,
                String8("TWOmxBufferProducer::queueBuffer(): "
                "Cannot wrap IGraphicBufferProducer::QueueBufferOutput "
                "in IOmxBufferProducer::QueueBufferOutput"));
    }

    _hidl_cb(toStatus(status), tOutput);
    for (auto& nhA : nhAA) {
        for (auto& nh : nhA) {
            if (nh != nullptr) {
                native_handle_delete(nh);
            }
        }
    }
    return Void();
}

Return<Status> TWOmxBufferProducer::cancelBuffer(
        int32_t slot, const hidl_handle& fence) {
    sp<Fence> lFence = new Fence();
    if (!convertTo(lFence.get(), fence)) {
        return ::android::hardware::Status::fromExceptionCode(
                ::android::hardware::Status::EX_BAD_PARCELABLE,
                String8("TWOmxBufferProducer::cancelBuffer(): "
                "Cannot convert hidl_handle to Fence"));
    }
    return toStatus(mBase->cancelBuffer(static_cast<int>(slot), lFence));
}

Return<void> TWOmxBufferProducer::query(int32_t what, query_cb _hidl_cb) {
    int lValue;
    int lReturn = mBase->query(static_cast<int>(what), &lValue);
    _hidl_cb(static_cast<int32_t>(lReturn), static_cast<int32_t>(lValue));
    return Void();
}

Return<void> TWOmxBufferProducer::connect(
        const sp<IOmxProducerListener>& listener,
        int32_t api, bool producerControlledByApp, connect_cb _hidl_cb) {
    sp<IProducerListener> lListener = listener == nullptr ?
            nullptr : new LWOmxProducerListener(listener);
    IGraphicBufferProducer::QueueBufferOutput lOutput;
    status_t status = mBase->connect(lListener,
            static_cast<int>(api),
            producerControlledByApp,
            &lOutput);

    QueueBufferOutput tOutput;
    std::vector<std::vector<native_handle_t*> > nhAA;
    if (!wrapAs(&tOutput, &nhAA, lOutput)) {
        return ::android::hardware::Status::fromExceptionCode(
                ::android::hardware::Status::EX_BAD_PARCELABLE,
                String8("TWOmxBufferProducer::connect(): "
                "Cannot wrap IGraphicBufferProducer::QueueBufferOutput "
                "in IOmxBufferProducer::QueueBufferOutput"));
    }

    _hidl_cb(toStatus(status), tOutput);
    for (auto& nhA : nhAA) {
        for (auto& nh : nhA) {
            if (nh != nullptr) {
                native_handle_delete(nh);
            }
        }
    }
    return Void();
}

Return<Status> TWOmxBufferProducer::disconnect(
        int32_t api, DisconnectMode mode) {
    return toStatus(mBase->disconnect(
            static_cast<int>(api),
            toGuiDisconnectMode(mode)));
}

Return<Status> TWOmxBufferProducer::setSidebandStream(const hidl_handle& stream) {
    return toStatus(mBase->setSidebandStream(NativeHandle::create(
            native_handle_clone(stream), true)));
}

Return<void> TWOmxBufferProducer::allocateBuffers(
        uint32_t width, uint32_t height, PixelFormat format, uint32_t usage) {
    mBase->allocateBuffers(
            width, height,
            static_cast<::android::PixelFormat>(format),
            usage);
    return Void();
}

Return<Status> TWOmxBufferProducer::allowAllocation(bool allow) {
    return toStatus(mBase->allowAllocation(allow));
}

Return<Status> TWOmxBufferProducer::setGenerationNumber(uint32_t generationNumber) {
    return toStatus(mBase->setGenerationNumber(generationNumber));
}

Return<void> TWOmxBufferProducer::getConsumerName(getConsumerName_cb _hidl_cb) {
    _hidl_cb(mBase->getConsumerName().string());
    return Void();
}

Return<Status> TWOmxBufferProducer::setSharedBufferMode(bool sharedBufferMode) {
    return toStatus(mBase->setSharedBufferMode(sharedBufferMode));
}

Return<Status> TWOmxBufferProducer::setAutoRefresh(bool autoRefresh) {
    return toStatus(mBase->setAutoRefresh(autoRefresh));
}

Return<Status> TWOmxBufferProducer::setDequeueTimeout(int64_t timeoutNs) {
    return toStatus(mBase->setDequeueTimeout(timeoutNs));
}

Return<void> TWOmxBufferProducer::getLastQueuedBuffer(
        getLastQueuedBuffer_cb _hidl_cb) {
    sp<GraphicBuffer> lOutBuffer = new GraphicBuffer();
    sp<Fence> lOutFence = new Fence();
    float lOutTransformMatrix[16];
    status_t status = mBase->getLastQueuedBuffer(
            &lOutBuffer, &lOutFence, lOutTransformMatrix);

    AnwBuffer tOutBuffer;
    wrapAs(&tOutBuffer, *lOutBuffer);
    hidl_handle tOutFence;
    native_handle_t* nh;
    if (!wrapAs(&tOutFence, &nh, *lOutFence)) {
        return ::android::hardware::Status::fromExceptionCode(
                ::android::hardware::Status::EX_BAD_PARCELABLE,
                String8("TWOmxBufferProducer::getLastQueuedBuffer(): "
                "Cannot wrap Fence in hidl_handle"));
    }
    hidl_array<float, 16> tOutTransformMatrix(lOutTransformMatrix);

    _hidl_cb(toStatus(status), tOutBuffer, tOutFence, tOutTransformMatrix);
    native_handle_delete(nh);
    return Void();
}

Return<void> TWOmxBufferProducer::getFrameTimestamps(
        getFrameTimestamps_cb _hidl_cb) {
    ::android::FrameEventHistoryDelta lDelta;
    mBase->getFrameTimestamps(&lDelta);

    FrameEventHistoryDelta tDelta;
    std::vector<std::vector<native_handle_t*> > nhAA;
    if (!wrapAs(&tDelta, &nhAA, lDelta)) {
        return ::android::hardware::Status::fromExceptionCode(
                ::android::hardware::Status::EX_BAD_PARCELABLE,
                String8("TWOmxBufferProducer::getFrameTimestamps(): "
                "Cannot wrap ::android::FrameEventHistoryDelta "
                "in FrameEventHistoryDelta"));
    }

    _hidl_cb(tDelta);
    for (auto& nhA : nhAA) {
        for (auto& nh : nhA) {
            if (nh != nullptr) {
                native_handle_delete(nh);
            }
        }
    }
    return Void();
}

Return<void> TWOmxBufferProducer::getUniqueId(getUniqueId_cb _hidl_cb) {
    uint64_t outId;
    status_t status = mBase->getUniqueId(&outId);
    _hidl_cb(toStatus(status), outId);
    return Void();
}

// LWOmxBufferProducer

LWOmxBufferProducer::LWOmxBufferProducer(sp<IOmxBufferProducer> const& base) :
    mBase(base) {
}

status_t LWOmxBufferProducer::requestBuffer(int slot, sp<GraphicBuffer>* buf) {
    *buf = new GraphicBuffer();
    status_t fnStatus;
    status_t transStatus = toStatusT(mBase->requestBuffer(
            static_cast<int32_t>(slot),
            [&fnStatus, &buf] (Status status, AnwBuffer const& buffer) {
                fnStatus = toStatusT(status);
                if (!convertTo(buf->get(), buffer)) {
                    fnStatus = fnStatus == NO_ERROR ? BAD_VALUE : fnStatus;
                }
            }));
    return transStatus == NO_ERROR ? fnStatus : transStatus;
}

status_t LWOmxBufferProducer::setMaxDequeuedBufferCount(
        int maxDequeuedBuffers) {
    return toStatusT(mBase->setMaxDequeuedBufferCount(
            static_cast<int32_t>(maxDequeuedBuffers)));
}

status_t LWOmxBufferProducer::setAsyncMode(bool async) {
    return toStatusT(mBase->setAsyncMode(async));
}

status_t LWOmxBufferProducer::dequeueBuffer(
        int* slot, sp<Fence>* fence,
        uint32_t w, uint32_t h, ::android::PixelFormat format,
        uint32_t usage, FrameEventHistoryDelta* outTimestamps) {
    *fence = new Fence();
    status_t fnStatus;
    status_t transStatus = toStatusT(mBase->dequeueBuffer(
            w, h, static_cast<PixelFormat>(format), usage,
            outTimestamps != nullptr,
            [&fnStatus, slot, fence, outTimestamps] (
                    Status status,
                    int32_t tSlot,
                    hidl_handle const& tFence,
                    IOmxBufferProducer::FrameEventHistoryDelta const& tTs) {
                fnStatus = toStatusT(status);
                *slot = tSlot;
                if (!convertTo(fence->get(), tFence)) {
                    fnStatus = fnStatus == NO_ERROR ? BAD_VALUE : fnStatus;
                }
                if (outTimestamps && !convertTo(outTimestamps, tTs)) {
                    fnStatus = fnStatus == NO_ERROR ? BAD_VALUE : fnStatus;
                }
            }));
    return transStatus == NO_ERROR ? fnStatus : transStatus;
}

status_t LWOmxBufferProducer::detachBuffer(int slot) {
    return toStatusT(mBase->detachBuffer(static_cast<int>(slot)));
}

status_t LWOmxBufferProducer::detachNextBuffer(
        sp<GraphicBuffer>* outBuffer, sp<Fence>* outFence) {
    *outBuffer = new GraphicBuffer();
    *outFence = new Fence();
    status_t fnStatus;
    status_t transStatus = toStatusT(mBase->detachNextBuffer(
            [&fnStatus, outBuffer, outFence] (
                    Status status,
                    AnwBuffer const& tBuffer,
                    hidl_handle const& tFence) {
                fnStatus = toStatusT(status);
                if (!convertTo(outFence->get(), tFence)) {
                    fnStatus = fnStatus == NO_ERROR ? BAD_VALUE : fnStatus;
                }
                if (!convertTo(outBuffer->get(), tBuffer)) {
                    fnStatus = fnStatus == NO_ERROR ? BAD_VALUE : fnStatus;
                }
            }));
    return transStatus == NO_ERROR ? fnStatus : transStatus;
}

status_t LWOmxBufferProducer::attachBuffer(
        int* outSlot, const sp<GraphicBuffer>& buffer) {
    AnwBuffer tBuffer;
    wrapAs(&tBuffer, *buffer);
    status_t fnStatus;
    status_t transStatus = toStatusT(mBase->attachBuffer(tBuffer,
            [&fnStatus, outSlot] (Status status, int32_t slot) {
                fnStatus = toStatusT(status);
                *outSlot = slot;
            }));
    return transStatus == NO_ERROR ? fnStatus : transStatus;
}

status_t LWOmxBufferProducer::queueBuffer(
        int slot,
        const QueueBufferInput& input,
        QueueBufferOutput* output) {
    IOmxBufferProducer::QueueBufferInput tInput;
    native_handle_t* nh;
    if (!wrapAs(&tInput, &nh, input)) {
        return BAD_VALUE;
    }
    status_t fnStatus;
    status_t transStatus = toStatusT(mBase->queueBuffer(slot, tInput,
            [&fnStatus, output] (
                    Status status,
                    IOmxBufferProducer::QueueBufferOutput const& tOutput) {
                fnStatus = toStatusT(status);
                if (!convertTo(output, tOutput)) {
                    fnStatus = fnStatus == NO_ERROR ? BAD_VALUE : fnStatus;
                }
            }));
    native_handle_delete(nh);
    return transStatus == NO_ERROR ? fnStatus : transStatus;
}

status_t LWOmxBufferProducer::cancelBuffer(int slot, const sp<Fence>& fence) {
    hidl_handle tFence;
    native_handle_t* nh;
    if (!wrapAs(&tFence, &nh, *fence)) {
        return BAD_VALUE;
    }

    status_t status = toStatusT(mBase->cancelBuffer(
            static_cast<int32_t>(slot), tFence));
    native_handle_delete(nh);
    return status;
}

int LWOmxBufferProducer::query(int what, int* value) {
    int result;
    status_t transStatus = toStatusT(mBase->query(
            static_cast<int32_t>(what),
            [&result, value] (int32_t tResult, int32_t tValue) {
                result = static_cast<int>(tResult);
                *value = static_cast<int>(tValue);
            }));
    return transStatus == NO_ERROR ? result : static_cast<int>(transStatus);
}

status_t LWOmxBufferProducer::connect(
        const sp<IProducerListener>& listener, int api,
        bool producerControlledByApp, QueueBufferOutput* output) {
    sp<IOmxProducerListener> tListener = listener == nullptr ?
            nullptr : new TWOmxProducerListener(listener);
    status_t fnStatus;
    status_t transStatus = toStatusT(mBase->connect(
            tListener, static_cast<int32_t>(api), producerControlledByApp,
            [&fnStatus, output] (
                    Status status,
                    IOmxBufferProducer::QueueBufferOutput const& tOutput) {
                fnStatus = toStatusT(status);
                if (!convertTo(output, tOutput)) {
                    fnStatus = fnStatus == NO_ERROR ? BAD_VALUE : fnStatus;
                }
            }));
    return transStatus == NO_ERROR ? fnStatus : transStatus;
}

status_t LWOmxBufferProducer::disconnect(int api, DisconnectMode mode) {
    return toStatusT(mBase->disconnect(
            static_cast<int32_t>(api), toOmxDisconnectMode(mode)));
}

status_t LWOmxBufferProducer::setSidebandStream(
        const sp<NativeHandle>& stream) {
    return toStatusT(mBase->setSidebandStream(stream->handle()));
}

void LWOmxBufferProducer::allocateBuffers(uint32_t width, uint32_t height,
        ::android::PixelFormat format, uint32_t usage) {
    mBase->allocateBuffers(
            width, height, static_cast<PixelFormat>(format), usage);
}

status_t LWOmxBufferProducer::allowAllocation(bool allow) {
    return toStatusT(mBase->allowAllocation(allow));
}

status_t LWOmxBufferProducer::setGenerationNumber(uint32_t generationNumber) {
    return toStatusT(mBase->setGenerationNumber(generationNumber));
}

String8 LWOmxBufferProducer::getConsumerName() const {
    String8 lName;
    mBase->getConsumerName([&lName] (hidl_string const& name) {
                lName = name.c_str();
            });
    return lName;
}

status_t LWOmxBufferProducer::setSharedBufferMode(bool sharedBufferMode) {
    return toStatusT(mBase->setSharedBufferMode(sharedBufferMode));
}

status_t LWOmxBufferProducer::setAutoRefresh(bool autoRefresh) {
    return toStatusT(mBase->setAutoRefresh(autoRefresh));
}

status_t LWOmxBufferProducer::setDequeueTimeout(nsecs_t timeout) {
    return toStatusT(mBase->setDequeueTimeout(static_cast<int64_t>(timeout)));
}

status_t LWOmxBufferProducer::getLastQueuedBuffer(
        sp<GraphicBuffer>* outBuffer,
        sp<Fence>* outFence,
        float outTransformMatrix[16]) {
    status_t fnStatus;
    status_t transStatus = toStatusT(mBase->getLastQueuedBuffer(
            [&fnStatus, outBuffer, outFence, &outTransformMatrix] (
                    Status status,
                    AnwBuffer const& buffer,
                    hidl_handle const& fence,
                    hidl_array<float, 16> const& transformMatrix) {
                fnStatus = toStatusT(status);
                *outBuffer = new GraphicBuffer();
                if (!convertTo(outBuffer->get(), buffer)) {
                    fnStatus = fnStatus == NO_ERROR ? BAD_VALUE : fnStatus;
                }
                *outFence = new Fence();
                if (!convertTo(outFence->get(), fence)) {
                    fnStatus = fnStatus == NO_ERROR ? BAD_VALUE : fnStatus;
                }
                std::copy(transformMatrix.data(),
                        transformMatrix.data() + 16,
                        outTransformMatrix);
            }));
    return transStatus == NO_ERROR ? fnStatus : transStatus;
}

void LWOmxBufferProducer::getFrameTimestamps(FrameEventHistoryDelta* outDelta) {
    mBase->getFrameTimestamps([outDelta] (
            IOmxBufferProducer::FrameEventHistoryDelta const& tDelta) {
                convertTo(outDelta, tDelta);
            });
}

status_t LWOmxBufferProducer::getUniqueId(uint64_t* outId) const {
    status_t fnStatus;
    status_t transStatus = toStatusT(mBase->getUniqueId(
            [&fnStatus, outId] (Status status, uint64_t id) {
                fnStatus = toStatusT(status);
                *outId = id;
            }));
    return transStatus == NO_ERROR ? fnStatus : transStatus;
}

}  // namespace implementation
}  // namespace V1_0
}  // namespace omx
}  // namespace media
}  // namespace hardware
}  // namespace android
