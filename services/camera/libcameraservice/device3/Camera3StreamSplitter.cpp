/*
 * Copyright 2014,2016 The Android Open Source Project
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

#include <inttypes.h>

#define LOG_TAG "Camera3StreamSplitter"
#define ATRACE_TAG ATRACE_TAG_CAMERA
//#define LOG_NDEBUG 0

#include <gui/BufferItem.h>
#include <gui/IGraphicBufferConsumer.h>
#include <gui/IGraphicBufferProducer.h>
#include <gui/BufferQueue.h>
#include <gui/Surface.h>

#include <ui/GraphicBuffer.h>

#include <binder/ProcessState.h>

#include <utils/Trace.h>

#include "Camera3StreamSplitter.h"

namespace android {

status_t Camera3StreamSplitter::connect(const std::vector<sp<Surface> >& surfaces,
                                           uint32_t consumerUsage, size_t hal_max_buffers,
                                           sp<Surface>& consumer) {
    if (consumer != nullptr) {
        ALOGE("%s: output Surface is not NULL", __FUNCTION__);
        return BAD_VALUE;
    }

    Mutex::Autolock lock(mMutex);
    status_t res = OK;

    if (mOutputs.size() > 0 || mConsumer != nullptr) {
        ALOGE("%s: StreamSplitter already connected", __FUNCTION__);
        return BAD_VALUE;
    }

    // Add output surfaces. This has to be before creating internal buffer queue
    // in order to get max consumer side buffers.
    for (size_t i = 0; i < surfaces.size(); i++) {
        if (surfaces[i] == nullptr) {
            ALOGE("%s: Fatal: surface is NULL", __FUNCTION__);
            return BAD_VALUE;
        }
        res = addOutputLocked(surfaces[i], hal_max_buffers, OutputType::NonDeferred);
        if (res != OK) {
            ALOGE("%s: Failed to add output surface: %s(%d)",
                    __FUNCTION__, strerror(-res), res);
            return res;
        }
    }

    // Create buffer queue for input
    BufferQueue::createBufferQueue(&mProducer, &mConsumer);

    mBufferItemConsumer = new BufferItemConsumer(mConsumer, consumerUsage,
                                                 mMaxConsumerBuffers);
    if (mBufferItemConsumer == nullptr) {
        return NO_MEMORY;
    }
    mConsumer->setConsumerName(getUniqueConsumerName());

    mSurface = new Surface(mProducer);
    if (mSurface == nullptr) {
        return NO_MEMORY;
    }
    consumer = mSurface;

    res = mConsumer->consumerConnect(this, /* controlledByApp */ false);

    return res;
}

void Camera3StreamSplitter::disconnect() {
    Mutex::Autolock lock(mMutex);

    for (auto& output : mOutputs) {
        output->disconnect(NATIVE_WINDOW_API_CAMERA);
    }
    mOutputs.clear();

    if (mConsumer != nullptr) {
        mConsumer->consumerDisconnect();
        mConsumer.clear();
    }

    if (mBuffers.size() > 0) {
        ALOGI("%zu buffers still being tracked", mBuffers.size());
    }
}

Camera3StreamSplitter::~Camera3StreamSplitter() {
    disconnect();
}

status_t Camera3StreamSplitter::addOutput(
        const sp<Surface>& outputQueue, size_t hal_max_buffers) {
    Mutex::Autolock lock(mMutex);
    return addOutputLocked(outputQueue, hal_max_buffers, OutputType::Deferred);
}

status_t Camera3StreamSplitter::addOutputLocked(
        const sp<Surface>& outputQueue, size_t hal_max_buffers,
        OutputType outputType) {
    if (outputQueue == nullptr) {
        ALOGE("addOutput: outputQueue must not be NULL");
        return BAD_VALUE;
    }
    if (hal_max_buffers < 1) {
        ALOGE("%s: Camera HAL requested max_buffer count: %zu, requires at least 1",
                __FUNCTION__, hal_max_buffers);
        return BAD_VALUE;
    }

    sp<IGraphicBufferProducer> gbp = outputQueue->getIGraphicBufferProducer();
    // Connect to the buffer producer
    IGraphicBufferProducer::QueueBufferOutput queueBufferOutput;
    sp<OutputListener> listener(new OutputListener(this, gbp));
    IInterface::asBinder(gbp)->linkToDeath(listener);
    status_t status = gbp->connect(listener, NATIVE_WINDOW_API_CAMERA,
            /* producerControlledByApp */ true, &queueBufferOutput);
    if (status != NO_ERROR) {
        ALOGE("addOutput: failed to connect (%d)", status);
       return status;
    }

    // Query consumer side buffer count, and update overall buffer count
    int maxConsumerBuffers = 0;
    status = static_cast<ANativeWindow*>(outputQueue.get())->query(
            outputQueue.get(),
            NATIVE_WINDOW_MIN_UNDEQUEUED_BUFFERS, &maxConsumerBuffers);
    if (status != OK) {
        ALOGE("%s: Unable to query consumer undequeued buffer count"
              " for surface", __FUNCTION__);
        return status;
    }

    if (maxConsumerBuffers > mMaxConsumerBuffers) {
        if (outputType == OutputType::Deferred) {
            ALOGE("%s: Fatal: Deferred surface has higher consumer buffer count"
                  " %d than what's already configured %d", __FUNCTION__,
                  maxConsumerBuffers, mMaxConsumerBuffers);
            return BAD_VALUE;
        }
        mMaxConsumerBuffers = maxConsumerBuffers;
    }

    ALOGV("%s: Consumer wants %d buffers, HAL wants %zu", __FUNCTION__,
            maxConsumerBuffers, hal_max_buffers);
    size_t totalBufferCount = maxConsumerBuffers + hal_max_buffers;
    status = native_window_set_buffer_count(outputQueue.get(),
            totalBufferCount);
    if (status != OK) {
        ALOGE("%s: Unable to set buffer count for surface %p",
                __FUNCTION__, outputQueue.get());
        return status;
    }

    // Set dequeueBuffer/attachBuffer timeout if the consumer is not hw composer or hw texture.
    // We need skip these cases as timeout will disable the non-blocking (async) mode.
    int32_t usage = 0;
    static_cast<ANativeWindow*>(outputQueue.get())->query(
            outputQueue.get(),
            NATIVE_WINDOW_CONSUMER_USAGE_BITS, &usage);
    if (!(usage & (GRALLOC_USAGE_HW_COMPOSER | GRALLOC_USAGE_HW_TEXTURE))) {
        outputQueue->setDequeueTimeout(kDequeueBufferTimeout);
    }

    status = gbp->allowAllocation(false);
    if (status != OK) {
        ALOGE("%s: Failed to turn off allocation for outputQueue", __FUNCTION__);
        return status;
    }

    // Add new entry into mOutputs
    mOutputs.push_back(gbp);
    return NO_ERROR;
}

String8 Camera3StreamSplitter::getUniqueConsumerName() {
    static volatile int32_t counter = 0;
    return String8::format("Camera3StreamSplitter-%d", android_atomic_inc(&counter));
}

status_t Camera3StreamSplitter::notifyRequestedSurfaces(
        const std::vector<size_t>& surfaces) {
    ATRACE_CALL();
    Mutex::Autolock lock(mMutex);

    mRequestedSurfaces.push_back(surfaces);
    return OK;
}


void Camera3StreamSplitter::onFrameAvailable(const BufferItem& /* item */) {
    ATRACE_CALL();
    Mutex::Autolock lock(mMutex);

    // The current policy is that if any one consumer is consuming buffers too
    // slowly, the splitter will stall the rest of the outputs by not acquiring
    // any more buffers from the input. This will cause back pressure on the
    // input queue, slowing down its producer.

    // If there are too many outstanding buffers, we block until a buffer is
    // released back to the input in onBufferReleased
    while (mOutstandingBuffers >= mMaxConsumerBuffers) {
        mReleaseCondition.wait(mMutex);

        // If the splitter is abandoned while we are waiting, the release
        // condition variable will be broadcast, and we should just return
        // without attempting to do anything more (since the input queue will
        // also be abandoned).
        if (mIsAbandoned) {
            return;
        }
    }
    // If the splitter is abandoned without reaching mMaxConsumerBuffers, just
    // return without attempting to do anything more.
    if (mIsAbandoned) {
        return;
    }

    ++mOutstandingBuffers;

    // Acquire and detach the buffer from the input
    BufferItem bufferItem;
    status_t status = mConsumer->acquireBuffer(&bufferItem, /* presentWhen */ 0);
    LOG_ALWAYS_FATAL_IF(status != NO_ERROR,
            "acquiring buffer from input failed (%d)", status);

    ALOGV("acquired buffer %#" PRIx64 " from input",
            bufferItem.mGraphicBuffer->getId());

    status = mConsumer->detachBuffer(bufferItem.mSlot);
    LOG_ALWAYS_FATAL_IF(status != NO_ERROR,
            "detaching buffer from input failed (%d)", status);

    IGraphicBufferProducer::QueueBufferInput queueInput(
            bufferItem.mTimestamp, bufferItem.mIsAutoTimestamp,
            bufferItem.mDataSpace, bufferItem.mCrop,
            static_cast<int32_t>(bufferItem.mScalingMode),
            bufferItem.mTransform, bufferItem.mFence);

    // Attach and queue the buffer to each of the outputs
    std::vector<std::vector<size_t> >::iterator surfaces = mRequestedSurfaces.begin();
    if (surfaces != mRequestedSurfaces.end()) {

        LOG_ALWAYS_FATAL_IF(surfaces->size() == 0,
                "requested surface ids shouldn't be empty");

        // Initialize our reference count for this buffer
        mBuffers[bufferItem.mGraphicBuffer->getId()] =
                std::unique_ptr<BufferTracker>(
                new BufferTracker(bufferItem.mGraphicBuffer, surfaces->size()));

        for (auto id : *surfaces) {

            LOG_ALWAYS_FATAL_IF(id >= mOutputs.size(),
                    "requested surface id exceeding max registered ids");

            int slot = BufferItem::INVALID_BUFFER_SLOT;
            status = mOutputs[id]->attachBuffer(&slot, bufferItem.mGraphicBuffer);
            if (status == NO_INIT) {
                // If we just discovered that this output has been abandoned, note
                // that, decrement the reference count so that we still release this
                // buffer eventually, and move on to the next output
                onAbandonedLocked();
                mBuffers[bufferItem.mGraphicBuffer->getId()]->
                        decrementReferenceCountLocked();
                continue;
            } else if (status == WOULD_BLOCK) {
                // If the output is async, attachBuffer may return WOULD_BLOCK
                // indicating number of dequeued buffers has reached limit. In
                // this case, simply decrement the reference count, and move on
                // to the next output.
                // TODO: Do we need to report BUFFER_ERROR for this result?
                mBuffers[bufferItem.mGraphicBuffer->getId()]->
                        decrementReferenceCountLocked();
                continue;
            } else if (status == TIMED_OUT) {
                // If attachBuffer times out due to the value set by
                // setDequeueTimeout, simply decrement the reference count, and
                // move on to the next output.
                // TODO: Do we need to report BUFFER_ERROR for this result?
                mBuffers[bufferItem.mGraphicBuffer->getId()]->
                        decrementReferenceCountLocked();
                continue;
            } else {
                LOG_ALWAYS_FATAL_IF(status != NO_ERROR,
                        "attaching buffer to output failed (%d)", status);
            }

            IGraphicBufferProducer::QueueBufferOutput queueOutput;
            status = mOutputs[id]->queueBuffer(slot, queueInput, &queueOutput);
            if (status == NO_INIT) {
                // If we just discovered that this output has been abandoned, note
                // that, increment the release count so that we still release this
                // buffer eventually, and move on to the next output
                onAbandonedLocked();
                mBuffers[bufferItem.mGraphicBuffer->getId()]->
                        decrementReferenceCountLocked();
                continue;
            } else {
                LOG_ALWAYS_FATAL_IF(status != NO_ERROR,
                        "queueing buffer to output failed (%d)", status);
            }

            // If the queued buffer replaces a pending buffer in the async
            // queue, no onBufferReleased is called by the buffer queue.
            // Proactively trigger the callback to avoid buffer loss.
            if (queueOutput.bufferReplaced) {
                onBufferReleasedByOutputLocked(mOutputs[id]);
            }

            ALOGV("queued buffer %#" PRIx64 " to output %p",
                    bufferItem.mGraphicBuffer->getId(), mOutputs[id].get());
        }

        mRequestedSurfaces.erase(surfaces);
    }
}

void Camera3StreamSplitter::onBufferReleasedByOutput(
        const sp<IGraphicBufferProducer>& from) {
    ATRACE_CALL();
    Mutex::Autolock lock(mMutex);

    onBufferReleasedByOutputLocked(from);
}

void Camera3StreamSplitter::onBufferReleasedByOutputLocked(
        const sp<IGraphicBufferProducer>& from) {

    sp<GraphicBuffer> buffer;
    sp<Fence> fence;
    status_t status = from->detachNextBuffer(&buffer, &fence);
    if (status == NO_INIT) {
        // If we just discovered that this output has been abandoned, note that,
        // but we can't do anything else, since buffer is invalid
        onAbandonedLocked();
        return;
    } else {
        LOG_ALWAYS_FATAL_IF(status != NO_ERROR,
                "detaching buffer from output failed (%d)", status);
    }

    ALOGV("detached buffer %#" PRIx64 " from output %p",
          buffer->getId(), from.get());

    BufferTracker& tracker = *(mBuffers[buffer->getId()]);

    // Merge the release fence of the incoming buffer so that the fence we send
    // back to the input includes all of the outputs' fences
    tracker.mergeFence(fence);

    // Check to see if this is the last outstanding reference to this buffer
    size_t referenceCount = tracker.decrementReferenceCountLocked();
    ALOGV("buffer %#" PRIx64 " reference count %zu", buffer->getId(),
            referenceCount);
    if (referenceCount > 0) {
        return;
    }

    // If we've been abandoned, we can't return the buffer to the input, so just
    // stop tracking it and move on
    if (mIsAbandoned) {
        mBuffers.erase(buffer->getId());
        return;
    }

    // Attach and release the buffer back to the input
    int consumerSlot = BufferItem::INVALID_BUFFER_SLOT;
    status = mConsumer->attachBuffer(&consumerSlot, tracker.getBuffer());
    LOG_ALWAYS_FATAL_IF(status != NO_ERROR,
            "attaching buffer to input failed (%d)", status);

    status = mConsumer->releaseBuffer(consumerSlot, /* frameNumber */ 0,
            EGL_NO_DISPLAY, EGL_NO_SYNC_KHR, tracker.getMergedFence());
    LOG_ALWAYS_FATAL_IF(status != NO_ERROR,
            "releasing buffer to input failed (%d)", status);

    ALOGV("released buffer %#" PRIx64 " to input", buffer->getId());

    // We no longer need to track the buffer once it has been returned to the
    // input
    mBuffers.erase(buffer->getId());

    // Notify any waiting onFrameAvailable calls
    --mOutstandingBuffers;
    mReleaseCondition.signal();
}

void Camera3StreamSplitter::onAbandonedLocked() {
    ALOGE("one of my outputs has abandoned me");
    if (!mIsAbandoned && mConsumer != nullptr) {
        mConsumer->consumerDisconnect();
    }
    mIsAbandoned = true;
    mReleaseCondition.broadcast();
}

Camera3StreamSplitter::OutputListener::OutputListener(
        wp<Camera3StreamSplitter> splitter,
        wp<IGraphicBufferProducer> output)
      : mSplitter(splitter), mOutput(output) {}

void Camera3StreamSplitter::OutputListener::onBufferReleased() {
    sp<Camera3StreamSplitter> splitter = mSplitter.promote();
    sp<IGraphicBufferProducer> output = mOutput.promote();
    if (splitter != nullptr && output != nullptr) {
        splitter->onBufferReleasedByOutput(output);
    }
}

void Camera3StreamSplitter::OutputListener::binderDied(const wp<IBinder>& /* who */) {
    sp<Camera3StreamSplitter> splitter = mSplitter.promote();
    if (splitter != nullptr) {
        Mutex::Autolock lock(splitter->mMutex);
        splitter->onAbandonedLocked();
    }
}

Camera3StreamSplitter::BufferTracker::BufferTracker(
        const sp<GraphicBuffer>& buffer, size_t referenceCount)
      : mBuffer(buffer), mMergedFence(Fence::NO_FENCE),
        mReferenceCount(referenceCount) {}

void Camera3StreamSplitter::BufferTracker::mergeFence(const sp<Fence>& with) {
    mMergedFence = Fence::merge(String8("Camera3StreamSplitter"), mMergedFence, with);
}

size_t Camera3StreamSplitter::BufferTracker::decrementReferenceCountLocked() {
    if (mReferenceCount > 0)
        --mReferenceCount;
    return mReferenceCount;
}

} // namespace android
