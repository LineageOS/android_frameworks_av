/*
 * Copyright (C) 2013 The Android Open Source Project
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

#define LOG_TAG "GraphicBufferSource"
//#define LOG_NDEBUG 0
#include <utils/Log.h>

#define STRINGIFY_ENUMS // for asString in HardwareAPI.h/VideoAPI.h

#include "GraphicBufferSource.h"
#include <media/stagefright/foundation/ADebug.h>
#include <media/stagefright/foundation/AMessage.h>
#include <media/stagefright/foundation/ColorUtils.h>

#include <media/hardware/MetadataBufferType.h>
#include <ui/GraphicBuffer.h>
#include <gui/BufferItem.h>
#include <HardwareAPI.h>

#include <inttypes.h>
#include "FrameDropper.h"

namespace android {

GraphicBufferSource::PersistentProxyListener::PersistentProxyListener(
        const wp<IGraphicBufferConsumer> &consumer,
        const wp<ConsumerListener>& consumerListener) :
    mConsumerListener(consumerListener),
    mConsumer(consumer) {}

GraphicBufferSource::PersistentProxyListener::~PersistentProxyListener() {}

void GraphicBufferSource::PersistentProxyListener::onFrameAvailable(
        const BufferItem& item) {
    sp<ConsumerListener> listener(mConsumerListener.promote());
    if (listener != NULL) {
        listener->onFrameAvailable(item);
    } else {
        sp<IGraphicBufferConsumer> consumer(mConsumer.promote());
        if (consumer == NULL) {
            return;
        }
        BufferItem bi;
        status_t err = consumer->acquireBuffer(&bi, 0);
        if (err != OK) {
            ALOGE("PersistentProxyListener: acquireBuffer failed (%d)", err);
            return;
        }

        err = consumer->detachBuffer(bi.mSlot);
        if (err != OK) {
            ALOGE("PersistentProxyListener: detachBuffer failed (%d)", err);
            return;
        }

        err = consumer->attachBuffer(&bi.mSlot, bi.mGraphicBuffer);
        if (err != OK) {
            ALOGE("PersistentProxyListener: attachBuffer failed (%d)", err);
            return;
        }

        err = consumer->releaseBuffer(bi.mSlot, 0,
                EGL_NO_DISPLAY, EGL_NO_SYNC_KHR, bi.mFence);
        if (err != OK) {
            ALOGE("PersistentProxyListener: releaseBuffer failed (%d)", err);
        }
    }
}

void GraphicBufferSource::PersistentProxyListener::onFrameReplaced(
        const BufferItem& item) {
    sp<ConsumerListener> listener(mConsumerListener.promote());
    if (listener != NULL) {
        listener->onFrameReplaced(item);
    }
}

void GraphicBufferSource::PersistentProxyListener::onBuffersReleased() {
    sp<ConsumerListener> listener(mConsumerListener.promote());
    if (listener != NULL) {
        listener->onBuffersReleased();
    }
}

void GraphicBufferSource::PersistentProxyListener::onSidebandStreamChanged() {
    sp<ConsumerListener> listener(mConsumerListener.promote());
    if (listener != NULL) {
        listener->onSidebandStreamChanged();
    }
}

GraphicBufferSource::GraphicBufferSource(
        const sp<IOMXNode> &omxNode,
        uint32_t bufferWidth,
        uint32_t bufferHeight,
        uint32_t bufferCount,
        uint32_t consumerUsage,
        const sp<IGraphicBufferConsumer> &consumer) :
    mInitCheck(UNKNOWN_ERROR),
    mOMXNode(omxNode),
    mExecuting(false),
    mSuspended(false),
    mLastDataSpace(HAL_DATASPACE_UNKNOWN),
    mIsPersistent(false),
    mConsumer(consumer),
    mNumFramesAvailable(0),
    mNumBufferAcquired(0),
    mEndOfStream(false),
    mEndOfStreamSent(false),
    mMaxTimestampGapUs(-1ll),
    mPrevOriginalTimeUs(-1ll),
    mPrevModifiedTimeUs(-1ll),
    mSkipFramesBeforeNs(-1ll),
    mRepeatAfterUs(-1ll),
    mRepeatLastFrameGeneration(0),
    mRepeatLastFrameTimestamp(-1ll),
    mLatestBufferId(-1),
    mLatestBufferFrameNum(0),
    mLatestBufferFence(Fence::NO_FENCE),
    mRepeatBufferDeferred(false),
    mTimePerCaptureUs(-1ll),
    mTimePerFrameUs(-1ll),
    mPrevCaptureUs(-1ll),
    mPrevFrameUs(-1ll),
    mInputBufferTimeOffsetUs(0ll) {

    ALOGV("GraphicBufferSource w=%u h=%u c=%u",
            bufferWidth, bufferHeight, bufferCount);

    if (bufferWidth == 0 || bufferHeight == 0) {
        ALOGE("Invalid dimensions %ux%u", bufferWidth, bufferHeight);
        mInitCheck = BAD_VALUE;
        return;
    }

    if (mConsumer == NULL) {
        String8 name("GraphicBufferSource");

        BufferQueue::createBufferQueue(&mProducer, &mConsumer);
        mConsumer->setConsumerName(name);

        // use consumer usage bits queried from encoder, but always add HW_VIDEO_ENCODER
        // for backward compatibility.
        consumerUsage |= GRALLOC_USAGE_HW_VIDEO_ENCODER;
        mConsumer->setConsumerUsageBits(consumerUsage);

        mInitCheck = mConsumer->setMaxAcquiredBufferCount(bufferCount);
        if (mInitCheck != NO_ERROR) {
            ALOGE("Unable to set BQ max acquired buffer count to %u: %d",
                    bufferCount, mInitCheck);
            return;
        }
    } else {
        mIsPersistent = true;
    }
    mConsumer->setDefaultBufferSize(bufferWidth, bufferHeight);
    // Note that we can't create an sp<...>(this) in a ctor that will not keep a
    // reference once the ctor ends, as that would cause the refcount of 'this'
    // dropping to 0 at the end of the ctor.  Since all we need is a wp<...>
    // that's what we create.
    wp<BufferQueue::ConsumerListener> listener = static_cast<BufferQueue::ConsumerListener*>(this);
    sp<IConsumerListener> proxy;
    if (!mIsPersistent) {
        proxy = new BufferQueue::ProxyConsumerListener(listener);
    } else {
        proxy = new PersistentProxyListener(mConsumer, listener);
    }

    mInitCheck = mConsumer->consumerConnect(proxy, false);
    if (mInitCheck != NO_ERROR) {
        ALOGE("Error connecting to BufferQueue: %s (%d)",
                strerror(-mInitCheck), mInitCheck);
        return;
    }

    memset(&mColorAspects, 0, sizeof(mColorAspects));

    CHECK(mInitCheck == NO_ERROR);
}

GraphicBufferSource::~GraphicBufferSource() {
    if (mLatestBufferId >= 0) {
        releaseBuffer(
                mLatestBufferId, mLatestBufferFrameNum,
                mBufferSlot[mLatestBufferId], mLatestBufferFence);
    }
    if (mNumBufferAcquired != 0) {
        ALOGW("potential buffer leak (acquired %d)", mNumBufferAcquired);
    }
    if (mConsumer != NULL && !mIsPersistent) {
        status_t err = mConsumer->consumerDisconnect();
        if (err != NO_ERROR) {
            ALOGW("consumerDisconnect failed: %d", err);
        }
    }
}

Status GraphicBufferSource::onOmxExecuting() {
    Mutex::Autolock autoLock(mMutex);
    ALOGV("--> executing; avail=%zu, codec vec size=%zd",
            mNumFramesAvailable, mCodecBuffers.size());
    CHECK(!mExecuting);
    mExecuting = true;
    mLastDataSpace = HAL_DATASPACE_UNKNOWN;
    ALOGV("clearing last dataSpace");

    // Start by loading up as many buffers as possible.  We want to do this,
    // rather than just submit the first buffer, to avoid a degenerate case:
    // if all BQ buffers arrive before we start executing, and we only submit
    // one here, the other BQ buffers will just sit until we get notified
    // that the codec buffer has been released.  We'd then acquire and
    // submit a single additional buffer, repeatedly, never using more than
    // one codec buffer simultaneously.  (We could instead try to submit
    // all BQ buffers whenever any codec buffer is freed, but if we get the
    // initial conditions right that will never be useful.)
    while (mNumFramesAvailable) {
        if (!fillCodecBuffer_l()) {
            ALOGV("stop load with frames available (codecAvail=%d)",
                    isCodecBufferAvailable_l());
            break;
        }
    }

    ALOGV("done loading initial frames, avail=%zu", mNumFramesAvailable);

    // If EOS has already been signaled, and there are no more frames to
    // submit, try to send EOS now as well.
    if (mEndOfStream && mNumFramesAvailable == 0) {
        submitEndOfInputStream_l();
    }

    if (mRepeatAfterUs > 0ll && mLooper == NULL) {
        mReflector = new AHandlerReflector<GraphicBufferSource>(this);

        mLooper = new ALooper;
        mLooper->registerHandler(mReflector);
        mLooper->start();

        if (mLatestBufferId >= 0) {
            sp<AMessage> msg =
                new AMessage(kWhatRepeatLastFrame, mReflector);

            msg->setInt32("generation", ++mRepeatLastFrameGeneration);
            msg->post(mRepeatAfterUs);
        }
    }

    return Status::ok();
}

Status GraphicBufferSource::onOmxIdle() {
    ALOGV("omxIdle");

    Mutex::Autolock autoLock(mMutex);

    if (mExecuting) {
        // We are only interested in the transition from executing->idle,
        // not loaded->idle.
        mExecuting = false;
    }
    return Status::ok();
}

Status GraphicBufferSource::onOmxLoaded(){
    Mutex::Autolock autoLock(mMutex);
    if (!mExecuting) {
        // This can happen if something failed very early.
        ALOGW("Dropped back down to Loaded without Executing");
    }

    if (mLooper != NULL) {
        mLooper->unregisterHandler(mReflector->id());
        mReflector.clear();

        mLooper->stop();
        mLooper.clear();
    }

    ALOGV("--> loaded; avail=%zu eos=%d eosSent=%d",
            mNumFramesAvailable, mEndOfStream, mEndOfStreamSent);

    // Codec is no longer executing.  Discard all codec-related state.
    mCodecBuffers.clear();
    // TODO: scan mCodecBuffers to verify that all mGraphicBuffer entries
    //       are null; complain if not

    mExecuting = false;
    return Status::ok();
}

Status GraphicBufferSource::onInputBufferAdded(int32_t bufferID) {
    Mutex::Autolock autoLock(mMutex);

    if (mExecuting) {
        // This should never happen -- buffers can only be allocated when
        // transitioning from "loaded" to "idle".
        ALOGE("addCodecBuffer: buffer added while executing");
        return Status::fromServiceSpecificError(INVALID_OPERATION);
    }

    ALOGV("addCodecBuffer id=%u", bufferID);

    CodecBuffer codecBuffer;
    codecBuffer.mBufferID = bufferID;
    mCodecBuffers.add(codecBuffer);
    return Status::ok();
}

Status GraphicBufferSource::onInputBufferEmptied(
        int32_t bufferID, const OMXFenceParcelable &fenceParcel) {
    int fenceFd = fenceParcel.get();

    Mutex::Autolock autoLock(mMutex);
    if (!mExecuting) {
        if (fenceFd >= 0) {
            ::close(fenceFd);
        }
        return Status::fromServiceSpecificError(INVALID_OPERATION);
    }

    int cbi = findMatchingCodecBuffer_l(bufferID);
    if (cbi < 0) {
        // This should never happen.
        ALOGE("codecBufferEmptied: buffer not recognized (id=%u)", bufferID);
        if (fenceFd >= 0) {
            ::close(fenceFd);
        }
        return Status::fromServiceSpecificError(BAD_VALUE);
    }

    ALOGV("codecBufferEmptied id=%u", bufferID);
    CodecBuffer& codecBuffer(mCodecBuffers.editItemAt(cbi));

    // header->nFilledLen may not be the original value, so we can't compare
    // that to zero to see of this was the EOS buffer.  Instead we just
    // see if the GraphicBuffer reference was null, which should only ever
    // happen for EOS.
    if (codecBuffer.mGraphicBuffer == NULL) {
        if (!(mEndOfStream && mEndOfStreamSent)) {
            // This can happen when broken code sends us the same buffer
            // twice in a row.
            ALOGE("ERROR: codecBufferEmptied on non-EOS null buffer "
                    "(buffer emptied twice?)");
        }
        // No GraphicBuffer to deal with, no additional input or output is
        // expected, so just return.
        if (fenceFd >= 0) {
            ::close(fenceFd);
        }
        return Status::fromServiceSpecificError(BAD_VALUE);
    }

    // Find matching entry in our cached copy of the BufferQueue slots.
    // If we find a match, release that slot.  If we don't, the BufferQueue
    // has dropped that GraphicBuffer, and there's nothing for us to release.
    int id = codecBuffer.mSlot;
    sp<Fence> fence = new Fence(fenceFd);
    if (mBufferSlot[id] != NULL &&
        mBufferSlot[id]->handle == codecBuffer.mGraphicBuffer->handle) {
        mBufferUseCount[id]--;

        ALOGV("codecBufferEmptied: slot=%d, cbi=%d, useCount=%d, handle=%p",
                id, cbi, mBufferUseCount[id], mBufferSlot[id]->handle);

        if (mBufferUseCount[id] < 0) {
            ALOGW("mBufferUseCount for bq slot %d < 0 (=%d)", id, mBufferUseCount[id]);
            mBufferUseCount[id] = 0;
        }
        if (id != mLatestBufferId && mBufferUseCount[id] == 0) {
            releaseBuffer(id, codecBuffer.mFrameNumber, mBufferSlot[id], fence);
        }
    } else {
        ALOGV("codecBufferEmptied: no match for emptied buffer in cbi %d",
                cbi);
        // we will not reuse codec buffer, so there is no need to wait for fence
    }

    // Mark the codec buffer as available by clearing the GraphicBuffer ref.
    codecBuffer.mGraphicBuffer = NULL;

    if (mNumFramesAvailable) {
        // Fill this codec buffer.
        CHECK(!mEndOfStreamSent);
        ALOGV("buffer freed, %zu frames avail (eos=%d)",
                mNumFramesAvailable, mEndOfStream);
        fillCodecBuffer_l();
    } else if (mEndOfStream) {
        // No frames available, but EOS is pending, so use this buffer to
        // send that.
        ALOGV("buffer freed, EOS pending");
        submitEndOfInputStream_l();
    } else if (mRepeatBufferDeferred) {
        bool success = repeatLatestBuffer_l();
        if (success) {
            ALOGV("deferred repeatLatestBuffer_l SUCCESS");
        } else {
            ALOGV("deferred repeatLatestBuffer_l FAILURE");
        }
        mRepeatBufferDeferred = false;
    }

    return Status::ok();
}

void GraphicBufferSource::onDataSpaceChanged_l(
        android_dataspace dataSpace, android_pixel_format pixelFormat) {
    ALOGD("got buffer with new dataSpace #%x", dataSpace);
    mLastDataSpace = dataSpace;

    if (ColorUtils::convertDataSpaceToV0(dataSpace)) {
        omx_message msg;
        msg.type = omx_message::EVENT;
        msg.fenceFd = -1;
        msg.u.event_data.event = OMX_EventDataSpaceChanged;
        msg.u.event_data.data1 = mLastDataSpace;
        msg.u.event_data.data2 = ColorUtils::packToU32(mColorAspects);
        msg.u.event_data.data3 = pixelFormat;

        mOMXNode->dispatchMessage(msg);
    }
}

bool GraphicBufferSource::fillCodecBuffer_l() {
    CHECK(mExecuting && mNumFramesAvailable > 0);

    if (mSuspended) {
        return false;
    }

    int cbi = findAvailableCodecBuffer_l();
    if (cbi < 0) {
        // No buffers available, bail.
        ALOGV("fillCodecBuffer_l: no codec buffers, avail now %zu",
                mNumFramesAvailable);
        return false;
    }

    ALOGV("fillCodecBuffer_l: acquiring buffer, avail=%zu",
            mNumFramesAvailable);
    BufferItem item;
    status_t err = mConsumer->acquireBuffer(&item, 0);
    if (err == BufferQueue::NO_BUFFER_AVAILABLE) {
        // shouldn't happen
        ALOGW("fillCodecBuffer_l: frame was not available");
        return false;
    } else if (err != OK) {
        // now what? fake end-of-stream?
        ALOGW("fillCodecBuffer_l: acquireBuffer returned err=%d", err);
        return false;
    }

    mNumBufferAcquired++;
    mNumFramesAvailable--;

    // If this is the first time we're seeing this buffer, add it to our
    // slot table.
    if (item.mGraphicBuffer != NULL) {
        ALOGV("fillCodecBuffer_l: setting mBufferSlot %d", item.mSlot);
        mBufferSlot[item.mSlot] = item.mGraphicBuffer;
        mBufferUseCount[item.mSlot] = 0;
    }

    if (item.mDataSpace != mLastDataSpace) {
        onDataSpaceChanged_l(
                item.mDataSpace, (android_pixel_format)mBufferSlot[item.mSlot]->getPixelFormat());
    }


    err = UNKNOWN_ERROR;

    // only submit sample if start time is unspecified, or sample
    // is queued after the specified start time
    bool dropped = false;
    if (mSkipFramesBeforeNs < 0ll || item.mTimestamp >= mSkipFramesBeforeNs) {
        // if start time is set, offset time stamp by start time
        if (mSkipFramesBeforeNs > 0) {
            item.mTimestamp -= mSkipFramesBeforeNs;
        }

        int64_t timeUs = item.mTimestamp / 1000;
        if (mFrameDropper != NULL && mFrameDropper->shouldDrop(timeUs)) {
            ALOGV("skipping frame (%lld) to meet max framerate", static_cast<long long>(timeUs));
            // set err to OK so that the skipped frame can still be saved as the lastest frame
            err = OK;
            dropped = true;
        } else {
            err = submitBuffer_l(item, cbi);
        }
    }

    if (err != OK) {
        ALOGV("submitBuffer_l failed, releasing bq slot %d", item.mSlot);
        releaseBuffer(item.mSlot, item.mFrameNumber, item.mGraphicBuffer, item.mFence);
    } else {
        ALOGV("buffer submitted (bq %d, cbi %d)", item.mSlot, cbi);
        setLatestBuffer_l(item, dropped);
    }

    return true;
}

bool GraphicBufferSource::repeatLatestBuffer_l() {
    CHECK(mExecuting && mNumFramesAvailable == 0);

    if (mLatestBufferId < 0 || mSuspended) {
        return false;
    }
    if (mBufferSlot[mLatestBufferId] == NULL) {
        // This can happen if the remote side disconnects, causing
        // onBuffersReleased() to NULL out our copy of the slots.  The
        // buffer is gone, so we have nothing to show.
        //
        // To be on the safe side we try to release the buffer.
        ALOGD("repeatLatestBuffer_l: slot was NULL");
        mConsumer->releaseBuffer(
                mLatestBufferId,
                mLatestBufferFrameNum,
                EGL_NO_DISPLAY,
                EGL_NO_SYNC_KHR,
                mLatestBufferFence);
        mLatestBufferId = -1;
        mLatestBufferFrameNum = 0;
        mLatestBufferFence = Fence::NO_FENCE;
        return false;
    }

    int cbi = findAvailableCodecBuffer_l();
    if (cbi < 0) {
        // No buffers available, bail.
        ALOGV("repeatLatestBuffer_l: no codec buffers.");
        return false;
    }

    BufferItem item;
    item.mSlot = mLatestBufferId;
    item.mFrameNumber = mLatestBufferFrameNum;
    item.mTimestamp = mRepeatLastFrameTimestamp;
    item.mFence = mLatestBufferFence;

    status_t err = submitBuffer_l(item, cbi);

    if (err != OK) {
        return false;
    }

    ++mBufferUseCount[item.mSlot];

    /* repeat last frame up to kRepeatLastFrameCount times.
     * in case of static scene, a single repeat might not get rid of encoder
     * ghosting completely, refresh a couple more times to get better quality
     */
    if (--mRepeatLastFrameCount > 0) {
        mRepeatLastFrameTimestamp = item.mTimestamp + mRepeatAfterUs * 1000;

        if (mReflector != NULL) {
            sp<AMessage> msg = new AMessage(kWhatRepeatLastFrame, mReflector);
            msg->setInt32("generation", ++mRepeatLastFrameGeneration);
            msg->post(mRepeatAfterUs);
        }
    }

    return true;
}

void GraphicBufferSource::setLatestBuffer_l(
        const BufferItem &item, bool dropped) {
    if (mLatestBufferId >= 0) {
        if (mBufferUseCount[mLatestBufferId] == 0) {
            releaseBuffer(mLatestBufferId, mLatestBufferFrameNum,
                    mBufferSlot[mLatestBufferId], mLatestBufferFence);
            // mLatestBufferFence will be set to new fence just below
        }
    }

    mLatestBufferId = item.mSlot;
    mLatestBufferFrameNum = item.mFrameNumber;
    mRepeatLastFrameTimestamp = item.mTimestamp + mRepeatAfterUs * 1000;

    if (!dropped) {
        ++mBufferUseCount[item.mSlot];
    }

    ALOGV("setLatestBuffer_l: slot=%d, useCount=%d",
            item.mSlot, mBufferUseCount[item.mSlot]);

    mRepeatBufferDeferred = false;
    mRepeatLastFrameCount = kRepeatLastFrameCount;
    mLatestBufferFence = item.mFence;

    if (mReflector != NULL) {
        sp<AMessage> msg = new AMessage(kWhatRepeatLastFrame, mReflector);
        msg->setInt32("generation", ++mRepeatLastFrameGeneration);
        msg->post(mRepeatAfterUs);
    }
}

bool GraphicBufferSource::getTimestamp(
        const BufferItem &item, int64_t *origTimeUs, int64_t *codecTimeUs) {
    *origTimeUs = -1ll;

    int64_t timeUs = item.mTimestamp / 1000;
    timeUs += mInputBufferTimeOffsetUs;

    if (mTimePerCaptureUs > 0ll
            && (mTimePerCaptureUs > 2 * mTimePerFrameUs
            || mTimePerFrameUs > 2 * mTimePerCaptureUs)) {
        // Time lapse or slow motion mode
        if (mPrevCaptureUs < 0ll) {
            // first capture
            mPrevCaptureUs = timeUs;
            mPrevFrameUs = timeUs;
        } else {
            // snap to nearest capture point
            int64_t nFrames = (timeUs + mTimePerCaptureUs / 2 - mPrevCaptureUs)
                    / mTimePerCaptureUs;
            if (nFrames <= 0) {
                // skip this frame as it's too close to previous capture
                ALOGV("skipping frame, timeUs %lld", static_cast<long long>(timeUs));
                return false;
            }
            mPrevCaptureUs = mPrevCaptureUs + nFrames * mTimePerCaptureUs;
            mPrevFrameUs += mTimePerFrameUs * nFrames;
        }

        ALOGV("timeUs %lld, captureUs %lld, frameUs %lld",
                static_cast<long long>(timeUs),
                static_cast<long long>(mPrevCaptureUs),
                static_cast<long long>(mPrevFrameUs));

        *codecTimeUs = mPrevFrameUs;
        return true;
    } else {
        int64_t originalTimeUs = timeUs;
        if (originalTimeUs <= mPrevOriginalTimeUs) {
                // Drop the frame if it's going backward in time. Bad timestamp
                // could disrupt encoder's rate control completely.
            ALOGW("Dropping frame that's going backward in time");
            return false;
        }

        if (mMaxTimestampGapUs > 0ll) {
            //TODO: Fix the case when mMaxTimestampGapUs and mTimePerCaptureUs are both set.

            /* Cap timestamp gap between adjacent frames to specified max
             *
             * In the scenario of cast mirroring, encoding could be suspended for
             * prolonged periods. Limiting the pts gap to workaround the problem
             * where encoder's rate control logic produces huge frames after a
             * long period of suspension.
             */
            if (mPrevOriginalTimeUs >= 0ll) {
                int64_t timestampGapUs = originalTimeUs - mPrevOriginalTimeUs;
                timeUs = (timestampGapUs < mMaxTimestampGapUs ?
                    timestampGapUs : mMaxTimestampGapUs) + mPrevModifiedTimeUs;
            }
            *origTimeUs = originalTimeUs;
            ALOGV("IN  timestamp: %lld -> %lld",
                static_cast<long long>(originalTimeUs),
                static_cast<long long>(timeUs));
        }

        mPrevOriginalTimeUs = originalTimeUs;
        mPrevModifiedTimeUs = timeUs;
    }

    *codecTimeUs = timeUs;
    return true;
}

status_t GraphicBufferSource::submitBuffer_l(const BufferItem &item, int cbi) {
    ALOGV("submitBuffer_l: slot=%d, cbi=%d", item.mSlot, cbi);

    int64_t origTimeUs, codecTimeUs;
    if (!getTimestamp(item, &origTimeUs, &codecTimeUs)) {
        return UNKNOWN_ERROR;
    }

    CodecBuffer& codecBuffer(mCodecBuffers.editItemAt(cbi));
    codecBuffer.mGraphicBuffer = mBufferSlot[item.mSlot];
    codecBuffer.mSlot = item.mSlot;
    codecBuffer.mFrameNumber = item.mFrameNumber;

    IOMX::buffer_id bufferID = codecBuffer.mBufferID;
    const sp<GraphicBuffer> &buffer = codecBuffer.mGraphicBuffer;
    int fenceID = item.mFence->isValid() ? item.mFence->dup() : -1;

    status_t err = mOMXNode->emptyGraphicBuffer(
            bufferID, buffer, OMX_BUFFERFLAG_ENDOFFRAME,
            codecTimeUs, origTimeUs, fenceID);

    if (err != OK) {
        ALOGW("WARNING: emptyGraphicBuffer failed: 0x%x", err);
        codecBuffer.mGraphicBuffer = NULL;
        return err;
    }

    ALOGV("emptyGraphicBuffer succeeded, id=%u buf=%p bufhandle=%p",
            bufferID, buffer->getNativeBuffer(), buffer->handle);
    return OK;
}

void GraphicBufferSource::submitEndOfInputStream_l() {
    CHECK(mEndOfStream);
    if (mEndOfStreamSent) {
        ALOGV("EOS already sent");
        return;
    }

    int cbi = findAvailableCodecBuffer_l();
    if (cbi < 0) {
        ALOGV("submitEndOfInputStream_l: no codec buffers available");
        return;
    }

    // We reject any additional incoming graphic buffers, so there's no need
    // to stick a placeholder into codecBuffer.mGraphicBuffer to mark it as
    // in-use.
    CodecBuffer& codecBuffer(mCodecBuffers.editItemAt(cbi));
    IOMX::buffer_id bufferID = codecBuffer.mBufferID;

    status_t err = mOMXNode->emptyGraphicBuffer(
            bufferID, NULL /* buffer */,
            OMX_BUFFERFLAG_ENDOFFRAME | OMX_BUFFERFLAG_EOS,
            0 /* timestamp */, -1ll /* origTimestamp */, -1 /* fenceFd */);
    if (err != OK) {
        ALOGW("emptyDirectBuffer EOS failed: 0x%x", err);
    } else {
        ALOGV("submitEndOfInputStream_l: buffer submitted, id=%u cbi=%d",
                bufferID, cbi);
        mEndOfStreamSent = true;
    }
}

int GraphicBufferSource::findAvailableCodecBuffer_l() {
    CHECK(mCodecBuffers.size() > 0);

    for (int i = (int)mCodecBuffers.size() - 1; i>= 0; --i) {
        if (mCodecBuffers[i].mGraphicBuffer == NULL) {
            return i;
        }
    }
    return -1;
}

int GraphicBufferSource::findMatchingCodecBuffer_l(IOMX::buffer_id bufferID) {
    for (int i = (int)mCodecBuffers.size() - 1; i>= 0; --i) {
        if (mCodecBuffers[i].mBufferID == bufferID) {
            return i;
        }
    }
    return -1;
}

/*
 * Releases an acquired buffer back to the consumer for either persistent
 * or non-persistent surfaces.
 *
 * id: buffer slot to release (in persistent case the id might be changed)
 * frameNum: frame number of the frame being released
 * buffer: GraphicBuffer pointer to release (note this must not be & as we
 *         will clear the original mBufferSlot in persistent case)
 *         Use NOLINT to supress warning on the copy of 'buffer'.
 * fence: fence of the frame being released
 */
void GraphicBufferSource::releaseBuffer(
        int &id, uint64_t frameNum,
        const sp<GraphicBuffer> buffer, const sp<Fence> &fence) {  // NOLINT
    ALOGV("releaseBuffer: slot=%d", id);
    if (mIsPersistent) {
        mConsumer->detachBuffer(id);
        mBufferSlot[id] = NULL;

        if (mConsumer->attachBuffer(&id, buffer) == OK) {
            mConsumer->releaseBuffer(
                    id, 0, EGL_NO_DISPLAY, EGL_NO_SYNC_KHR, fence);
        }
    } else {
        mConsumer->releaseBuffer(
                id, frameNum, EGL_NO_DISPLAY, EGL_NO_SYNC_KHR, fence);
    }
    id = -1; // invalidate id
    mNumBufferAcquired--;
}

// BufferQueue::ConsumerListener callback
void GraphicBufferSource::onFrameAvailable(const BufferItem& /*item*/) {
    Mutex::Autolock autoLock(mMutex);

    ALOGV("onFrameAvailable exec=%d avail=%zu",
            mExecuting, mNumFramesAvailable);

    if (mEndOfStream || mSuspended) {
        if (mEndOfStream) {
            // This should only be possible if a new buffer was queued after
            // EOS was signaled, i.e. the app is misbehaving.

            ALOGW("onFrameAvailable: EOS is set, ignoring frame");
        } else {
            ALOGV("onFrameAvailable: suspended, ignoring frame");
        }

        BufferItem item;
        status_t err = mConsumer->acquireBuffer(&item, 0);
        if (err == OK) {
            mNumBufferAcquired++;

            // If this is the first time we're seeing this buffer, add it to our
            // slot table.
            if (item.mGraphicBuffer != NULL) {
                ALOGV("onFrameAvailable: setting mBufferSlot %d", item.mSlot);
                mBufferSlot[item.mSlot] = item.mGraphicBuffer;
                mBufferUseCount[item.mSlot] = 0;
            }

            releaseBuffer(item.mSlot, item.mFrameNumber,
                    item.mGraphicBuffer, item.mFence);
        }
        return;
    }

    mNumFramesAvailable++;

    mRepeatBufferDeferred = false;
    ++mRepeatLastFrameGeneration;

    if (mExecuting) {
        fillCodecBuffer_l();
    }
}

// BufferQueue::ConsumerListener callback
void GraphicBufferSource::onBuffersReleased() {
    Mutex::Autolock lock(mMutex);

    uint64_t slotMask;
    if (mConsumer->getReleasedBuffers(&slotMask) != NO_ERROR) {
        ALOGW("onBuffersReleased: unable to get released buffer set");
        slotMask = 0xffffffffffffffffULL;
    }

    ALOGV("onBuffersReleased: 0x%016" PRIx64, slotMask);

    for (int i = 0; i < BufferQueue::NUM_BUFFER_SLOTS; i++) {
        if ((slotMask & 0x01) != 0) {
            mBufferSlot[i] = NULL;
            mBufferUseCount[i] = 0;
        }
        slotMask >>= 1;
    }
}

// BufferQueue::ConsumerListener callback
void GraphicBufferSource::onSidebandStreamChanged() {
    ALOG_ASSERT(false, "GraphicBufferSource can't consume sideband streams");
}

void GraphicBufferSource::setDefaultDataSpace(android_dataspace dataSpace) {
    // no need for mutex as we are not yet running
    ALOGD("setting dataspace: %#x", dataSpace);
    mConsumer->setDefaultBufferDataSpace(dataSpace);
    mLastDataSpace = dataSpace;
}

Status GraphicBufferSource::setSuspend(bool suspend) {
    ALOGV("setSuspend=%d", suspend);

    Mutex::Autolock autoLock(mMutex);

    if (suspend) {
        mSuspended = true;

        while (mNumFramesAvailable > 0) {
            BufferItem item;
            status_t err = mConsumer->acquireBuffer(&item, 0);

            if (err == BufferQueue::NO_BUFFER_AVAILABLE) {
                // shouldn't happen.
                ALOGW("suspend: frame was not available");
                break;
            } else if (err != OK) {
                ALOGW("suspend: acquireBuffer returned err=%d", err);
                break;
            }

            ++mNumBufferAcquired;
            --mNumFramesAvailable;

            releaseBuffer(item.mSlot, item.mFrameNumber,
                    item.mGraphicBuffer, item.mFence);
        }
        return Status::ok();
    }

    mSuspended = false;

    if (mExecuting && mNumFramesAvailable == 0 && mRepeatBufferDeferred) {
        if (repeatLatestBuffer_l()) {
            ALOGV("suspend/deferred repeatLatestBuffer_l SUCCESS");

            mRepeatBufferDeferred = false;
        } else {
            ALOGV("suspend/deferred repeatLatestBuffer_l FAILURE");
        }
    }
    return Status::ok();
}

Status GraphicBufferSource::setRepeatPreviousFrameDelayUs(int64_t repeatAfterUs) {
    ALOGV("setRepeatPreviousFrameDelayUs: delayUs=%lld", (long long)repeatAfterUs);

    Mutex::Autolock autoLock(mMutex);

    if (mExecuting || repeatAfterUs <= 0ll) {
        return Status::fromServiceSpecificError(INVALID_OPERATION);
    }

    mRepeatAfterUs = repeatAfterUs;
    return Status::ok();
}

Status GraphicBufferSource::setMaxTimestampGapUs(int64_t maxGapUs) {
    ALOGV("setMaxTimestampGapUs: maxGapUs=%lld", (long long)maxGapUs);

    Mutex::Autolock autoLock(mMutex);

    if (mExecuting || maxGapUs <= 0ll) {
        return Status::fromServiceSpecificError(INVALID_OPERATION);
    }

    mMaxTimestampGapUs = maxGapUs;

    return Status::ok();
}

Status GraphicBufferSource::setTimeOffsetUs(int64_t timeOffsetUs) {
    Mutex::Autolock autoLock(mMutex);

    // timeOffsetUs must be negative for adjustment.
    if (timeOffsetUs >= 0ll) {
        return Status::fromServiceSpecificError(INVALID_OPERATION);
    }

    mInputBufferTimeOffsetUs = timeOffsetUs;
    return Status::ok();
}

Status GraphicBufferSource::setMaxFps(float maxFps) {
    ALOGV("setMaxFps: maxFps=%lld", (long long)maxFps);

    Mutex::Autolock autoLock(mMutex);

    if (mExecuting) {
        return Status::fromServiceSpecificError(INVALID_OPERATION);
    }

    mFrameDropper = new FrameDropper();
    status_t err = mFrameDropper->setMaxFrameRate(maxFps);
    if (err != OK) {
        mFrameDropper.clear();
        return Status::fromServiceSpecificError(err);
    }

    return Status::ok();
}

Status GraphicBufferSource::setStartTimeUs(int64_t skipFramesBeforeUs) {
    ALOGV("setStartTimeUs: skipFramesBeforeUs=%lld", (long long)skipFramesBeforeUs);

    Mutex::Autolock autoLock(mMutex);

    mSkipFramesBeforeNs =
            (skipFramesBeforeUs > 0) ? (skipFramesBeforeUs * 1000) : -1ll;

    return Status::ok();
}

Status GraphicBufferSource::setTimeLapseConfig(int64_t timePerFrameUs, int64_t timePerCaptureUs) {
    ALOGV("setTimeLapseConfig: timePerFrameUs=%lld, timePerCaptureUs=%lld",
            (long long)timePerFrameUs, (long long)timePerCaptureUs);

    Mutex::Autolock autoLock(mMutex);

    if (mExecuting || timePerFrameUs <= 0ll || timePerCaptureUs <= 0ll) {
        return Status::fromServiceSpecificError(INVALID_OPERATION);
    }

    mTimePerFrameUs = timePerFrameUs;
    mTimePerCaptureUs = timePerCaptureUs;

    return Status::ok();
}

Status GraphicBufferSource::setColorAspects(int32_t aspectsPacked) {
    Mutex::Autolock autoLock(mMutex);
    mColorAspects = ColorUtils::unpackToColorAspects(aspectsPacked);
    ALOGD("requesting color aspects (R:%d(%s), P:%d(%s), M:%d(%s), T:%d(%s))",
            mColorAspects.mRange, asString(mColorAspects.mRange),
            mColorAspects.mPrimaries, asString(mColorAspects.mPrimaries),
            mColorAspects.mMatrixCoeffs, asString(mColorAspects.mMatrixCoeffs),
            mColorAspects.mTransfer, asString(mColorAspects.mTransfer));

    return Status::ok();
}

Status GraphicBufferSource::signalEndOfInputStream() {
    Mutex::Autolock autoLock(mMutex);
    ALOGV("signalEndOfInputStream: exec=%d avail=%zu eos=%d",
            mExecuting, mNumFramesAvailable, mEndOfStream);

    if (mEndOfStream) {
        ALOGE("EOS was already signaled");
        return Status::fromStatusT(INVALID_OPERATION);
    }

    // Set the end-of-stream flag.  If no frames are pending from the
    // BufferQueue, and a codec buffer is available, and we're executing,
    // we initiate the EOS from here.  Otherwise, we'll let
    // codecBufferEmptied() (or omxExecuting) do it.
    //
    // Note: if there are no pending frames and all codec buffers are
    // available, we *must* submit the EOS from here or we'll just
    // stall since no future events are expected.
    mEndOfStream = true;

    if (mExecuting && mNumFramesAvailable == 0) {
        submitEndOfInputStream_l();
    }

    return Status::ok();
}

void GraphicBufferSource::onMessageReceived(const sp<AMessage> &msg) {
    switch (msg->what()) {
        case kWhatRepeatLastFrame:
        {
            Mutex::Autolock autoLock(mMutex);

            int32_t generation;
            CHECK(msg->findInt32("generation", &generation));

            if (generation != mRepeatLastFrameGeneration) {
                // stale
                break;
            }

            if (!mExecuting || mNumFramesAvailable > 0) {
                break;
            }

            bool success = repeatLatestBuffer_l();

            if (success) {
                ALOGV("repeatLatestBuffer_l SUCCESS");
            } else {
                ALOGV("repeatLatestBuffer_l FAILURE");
                mRepeatBufferDeferred = true;
            }
            break;
        }

        default:
            TRESPASS();
    }
}

}  // namespace android
