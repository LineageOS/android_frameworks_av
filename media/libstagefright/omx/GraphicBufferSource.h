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

#ifndef GRAPHIC_BUFFER_SOURCE_H_

#define GRAPHIC_BUFFER_SOURCE_H_

#include <gui/IGraphicBufferProducer.h>
#include <gui/BufferQueue.h>
#include <utils/RefBase.h>

#include <VideoAPI.h>
#include <media/IOMX.h>
#include <media/OMXFenceParcelable.h>
#include <media/stagefright/foundation/ABase.h>
#include <media/stagefright/foundation/AHandlerReflector.h>
#include <media/stagefright/foundation/ALooper.h>

#include <android/BnGraphicBufferSource.h>
#include <android/BnOMXBufferSource.h>

namespace android {

using ::android::binder::Status;

struct FrameDropper;

/*
 * This class is used to feed OMX codecs from a Surface via BufferQueue.
 *
 * Instances of the class don't run on a dedicated thread.  Instead,
 * various events trigger data movement:
 *
 *  - Availability of a new frame of data from the BufferQueue (notified
 *    via the onFrameAvailable callback).
 *  - The return of a codec buffer (via OnEmptyBufferDone).
 *  - Application signaling end-of-stream.
 *  - Transition to or from "executing" state.
 *
 * Frames of data (and, perhaps, the end-of-stream indication) can arrive
 * before the codec is in the "executing" state, so we need to queue
 * things up until we're ready to go.
 */
class GraphicBufferSource : public BnGraphicBufferSource,
                            public BnOMXBufferSource,
                            public BufferQueue::ConsumerListener {
public:
    GraphicBufferSource();

    virtual ~GraphicBufferSource();

    // We can't throw an exception if the constructor fails, so we just set
    // this and require that the caller test the value.
    status_t initCheck() const {
        return mInitCheck;
    }

    // Returns the handle to the producer side of the BufferQueue.  Buffers
    // queued on this will be received by GraphicBufferSource.
    sp<IGraphicBufferProducer> getIGraphicBufferProducer() const {
        return mProducer;
    }

    // This is called when OMX transitions to OMX_StateExecuting, which means
    // we can start handing it buffers.  If we already have buffers of data
    // sitting in the BufferQueue, this will send them to the codec.
    Status onOmxExecuting() override;

    // This is called when OMX transitions to OMX_StateIdle, indicating that
    // the codec is meant to return all buffers back to the client for them
    // to be freed. Do NOT submit any more buffers to the component.
    Status onOmxIdle() override;

    // This is called when OMX transitions to OMX_StateLoaded, indicating that
    // we are shutting down.
    Status onOmxLoaded() override;

    // A "codec buffer", i.e. a buffer that can be used to pass data into
    // the encoder, has been allocated.  (This call does not call back into
    // OMXNodeInstance.)
    Status onInputBufferAdded(int32_t bufferID) override;

    // Called from OnEmptyBufferDone.  If we have a BQ buffer available,
    // fill it with a new frame of data; otherwise, just mark it as available.
    Status onInputBufferEmptied(
            int32_t bufferID, const OMXFenceParcelable& fenceParcel) override;

    // Configure the buffer source to be used with an OMX node with the default
    // data space.
    Status configure(const sp<IOMXNode>& omxNode, int32_t dataSpace) override;

    // This is called after the last input frame has been submitted.  We
    // need to submit an empty buffer with the EOS flag set.  If we don't
    // have a codec buffer ready, we just set the mEndOfStream flag.
    Status signalEndOfInputStream() override;

    // If suspend is true, all incoming buffers (including those currently
    // in the BufferQueue) will be discarded until the suspension is lifted.
    Status setSuspend(bool suspend) override;

    // Specifies the interval after which we requeue the buffer previously
    // queued to the encoder. This is useful in the case of surface flinger
    // providing the input surface if the resulting encoded stream is to
    // be displayed "live". If we were not to push through the extra frame
    // the decoder on the remote end would be unable to decode the latest frame.
    // This API must be called before transitioning the encoder to "executing"
    // state and once this behaviour is specified it cannot be reset.
    Status setRepeatPreviousFrameDelayUs(int64_t repeatAfterUs) override;

    // Sets the input buffer timestamp offset.
    // When set, the sample's timestamp will be adjusted with the timeOffsetUs.
    Status setTimeOffsetUs(int64_t timeOffsetUs) override;

    // When set, the max frame rate fed to the encoder will be capped at maxFps.
    Status setMaxFps(float maxFps) override;

    // Sets the time lapse (or slow motion) parameters.
    // When set, the sample's timestamp will be modified to playback framerate,
    // and capture timestamp will be modified to capture rate.
    Status setTimeLapseConfig(int64_t timePerFrameUs, int64_t timePerCaptureUs) override;

    // Sets the start time us (in system time), samples before which should
    // be dropped and not submitted to encoder
    Status setStartTimeUs(int64_t startTimeUs) override;

    // Sets the desired color aspects, e.g. to be used when producer does not specify a dataspace.
    Status setColorAspects(int32_t aspectsPacked) override;

protected:
    // BufferQueue::ConsumerListener interface, called when a new frame of
    // data is available.  If we're executing and a codec buffer is
    // available, we acquire the buffer, copy the GraphicBuffer reference
    // into the codec buffer, and call Empty[This]Buffer.  If we're not yet
    // executing or there's no codec buffer available, we just increment
    // mNumFramesAvailable and return.
    void onFrameAvailable(const BufferItem& item) override;

    // BufferQueue::ConsumerListener interface, called when the client has
    // released one or more GraphicBuffers.  We clear out the appropriate
    // set of mBufferSlot entries.
    void onBuffersReleased() override;

    // BufferQueue::ConsumerListener interface, called when the client has
    // changed the sideband stream. GraphicBufferSource doesn't handle sideband
    // streams so this is a no-op (and should never be called).
    void onSidebandStreamChanged() override;

private:

    // Keep track of codec input buffers.  They may either be available
    // (mGraphicBuffer == NULL) or in use by the codec.
    struct CodecBuffer {
        IOMX::buffer_id mBufferID;

        // buffer producer's frame-number for buffer
        uint64_t mFrameNumber;

        // buffer producer's buffer slot for buffer
        int mSlot;

        sp<GraphicBuffer> mGraphicBuffer;
    };

    // Returns the index of an available codec buffer.  If none are
    // available, returns -1.  Mutex must be held by caller.
    int findAvailableCodecBuffer_l();

    // Returns true if a codec buffer is available.
    bool isCodecBufferAvailable_l() {
        return findAvailableCodecBuffer_l() >= 0;
    }

    // Finds the mCodecBuffers entry that matches.  Returns -1 if not found.
    int findMatchingCodecBuffer_l(IOMX::buffer_id bufferID);

    // Fills a codec buffer with a frame from the BufferQueue.  This must
    // only be called when we know that a frame of data is ready (i.e. we're
    // in the onFrameAvailable callback, or if we're in codecBufferEmptied
    // and mNumFramesAvailable is nonzero).  Returns without doing anything if
    // we don't have a codec buffer available.
    //
    // Returns true if we successfully filled a codec buffer with a BQ buffer.
    bool fillCodecBuffer_l();

    // Marks the mCodecBuffers entry as in-use, copies the GraphicBuffer
    // reference into the codec buffer, and submits the data to the codec.
    status_t submitBuffer_l(const BufferItem &item, int cbi);

    // Submits an empty buffer, with the EOS flag set.   Returns without
    // doing anything if we don't have a codec buffer available.
    void submitEndOfInputStream_l();

    // Acquire buffer from the consumer
    status_t acquireBuffer(BufferItem *bi);

    // Release buffer to the consumer
    void releaseBuffer(int id, uint64_t frameNum, const sp<Fence> &fence);

    void setLatestBuffer_l(const BufferItem &item);
    bool repeatLatestBuffer_l();
    bool getTimestamp(const BufferItem &item, int64_t *codecTimeUs);

    // called when the data space of the input buffer changes
    void onDataSpaceChanged_l(android_dataspace dataSpace, android_pixel_format pixelFormat);

    // Lock, covers all member variables.
    mutable Mutex mMutex;

    // Used to report constructor failure.
    status_t mInitCheck;

    // Pointer back to the IOMXNode that created us.  We send buffers here.
    sp<IOMXNode> mOMXNode;

    // Set by omxExecuting() / omxIdling().
    bool mExecuting;

    bool mSuspended;

    // Last dataspace seen
    android_dataspace mLastDataSpace;

    // Our BufferQueue interfaces. mProducer is passed to the producer through
    // getIGraphicBufferProducer, and mConsumer is used internally to retrieve
    // the buffers queued by the producer.
    sp<IGraphicBufferProducer> mProducer;
    sp<IGraphicBufferConsumer> mConsumer;

    // Number of frames pending in BufferQueue that haven't yet been
    // forwarded to the codec.
    size_t mNumFramesAvailable;

    // Number of frames acquired from consumer (debug only)
    int32_t mNumBufferAcquired;

    // Set to true if we want to send end-of-stream after we run out of
    // frames in BufferQueue.
    bool mEndOfStream;
    bool mEndOfStreamSent;

    // Cache of GraphicBuffers from the buffer queue.  When the codec
    // is done processing a GraphicBuffer, we can use this to map back
    // to a slot number.
    sp<GraphicBuffer> mBufferSlot[BufferQueue::NUM_BUFFER_SLOTS];
    int32_t mBufferUseCount[BufferQueue::NUM_BUFFER_SLOTS];

    // Tracks codec buffers.
    Vector<CodecBuffer> mCodecBuffers;

    ////
    friend struct AHandlerReflector<GraphicBufferSource>;

    enum {
        kWhatRepeatLastFrame,
    };
    enum {
        kRepeatLastFrameCount = 10,
    };

    int64_t mPrevOriginalTimeUs;
    int64_t mSkipFramesBeforeNs;

    sp<FrameDropper> mFrameDropper;

    sp<ALooper> mLooper;
    sp<AHandlerReflector<GraphicBufferSource> > mReflector;

    int64_t mRepeatAfterUs;
    int32_t mRepeatLastFrameGeneration;
    int64_t mRepeatLastFrameTimestamp;
    int32_t mRepeatLastFrameCount;

    int mLatestBufferId;
    uint64_t mLatestBufferFrameNum;
    sp<Fence> mLatestBufferFence;

    // The previous buffer should've been repeated but
    // no codec buffer was available at the time.
    bool mRepeatBufferDeferred;

    // Time lapse / slow motion configuration
    int64_t mTimePerCaptureUs;
    int64_t mTimePerFrameUs;
    int64_t mPrevCaptureUs;
    int64_t mPrevFrameUs;

    int64_t mInputBufferTimeOffsetUs;

    ColorAspects mColorAspects;

    void onMessageReceived(const sp<AMessage> &msg);

    DISALLOW_EVIL_CONSTRUCTORS(GraphicBufferSource);
};

}  // namespace android

#endif  // GRAPHIC_BUFFER_SOURCE_H_
