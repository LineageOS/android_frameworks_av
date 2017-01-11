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

#ifndef ANDROID_SERVERS_STREAMSPLITTER_H
#define ANDROID_SERVERS_STREAMSPLITTER_H

#include <gui/IConsumerListener.h>
#include <gui/IProducerListener.h>
#include <gui/BufferItemConsumer.h>

#include <utils/Condition.h>
#include <utils/Mutex.h>
#include <utils/StrongPointer.h>
#include <utils/Timers.h>

namespace android {

class GraphicBuffer;
class IGraphicBufferConsumer;
class IGraphicBufferProducer;

// Camera3StreamSplitter is an autonomous class that manages one input BufferQueue
// and multiple output BufferQueues. By using the buffer attach and detach logic
// in BufferQueue, it is able to present the illusion of a single split
// BufferQueue, where each buffer queued to the input is available to be
// acquired by each of the outputs, and is able to be dequeued by the input
// again only once all of the outputs have released it.
class Camera3StreamSplitter : public BnConsumerListener {
public:

    // Constructor
    Camera3StreamSplitter() = default;

    // Connect to the stream splitter by creating buffer queue and connecting it
    // with output surfaces.
    status_t connect(const std::vector<sp<Surface> >& surfaces,
            uint32_t consumerUsage, size_t hal_max_buffers,
            sp<Surface>& consumer);

    // addOutput adds an output BufferQueue to the splitter. The splitter
    // connects to outputQueue as a CPU producer, and any buffers queued
    // to the input will be queued to each output. It is assumed that all of the
    // outputs are added before any buffers are queued on the input. If any
    // output is abandoned by its consumer, the splitter will abandon its input
    // queue (see onAbandoned).
    //
    // A return value other than NO_ERROR means that an error has occurred and
    // outputQueue has not been added to the splitter. BAD_VALUE is returned if
    // outputQueue is NULL. See IGraphicBufferProducer::connect for explanations
    // of other error codes.
    status_t addOutput(const sp<Surface>& outputQueue, size_t hal_max_buffers);

    // Request surfaces for a particular frame number. The requested surfaces
    // are stored in a FIFO queue. And when the buffer becomes available from the
    // input queue, the registered surfaces are used to decide which output is
    // the buffer sent to.
    status_t notifyRequestedSurfaces(const std::vector<size_t>& surfaces);

    // Disconnect the buffer queue from output surfaces.
    void disconnect();

private:
    // From IConsumerListener
    //
    // During this callback, we store some tracking information, detach the
    // buffer from the input, and attach it to each of the outputs. This call
    // can block if there are too many outstanding buffers. If it blocks, it
    // will resume when onBufferReleasedByOutput releases a buffer back to the
    // input.
    void onFrameAvailable(const BufferItem& item) override;

    // From IConsumerListener
    // We don't care about released buffers because we detach each buffer as
    // soon as we acquire it. See the comment for onBufferReleased below for
    // some clarifying notes about the name.
    void onBuffersReleased() override {}

    // From IConsumerListener
    // We don't care about sideband streams, since we won't be splitting them
    void onSidebandStreamChanged() override {}

    // This is the implementation of the onBufferReleased callback from
    // IProducerListener. It gets called from an OutputListener (see below), and
    // 'from' is which producer interface from which the callback was received.
    //
    // During this callback, we detach the buffer from the output queue that
    // generated the callback, update our state tracking to see if this is the
    // last output releasing the buffer, and if so, release it to the input.
    // If we release the buffer to the input, we allow a blocked
    // onFrameAvailable call to proceed.
    void onBufferReleasedByOutput(const sp<IGraphicBufferProducer>& from);

    // When this is called, the splitter disconnects from (i.e., abandons) its
    // input queue and signals any waiting onFrameAvailable calls to wake up.
    // It still processes callbacks from other outputs, but only detaches their
    // buffers so they can continue operating until they run out of buffers to
    // acquire. This must be called with mMutex locked.
    void onAbandonedLocked();

    // This is a thin wrapper class that lets us determine which BufferQueue
    // the IProducerListener::onBufferReleased callback is associated with. We
    // create one of these per output BufferQueue, and then pass the producer
    // into onBufferReleasedByOutput above.
    class OutputListener : public BnProducerListener,
                           public IBinder::DeathRecipient {
    public:
        OutputListener(wp<Camera3StreamSplitter> splitter,
                wp<IGraphicBufferProducer> output);
        virtual ~OutputListener() = default;

        // From IProducerListener
        void onBufferReleased() override;

        // From IBinder::DeathRecipient
        void binderDied(const wp<IBinder>& who) override;

    private:
        wp<Camera3StreamSplitter> mSplitter;
        wp<IGraphicBufferProducer> mOutput;
    };

    class BufferTracker {
    public:
        BufferTracker(const sp<GraphicBuffer>& buffer, size_t referenceCount);
        ~BufferTracker() = default;

        const sp<GraphicBuffer>& getBuffer() const { return mBuffer; }
        const sp<Fence>& getMergedFence() const { return mMergedFence; }

        void mergeFence(const sp<Fence>& with);

        // Returns the new value
        // Only called while mMutex is held
        size_t decrementReferenceCountLocked();

    private:

        // Disallow copying
        BufferTracker(const BufferTracker& other);
        BufferTracker& operator=(const BufferTracker& other);

        sp<GraphicBuffer> mBuffer; // One instance that holds this native handle
        sp<Fence> mMergedFence;
        size_t mReferenceCount;
    };

    // A deferred output is an output being added to the splitter after
    // connect() call, whereas a non deferred output is added within connect()
    // call.
    enum class OutputType { NonDeferred, Deferred };

    // Must be accessed through RefBase
    virtual ~Camera3StreamSplitter();

    status_t addOutputLocked(const sp<Surface>& outputQueue,
                             size_t hal_max_buffers, OutputType outputType);

    // Get unique name for the buffer queue consumer
    static String8 getUniqueConsumerName();

    // Max consumer side buffers for deferred surface. This will be used as a
    // lower bound for overall consumer side max buffers.
    static const int MAX_BUFFERS_DEFERRED_OUTPUT = 2;
    int mMaxConsumerBuffers = MAX_BUFFERS_DEFERRED_OUTPUT;

    static const nsecs_t kDequeueBufferTimeout   = s2ns(1); // 1 sec

    // mIsAbandoned is set to true when an output dies. Once the Camera3StreamSplitter
    // has been abandoned, it will continue to detach buffers from other
    // outputs, but it will disconnect from the input and not attempt to
    // communicate with it further.
    bool mIsAbandoned = false;

    Mutex mMutex;
    Condition mReleaseCondition;
    int mOutstandingBuffers = 0;

    sp<IGraphicBufferProducer> mProducer;
    sp<IGraphicBufferConsumer> mConsumer;
    sp<BufferItemConsumer> mBufferItemConsumer;
    sp<Surface> mSurface;

    std::vector<sp<IGraphicBufferProducer> > mOutputs;
    // Tracking which outputs should the buffer be attached and queued
    // to for each input buffer.
    std::vector<std::vector<size_t> > mRequestedSurfaces;

    // Map of GraphicBuffer IDs (GraphicBuffer::getId()) to buffer tracking
    // objects (which are mostly for counting how many outputs have released the
    // buffer, but also contain merged release fences).
    std::unordered_map<uint64_t, std::unique_ptr<BufferTracker> > mBuffers;
};

} // namespace android

#endif
