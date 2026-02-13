/*
 * Copyright (C) 2026 The Android Open Source Project
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
// #define LOG_NDEBUG 0
#define LOG_TAG "LegacyGraphicsTracker_test"
#include <poll.h>
#include <unistd.h>

#include <android/hardware_buffer.h>
#include <binder/IPCThreadState.h>
#include <binder/IServiceManager.h>
#include <binder/ProcessState.h>
#include <codec2/aidl/LegacyGraphicsTracker.h>
#include <gtest/gtest.h>
#include <gui/BufferItemConsumer.h>
#include <gui/BufferQueue.h>
#include <gui/IConsumerListener.h>
#include <gui/IGraphicBufferProducer.h>
#include <gui/IProducerListener.h>
#include <gui/Surface.h>
#include <private/android/AHardwareBufferHelpers.h>

#include <C2BlockInternal.h>
#include <C2FenceFactory.h>

#include <atomic>
#include <iostream>
#include <memory>
#include <thread>

using ::aidl::android::hardware::media::c2::implementation::LegacyGraphicsTracker;
using ::android::BufferItem;
using ::android::BufferItemConsumer;
using ::android::BufferQueue;
using ::android::Fence;
using ::android::GraphicBuffer;
using ::android::IConsumerListener;
using ::android::IGraphicBufferProducer;
using ::android::IProducerListener;
using ::android::OK;
using ::android::sp;
using ::android::Surface;
using ::android::wp;

namespace {
struct BqStatistics {
    std::atomic<int> mDequeued;
    std::atomic<int> mQueued;
    std::atomic<int> mBlocked;
    std::atomic<int> mDropped;
    std::atomic<int> mDiscarded;
    std::atomic<int> mReleased;

    void log() {
        ALOGD("Dequeued: %d, Queued: %d, Blocked: %d, "
              "Dropped: %d, Discarded %d, Released %d",
              (int)mDequeued, (int)mQueued, (int)mBlocked, (int)mDropped, (int)mDiscarded,
              (int)mReleased);
    }

    void clear() {
        mDequeued = 0;
        mQueued = 0;
        mBlocked = 0;
        mDropped = 0;
        mDiscarded = 0;
        mReleased = 0;
    }
};

struct DummyConsumerListener : public BufferItemConsumer::FrameAvailableListener {
    void onFrameAvailable(const BufferItem& /* item */) override {}
};

struct TestConsumerListener : public BufferItemConsumer::FrameAvailableListener {
    TestConsumerListener(const sp<BufferItemConsumer>& consumer) : mConsumer(consumer) {}
    void onFrameAvailable(const BufferItem&) override {
        constexpr static int kRenderDelayUs = 1000000 / 30;  // 30fps
        BufferItem buffer;
        // consume buffer
        sp<BufferItemConsumer> consumer = mConsumer.promote();
        if (consumer != nullptr && consumer->acquireBuffer(&buffer, 0) == android::NO_ERROR) {
            ::usleep(kRenderDelayUs);
            consumer->releaseBuffer(buffer.mGraphicBuffer, buffer.mFence);
        }
    }

    wp<BufferItemConsumer> mConsumer;
};

struct TestProducerListener : public android::BnProducerListener {
    TestProducerListener(std::shared_ptr<LegacyGraphicsTracker> tracker,
                         std::shared_ptr<BqStatistics>& stat, uint32_t generation)
        : BnProducerListener(), mTracker(tracker), mStat(stat), mGeneration(generation) {}
    virtual void onBufferReleased() override {
        auto tracker = mTracker.lock();
        if (tracker) {
            mStat->mReleased++;
            tracker->onReleased(mGeneration);
        }
    }
    virtual bool needsReleaseNotify() override { return true; }
    virtual void onBuffersDiscarded(const std::vector<int32_t>&) override {}

    std::weak_ptr<LegacyGraphicsTracker> mTracker;
    std::shared_ptr<BqStatistics> mStat;
    uint32_t mGeneration;
};

struct Frame {
    AHardwareBuffer* buffer_;
    sp<Fence> fence_;

    Frame() : buffer_{nullptr}, fence_{nullptr} {}
    Frame(AHardwareBuffer* buffer, sp<Fence> fence) : buffer_(buffer), fence_(fence) {}
    ~Frame() {
        if (buffer_) {
            AHardwareBuffer_release(buffer_);
        }
    }
};

struct FrameQueue {
    bool mStopped;
    bool mDrain;
    std::queue<std::shared_ptr<Frame>> mQueue;
    std::mutex mMutex;
    std::condition_variable mCond;

    FrameQueue() : mStopped{false}, mDrain{false} {}

    bool queueItem(AHardwareBuffer* buffer, sp<Fence> fence) {
        std::shared_ptr<Frame> frame = std::make_shared<Frame>(buffer, fence);
        if (mStopped) {
            return false;
        }
        if (!frame) {
            return false;
        }
        std::unique_lock<std::mutex> l(mMutex);
        mQueue.emplace(frame);
        l.unlock();
        mCond.notify_all();
        return true;
    }

    void stop(bool drain = false) {
        bool stopped = false;
        {
            std::unique_lock<std::mutex> l(mMutex);
            if (!mStopped) {
                mStopped = true;
                mDrain = drain;
                stopped = true;
            }
            l.unlock();
            if (stopped) {
                mCond.notify_all();
            }
        }
    }

    bool waitItem(std::shared_ptr<Frame>* frame) {
        while (true) {
            std::unique_lock<std::mutex> l(mMutex);
            if (!mDrain && mStopped) {
                // stop without consuming the queue.
                return false;
            }
            if (!mQueue.empty()) {
                *frame = mQueue.front();
                mQueue.pop();
                return true;
            } else if (mStopped) {
                // stop after consuming the queue.
                return false;
            }
            mCond.wait(l);
        }
    }
};

}  // namespace

class LegacyGraphicsTrackerTest : public ::testing::Test {
  public:
    const uint64_t kTestUsageFlag = GRALLOC_USAGE_SW_WRITE_OFTEN;

    void queueBuffer(FrameQueue* queue) {
        while (true) {
            std::shared_ptr<Frame> frame;
            if (!queue->waitItem(&frame)) {
                break;
            }
            uint64_t bid;
            if (__builtin_available(android __ANDROID_API_T__, *)) {
                if (AHardwareBuffer_getId(frame->buffer_, &bid) != android::NO_ERROR) {
                    break;
                }
            } else {
                break;
            }
            android::status_t ret = frame->fence_->wait(-1);
            if (ret != android::NO_ERROR) {
                mTracker->deallocate(bid, frame->fence_);
                mBqStat->mDiscarded++;
                continue;
            }

            std::shared_ptr<C2GraphicBlock> blk =
                    _C2BlockFactory::CreateGraphicBlock(frame->buffer_);
            if (!blk) {
                mTracker->deallocate(bid, Fence::NO_FENCE);
                mBqStat->mDiscarded++;
                continue;
            }
            IGraphicBufferProducer::QueueBufferInput input(
                    0, false, HAL_DATASPACE_UNKNOWN, android::Rect(0, 0, 1, 1),
                    NATIVE_WINDOW_SCALING_MODE_FREEZE, 0, Fence::NO_FENCE);
            IGraphicBufferProducer::QueueBufferOutput output{};
            c2_status_t res = mTracker->render(blk->share(C2Rect(1, 1), C2Fence()), input, &output);
            if (res != C2_OK) {
                mTracker->deallocate(bid, Fence::NO_FENCE);
                mBqStat->mDiscarded++;
                continue;
            }
            if (output.bufferReplaced) {
                mBqStat->mDropped++;
            }
            mBqStat->mQueued++;
        }
    }

    void stopTrackerAfterUs(int us) {
        ::usleep(us);
        mTracker->stop();
    }

  protected:
    bool init(int maxDequeueCount, bool controlledByApp = true) {
        mTracker = LegacyGraphicsTracker::CreateLegacyGraphicsTracker(maxDequeueCount);
        if (!mTracker) {
            return false;
        }
        sp<Surface> surface;
        std::tie(mConsumer, surface) = BufferItemConsumer::create(
                kTestUsageFlag, BufferItemConsumer::DEFAULT_MAX_BUFFERS, controlledByApp);
        mProducer = surface->getIGraphicBufferProducer();

        return true;
    }
    bool configure(sp<IProducerListener> producerListener,
                   sp<BufferItemConsumer::FrameAvailableListener> consumerListener,
                   int maxAcquiredCount = 1) {
        mConsumerListener = consumerListener;
        mConsumer->setFrameAvailableListener(mConsumerListener);
        if (mConsumer->setMaxAcquiredBufferCount(maxAcquiredCount) != ::android::NO_ERROR) {
            return false;
        }
        IGraphicBufferProducer::QueueBufferOutput qbo{};
        if (mProducer->connect(producerListener, NATIVE_WINDOW_API_MEDIA, true, &qbo) !=
            ::android::NO_ERROR) {
            return false;
        }
        if (mProducer->setDequeueTimeout(0) != ::android::NO_ERROR) {
            return false;
        }
        return true;
    }

    virtual void TearDown() override {
        mBqStat->log();
        mBqStat->clear();

        if (mTracker) {
            mTracker->stop();
            mTracker.reset();
        }
        if (mProducer) {
            mProducer->disconnect(NATIVE_WINDOW_API_MEDIA);
        }
        mProducer.clear();
        mConsumer.clear();
    }

  protected:
    std::shared_ptr<BqStatistics> mBqStat = std::make_shared<BqStatistics>();
    sp<IGraphicBufferProducer> mProducer;
    sp<BufferItemConsumer> mConsumer;
    sp<BufferItemConsumer::FrameAvailableListener> mConsumerListener;
    std::shared_ptr<LegacyGraphicsTracker> mTracker;
};

TEST_F(LegacyGraphicsTrackerTest, AllocateAndBlockedTest) {
    uint32_t generation = 1;
    const int maxDequeueCount = 10;

    ASSERT_TRUE(init(maxDequeueCount));
    ASSERT_TRUE(configure(new TestProducerListener(mTracker, mBqStat, generation),
                          new DummyConsumerListener()));

    ASSERT_EQ(OK, mProducer->setGenerationNumber(generation));
    c2_status_t ret = mTracker->configureGraphics(mProducer, generation);
    ASSERT_EQ(C2_OK, ret);
    ASSERT_EQ(maxDequeueCount, mTracker->getCurDequeueable());

    AHardwareBuffer* buf;
    sp<Fence> fence;
    uint64_t bid;

    // Allocate and check dequeueable
    if (__builtin_available(android __ANDROID_API_T__, *)) {
        for (int i = 0; i < maxDequeueCount; ++i) {
            ret = mTracker->allocate(0, 0, 0, kTestUsageFlag, &buf, &fence);
            ASSERT_EQ(C2_OK, ret);
            mBqStat->mDequeued++;
            ASSERT_EQ(maxDequeueCount - (i + 1), mTracker->getCurDequeueable());
            ASSERT_EQ(OK, AHardwareBuffer_getId(buf, &bid));
            ALOGD("alloced : bufferId: %llu", (unsigned long long)bid);
            AHardwareBuffer_release(buf);
        }
    } else {
        GTEST_SKIP();
    }

    // Allocate should be blocked
    ret = mTracker->allocate(0, 0, 0, kTestUsageFlag, &buf, &fence);
    ALOGD("alloc : err(%d, %d)", ret, C2_BLOCKING);
    ASSERT_EQ(C2_BLOCKING, ret);
    mBqStat->mBlocked++;
    ASSERT_EQ(0, mTracker->getCurDequeueable());
}

TEST_F(LegacyGraphicsTrackerTest, AllocateAndDeallocateTest) {
    uint32_t generation = 1;
    const int maxDequeueCount = 10;

    ASSERT_TRUE(init(maxDequeueCount));
    ASSERT_TRUE(configure(new TestProducerListener(mTracker, mBqStat, generation),
                          new DummyConsumerListener()));

    ASSERT_EQ(OK, mProducer->setGenerationNumber(generation));
    c2_status_t ret = mTracker->configureGraphics(mProducer, generation);
    ASSERT_EQ(C2_OK, ret);

    ASSERT_EQ(maxDequeueCount, mTracker->getCurDequeueable());
    AHardwareBuffer* buf;
    sp<Fence> fence;
    uint64_t bid;
    std::vector<uint64_t> bids;

    // Allocate and store buffer id
    if (__builtin_available(android __ANDROID_API_T__, *)) {
        for (int i = 0; i < maxDequeueCount; ++i) {
            ret = mTracker->allocate(0, 0, 0, kTestUsageFlag, &buf, &fence);
            ASSERT_EQ(C2_OK, ret);
            mBqStat->mDequeued++;
            ASSERT_EQ(OK, AHardwareBuffer_getId(buf, &bid));
            bids.push_back(bid);
            ALOGD("alloced : bufferId: %llu", (unsigned long long)bid);
            AHardwareBuffer_release(buf);
        }
    } else {
        GTEST_SKIP();
    }

    // Deallocate and check dequeueable
    for (int i = 0; i < maxDequeueCount; ++i) {
        ALOGD("dealloc : bufferId: %llu", (unsigned long long)bids[i]);
        ret = mTracker->deallocate(bids[i], Fence::NO_FENCE);
        ASSERT_EQ(C2_OK, ret);
        ASSERT_EQ(i + 1, mTracker->getCurDequeueable());
        mBqStat->mDiscarded++;
    }
}

TEST_F(LegacyGraphicsTrackerTest, DropAndReleaseTest) {
    uint32_t generation = 1;
    const int maxDequeueCount = 10;

    ASSERT_TRUE(init(maxDequeueCount));
    ASSERT_TRUE(configure(new TestProducerListener(mTracker, mBqStat, generation),
                          new DummyConsumerListener()));

    ASSERT_EQ(OK, mProducer->setGenerationNumber(generation));
    c2_status_t ret = mTracker->configureGraphics(mProducer, generation);
    ASSERT_EQ(C2_OK, ret);

    ASSERT_EQ(maxDequeueCount, mTracker->getCurDequeueable());

    FrameQueue frameQueue;
    std::thread queueThread(&LegacyGraphicsTrackerTest::queueBuffer, this, &frameQueue);
    AHardwareBuffer *buf1, *buf2;
    sp<Fence> fence1, fence2;

    ret = mTracker->allocate(0, 0, 0, kTestUsageFlag, &buf1, &fence1);
    ASSERT_EQ(C2_OK, ret);
    mBqStat->mDequeued++;
    ASSERT_EQ(maxDequeueCount - 1, mTracker->getCurDequeueable());

    ret = mTracker->allocate(0, 0, 0, kTestUsageFlag, &buf2, &fence2);
    ASSERT_EQ(C2_OK, ret);
    mBqStat->mDequeued++;
    ASSERT_EQ(maxDequeueCount - 2, mTracker->getCurDequeueable());

    // Queue two buffers without consuming, one should be dropped
    ASSERT_TRUE(frameQueue.queueItem(buf1, fence1));
    ASSERT_TRUE(frameQueue.queueItem(buf2, fence2));

    frameQueue.stop(true);
    if (queueThread.joinable()) {
        queueThread.join();
    }

    ASSERT_EQ(maxDequeueCount - 1, mTracker->getCurDequeueable());

    // Consume one buffer and release
    BufferItem item;
    ASSERT_EQ(OK, mConsumer->acquireBuffer(&item, 0));
    ASSERT_EQ(OK, mConsumer->releaseBuffer(item.mGraphicBuffer, item.mFence));

    // Nothing to consume
    ASSERT_NE(OK, mConsumer->acquireBuffer(&item, 0));

    ASSERT_EQ(maxDequeueCount, mTracker->getCurDequeueable());
    ASSERT_EQ(1, mBqStat->mReleased);
    ASSERT_EQ(1, mBqStat->mDropped);
}

TEST_F(LegacyGraphicsTrackerTest, RenderTest) {
    uint32_t generation = 1;
    const int maxDequeueCount = 10;
    const int maxNumAlloc = 20;

    ASSERT_TRUE(init(maxDequeueCount, /*controlledByApp=*/false));
    ASSERT_TRUE(configure(new TestProducerListener(mTracker, mBqStat, generation),
                          new TestConsumerListener(mConsumer), 1));

    ASSERT_EQ(OK, mProducer->setGenerationNumber(generation));

    ASSERT_EQ(C2_OK, mTracker->configureGraphics(mProducer, generation));
    ASSERT_EQ(C2_OK, mTracker->configureMaxDequeueCount(maxDequeueCount));

    int waitFd = -1;
    ASSERT_EQ(C2_OK, mTracker->getWaitableFd(&waitFd));
    C2Fence waitFence = _C2FenceFactory::CreatePipeFence(waitFd);

    FrameQueue frameQueue;
    std::thread queueThread(&LegacyGraphicsTrackerTest::queueBuffer, this, &frameQueue);

    int numAlloc = 0;

    while (numAlloc < maxNumAlloc) {
        AHardwareBuffer* buf;
        sp<Fence> fence;
        c2_status_t ret = mTracker->allocate(0, 0, 0, kTestUsageFlag, &buf, &fence);
        if (ret == C2_BLOCKING) {
            mBqStat->mBlocked++;
            c2_status_t waitRes = waitFence.wait(3000000000);
            if (waitRes == C2_TIMED_OUT || waitRes == C2_OK) {
                continue;
            }
            ALOGE("alloc wait failed: c2_err(%d)", waitRes);
            break;
        }
        if (ret != C2_OK) {
            ALOGE("alloc error: c2_err(%d)", ret);
            break;
        }
        mBqStat->mDequeued++;
        if (!frameQueue.queueItem(buf, fence)) {
            ALOGE("queue to render failed");
            break;
        }
        ++numAlloc;
    }

    frameQueue.stop(true);
    // Wait more than enough time(1 sec) to render all queued frames for sure.
    ::usleep(1000000);

    if (queueThread.joinable()) {
        queueThread.join();
    }
    ASSERT_EQ(numAlloc, maxNumAlloc);
    ASSERT_EQ(numAlloc, mBqStat->mDequeued);
    ASSERT_EQ(mBqStat->mDequeued, mBqStat->mQueued);
    ASSERT_EQ(mBqStat->mDequeued, mBqStat->mReleased + mBqStat->mDropped);
}

TEST_F(LegacyGraphicsTrackerTest, StopAndWaitTest) {
    uint32_t generation = 1;
    const int maxDequeueCount = 2;

    ASSERT_TRUE(init(maxDequeueCount, /*controlledByApp=*/false));
    ASSERT_TRUE(configure(new TestProducerListener(mTracker, mBqStat, generation),
                          new TestConsumerListener(mConsumer), 1));

    ASSERT_EQ(OK, mProducer->setGenerationNumber(generation));

    ASSERT_EQ(C2_OK, mTracker->configureGraphics(mProducer, generation));
    ASSERT_EQ(C2_OK, mTracker->configureMaxDequeueCount(maxDequeueCount));

    int waitFd = -1;
    ASSERT_EQ(C2_OK, mTracker->getWaitableFd(&waitFd));
    C2Fence waitFence = _C2FenceFactory::CreatePipeFence(waitFd);

    AHardwareBuffer *buf1, *buf2;
    sp<Fence> fence;

    ASSERT_EQ(C2_OK, mTracker->allocate(0, 0, 0, kTestUsageFlag, &buf1, &fence));
    mBqStat->mDequeued++;
    AHardwareBuffer_release(buf1);

    ASSERT_EQ(C2_OK, mTracker->allocate(0, 0, 0, kTestUsageFlag, &buf2, &fence));
    mBqStat->mDequeued++;
    AHardwareBuffer_release(buf2);

    ASSERT_EQ(0, mTracker->getCurDequeueable());
    ASSERT_EQ(C2_TIMED_OUT, waitFence.wait(3000000000));

    std::thread stopThread(&LegacyGraphicsTrackerTest::stopTrackerAfterUs, this, 500000);
    ASSERT_EQ(C2_BAD_STATE, waitFence.wait(3000000000));

    if (stopThread.joinable()) {
        stopThread.join();
    }
}

TEST_F(LegacyGraphicsTrackerTest, SurfaceChangeTest) {
    uint32_t generation = 1;
    const int maxDequeueCount = 10;

    const int maxNumAlloc = 20;

    const int firstPassAlloc = 12;
    const int firstPassRender = 8;

    ASSERT_TRUE(init(maxDequeueCount, /*controlledByApp=*/false));
    ASSERT_TRUE(configure(new TestProducerListener(mTracker, mBqStat, generation),
                          new TestConsumerListener(mConsumer), 1));

    ASSERT_EQ(OK, mProducer->setGenerationNumber(generation));

    ASSERT_EQ(C2_OK, mTracker->configureGraphics(mProducer, generation));
    ASSERT_EQ(C2_OK, mTracker->configureMaxDequeueCount(maxDequeueCount));

    int waitFd = -1;
    ASSERT_EQ(C2_OK, mTracker->getWaitableFd(&waitFd));
    C2Fence waitFence = _C2FenceFactory::CreatePipeFence(waitFd);

    AHardwareBuffer* bufs[maxNumAlloc];
    sp<Fence> fences[maxNumAlloc];

    FrameQueue frameQueue;
    std::thread queueThread(&LegacyGraphicsTrackerTest::queueBuffer, this, &frameQueue);
    int numAlloc = 0;

    for (int i = 0; i < firstPassRender; ++i) {
        ASSERT_EQ(C2_OK, mTracker->allocate(0, 0, 0, kTestUsageFlag, &bufs[i], &fences[i]));
        mBqStat->mDequeued++;
        numAlloc++;
        ASSERT_EQ(true, frameQueue.queueItem(bufs[i], fences[i]));
    }

    while (numAlloc < firstPassAlloc) {
        c2_status_t ret =
                mTracker->allocate(0, 0, 0, kTestUsageFlag, &bufs[numAlloc], &fences[numAlloc]);
        if (ret == C2_BLOCKING) {
            mBqStat->mBlocked++;
            c2_status_t waitRes = waitFence.wait(3000000000);
            if (waitRes == C2_TIMED_OUT || waitRes == C2_OK) {
                continue;
            }
            ALOGE("alloc wait failed: c2_err(%d)", waitRes);
            break;
        }
        if (ret != C2_OK) {
            ALOGE("alloc error: c2_err(%d)", ret);
            break;
        }
        mBqStat->mDequeued++;
        numAlloc++;
    }
    ASSERT_EQ(numAlloc, firstPassAlloc);

    // switching surface
    sp<IGraphicBufferProducer> oldProducer = mProducer;
    sp<BufferItemConsumer> oldConsumer = mConsumer;
    sp<BufferItemConsumer::FrameAvailableListener> oldConsumerListener = mConsumerListener;
    mProducer.clear();
    mConsumer.clear();
    sp<Surface> surface;
    std::tie(mConsumer, surface) = BufferItemConsumer::create(
            kTestUsageFlag, BufferItemConsumer::DEFAULT_MAX_BUFFERS, /*controlledByApp=*/false);
    mProducer = surface->getIGraphicBufferProducer();

    generation += 1;

    ASSERT_TRUE(configure(new TestProducerListener(mTracker, mBqStat, generation),
                          new TestConsumerListener(mConsumer), 1));
    ASSERT_EQ(OK, mProducer->setGenerationNumber(generation));
    ASSERT_EQ(C2_OK, mTracker->configureGraphics(mProducer, generation));
    ASSERT_EQ(C2_OK, mTracker->configureMaxDequeueCount(maxDequeueCount));

    ASSERT_EQ(OK, oldProducer->disconnect(NATIVE_WINDOW_API_MEDIA));
    oldProducer.clear();
    oldConsumer.clear();

    for (int i = firstPassRender; i < firstPassAlloc; ++i) {
        ASSERT_EQ(true, frameQueue.queueItem(bufs[i], fences[i]));
    }

    while (numAlloc < maxNumAlloc) {
        AHardwareBuffer* buf;
        sp<Fence> fence;
        c2_status_t ret = mTracker->allocate(0, 0, 0, kTestUsageFlag, &buf, &fence);
        if (ret == C2_BLOCKING) {
            mBqStat->mBlocked++;
            c2_status_t waitRes = waitFence.wait(3000000000);
            if (waitRes == C2_TIMED_OUT || waitRes == C2_OK) {
                continue;
            }
            ALOGE("alloc wait failed: c2_err(%d)", waitRes);
            break;
        }
        if (ret != C2_OK) {
            ALOGE("alloc error: c2_err(%d)", ret);
            break;
        }
        mBqStat->mDequeued++;
        if (!frameQueue.queueItem(buf, fence)) {
            ALOGE("queue to render failed");
            break;
        }
        ++numAlloc;
    }

    ASSERT_EQ(numAlloc, maxNumAlloc);

    frameQueue.stop(true);
    // Wait more than enough time(1 sec) to render all queued frames for sure.
    ::usleep(1000000);

    if (queueThread.joinable()) {
        queueThread.join();
    }
    // mReleased should not be checked. IProducerListener::onBufferReleased()
    // from the previous Surface could be missing after a new Surface was
    // configured. Instead check # of dequeueable and queueBuffer() calls.
    ASSERT_EQ(numAlloc, mBqStat->mQueued);
    ASSERT_EQ(maxDequeueCount, mTracker->getCurDequeueable());

    for (int i = 0; i < maxDequeueCount; ++i) {
        AHardwareBuffer* buf;
        sp<Fence> fence;

        ASSERT_EQ(C2_OK, mTracker->allocate(0, 0, 0, kTestUsageFlag, &buf, &fence));
        AHardwareBuffer_release(buf);
        mBqStat->mDequeued++;
        numAlloc++;
    }
    ASSERT_EQ(C2_BLOCKING, mTracker->allocate(0, 0, 0, kTestUsageFlag, &bufs[0], &fences[0]));
}

TEST_F(LegacyGraphicsTrackerTest, maxDequeueIncreaseTest) {
    uint32_t generation = 1;
    int maxDequeueCount = 10;
    int dequeueIncrease = 4;

    int numAlloc = 0;

    ASSERT_TRUE(init(maxDequeueCount, /*controlledByApp=*/false));
    ASSERT_TRUE(configure(new TestProducerListener(mTracker, mBqStat, generation),
                          new TestConsumerListener(mConsumer), 1));

    ASSERT_EQ(OK, mProducer->setGenerationNumber(generation));
    ASSERT_EQ(C2_OK, mTracker->configureGraphics(mProducer, generation));

    int waitFd = -1;
    ASSERT_EQ(C2_OK, mTracker->getWaitableFd(&waitFd));
    C2Fence waitFence = _C2FenceFactory::CreatePipeFence(waitFd);

    AHardwareBuffer* buf;
    sp<Fence> fence;
    uint64_t bids[maxDequeueCount];
    if (__builtin_available(android __ANDROID_API_T__, *)) {
        for (int i = 0; i < maxDequeueCount; ++i) {
            ASSERT_EQ(C2_OK, waitFence.wait(1000000000));
            ASSERT_EQ(C2_OK, mTracker->allocate(0, 0, 0, kTestUsageFlag, &buf, &fence));
            ASSERT_EQ(OK, AHardwareBuffer_getId(buf, &bids[i]));
            AHardwareBuffer_release(buf);
            mBqStat->mDequeued++;
            numAlloc++;
        }
    } else {
        GTEST_SKIP();
    }
    ASSERT_EQ(C2_TIMED_OUT, waitFence.wait(1000000000));
    ASSERT_EQ(C2_BLOCKING, mTracker->allocate(0, 0, 0, kTestUsageFlag, &buf, &fence));

    ASSERT_EQ(C2_OK, mTracker->deallocate(bids[0], Fence::NO_FENCE));
    mBqStat->mDiscarded++;

    maxDequeueCount += dequeueIncrease;
    ASSERT_EQ(C2_OK, mTracker->configureMaxDequeueCount(maxDequeueCount));
    for (int i = 0; i < dequeueIncrease + 1; ++i) {
        ASSERT_EQ(C2_OK, waitFence.wait(1000000000));
        ASSERT_EQ(C2_OK, mTracker->allocate(0, 0, 0, kTestUsageFlag, &buf, &fence));
        AHardwareBuffer_release(buf);
        mBqStat->mDequeued++;
        numAlloc++;
    }
    ASSERT_EQ(C2_TIMED_OUT, waitFence.wait(1000000000));
    ASSERT_EQ(C2_BLOCKING, mTracker->allocate(0, 0, 0, kTestUsageFlag, &buf, &fence));

    ASSERT_EQ(C2_OK, mTracker->deallocate(bids[1], Fence::NO_FENCE));
    mBqStat->mDiscarded++;

    maxDequeueCount += dequeueIncrease;
    ASSERT_EQ(C2_OK, mTracker->configureMaxDequeueCount(maxDequeueCount));
    for (int i = 0; i < dequeueIncrease + 1; ++i) {
        ASSERT_EQ(C2_OK, waitFence.wait(1000000000));
        ASSERT_EQ(C2_OK, mTracker->allocate(0, 0, 0, kTestUsageFlag, &buf, &fence));
        AHardwareBuffer_release(buf);
        mBqStat->mDequeued++;
        numAlloc++;
    }
    ASSERT_EQ(C2_TIMED_OUT, waitFence.wait(1000000000));
    ASSERT_EQ(C2_BLOCKING, mTracker->allocate(0, 0, 0, kTestUsageFlag, &buf, &fence));
}

TEST_F(LegacyGraphicsTrackerTest, maxDequeueDecreaseTest) {
    uint32_t generation = 1;
    int maxDequeueCount = 12;
    int dequeueDecrease = 4;

    int numAlloc = 0;

    ASSERT_TRUE(init(maxDequeueCount, /*controlledByApp=*/false));
    ASSERT_TRUE(configure(new TestProducerListener(mTracker, mBqStat, generation),
                          new TestConsumerListener(mConsumer), 1));

    ASSERT_EQ(OK, mProducer->setGenerationNumber(generation));
    ASSERT_EQ(C2_OK, mTracker->configureGraphics(mProducer, generation));

    int waitFd = -1;
    ASSERT_EQ(C2_OK, mTracker->getWaitableFd(&waitFd));
    C2Fence waitFence = _C2FenceFactory::CreatePipeFence(waitFd);

    AHardwareBuffer* buf;
    sp<Fence> fence;
    uint64_t bids[maxDequeueCount];
    if (__builtin_available(android __ANDROID_API_T__, *)) {
        for (int i = 0; i < maxDequeueCount; ++i) {
            ASSERT_EQ(C2_OK, waitFence.wait(1000000000));
            ASSERT_EQ(C2_OK, mTracker->allocate(0, 0, 0, kTestUsageFlag, &buf, &fence));
            ASSERT_EQ(OK, AHardwareBuffer_getId(buf, &bids[i]));
            AHardwareBuffer_release(buf);
            mBqStat->mDequeued++;
            numAlloc++;
        }
    } else {
        GTEST_SKIP();
    }
    ASSERT_EQ(C2_TIMED_OUT, waitFence.wait(1000000000));
    ASSERT_EQ(C2_BLOCKING, mTracker->allocate(0, 0, 0, kTestUsageFlag, &buf, &fence));

    int discardIdx = 0;
    maxDequeueCount -= dequeueDecrease;
    ASSERT_EQ(C2_OK, mTracker->configureMaxDequeueCount(maxDequeueCount));
    for (int i = 0; i < dequeueDecrease + 1; ++i) {
        ASSERT_EQ(C2_TIMED_OUT, waitFence.wait(1000000000));
        ASSERT_EQ(C2_BLOCKING, mTracker->allocate(0, 0, 0, kTestUsageFlag, &buf, &fence));
        ASSERT_EQ(C2_OK, mTracker->deallocate(bids[discardIdx++], Fence::NO_FENCE));
        mBqStat->mDiscarded++;
    }
    ASSERT_EQ(C2_OK, waitFence.wait(1000000000));
    ASSERT_EQ(C2_OK, mTracker->allocate(0, 0, 0, kTestUsageFlag, &buf, &fence));
    mBqStat->mDequeued++;

    ASSERT_EQ(C2_OK, mTracker->deallocate(bids[discardIdx++], Fence::NO_FENCE));
    mBqStat->mDiscarded++;
    ASSERT_EQ(C2_OK, mTracker->deallocate(bids[discardIdx++], Fence::NO_FENCE));
    mBqStat->mDiscarded++;
    maxDequeueCount -= dequeueDecrease;

    ASSERT_EQ(C2_OK, mTracker->configureMaxDequeueCount(maxDequeueCount));
    for (int i = 0; i < dequeueDecrease - 1; ++i) {
        ASSERT_EQ(C2_TIMED_OUT, waitFence.wait(1000000000));
        ASSERT_EQ(C2_BLOCKING, mTracker->allocate(0, 0, 0, kTestUsageFlag, &buf, &fence));
        ASSERT_EQ(C2_OK, mTracker->deallocate(bids[discardIdx++], Fence::NO_FENCE));
        mBqStat->mDiscarded++;
    }
    ASSERT_EQ(C2_OK, waitFence.wait(1000000000));
    ASSERT_EQ(C2_OK, mTracker->allocate(0, 0, 0, kTestUsageFlag, &buf, &fence));
    mBqStat->mDequeued++;
}

TEST_F(LegacyGraphicsTrackerTest, DirectAllocationTest) {
    int maxDequeueCount = 10;
    mTracker = LegacyGraphicsTracker::CreateLegacyGraphicsTracker(maxDequeueCount);
    ASSERT_NE(nullptr, mTracker);

    // Configure with null IGBP for direct allocation
    ASSERT_EQ(C2_OK, mTracker->configureGraphics(nullptr, 1));

    AHardwareBuffer* buf;
    sp<Fence> fence;
    uint64_t bid;

    if (__builtin_available(android __ANDROID_API_T__, *)) {
        // Direct allocation
        ASSERT_EQ(C2_OK, mTracker->allocate(640, 480, HAL_PIXEL_FORMAT_RGBA_8888, kTestUsageFlag,
                                            &buf, &fence));
        ASSERT_NE(nullptr, buf);
        ASSERT_EQ(OK, AHardwareBuffer_getId(buf, &bid));

        // Render should fail because there is no surface
        // Note: requestRender() on a null surface (direct allocation mode) actively removes
        // the buffer from tracking (reclaims it) and returns C2_BAD_STATE.
        std::shared_ptr<C2GraphicBlock> blk = _C2BlockFactory::CreateGraphicBlock(buf);
        IGraphicBufferProducer::QueueBufferInput input(
                0, false, HAL_DATASPACE_UNKNOWN, android::Rect(0, 0, 1, 1),
                NATIVE_WINDOW_SCALING_MODE_FREEZE, 0, Fence::NO_FENCE);
        IGraphicBufferProducer::QueueBufferOutput output{};
        ASSERT_EQ(C2_BAD_STATE,
                  mTracker->render(blk->share(C2Rect(640, 480), C2Fence()), input, &output));

        // Buffer should be already removed from tracking by render()
        ASSERT_EQ(maxDequeueCount, mTracker->getCurDequeueable());
        ASSERT_EQ(C2_NOT_FOUND, mTracker->deallocate(bid, Fence::NO_FENCE));

        AHardwareBuffer_release(buf);
    }
}

TEST_F(LegacyGraphicsTrackerTest, ConfigureSameGenerationTest) {
    uint32_t generation = 1;
    const int maxDequeueCount = 10;
    ASSERT_TRUE(init(maxDequeueCount));
    ASSERT_TRUE(configure(new TestProducerListener(mTracker, mBqStat, generation),
                          new DummyConsumerListener()));

    ASSERT_EQ(C2_OK, mTracker->configureGraphics(mProducer, generation));
    // Same generation should fail
    ASSERT_EQ(C2_BAD_VALUE, mTracker->configureGraphics(mProducer, generation));
}

TEST_F(LegacyGraphicsTrackerTest, MaxDequeueBoundsTest) {
    const int maxDequeueCount = 10;
    ASSERT_TRUE(init(maxDequeueCount));

    ASSERT_EQ(C2_BAD_VALUE, mTracker->configureMaxDequeueCount(0));  // Too small
    ASSERT_EQ(C2_BAD_VALUE, mTracker->configureMaxDequeueCount(
                                    ::android::BufferQueueDefs::NUM_BUFFER_SLOTS));  // Too large
    ASSERT_EQ(C2_OK, mTracker->configureMaxDequeueCount(5));                         // Valid
}

TEST_F(LegacyGraphicsTrackerTest, DeallocateInvalidIdTest) {
    const int maxDequeueCount = 10;
    ASSERT_TRUE(init(maxDequeueCount));
    ASSERT_TRUE(
            configure(new TestProducerListener(mTracker, mBqStat, 1), new DummyConsumerListener()));
    ASSERT_EQ(C2_OK, mTracker->configureGraphics(mProducer, 1));

    uint64_t invalidId = 0xFFFFFFFFFFFFFFFF;
    ASSERT_EQ(C2_NOT_FOUND, mTracker->deallocate(invalidId, Fence::NO_FENCE));
}

TEST_F(LegacyGraphicsTrackerTest, DoubleDeallocateTest) {
    uint32_t generation = 1;
    const int maxDequeueCount = 10;
    ASSERT_TRUE(init(maxDequeueCount));
    ASSERT_TRUE(configure(new TestProducerListener(mTracker, mBqStat, generation),
                          new DummyConsumerListener()));
    ASSERT_EQ(C2_OK, mTracker->configureGraphics(mProducer, generation));

    AHardwareBuffer* buf;
    sp<Fence> fence;
    uint64_t bid;

    if (__builtin_available(android __ANDROID_API_T__, *)) {
        ASSERT_EQ(C2_OK, mTracker->allocate(0, 0, 0, kTestUsageFlag, &buf, &fence));
        ASSERT_EQ(OK, AHardwareBuffer_getId(buf, &bid));

        ASSERT_EQ(C2_OK, mTracker->deallocate(bid, Fence::NO_FENCE));
        ASSERT_EQ(C2_NOT_FOUND, mTracker->deallocate(bid, Fence::NO_FENCE));  // Double free

        AHardwareBuffer_release(buf);
    }
}

TEST_F(LegacyGraphicsTrackerTest, OnRequestStopTest) {
    uint32_t generation = 1;
    const int maxDequeueCount = 10;
    ASSERT_TRUE(init(maxDequeueCount));
    ASSERT_TRUE(configure(new TestProducerListener(mTracker, mBqStat, generation),
                          new DummyConsumerListener()));
    ASSERT_EQ(C2_OK, mTracker->configureGraphics(mProducer, generation));

    mTracker->onRequestStop();

    // Allocation should still succeed (via PlaceHolderSurface)
    AHardwareBuffer* buf;
    sp<Fence> fence;
    if (__builtin_available(android __ANDROID_API_T__, *)) {
        ASSERT_EQ(C2_OK, mTracker->allocate(640, 480, HAL_PIXEL_FORMAT_RGBA_8888, kTestUsageFlag,
                                            &buf, &fence));
        ASSERT_NE(nullptr, buf);
        AHardwareBuffer_release(buf);
    }
}

TEST_F(LegacyGraphicsTrackerTest, WaitableFdSignalingTest) {
    uint32_t generation = 1;
    const int maxDequeueCount = 2;  // Small count to easily exhaust
    ASSERT_TRUE(init(maxDequeueCount));
    ASSERT_TRUE(configure(new TestProducerListener(mTracker, mBqStat, generation),
                          new DummyConsumerListener()));
    ASSERT_EQ(C2_OK, mTracker->configureGraphics(mProducer, generation));
    ASSERT_EQ(C2_OK, mTracker->configureMaxDequeueCount(maxDequeueCount));

    int pipeFd = -1;
    ASSERT_EQ(C2_OK, mTracker->getWaitableFd(&pipeFd));
    ASSERT_GE(pipeFd, 0);

    AHardwareBuffer *buf1, *buf2;
    sp<Fence> fence;

    // Allocate all available buffers
    if (__builtin_available(android __ANDROID_API_T__, *)) {
        ASSERT_EQ(C2_OK, mTracker->allocate(0, 0, 0, kTestUsageFlag, &buf1, &fence));
        ASSERT_EQ(C2_OK, mTracker->allocate(0, 0, 0, kTestUsageFlag, &buf2, &fence));

        struct pollfd pfd;
        pfd.fd = pipeFd;
        pfd.events = POLLIN;
        int ret = poll(&pfd, 1, 0);  // Non-blocking check
        ASSERT_EQ(0, ret);           // Should be 0 (timeout, no data)

        // Deallocate one
        uint64_t bid;
        AHardwareBuffer_getId(buf1, &bid);
        mTracker->deallocate(bid, Fence::NO_FENCE);

        // Now FD SHOULD be readable
        ret = poll(&pfd, 1, 1000);
        ASSERT_GT(ret, 0);
        ASSERT_TRUE(pfd.revents & POLLIN);

        AHardwareBuffer_release(buf1);
        AHardwareBuffer_release(buf2);
    }
    close(pipeFd);
}

TEST_F(LegacyGraphicsTrackerTest, StopIdempotencyTest) {
    int maxDequeueCount = 10;
    mTracker = LegacyGraphicsTracker::CreateLegacyGraphicsTracker(maxDequeueCount);
    ASSERT_NE(nullptr, mTracker);

    mTracker->stop();
    mTracker->stop();  // Should not crash

    // Verify allocate fails after stop
    AHardwareBuffer* buf;
    sp<Fence> fence;
    ASSERT_EQ(C2_BAD_STATE, mTracker->allocate(0, 0, 0, kTestUsageFlag, &buf, &fence));
}

TEST_F(LegacyGraphicsTrackerTest, PollForRenderedFramesTest) {
    uint32_t generation = 1;
    const int maxDequeueCount = 10;
    ASSERT_TRUE(init(maxDequeueCount));
    ASSERT_TRUE(configure(new TestProducerListener(mTracker, mBqStat, generation),
                          new DummyConsumerListener()));
    ASSERT_EQ(C2_OK, mTracker->configureGraphics(mProducer, generation));

    // Just verify it doesn't crash on valid or empty call
    android::FrameEventHistoryDelta delta;
    mTracker->pollForRenderedFrames(&delta);
}
