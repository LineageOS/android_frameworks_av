/*
 * Copyright (C) 2024 The Android Open Source Project
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

#define LOG_TAG "Camera3StreamSplitterTest"
// #define LOG_NDEBUG 0

#include <android/hardware_buffer.h>
#include <com_android_graphics_libgui_flags.h>
#include <com_android_internal_camera_flags.h>
#include <gui/BufferItemConsumer.h>
#include <gui/IGraphicBufferConsumer.h>
#include <gui/Surface.h>
#include <ui/Fence.h>
#include <ui/GraphicBuffer.h>
#include <ui/GraphicBufferAllocator.h>
#include <ui/PixelFormat.h>

#include <system/window.h>
#include <vndk/window.h>

#include <gtest/gtest.h>

#include "../device3/Flags.h"

#if USE_NEW_STREAM_SPLITTER
#include "../device3/Camera3StreamSplitter.h"
#else
#include "../device3/deprecated/DeprecatedCamera3StreamSplitter.h"
#endif  // USE_NEW_STREAM_SPLITTER

using namespace android;

namespace {

uint64_t kConsumerUsage = AHARDWAREBUFFER_USAGE_CAMERA_READ;
uint64_t kProducerUsage = AHARDWAREBUFFER_USAGE_CAMERA_READ;
size_t kHalMaxBuffers = 3;
uint32_t kWidth = 640;
uint32_t kHeight = 480;
PixelFormat kFormat = HAL_PIXEL_FORMAT_YCBCR_420_888;
int64_t kDynamicRangeProfile = 0;

std::tuple<sp<BufferItemConsumer>, sp<Surface>> createConsumerAndSurface() {
    return BufferItemConsumer::create(kConsumerUsage);
}

class Camera3StreamSplitterTest : public testing::Test {
  public:
    void SetUp() override {
#if USE_NEW_STREAM_SPLITTER
        mSplitter = sp<Camera3StreamSplitter>::make();
#else
        mSplitter = sp<DeprecatedCamera3StreamSplitter>::make();
#endif  // USE_NEW_STREAM_SPLITTER
    }

  protected:
#if USE_NEW_STREAM_SPLITTER
    sp<Camera3StreamSplitter> mSplitter;
#else
    sp<DeprecatedCamera3StreamSplitter> mSplitter;
#endif  // USE_NEW_STREAM_SPLITTER
};

class TestSurfaceListener : public SurfaceListener {
  public:
    virtual void onBufferReleased() override { mNumBuffersReleased++; }
    virtual bool needsReleaseNotify() { return true; }
    virtual void onBufferDetached(uint64_t) override {}
    virtual void onBuffersDiscarded(const std::vector<sp<GraphicBuffer>>&) override {};

    uint32_t mNumBuffersReleased = 0;
};

class TestConsumerListener : public BufferItemConsumer::FrameAvailableListener {
  public:
    TestConsumerListener(const wp<BufferItemConsumer>& consumer) : mConsumer(consumer) {}

    virtual void onFrameAvailable(const BufferItem&) {
        sp<BufferItemConsumer> consumer = mConsumer.promote();
        EXPECT_NE(nullptr, consumer);

        BufferItem item;
        EXPECT_EQ(OK, consumer->acquireBuffer(&item, 0));
        mNumBuffersAcquired++;
        EXPECT_EQ(OK, consumer->releaseBuffer(item, Fence::NO_FENCE));
    }
    virtual void onFrameReplaced(const BufferItem&) {}
    virtual void onFrameDequeued(const uint64_t) {}
    virtual void onFrameCancelled(const uint64_t) {}
    virtual void onFrameDetached(const uint64_t) {}

    wp<BufferItemConsumer> mConsumer;
    uint32_t mNumBuffersAcquired = 0;
};

}  // namespace

TEST_F(Camera3StreamSplitterTest, WithoutSurfaces_NoBuffersConsumed) {
    sp<Surface> consumer;
    EXPECT_EQ(OK, mSplitter->connect({}, kConsumerUsage, kProducerUsage, kHalMaxBuffers, kWidth,
                                     kHeight, kFormat, &consumer, kDynamicRangeProfile));

    sp<TestSurfaceListener> surfaceListener = sp<TestSurfaceListener>::make();
    EXPECT_EQ(OK, consumer->connect(NATIVE_WINDOW_API_CAMERA, surfaceListener, false));

    sp<GraphicBuffer> buffer = new GraphicBuffer(kWidth, kHeight, kFormat, kProducerUsage);
    EXPECT_EQ(OK, consumer->attachBuffer(buffer->getNativeBuffer()));
    // TODO: Do this with the surface itself once the API is available.
    EXPECT_EQ(OK,
              ANativeWindow_queueBuffer(consumer.get(), buffer->getNativeBuffer(), /*fenceFd*/ -1));

    EXPECT_EQ(0u, surfaceListener->mNumBuffersReleased);
}

TEST_F(Camera3StreamSplitterTest, TestProcessSingleBuffer) {
    //
    // Set up output consumers:
    //
    constexpr auto kSurfaceId1 = 1;
    auto [bufferItemConsumer1, surface1] = createConsumerAndSurface();
    sp<TestConsumerListener> consumerListener1 =
            sp<TestConsumerListener>::make(bufferItemConsumer1);
    bufferItemConsumer1->setFrameAvailableListener(consumerListener1);

    constexpr auto kSurfaceId2 = 2;
    auto [bufferItemConsumer2, surface2] = createConsumerAndSurface();
    sp<TestConsumerListener> consumerListener2 =
            sp<TestConsumerListener>::make(bufferItemConsumer2);
    bufferItemConsumer2->setFrameAvailableListener(consumerListener2);

    //
    // Connect it to the splitter, get the input surface, and set it up:
    //
    sp<Surface> inputSurface;
    EXPECT_EQ(OK, mSplitter->connect({{kSurfaceId1, surface1}, {kSurfaceId2, surface2}},
                                     kConsumerUsage, kProducerUsage, kHalMaxBuffers, kWidth,
                                     kHeight, kFormat, &inputSurface, kDynamicRangeProfile));
    sp<TestSurfaceListener> surfaceListener = sp<TestSurfaceListener>::make();
    EXPECT_EQ(OK, inputSurface->connect(NATIVE_WINDOW_API_CAMERA, surfaceListener, false));
    EXPECT_EQ(OK, inputSurface->allowAllocation(false));

    //
    // Create a buffer to use:
    //
    sp<GraphicBuffer> singleBuffer = new GraphicBuffer(kWidth, kHeight, kFormat, kProducerUsage);
    EXPECT_NE(nullptr, singleBuffer);
    mSplitter->attachBufferToOutputs(singleBuffer->getNativeBuffer(), {kSurfaceId1, kSurfaceId2});

    //
    // Verify that when we attach the buffer, it's processed appropriately:
    //
    EXPECT_EQ(OK, inputSurface->attachBuffer(singleBuffer->getNativeBuffer()));
    EXPECT_EQ(OK, mSplitter->getOnFrameAvailableResult());
    // TODO: Do this with the surface itself once the API is available.
    EXPECT_EQ(OK, ANativeWindow_queueBuffer(inputSurface.get(), singleBuffer->getNativeBuffer(),
                                            /*fenceFd*/ -1));

    EXPECT_EQ(1u, consumerListener1->mNumBuffersAcquired);
    EXPECT_EQ(1u, consumerListener2->mNumBuffersAcquired);
    EXPECT_EQ(1u, surfaceListener->mNumBuffersReleased);
}

TEST_F(Camera3StreamSplitterTest, AddingSameBufferManyTimes) {
    //
    // Set up output consumers:
    //
    constexpr auto kSurfaceId1 = 1;
    auto [bufferItemConsumer1, surface1] = createConsumerAndSurface();
    sp<TestConsumerListener> consumerListener1 =
            sp<TestConsumerListener>::make(bufferItemConsumer1);
    bufferItemConsumer1->setFrameAvailableListener(consumerListener1);

    constexpr auto kSurfaceId2 = 2;
    auto [bufferItemConsumer2, surface2] = createConsumerAndSurface();
    sp<TestConsumerListener> consumerListener2 =
            sp<TestConsumerListener>::make(bufferItemConsumer2);
    bufferItemConsumer2->setFrameAvailableListener(consumerListener2);

    //
    // Connect it to the splitter, get the input surface, and set it up:
    //
    sp<Surface> inputSurface;
    EXPECT_EQ(OK, mSplitter->connect({{kSurfaceId1, surface1}, {kSurfaceId2, surface2}},
                                     kConsumerUsage, kProducerUsage, kHalMaxBuffers, kWidth,
                                     kHeight, kFormat, &inputSurface, kDynamicRangeProfile));
    sp<TestSurfaceListener> surfaceListener = sp<TestSurfaceListener>::make();
    EXPECT_EQ(OK, inputSurface->connect(NATIVE_WINDOW_API_CAMERA, surfaceListener, false));
    // TODO: Do this with the surface itself once the API is available.
    EXPECT_EQ(OK, inputSurface->allowAllocation(false));

    //
    // Create a buffer to use:
    //
    sp<GraphicBuffer> singleBuffer = new GraphicBuffer(kWidth, kHeight, kFormat, kProducerUsage);
    EXPECT_NE(nullptr, singleBuffer);

    //
    // When we attach the same buffer multiple times, it shouldn't be attached if it had been
    // already.
    //
    for (int i = 0; i < 1000; i++) {
        EXPECT_EQ(OK, mSplitter->attachBufferToOutputs(singleBuffer->getNativeBuffer(),
                                                       {kSurfaceId1, kSurfaceId2}));
    }
}
