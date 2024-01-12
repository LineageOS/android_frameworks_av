/*
 * Copyright 2018 The Android Open Source Project
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

#include <android/hidl/token/1.0/ITokenManager.h>
#include <android/hidl/manager/1.2/IServiceManager.h>
#include <gtest/gtest.h>
#include <hidl/ServiceManagement.h>
#include <media/NdkImageReader.h>
#include <media/NdkImage.h>
#include <mediautils/AImageReaderUtils.h>
#include <gui/IGraphicBufferProducer.h>
#include <gui/Surface.h>
#include <gui/bufferqueue/1.0/H2BGraphicBufferProducer.h>
#include <NdkImagePriv.h>
#include <NdkImageReaderPriv.h>
#include <vndk/hardware_buffer.h>
#include <memory>

namespace android {

using HGraphicBufferProducer = hardware::graphics::bufferqueue::V1_0::
        IGraphicBufferProducer;
using hardware::graphics::bufferqueue::V1_0::utils::H2BGraphicBufferProducer;
using hidl::manager::V1_2::IServiceManager;
using hidl::token::V1_0::ITokenManager;
using aimg::AImageReader_getHGBPFromHandle;

typedef IGraphicBufferProducer::QueueBufferInput QueueBufferInput;
typedef IGraphicBufferProducer::QueueBufferOutput QueueBufferOutput;

static constexpr uint64_t kImageBufferUsage =
    AHARDWAREBUFFER_USAGE_CPU_WRITE_OFTEN;
static constexpr int kImageWidth = 640;
static constexpr int kImageHeight = 480;
static constexpr int kImageFormat = AIMAGE_FORMAT_RGBA_8888;
static constexpr int kMaxImages = 1;

static constexpr int64_t kQueueBufferInputTimeStamp = 1384888611;
static constexpr bool kQueueBufferInputIsAutoTimeStamp = false;
static constexpr android_dataspace kQueueBufferInputDataspace = HAL_DATASPACE_UNKNOWN;
static const Rect kQueueBufferInputRect = Rect(kImageWidth, kImageHeight);
static constexpr int kQueueBufferInputScalingMode = 0;
static constexpr int kQueueBufferInputTransform = 0;
static const sp<Fence> kQueueBufferInputFence = Fence::NO_FENCE;

static constexpr int kOnImageAvailableWaitUs = 100 * 1000;

class AImageReaderWindowTest : public ::testing::Test {
   public:
    void SetUp() override {
        AImageReader_newWithUsage(kImageWidth, kImageHeight, kImageFormat,
                                  kImageBufferUsage , kMaxImages, &imageReader_);
        media_status_t ret = AMEDIA_ERROR_UNKNOWN;
        ASSERT_NE(imageReader_, nullptr);
        ret = AImageReader_setImageListener(imageReader_,
                                            &imageReaderAvailableCb_);
        ASSERT_EQ(ret, AMEDIA_OK);
        ret = AImageReader_setBufferRemovedListener(imageReader_,
                                                    &imageReaderDetachedCb_);
        ASSERT_EQ(ret, AMEDIA_OK);
    }
    void TearDown() override {
        if (imageReader_) {
            AImageReader_delete(imageReader_);
        }
    }

    void HandleImageAvailable() {
        AImage *outImage = nullptr;
        media_status_t ret = AMEDIA_OK;
        auto imageDeleter = [](AImage *img) { AImage_delete(img); };
        std::unique_ptr<AImage, decltype(imageDeleter)> img(nullptr, imageDeleter);

        // Test that the image can be acquired.
        ret = AImageReader_acquireNextImage(imageReader_, &outImage);
        ASSERT_EQ(ret, AMEDIA_OK);
        img.reset(outImage);
        ASSERT_NE(img, nullptr);

        // Test that we can get a handle to the image's hardware buffer and a
        // native handle to it.
        AHardwareBuffer *hardwareBuffer = nullptr;
        ret = AImage_getHardwareBuffer(img.get(), &hardwareBuffer);
        ASSERT_EQ(ret, AMEDIA_OK);
        ASSERT_NE(hardwareBuffer, nullptr);
        const native_handle_t *nh = AHardwareBuffer_getNativeHandle(hardwareBuffer);
        ASSERT_NE(nh, nullptr);
        std::unique_lock<std::mutex> lock(imageAvailableMutex_);
        imageAvailable_ = true;
        imageCondVar_.notify_one();
    }

    static void onImageAvailable(void *context, AImageReader *reader) {
        (void)reader;
        AImageReaderWindowTest *thisContext =
            reinterpret_cast<AImageReaderWindowTest *>(context);
        thisContext->HandleImageAvailable();
    }

    static void onBufferRemoved(void *, AImageReader *, AHardwareBuffer *) {
    }

    static void fillRGBA8Buffer(uint8_t* buf, int w, int h, int stride) {
        const size_t PIXEL_SIZE = 4;
        for (int x = 0; x < w; x++) {
            for (int y = 0; y < h; y++) {
                off_t offset = (y * stride + x) * PIXEL_SIZE;
                for (int c = 0; c < 4; c++) {
                    int parityX = (x / (1 << (c+2))) & 1;
                    int parityY = (y / (1 << (c+2))) & 1;
                    buf[offset + c] = (parityX ^ parityY) ? 231 : 35;
                }
            }
        }
    }

    void validateIGBP(sp<IGraphicBufferProducer>& igbp) {
        int dequeuedSlot = -1;
        sp<Fence> dequeuedFence;
        IGraphicBufferProducer::QueueBufferOutput output;
        ASSERT_EQ(OK, igbp->connect(nullptr, NATIVE_WINDOW_API_CPU, false, &output));

        // Test that we can dequeue a buffer.
        ASSERT_EQ(OK,
                  ~IGraphicBufferProducer::BUFFER_NEEDS_REALLOCATION &
                          (igbp->dequeueBuffer(&dequeuedSlot, &dequeuedFence,
                                               kImageWidth, kImageHeight,
                                               kImageFormat, kImageBufferUsage,
                                               nullptr, nullptr)));
        EXPECT_LE(0, dequeuedSlot);
        EXPECT_GT(BufferQueue::NUM_BUFFER_SLOTS, dequeuedSlot);

        sp<GraphicBuffer> dequeuedBuffer;
        igbp->requestBuffer(dequeuedSlot, &dequeuedBuffer);
        uint8_t* img = nullptr;
        ASSERT_EQ(NO_ERROR, dequeuedBuffer->lock(kImageBufferUsage, (void**)(&img)));

        // Write in some placeholder image data.
        fillRGBA8Buffer(img, dequeuedBuffer->getWidth(), dequeuedBuffer->getHeight(),
                        dequeuedBuffer->getStride());
        ASSERT_EQ(NO_ERROR, dequeuedBuffer->unlock());
        QueueBufferInput queueBufferInput(kQueueBufferInputTimeStamp,
                                          kQueueBufferInputIsAutoTimeStamp,
                                          kQueueBufferInputDataspace,
                                          kQueueBufferInputRect,
                                          kQueueBufferInputScalingMode,
                                          kQueueBufferInputTransform,
                                          kQueueBufferInputFence);
        QueueBufferOutput queueBufferOutput;
        ASSERT_EQ(OK, igbp->queueBuffer(dequeuedSlot, queueBufferInput,
                                        &queueBufferOutput));
        // wait until the onImageAvailable callback is called, or timeout completes.
        std::unique_lock<std::mutex> lock(imageAvailableMutex_);
        imageCondVar_.wait_for(lock, std::chrono::microseconds(kOnImageAvailableWaitUs),
                               [this]{ return this->imageAvailable_;});
        EXPECT_TRUE(imageAvailable_) <<  "Timed out waiting for image data to be handled!\n";
    }

    AImageReader *imageReader_ = nullptr;
    AImageReader_ImageListener imageReaderAvailableCb_{this, onImageAvailable};
    AImageReader_BufferRemovedListener imageReaderDetachedCb_{this, onBufferRemoved};
    std::mutex imageAvailableMutex_;
    std::condition_variable imageCondVar_;
    bool imageAvailable_ = false;
};


TEST_F(AImageReaderWindowTest, CreateWindowNativeHandle) {
    // Check that we can create a native_handle_t corresponding to the
    // AImageReader.
    native_handle_t *nh = nullptr;
    media_status_t status = AImageReader_getWindowNativeHandle(imageReader_, &nh);

    // On newer devices without the HIDL TokenManager service this API is
    // deprecated and will return an error.
    if (IServiceManager::Transport::EMPTY ==
        hardware::defaultServiceManager1_2()->getTransport(ITokenManager::descriptor, "default")) {
      EXPECT_EQ(status, AMEDIA_ERROR_UNKNOWN);
      return;
    }
    ASSERT_NE(nh, nullptr);

    // Check that there are only ints in the handle.
    ASSERT_EQ(nh->numFds, 0);
    ASSERT_NE(nh->numInts, 0);

    // Check that the HGBP can be retrieved from the handle.
    sp<HGraphicBufferProducer> hgbp =  AImageReader_getHGBPFromHandle(nh);
    ASSERT_NE(hgbp, nullptr);
    sp<IGraphicBufferProducer> igbp = new H2BGraphicBufferProducer(hgbp);

    validateIGBP(igbp);
}

TEST_F(AImageReaderWindowTest, CreateWindow) {
    ANativeWindow* window = nullptr;
    media_status_t status = AImageReader_getWindow(imageReader_, &window);

    ASSERT_NE(window, nullptr);

    sp<IGraphicBufferProducer> igbp = Surface::getIGraphicBufferProducer(window);

    validateIGBP(igbp);
}

class AImageReaderPrivateFormatTest : public ::testing::Test {
  public:
    void SetUp() override {
        auto status = AImageReader_new(kImageWidth, kImageHeight, AIMAGE_FORMAT_RAW_DEPTH,
                                       kMaxImages, &imgReader);
        EXPECT_TRUE(status == AMEDIA_OK);
    }

    void TearDown() override {
        if (imgReader) {
            AImageReader_delete(imgReader);
        }
    }
    AImageReader *imgReader = nullptr;
};

TEST_F(AImageReaderPrivateFormatTest, CreateTest) {
    EXPECT_TRUE(imgReader != nullptr);
}


}  // namespace android
