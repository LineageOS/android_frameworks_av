/*
 * Copyright (C) 2022 The Android Open Source Project
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

#include <cutils/native_handle.h>
#include <fuzzer/FuzzedDataProvider.h>
#include <gui/BufferQueue.h>
#include <media/NdkImageReader.h>
#include <functional>

constexpr int32_t kMaxSize = INT_MAX;
constexpr int32_t kMinSize = 1;
constexpr int32_t kMinImages = 1;

class NdkImageReaderFuzzer {
  public:
    NdkImageReaderFuzzer(const uint8_t* data, size_t size) : mFdp(data, size){};
    void process();

  private:
    FuzzedDataProvider mFdp;
    static void onImageAvailable(void*, AImageReader*){};
    static void onBufferRemoved(void*, AImageReader*, AHardwareBuffer*){};
};

void NdkImageReaderFuzzer::process() {
    AImageReader* reader = nullptr;
    AImage* img = nullptr;
    native_handle_t* handle = nullptr;
    int32_t* acquireFenceFd = nullptr;
    int32_t imageWidth = mFdp.ConsumeIntegralInRange<int32_t>(kMinSize, kMaxSize);
    int32_t imageHeight = mFdp.ConsumeIntegralInRange<int32_t>(kMinSize, kMaxSize);
    int32_t imageFormat = mFdp.ConsumeIntegralInRange<int32_t>(kMinSize, kMaxSize);
    int32_t imageUsage = mFdp.ConsumeIntegralInRange<int32_t>(kMinSize, kMaxSize);
    int32_t imageMaxCount = mFdp.ConsumeIntegralInRange<int32_t>(
            kMinImages, android::BufferQueue::MAX_MAX_ACQUIRED_BUFFERS);
    AImageReader_ImageListener readerAvailableCb{this, NdkImageReaderFuzzer::onImageAvailable};
    AImageReader_BufferRemovedListener readerDetachedCb{this, onBufferRemoved};

    if (mFdp.ConsumeBool()) {
        AImageReader_new(imageWidth, imageHeight, imageFormat, imageMaxCount, &reader);
    } else {
        AImageReader_newWithUsage(imageWidth, imageHeight, imageFormat, imageUsage, imageMaxCount,
                                  &reader);
    }
    while (mFdp.remaining_bytes()) {
        auto ndkImageFunction = mFdp.PickValueInArray<const std::function<void()>>({
                [&]() { AImageReader_acquireNextImage(reader, &img); },
                [&]() { AImageReader_acquireLatestImage(reader, &img); },
                [&]() { AImageReader_setImageListener(reader, &readerAvailableCb); },
                [&]() { AImageReader_acquireNextImageAsync(reader, &img, acquireFenceFd); },
                [&]() { AImageReader_acquireLatestImageAsync(reader, &img, acquireFenceFd); },
                [&]() { AImageReader_setBufferRemovedListener(reader, &readerDetachedCb); },
                [&]() { AImageReader_getWindowNativeHandle(reader, &handle); },
        });
        ndkImageFunction();
    }
    AImageReader_delete(reader);
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    NdkImageReaderFuzzer ndkImageReaderFuzzer(data, size);
    ndkImageReaderFuzzer.process();
    return 0;
}
