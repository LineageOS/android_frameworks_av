/*
 * Copyright (C) 2019 The Android Open Source Project
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

#ifndef __BENCHMARK_COMMON_H__
#define __BENCHMARK_COMMON_H__

#include <sys/stat.h>
#include <inttypes.h>
#include <mutex>
#include <queue>
#include <thread>
#include <iostream>

#include <media/NdkMediaCodec.h>
#include <media/NdkMediaError.h>

#include "Stats.h"
#define UNUSED(x) (void)(x)

using namespace std;

constexpr uint32_t kQueueDequeueTimeoutUs = 1000;
constexpr uint32_t kMaxCSDStrlen = 16;
constexpr uint32_t kMaxBufferSize = 1024 * 1024 * 16;
// Change in kDefaultAudioEncodeFrameSize should also be taken to
// AUDIO_ENCODE_DEFAULT_MAX_INPUT_SIZE present in Encoder.java
constexpr uint32_t kDefaultAudioEncodeFrameSize = 4096;

template <typename T>
class CallBackQueue {
  public:
    CallBackQueue() {}
    ~CallBackQueue() {}

    void push(T elem) {
        bool needsNotify = false;
        {
            lock_guard<mutex> lock(mMutex);
            needsNotify = mQueue.empty();
            mQueue.push(move(elem));
        }
        if (needsNotify) mQueueNotEmptyCondition.notify_one();
    }

    T pop() {
        unique_lock<mutex> lock(mMutex);
        if (mQueue.empty()) {
            mQueueNotEmptyCondition.wait(lock, [this]() { return !mQueue.empty(); });
        }
        auto result = mQueue.front();
        mQueue.pop();
        return result;
    }

  private:
    mutex mMutex;
    queue<T> mQueue;
    condition_variable mQueueNotEmptyCondition;
};

class CallBackHandle {
  public:
    CallBackHandle() : mSawError(false), mIsDone(false), mStats(nullptr) {
        mStats = new Stats();
    }

    virtual ~CallBackHandle() {
        if (mIOThread.joinable()) mIOThread.join();
        if (mStats) delete mStats;
    }

    void ioThread();

    // Implementation in child class (Decoder/Encoder)
    virtual void onInputAvailable(AMediaCodec *codec, int32_t index) {
        (void)codec;
        (void)index;
    }
    virtual void onFormatChanged(AMediaCodec *codec, AMediaFormat *format) {
        (void)codec;
        (void)format;
    }
    virtual void onError(AMediaCodec *codec, media_status_t err) {
        (void)codec;
        (void)err;
    }
    virtual void onOutputAvailable(AMediaCodec *codec, int32_t index,
                                   AMediaCodecBufferInfo *bufferInfo) {
        (void)codec;
        (void)index;
        (void)bufferInfo;
    }

    Stats *getStats() { return mStats; }

    // Keep a queue of all function callbacks.
    typedef function<void()> IOTask;
    CallBackQueue<IOTask> mIOQueue;
    thread mIOThread;
    bool mSawError;
    bool mIsDone;

  protected:
    Stats *mStats;
};

// Async API's callback
void OnInputAvailableCB(AMediaCodec *codec, void *userdata, int32_t index);

void OnOutputAvailableCB(AMediaCodec *codec, void *userdata, int32_t index,
                         AMediaCodecBufferInfo *bufferInfo);

void OnFormatChangedCB(AMediaCodec *codec, void *userdata, AMediaFormat *format);

void OnErrorCB(AMediaCodec *codec, void * /* userdata */, media_status_t err, int32_t actionCode,
               const char *detail);

// Utility to create and configure AMediaCodec
AMediaCodec *createMediaCodec(AMediaFormat *format, const char *mime, string codecName,
                              bool isEncoder);

#endif  // __BENCHMARK_COMMON_H__
