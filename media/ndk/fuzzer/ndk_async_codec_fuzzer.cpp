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
#include <NdkMediaCodecFuzzerBase.h>
#include <media/NdkMediaFormatPriv.h>
#include <functional>
#include <mutex>
#include <queue>
#include <thread>

using namespace android;
using namespace std;

constexpr int32_t kMaxCryptoInfoAPIs = 3;
constexpr int32_t kMaxNdkCodecAPIs = 5;

template <typename T>
class CallBackQueue {
  public:
    void push(T elem) {
        bool needsNotify = false;
        {
            unique_lock<mutex> lock(mMutex);
            needsNotify = mQueue.empty();
            mQueue.push(std::move(elem));
        }
        if (needsNotify) {
            mQueueNotEmptyCondition.notify_one();
        }
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
    std::queue<T> mQueue;
    std::condition_variable mQueueNotEmptyCondition;
};

class CallBackHandle {
  public:
    CallBackHandle() : mSawError(false), mIsDone(false) {}

    virtual ~CallBackHandle() {}

    void ioThread();

    // Implementation in child class (Decoder/Encoder)
    virtual void invokeInputBufferAPI(AMediaCodec* codec, int32_t index) {
        (void)codec;
        (void)index;
    }
    virtual void onFormatChanged(AMediaCodec* codec, AMediaFormat* format) {
        (void)codec;
        (void)format;
    }
    virtual void receiveError(void) {}
    virtual void invokeOutputBufferAPI(AMediaCodec* codec, int32_t index,
                                       AMediaCodecBufferInfo* bufferInfo) {
        (void)codec;
        (void)index;
        (void)bufferInfo;
    }

    // Keep a queue of all function callbacks.
    typedef function<void()> IOTask;
    CallBackQueue<IOTask> mIOQueue;
    bool mSawError;
    bool mIsDone;
};

void CallBackHandle::ioThread() {
    while (!mIsDone && !mSawError) {
        auto task = mIOQueue.pop();
        task();
    }
}

static void onAsyncInputAvailable(AMediaCodec* codec, void* userdata, int32_t index) {
    CallBackHandle* self = (CallBackHandle*)userdata;
    self->mIOQueue.push([self, codec, index]() { self->invokeInputBufferAPI(codec, index); });
}

static void onAsyncOutputAvailable(AMediaCodec* codec, void* userdata, int32_t index,
                                   AMediaCodecBufferInfo* bufferInfo) {
    CallBackHandle* self = (CallBackHandle*)userdata;
    AMediaCodecBufferInfo bufferInfoCopy = *bufferInfo;
    self->mIOQueue.push([self, codec, index, bufferInfoCopy]() {
        AMediaCodecBufferInfo bc = bufferInfoCopy;
        self->invokeOutputBufferAPI(codec, index, &bc);
    });
}

static void onAsyncFormatChanged(AMediaCodec* codec, void* userdata, AMediaFormat* format) {
    (void)codec;
    (void)userdata;
    (void)format;
};

static void onAsyncError(AMediaCodec* codec, void* userdata, media_status_t err, int32_t actionCode,
                         const char* detail) {
    CallBackHandle* self = (CallBackHandle*)userdata;
    self->mSawError = true;
    self->receiveError();
    (void)codec;
    (void)err;
    (void)actionCode;
    (void)detail;
};

class NdkAsyncCodecFuzzer : public NdkMediaCodecFuzzerBase, public CallBackHandle {
  public:
    NdkAsyncCodecFuzzer(const uint8_t* data, size_t size)
        : NdkMediaCodecFuzzerBase(), mFdp(data, size) {
        setFdp(&mFdp);
        mStopCodec = false;
        mSawInputEOS = false;
        mSignalledError = false;
        mIsEncoder = false;
        mNumOfFrames = 0;
        mNumInputFrames = 0;
    };
    ~NdkAsyncCodecFuzzer() {
        mIOThreadPool->stop();
        delete (mIOThreadPool);
    };

    void process();

    static void codecOnFrameRendered(AMediaCodec* codec, void* userdata, int64_t mediaTimeUs,
                                     int64_t systemNano) {
        (void)codec;
        (void)userdata;
        (void)mediaTimeUs;
        (void)systemNano;
    };
    class ThreadPool {
      public:
        void start();
        void queueJob(const std::function<void()>& job);
        void stop();

      private:
        void ThreadLoop();
        bool mShouldTerminate = false;
        std::vector<std::thread> mThreads;
        std::mutex mQueueMutex;
        std::condition_variable mQueueMutexCondition;
        std::queue<std::function<void()>> mJobs;
    };

  private:
    FuzzedDataProvider mFdp;
    AMediaCodec* mCodec = nullptr;
    void invokeCodecCryptoInfoAPI();
    void invokekAsyncCodecAPIs(bool isEncoder);
    void invokeAsyncCodeConfigAPI();
    void invokeInputBufferAPI(AMediaCodec* codec, int32_t bufferIndex);
    void invokeOutputBufferAPI(AMediaCodec* codec, int32_t bufferIndex,
                               AMediaCodecBufferInfo* bufferInfo);
    void invokeFormatAPI(AMediaCodec* codec);
    void receiveError();
    bool mStopCodec;
    bool mSawInputEOS;
    bool mSignalledError;
    int32_t mNumOfFrames;
    int32_t mNumInputFrames;
    mutable Mutex mMutex;
    bool mIsEncoder;
    ThreadPool* mIOThreadPool = new ThreadPool();
};

void NdkAsyncCodecFuzzer::ThreadPool::start() {
    const uint32_t numThreads = std::thread::hardware_concurrency();
    mThreads.resize(numThreads);
    for (uint32_t i = 0; i < numThreads; ++i) {
        mThreads.at(i) = std::thread(&ThreadPool::ThreadLoop, this);
    }
}

void NdkAsyncCodecFuzzer::ThreadPool::ThreadLoop() {
    while (true) {
        std::function<void()> job;
        {
            std::unique_lock<std::mutex> lock(mQueueMutex);
            mQueueMutexCondition.wait(lock, [this] { return !mJobs.empty() || mShouldTerminate; });
            if (mShouldTerminate) {
                return;
            }
            job = mJobs.front();
            mJobs.pop();
        }
        job();
    }
}

void NdkAsyncCodecFuzzer::ThreadPool::queueJob(const std::function<void()>& job) {
    {
        std::unique_lock<std::mutex> lock(mQueueMutex);
        mJobs.push(job);
    }
    mQueueMutexCondition.notify_one();
}

void NdkAsyncCodecFuzzer::ThreadPool::stop() {
    {
        std::unique_lock<std::mutex> lock(mQueueMutex);
        mShouldTerminate = true;
    }
    mQueueMutexCondition.notify_all();
    for (std::thread& active_thread : mThreads) {
        active_thread.join();
    }
    mThreads.clear();
}

void NdkAsyncCodecFuzzer::receiveError(void) {
    mSignalledError = true;
}

void NdkAsyncCodecFuzzer::invokeInputBufferAPI(AMediaCodec* codec, int32_t bufferIndex) {
    size_t bufferSize = 0;
    Mutex::Autolock autoLock(mMutex);
    if (mSignalledError) {
        CallBackHandle::mSawError = true;
        return;
    }
    if (mStopCodec || bufferIndex < 0 || mSawInputEOS) {
        return;
    }

    uint8_t* buffer = AMediaCodec_getInputBuffer(codec, bufferIndex, &bufferSize);
    if (buffer) {
        std::vector<uint8_t> bytesRead = mFdp.ConsumeBytes<uint8_t>(
                std::min(mFdp.ConsumeIntegralInRange<size_t>(kMinBytes, kMaxBytes), bufferSize));
        memcpy(buffer, bytesRead.data(), bytesRead.size());
        bufferSize = bytesRead.size();
    } else {
        mSignalledError = true;
        return;
    }

    uint32_t flag = 0;
    if (!bufferSize || mNumInputFrames == mNumOfFrames) {
        flag |= AMEDIACODEC_BUFFER_FLAG_END_OF_STREAM;
        mSawInputEOS = true;
    }
    AMediaCodec_queueInputBuffer(codec, bufferIndex, 0 /* offset */, bufferSize, 0 /* time */,
                                 flag);
    mNumInputFrames++;
}

void NdkAsyncCodecFuzzer::invokeOutputBufferAPI(AMediaCodec* codec, int32_t bufferIndex,
                                                AMediaCodecBufferInfo* bufferInfo) {
    size_t bufferSize = 0;
    Mutex::Autolock autoLock(mMutex);

    if (mSignalledError) {
        CallBackHandle::mSawError = true;
        return;
    }

    if (mStopCodec || bufferIndex < 0 || mIsDone) {
        return;
    }

    if (!mIsEncoder) {
        (void)AMediaCodec_getOutputBuffer(codec, bufferIndex, &bufferSize);
    }
    AMediaCodec_releaseOutputBuffer(codec, bufferIndex, mFdp.ConsumeBool());
    mIsDone = (0 != (bufferInfo->flags & AMEDIACODEC_BUFFER_FLAG_END_OF_STREAM));
}

void NdkAsyncCodecFuzzer::invokeFormatAPI(AMediaCodec* codec) {
    AMediaFormat* codecFormat = nullptr;
    if (mFdp.ConsumeBool()) {
        codecFormat = AMediaCodec_getInputFormat(codec);
    } else {
        codecFormat = AMediaCodec_getOutputFormat(codec);
    }
    if (codecFormat) {
        AMediaFormat_delete(codecFormat);
    }
}

void NdkAsyncCodecFuzzer::invokekAsyncCodecAPIs(bool isEncoder) {
    ANativeWindow* nativeWindow = nullptr;

    if (mFdp.ConsumeBool()) {
        AMediaCodec_createInputSurface(mCodec, &nativeWindow);
    }

    if (AMEDIA_OK == AMediaCodec_configure(mCodec, getCodecFormat(), nativeWindow,
                                           nullptr /* crypto */,
                                           (isEncoder ? AMEDIACODEC_CONFIGURE_FLAG_ENCODE : 0))) {
        mNumOfFrames = mFdp.ConsumeIntegralInRange<size_t>(kMinIterations, kMaxIterations);
        // Configure codecs to run in async mode.
        AMediaCodecOnAsyncNotifyCallback callBack = {onAsyncInputAvailable, onAsyncOutputAvailable,
                                                     onAsyncFormatChanged, onAsyncError};
        AMediaCodec_setAsyncNotifyCallback(mCodec, callBack, this);
        mIOThreadPool->queueJob([this] { CallBackHandle::ioThread(); });

        AMediaCodec_start(mCodec);
        sleep(5);
        int32_t count = 0;
        while (++count <= mNumOfFrames) {
            int32_t ndkcodecAPI =
                    mFdp.ConsumeIntegralInRange<size_t>(kMinAPICase, kMaxNdkCodecAPIs);
            switch (ndkcodecAPI) {
                case 0: {  // get input and output Format
                    invokeFormatAPI(mCodec);
                    break;
                }
                case 1: {
                    AMediaCodec_signalEndOfInputStream(mCodec);
                    mSawInputEOS = true;
                    break;
                }
                case 2: {  // set parameters
                    // Create a new parameter and set
                    AMediaFormat* params = AMediaFormat_new();
                    AMediaFormat_setInt32(
                            params, "video-bitrate",
                            mFdp.ConsumeIntegralInRange<size_t>(kMinIntKeyValue, kMaxIntKeyValue));
                    AMediaCodec_setParameters(mCodec, params);
                    AMediaFormat_delete(params);
                    break;
                }
                case 3: {  // flush codec
                    AMediaCodec_flush(mCodec);
                    if (mFdp.ConsumeBool()) {
                        AMediaCodec_start(mCodec);
                    }
                    break;
                }
                case 4: {
                    char* name = nullptr;
                    AMediaCodec_getName(mCodec, &name);
                    AMediaCodec_releaseName(mCodec, name);
                    break;
                }
                case 5:
                default: {
                    std::vector<uint8_t> userData = mFdp.ConsumeBytes<uint8_t>(
                            mFdp.ConsumeIntegralInRange<size_t>(kMinBytes, kMaxBytes));
                    AMediaCodecOnFrameRendered callback = codecOnFrameRendered;
                    AMediaCodec_setOnFrameRenderedCallback(mCodec, callback, userData.data());
                    break;
                }
            }
        }
        {
            Mutex::Autolock autoLock(mMutex);
            mStopCodec = 1;
            AMediaCodec_stop(mCodec);
        }
    }

    if (nativeWindow) {
        ANativeWindow_release(nativeWindow);
    }
}

void NdkAsyncCodecFuzzer::invokeAsyncCodeConfigAPI() {
    mIOThreadPool->start();

    while (mFdp.remaining_bytes() > 0) {
        mIsEncoder = mFdp.ConsumeBool();
        mCodec = createCodec(mIsEncoder, mFdp.ConsumeBool() /* isCodecForClient */);
        if (mCodec) {
            invokekAsyncCodecAPIs(mIsEncoder);
            AMediaCodec_delete(mCodec);
        }
    }
    mIOThreadPool->stop();
}

void NdkAsyncCodecFuzzer::invokeCodecCryptoInfoAPI() {
    while (mFdp.remaining_bytes() > 0) {
        AMediaCodecCryptoInfo* cryptoInfo = getAMediaCodecCryptoInfo();
        int32_t ndkCryptoInfoAPI =
                mFdp.ConsumeIntegralInRange<size_t>(kMinAPICase, kMaxCryptoInfoAPIs);
        switch (ndkCryptoInfoAPI) {
            case 0: {
                size_t sizes[kMaxCryptoKey];
                AMediaCodecCryptoInfo_getEncryptedBytes(cryptoInfo, sizes);
                break;
            }
            case 1: {
                size_t sizes[kMaxCryptoKey];
                AMediaCodecCryptoInfo_getClearBytes(cryptoInfo, sizes);
                break;
            }
            case 2: {
                uint8_t bytes[kMaxCryptoKey];
                AMediaCodecCryptoInfo_getIV(cryptoInfo, bytes);
                break;
            }
            case 3:
            default: {
                uint8_t bytes[kMaxCryptoKey];
                AMediaCodecCryptoInfo_getKey(cryptoInfo, bytes);
                break;
            }
        }
        AMediaCodecCryptoInfo_delete(cryptoInfo);
    }
}

void NdkAsyncCodecFuzzer::process() {
    if (mFdp.ConsumeBool()) {
        invokeCodecCryptoInfoAPI();
    } else {
        invokeAsyncCodeConfigAPI();
    }
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    NdkAsyncCodecFuzzer ndkAsyncCodecFuzzer(data, size);
    ndkAsyncCodecFuzzer.process();
    return 0;
}
