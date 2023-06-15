/*
 * Copyright (C) 2023 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

#include <datasource/HTTPBase.h>
#include <fuzzer/FuzzedDataProvider.h>
#include <media/MediaHTTPConnection.h>
#include <media/MediaHTTPService.h>
#include <media/stagefright/MediaDefs.h>
#include <media/stagefright/rtsp/SDPLoader.h>

using namespace android;

constexpr int32_t kMinCapacity = 0;
constexpr int32_t kMaxCapacity = 1000;
constexpr int32_t kMaxStringLength = 20;
constexpr int32_t kMaxBytes = 128;
enum { kWhatLoad = 'load' };

struct FuzzAHandler : public AHandler {
  public:
    FuzzAHandler(std::function<void()> signalEosFunction) : mSignalEosFunction(signalEosFunction) {}

  protected:
    void onMessageReceived(const sp<AMessage>& msg) override {
        switch (msg->what()) {
            case kWhatLoad: {
                mSignalEosFunction();
                break;
            }
        }
        return;
    }

  private:
    std::function<void()> mSignalEosFunction;
};

struct FuzzMediaHTTPConnection : public MediaHTTPConnection {
  public:
    FuzzMediaHTTPConnection(FuzzedDataProvider* fdp) : mFdp(fdp) {
        mSize = mFdp->ConsumeIntegralInRange(kMinCapacity, kMaxCapacity);
        mData = mFdp->ConsumeBytes<uint8_t>(mSize);
        mSize = mData.size();
    }
    virtual bool connect(const char* /* uri */,
                         const KeyedVector<String8, String8>* /* headers */) {
        return mFdp->ConsumeBool();
    }
    virtual void disconnect() { return; }
    virtual ssize_t readAt(off64_t offset, void* data, size_t size) {
        if ((size + offset <= mData.size()) && (offset >= 0)) {
           memcpy(data, mData.data() + offset, size);
           return size;
        }
        return 0;
    }
    virtual off64_t getSize() { return mSize; }
    virtual status_t getMIMEType(String8* /*mimeType*/) {return mFdp->ConsumeIntegral<status_t>();}
    virtual status_t getUri(String8* /*uri*/) {return mFdp->ConsumeIntegral<status_t>();}

  private:
    FuzzedDataProvider* mFdp = nullptr;
    std::vector<uint8_t> mData;
    size_t mSize = 0;
};

struct FuzzMediaHTTPService : public MediaHTTPService {
  public:
    FuzzMediaHTTPService(FuzzedDataProvider* fdp) : mFdp(fdp) {}
    virtual sp<MediaHTTPConnection> makeHTTPConnection() {
        mediaHTTPConnection = sp<FuzzMediaHTTPConnection>::make(mFdp);
        return mediaHTTPConnection;
    }

  private:
    sp<FuzzMediaHTTPConnection> mediaHTTPConnection = nullptr;
    FuzzedDataProvider* mFdp = nullptr;
};

class SDPLoaderFuzzer {
  public:
    SDPLoaderFuzzer(const uint8_t* data, size_t size) : mFdp(data, size) {}
    void process();

  private:
    void signalEos();

    bool mEosReached = false;
    std::mutex mMsgPostCompleteMutex;
    std::condition_variable mConditionalVariable;
    FuzzedDataProvider mFdp;
};

void SDPLoaderFuzzer::signalEos() {
    mEosReached = true;
    mConditionalVariable.notify_one();
    return;
}

void SDPLoaderFuzzer::process() {
    sp<FuzzAHandler> handler = sp<FuzzAHandler>::make(std::bind(&SDPLoaderFuzzer::signalEos, this));
    sp<ALooper> looper = sp<ALooper>::make();
    looper->start();
    looper->registerHandler(handler);
    const sp<AMessage> notify = sp<AMessage>::make(kWhatLoad, handler);
    sp<SDPLoader> sdpLoader =
            sp<SDPLoader>::make(notify, mFdp.ConsumeIntegral<uint32_t>() /* flags */,
                                sp<FuzzMediaHTTPService>::make(&mFdp) /* httpService */);

    KeyedVector<String8, String8> headers;
    for (size_t idx = 0; idx < mFdp.ConsumeIntegralInRange<size_t>(kMinCapacity, kMaxCapacity);
         ++idx) {
        headers.add(String8(mFdp.ConsumeRandomLengthString(kMaxBytes).c_str()) /* key */,
                    String8(mFdp.ConsumeRandomLengthString(kMaxBytes).c_str()) /* value */);
    }

    sdpLoader->load(mFdp.ConsumeRandomLengthString(kMaxBytes).c_str() /* url */, &headers);

    std::unique_lock waitForMsgPostComplete(mMsgPostCompleteMutex);
    mConditionalVariable.wait(waitForMsgPostComplete, [this] { return mEosReached; });
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    SDPLoaderFuzzer sdpLoaderFuzzer(data, size);
    sdpLoaderFuzzer.process();
    return 0;
}
