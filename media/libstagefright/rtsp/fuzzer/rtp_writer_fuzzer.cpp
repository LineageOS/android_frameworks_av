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

#include <fuzzer/FuzzedDataProvider.h>
#include <media/stagefright/MediaBuffer.h>
#include <media/stagefright/MediaDefs.h>
#include <media/stagefright/rtsp/ARTPWriter.h>

constexpr int32_t kMinSize = 0;
constexpr int32_t kMaxSize = 65536;
constexpr int32_t kMaxTime = 1000;
constexpr int32_t kMaxBytes = 128;
constexpr int32_t kAMRNBFrameSizes[] = {13, 14, 16, 18, 20, 21, 27, 32};
constexpr int32_t kAMRWBFrameSizes[] = {18, 24, 33, 37, 41, 47, 51, 59, 61};
constexpr int32_t kAMRIndexOffset = 8;

using namespace android;

const char* kKeyMimeTypeArray[] = {MEDIA_MIMETYPE_VIDEO_AVC, MEDIA_MIMETYPE_VIDEO_HEVC,
                                   MEDIA_MIMETYPE_VIDEO_H263, MEDIA_MIMETYPE_AUDIO_AMR_NB,
                                   MEDIA_MIMETYPE_AUDIO_AMR_WB};

struct TestMediaSource : public MediaSource {
  public:
    TestMediaSource(FuzzedDataProvider& mFdp) : mTestMetaData(new MetaData) {
        int32_t vectorSize = 0;
        mAllowRead = mFdp.ConsumeBool();
        mKeySps = mFdp.ConsumeIntegral<int32_t>();
        mKeyVps = mFdp.ConsumeIntegral<int32_t>();
        mKeyPps = mFdp.ConsumeIntegral<int32_t>();
        mKeyTime = mFdp.ConsumeIntegralInRange<int64_t>(kMinSize, kMaxTime);

        mMimeType = mFdp.PickValueInArray(kKeyMimeTypeArray);
        mTestMetaData->setCString(kKeyMIMEType, mMimeType);
        if (mMimeType == MEDIA_MIMETYPE_AUDIO_AMR_NB) {
            int32_t index =
                    mFdp.ConsumeIntegralInRange<int32_t>(kMinSize, std::size(kAMRNBFrameSizes) - 1);
            vectorSize = kAMRNBFrameSizes[index];
            mData.push_back(kAMRIndexOffset * index);
        } else if (mMimeType == MEDIA_MIMETYPE_AUDIO_AMR_WB) {
            int32_t index =
                    mFdp.ConsumeIntegralInRange<int32_t>(kMinSize, std::size(kAMRWBFrameSizes) - 1);
            vectorSize = kAMRWBFrameSizes[index];
            mData.push_back(kAMRIndexOffset * index);
        } else if (mMimeType == MEDIA_MIMETYPE_VIDEO_H263) {
            // Required format for H263 media data
            mData.push_back(0);
            mData.push_back(0);
            vectorSize = mFdp.ConsumeIntegralInRange<int32_t>(kMinSize, kMaxSize);
        } else {
            vectorSize = mFdp.ConsumeIntegralInRange<int32_t>(kMinSize, kMaxSize);
        }
        for (size_t idx = mData.size(); idx < vectorSize; ++idx) {
            mData.push_back(mFdp.ConsumeIntegral<uint8_t>());
        }
    }
    virtual status_t start(MetaData* /*params*/) { return OK; }
    virtual status_t stop() { return OK; }
    virtual sp<MetaData> getFormat() { return mTestMetaData; }
    virtual status_t read(MediaBufferBase** buffer, const ReadOptions* /*options*/) {
        if (!mAllowRead) {
            return -1;
        }
        *buffer = new MediaBuffer(mData.data() /*data*/, mData.size() /*size*/);
        if (mKeySps) {
            (*buffer)->meta_data().setInt32(kKeySps, mKeySps);
        }
        if (mKeyVps) {
            (*buffer)->meta_data().setInt32(kKeyVps, mKeyVps);
        }
        if (mKeyPps) {
            (*buffer)->meta_data().setInt32(kKeyPps, mKeyPps);
        }
        (*buffer)->meta_data().setInt64(kKeyTime, mKeyTime);
        return OK;
    }

  private:
    int32_t mKeySps;
    int32_t mKeyVps;
    int32_t mKeyPps;
    int64_t mKeyTime;
    bool mAllowRead;
    const char* mMimeType;
    sp<MetaData> mTestMetaData;
    std::vector<uint8_t> mData;
};

class ARTPWriterFuzzer {
  public:
    ARTPWriterFuzzer(const uint8_t* data, size_t size)
        : mDataSourceFd(memfd_create("InputFile", MFD_ALLOW_SEALING)), mFdp(data, size) {}
    ~ARTPWriterFuzzer() { close(mDataSourceFd); }
    void process();

  private:
    void createARTPWriter();
    const int32_t mDataSourceFd;
    FuzzedDataProvider mFdp;
    sp<ARTPWriter> mArtpWriter;
};

void ARTPWriterFuzzer::createARTPWriter() {
    String8 localIp = String8(mFdp.ConsumeRandomLengthString(kMaxBytes).c_str());
    String8 remoteIp = String8(mFdp.ConsumeRandomLengthString(kMaxBytes).c_str());
    mArtpWriter = sp<ARTPWriter>::make(
            mDataSourceFd, localIp, mFdp.ConsumeIntegral<uint16_t>() /* localPort */, remoteIp,
            mFdp.ConsumeIntegral<uint16_t>() /* remotePort */,
            mFdp.ConsumeIntegralInRange<uint32_t>(kMinSize, kMaxSize) /* seqNo */);
}

void ARTPWriterFuzzer::process() {
    if (mFdp.ConsumeBool()) {
        mArtpWriter = sp<ARTPWriter>::make(mDataSourceFd);
        if (mArtpWriter->getSequenceNum() > kMaxSize) {
            createARTPWriter();
        }
    } else {
        createARTPWriter();
    }

    mArtpWriter->addSource(sp<TestMediaSource>::make(mFdp) /* source */);

    while (mFdp.remaining_bytes()) {
        auto invokeRTPWriterFuzzer = mFdp.PickValueInArray<const std::function<void()>>({
                [&]() {
                    sp<MetaData> metaData = sp<MetaData>::make();
                    if (mFdp.ConsumeBool()) {
                        metaData->setInt32(kKeySelfID, mFdp.ConsumeIntegral<int32_t>());
                    }
                    if (mFdp.ConsumeBool()) {
                        metaData->setInt32(kKeyPayloadType, mFdp.ConsumeIntegral<int32_t>());
                    }
                    if (mFdp.ConsumeBool()) {
                        metaData->setInt32(kKeyRtpExtMap, mFdp.ConsumeIntegral<int32_t>());
                    }
                    if (mFdp.ConsumeBool()) {
                        metaData->setInt32(kKeyRtpCvoDegrees, mFdp.ConsumeIntegral<int32_t>());
                    }
                    if (mFdp.ConsumeBool()) {
                        metaData->setInt32(kKeyRtpDscp, mFdp.ConsumeIntegral<int32_t>());
                    }
                    if (mFdp.ConsumeBool()) {
                        metaData->setInt64(kKeySocketNetwork, mFdp.ConsumeIntegral<int64_t>());
                    }
                    mArtpWriter->start(metaData.get() /*param*/);
                },
                [&]() {
                    mArtpWriter->setTMMBNInfo(mFdp.ConsumeIntegral<uint32_t>() /* opponentID */,
                                              mFdp.ConsumeIntegral<uint32_t>() /* bitrate */);
                },
                [&]() { mArtpWriter->stop(); },
                [&]() {
                    mArtpWriter->updateCVODegrees(mFdp.ConsumeIntegral<int32_t>() /* cvoDegrees */);
                },
                [&]() {
                    mArtpWriter->updatePayloadType(
                            mFdp.ConsumeIntegral<int32_t>() /* payloadType */);
                },

        });
        invokeRTPWriterFuzzer();
    }
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    ARTPWriterFuzzer artpWriterFuzzer(data, size);
    artpWriterFuzzer.process();
    return 0;
}
