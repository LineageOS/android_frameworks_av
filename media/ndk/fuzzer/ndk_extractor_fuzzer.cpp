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

#include <android/binder_process.h>
#include <fuzzer/FuzzedDataProvider.h>
#include <media/NdkMediaExtractor.h>
#include <stdlib.h>
#include <unistd.h>

constexpr int32_t kCaseStart = 0;
constexpr int32_t kCaseEnd = 8;
constexpr float kMinDataSizeFactor = 0.5;
constexpr int32_t kMaxIterations = 1000;
const std::string kPathPrefix = "file://";

constexpr SeekMode kSeekMode[] = {AMEDIAEXTRACTOR_SEEK_PREVIOUS_SYNC,
                                  AMEDIAEXTRACTOR_SEEK_NEXT_SYNC,
                                  AMEDIAEXTRACTOR_SEEK_CLOSEST_SYNC};

class NdkExtractorFuzzer {
  public:
    NdkExtractorFuzzer(const uint8_t* data, size_t size) : mFdp(data, size) {
        mDataSourceFd = mkstemp(mTestPath);
        std::vector<char> dataBuffer = mFdp.ConsumeBytes<char>(
                mFdp.ConsumeIntegralInRange<int32_t>(kMinDataSizeFactor * size, size));
        mDataSize = dataBuffer.size();
        write(mDataSourceFd, dataBuffer.data(), dataBuffer.size());
    };

    ~NdkExtractorFuzzer() {
        close(mDataSourceFd);
        remove(mTestPath);
    };

    void process();

  private:
    FuzzedDataProvider mFdp;
    int32_t mDataSourceFd = 0;
    int32_t mDataSize = 0;

    // Defined a mutable TestSource file path for mkstemp().
    char mTestPath[64] = "/data/local/tmp/TestSource_XXXXXX";
};

void NdkExtractorFuzzer::process() {
    AMediaExtractor* mMediaExtractor = AMediaExtractor_new();
    AMediaDataSource* mDataSource = nullptr;

    if (mFdp.ConsumeBool()) {
        AMediaExtractor_setDataSourceFd(mMediaExtractor, mDataSourceFd, 0, mDataSize);
    } else {
        mDataSource = AMediaDataSource_newUri((kPathPrefix + mTestPath).c_str(), 0 /* numkeys */,
                                              nullptr /* keyvalues */);
        AMediaExtractor_setDataSourceCustom(mMediaExtractor, mDataSource);
    }

    /**
     * Limiting the number of iterations of while loop
     * to prevent a possible timeout.
     */
    int32_t count = 0;
    while (mFdp.remaining_bytes() && count++ < kMaxIterations) {
        switch (mFdp.ConsumeIntegralInRange<int32_t>(kCaseStart, kCaseEnd)) {
            case 0:{
                AMediaExtractor_selectTrack(mMediaExtractor,
                                            mFdp.ConsumeIntegral<size_t>() /* idx */);
                break;
            }
            case 1:{
                AMediaExtractor_unselectTrack(mMediaExtractor,
                                              mFdp.ConsumeIntegral<size_t>() /* idx */);
                break;
            }
            case 2:{
                int32_t sampleSize = AMediaExtractor_getSampleSize(mMediaExtractor);
                if (sampleSize > 0) {
                    std::vector<uint8_t> buffer(sampleSize);
                    AMediaExtractor_readSampleData(
                            mMediaExtractor, buffer.data(),
                            mFdp.ConsumeIntegralInRange<size_t>(0, sampleSize) /* capacity */);
                }
                break;
            }
            case 3:{
                AMediaExtractor_getSampleFlags(mMediaExtractor);
                break;
            }
            case 4:{
                AMediaExtractor_getSampleCryptoInfo(mMediaExtractor);
                break;
            }
            case 5:{
                AMediaExtractor_getPsshInfo(mMediaExtractor);
                break;
            }
            case 6:{
                AMediaExtractor_advance(mMediaExtractor);
                break;
            }
            case 7:{
                AMediaFormat* mediaFormat = mFdp.ConsumeBool() ? AMediaFormat_new() : nullptr;
                AMediaExtractor_getSampleFormat(mMediaExtractor, mediaFormat);
                AMediaFormat_delete(mediaFormat);
                break;
            }
            case 8:{
                AMediaExtractor_seekTo(mMediaExtractor,
                                       mFdp.ConsumeIntegral<int64_t>() /* seekPosUs */,
                                       mFdp.PickValueInArray(kSeekMode) /* mode */);
                break;
            }
        };
    }

    AMediaDataSource_delete(mDataSource);
    AMediaExtractor_delete(mMediaExtractor);
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    /**
     * Create a threadpool for incoming binder transactions,
     * without this extractor results in a DoS after few instances.
     */
    ABinderProcess_startThreadPool();

    NdkExtractorFuzzer ndkExtractorFuzzer(data, size);
    ndkExtractorFuzzer.process();
    return 0;
}
