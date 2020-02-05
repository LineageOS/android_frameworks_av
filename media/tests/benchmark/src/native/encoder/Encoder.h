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

#ifndef __ENCODER_H__
#define __ENCODER_H__

#include <chrono>
#include <condition_variable>
#include <mutex>
#include <queue>
#include <thread>

#include "media/NdkImage.h"
#include "BenchmarkCommon.h"
#include "Stats.h"


struct encParameter {
    int32_t bitrate = -1;
    int32_t numFrames = -1;
    int32_t frameSize = -1;
    int32_t sampleRate = 0;
    int32_t numChannels = 0;
    int32_t maxFrameSize = -1;
    int32_t width = 0;
    int32_t height = 0;
    int32_t frameRate = -1;
    int32_t profile = 0;
    int32_t level = 0;
    int32_t colorFormat = AIMAGE_FORMAT_YUV_420_888;
};

class Encoder : public CallBackHandle {
  public:
    Encoder()
        : mCodec(nullptr),
          mFormat(nullptr),
          mNumInputFrame(0),
          mNumOutputFrame(0),
          mSawInputEOS(false),
          mSawOutputEOS(false),
          mSignalledError(false),
          mErrorCode(AMEDIA_OK) {}

    virtual ~Encoder() {}

    // Encoder related utilities
    void setupEncoder();

    void deInitCodec();

    void resetEncoder();

    // Async callback APIs
    void onInputAvailable(AMediaCodec *codec, int32_t index) override;

    void onFormatChanged(AMediaCodec *codec, AMediaFormat *format) override;

    void onError(AMediaCodec *mediaCodec, media_status_t err) override;

    void onOutputAvailable(AMediaCodec *codec, int32_t index,
                           AMediaCodecBufferInfo *bufferInfo) override;

    // Process the frames and give encoded output
    int32_t encode(std::string &codecName, std::ifstream &eleStream, size_t eleSize, bool asyncMode,
                   encParameter encParams, char *mime);

    void dumpStatistics(string inputReference, int64_t durationUs, string codecName = "",
                        string mode = "", string statsFile = "");

  private:
    AMediaCodec *mCodec;
    AMediaFormat *mFormat;

    int32_t mNumInputFrame;
    int32_t mNumOutputFrame;
    bool mSawInputEOS;
    bool mSawOutputEOS;
    bool mSignalledError;
    media_status_t mErrorCode;

    char *mMime;
    int32_t mOffset;
    std::ifstream *mEleStream;
    size_t mInputBufferSize;
    encParameter mParams;

    // Asynchronous locks
    std::mutex mMutex;
    std::condition_variable mEncoderDoneCondition;
};
#endif  // __ENCODER_H__
