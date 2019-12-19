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

#ifndef __C2_ENCODER_H__
#define __C2_ENCODER_H__

#include <stdio.h>
#include <algorithm>
#include <fstream>

#include "BenchmarkC2Common.h"

#define DEFAULT_AUDIO_FRAME_SIZE 4096

constexpr int32_t KDefaultFrameRate = 25;

class C2Encoder : public BenchmarkC2Common {
  public:
    C2Encoder()
        : mIsAudioEncoder(false),
          mWidth(0),
          mHeight(0),
          mNumInputFrame(0),
          mComponent(nullptr) {}

    int32_t createCodec2Component(string codecName, AMediaFormat *format);

    int32_t encodeFrames(ifstream &eleStream, size_t inputBufferSize);

    int32_t getInputMaxBufSize();

    void deInitCodec();

    void dumpStatistics(string inputReference, int64_t durationUs);

    void resetEncoder();

  private:
    bool mIsAudioEncoder;

    int32_t mWidth;
    int32_t mHeight;
    int32_t mFrameRate;
    int32_t mSampleRate;

    int32_t mNumInputFrame;
    int32_t mInputMaxBufSize;

    std::shared_ptr<android::Codec2Client::Listener> mListener;
    std::shared_ptr<android::Codec2Client::Component> mComponent;
};

#endif  // __C2_ENCODER_H__
