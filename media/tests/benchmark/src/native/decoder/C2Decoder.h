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

#ifndef __C2_DECODER_H__
#define __C2_DECODER_H__

#include "BenchmarkC2Common.h"

#define ALIGN(_sz, _align) (((_sz) + ((_align) - 1)) & ~((_align) - 1))

class C2Decoder : public BenchmarkC2Common {
  public:
    C2Decoder() : mOffset(0), mNumInputFrame(0), mComponent(nullptr) {}

    int32_t createCodec2Component(string codecName, AMediaFormat *format);

    int32_t decodeFrames(uint8_t *inputBuffer, vector<AMediaCodecBufferInfo> &frameInfo);

    void deInitCodec();

    void dumpStatistics(string inputReference, int64_t durationUs);

    void resetDecoder();

  private:
    int32_t mOffset;
    int32_t mNumInputFrame;
    vector<AMediaCodecBufferInfo> mFrameMetaData;

    std::shared_ptr<android::Codec2Client::Listener> mListener;
    std::shared_ptr<android::Codec2Client::Component> mComponent;
};

#endif  // __C2_DECODER_H__
