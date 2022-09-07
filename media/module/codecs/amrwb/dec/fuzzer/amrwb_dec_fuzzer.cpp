/******************************************************************************
 *
 * Copyright (C) 2020 The Android Open Source Project
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
 *****************************************************************************
 * Originally developed and contributed by Ittiam Systems Pvt. Ltd, Bangalore
 */
#include <malloc.h>
#include <string.h>
#include <algorithm>
#include "pvamrwbdecoder.h"
#include "pvamrwbdecoder_api.h"

// Constants for AMR-WB.
constexpr int32_t kSamplesPerFrame = 320;
constexpr int32_t kBitsPerSample = 16;
constexpr int32_t kMaxSourceDataUnitSize = KAMRWB_NB_BITS_MAX * sizeof(int16_t);
constexpr int32_t kOutputBufferSize = kSamplesPerFrame * kBitsPerSample / 8;
constexpr int32_t kFrameSizes[16] = {17, 23, 32, 36, 40, 46, 50, 58,
                                     60, 17, 23, 32, 36, 40, 46, 50};

class Codec {
 public:
  Codec() = default;
  ~Codec() { deInitDecoder(); }
  bool initDecoder();
  void decodeFrames(const uint8_t *data, size_t size);
  void deInitDecoder();

 private:
  void *mAmrHandle = nullptr;
  int16_t *mDecoderCookie = nullptr;
  void *mDecoderBuffer = nullptr;
};

bool Codec::initDecoder() {
  mDecoderBuffer = malloc(pvDecoder_AmrWbMemRequirements());
  if (mDecoderBuffer) {
    pvDecoder_AmrWb_Init(&mAmrHandle, mDecoderBuffer, &mDecoderCookie);
    return true;
  } else {
    return false;
  }
}

void Codec::deInitDecoder() {
  if (mDecoderBuffer) {
    free(mDecoderBuffer);
    mDecoderBuffer = nullptr;
  }
  mAmrHandle = nullptr;
  mDecoderCookie = nullptr;
}

void Codec::decodeFrames(const uint8_t *data, size_t size) {
  RX_State_wb rx_state{};
  while (size > 0) {
    uint8_t modeByte = *data;
    bool quality = modeByte & 0x01;
    int16 mode = ((modeByte >> 3) & 0x0f);
    ++data;
    --size;
    int32_t frameSize = kFrameSizes[mode];
    int16_t inputSampleBuf[kMaxSourceDataUnitSize];
    uint8_t *inputBuf = new uint8_t[frameSize];
    if (!inputBuf) {
      return;
    }
    int32_t minSize = std::min((int32_t)size, frameSize);
    memcpy(inputBuf, data, minSize);
    int16 frameMode = mode;
    int16 frameType;
    mime_unsorting(inputBuf, inputSampleBuf, &frameType, &frameMode, quality, &rx_state);

    int16_t numSamplesOutput;
    int16_t outputBuf[kOutputBufferSize];
    pvDecoder_AmrWb(frameMode, inputSampleBuf, outputBuf, &numSamplesOutput, mDecoderBuffer,
                    frameType, mDecoderCookie);
    data += minSize;
    size -= minSize;
    delete[] inputBuf;
  }
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size < 2) {
    return 0;
  }
  Codec *codec = new Codec();
  if (!codec) {
    return 0;
  }
  if (codec->initDecoder()) {
    codec->decodeFrames(data, size);
  }
  delete codec;
  return 0;
}
