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
#include <string.h>
#include <algorithm>
#include "gsmamr_dec.h"

// Constants for AMR-NB
constexpr int32_t kSamplesPerFrame = L_FRAME;
constexpr int32_t kBitsPerSample = 16;
constexpr int32_t kOutputBufferSize = kSamplesPerFrame * kBitsPerSample / 8;
const bitstream_format kBitStreamFormats[2] = {MIME_IETF, IF2};
const int32_t kLocalWmfDecBytesPerFrame[8] = {12, 13, 15, 17, 19, 20, 26, 31};
const int32_t kLocalIf2DecBytesPerFrame[8] = {13, 14, 16, 18, 19, 21, 26, 31};

class Codec {
 public:
  Codec() = default;
  ~Codec() { deInitDecoder(); }
  int16_t initDecoder();
  void deInitDecoder();
  void decodeFrames(const uint8_t *data, size_t size);

 private:
  void *mAmrHandle = nullptr;
};

int16_t Codec::initDecoder() { return GSMInitDecode(&mAmrHandle, (Word8 *)"AMRNBDecoder"); }

void Codec::deInitDecoder() { GSMDecodeFrameExit(&mAmrHandle); }

void Codec::decodeFrames(const uint8_t *data, size_t size) {
  while (size > 0) {
    uint8_t mode = *data;
    bool bit = mode & 0x01;
    bitstream_format bitsreamFormat = kBitStreamFormats[bit];
    int32_t frameSize = 0;
    /* Find frame type */
    Frame_Type_3GPP frameType = static_cast<Frame_Type_3GPP>((mode >> 3) & 0x07);
    ++data;
    --size;
    if (bit) {
      frameSize = kLocalIf2DecBytesPerFrame[frameType];
    } else {
      frameSize = kLocalWmfDecBytesPerFrame[frameType];
    }
    int16_t outputBuf[kOutputBufferSize];
    uint8_t *inputBuf = new uint8_t[frameSize];
    if (!inputBuf) {
      return;
    }
    int32_t minSize = std::min((int32_t)size, frameSize);
    memcpy(inputBuf, data, minSize);
    AMRDecode(mAmrHandle, frameType, inputBuf, outputBuf, bitsreamFormat);
    /* AMRDecode() decodes minSize number of bytes if decode is successful.
     * AMRDecode() returns -1 if decode fails.
     * Even if no bytes are decoded, increment by minSize to ensure fuzzer proceeds
     * to feed next data */
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
  if (codec->initDecoder() == 0) {
    codec->decodeFrames(data, size);
  }
  delete codec;
  return 0;
}
