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
#include "mp4dec_api.h"
#define MPEG4_MAX_WIDTH 1920
#define MPEG4_MAX_HEIGHT 1080
#define H263_MAX_WIDTH 352
#define H263_MAX_HEIGHT 288
#define DEFAULT_WIDTH 352
#define DEFAULT_HEIGHT 288

constexpr size_t kMaxNumDecodeCalls = 100;
constexpr uint8_t kNumOutputBuffers = 2;
constexpr int kLayer = 1;

struct tagvideoDecControls;

/* == ceil(num / den) * den. T must be integer type, alignment must be positive power of 2 */
template <class T, class U>
inline static const T align(const T &num, const U &den) {
  return (num + (T)(den - 1)) & (T) ~(den - 1);
}

class Codec {
 public:
  Codec() = default;
  ~Codec() { deInitDecoder(); }
  bool initDecoder();
  bool allocOutputBuffer(size_t outputBufferSize);
  void freeOutputBuffer();
  void handleResolutionChange();
  void decodeFrames(const uint8_t *data, size_t size);
  void deInitDecoder();

 private:
  tagvideoDecControls *mDecHandle = nullptr;
  uint8_t *mOutputBuffer[kNumOutputBuffers];
  bool mInitialized = false;
  bool mFramesConfigured = false;
#ifdef MPEG4
  MP4DecodingMode mInputMode = MPEG4_MODE;
  size_t mMaxWidth = MPEG4_MAX_WIDTH;
  size_t mMaxHeight = MPEG4_MAX_HEIGHT;
#else
  MP4DecodingMode mInputMode = H263_MODE;
  size_t mMaxWidth = H263_MAX_WIDTH;
  size_t mMaxHeight = H263_MAX_HEIGHT;
#endif
  uint32_t mNumSamplesOutput = 0;
  uint32_t mWidth = DEFAULT_WIDTH;
  uint32_t mHeight = DEFAULT_HEIGHT;
};

bool Codec::initDecoder() {
  mDecHandle = new tagvideoDecControls;
  if (!mDecHandle) {
    return false;
  }
  memset(mDecHandle, 0, sizeof(tagvideoDecControls));
  return true;
}

bool Codec::allocOutputBuffer(size_t outputBufferSize) {
  for (uint8_t i = 0; i < kNumOutputBuffers; ++i) {
    if (!mOutputBuffer[i]) {
      mOutputBuffer[i] = static_cast<uint8_t *>(malloc(outputBufferSize));
      if (!mOutputBuffer[i]) {
        return false;
      }
    }
  }
  return true;
}

void Codec::freeOutputBuffer() {
  for (uint8_t i = 0; i < kNumOutputBuffers; ++i) {
    if (mOutputBuffer[i]) {
      free(mOutputBuffer[i]);
      mOutputBuffer[i] = nullptr;
    }
  }
}

void Codec::handleResolutionChange() {
  int32_t dispWidth, dispHeight;
  PVGetVideoDimensions(mDecHandle, &dispWidth, &dispHeight);

  int32_t bufWidth, bufHeight;
  PVGetBufferDimensions(mDecHandle, &bufWidth, &bufHeight);

  if (dispWidth != mWidth || dispHeight != mHeight) {
    mWidth = dispWidth;
    mHeight = dispHeight;
  }
}

void Codec::decodeFrames(const uint8_t *data, size_t size) {
  size_t outputBufferSize = align(mMaxWidth, 16) * align(mMaxHeight, 16) * 3 / 2;
  uint8_t *start_code = const_cast<uint8_t *>(data);
  static const uint8_t volInfo[] = {0x00, 0x00, 0x01, 0xB0};
  bool volHeader = memcmp(start_code, volInfo, 4) == 0;
  if (volHeader) {
    PVCleanUpVideoDecoder(mDecHandle);
    mInitialized = false;
  }

  if (!mInitialized) {
    uint8_t *volData[1]{};
    int32_t volSize = 0;

    if (volHeader) { /* removed some codec config part */
      volData[0] = const_cast<uint8_t *>(data);
      volSize = size;
    }

    if (!PVInitVideoDecoder(mDecHandle, volData, &volSize, kLayer, mMaxWidth, mMaxHeight,
                            mInputMode)) {
      return;
    }
    mInitialized = true;
    MP4DecodingMode actualMode = PVGetDecBitstreamMode(mDecHandle);
    if (mInputMode != actualMode) {
      return;
    }

    PVSetPostProcType(mDecHandle, 0);
  }
  size_t yFrameSize = sizeof(uint8) * mDecHandle->size;
  if (outputBufferSize < yFrameSize * 3 / 2) {
    return;
  }
  if (!allocOutputBuffer(outputBufferSize)) {
    return;
  }
  size_t numDecodeCalls = 0;
  while ((size > 0) && (numDecodeCalls < kMaxNumDecodeCalls)) {
    if (!mFramesConfigured) {
      PVSetReferenceYUV(mDecHandle, mOutputBuffer[1]);
      mFramesConfigured = true;
    }

    // Need to check if header contains new info, e.g., width/height, etc.
    VopHeaderInfo header_info;
    uint32_t useExtTimestamp = (numDecodeCalls == 0);
    int32_t tempSize = (int32_t)size;
    uint8_t *bitstreamTmp = const_cast<uint8_t *>(data);
    uint32_t timestamp = 0;
    if (PVDecodeVopHeader(mDecHandle, &bitstreamTmp, &timestamp, &tempSize, &header_info,
                          &useExtTimestamp, mOutputBuffer[mNumSamplesOutput & 1]) != PV_TRUE) {
      return;
    }

    handleResolutionChange();

    PVDecodeVopBody(mDecHandle, &tempSize);
    uint32_t bytesConsumed = 1;
    if (size > tempSize) {
      bytesConsumed = size - tempSize;
    }
    data += bytesConsumed;
    size -= bytesConsumed;
    ++mNumSamplesOutput;
    ++numDecodeCalls;
  }
  freeOutputBuffer();
}

void Codec::deInitDecoder() {
  PVCleanUpVideoDecoder(mDecHandle);
  delete mDecHandle;
  mDecHandle = nullptr;
  mInitialized = false;
  freeOutputBuffer();
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size < 4) {
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
