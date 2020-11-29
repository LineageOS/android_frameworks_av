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

#include <stdlib.h>
#include <algorithm>

#include <pvmp3decoder_api.h>

constexpr int kMaxFrameSamples = 4608;
constexpr int kMaxChannels = 2;
constexpr e_equalization kEqualizerTypes[] = {flat, bass_boost, rock, pop,
                                              jazz, classical,  talk, flat_};

static bool parseMp3Header(uint32_t header, size_t *frame_size,
                           uint32_t *out_sampling_rate = nullptr, uint32_t *out_channels = nullptr,
                           uint32_t *out_bitrate = nullptr, uint32_t *out_num_samples = nullptr) {
  *frame_size = 0;
  if (out_sampling_rate) *out_sampling_rate = 0;
  if (out_channels) *out_channels = 0;
  if (out_bitrate) *out_bitrate = 0;
  if (out_num_samples) *out_num_samples = 0;

  if ((header & 0xffe00000) != 0xffe00000) {
    return false;
  }
  unsigned version = (header >> 19) & 3;
  if (version == 0x01) {
    return false;
  }
  unsigned layer = (header >> 17) & 3;
  if (layer == 0x00) {
    return false;
  }
  unsigned bitrate_index = (header >> 12) & 0x0f;
  if (bitrate_index == 0 || bitrate_index == 0x0f) {
    return false;
  }
  unsigned sampling_rate_index = (header >> 10) & 3;
  if (sampling_rate_index == 3) {
    return false;
  }
  static const int kSamplingRateV1[] = {44100, 48000, 32000};
  int sampling_rate = kSamplingRateV1[sampling_rate_index];
  if (version == 2 /* V2 */) {
    sampling_rate /= 2;
  } else if (version == 0 /* V2.5 */) {
    sampling_rate /= 4;
  }

  unsigned padding = (header >> 9) & 1;

  if (layer == 3) {  // layer I
    static const int kBitrateV1[] = {32,  64,  96,  128, 160, 192, 224,
                                     256, 288, 320, 352, 384, 416, 448};
    static const int kBitrateV2[] = {32,  48,  56,  64,  80,  96,  112,
                                     128, 144, 160, 176, 192, 224, 256};

    int bitrate =
        (version == 3 /* V1 */) ? kBitrateV1[bitrate_index - 1] : kBitrateV2[bitrate_index - 1];

    if (out_bitrate) {
      *out_bitrate = bitrate;
    }
    *frame_size = (12000 * bitrate / sampling_rate + padding) * 4;
    if (out_num_samples) {
      *out_num_samples = 384;
    }
  } else {  // layer II or III
    static const int kBitrateV1L2[] = {32,  48,  56,  64,  80,  96,  112,
                                       128, 160, 192, 224, 256, 320, 384};
    static const int kBitrateV1L3[] = {32,  40,  48,  56,  64,  80,  96,
                                       112, 128, 160, 192, 224, 256, 320};
    static const int kBitrateV2[] = {8, 16, 24, 32, 40, 48, 56, 64, 80, 96, 112, 128, 144, 160};
    int bitrate;
    if (version == 3 /* V1 */) {
      bitrate =
          (layer == 2 /* L2 */) ? kBitrateV1L2[bitrate_index - 1] : kBitrateV1L3[bitrate_index - 1];

      if (out_num_samples) {
        *out_num_samples = 1152;
      }
    } else {  // V2 (or 2.5)
      bitrate = kBitrateV2[bitrate_index - 1];
      if (out_num_samples) {
        *out_num_samples = (layer == 1 /* L3 */) ? 576 : 1152;
      }
    }

    if (out_bitrate) {
      *out_bitrate = bitrate;
    }

    if (version == 3 /* V1 */) {
      *frame_size = 144000 * bitrate / sampling_rate + padding;
    } else {  // V2 or V2.5
      size_t tmp = (layer == 1 /* L3 */) ? 72000 : 144000;
      *frame_size = tmp * bitrate / sampling_rate + padding;
    }
  }

  if (out_sampling_rate) {
    *out_sampling_rate = sampling_rate;
  }

  if (out_channels) {
    int channel_mode = (header >> 6) & 3;
    *out_channels = (channel_mode == 3) ? 1 : 2;
  }

  return true;
}

static uint32_t U32_AT(const uint8_t *ptr) {
  return ptr[0] << 24 | ptr[1] << 16 | ptr[2] << 8 | ptr[3];
}

static bool checkHeader(uint8 *header, size_t inSize) {
  size_t frameSize;
  size_t totalInSize = 0;
  bool isValidBuffer = false;

  while (totalInSize + 4 < inSize) {
    isValidBuffer = true;
    uint32_t val = U32_AT(header + totalInSize);
    if (!parseMp3Header(val, &frameSize, nullptr, nullptr, nullptr, nullptr)) {
      return false;
    }
    totalInSize += frameSize;
  }

  return (isValidBuffer);
}

class Codec {
 public:
  Codec() = default;
  ~Codec() { deInitDecoder(); }

  bool initDecoder();
  void decodeFrames(uint8_t *data, size_t size);
  void deInitDecoder();

 private:
  tPVMP3DecoderExternal *mConfig = nullptr;
  void *mDecoderBuf = nullptr;
};

bool Codec::initDecoder() {
  mConfig = new tPVMP3DecoderExternal{};
  if (!mConfig) {
    return false;
  }
  size_t decoderBufSize = pvmp3_decoderMemRequirements();
  mDecoderBuf = malloc(decoderBufSize);
  if (!mDecoderBuf) {
    return false;
  }
  memset(mDecoderBuf, 0x0, decoderBufSize);
  pvmp3_InitDecoder(mConfig, mDecoderBuf);
  return true;
}

void Codec::decodeFrames(uint8_t *data, size_t size) {
  uint8_t equalizerTypeValue = (data[0] & 0x7);
  mConfig->equalizerType = kEqualizerTypes[equalizerTypeValue];
  mConfig->crcEnabled = data[1] & 0x1;

  while (size > 0) {
    bool status = checkHeader(data, size);
    if (!status) {
      size--;
      data++;
      continue;
    }
    size_t outBufSize = kMaxFrameSamples * kMaxChannels;
    size_t usedBytes = 0;
    int16_t outputBuf[outBufSize];
    mConfig->inputBufferCurrentLength = size;
    mConfig->inputBufferUsedLength = 0;
    mConfig->inputBufferMaxLength = 0;
    mConfig->pInputBuffer = data;
    mConfig->pOutputBuffer = outputBuf;
    mConfig->outputFrameSize = outBufSize / sizeof(int16_t);

    ERROR_CODE decoderErr;
    decoderErr = pvmp3_framedecoder(mConfig, mDecoderBuf);
    if (decoderErr != NO_DECODING_ERROR) {
      size--;
      data++;
    } else {
      usedBytes = std::min((int32_t)size, mConfig->inputBufferUsedLength);
      size -= usedBytes;
      data += usedBytes;
    }
  }
}

void Codec::deInitDecoder() {
  if (mDecoderBuf) {
    free(mDecoderBuf);
    mDecoderBuf = nullptr;
  }
  delete mConfig;
  mConfig = nullptr;
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
    codec->decodeFrames(const_cast<uint8_t *>(data), size);
  }
  delete codec;
  return 0;
}
