/*
 * Copyright (C) 2020 The Android Open Source Project
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

#include "libaudioprocessing_fuzz_utils.h"
#include "fuzzer/FuzzedDataProvider.h"
#include <media/AudioResampler.h>
#include <media/RecordBufferConverter.h>
#include <stddef.h>
#include <stdint.h>

using namespace android;

constexpr int MAX_FRAMES = 1024;

#define AUDIO_FORMAT_PCM_MAIN 0

// Copied and simplified from audio-hal-enums.h?l=571
constexpr uint32_t FUZZ_AUDIO_FORMATS[] = {
  AUDIO_FORMAT_PCM_MAIN | AUDIO_FORMAT_PCM_SUB_16_BIT,
  AUDIO_FORMAT_PCM_MAIN | AUDIO_FORMAT_PCM_SUB_8_BIT,
  AUDIO_FORMAT_PCM_MAIN | AUDIO_FORMAT_PCM_SUB_32_BIT,
  AUDIO_FORMAT_PCM_MAIN | AUDIO_FORMAT_PCM_SUB_8_24_BIT,
  AUDIO_FORMAT_PCM_MAIN | AUDIO_FORMAT_PCM_SUB_FLOAT,
  AUDIO_FORMAT_PCM_MAIN | AUDIO_FORMAT_PCM_SUB_24_BIT_PACKED,
  0x01000000u,
  0x02000000u,
  0x03000000u,
  0x04000000u,
  AUDIO_FORMAT_AAC | AUDIO_FORMAT_AAC_SUB_MAIN,
  AUDIO_FORMAT_AAC | AUDIO_FORMAT_AAC_SUB_LC,
  AUDIO_FORMAT_AAC | AUDIO_FORMAT_AAC_SUB_SSR,
  AUDIO_FORMAT_AAC | AUDIO_FORMAT_AAC_SUB_LTP,
  AUDIO_FORMAT_AAC | AUDIO_FORMAT_AAC_SUB_HE_V1,
  AUDIO_FORMAT_AAC | AUDIO_FORMAT_AAC_SUB_SCALABLE,
  AUDIO_FORMAT_AAC | AUDIO_FORMAT_AAC_SUB_ERLC,
  AUDIO_FORMAT_AAC | AUDIO_FORMAT_AAC_SUB_LD,
  AUDIO_FORMAT_AAC | AUDIO_FORMAT_AAC_SUB_HE_V2,
  AUDIO_FORMAT_AAC | AUDIO_FORMAT_AAC_SUB_ELD,
  AUDIO_FORMAT_AAC | AUDIO_FORMAT_AAC_SUB_XHE,
  0x05000000u,
  0x06000000u,
  0x07000000u,
  0x08000000u,
  0x09000000u,
  0x0A000000u,
  AUDIO_FORMAT_E_AC3 | AUDIO_FORMAT_E_AC3_SUB_JOC,
  0x0B000000u,
  0x0C000000u,
  0x0D000000u,
  0x0E000000u,
  0x10000000u,
  0x11000000u,
  0x12000000u,
  0x13000000u,
  0x14000000u,
  0x15000000u,
  0x16000000u,
  0x17000000u,
  0x18000000u,
  0x19000000u,
  0x1A000000u,
  0x1B000000u,
  0x1C000000u,
  0x1D000000u,
  0x1E000000u,
  AUDIO_FORMAT_AAC_ADTS | AUDIO_FORMAT_AAC_SUB_MAIN,
  AUDIO_FORMAT_AAC_ADTS | AUDIO_FORMAT_AAC_SUB_LC,
  AUDIO_FORMAT_AAC_ADTS | AUDIO_FORMAT_AAC_SUB_SSR,
  AUDIO_FORMAT_AAC_ADTS | AUDIO_FORMAT_AAC_SUB_LTP,
  AUDIO_FORMAT_AAC_ADTS | AUDIO_FORMAT_AAC_SUB_HE_V1,
  AUDIO_FORMAT_AAC_ADTS | AUDIO_FORMAT_AAC_SUB_SCALABLE,
  AUDIO_FORMAT_AAC_ADTS | AUDIO_FORMAT_AAC_SUB_ERLC,
  AUDIO_FORMAT_AAC_ADTS | AUDIO_FORMAT_AAC_SUB_LD,
  AUDIO_FORMAT_AAC_ADTS | AUDIO_FORMAT_AAC_SUB_HE_V2,
  AUDIO_FORMAT_AAC_ADTS | AUDIO_FORMAT_AAC_SUB_ELD,
  AUDIO_FORMAT_AAC_ADTS | AUDIO_FORMAT_AAC_SUB_XHE,
  0x1F000000u,
  0x20000000u,
  0x21000000u,
  0x22000000u,
  0x23000000u,
  0x24000000u,
  AUDIO_FORMAT_MAT | AUDIO_FORMAT_MAT_SUB_1_0,
  AUDIO_FORMAT_MAT | AUDIO_FORMAT_MAT_SUB_2_0,
  AUDIO_FORMAT_MAT | AUDIO_FORMAT_MAT_SUB_2_1,
  0x25000000u,
  AUDIO_FORMAT_AAC_LATM | AUDIO_FORMAT_AAC_SUB_LC,
  AUDIO_FORMAT_AAC_LATM | AUDIO_FORMAT_AAC_SUB_HE_V1,
  AUDIO_FORMAT_AAC_LATM | AUDIO_FORMAT_AAC_SUB_HE_V2,
  0x26000000u,
  0x27000000u,
  0x28000000u,
  0x29000000u,
  0x2A000000u,
  0x2B000000u,
  0xFFFFFFFFu,
  AUDIO_FORMAT_PCM_MAIN,
  AUDIO_FORMAT_PCM,
};
constexpr size_t NUM_AUDIO_FORMATS = std::size(FUZZ_AUDIO_FORMATS);

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  FuzzedDataProvider fdp(data, size);
  fdp.ConsumeIntegral<int>();

  const audio_channel_mask_t srcChannelMask = (audio_channel_mask_t)fdp.ConsumeIntegral<int>();
  const audio_format_t srcFormat =
      (audio_format_t)FUZZ_AUDIO_FORMATS[fdp.ConsumeIntegralInRange<int>(0, NUM_AUDIO_FORMATS - 1)];
  const uint32_t srcSampleRate = fdp.ConsumeIntegralInRange<int>(1, 0x7fffffff);
  const audio_channel_mask_t dstChannelMask = (audio_channel_mask_t)fdp.ConsumeIntegral<int>();
  const audio_format_t dstFormat =
      (audio_format_t)FUZZ_AUDIO_FORMATS[fdp.ConsumeIntegralInRange<int>(0, NUM_AUDIO_FORMATS - 1)];
  const uint32_t dstSampleRate = fdp.ConsumeIntegralInRange<int>(1, 0x7fffffff);

  // Certain formats will result in LOG_ALWAYS_FATAL errors that aren't interesting crashes
  // for fuzzing.  Don't use those ones.
  const uint32_t dstChannelCount = audio_channel_count_from_in_mask(dstChannelMask);
  constexpr android::AudioResampler::src_quality quality =
      android::AudioResampler::DEFAULT_QUALITY;
  const int maxChannels =
      quality < android::AudioResampler::DYN_LOW_QUALITY ? 2 : 8;
  if (dstChannelCount < 1 || dstChannelCount > maxChannels) {
    return 0;
  }

  const uint32_t srcChannelCount = audio_channel_count_from_in_mask(srcChannelMask);
  if (srcChannelCount < 1 || srcChannelCount > maxChannels) {
    return 0;
  }

  RecordBufferConverter converter(srcChannelMask, srcFormat, srcSampleRate,
                                  dstChannelMask, dstFormat, dstSampleRate);
  if (converter.initCheck() != NO_ERROR) {
    return 0;
  }

  const uint32_t srcFrameSize = srcChannelCount * audio_bytes_per_sample(srcFormat);
  const int srcNumFrames = fdp.ConsumeIntegralInRange<int>(0, MAX_FRAMES);
  constexpr size_t metadataSize = 2 + 3 * sizeof(int) + 2 * sizeof(float);
  std::vector<uint8_t> inputData = fdp.ConsumeBytes<uint8_t>(
      metadataSize + (srcFrameSize * srcNumFrames));
  Provider provider(inputData.data(), srcNumFrames, srcFrameSize);

  const uint32_t dstFrameSize = dstChannelCount * audio_bytes_per_sample(dstFormat);
  const size_t frames = fdp.ConsumeIntegralInRange<size_t>(0, MAX_FRAMES + 1);
  int8_t dst[dstFrameSize * frames];
  memset(dst, 0, sizeof(int8_t) * dstFrameSize * frames);

  // Add a small number of loops to see if repeated calls to convert cause
  // any change in behavior.
  const int numLoops = fdp.ConsumeIntegralInRange<int>(1, 3);
  for (int loop = 0; loop < numLoops; ++loop) {
    switch (fdp.ConsumeIntegralInRange<int>(0, 1)) {
      case 0:
        converter.reset();
        FALLTHROUGH_INTENDED;
      case 1:
        converter.convert(dst, &provider, frames);
        break;
    }
  }

  return 0;
}
