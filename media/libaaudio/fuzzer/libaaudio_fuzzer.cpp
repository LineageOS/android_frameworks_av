/*
 * Copyright (C) 2021 The Android Open Source Project
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

#include "aaudio/AAudio.h"
#include "aaudio/AAudioTesting.h"
#include <fuzzer/FuzzedDataProvider.h>

#include <functional>

constexpr int32_t kRandomStringLength = 256;
constexpr int32_t kMaxRuns = 100;
constexpr int64_t kNanosPerMillisecond = 1000 * 1000;

constexpr aaudio_direction_t kDirections[] = {
    AAUDIO_DIRECTION_OUTPUT, AAUDIO_DIRECTION_INPUT, AAUDIO_UNSPECIFIED};

constexpr aaudio_performance_mode_t kPerformanceModes[] = {
    AAUDIO_PERFORMANCE_MODE_NONE, AAUDIO_PERFORMANCE_MODE_POWER_SAVING,
    AAUDIO_PERFORMANCE_MODE_LOW_LATENCY, AAUDIO_UNSPECIFIED};

constexpr aaudio_format_t kFormats[] = {
    AAUDIO_FORMAT_INVALID,        AAUDIO_FORMAT_UNSPECIFIED,
    AAUDIO_FORMAT_PCM_I16,        AAUDIO_FORMAT_PCM_FLOAT,
    AAUDIO_FORMAT_PCM_I24_PACKED, AAUDIO_FORMAT_PCM_I32};

constexpr aaudio_sharing_mode_t kSharingModes[] = {
    AAUDIO_SHARING_MODE_EXCLUSIVE, AAUDIO_SHARING_MODE_SHARED};

constexpr int32_t kSampleRates[] = {AAUDIO_UNSPECIFIED,
                                    8000,
                                    11025,
                                    16000,
                                    22050,
                                    32000,
                                    44100,
                                    48000,
                                    88200,
                                    96000};

constexpr aaudio_usage_t kUsages[] = {
    AAUDIO_USAGE_MEDIA,
    AAUDIO_USAGE_VOICE_COMMUNICATION,
    AAUDIO_USAGE_VOICE_COMMUNICATION_SIGNALLING,
    AAUDIO_USAGE_ALARM,
    AAUDIO_USAGE_NOTIFICATION,
    AAUDIO_USAGE_NOTIFICATION_RINGTONE,
    AAUDIO_USAGE_NOTIFICATION_EVENT,
    AAUDIO_USAGE_ASSISTANCE_ACCESSIBILITY,
    AAUDIO_USAGE_ASSISTANCE_NAVIGATION_GUIDANCE,
    AAUDIO_USAGE_ASSISTANCE_SONIFICATION,
    AAUDIO_USAGE_GAME,
    AAUDIO_USAGE_ASSISTANT,
    AAUDIO_SYSTEM_USAGE_EMERGENCY,
    AAUDIO_SYSTEM_USAGE_SAFETY,
    AAUDIO_SYSTEM_USAGE_VEHICLE_STATUS,
    AAUDIO_SYSTEM_USAGE_ANNOUNCEMENT,
    AAUDIO_UNSPECIFIED};

constexpr aaudio_content_type_t kContentTypes[] = {
    AAUDIO_CONTENT_TYPE_SPEECH, AAUDIO_CONTENT_TYPE_MUSIC,
    AAUDIO_CONTENT_TYPE_MOVIE, AAUDIO_CONTENT_TYPE_SONIFICATION,
    AAUDIO_UNSPECIFIED};

constexpr aaudio_input_preset_t kInputPresets[] = {
    AAUDIO_INPUT_PRESET_GENERIC,
    AAUDIO_INPUT_PRESET_CAMCORDER,
    AAUDIO_INPUT_PRESET_VOICE_RECOGNITION,
    AAUDIO_INPUT_PRESET_VOICE_COMMUNICATION,
    AAUDIO_INPUT_PRESET_UNPROCESSED,
    AAUDIO_INPUT_PRESET_VOICE_PERFORMANCE,
    AAUDIO_UNSPECIFIED};

constexpr aaudio_allowed_capture_policy_t kAllowedCapturePolicies[] = {
    AAUDIO_ALLOW_CAPTURE_BY_ALL, AAUDIO_ALLOW_CAPTURE_BY_SYSTEM,
    AAUDIO_ALLOW_CAPTURE_BY_NONE, AAUDIO_UNSPECIFIED};

constexpr aaudio_session_id_t kSessionIds[] = {
    AAUDIO_SESSION_ID_NONE, AAUDIO_SESSION_ID_ALLOCATE, AAUDIO_UNSPECIFIED};

constexpr aaudio_policy_t kPolicies[] = {
    AAUDIO_POLICY_NEVER, AAUDIO_POLICY_AUTO, AAUDIO_POLICY_ALWAYS,
    AAUDIO_UNSPECIFIED};

class LibAaudioFuzzer {
public:
  ~LibAaudioFuzzer() { deInit(); }
  bool init();
  void invokeAAudioSetAPIs(FuzzedDataProvider &fdp);
  void process(const uint8_t *data, size_t size);
  void deInit();

private:
  AAudioStreamBuilder *mAaudioBuilder = nullptr;
  AAudioStream *mAaudioStream = nullptr;
};

bool LibAaudioFuzzer::init() {
  aaudio_result_t result = AAudio_createStreamBuilder(&mAaudioBuilder);
  if ((result != AAUDIO_OK) || (!mAaudioBuilder)) {
    return false;
  }
  return true;
}

void LibAaudioFuzzer::invokeAAudioSetAPIs(FuzzedDataProvider &fdp){
  aaudio_performance_mode_t mode = fdp.PickValueInArray(
          {fdp.PickValueInArray(kPerformanceModes), fdp.ConsumeIntegral<int32_t>()});
  AAudioStreamBuilder_setPerformanceMode(mAaudioBuilder, mode);

  int32_t deviceId = fdp.PickValueInArray({AAUDIO_UNSPECIFIED, fdp.ConsumeIntegral<int32_t>()});
  AAudioStreamBuilder_setDeviceId(mAaudioBuilder, deviceId);

  std::string packageName =
          fdp.PickValueInArray<std::string>({"android.nativemedia.aaudio", "android.app.appops.cts",
                                             fdp.ConsumeRandomLengthString(kRandomStringLength)});
  AAudioStreamBuilder_setPackageName(mAaudioBuilder, packageName.c_str());

  std::string attributionTag = fdp.ConsumeRandomLengthString(kRandomStringLength);
  AAudioStreamBuilder_setAttributionTag(mAaudioBuilder, attributionTag.c_str());

  int32_t sampleRate = fdp.PickValueInArray(kSampleRates);
  AAudioStreamBuilder_setSampleRate(mAaudioBuilder, sampleRate);

  int32_t channelCount = fdp.PickValueInArray({AAUDIO_UNSPECIFIED, fdp.ConsumeIntegral<int32_t>()});
  AAudioStreamBuilder_setChannelCount(mAaudioBuilder, channelCount);

  aaudio_direction_t direction =
          fdp.PickValueInArray({fdp.PickValueInArray(kDirections), fdp.ConsumeIntegral<int32_t>()});
  AAudioStreamBuilder_setDirection(mAaudioBuilder, direction);

  aaudio_format_t format =
          fdp.PickValueInArray({fdp.PickValueInArray(kFormats), fdp.ConsumeIntegral<int32_t>()});
  AAudioStreamBuilder_setFormat(mAaudioBuilder, format);

  aaudio_sharing_mode_t sharingMode = fdp.PickValueInArray(
          {fdp.PickValueInArray(kSharingModes), fdp.ConsumeIntegral<int32_t>()});
  AAudioStreamBuilder_setSharingMode(mAaudioBuilder, sharingMode);

  aaudio_usage_t usage =
          fdp.PickValueInArray({fdp.PickValueInArray(kUsages), fdp.ConsumeIntegral<int32_t>()});
  AAudioStreamBuilder_setUsage(mAaudioBuilder, usage);

  aaudio_content_type_t contentType = fdp.PickValueInArray(
          {fdp.PickValueInArray(kContentTypes), fdp.ConsumeIntegral<int32_t>()});
  AAudioStreamBuilder_setContentType(mAaudioBuilder, contentType);

  aaudio_input_preset_t inputPreset = fdp.PickValueInArray(
          {fdp.PickValueInArray(kInputPresets), fdp.ConsumeIntegral<int32_t>()});
  AAudioStreamBuilder_setInputPreset(mAaudioBuilder, inputPreset);

  bool privacySensitive = fdp.ConsumeBool();
  AAudioStreamBuilder_setPrivacySensitive(mAaudioBuilder, privacySensitive);

  int32_t frames = fdp.PickValueInArray({AAUDIO_UNSPECIFIED, fdp.ConsumeIntegral<int32_t>()});
  AAudioStreamBuilder_setBufferCapacityInFrames(mAaudioBuilder, frames);

  aaudio_allowed_capture_policy_t allowedCapturePolicy = fdp.PickValueInArray(
          {fdp.PickValueInArray(kAllowedCapturePolicies), fdp.ConsumeIntegral<int32_t>()});
  AAudioStreamBuilder_setAllowedCapturePolicy(mAaudioBuilder, allowedCapturePolicy);

  aaudio_session_id_t sessionId =
          fdp.PickValueInArray({fdp.PickValueInArray(kSessionIds), fdp.ConsumeIntegral<int32_t>()});
  AAudioStreamBuilder_setSessionId(mAaudioBuilder, sessionId);

  AAudioStreamBuilder_setDataCallback(mAaudioBuilder, nullptr, nullptr);
  AAudioStreamBuilder_setErrorCallback(mAaudioBuilder, nullptr, nullptr);

  int32_t framesPerDataCallback =
          fdp.PickValueInArray({AAUDIO_UNSPECIFIED, fdp.ConsumeIntegral<int32_t>()});
  AAudioStreamBuilder_setFramesPerDataCallback(mAaudioBuilder, framesPerDataCallback);

  aaudio_policy_t policy =
          fdp.PickValueInArray({fdp.PickValueInArray(kPolicies), fdp.ConsumeIntegral<int32_t>()});
  AAudio_setMMapPolicy(policy);
}

void LibAaudioFuzzer::process(const uint8_t *data, size_t size) {
  FuzzedDataProvider fdp(data, size);
  int32_t maxFrames = 0;
  int32_t count = 0;
  aaudio_stream_state_t state = AAUDIO_STREAM_STATE_UNKNOWN;

  invokeAAudioSetAPIs(fdp);

  aaudio_result_t result = AAudioStreamBuilder_openStream(mAaudioBuilder, &mAaudioStream);
  if ((result != AAUDIO_OK) || (!mAaudioStream)) {
    return;
  }
  /* The 'runs' variable serves to set an upper limit on the loop iterations, preventing excessive
   * execution.
   */
  int32_t runs = kMaxRuns;
  while (fdp.remaining_bytes() > 0 && --runs) {
    auto AAudioapi = fdp.PickValueInArray<const std::function<void()>>({
            [&]() { (void)AAudio_getMMapPolicy(); },

            [&]() {
                int32_t framesPerBurst = AAudioStream_getFramesPerBurst(mAaudioStream);
                uint8_t numberOfBursts = fdp.ConsumeIntegral<uint8_t>();
                maxFrames = numberOfBursts * framesPerBurst;
                int32_t requestedBufferSize = fdp.ConsumeIntegral<uint16_t>() * framesPerBurst;
                AAudioStream_setBufferSizeInFrames(mAaudioStream, requestedBufferSize);
            },
            [&]() {
                int64_t position = 0, nanoseconds = 0;
                AAudioStream_getTimestamp(mAaudioStream, CLOCK_MONOTONIC, &position, &nanoseconds);
            },
            [&]() {
                AAudioStream_requestStart(mAaudioStream);
            },
            [&]() {
                AAudioStream_requestPause(mAaudioStream);
            },
            [&]() {
                AAudioStream_requestFlush(mAaudioStream);
            },
            [&]() {
                AAudioStream_requestStop(mAaudioStream);
            },
            [&]() {
                aaudio_format_t actualFormat = AAudioStream_getFormat(mAaudioStream);
                int32_t actualChannelCount = AAudioStream_getChannelCount(mAaudioStream);

                count = fdp.ConsumeIntegral<int32_t>();
                aaudio_direction_t direction = AAudioStream_getDirection(mAaudioStream);

                if (actualFormat == AAUDIO_FORMAT_PCM_I16) {
                    std::vector<int16_t> inputShortData(maxFrames * actualChannelCount, 0x0);
                    if (direction == AAUDIO_DIRECTION_INPUT) {
                        AAudioStream_read(mAaudioStream, inputShortData.data(), maxFrames,
                                          count * kNanosPerMillisecond);
                    } else if (direction == AAUDIO_DIRECTION_OUTPUT) {
                        AAudioStream_write(mAaudioStream, inputShortData.data(), maxFrames,
                                           count * kNanosPerMillisecond);
                    }
                } else if (actualFormat == AAUDIO_FORMAT_PCM_FLOAT) {
                    std::vector<float> inputFloatData(maxFrames * actualChannelCount, 0x0);
                    if (direction == AAUDIO_DIRECTION_INPUT) {
                        AAudioStream_read(mAaudioStream, inputFloatData.data(), maxFrames,
                                          count * kNanosPerMillisecond);
                    } else if (direction == AAUDIO_DIRECTION_OUTPUT) {
                        AAudioStream_write(mAaudioStream, inputFloatData.data(), maxFrames,
                                           count * kNanosPerMillisecond);
                    }
                }
            },
            [&]() {
                AAudioStream_waitForStateChange(mAaudioStream, AAUDIO_STREAM_STATE_UNKNOWN, &state,
                                                count * kNanosPerMillisecond);
            },
            [&]() { (void)AAudio_convertStreamStateToText(state); },
            [&]() {
                (void)AAudioStream_getState(mAaudioStream);
            },
            [&]() {
                (void)AAudioStream_getUsage(mAaudioStream);
            },
            [&]() {
                (void)AAudioStream_getSamplesPerFrame(mAaudioStream);
            },
            [&]() {
                (void)AAudioStream_getContentType(mAaudioStream);
            },
            [&]() {
                (void)AAudioStream_getInputPreset(mAaudioStream);
            },
            [&]() {
                (void)AAudioStream_isPrivacySensitive(mAaudioStream);
            },
            [&]() {
                (void)AAudioStream_getAllowedCapturePolicy(mAaudioStream);
            },
            [&]() {
                (void)AAudioStream_getPerformanceMode(mAaudioStream);
            },
            [&]() {
                (void)AAudioStream_getDeviceId(mAaudioStream);
            },
            [&]() {
                (void)AAudioStream_getSharingMode(mAaudioStream);
            },
            [&]() {
                (void)AAudioStream_getSessionId(mAaudioStream);
            },
            [&]() {
                (void)AAudioStream_getFramesRead(mAaudioStream);
            },
            [&]() {
                (void)AAudioStream_getXRunCount(mAaudioStream);
            },
            [&]() {
                (void)AAudioStream_getFramesWritten(mAaudioStream);
            },
            [&]() {
                (void)AAudioStream_getBufferCapacityInFrames(mAaudioStream);
            },
            [&]() {
                (void)AAudioStream_getBufferSizeInFrames(mAaudioStream);
            },
            [&]() {
                (void)AAudioStream_isMMapUsed(mAaudioStream);
            },
    });
    AAudioapi();
  }
  AAudioStream_release(mAaudioStream);
}

void LibAaudioFuzzer::deInit() {
  if (mAaudioBuilder) {
    AAudioStreamBuilder_delete(mAaudioBuilder);
  }
  if (mAaudioStream) {
    AAudioStream_close(mAaudioStream);
  }
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  LibAaudioFuzzer libAaudioFuzzer;
  if (libAaudioFuzzer.init()) {
    libAaudioFuzzer.process(data, size);
  }
  return 0;
}
