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

#include <fstream>
#include <iostream>
#include <string>
#include <tuple>
#include <vector>

// #define LOG_NDEBUG 0
#define LOG_TAG "AudioEffectAnalyser"

#include <android-base/file.h>
#include <android-base/stringprintf.h>
#include <binder/ProcessState.h>
#include <gtest/gtest.h>
#include <media/AudioEffect.h>
#include <system/audio_effects/effect_bassboost.h>
#include <system/audio_effects/effect_equalizer.h>

#include "audio_test_utils.h"
#include "pffft.hpp"
#include "test_execution_tracer.h"

#define CHECK_OK(expr, msg) \
    mStatus = (expr);       \
    if (OK != mStatus) {    \
        mMsg = (msg);       \
        return;             \
    }

using namespace android;

constexpr float kDefAmplitude = 0.60f;

constexpr float kPlayBackDurationSec = 1.5;
constexpr float kCaptureDurationSec = 1.0;
constexpr float kPrimeDurationInSec = 0.5;

// chosen to safely sample largest center freq of eq bands
constexpr uint32_t kSamplingFrequency = 48000;

// allows no fmt conversion before fft
constexpr audio_format_t kFormat = AUDIO_FORMAT_PCM_FLOAT;

// playback and capture are done with channel mask configured to mono.
// effect analysis should not depend on mask, mono makes it easier.

constexpr int kNPointFFT = 16384;
constexpr float kBinWidth = (float)kSamplingFrequency / kNPointFFT;

const char* gPackageName = "AudioEffectAnalyser";

static_assert(kPrimeDurationInSec + 2 * kNPointFFT / kSamplingFrequency < kCaptureDurationSec,
              "capture at least, prime, pad, nPointFft size of samples");
static_assert(kPrimeDurationInSec + 2 * kNPointFFT / kSamplingFrequency < kPlayBackDurationSec,
              "playback needs to be active during capture");

struct CaptureEnv {
    // input args
    uint32_t mSampleRate{kSamplingFrequency};
    audio_format_t mFormat{kFormat};
    audio_channel_mask_t mChannelMask{AUDIO_CHANNEL_IN_MONO};
    float mCaptureDuration{kCaptureDurationSec};
    // output val
    status_t mStatus{OK};
    std::string mMsg;
    std::string mDumpFileName;

    ~CaptureEnv();
    void capture();
};

CaptureEnv::~CaptureEnv() {
    if (!mDumpFileName.empty()) {
        std::ifstream f(mDumpFileName);
        if (f.good()) {
            f.close();
            remove(mDumpFileName.c_str());
        }
    }
}

void CaptureEnv::capture() {
    audio_port_v7 port;
    CHECK_OK(getPortByAttributes(AUDIO_PORT_ROLE_SOURCE, AUDIO_PORT_TYPE_DEVICE,
                                 AUDIO_DEVICE_IN_REMOTE_SUBMIX, "0", port),
             "Could not find port")
    const auto capture =
            sp<AudioCapture>::make(AUDIO_SOURCE_REMOTE_SUBMIX, mSampleRate, mFormat, mChannelMask);
    CHECK_OK(capture->create(), "record creation failed")
    CHECK_OK(capture->setRecordDuration(mCaptureDuration), "set record duration failed")
    CHECK_OK(capture->enableRecordDump(), "enable record dump failed")
    auto cbCapture = sp<OnAudioDeviceUpdateNotifier>::make();
    CHECK_OK(capture->getAudioRecordHandle()->addAudioDeviceCallback(cbCapture),
             "addAudioDeviceCallback failed")
    CHECK_OK(capture->start(), "start recording failed")
    CHECK_OK(capture->audioProcess(), "recording process failed")
    CHECK_OK(cbCapture->waitForAudioDeviceCb(), "audio device callback notification timed out");
    if (port.id != capture->getAudioRecordHandle()->getRoutedDeviceId()) {
        CHECK_OK(BAD_VALUE, "Capture NOT routed on expected port")
    }
    CHECK_OK(getPortByAttributes(AUDIO_PORT_ROLE_SINK, AUDIO_PORT_TYPE_DEVICE,
                                 AUDIO_DEVICE_OUT_REMOTE_SUBMIX, "0", port),
             "Could not find port")
    CHECK_OK(capture->stop(), "record stop failed")
    mDumpFileName = capture->getRecordDumpFileName();
}

struct PlaybackEnv {
    // input args
    uint32_t mSampleRate{kSamplingFrequency};
    audio_format_t mFormat{kFormat};
    audio_channel_mask_t mChannelMask{AUDIO_CHANNEL_OUT_MONO};
    audio_session_t mSessionId{AUDIO_SESSION_NONE};
    std::string mRes;
    // output val
    status_t mStatus{OK};
    std::string mMsg;

    void play();
};

void PlaybackEnv::play() {
    const auto ap =
            sp<AudioPlayback>::make(mSampleRate, mFormat, mChannelMask, AUDIO_OUTPUT_FLAG_NONE,
                                    mSessionId, AudioTrack::TRANSFER_OBTAIN);
    CHECK_OK(ap->loadResource(mRes.c_str()), "Unable to open Resource")
    const auto cbPlayback = sp<OnAudioDeviceUpdateNotifier>::make();
    CHECK_OK(ap->create(), "track creation failed")
    ap->getAudioTrackHandle()->setVolume(1.0f);
    CHECK_OK(ap->getAudioTrackHandle()->addAudioDeviceCallback(cbPlayback),
             "addAudioDeviceCallback failed")
    CHECK_OK(ap->start(), "audio track start failed")
    CHECK_OK(cbPlayback->waitForAudioDeviceCb(), "audio device callback notification timed out")
    CHECK_OK(ap->onProcess(), "playback process failed")
    ap->stop();
}

void generateMultiTone(const std::vector<int>& toneFrequencies, float samplingFrequency,
                       float duration, float amplitude, float* buffer, int numSamples) {
    int totalFrameCount = (samplingFrequency * duration);
    int limit = std::min(totalFrameCount, numSamples);

    for (auto i = 0; i < limit; i++) {
        buffer[i] = 0;
        for (auto j = 0; j < toneFrequencies.size(); j++) {
            buffer[i] += sin(2 * M_PI * toneFrequencies[j] * i / samplingFrequency);
        }
        buffer[i] *= (amplitude / toneFrequencies.size());
    }
}

sp<AudioEffect> createEffect(const effect_uuid_t* type,
                             audio_session_t sessionId = AUDIO_SESSION_OUTPUT_MIX) {
    std::string packageName{gPackageName};
    AttributionSourceState attributionSource;
    attributionSource.packageName = packageName;
    attributionSource.uid = VALUE_OR_FATAL(legacy2aidl_uid_t_int32_t(getuid()));
    attributionSource.pid = VALUE_OR_FATAL(legacy2aidl_pid_t_int32_t(getpid()));
    attributionSource.token = sp<BBinder>::make();
    sp<AudioEffect> effect = sp<AudioEffect>::make(attributionSource);
    effect->set(type, nullptr, 0, nullptr, sessionId, AUDIO_IO_HANDLE_NONE, {}, false, false);
    return effect;
}

void computeFilterGainsAtTones(float captureDuration, int nPointFft, std::vector<int>& binOffsets,
                               float* inputMag, float* gaindB, const char* res,
                               audio_session_t sessionId) {
    int totalFrameCount = captureDuration * kSamplingFrequency;
    auto output = pffft::AlignedVector<float>(totalFrameCount);
    auto fftOutput = pffft::AlignedVector<float>(nPointFft);
    PlaybackEnv argsP;
    argsP.mRes = std::string{res};
    argsP.mSessionId = sessionId;
    CaptureEnv argsR;
    argsR.mCaptureDuration = captureDuration;
    std::thread playbackThread(&PlaybackEnv::play, &argsP);
    std::thread captureThread(&CaptureEnv::capture, &argsR);
    captureThread.join();
    playbackThread.join();
    ASSERT_EQ(OK, argsR.mStatus) << argsR.mMsg;
    ASSERT_EQ(OK, argsP.mStatus) << argsP.mMsg;
    ASSERT_FALSE(argsR.mDumpFileName.empty()) << "recorded not written to file";
    std::ifstream fin(argsR.mDumpFileName, std::ios::in | std::ios::binary);
    fin.read((char*)output.data(), totalFrameCount * sizeof(output[0]));
    fin.close();
    PFFFT_Setup* handle = pffft_new_setup(nPointFft, PFFFT_REAL);
    // ignore first few samples. This is to not analyse until audio track is re-routed to remote
    // submix source, also for the effect filter response to reach steady-state (priming / pruning
    // samples).
    int rerouteOffset = kPrimeDurationInSec * kSamplingFrequency;
    pffft_transform_ordered(handle, output.data() + rerouteOffset, fftOutput.data(), nullptr,
                            PFFFT_FORWARD);
    pffft_destroy_setup(handle);
    for (auto i = 0; i < binOffsets.size(); i++) {
        auto k = binOffsets[i];
        auto outputMag = sqrt((fftOutput[k * 2] * fftOutput[k * 2]) +
                              (fftOutput[k * 2 + 1] * fftOutput[k * 2 + 1]));
        gaindB[i] = 20 * log10(outputMag / inputMag[i]);
    }
}

std::tuple<int, int> roundToFreqCenteredToFftBin(float binWidth, float freq) {
    int bin_index = std::round(freq / binWidth);
    int cfreq = std::round(bin_index * binWidth);
    return std::make_tuple(bin_index, cfreq);
}

TEST(AudioEffectTest, CheckEqualizerEffect) {
    audio_session_t sessionId =
            (audio_session_t)AudioSystem::newAudioUniqueId(AUDIO_UNIQUE_ID_USE_SESSION);
    sp<AudioEffect> equalizer = createEffect(SL_IID_EQUALIZER, sessionId);
    ASSERT_EQ(OK, equalizer->initCheck());
    ASSERT_EQ(NO_ERROR, equalizer->setEnabled(true));
    if ((equalizer->descriptor().flags & EFFECT_FLAG_HW_ACC_MASK) != 0) {
        GTEST_SKIP() << "effect processed output inaccessible, skipping test";
    }
#define MAX_PARAMS 64
    uint32_t buf32[sizeof(effect_param_t) / sizeof(uint32_t) + MAX_PARAMS];
    effect_param_t* eqParam = (effect_param_t*)(&buf32);

    // get num of presets
    eqParam->psize = sizeof(uint32_t);
    eqParam->vsize = sizeof(uint16_t);
    *(int32_t*)eqParam->data = EQ_PARAM_GET_NUM_OF_PRESETS;
    EXPECT_EQ(0, equalizer->getParameter(eqParam));
    EXPECT_EQ(0, eqParam->status);
    int numPresets = *((uint16_t*)((int32_t*)eqParam->data + 1));

    // get num of bands
    eqParam->psize = sizeof(uint32_t);
    eqParam->vsize = sizeof(uint16_t);
    *(int32_t*)eqParam->data = EQ_PARAM_NUM_BANDS;
    EXPECT_EQ(0, equalizer->getParameter(eqParam));
    EXPECT_EQ(0, eqParam->status);
    int numBands = *((uint16_t*)((int32_t*)eqParam->data + 1));

    const int totalFrameCount = kSamplingFrequency * kPlayBackDurationSec;

    // get band center frequencies
    std::vector<int> centerFrequencies;
    std::vector<int> binOffsets;
    for (auto i = 0; i < numBands; i++) {
        eqParam->psize = sizeof(uint32_t) * 2;
        eqParam->vsize = sizeof(uint32_t);
        *(int32_t*)eqParam->data = EQ_PARAM_CENTER_FREQ;
        *((uint16_t*)((int32_t*)eqParam->data + 1)) = i;
        EXPECT_EQ(0, equalizer->getParameter(eqParam));
        EXPECT_EQ(0, eqParam->status);
        float cfreq = *((int32_t*)eqParam->data + 2) / 1000;  // milli hz
        // pick frequency close to bin center frequency
        auto [bin_index, bin_freq] = roundToFreqCenteredToFftBin(kBinWidth, cfreq);
        centerFrequencies.push_back(bin_freq);
        binOffsets.push_back(bin_index);
    }

    // input for effect module
    auto input = pffft::AlignedVector<float>(totalFrameCount);
    generateMultiTone(centerFrequencies, kSamplingFrequency, kPlayBackDurationSec, kDefAmplitude,
                      input.data(), totalFrameCount);
    auto fftInput = pffft::AlignedVector<float>(kNPointFFT);
    PFFFT_Setup* handle = pffft_new_setup(kNPointFFT, PFFFT_REAL);
    pffft_transform_ordered(handle, input.data(), fftInput.data(), nullptr, PFFFT_FORWARD);
    pffft_destroy_setup(handle);
    float inputMag[numBands];
    for (auto i = 0; i < numBands; i++) {
        auto k = binOffsets[i];
        inputMag[i] = sqrt((fftInput[k * 2] * fftInput[k * 2]) +
                           (fftInput[k * 2 + 1] * fftInput[k * 2 + 1]));
    }
    TemporaryFile tf("/data/local/tmp");
    close(tf.release());
    std::ofstream fout(tf.path, std::ios::out | std::ios::binary);
    fout.write((char*)input.data(), input.size() * sizeof(input[0]));
    fout.close();

    float expGaindB[numBands], actGaindB[numBands];

    std::string msg = "";
    int numPresetsOk = 0;
    for (auto preset = 0; preset < numPresets; preset++) {
        // set preset
        eqParam->psize = sizeof(uint32_t);
        eqParam->vsize = sizeof(uint32_t);
        *(int32_t*)eqParam->data = EQ_PARAM_CUR_PRESET;
        *((uint16_t*)((int32_t*)eqParam->data + 1)) = preset;
        EXPECT_EQ(0, equalizer->setParameter(eqParam));
        EXPECT_EQ(0, eqParam->status);
        // get preset gains
        eqParam->psize = sizeof(uint32_t);
        eqParam->vsize = (numBands + 1) * sizeof(uint32_t);
        *(int32_t*)eqParam->data = EQ_PARAM_PROPERTIES;
        EXPECT_EQ(0, equalizer->getParameter(eqParam));
        EXPECT_EQ(0, eqParam->status);
        t_equalizer_settings* settings =
                reinterpret_cast<t_equalizer_settings*>((int32_t*)eqParam->data + 1);
        EXPECT_EQ(preset, settings->curPreset);
        EXPECT_EQ(numBands, settings->numBands);
        for (auto i = 0; i < numBands; i++) {
            expGaindB[i] = ((int16_t)settings->bandLevels[i]) / 100.0f;  // gain in milli bels
        }
        memset(actGaindB, 0, sizeof(actGaindB));
        ASSERT_NO_FATAL_FAILURE(computeFilterGainsAtTones(kCaptureDurationSec, kNPointFFT,
                                                          binOffsets, inputMag, actGaindB, tf.path,
                                                          sessionId));
        bool isOk = true;
        for (auto i = 0; i < numBands - 1; i++) {
            auto diffA = expGaindB[i] - expGaindB[i + 1];
            auto diffB = actGaindB[i] - actGaindB[i + 1];
            if (diffA == 0 && fabs(diffA - diffB) > 1.0f) {
                msg += (android::base::StringPrintf(
                        "For eq preset : %d, between bands %d and %d, expected relative gain is : "
                        "%f, got relative gain is : %f, error : %f \n",
                        preset, i, i + 1, diffA, diffB, diffA - diffB));
                isOk = false;
            } else if (diffA * diffB < 0) {
                msg += (android::base::StringPrintf(
                        "For eq preset : %d, between bands %d and %d, expected relative gain and "
                        "seen relative gain are of opposite signs \n. Expected relative gain is : "
                        "%f, seen relative gain is : %f \n",
                        preset, i, i + 1, diffA, diffB));
                isOk = false;
            }
        }
        if (isOk) numPresetsOk++;
    }
    EXPECT_EQ(numPresetsOk, numPresets) << msg;
}

TEST(AudioEffectTest, CheckBassBoostEffect) {
    audio_session_t sessionId =
            (audio_session_t)AudioSystem::newAudioUniqueId(AUDIO_UNIQUE_ID_USE_SESSION);
    sp<AudioEffect> bassboost = createEffect(SL_IID_BASSBOOST, sessionId);
    ASSERT_EQ(OK, bassboost->initCheck());
    ASSERT_EQ(NO_ERROR, bassboost->setEnabled(true));
    if ((bassboost->descriptor().flags & EFFECT_FLAG_HW_ACC_MASK) != 0) {
        GTEST_SKIP() << "effect processed output inaccessible, skipping test";
    }
    int32_t buf32[sizeof(effect_param_t) / sizeof(int32_t) + MAX_PARAMS];
    effect_param_t* bbParam = (effect_param_t*)(&buf32);

    bbParam->psize = sizeof(int32_t);
    bbParam->vsize = sizeof(int32_t);
    *(int32_t*)bbParam->data = BASSBOOST_PARAM_STRENGTH_SUPPORTED;
    EXPECT_EQ(0, bassboost->getParameter(bbParam));
    EXPECT_EQ(0, bbParam->status);
    bool strengthSupported = *((int32_t*)bbParam->data + 1);

    const int totalFrameCount = kSamplingFrequency * kPlayBackDurationSec;

    // selecting bass frequency, speech tone (for relative gain)
    std::vector<int> testFrequencies{100, 1200};
    std::vector<int> binOffsets;
    for (auto i = 0; i < testFrequencies.size(); i++) {
        // pick frequency close to bin center frequency
        auto [bin_index, bin_freq] = roundToFreqCenteredToFftBin(kBinWidth, testFrequencies[i]);
        testFrequencies[i] = bin_freq;
        binOffsets.push_back(bin_index);
    }

    // input for effect module
    auto input = pffft::AlignedVector<float>(totalFrameCount);
    generateMultiTone(testFrequencies, kSamplingFrequency, kPlayBackDurationSec, kDefAmplitude,
                      input.data(), totalFrameCount);
    auto fftInput = pffft::AlignedVector<float>(kNPointFFT);
    PFFFT_Setup* handle = pffft_new_setup(kNPointFFT, PFFFT_REAL);
    pffft_transform_ordered(handle, input.data(), fftInput.data(), nullptr, PFFFT_FORWARD);
    pffft_destroy_setup(handle);
    float inputMag[testFrequencies.size()];
    for (auto i = 0; i < testFrequencies.size(); i++) {
        auto k = binOffsets[i];
        inputMag[i] = sqrt((fftInput[k * 2] * fftInput[k * 2]) +
                           (fftInput[k * 2 + 1] * fftInput[k * 2 + 1]));
    }
    TemporaryFile tf("/data/local/tmp");
    close(tf.release());
    std::ofstream fout(tf.path, std::ios::out | std::ios::binary);
    fout.write((char*)input.data(), input.size() * sizeof(input[0]));
    fout.close();

    float gainWithOutFilter[testFrequencies.size()];
    memset(gainWithOutFilter, 0, sizeof(gainWithOutFilter));
    ASSERT_NO_FATAL_FAILURE(computeFilterGainsAtTones(kCaptureDurationSec, kNPointFFT, binOffsets,
                                                      inputMag, gainWithOutFilter, tf.path,
                                                      AUDIO_SESSION_OUTPUT_MIX));
    float diffA = gainWithOutFilter[0] - gainWithOutFilter[1];
    float prevGain = -100.f;
    for (auto strength = 150; strength < 1000; strength += strengthSupported ? 150 : 1000) {
        // configure filter strength
        if (strengthSupported) {
            bbParam->psize = sizeof(int32_t);
            bbParam->vsize = sizeof(int16_t);
            *(int32_t*)bbParam->data = BASSBOOST_PARAM_STRENGTH;
            *((int16_t*)((int32_t*)bbParam->data + 1)) = strength;
            EXPECT_EQ(0, bassboost->setParameter(bbParam));
            EXPECT_EQ(0, bbParam->status);
        }
        float gainWithFilter[testFrequencies.size()];
        memset(gainWithFilter, 0, sizeof(gainWithFilter));
        ASSERT_NO_FATAL_FAILURE(computeFilterGainsAtTones(kCaptureDurationSec, kNPointFFT,
                                                          binOffsets, inputMag, gainWithFilter,
                                                          tf.path, sessionId));
        float diffB = gainWithFilter[0] - gainWithFilter[1];
        EXPECT_GT(diffB, diffA) << "bassboost effect not seen";
        EXPECT_GE(diffB, prevGain) << "increase in boost strength causing fall in gain";
        prevGain = diffB;
    }
}

int main(int argc, char** argv) {
    android::ProcessState::self()->startThreadPool();
    ::testing::InitGoogleTest(&argc, argv);
    ::testing::UnitTest::GetInstance()->listeners().Append(new TestExecutionTracer());
    return RUN_ALL_TESTS();
}
