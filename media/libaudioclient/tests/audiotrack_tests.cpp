/*
 * Copyright (C) 2021 The Android Open Source Project
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

#include <thread>

//#define LOG_NDEBUG 0
#define LOG_TAG "AudioTrackTests"

#include <android-base/logging.h>
#include <binder/ProcessState.h>
#include <gtest/gtest.h>

#include "audio_test_utils.h"
#include "test_execution_tracer.h"

using namespace android;

// Test that the basic constructor returns an object that doesn't crash
// on stop() or destruction.

TEST(AudioTrackTestBasic, EmptyAudioTrack) {
    AttributionSourceState attributionSource;
    attributionSource.packageName = "AudioTrackTest";
    attributionSource.uid = VALUE_OR_FATAL(legacy2aidl_uid_t_int32_t(getuid()));
    attributionSource.pid = VALUE_OR_FATAL(legacy2aidl_pid_t_int32_t(getpid()));
    attributionSource.token = sp<BBinder>::make();
    const auto at = sp<AudioTrack>::make(attributionSource);

    EXPECT_EQ(NO_INIT, at->initCheck());
    EXPECT_EQ(true, at->stopped());

    // ensure we do not crash.
    at->stop();
}

TEST(AudioTrackTest, TestPlayTrack) {
    const auto ap = sp<AudioPlayback>::make(44100 /* sampleRate */, AUDIO_FORMAT_PCM_16_BIT,
                                            AUDIO_CHANNEL_OUT_STEREO, AUDIO_OUTPUT_FLAG_NONE,
                                            AUDIO_SESSION_NONE, AudioTrack::TRANSFER_OBTAIN);
    ASSERT_NE(nullptr, ap);
    ASSERT_EQ(OK, ap->loadResource("/data/local/tmp/bbb_2ch_24kHz_s16le.raw"))
            << "Unable to open Resource";
    EXPECT_EQ(OK, ap->create()) << "track creation failed";
    EXPECT_EQ(OK, ap->start()) << "audio track start failed";
    EXPECT_EQ(OK, ap->onProcess());
    ap->stop();
}

TEST(AudioTrackTest, TestSeek) {
    const auto ap = sp<AudioPlayback>::make(
            44100 /* sampleRate */, AUDIO_FORMAT_PCM_16_BIT, AUDIO_CHANNEL_OUT_STEREO);
    ASSERT_NE(nullptr, ap);
    ASSERT_EQ(OK, ap->loadResource("/data/local/tmp/bbb_2ch_24kHz_s16le.raw"))
            << "Unable to open Resource";
    EXPECT_EQ(OK, ap->create()) << "track creation failed";
    EXPECT_EQ(OK, ap->start()) << "audio track start failed";
    EXPECT_EQ(OK, ap->onProcess(true));
    ap->stop();
}

TEST(AudioTrackTest, OffloadOrDirectPlayback) {
    audio_offload_info_t info = AUDIO_INFO_INITIALIZER;
    info.sample_rate = 44100;
    info.channel_mask = AUDIO_CHANNEL_OUT_STEREO;
    info.format = AUDIO_FORMAT_MP3;
    info.stream_type = AUDIO_STREAM_MUSIC;
    info.bit_rate = 192;
    info.duration_us = 120 * 1000000;  // 120 sec

    audio_config_base_t config = {/* .sample_rate = */ info.sample_rate,
                                  /* .channel_mask = */ info.channel_mask,
                                  /* .format = */ AUDIO_FORMAT_PCM_16_BIT};
    audio_attributes_t attributes = AUDIO_ATTRIBUTES_INITIALIZER;
    attributes.content_type = AUDIO_CONTENT_TYPE_MUSIC;
    attributes.usage = AUDIO_USAGE_MEDIA;
    attributes.flags = AUDIO_FLAG_NONE;

    if (!AudioTrack::isDirectOutputSupported(config, attributes) &&
        AUDIO_OFFLOAD_NOT_SUPPORTED == AudioSystem::getOffloadSupport(info)) {
        GTEST_SKIP() << "offload or direct playback is not supported";
    }
    sp<AudioPlayback> ap = nullptr;
    if (AUDIO_OFFLOAD_NOT_SUPPORTED != AudioSystem::getOffloadSupport(info)) {
        ap = sp<AudioPlayback>::make(info.sample_rate, info.format, info.channel_mask,
                                     AUDIO_OUTPUT_FLAG_COMPRESS_OFFLOAD, AUDIO_SESSION_NONE,
                                     AudioTrack::TRANSFER_OBTAIN, nullptr, &info);
    } else {
        ap = sp<AudioPlayback>::make(config.sample_rate, config.format, config.channel_mask,
                                     AUDIO_OUTPUT_FLAG_DIRECT, AUDIO_SESSION_NONE,
                                     AudioTrack::TRANSFER_OBTAIN);
    }
    ASSERT_NE(nullptr, ap);
    EXPECT_EQ(OK, ap->create()) << "track creation failed";
    audio_dual_mono_mode_t mode;
    if (OK != ap->getAudioTrackHandle()->getDualMonoMode(&mode)) {
        std::cerr << "no dual mono presentation is available" << std::endl;
    }
    if (OK != ap->getAudioTrackHandle()->setDualMonoMode(AUDIO_DUAL_MONO_MODE_LR)) {
        std::cerr << "no dual mono presentation is available" << std::endl;
    } else {
        EXPECT_EQ(OK, ap->getAudioTrackHandle()->getDualMonoMode(&mode));
        EXPECT_EQ(AUDIO_DUAL_MONO_MODE_LR, mode);
    }
    float leveldB;
    if (OK != ap->getAudioTrackHandle()->getAudioDescriptionMixLevel(&leveldB)) {
        std::cerr << "Audio Description mixing is unavailable" << std::endl;
    }
    if (OK != ap->getAudioTrackHandle()->setAudioDescriptionMixLevel(3.14f)) {
        std::cerr << "Audio Description mixing is unavailable" << std::endl;
    } else {
        EXPECT_EQ(OK, ap->getAudioTrackHandle()->getAudioDescriptionMixLevel(&leveldB));
        EXPECT_EQ(3.14f, leveldB);
    }
    AudioPlaybackRate audioRate;
    audioRate = ap->getAudioTrackHandle()->getPlaybackRate();
    std::cerr << "playback speed :: " << audioRate.mSpeed << std::endl
              << "playback pitch :: " << audioRate.mPitch << std::endl;
    audioRate.mSpeed = 2.0f;
    audioRate.mPitch = 2.0f;
    audioRate.mStretchMode = AUDIO_TIMESTRETCH_STRETCH_VOICE;
    audioRate.mFallbackMode = AUDIO_TIMESTRETCH_FALLBACK_MUTE;
    EXPECT_TRUE(isAudioPlaybackRateValid(audioRate));
    if (OK != ap->getAudioTrackHandle()->setPlaybackRate(audioRate)) {
        std::cerr << "unable to set playback rate parameters" << std::endl;
    } else {
        AudioPlaybackRate audioRateLocal;
        audioRateLocal = ap->getAudioTrackHandle()->getPlaybackRate();
        EXPECT_TRUE(isAudioPlaybackRateEqual(audioRate, audioRateLocal));
    }
    ap->stop();
}

TEST(AudioTrackTest, TestAudioCbNotifier) {
    const auto ap = sp<AudioPlayback>::make(0 /* sampleRate */, AUDIO_FORMAT_PCM_16_BIT,
                                            AUDIO_CHANNEL_OUT_STEREO, AUDIO_OUTPUT_FLAG_FAST,
                                            AUDIO_SESSION_NONE, AudioTrack::TRANSFER_SHARED);
    ASSERT_NE(nullptr, ap);
    ASSERT_EQ(OK, ap->loadResource("/data/local/tmp/bbb_2ch_24kHz_s16le.raw"))
            << "Unable to open Resource";
    EXPECT_EQ(OK, ap->create()) << "track creation failed";
    EXPECT_EQ(BAD_VALUE, ap->getAudioTrackHandle()->addAudioDeviceCallback(nullptr));
    sp<OnAudioDeviceUpdateNotifier> cb = sp<OnAudioDeviceUpdateNotifier>::make();
    sp<OnAudioDeviceUpdateNotifier> cbOld = sp<OnAudioDeviceUpdateNotifier>::make();
    EXPECT_EQ(OK, ap->getAudioTrackHandle()->addAudioDeviceCallback(cbOld));
    EXPECT_EQ(INVALID_OPERATION, ap->getAudioTrackHandle()->addAudioDeviceCallback(cbOld));
    EXPECT_EQ(OK, ap->getAudioTrackHandle()->addAudioDeviceCallback(cb));
    EXPECT_EQ(OK, ap->start()) << "audio track start failed";
    EXPECT_EQ(OK, ap->onProcess());
    EXPECT_EQ(OK, cb->waitForAudioDeviceCb());
    const auto [oldAudioIo, oldDeviceIds] = cbOld->getLastPortAndDevices();
    EXPECT_EQ(AUDIO_IO_HANDLE_NONE, oldAudioIo);
    EXPECT_TRUE(oldDeviceIds.empty());
    const auto [audioIo, deviceIds] = cb->getLastPortAndDevices();
    EXPECT_NE(AUDIO_IO_HANDLE_NONE, audioIo);
    EXPECT_FALSE(deviceIds.empty());
    EXPECT_EQ(audioIo, ap->getAudioTrackHandle()->getOutput());
    DeviceIdVector routedDeviceIds = ap->getAudioTrackHandle()->getRoutedDeviceIds();
    EXPECT_TRUE(areDeviceIdsEqual(routedDeviceIds, deviceIds));
    String8 keys;
    keys = ap->getAudioTrackHandle()->getParameters(keys);
    if (!keys.empty()) {
        std::cerr << "track parameters :: " << keys << std::endl;
    }
    EXPECT_TRUE(checkPatchPlayback(audioIo, deviceIds));
    EXPECT_EQ(BAD_VALUE, ap->getAudioTrackHandle()->removeAudioDeviceCallback(nullptr));
    EXPECT_EQ(INVALID_OPERATION, ap->getAudioTrackHandle()->removeAudioDeviceCallback(cbOld));
    EXPECT_EQ(OK, ap->getAudioTrackHandle()->removeAudioDeviceCallback(cb));
    ap->stop();
}

class AudioTrackOffloadTest : public ::testing::Test {
  protected:
    void TearDown() override {
        if (!IsSkipped()) {
            // Let the offload AF stream to exit to avoid interfering with other tests.
            std::this_thread::sleep_for(std::chrono::milliseconds(750));
        }
    }
    bool halSupportsOffload(audio_offload_info_t* info, std::string* resource = nullptr) const;
    void testPlayback(bool testDrainPause, sp<AudioPlayback>* outPlayback = nullptr);
};

bool AudioTrackOffloadTest::halSupportsOffload(audio_offload_info_t* info,
                                               std::string* resource) const {
    *info = AUDIO_INFO_INITIALIZER;
    info->sample_rate = 48000;
    info->channel_mask = AUDIO_CHANNEL_OUT_STEREO;
    info->format = AUDIO_FORMAT_MP3;
    info->stream_type = AUDIO_STREAM_MUSIC;
    info->bit_rate = 236256;
    info->duration_us = 120 * 1000000;  // 120 sec to ensure the offloading choice
    if (resource) *resource = "/data/local/tmp/sine960hz_48000_3s_id3v1.mp3";
    return AudioSystem::getOffloadSupport(*info) != AUDIO_OFFLOAD_NOT_SUPPORTED;
}

void AudioTrackOffloadTest::testPlayback(bool testDrainPause, sp<AudioPlayback>* outPlayback) {
    audio_offload_info_t info;
    std::string resource;

    if (!halSupportsOffload(&info, &resource)) {
        GTEST_SKIP() << "offload playback is not supported for "
                     << audio_format_to_string(info.format);
    }
    auto ap = sp<AudioPlayback>::make(info.sample_rate, info.format, info.channel_mask,
                                      AUDIO_OUTPUT_FLAG_COMPRESS_OFFLOAD, AUDIO_SESSION_NONE,
                                      AudioTrack::TRANSFER_OBTAIN, nullptr, &info);
    ASSERT_EQ(OK, ap->loadResource(resource.c_str())) << "unable to open the media file";
    ASSERT_EQ(OK, ap->create()) << "track creation failed";
    status_t status = OK;
    // Starting offload track may fail if the audio flinger hasn't yet cleared the I/O thread.
    for (int retries = 0; retries < 3; ++retries) {
        if ((status = ap->start()) == OK) break;
        std::this_thread::sleep_for(std::chrono::seconds(1));
        LOG(INFO) << __func__ << ": Will retry starting track, previous status: " << status;
    }
    ASSERT_EQ(OK, status) << "audio track start failed";
    LOG(INFO) << __func__ << ": Started track";
    EXPECT_EQ(OK, ap->onProcess());
    LOG(INFO) << __func__ << ": onProcess done";
    if (!outPlayback) {
        ap->stop();
        LOG(INFO) << __func__ << ": Stopped track";
    }
    if (testDrainPause) {
        // Wait for draining to start, no event for this.
        std::this_thread::sleep_for(std::chrono::milliseconds(200));
        LOG(INFO) << __func__ << ": Pausing drain";
        ap->pause();
        LOG(INFO) << __func__ << ": Resuming drain";
        ap->resume();
    }
    if (!outPlayback) {
        LOG(INFO) << __func__ << ": Waiting for stream end";
        EXPECT_TRUE(ap->waitForStreamEnd()) << "Did not receive onStreamEnd";
    } else {
        *outPlayback = std::move(ap);
    }
}

TEST_F(AudioTrackOffloadTest, Completion) {
    testPlayback(false /*testDrainPause*/);
}

TEST_F(AudioTrackOffloadTest, DrainPause) {
    testPlayback(true /*testDrainPause*/);
}

// Similar to AudioTrackOffloadTest.testMultipleAudioTrackOffloadPreemption
TEST_F(AudioTrackOffloadTest, ClipPreemption) {
    audio_offload_info_t info;
    if (!halSupportsOffload(&info)) {
        GTEST_SKIP() << "offload playback is not supported for "
                     << audio_format_to_string(info.format);
    }
    sp<AudioPlayback> trackOne, trackTwo;
    {
        SCOPED_TRACE("track 1");
        LOG(INFO) << __func__ << ": Creating and starting track 1";
        ASSERT_NO_FATAL_FAILURE(testPlayback(false /*testDrainPause*/, &trackOne));
    }
    {
        SCOPED_TRACE("track 2");
        // Wait for track 1 to start playing, no event for this.
        std::this_thread::sleep_for(std::chrono::milliseconds(300));
        LOG(INFO) << __func__ << ": Creating and starting track 2";
        ASSERT_NO_FATAL_FAILURE(testPlayback(false /*testDrainPause*/, &trackTwo));
        std::this_thread::sleep_for(std::chrono::milliseconds(200));
        trackTwo->stop();
    }
    LOG(INFO) << __func__ << ": Waiting for stream end on track 2";
    EXPECT_TRUE(trackTwo->waitForStreamEnd()) << "Did not receive onStreamEnd on track 2";
}

class AudioTrackCreateTest
    : public ::testing::TestWithParam<std::tuple<uint32_t, audio_format_t, audio_channel_mask_t,
                                                 audio_output_flags_t, audio_session_t>> {
  public:
    AudioTrackCreateTest()
        : mSampleRate(std::get<0>(GetParam())),
          mFormat(std::get<1>(GetParam())),
          mChannelMask(std::get<2>(GetParam())),
          mFlags(std::get<3>(GetParam())),
          mSessionId(std::get<4>(GetParam())){};

    const uint32_t mSampleRate;
    const audio_format_t mFormat;
    const audio_channel_mask_t mChannelMask;
    const audio_output_flags_t mFlags;
    const audio_session_t mSessionId;

    sp<AudioPlayback> mAP;

    virtual void SetUp() override {
        mAP = sp<AudioPlayback>::make(mSampleRate, mFormat, mChannelMask, mFlags,
                                              mSessionId);
        ASSERT_NE(nullptr, mAP);
        ASSERT_EQ(OK, mAP->loadResource("/data/local/tmp/bbb_2ch_24kHz_s16le.raw"))
                << "Unable to open Resource";
        ASSERT_EQ(OK, mAP->create()) << "track creation failed";
    }

    virtual void TearDown() override {
        if (mAP) mAP->stop();
    }
};

TEST_P(AudioTrackCreateTest, TestCreateTrack) {
    EXPECT_EQ(mFormat, mAP->getAudioTrackHandle()->format());
    EXPECT_EQ(audio_channel_count_from_out_mask(mChannelMask),
              mAP->getAudioTrackHandle()->channelCount());
    if (mSampleRate != 0) EXPECT_EQ(mSampleRate, mAP->getAudioTrackHandle()->getSampleRate());
    if (mSessionId != AUDIO_SESSION_NONE)
        EXPECT_EQ(mSessionId, mAP->getAudioTrackHandle()->getSessionId());
    EXPECT_EQ(mSampleRate, mAP->getAudioTrackHandle()->getOriginalSampleRate());
    EXPECT_EQ(OK, mAP->start()) << "audio track start failed";
    EXPECT_EQ(OK, mAP->onProcess());
}

// sampleRate, format, channelMask, flags, sessionId
INSTANTIATE_TEST_SUITE_P(
        AudioTrackParameterizedTest, AudioTrackCreateTest,
        ::testing::Combine(::testing::Values(48000), ::testing::Values(AUDIO_FORMAT_PCM_16_BIT),
                           ::testing::Values(AUDIO_CHANNEL_OUT_STEREO),
                           ::testing::Values(AUDIO_OUTPUT_FLAG_NONE,
                                             AUDIO_OUTPUT_FLAG_PRIMARY | AUDIO_OUTPUT_FLAG_FAST,
                                             AUDIO_OUTPUT_FLAG_RAW | AUDIO_OUTPUT_FLAG_FAST,
                                             AUDIO_OUTPUT_FLAG_DEEP_BUFFER),
                           ::testing::Values(AUDIO_SESSION_NONE)));

int main(int argc, char** argv) {
    android::ProcessState::self()->startThreadPool();
    ::testing::InitGoogleTest(&argc, argv);
    ::testing::UnitTest::GetInstance()->listeners().Append(new TestExecutionTracer());
    return RUN_ALL_TESTS();
}
