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

#include <sstream>

//#define LOG_NDEBUG 0
#define LOG_TAG "AudioRecordTest"

#include <android-base/logging.h>
#include <binder/ProcessState.h>
#include <gtest/gtest.h>

#include "audio_test_utils.h"
#include "test_execution_tracer.h"

using namespace android;

class AudioRecordTest : public ::testing::Test {
  public:
    void SetUp() override {
        mAC = new AudioCapture(AUDIO_SOURCE_DEFAULT, 44100, AUDIO_FORMAT_PCM_16_BIT,
                               AUDIO_CHANNEL_IN_FRONT);
        ASSERT_NE(nullptr, mAC);
        ASSERT_EQ(OK, mAC->create()) << "record creation failed";
    }

    void TearDown() override {
        if (mAC) ASSERT_EQ(OK, mAC->stop());
    }

    sp<AudioCapture> mAC;
};

using RecordCreateTestParam = std::tuple<uint32_t, audio_format_t, audio_channel_mask_t,
                                         audio_input_flags_t, audio_session_t, audio_source_t>;
enum {
    RECORD_PARAM_SAMPLE_RATE,
    RECORD_PARAM_FORMAT,
    RECORD_PARAM_CHANNEL_MASK,
    RECORD_PARAM_FLAGS,
    RECORD_PARAM_SESSION_ID,
    RECORD_PARAM_INPUT_SOURCE
};

class AudioRecordCreateTest : public ::testing::TestWithParam<RecordCreateTestParam> {
  public:
    AudioRecordCreateTest()
        : mSampleRate(std::get<RECORD_PARAM_SAMPLE_RATE>(GetParam())),
          mFormat(std::get<RECORD_PARAM_FORMAT>(GetParam())),
          mChannelMask(std::get<RECORD_PARAM_CHANNEL_MASK>(GetParam())),
          mFlags(std::get<RECORD_PARAM_FLAGS>(GetParam())),
          mSessionId(std::get<RECORD_PARAM_SESSION_ID>(GetParam())),
          mInputSource(std::get<RECORD_PARAM_INPUT_SOURCE>(GetParam())){};

    const uint32_t mSampleRate;
    const audio_format_t mFormat;
    const audio_channel_mask_t mChannelMask;
    const audio_input_flags_t mFlags;
    const audio_session_t mSessionId;
    const audio_source_t mInputSource;
    const AudioRecord::transfer_type mTransferType = AudioRecord::TRANSFER_OBTAIN;

    sp<AudioCapture> mAC;

    void SetUp() override {
        mAC = new AudioCapture(mInputSource, mSampleRate, mFormat, mChannelMask, mFlags, mSessionId,
                               mTransferType);
        ASSERT_NE(nullptr, mAC);
        ASSERT_EQ(OK, mAC->create()) << "record creation failed";
    }

    void TearDown() override {
        if (mAC) ASSERT_EQ(OK, mAC->stop());
    }
};

TEST_F(AudioRecordTest, TestSimpleRecord) {
    EXPECT_EQ(OK, mAC->start()) << "start recording failed";
    EXPECT_EQ(OK, mAC->audioProcess()) << "audioProcess failed";
}

TEST_F(AudioRecordTest, TestAudioCbNotifier) {
    EXPECT_EQ(BAD_VALUE, mAC->getAudioRecordHandle()->addAudioDeviceCallback(nullptr));
    sp<OnAudioDeviceUpdateNotifier> cb = sp<OnAudioDeviceUpdateNotifier>::make();
    sp<OnAudioDeviceUpdateNotifier> cbOld = sp<OnAudioDeviceUpdateNotifier>::make();
    EXPECT_EQ(OK, mAC->getAudioRecordHandle()->addAudioDeviceCallback(cbOld));
    EXPECT_EQ(INVALID_OPERATION, mAC->getAudioRecordHandle()->addAudioDeviceCallback(cbOld));
    EXPECT_EQ(OK, mAC->getAudioRecordHandle()->addAudioDeviceCallback(cb));
    EXPECT_EQ(OK, mAC->start()) << "record creation failed";
    EXPECT_EQ(OK, cb->waitForAudioDeviceCb());
    EXPECT_EQ(AUDIO_IO_HANDLE_NONE, cbOld->mAudioIo);
    EXPECT_EQ(AUDIO_PORT_HANDLE_NONE, cbOld->mDeviceId);
    EXPECT_NE(AUDIO_IO_HANDLE_NONE, cb->mAudioIo);
    EXPECT_NE(AUDIO_PORT_HANDLE_NONE, cb->mDeviceId);
    EXPECT_EQ(BAD_VALUE, mAC->getAudioRecordHandle()->removeAudioDeviceCallback(nullptr));
    EXPECT_EQ(INVALID_OPERATION, mAC->getAudioRecordHandle()->removeAudioDeviceCallback(cbOld));
    EXPECT_EQ(OK, mAC->getAudioRecordHandle()->removeAudioDeviceCallback(cb));
    mAC->stop();
}

TEST_F(AudioRecordTest, TestEventRecordTrackPause) {
    const auto playback = sp<AudioPlayback>::make(
            8000 /* sampleRate */, AUDIO_FORMAT_PCM_16_BIT, AUDIO_CHANNEL_OUT_MONO);
    ASSERT_EQ(OK, playback->loadResource("/data/local/tmp/bbb_1ch_8kHz_s16le.raw"))
            << "Unable to open Resource";
    EXPECT_EQ(OK, playback->create()) << "AudioTrack Creation failed";
    audio_session_t audioTrackSession = playback->getAudioTrackHandle()->getSessionId();
    EXPECT_EQ(OK, mAC->start(AudioSystem::SYNC_EVENT_PRESENTATION_COMPLETE, audioTrackSession))
            << "record creation failed";
    EXPECT_EQ(OK, playback->start());
    RawBuffer buffer;
    status_t status = mAC->obtainBufferCb(buffer);
    EXPECT_EQ(status, TIMED_OUT) << "Not expecting any callbacks until track sends Sync event";
    playback->getAudioTrackHandle()->pause();
    EXPECT_EQ(OK, mAC->audioProcess()) << "audioProcess failed";
    playback->stop();
}

TEST_F(AudioRecordTest, TestEventRecordTrackStop) {
    const auto playback = sp<AudioPlayback>::make(
            8000 /* sampleRate */, AUDIO_FORMAT_PCM_16_BIT, AUDIO_CHANNEL_OUT_MONO);
    ASSERT_EQ(OK, playback->loadResource("/data/local/tmp/bbb_1ch_8kHz_s16le.raw"))
            << "Unable to open Resource";
    EXPECT_EQ(OK, playback->create()) << "AudioTrack Creation failed";
    audio_session_t audioTrackSession = playback->getAudioTrackHandle()->getSessionId();
    EXPECT_EQ(OK, mAC->start(AudioSystem::SYNC_EVENT_PRESENTATION_COMPLETE, audioTrackSession))
            << "record creation failed";
    EXPECT_EQ(OK, playback->start());
    RawBuffer buffer;
    status_t status = mAC->obtainBufferCb(buffer);
    EXPECT_EQ(status, TIMED_OUT) << "Not expecting any callbacks until track sends Sync event";
    playback->stop();
    EXPECT_EQ(OK, mAC->audioProcess()) << "audioProcess failed";
}

TEST_F(AudioRecordTest, TestGetSetMarker) {
    mAC->mMarkerPosition = (mAC->mNotificationFrames << 3) + (mAC->mNotificationFrames >> 1);
    EXPECT_EQ(OK, mAC->getAudioRecordHandle()->setMarkerPosition(mAC->mMarkerPosition))
            << "setMarkerPosition() failed";
    uint32_t marker;
    EXPECT_EQ(OK, mAC->getAudioRecordHandle()->getMarkerPosition(&marker))
            << "getMarkerPosition() failed";
    EXPECT_EQ(OK, mAC->start()) << "start recording failed";
    EXPECT_EQ(OK, mAC->audioProcess()) << "audioProcess failed";
    EXPECT_EQ(marker, mAC->mMarkerPosition)
            << "configured marker and received marker are different";
    EXPECT_EQ(mAC->mReceivedCbMarkerAtPosition, mAC->mMarkerPosition)
            << "configured marker and received cb marker are different";
}

TEST_F(AudioRecordTest, TestGetSetMarkerPeriodical) {
    mAC->mMarkerPeriod = (mAC->mNotificationFrames << 3) + (mAC->mNotificationFrames >> 1);
    EXPECT_EQ(OK, mAC->getAudioRecordHandle()->setPositionUpdatePeriod(mAC->mMarkerPeriod))
            << "setPositionUpdatePeriod() failed";
    uint32_t marker;
    EXPECT_EQ(OK, mAC->getAudioRecordHandle()->getPositionUpdatePeriod(&marker))
            << "getPositionUpdatePeriod() failed";
    EXPECT_EQ(OK, mAC->start()) << "start recording failed";
    EXPECT_EQ(OK, mAC->audioProcess()) << "audioProcess failed";
    EXPECT_EQ(marker, mAC->mMarkerPeriod) << "configured marker and received marker are different";
    EXPECT_EQ(mAC->mReceivedCbMarkerCount, mAC->mNumFramesToRecord / mAC->mMarkerPeriod)
            << "configured marker and received cb marker are different";
}

TEST_F(AudioRecordTest, TestGetPosition) {
    uint32_t position;
    EXPECT_EQ(OK, mAC->getAudioRecordHandle()->getPosition(&position)) << "getPosition() failed";
    EXPECT_EQ(0, position);
    EXPECT_EQ(OK, mAC->start()) << "start recording failed";
    EXPECT_EQ(OK, mAC->audioProcess()) << "audioProcess failed";
    EXPECT_EQ(OK, mAC->stop());
    EXPECT_EQ(OK, mAC->getAudioRecordHandle()->getPosition(&position)) << "getPosition() failed";
}

// TODO: Add checkPatchCapture(), verify the information of patch via dumpPort() and dumpPatch()
TEST_P(AudioRecordCreateTest, TestCreateRecord) {
    EXPECT_EQ(mFormat, mAC->getAudioRecordHandle()->format());
    EXPECT_EQ(audio_channel_count_from_in_mask(mChannelMask),
              mAC->getAudioRecordHandle()->channelCount());
    if (mAC->mFrameCount != 0)
        EXPECT_LE(mAC->mFrameCount, mAC->getAudioRecordHandle()->frameCount());
    EXPECT_EQ(mInputSource, mAC->getAudioRecordHandle()->inputSource());
    if (mSampleRate != 0) EXPECT_EQ(mSampleRate, mAC->getAudioRecordHandle()->getSampleRate());
    if (mSessionId != AUDIO_SESSION_NONE)
        EXPECT_EQ(mSessionId, mAC->getAudioRecordHandle()->getSessionId());
    if (mTransferType != AudioRecord::TRANSFER_CALLBACK) {
        uint32_t marker;
        mAC->mMarkerPosition = (mAC->mNotificationFrames << 3) + (mAC->mNotificationFrames >> 1);
        EXPECT_EQ(INVALID_OPERATION,
                  mAC->getAudioRecordHandle()->setMarkerPosition(mAC->mMarkerPosition));
        EXPECT_EQ(OK, mAC->getAudioRecordHandle()->getMarkerPosition(&marker));
        EXPECT_EQ(INVALID_OPERATION,
                  mAC->getAudioRecordHandle()->setPositionUpdatePeriod(mAC->mMarkerPosition));
        EXPECT_EQ(OK, mAC->getAudioRecordHandle()->getPositionUpdatePeriod(&marker));
    }
    EXPECT_EQ(OK, mAC->start()) << "start recording failed";
    EXPECT_EQ(OK, mAC->audioProcess()) << "audioProcess failed";
}

static std::string GetRecordTestName(const testing::TestParamInfo<RecordCreateTestParam>& info) {
    const auto& p = info.param;
    std::ostringstream s;
    s << std::get<RECORD_PARAM_SAMPLE_RATE>(p) << "_"
      << audio_format_to_string(std::get<RECORD_PARAM_FORMAT>(p)) << "__"
      << audio_channel_mask_to_string(std::get<RECORD_PARAM_CHANNEL_MASK>(p)) << "__"
      << "Flags_0x" << std::hex << std::get<RECORD_PARAM_FLAGS>(p) << std::dec << "__"
      << "Session_" << std::get<RECORD_PARAM_SESSION_ID>(p) << "__"
      << audio_source_to_string(std::get<RECORD_PARAM_INPUT_SOURCE>(p));
    return s.str();
}

// for port primary input
INSTANTIATE_TEST_SUITE_P(AudioRecordPrimaryInput, AudioRecordCreateTest,
                         ::testing::Combine(::testing::Values(8000, 11025, 12000, 16000, 22050,
                                                              24000, 32000, 44100, 48000),
                                            ::testing::Values(AUDIO_FORMAT_PCM_8_24_BIT),
                                            ::testing::Values(AUDIO_CHANNEL_IN_MONO,
                                                              AUDIO_CHANNEL_IN_STEREO,
                                                              AUDIO_CHANNEL_IN_FRONT_BACK),
                                            ::testing::Values(AUDIO_INPUT_FLAG_NONE),
                                            ::testing::Values(AUDIO_SESSION_NONE),
                                            ::testing::Values(AUDIO_SOURCE_DEFAULT)),
                         GetRecordTestName);

// for port fast input
INSTANTIATE_TEST_SUITE_P(AudioRecordFastInput, AudioRecordCreateTest,
                         ::testing::Combine(::testing::Values(8000, 11025, 12000, 16000, 22050,
                                                              24000, 32000, 44100, 48000),
                                            ::testing::Values(AUDIO_FORMAT_PCM_8_24_BIT),
                                            ::testing::Values(AUDIO_CHANNEL_IN_MONO,
                                                              AUDIO_CHANNEL_IN_STEREO,
                                                              AUDIO_CHANNEL_IN_FRONT_BACK),
                                            ::testing::Values(AUDIO_INPUT_FLAG_FAST),
                                            ::testing::Values(AUDIO_SESSION_NONE),
                                            ::testing::Values(AUDIO_SOURCE_DEFAULT)),
                         GetRecordTestName);

// misc
INSTANTIATE_TEST_SUITE_P(AudioRecordMiscInput, AudioRecordCreateTest,
                         ::testing::Combine(::testing::Values(48000),
                                            ::testing::Values(AUDIO_FORMAT_PCM_16_BIT),
                                            ::testing::Values(AUDIO_CHANNEL_IN_MONO),
                                            ::testing::Values(AUDIO_INPUT_FLAG_NONE),
                                            ::testing::Values(AUDIO_SESSION_NONE),
                                            ::testing::Values(AUDIO_SOURCE_MIC,
                                                              AUDIO_SOURCE_CAMCORDER,
                                                              AUDIO_SOURCE_VOICE_RECOGNITION,
                                                              AUDIO_SOURCE_VOICE_COMMUNICATION,
                                                              AUDIO_SOURCE_UNPROCESSED)),
                         GetRecordTestName);

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    ::testing::UnitTest::GetInstance()->listeners().Append(new TestExecutionTracer());
    android::base::SetMinimumLogSeverity(::android::base::DEBUG);
    // This is for death handlers instantiated by the framework code.
    android::ProcessState::self()->setThreadPoolMaxThreadCount(1);
    android::ProcessState::self()->startThreadPool();
    return RUN_ALL_TESTS();
}
