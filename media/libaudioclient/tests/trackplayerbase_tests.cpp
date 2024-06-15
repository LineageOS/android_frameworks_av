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

#define LOG_TAG "TrackPlayerBaseTest"

#include <binder/ProcessState.h>
#include <gtest/gtest.h>
#include <media/TrackPlayerBase.h>

#include "test_execution_tracer.h"

using namespace android;
using namespace android::media;

class TrackPlayer : public TrackPlayerBase, public AudioTrack::IAudioTrackCallback {
  public:
    // methods protected in base class
    using TrackPlayerBase::playerPause;
    using TrackPlayerBase::playerSetVolume;
    using TrackPlayerBase::playerStart;
    using TrackPlayerBase::playerStop;
};

class TrackPlayerBaseTest
    : public ::testing::TestWithParam<std::tuple<double, double, uint32_t, uint32_t>> {
  public:
    TrackPlayerBaseTest()
        : mDuration(std::get<0>(GetParam())),
          mPulseFreq(std::get<1>(GetParam())),
          mChannelCount(std::get<2>(GetParam())),
          mSampleRate(std::get<3>(GetParam())){};

    virtual void SetUp() override {
        mFrameCount = mDuration * mSampleRate;
        audio_channel_mask_t channelMask = audio_channel_out_mask_from_count(mChannelCount);
        sp<AudioTrack> track = new AudioTrack(mStreamType, mSampleRate, mFormat, channelMask,
                                              mFrameCount, mFlags, nullptr /* callback */,
                                              0 /* notificationFrames */, AUDIO_SESSION_NONE);
        ASSERT_EQ(track->initCheck(), NO_ERROR);

        mPlayer = new TrackPlayer();
        mPlayer->init(track.get(), mPlayer, PLAYER_TYPE_AAUDIO, AUDIO_USAGE_MEDIA,
                      AUDIO_SESSION_NONE);
        sp<AudioTrack> playerTrack = mPlayer->mAudioTrack;
        ASSERT_EQ(playerTrack->initCheck(), NO_ERROR);

        mBufferSize = mFrameCount * playerTrack->frameSize();
        mBuffer.resize(mBufferSize, 0);

        // populate buffer
        ASSERT_NE(mPulseFreq, 0);
        int32_t nPulseSamples = mSampleRate / mPulseFreq;
        int32_t pulseSize = nPulseSamples * playerTrack->frameSize();

        int32_t marker = 0;
        while (marker + pulseSize <= mBufferSize) {
            memset(mBuffer.data() + marker, 127, pulseSize / 2);
            marker += pulseSize;
        }
    }

    void playBuffer() {
        bool blocking = true;
        ssize_t nbytes = mPlayer->mAudioTrack->write(mBuffer.data(), mBufferSize, blocking);
        EXPECT_EQ(nbytes, mBufferSize) << "Did not write all data in blocking mode";
    }

    const double mDuration;  // seconds
    sp<TrackPlayer> mPlayer;

  private:
    const double mPulseFreq;
    const uint32_t mChannelCount;
    const uint32_t mSampleRate;

    const audio_format_t mFormat = AUDIO_FORMAT_PCM_16_BIT;
    const audio_output_flags_t mFlags = AUDIO_OUTPUT_FLAG_NONE;
    const audio_stream_type_t mStreamType = AUDIO_STREAM_MUSIC;

    int32_t mBufferSize;
    int32_t mFrameCount;
    std::vector<uint8_t> mBuffer;
};

class PlaybackTestParam : public TrackPlayerBaseTest {};

TEST_P(PlaybackTestParam, PlaybackTest) {
    // no-op implementation
    EXPECT_TRUE(mPlayer->setStartDelayMs(0).isOk());

    ASSERT_EQ(mPlayer->playerStart(), NO_ERROR);
    ASSERT_NO_FATAL_FAILURE(playBuffer());
    EXPECT_EQ(mPlayer->playerStop(), NO_ERROR);
}

INSTANTIATE_TEST_SUITE_P(TrackPlayerTest, PlaybackTestParam,
                         ::testing::Values(std::make_tuple(2.5, 25.0, 2, 48000)));

class ChangeVolumeTestParam : public TrackPlayerBaseTest {};

TEST_P(ChangeVolumeTestParam, ChangeVolumeTest) {
    float volume = 1.0f;
    (void)mPlayer->setPlayerVolume(volume / 2, volume);

    ASSERT_TRUE(mPlayer->start().isOk());
    ASSERT_EQ(mPlayer->playerSetVolume(), NO_ERROR);

    ASSERT_NO_FATAL_FAILURE(playBuffer());

    EXPECT_TRUE(mPlayer->stop().isOk());

    std::vector<float> setVol = {0.95f, 0.05f, 0.5f, 0.25f, -1.0f, 1.0f, 1.0f};
    std::vector<float> setPan = {0.0f, 0.0f, 1.0f, -1.0f, -1.0f, 0.5f, -0.5f};

    ASSERT_TRUE(mPlayer->start().isOk());

    for (int32_t i = 0; i < setVol.size(); i++) {
        EXPECT_TRUE(mPlayer->setVolume(setVol[i]).isOk());
        EXPECT_TRUE(mPlayer->setPan(setPan[i]).isOk());
        ASSERT_NO_FATAL_FAILURE(playBuffer());
    }
    EXPECT_TRUE(mPlayer->stop().isOk());
}

INSTANTIATE_TEST_SUITE_P(TrackPlayerTest, ChangeVolumeTestParam,
                         ::testing::Values(std::make_tuple(1.0, 100.0, 1, 24000)));

class PauseTestParam : public TrackPlayerBaseTest {};

TEST_P(PauseTestParam, PauseTest) {
    ASSERT_EQ(mPlayer->playerStart(), NO_ERROR);
    ASSERT_NO_FATAL_FAILURE(playBuffer());

    ASSERT_EQ(mPlayer->playerPause(), NO_ERROR);
    ASSERT_EQ(mPlayer->playerStart(), NO_ERROR);

    ASSERT_NO_FATAL_FAILURE(playBuffer());

    EXPECT_EQ(mPlayer->playerStop(), NO_ERROR);

    for (int32_t i = 0; i < 5; i++) {
        ASSERT_TRUE(mPlayer->start().isOk());
        ASSERT_NO_FATAL_FAILURE(playBuffer());
        ASSERT_TRUE(mPlayer->pause().isOk());
    }
    EXPECT_TRUE(mPlayer->stop().isOk());
}

INSTANTIATE_TEST_SUITE_P(TrackPlayerTest, PauseTestParam,
                         ::testing::Values(std::make_tuple(1.0, 75.0, 2, 24000)));

int main(int argc, char** argv) {
    android::ProcessState::self()->startThreadPool();
    ::testing::InitGoogleTest(&argc, argv);
    ::testing::UnitTest::GetInstance()->listeners().Append(new TestExecutionTracer());
    return RUN_ALL_TESTS();
}
