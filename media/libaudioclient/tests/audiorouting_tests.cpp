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

//#define LOG_NDEBUG 0
#define LOG_TAG "AudioRoutingTest"

#include <string.h>

#include <binder/Binder.h>
#include <binder/ProcessState.h>
#include <cutils/properties.h>
#include <gtest/gtest.h>

#include "audio_test_utils.h"
#include "test_execution_tracer.h"

using namespace android;

// UNIT TEST
TEST(AudioTrackTest, TestPerformanceMode) {
    std::vector<struct audio_port_v7> ports;
    ASSERT_EQ(OK, listAudioPorts(ports));
    audio_output_flags_t output_flags[] = {AUDIO_OUTPUT_FLAG_FAST, AUDIO_OUTPUT_FLAG_DEEP_BUFFER};
    audio_flags_mask_t flags[] = {AUDIO_FLAG_LOW_LATENCY, AUDIO_FLAG_DEEP_BUFFER};
    bool hasFlag = false;
    for (int i = 0; i < sizeof(flags) / sizeof(flags[0]); i++) {
        hasFlag = false;
        for (const auto& port : ports) {
            if (port.role == AUDIO_PORT_ROLE_SOURCE && port.type == AUDIO_PORT_TYPE_MIX) {
                if ((port.active_config.flags.output & output_flags[i]) != 0) {
                    hasFlag = true;
                    break;
                }
            }
        }
        if (!hasFlag) continue;
        audio_attributes_t attributes = AUDIO_ATTRIBUTES_INITIALIZER;
        attributes.usage = AUDIO_USAGE_MEDIA;
        attributes.content_type = AUDIO_CONTENT_TYPE_MUSIC;
        attributes.flags = flags[i];
        sp<AudioPlayback> ap = sp<AudioPlayback>::make(0 /* sampleRate */, AUDIO_FORMAT_PCM_16_BIT,
                                                       AUDIO_CHANNEL_OUT_STEREO,
                                                       AUDIO_OUTPUT_FLAG_NONE, AUDIO_SESSION_NONE,
                                                       AudioTrack::TRANSFER_OBTAIN, &attributes);
        ASSERT_NE(nullptr, ap);
        ASSERT_EQ(OK, ap->loadResource("/data/local/tmp/bbb_2ch_24kHz_s16le.raw"))
                << "Unable to open Resource";
        ASSERT_EQ(OK, ap->create()) << "track creation failed";
        sp<OnAudioDeviceUpdateNotifier> cb = sp<OnAudioDeviceUpdateNotifier>::make();
        EXPECT_EQ(OK, ap->getAudioTrackHandle()->addAudioDeviceCallback(cb));
        EXPECT_EQ(OK, ap->start()) << "audio track start failed";
        EXPECT_EQ(OK, ap->onProcess());
        EXPECT_EQ(OK, cb->waitForAudioDeviceCb());
        EXPECT_TRUE(checkPatchPlayback(cb->mAudioIo, cb->mDeviceId));
        EXPECT_NE(0, ap->getAudioTrackHandle()->getFlags() & output_flags[i]);
        audio_patch patch;
        EXPECT_EQ(OK, getPatchForOutputMix(cb->mAudioIo, patch));
        if (output_flags[i] != AUDIO_OUTPUT_FLAG_FAST) {
            // A "normal" output can still have a FastMixer, depending on the buffer size.
            // Thus, a fast track can be created on a mix port which does not have the FAST flag.
            for (auto j = 0; j < patch.num_sources; j++) {
                if (patch.sources[j].type == AUDIO_PORT_TYPE_MIX &&
                    patch.sources[j].ext.mix.handle == cb->mAudioIo) {
                    SCOPED_TRACE(dumpPortConfig(patch.sources[j]));
                    EXPECT_NE(0, patch.sources[j].flags.output & output_flags[i])
                            << "expected output flag "
                            << audio_output_flag_to_string(output_flags[i]) << " is absent";
                }
            }
        }
        ap->stop();
    }
}

TEST(AudioTrackTest, DefaultRoutingTest) {
    audio_port_v7 port;
    if (OK != getPortByAttributes(AUDIO_PORT_ROLE_SOURCE, AUDIO_PORT_TYPE_DEVICE,
                                  AUDIO_DEVICE_IN_REMOTE_SUBMIX, "0", port)) {
        GTEST_SKIP() << "remote submix in device not connected";
    }

    // create record instance
    sp<AudioCapture> capture = sp<AudioCapture>::make(
            AUDIO_SOURCE_REMOTE_SUBMIX, 48000, AUDIO_FORMAT_PCM_16_BIT, AUDIO_CHANNEL_IN_STEREO);
    ASSERT_NE(nullptr, capture);
    ASSERT_EQ(OK, capture->create()) << "record creation failed";
    sp<OnAudioDeviceUpdateNotifier> cbCapture = sp<OnAudioDeviceUpdateNotifier>::make();
    EXPECT_EQ(OK, capture->getAudioRecordHandle()->addAudioDeviceCallback(cbCapture));

    // create playback instance
    sp<AudioPlayback> playback = sp<AudioPlayback>::make(
            48000 /* sampleRate */, AUDIO_FORMAT_PCM_16_BIT, AUDIO_CHANNEL_OUT_STEREO,
            AUDIO_OUTPUT_FLAG_NONE, AUDIO_SESSION_NONE);
    ASSERT_NE(nullptr, playback);
    ASSERT_EQ(OK, playback->loadResource("/data/local/tmp/bbb_2ch_24kHz_s16le.raw"))
            << "Unable to open Resource";
    ASSERT_EQ(OK, playback->create()) << "track creation failed";
    sp<OnAudioDeviceUpdateNotifier> cbPlayback = sp<OnAudioDeviceUpdateNotifier>::make();
    EXPECT_EQ(OK, playback->getAudioTrackHandle()->addAudioDeviceCallback(cbPlayback));

    // capture should be routed to submix in port
    EXPECT_EQ(OK, capture->start()) << "start recording failed";
    EXPECT_EQ(OK, cbCapture->waitForAudioDeviceCb());
    EXPECT_EQ(port.id, capture->getAudioRecordHandle()->getRoutedDeviceId())
            << "Capture NOT routed on expected port";

    // capture start should create submix out port
    status_t status = getPortByAttributes(AUDIO_PORT_ROLE_SINK, AUDIO_PORT_TYPE_DEVICE,
                                          AUDIO_DEVICE_OUT_REMOTE_SUBMIX, "0", port);
    EXPECT_EQ(OK, status) << "Could not find port";

    // playback should be routed to submix out as long as capture is active
    EXPECT_EQ(OK, playback->start()) << "audio track start failed";
    EXPECT_EQ(OK, cbPlayback->waitForAudioDeviceCb());
    EXPECT_EQ(port.id, playback->getAudioTrackHandle()->getRoutedDeviceId())
            << "Playback NOT routed on expected port";

    capture->stop();
    playback->stop();
}

class AudioRoutingTest : public ::testing::Test {
  public:
    void SetUp() override {
        audio_port_v7 port;
        if (OK != getPortByAttributes(AUDIO_PORT_ROLE_SOURCE, AUDIO_PORT_TYPE_DEVICE,
                                      AUDIO_DEVICE_IN_REMOTE_SUBMIX, "0", port)) {
            GTEST_SKIP() << "remote submix in device not connected";
        }
        uint32_t mixType = MIX_TYPE_PLAYERS;
        uint32_t mixFlag = MIX_ROUTE_FLAG_LOOP_BACK;
        audio_devices_t deviceType = AUDIO_DEVICE_OUT_REMOTE_SUBMIX;
        AudioMixMatchCriterion criterion(AUDIO_USAGE_MEDIA, AUDIO_SOURCE_DEFAULT,
                                         RULE_MATCH_ATTRIBUTE_USAGE);
        std::vector<AudioMixMatchCriterion> criteria{criterion};
        audio_config_t config = AUDIO_CONFIG_INITIALIZER;
        config.channel_mask = AUDIO_CHANNEL_OUT_STEREO;
        config.format = AUDIO_FORMAT_PCM_16_BIT;
        config.sample_rate = 48000;
        AudioMix mix(criteria, mixType, config, mixFlag, String8{mAddress.c_str()}, 0);
        mix.mDeviceType = deviceType;
        mix.mToken = sp<BBinder>::make();
        mMixes.push(mix);
        if (OK == AudioSystem::registerPolicyMixes(mMixes, true)) {
            mPolicyMixRegistered = true;
        }
        ASSERT_TRUE(mPolicyMixRegistered) << "register policy mix failed";
    }

    void TearDown() override {
        if (mPolicyMixRegistered) {
            EXPECT_EQ(OK, AudioSystem::registerPolicyMixes(mMixes, false));
        }
    }

    bool mPolicyMixRegistered{false};
    std::string mAddress{"mix_1"};
    Vector<AudioMix> mMixes;
};

TEST_F(AudioRoutingTest, ConcurrentDynamicRoutingTest) {
    audio_port_v7 port, port_mix;
    // expect legacy submix in port to be connected
    status_t status = getPortByAttributes(AUDIO_PORT_ROLE_SOURCE, AUDIO_PORT_TYPE_DEVICE,
                                          AUDIO_DEVICE_IN_REMOTE_SUBMIX, "0", port);
    EXPECT_EQ(OK, status) << "Could not find port";

    // as policy mix is registered, expect submix in port with mAddress to be connected
    status = getPortByAttributes(AUDIO_PORT_ROLE_SOURCE, AUDIO_PORT_TYPE_DEVICE,
                                 AUDIO_DEVICE_IN_REMOTE_SUBMIX, mAddress, port_mix);
    EXPECT_EQ(OK, status) << "Could not find port";

    // create playback instance
    sp<AudioPlayback> playback = sp<AudioPlayback>::make(
            48000 /* sampleRate */, AUDIO_FORMAT_PCM_16_BIT, AUDIO_CHANNEL_OUT_STEREO,
            AUDIO_OUTPUT_FLAG_NONE, AUDIO_SESSION_NONE, AudioTrack::TRANSFER_OBTAIN);
    ASSERT_NE(nullptr, playback);
    ASSERT_EQ(OK, playback->loadResource("/data/local/tmp/bbb_2ch_24kHz_s16le.raw"))
            << "Unable to open Resource";
    ASSERT_EQ(OK, playback->create()) << "track creation failed";
    sp<OnAudioDeviceUpdateNotifier> cbPlayback = sp<OnAudioDeviceUpdateNotifier>::make();
    EXPECT_EQ(OK, playback->getAudioTrackHandle()->addAudioDeviceCallback(cbPlayback));

    // create capture instances on different ports
    sp<AudioCapture> captureA = sp<AudioCapture>::make(
            AUDIO_SOURCE_REMOTE_SUBMIX, 48000, AUDIO_FORMAT_PCM_16_BIT, AUDIO_CHANNEL_IN_STEREO);
    ASSERT_NE(nullptr, captureA);
    ASSERT_EQ(OK, captureA->create()) << "record creation failed";
    sp<OnAudioDeviceUpdateNotifier> cbCaptureA = sp<OnAudioDeviceUpdateNotifier>::make();
    EXPECT_EQ(OK, captureA->getAudioRecordHandle()->addAudioDeviceCallback(cbCaptureA));

    audio_attributes_t attr = AUDIO_ATTRIBUTES_INITIALIZER;
    attr.source = AUDIO_SOURCE_REMOTE_SUBMIX;
    sprintf(attr.tags, "addr=%s", mAddress.c_str());
    sp<AudioCapture> captureB = sp<AudioCapture>::make(
            AUDIO_SOURCE_REMOTE_SUBMIX, 48000, AUDIO_FORMAT_PCM_16_BIT, AUDIO_CHANNEL_IN_STEREO,
            AUDIO_INPUT_FLAG_NONE, AUDIO_SESSION_ALLOCATE, AudioRecord::TRANSFER_CALLBACK, &attr);
    ASSERT_NE(nullptr, captureB);
    ASSERT_EQ(OK, captureB->create()) << "record creation failed";
    sp<OnAudioDeviceUpdateNotifier> cbCaptureB = sp<OnAudioDeviceUpdateNotifier>::make();
    EXPECT_EQ(OK, captureB->getAudioRecordHandle()->addAudioDeviceCallback(cbCaptureB));

    // launch
    EXPECT_EQ(OK, captureA->start()) << "start recording failed";
    EXPECT_EQ(OK, cbCaptureA->waitForAudioDeviceCb());
    EXPECT_EQ(port.id, captureA->getAudioRecordHandle()->getRoutedDeviceId())
            << "Capture NOT routed on expected port";

    EXPECT_EQ(OK, captureB->start()) << "start recording failed";
    EXPECT_EQ(OK, cbCaptureB->waitForAudioDeviceCb());
    EXPECT_EQ(port_mix.id, captureB->getAudioRecordHandle()->getRoutedDeviceId())
            << "Capture NOT routed on expected port";

    // as record started, expect submix out ports to be connected
    status = getPortByAttributes(AUDIO_PORT_ROLE_SINK, AUDIO_PORT_TYPE_DEVICE,
                                 AUDIO_DEVICE_OUT_REMOTE_SUBMIX, "0", port);
    EXPECT_EQ(OK, status) << "unexpected submix out port found";

    status = getPortByAttributes(AUDIO_PORT_ROLE_SINK, AUDIO_PORT_TYPE_DEVICE,
                                 AUDIO_DEVICE_OUT_REMOTE_SUBMIX, mAddress, port_mix);
    EXPECT_EQ(OK, status) << "Could not find port";

    // check if playback routed to desired port
    EXPECT_EQ(OK, playback->start());
    EXPECT_EQ(OK, cbPlayback->waitForAudioDeviceCb());
    EXPECT_EQ(port_mix.id, playback->getAudioTrackHandle()->getRoutedDeviceId())
            << "Playback NOT routed on expected port";

    captureB->stop();

    // check if mAddress submix out is disconnected as capture session is stopped
    status = getPortByAttributes(AUDIO_PORT_ROLE_SINK, AUDIO_PORT_TYPE_DEVICE,
                                 AUDIO_DEVICE_OUT_REMOTE_SUBMIX, mAddress, port_mix);
    EXPECT_NE(OK, status) << "unexpected submix in port found";

    // check if legacy submix out is connected
    status = getPortByAttributes(AUDIO_PORT_ROLE_SINK, AUDIO_PORT_TYPE_DEVICE,
                                 AUDIO_DEVICE_OUT_REMOTE_SUBMIX, "0", port);
    EXPECT_EQ(OK, status) << "port not found";

    // unregister policy
    EXPECT_EQ(OK, AudioSystem::registerPolicyMixes(mMixes, false));
    mPolicyMixRegistered = false;

    // as policy mix is unregistered, expect submix in port with mAddress to be disconnected
    status = getPortByAttributes(AUDIO_PORT_ROLE_SOURCE, AUDIO_PORT_TYPE_DEVICE,
                                 AUDIO_DEVICE_IN_REMOTE_SUBMIX, mAddress, port_mix);
    EXPECT_NE(OK, status) << "unexpected submix in port found";

    playback->onProcess();
    // as captureA is active, it should re route to legacy submix
    EXPECT_EQ(OK, cbPlayback->waitForAudioDeviceCb(port.id));
    EXPECT_EQ(port.id, playback->getAudioTrackHandle()->getRoutedDeviceId())
            << "Playback NOT routed on expected port";

    captureA->stop();
    playback->stop();
}

int main(int argc, char** argv) {
    android::ProcessState::self()->startThreadPool();
    ::testing::InitGoogleTest(&argc, argv);
    ::testing::UnitTest::GetInstance()->listeners().Append(new TestExecutionTracer());
    return RUN_ALL_TESTS();
}
