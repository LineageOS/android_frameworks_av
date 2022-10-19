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

#include <cutils/properties.h>
#include <gtest/gtest.h>
#include <string.h>

#include "audio_test_utils.h"

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
        sp<AudioPlayback> ap = sp<AudioPlayback>::make(
                0 /* sampleRate */, AUDIO_FORMAT_PCM_16_BIT, AUDIO_CHANNEL_OUT_STEREO,
                AUDIO_OUTPUT_FLAG_NONE, AUDIO_SESSION_NONE, AudioTrack::TRANSFER_OBTAIN,
                &attributes);
        ASSERT_NE(nullptr, ap);
        ASSERT_EQ(OK, ap->loadResource("/data/local/tmp/bbb_2ch_24kHz_s16le.raw"))
                << "Unable to open Resource";
        EXPECT_EQ(OK, ap->create()) << "track creation failed";
        sp<OnAudioDeviceUpdateNotifier> cb = sp<OnAudioDeviceUpdateNotifier>::make();
        EXPECT_EQ(OK, ap->getAudioTrackHandle()->addAudioDeviceCallback(cb));
        EXPECT_EQ(OK, ap->start()) << "audio track start failed";
        EXPECT_EQ(OK, ap->onProcess());
        EXPECT_EQ(OK, cb->waitForAudioDeviceCb());
        EXPECT_TRUE(checkPatchPlayback(cb->mAudioIo, cb->mDeviceId));
        EXPECT_NE(0, ap->getAudioTrackHandle()->getFlags() & output_flags[i]);
        audio_patch patch;
        EXPECT_EQ(OK, getPatchForOutputMix(cb->mAudioIo, patch));
        for (auto j = 0; j < patch.num_sources; j++) {
            if (patch.sources[j].type == AUDIO_PORT_TYPE_MIX &&
                patch.sources[j].ext.mix.handle == cb->mAudioIo) {
                if ((patch.sources[j].flags.output & output_flags[i]) == 0) {
                    ADD_FAILURE() << "expected output flag " << output_flags[i] << " is absent";
                    std::cerr << dumpPortConfig(patch.sources[j]);
                }
            }
        }
        ap->stop();
        ap->getAudioTrackHandle()->removeAudioDeviceCallback(cb);
    }
}

TEST(AudioTrackTest, TestRemoteSubmix) {
    std::vector<std::string> attachedDevices;
    std::vector<MixPort> mixPorts;
    std::vector<Route> routes;
    EXPECT_EQ(OK, parse_audio_policy_configuration_xml(attachedDevices, mixPorts, routes));
    bool hasFlag = false;
    for (int j = 0; j < attachedDevices.size() && !hasFlag; j++) {
        if (attachedDevices[j].find("Remote Submix") != -1) hasFlag = true;
    }
    if (!hasFlag) GTEST_SKIP() << " Device does not have Remote Submix port.";
    sp<AudioCapture> capture = new AudioCapture(AUDIO_SOURCE_REMOTE_SUBMIX, 48000,
                                                AUDIO_FORMAT_PCM_16_BIT, AUDIO_CHANNEL_IN_STEREO);
    ASSERT_NE(nullptr, capture);
    ASSERT_EQ(OK, capture->create()) << "record creation failed";

    sp<AudioPlayback> playback = sp<AudioPlayback>::make(
            48000 /* sampleRate */, AUDIO_FORMAT_PCM_16_BIT, AUDIO_CHANNEL_OUT_STEREO,
            AUDIO_OUTPUT_FLAG_NONE, AUDIO_SESSION_NONE);
    ASSERT_NE(nullptr, playback);
    ASSERT_EQ(OK, playback->loadResource("/data/local/tmp/bbb_2ch_24kHz_s16le.raw"))
            << "Unable to open Resource";
    ASSERT_EQ(OK, playback->create()) << "track creation failed";

    audio_port_v7 port;
    status_t status = getPortByAttributes(AUDIO_PORT_ROLE_SOURCE, AUDIO_PORT_TYPE_DEVICE,
                                          AUDIO_DEVICE_IN_REMOTE_SUBMIX, port);
    EXPECT_EQ(OK, status) << "Could not find port";

    EXPECT_EQ(OK, capture->start()) << "start recording failed";
    EXPECT_EQ(port.id, capture->getAudioRecordHandle()->getRoutedDeviceId())
            << "Capture NOT routed on expected port";

    status = getPortByAttributes(AUDIO_PORT_ROLE_SINK, AUDIO_PORT_TYPE_DEVICE,
                                 AUDIO_DEVICE_OUT_REMOTE_SUBMIX, port);
    EXPECT_EQ(OK, status) << "Could not find port";

    EXPECT_EQ(OK, playback->start()) << "audio track start failed";
    EXPECT_EQ(OK, playback->onProcess());
    ASSERT_EQ(port.id, playback->getAudioTrackHandle()->getRoutedDeviceId())
            << "Playback NOT routed on expected port";
    capture->stop();
    playback->stop();
}
