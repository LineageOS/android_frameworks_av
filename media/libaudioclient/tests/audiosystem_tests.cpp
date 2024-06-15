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

#include <string.h>

#include <set>

#define LOG_TAG "AudioSystemTest"

#include <gtest/gtest.h>
#include <log/log.h>
#include <media/AidlConversionCppNdk.h>
#include <media/IAudioFlinger.h>

#include "audio_test_utils.h"
#include "test_execution_tracer.h"

using android::media::audio::common::AudioDeviceAddress;
using android::media::audio::common::AudioDeviceDescription;
using android::media::audio::common::AudioDeviceType;
using android::media::audio::common::AudioPortExt;
using namespace android;

void anyPatchContainsInputDevice(audio_port_handle_t deviceId, bool& res) {
    std::vector<struct audio_patch> patches;
    status_t status = listAudioPatches(patches);
    ASSERT_EQ(OK, status);
    res = false;
    for (const auto& patch : patches) {
        if (patchContainsInputDevice(deviceId, patch)) {
            res = true;
            return;
        }
    }
}

class AudioSystemTest : public ::testing::Test {
  public:
    void SetUp() override {
        mAF = AudioSystem::get_audio_flinger();
        ASSERT_NE(mAF, nullptr) << "Permission denied";
    }

    void TearDown() override {
        if (mPlayback) {
            mPlayback->stop();
            mCbPlayback.clear();
            mPlayback.clear();
        }
        if (mCapture) {
            mCapture->stop();
            mCbRecord.clear();
            mCapture.clear();
        }
    }

    void createPlaybackSession(void);
    void createRecordSession(void);

    sp<IAudioFlinger> mAF;
    sp<AudioPlayback> mPlayback;
    sp<OnAudioDeviceUpdateNotifier> mCbPlayback;
    sp<AudioCapture> mCapture;
    sp<OnAudioDeviceUpdateNotifier> mCbRecord;
};

void AudioSystemTest::createPlaybackSession(void) {
    audio_attributes_t attributes = AUDIO_ATTRIBUTES_INITIALIZER;
    attributes.usage = AUDIO_USAGE_MEDIA;
    attributes.content_type = AUDIO_CONTENT_TYPE_MUSIC;
    mPlayback = sp<AudioPlayback>::make(48000, AUDIO_FORMAT_PCM_16_BIT, AUDIO_CHANNEL_OUT_STEREO,
                                        AUDIO_OUTPUT_FLAG_FAST, AUDIO_SESSION_NONE,
                                        AudioTrack::TRANSFER_SHARED, &attributes);
    ASSERT_NE(nullptr, mPlayback);
    ASSERT_EQ(NO_ERROR, mPlayback->loadResource("/data/local/tmp/bbb_2ch_24kHz_s16le.raw"));
    EXPECT_EQ(NO_ERROR, mPlayback->create());
    mCbPlayback = sp<OnAudioDeviceUpdateNotifier>::make();
    EXPECT_EQ(OK, mPlayback->getAudioTrackHandle()->addAudioDeviceCallback(mCbPlayback));
    EXPECT_EQ(NO_ERROR, mPlayback->start());
    EXPECT_EQ(OK, mPlayback->onProcess());
    EXPECT_EQ(OK, mCbPlayback->waitForAudioDeviceCb());
}

void AudioSystemTest::createRecordSession(void) {
    mCapture = new AudioCapture(AUDIO_SOURCE_DEFAULT, 44100, AUDIO_FORMAT_PCM_8_24_BIT,
                                AUDIO_CHANNEL_IN_MONO, AUDIO_INPUT_FLAG_FAST);
    ASSERT_NE(nullptr, mCapture);
    ASSERT_EQ(OK, mCapture->create()) << "record creation failed";
    mCbRecord = sp<OnAudioDeviceUpdateNotifier>::make();
    EXPECT_EQ(OK, mCapture->getAudioRecordHandle()->addAudioDeviceCallback(mCbRecord));
    EXPECT_EQ(OK, mCapture->start()) << "record creation failed";
    EXPECT_EQ(OK, mCbRecord->waitForAudioDeviceCb());
}

// UNIT TESTS
TEST_F(AudioSystemTest, CheckServerSideValues) {
    ASSERT_NO_FATAL_FAILURE(createPlaybackSession());
    EXPECT_GT(mAF->sampleRate(mCbPlayback->mAudioIo), 0);
    EXPECT_NE(mAF->format(mCbPlayback->mAudioIo), AUDIO_FORMAT_INVALID);
    EXPECT_GT(mAF->frameCount(mCbPlayback->mAudioIo), 0);
    size_t frameCountHal, frameCountHalCache;
    frameCountHal = mAF->frameCountHAL(mCbPlayback->mAudioIo);
    EXPECT_GT(frameCountHal, 0);
    EXPECT_EQ(OK, AudioSystem::getFrameCountHAL(mCbPlayback->mAudioIo, &frameCountHalCache));
    EXPECT_EQ(frameCountHal, frameCountHalCache);
    EXPECT_GT(mAF->latency(mCbPlayback->mAudioIo), 0);
    // client side latency is at least server side latency
    EXPECT_LE(mAF->latency(mCbPlayback->mAudioIo), mPlayback->getAudioTrackHandle()->latency());

    ASSERT_NO_FATAL_FAILURE(createRecordSession());
    EXPECT_GT(mAF->sampleRate(mCbRecord->mAudioIo), 0);
    // EXPECT_NE(mAF->format(mCbRecord->mAudioIo), AUDIO_FORMAT_INVALID);
    EXPECT_GT(mAF->frameCount(mCbRecord->mAudioIo), 0);
    EXPECT_GT(mAF->frameCountHAL(mCbRecord->mAudioIo), 0);
    frameCountHal = mAF->frameCountHAL(mCbRecord->mAudioIo);
    EXPECT_GT(frameCountHal, 0);
    EXPECT_EQ(OK, AudioSystem::getFrameCountHAL(mCbRecord->mAudioIo, &frameCountHalCache));
    EXPECT_EQ(frameCountHal, frameCountHalCache);
    // EXPECT_GT(mAF->latency(mCbRecord->mAudioIo), 0);
    // client side latency is at least server side latency
    // EXPECT_LE(mAF->latency(mCbRecord->mAudioIo), mCapture->getAudioRecordHandle()->latency());

    EXPECT_GT(AudioSystem::getPrimaryOutputSamplingRate(), 0);  // first fast mixer sample rate
    EXPECT_GT(AudioSystem::getPrimaryOutputFrameCount(), 0);    // fast mixer frame count
}

TEST_F(AudioSystemTest, GetSetMasterVolume) {
    ASSERT_NO_FATAL_FAILURE(createPlaybackSession());
    float origVol, tstVol;
    EXPECT_EQ(NO_ERROR, AudioSystem::getMasterVolume(&origVol));
    float newVol;
    if (origVol + 0.2f > 1.0f) {
        newVol = origVol - 0.2f;
    } else {
        newVol = origVol + 0.2f;
    }
    EXPECT_EQ(NO_ERROR, AudioSystem::setMasterVolume(newVol));
    EXPECT_EQ(NO_ERROR, AudioSystem::getMasterVolume(&tstVol));
    EXPECT_EQ(newVol, tstVol);
    EXPECT_EQ(NO_ERROR, AudioSystem::setMasterVolume(origVol));
    EXPECT_EQ(NO_ERROR, AudioSystem::getMasterVolume(&tstVol));
    EXPECT_EQ(origVol, tstVol);
}

TEST_F(AudioSystemTest, GetSetMasterMute) {
    ASSERT_NO_FATAL_FAILURE(createPlaybackSession());
    bool origMuteState, tstMuteState;
    EXPECT_EQ(NO_ERROR, AudioSystem::getMasterMute(&origMuteState));
    EXPECT_EQ(NO_ERROR, AudioSystem::setMasterMute(!origMuteState));
    EXPECT_EQ(NO_ERROR, AudioSystem::getMasterMute(&tstMuteState));
    EXPECT_EQ(!origMuteState, tstMuteState);
    EXPECT_EQ(NO_ERROR, AudioSystem::setMasterMute(origMuteState));
    EXPECT_EQ(NO_ERROR, AudioSystem::getMasterMute(&tstMuteState));
    EXPECT_EQ(origMuteState, tstMuteState);
}

TEST_F(AudioSystemTest, GetSetMicMute) {
    ASSERT_NO_FATAL_FAILURE(createPlaybackSession());
    bool origMuteState, tstMuteState;
    EXPECT_EQ(NO_ERROR, AudioSystem::isMicrophoneMuted(&origMuteState));
    EXPECT_EQ(NO_ERROR, AudioSystem::muteMicrophone(!origMuteState));
    EXPECT_EQ(NO_ERROR, AudioSystem::isMicrophoneMuted(&tstMuteState));
    EXPECT_EQ(!origMuteState, tstMuteState);
    EXPECT_EQ(NO_ERROR, AudioSystem::muteMicrophone(origMuteState));
    EXPECT_EQ(NO_ERROR, AudioSystem::isMicrophoneMuted(&tstMuteState));
    EXPECT_EQ(origMuteState, tstMuteState);
}

TEST_F(AudioSystemTest, GetSetMasterBalance) {
    ASSERT_NO_FATAL_FAILURE(createPlaybackSession());
    float origBalance, tstBalance;
    EXPECT_EQ(OK, AudioSystem::getMasterBalance(&origBalance));
    float newBalance;
    if (origBalance + 0.2f > 1.0f) {
        newBalance = origBalance - 0.2f;
    } else {
        newBalance = origBalance + 0.2f;
    }
    EXPECT_EQ(OK, AudioSystem::setMasterBalance(newBalance));
    EXPECT_EQ(OK, AudioSystem::getMasterBalance(&tstBalance));
    EXPECT_EQ(newBalance, tstBalance);
    EXPECT_EQ(OK, AudioSystem::setMasterBalance(origBalance));
    EXPECT_EQ(OK, AudioSystem::getMasterBalance(&tstBalance));
    EXPECT_EQ(origBalance, tstBalance);
}

TEST_F(AudioSystemTest, GetStreamVolume) {
    ASSERT_NO_FATAL_FAILURE(createPlaybackSession());
    float origStreamVol;
    EXPECT_EQ(NO_ERROR, AudioSystem::getStreamVolume(AUDIO_STREAM_MUSIC, &origStreamVol,
                                                     mCbPlayback->mAudioIo));
}

TEST_F(AudioSystemTest, GetStreamMute) {
    ASSERT_NO_FATAL_FAILURE(createPlaybackSession());
    bool origMuteState;
    EXPECT_EQ(NO_ERROR, AudioSystem::getStreamMute(AUDIO_STREAM_MUSIC, &origMuteState));
}

TEST_F(AudioSystemTest, StartAndStopAudioSource) {
    std::vector<struct audio_port_v7> ports;
    audio_port_config sourcePortConfig;
    audio_attributes_t attributes = AudioSystem::streamTypeToAttributes(AUDIO_STREAM_MUSIC);
    audio_port_handle_t sourcePortHandle = AUDIO_PORT_HANDLE_NONE;

    status_t status = listAudioPorts(ports);
    ASSERT_EQ(OK, status);
    if (ports.empty()) {
        GTEST_SKIP() << "No ports returned by the audio system";
    }

    bool sourceFound = false;
    for (const auto& port : ports) {
        if (port.role != AUDIO_PORT_ROLE_SOURCE || port.type != AUDIO_PORT_TYPE_DEVICE) continue;
        if (port.ext.device.type != AUDIO_DEVICE_IN_FM_TUNER) continue;
        sourceFound = true;
        sourcePortConfig = port.active_config;

        bool patchFound;

        // start audio source.
        status_t ret =
                AudioSystem::startAudioSource(&sourcePortConfig, &attributes, &sourcePortHandle);
        EXPECT_EQ(OK, ret) << "AudioSystem::startAudioSource for source "
                           << audio_device_to_string(port.ext.device.type) << " failed";
        if (ret != OK) continue;

        // verify that patch is established by the source port.
        ASSERT_NO_FATAL_FAILURE(anyPatchContainsInputDevice(port.id, patchFound));
        EXPECT_EQ(true, patchFound);
        EXPECT_NE(sourcePortHandle, AUDIO_PORT_HANDLE_NONE);

        if (sourcePortHandle != AUDIO_PORT_HANDLE_NONE) {
            ret = AudioSystem::stopAudioSource(sourcePortHandle);
            EXPECT_EQ(OK, ret) << "AudioSystem::stopAudioSource failed for handle "
                               << sourcePortHandle;
        }

        // verify that no source port patch exists.
        ASSERT_NO_FATAL_FAILURE(anyPatchContainsInputDevice(port.id, patchFound));
        EXPECT_EQ(false, patchFound);
    }
    if (!sourceFound) {
        GTEST_SKIP() << "No ports suitable for testing";
    }
}

TEST_F(AudioSystemTest, CreateAndReleaseAudioPatch) {
    status_t status;
    struct audio_patch audioPatch;
    std::vector<struct audio_port_v7> ports;
    audio_patch_handle_t audioPatchHandle = AUDIO_PATCH_HANDLE_NONE;

    bool patchFound = false;
    audio_port_v7 sourcePort{};
    audio_port_v7 sinkPort{};

    audioPatch.id = 0;
    audioPatch.num_sources = 1;
    audioPatch.num_sinks = 1;

    status = listAudioPorts(ports);
    ASSERT_EQ(OK, status);
    if (ports.empty()) {
        GTEST_SKIP() << "No output devices returned by the audio system";
    }

    bool sourceFound = false, sinkFound = false;
    for (const auto& port : ports) {
        if (port.role == AUDIO_PORT_ROLE_SOURCE && port.type == AUDIO_PORT_TYPE_DEVICE) {
            sourcePort = port;
            sourceFound = true;
        }
        if (port.role == AUDIO_PORT_ROLE_SINK && port.type == AUDIO_PORT_TYPE_DEVICE &&
            port.ext.device.type == AUDIO_DEVICE_OUT_SPEAKER) {
            sinkPort = port;
            sinkFound = true;
        }
        if (sourceFound && sinkFound) break;
    }
    if (!sourceFound || !sinkFound) {
        GTEST_SKIP() << "No ports suitable for testing";
    }

    audioPatch.sources[0] = sourcePort.active_config;
    audioPatch.sinks[0] = sinkPort.active_config;

    status = AudioSystem::createAudioPatch(&audioPatch, &audioPatchHandle);
    EXPECT_EQ(OK, status) << "AudioSystem::createAudioPatch failed between source "
                          << audio_device_to_string(sourcePort.ext.device.type) << " and sink "
                          << audio_device_to_string(sinkPort.ext.device.type);

    // verify that patch is established between source and the sink.
    ASSERT_NO_FATAL_FAILURE(anyPatchContainsInputDevice(sourcePort.id, patchFound));
    EXPECT_EQ(true, patchFound);

    EXPECT_NE(AUDIO_PORT_HANDLE_NONE, audioPatchHandle);
    status = AudioSystem::releaseAudioPatch(audioPatchHandle);
    EXPECT_EQ(OK, status) << "AudioSystem::releaseAudioPatch failed between source "
                          << audio_device_to_string(sourcePort.ext.device.type) << " and sink "
                          << audio_device_to_string(sinkPort.ext.device.type);

    // verify that no patch is established between source and the sink after releaseAudioPatch.
    ASSERT_NO_FATAL_FAILURE(anyPatchContainsInputDevice(sourcePort.id, patchFound));
    EXPECT_EQ(false, patchFound);
}

TEST_F(AudioSystemTest, GetAudioPort) {
    std::vector<struct audio_port_v7> ports;
    status_t status = listAudioPorts(ports);
    ASSERT_EQ(OK, status);
    for (const auto& port : ports) {
        audio_port_v7 portTest{.id = port.id};
        EXPECT_EQ(OK, AudioSystem::getAudioPort(&portTest));
        EXPECT_TRUE(audio_ports_v7_are_equal(&portTest, &port));
    }
}

TEST_F(AudioSystemTest, TestPhoneState) {
    uid_t uid = getuid();
    EXPECT_EQ(OK, AudioSystem::setPhoneState(AUDIO_MODE_RINGTONE, uid));
    audio_mode_t state = AudioSystem::getPhoneState();
    EXPECT_EQ(AUDIO_MODE_RINGTONE, state);
    EXPECT_EQ(OK, AudioSystem::setPhoneState(AUDIO_MODE_IN_COMMUNICATION, uid));
    state = AudioSystem::getPhoneState();
    EXPECT_EQ(AUDIO_MODE_IN_COMMUNICATION, state);
    EXPECT_EQ(OK, AudioSystem::setPhoneState(AUDIO_MODE_NORMAL, uid));
    state = AudioSystem::getPhoneState();
    EXPECT_EQ(AUDIO_MODE_NORMAL, state);
}

TEST_F(AudioSystemTest, GetDirectProfilesForAttributes) {
    std::vector<audio_profile> audioProfiles;
    audio_attributes_t attributes = AUDIO_ATTRIBUTES_INITIALIZER;
    attributes.usage = AUDIO_USAGE_MEDIA;
    attributes.content_type = AUDIO_CONTENT_TYPE_MUSIC;
    EXPECT_EQ(BAD_VALUE, AudioSystem::getDirectProfilesForAttributes(nullptr, nullptr));
    EXPECT_EQ(BAD_VALUE, AudioSystem::getDirectProfilesForAttributes(nullptr, &audioProfiles));
    EXPECT_EQ(BAD_VALUE, AudioSystem::getDirectProfilesForAttributes(&attributes, nullptr));
    EXPECT_EQ(NO_ERROR, AudioSystem::getDirectProfilesForAttributes(&attributes, &audioProfiles));
}

bool isPublicStrategy(const AudioProductStrategy& strategy) {
    bool result = true;
    for (auto& attribute : strategy.getVolumeGroupAttributes()) {
        if (attribute.getAttributes() == AUDIO_ATTRIBUTES_INITIALIZER &&
            (uint32_t(attribute.getStreamType()) >= AUDIO_STREAM_PUBLIC_CNT)) {
            result = false;
            break;
        }
    }
    return result;
}

TEST_F(AudioSystemTest, DevicesForRoleAndStrategy) {
    std::vector<struct audio_port_v7> ports;
    status_t status = listAudioPorts(ports);
    ASSERT_EQ(OK, status);

    std::vector<struct audio_port_v7> devicePorts;
    for (const auto& port : ports) {
        if (port.type == AUDIO_PORT_TYPE_DEVICE && audio_is_output_device(port.ext.device.type)) {
            devicePorts.push_back(port);
        }
    }
    if (devicePorts.empty()) {
        GTEST_SKIP() << "No output devices returned by the audio system";
    }

    AudioProductStrategyVector strategies;
    EXPECT_EQ(OK, AudioSystem::listAudioProductStrategies(strategies));
    if (strategies.empty()) {
        GTEST_SKIP() << "No strategies returned by the audio system";
    }

    audio_attributes_t attributes = AUDIO_ATTRIBUTES_INITIALIZER;
    attributes.usage = AUDIO_USAGE_MEDIA;

    bool hasStrategyForMedia = false;
    AudioProductStrategy mediaStrategy;
    for (const auto& strategy : strategies) {
        if (!isPublicStrategy(strategy)) continue;

        for (const auto& att : strategy.getVolumeGroupAttributes()) {
            if (strategy.attributesMatches(att.getAttributes(), attributes)) {
                hasStrategyForMedia = true;
                mediaStrategy = strategy;
                break;
            }
        }
    }

    if (!hasStrategyForMedia) {
        GTEST_SKIP() << "No strategies returned for music media";
    }

    AudioDeviceTypeAddrVector devices;
    EXPECT_EQ(BAD_VALUE, AudioSystem::getDevicesForRoleAndStrategy(PRODUCT_STRATEGY_NONE,
                                                                   DEVICE_ROLE_PREFERRED, devices));
    EXPECT_EQ(BAD_VALUE, AudioSystem::getDevicesForRoleAndStrategy(mediaStrategy.getId(),
                                                                   DEVICE_ROLE_NONE, devices));
    status = AudioSystem::getDevicesForRoleAndStrategy(mediaStrategy.getId(), DEVICE_ROLE_PREFERRED,
                                                       devices);
    if (status == NAME_NOT_FOUND) {
        AudioDeviceTypeAddrVector outputDevices;
        for (const auto& port : devicePorts) {
            if (port.ext.device.type == AUDIO_DEVICE_OUT_SPEAKER) {
                const AudioDeviceTypeAddr outputDevice(port.ext.device.type,
                                                       port.ext.device.address);
                outputDevices.push_back(outputDevice);
            }
        }
        EXPECT_EQ(OK, AudioSystem::setDevicesRoleForStrategy(mediaStrategy.getId(),
                                                             DEVICE_ROLE_PREFERRED, outputDevices));
        EXPECT_EQ(OK, AudioSystem::getDevicesForRoleAndStrategy(mediaStrategy.getId(),
                                                                DEVICE_ROLE_PREFERRED, devices));
        EXPECT_EQ(devices, outputDevices);
        EXPECT_EQ(OK, AudioSystem::clearDevicesRoleForStrategy(mediaStrategy.getId(),
                                                               DEVICE_ROLE_PREFERRED));
        EXPECT_EQ(NAME_NOT_FOUND, AudioSystem::getDevicesForRoleAndStrategy(
                                          mediaStrategy.getId(), DEVICE_ROLE_PREFERRED, devices));
    }
}

TEST_F(AudioSystemTest, VolumeIndexForAttributes) {
    AudioVolumeGroupVector groups;
    EXPECT_EQ(OK, AudioSystem::listAudioVolumeGroups(groups));
    for (const auto& group : groups) {
        if (group.getAudioAttributes().empty()) continue;
        const audio_attributes_t attr = group.getAudioAttributes()[0];
        if (attr == AUDIO_ATTRIBUTES_INITIALIZER) continue;
        audio_stream_type_t streamType = AudioSystem::attributesToStreamType(attr);
        if (streamType >= AUDIO_STREAM_PUBLIC_CNT) continue;

        volume_group_t vg;
        EXPECT_EQ(OK, AudioSystem::getVolumeGroupFromAudioAttributes(attr, vg));
        EXPECT_EQ(group.getId(), vg);

        int index;
        EXPECT_EQ(OK,
                  AudioSystem::getVolumeIndexForAttributes(attr, index, AUDIO_DEVICE_OUT_SPEAKER));

        int indexTest;
        EXPECT_EQ(OK, AudioSystem::getStreamVolumeIndex(streamType, &indexTest,
                                                        AUDIO_DEVICE_OUT_SPEAKER));
        EXPECT_EQ(index, indexTest);
    }
}

TEST_F(AudioSystemTest, DevicesRoleForCapturePreset) {
    std::vector<struct audio_port_v7> ports;
    status_t status = listAudioPorts(ports);
    ASSERT_EQ(OK, status);

    if (ports.empty()) {
        GTEST_SKIP() << "No ports returned by the audio system";
    }

    audio_devices_t inDeviceA = AUDIO_DEVICE_IN_BUILTIN_MIC;
    audio_devices_t inDeviceB = AUDIO_DEVICE_IN_BUILTIN_MIC;
    for (const auto& port : ports) {
        if (port.role != AUDIO_PORT_ROLE_SOURCE || port.type != AUDIO_PORT_TYPE_DEVICE) continue;
        if (port.ext.device.type == inDeviceA) continue;
        inDeviceB = port.ext.device.type;
        break;
    }
    const audio_source_t audioSource = AUDIO_SOURCE_MIC;
    const device_role_t role = DEVICE_ROLE_PREFERRED;
    const AudioDeviceTypeAddr inputDevice(inDeviceA, "");
    const AudioDeviceTypeAddrVector inputDevices = {inputDevice};
    const AudioDeviceTypeAddr outputDevice(AUDIO_DEVICE_OUT_SPEAKER, "");
    const AudioDeviceTypeAddrVector outputDevices = {outputDevice};

    // Test invalid device when setting
    EXPECT_EQ(BAD_VALUE,
              AudioSystem::setDevicesRoleForCapturePreset(audioSource, role, outputDevices));
    EXPECT_EQ(BAD_VALUE,
              AudioSystem::addDevicesRoleForCapturePreset(audioSource, role, outputDevices));
    EXPECT_EQ(BAD_VALUE,
              AudioSystem::removeDevicesRoleForCapturePreset(audioSource, role, outputDevices));

    // Test invalid role
    AudioDeviceTypeAddrVector devices;
    EXPECT_EQ(BAD_VALUE, AudioSystem::getDevicesForRoleAndCapturePreset(audioSource,
                                                                        DEVICE_ROLE_NONE, devices));
    EXPECT_EQ(BAD_VALUE, AudioSystem::setDevicesRoleForCapturePreset(audioSource, DEVICE_ROLE_NONE,
                                                                     inputDevices));
    EXPECT_EQ(BAD_VALUE, AudioSystem::addDevicesRoleForCapturePreset(audioSource, DEVICE_ROLE_NONE,
                                                                     inputDevices));
    EXPECT_EQ(BAD_VALUE, AudioSystem::removeDevicesRoleForCapturePreset(
                                 audioSource, DEVICE_ROLE_NONE, inputDevices));
    EXPECT_EQ(BAD_VALUE,
              AudioSystem::clearDevicesRoleForCapturePreset(audioSource, DEVICE_ROLE_NONE));

    // Without setting, call get/remove/clear must fail
    EXPECT_EQ(NAME_NOT_FOUND,
              AudioSystem::getDevicesForRoleAndCapturePreset(audioSource, role, devices));
    EXPECT_TRUE(devices.empty());
    EXPECT_EQ(NAME_NOT_FOUND,
              AudioSystem::removeDevicesRoleForCapturePreset(audioSource, role, devices));
    EXPECT_EQ(NAME_NOT_FOUND, AudioSystem::clearDevicesRoleForCapturePreset(audioSource, role));

    // Test set/get devices role
    EXPECT_EQ(NO_ERROR,
              AudioSystem::setDevicesRoleForCapturePreset(audioSource, role, inputDevices));
    ASSERT_EQ(NO_ERROR, AudioSystem::getDevicesForRoleAndCapturePreset(audioSource, role, devices));
    EXPECT_EQ(devices, inputDevices);

    // Test setting will change the previously set devices
    const AudioDeviceTypeAddr inputDevice2 = AudioDeviceTypeAddr(inDeviceB, "");
    AudioDeviceTypeAddrVector inputDevices2 = {inputDevice2};
    EXPECT_EQ(NO_ERROR,
              AudioSystem::setDevicesRoleForCapturePreset(audioSource, role, inputDevices2));
    devices.clear();
    EXPECT_EQ(NO_ERROR, AudioSystem::getDevicesForRoleAndCapturePreset(audioSource, role, devices));
    EXPECT_EQ(devices, inputDevices2);

    // Test add devices
    EXPECT_EQ(NO_ERROR,
              AudioSystem::addDevicesRoleForCapturePreset(audioSource, role, inputDevices));
    devices.clear();
    EXPECT_EQ(NO_ERROR, AudioSystem::getDevicesForRoleAndCapturePreset(audioSource, role, devices));
    EXPECT_EQ(2, devices.size());
    EXPECT_TRUE(std::find(devices.begin(), devices.end(), inputDevice) != devices.end());
    EXPECT_TRUE(std::find(devices.begin(), devices.end(), inputDevice2) != devices.end());

    // Test remove devices
    EXPECT_EQ(NO_ERROR,
              AudioSystem::removeDevicesRoleForCapturePreset(audioSource, role, inputDevices));
    devices.clear();
    EXPECT_EQ(NO_ERROR, AudioSystem::getDevicesForRoleAndCapturePreset(audioSource, role, devices));
    EXPECT_EQ(devices, inputDevices2);

    // Test remove devices that are not set as the device role
    EXPECT_EQ(BAD_VALUE,
              AudioSystem::removeDevicesRoleForCapturePreset(audioSource, role, inputDevices));

    // Test clear devices
    EXPECT_EQ(NO_ERROR, AudioSystem::clearDevicesRoleForCapturePreset(audioSource, role));
    devices.clear();
    EXPECT_EQ(NAME_NOT_FOUND,
              AudioSystem::getDevicesForRoleAndCapturePreset(audioSource, role, devices));

    AudioDeviceTypeAddrVector inputDevices3 = {inputDevice, inputDevice2};
    EXPECT_EQ(NO_ERROR,
              AudioSystem::setDevicesRoleForCapturePreset(audioSource, role, inputDevices3));
    devices.clear();
    EXPECT_EQ(NO_ERROR, AudioSystem::getDevicesForRoleAndCapturePreset(audioSource, role, devices));
    EXPECT_EQ(2, devices.size());
    EXPECT_TRUE(std::find(devices.begin(), devices.end(), inputDevice) != devices.end());
    EXPECT_TRUE(std::find(devices.begin(), devices.end(), inputDevice2) != devices.end());
    EXPECT_EQ(NO_ERROR, AudioSystem::clearDevicesRoleForCapturePreset(audioSource, role));
}

TEST_F(AudioSystemTest, UidDeviceAffinities) {
    uid_t uid = getuid();

    // Test invalid device for example audio_is_input_device
    AudioDeviceTypeAddr inputDevice(AUDIO_DEVICE_IN_BUILTIN_MIC, "");
    AudioDeviceTypeAddrVector inputDevices = {inputDevice};
    EXPECT_EQ(BAD_VALUE, AudioSystem::setUidDeviceAffinities(uid, inputDevices));

    // Test valid device for example audio_is_output_device
    AudioDeviceTypeAddr outputDevice(AUDIO_DEVICE_OUT_SPEAKER, "");
    AudioDeviceTypeAddrVector outputDevices = {outputDevice};
    EXPECT_EQ(NO_ERROR, AudioSystem::setUidDeviceAffinities(uid, outputDevices));
    EXPECT_EQ(NO_ERROR, AudioSystem::removeUidDeviceAffinities(uid));
}

TEST_F(AudioSystemTest, UserIdDeviceAffinities) {
    int userId = 200;

    // Test invalid device for example audio_is_input_device
    AudioDeviceTypeAddr inputDevice(AUDIO_DEVICE_IN_BUILTIN_MIC, "");
    AudioDeviceTypeAddrVector inputDevices = {inputDevice};
    EXPECT_EQ(BAD_VALUE, AudioSystem::setUserIdDeviceAffinities(userId, inputDevices));

    // Test valid device for ezample audio_is_output_device
    AudioDeviceTypeAddr outputDevice(AUDIO_DEVICE_OUT_SPEAKER, "");
    AudioDeviceTypeAddrVector outputDevices = {outputDevice};
    EXPECT_EQ(NO_ERROR, AudioSystem::setUserIdDeviceAffinities(userId, outputDevices));
    EXPECT_EQ(NO_ERROR, AudioSystem::removeUserIdDeviceAffinities(userId));
}

namespace {

class WithSimulatedDeviceConnections {
  public:
    WithSimulatedDeviceConnections()
        : mIsSupported(AudioSystem::setSimulateDeviceConnections(true) == OK) {}
    ~WithSimulatedDeviceConnections() {
        if (mIsSupported) {
            if (status_t status = AudioSystem::setSimulateDeviceConnections(false); status != OK) {
                ALOGE("Error restoring device connections simulation state: %d", status);
            }
        }
    }
    bool isSupported() const { return mIsSupported; }

  private:
    const bool mIsSupported;
};

android::media::audio::common::AudioPort GenerateUniqueDeviceAddress(
        const android::media::audio::common::AudioPort& port) {
    // Point-to-point connections do not use addresses.
    static const std::set<std::string> kPointToPointConnections = {
            AudioDeviceDescription::CONNECTION_ANALOG(), AudioDeviceDescription::CONNECTION_HDMI(),
            AudioDeviceDescription::CONNECTION_HDMI_ARC(),
            AudioDeviceDescription::CONNECTION_HDMI_EARC(),
            AudioDeviceDescription::CONNECTION_SPDIF()};
    static int nextId = 0;
    using Tag = AudioDeviceAddress::Tag;
    const auto& deviceDescription = port.ext.get<AudioPortExt::Tag::device>().device.type;
    AudioDeviceAddress address;
    if (kPointToPointConnections.count(deviceDescription.connection) == 0) {
        switch (suggestDeviceAddressTag(deviceDescription)) {
            case Tag::id:
                address = AudioDeviceAddress::make<Tag::id>(std::to_string(++nextId));
                break;
            case Tag::mac:
                address = AudioDeviceAddress::make<Tag::mac>(
                        std::vector<uint8_t>{1, 2, 3, 4, 5, static_cast<uint8_t>(++nextId & 0xff)});
                break;
            case Tag::ipv4:
                address = AudioDeviceAddress::make<Tag::ipv4>(
                        std::vector<uint8_t>{192, 168, 0, static_cast<uint8_t>(++nextId & 0xff)});
                break;
            case Tag::ipv6:
                address = AudioDeviceAddress::make<Tag::ipv6>(std::vector<int32_t>{
                        0xfc00, 0x0123, 0x4567, 0x89ab, 0xcdef, 0, 0, ++nextId & 0xffff});
                break;
            case Tag::alsa:
                address = AudioDeviceAddress::make<Tag::alsa>(std::vector<int32_t>{1, ++nextId});
                break;
        }
    }
    android::media::audio::common::AudioPort result = port;
    result.ext.get<AudioPortExt::Tag::device>().device.address = std::move(address);
    return result;
}

}  // namespace

TEST_F(AudioSystemTest, SetDeviceConnectedState) {
    WithSimulatedDeviceConnections connSim;
    if (!connSim.isSupported()) {
        GTEST_SKIP() << "Simulation of external device connections not supported";
    }
    std::vector<media::AudioPortFw> ports;
    ASSERT_EQ(OK, AudioSystem::listDeclaredDevicePorts(media::AudioPortRole::NONE, &ports));
    if (ports.empty()) {
        GTEST_SKIP() << "No ports returned by the audio system";
    }
    const std::set<AudioDeviceType> typesToUse{
            AudioDeviceType::IN_DEVICE,       AudioDeviceType::IN_HEADSET,
            AudioDeviceType::IN_MICROPHONE,   AudioDeviceType::OUT_DEVICE,
            AudioDeviceType::OUT_HEADPHONE,   AudioDeviceType::OUT_HEADSET,
            AudioDeviceType::OUT_HEARING_AID, AudioDeviceType::OUT_SPEAKER};
    std::vector<media::AudioPortFw> externalDevicePorts;
    for (const auto& port : ports) {
        if (const auto& device = port.hal.ext.get<AudioPortExt::device>().device;
            !device.type.connection.empty() && typesToUse.count(device.type.type)) {
            externalDevicePorts.push_back(port);
        }
    }
    if (externalDevicePorts.empty()) {
        GTEST_SKIP() << "No ports for considered non-attached devices";
    }
    for (auto& port : externalDevicePorts) {
        android::media::audio::common::AudioPort aidlPort = GenerateUniqueDeviceAddress(port.hal);
        SCOPED_TRACE(aidlPort.toString());
        audio_devices_t type;
        char address[AUDIO_DEVICE_MAX_ADDRESS_LEN];
        status_t status = aidl2legacy_AudioDevice_audio_device(
                aidlPort.ext.get<AudioPortExt::Tag::device>().device, &type, address);
        ASSERT_EQ(OK, status);
        audio_policy_dev_state_t deviceState = AudioSystem::getDeviceConnectionState(type, address);
        EXPECT_EQ(AUDIO_POLICY_DEVICE_STATE_UNAVAILABLE, deviceState);
        if (deviceState != AUDIO_POLICY_DEVICE_STATE_UNAVAILABLE) continue;
        // !!! Instead of the default format, use each format from 'ext.encodedFormats'
        // !!! if they are not empty
        status = AudioSystem::setDeviceConnectionState(AUDIO_POLICY_DEVICE_STATE_AVAILABLE,
                                                       aidlPort, AUDIO_FORMAT_DEFAULT);
        EXPECT_EQ(OK, status);
        if (status != OK) continue;
        deviceState = AudioSystem::getDeviceConnectionState(type, address);
        EXPECT_EQ(AUDIO_POLICY_DEVICE_STATE_AVAILABLE, deviceState);
        status = AudioSystem::setDeviceConnectionState(AUDIO_POLICY_DEVICE_STATE_UNAVAILABLE,
                                                       aidlPort, AUDIO_FORMAT_DEFAULT);
        EXPECT_EQ(OK, status);
        deviceState = AudioSystem::getDeviceConnectionState(type, address);
        EXPECT_EQ(AUDIO_POLICY_DEVICE_STATE_UNAVAILABLE, deviceState);
    }
}

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    ::testing::UnitTest::GetInstance()->listeners().Append(new TestExecutionTracer());
    return RUN_ALL_TESTS();
}
