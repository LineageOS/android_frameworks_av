/*
 * Copyright (C) 2019 The Android Open Source Project
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

#define LOG_TAG "audiofoundation_parcelable_test"

#include <gtest/gtest.h>

#include <binder/IServiceManager.h>
#include <binder/Parcelable.h>
#include <binder/ProcessState.h>
#include <media/AudioGain.h>
#include <media/AudioPort.h>
#include <media/AudioProfile.h>
#include <media/DeviceDescriptorBase.h>
#include <utils/Log.h>
#include <utils/String16.h>

namespace android {

static const audio_port_config TEST_AUDIO_PORT_CONFIG = {
        .id = 0,
        .role = AUDIO_PORT_ROLE_SINK,
        .type = AUDIO_PORT_TYPE_DEVICE,
        .config_mask = AUDIO_PORT_CONFIG_SAMPLE_RATE | AUDIO_PORT_CONFIG_CHANNEL_MASK |
                       AUDIO_PORT_CONFIG_FORMAT | AUDIO_PORT_CONFIG_GAIN,
        .sample_rate = 48000,
        .channel_mask = AUDIO_CHANNEL_OUT_STEREO,
        .format = AUDIO_FORMAT_PCM_16_BIT,
        .gain = {
                .index = 0,
                .mode = AUDIO_GAIN_MODE_JOINT,
                .channel_mask = AUDIO_CHANNEL_OUT_STEREO,
        }
};

class AudioPortConfigTestStub : public AudioPortConfig {
public:
    sp<AudioPort> getAudioPort() const override { return nullptr; }
};

AudioGains getAudioGainsForTest() {
    AudioGains audioGains;
    sp<AudioGain> audioGain = new AudioGain(0 /*index*/, false /*isInput*/);
    audioGain->setMode(AUDIO_GAIN_MODE_JOINT);
    audioGain->setChannelMask(AUDIO_CHANNEL_OUT_STEREO);
    audioGain->setMinValueInMb(-3200);
    audioGain->setMaxValueInMb(600);
    audioGain->setDefaultValueInMb(0);
    audioGain->setStepValueInMb(100);
    audioGain->setMinRampInMs(100);
    audioGain->setMaxRampInMs(500);
    audioGains.push_back(audioGain);
    return audioGains;
}

AudioProfileVector getAudioProfileVectorForTest() {
    AudioProfileVector audioProfiles;
    sp<AudioProfile> audioProfile = AudioProfile::createFullDynamic();
    audioProfile->setChannels({AUDIO_CHANNEL_OUT_MONO, AUDIO_CHANNEL_OUT_STEREO});
    audioProfile->setSampleRates({48000});
    audioProfiles.add(audioProfile);
    return audioProfiles;
}

TEST(AudioFoundationParcelableTest, ParcelingAudioProfile) {
    sp<AudioProfile> profile = getAudioProfileVectorForTest()[0];
    auto conv = legacy2aidl_AudioProfile(profile, false /*isInput*/);
    ASSERT_TRUE(conv.ok());
    auto convBack = aidl2legacy_AudioProfile(conv.value(), false /*isInput*/);
    ASSERT_TRUE(convBack.ok());
    ASSERT_TRUE(profile->equals(convBack.value()));
}

TEST(AudioFoundationParcelableTest, ParcelingAudioProfileVector) {
    AudioProfileVector profiles = getAudioProfileVectorForTest();
    auto conv = legacy2aidl_AudioProfileVector(profiles, false /*isInput*/);
    ASSERT_TRUE(conv.ok());
    auto convBack = aidl2legacy_AudioProfileVector(conv.value(), false /*isInput*/);
    ASSERT_TRUE(convBack.ok());
    ASSERT_TRUE(profiles.equals(convBack.value()));
}

TEST(AudioFoundationParcelableTest, ParcelingAudioGain) {
    sp<AudioGain> audioGain = getAudioGainsForTest()[0];
    auto conv = legacy2aidl_AudioGain(audioGain);
    ASSERT_TRUE(conv.ok());
    auto convBack = aidl2legacy_AudioGain(conv.value());
    ASSERT_TRUE(convBack.ok());
    ASSERT_TRUE(audioGain->equals(convBack.value()));
}

TEST(AudioFoundationParcelableTest, ParcelingAudioGains) {
    AudioGains audioGains = getAudioGainsForTest();
    auto conv = legacy2aidl_AudioGains(audioGains);
    ASSERT_TRUE(conv.ok());
    auto convBack = aidl2legacy_AudioGains(conv.value());
    ASSERT_TRUE(convBack.ok());
    ASSERT_TRUE(audioGains.equals(convBack.value()));
}

TEST(AudioFoundationParcelableTest, ParcelingAudioPort) {
    sp<AudioPort> audioPort = new AudioPort(
            "AudioPortName", AUDIO_PORT_TYPE_DEVICE, AUDIO_PORT_ROLE_SINK);
    audioPort->setGains(getAudioGainsForTest());
    audioPort->setAudioProfiles(getAudioProfileVectorForTest());

    media::AudioPortFw parcelable;
    ASSERT_EQ(NO_ERROR, audioPort->writeToParcelable(&parcelable));
    sp<AudioPort> audioPortFromParcel = new AudioPort(
            "", AUDIO_PORT_TYPE_NONE, AUDIO_PORT_ROLE_NONE);
    ASSERT_EQ(NO_ERROR, audioPortFromParcel->readFromParcelable(parcelable));
    ASSERT_TRUE(audioPortFromParcel->equals(audioPort));
}

TEST(AudioFoundationParcelableTest, ParcelingAudioPortConfig) {
    const bool isInput = false;
    Parcel data;
    sp<AudioPortConfig> audioPortConfig = new AudioPortConfigTestStub();
    audioPortConfig->applyAudioPortConfig(&TEST_AUDIO_PORT_CONFIG);
    media::audio::common::AudioPortConfig parcelable{};
    ASSERT_EQ(NO_ERROR, audioPortConfig->writeToParcelable(&parcelable, isInput));
    ASSERT_EQ(NO_ERROR, data.writeParcelable(parcelable));
    data.setDataPosition(0);
    media::audio::common::AudioPortConfig parcelableFromParcel{};
    ASSERT_EQ(NO_ERROR, data.readParcelable(&parcelableFromParcel));
    sp<AudioPortConfig> audioPortConfigFromParcel = new AudioPortConfigTestStub();
    ASSERT_EQ(NO_ERROR, audioPortConfigFromParcel->readFromParcelable(
                    parcelableFromParcel, isInput));
    ASSERT_TRUE(audioPortConfigFromParcel->equals(audioPortConfig, isInput));
}

TEST(AudioFoundationParcelableTest, ParcelingDeviceDescriptorBase) {
    sp<DeviceDescriptorBase> desc = new DeviceDescriptorBase(AUDIO_DEVICE_OUT_SPEAKER);
    desc->setGains(getAudioGainsForTest());
    desc->setAudioProfiles(getAudioProfileVectorForTest());
    desc->applyAudioPortConfig(&TEST_AUDIO_PORT_CONFIG);
    desc->setAddress("DeviceDescriptorBaseTestAddress");
    ASSERT_EQ(desc->setEncapsulationModes(1 << AUDIO_ENCAPSULATION_MODE_HANDLE), NO_ERROR);
    ASSERT_EQ(desc->setEncapsulationMetadataTypes(
            AUDIO_ENCAPSULATION_METADATA_TYPE_ALL_POSITION_BITS), NO_ERROR);

    media::AudioPortFw parcelable;
    ASSERT_EQ(NO_ERROR, desc->writeToParcelable(&parcelable));
    sp<DeviceDescriptorBase> descFromParcel = new DeviceDescriptorBase(AUDIO_DEVICE_NONE);
    ASSERT_EQ(NO_ERROR, descFromParcel->readFromParcelable(parcelable));
    ASSERT_TRUE(descFromParcel->equals(desc));
}

} // namespace android
