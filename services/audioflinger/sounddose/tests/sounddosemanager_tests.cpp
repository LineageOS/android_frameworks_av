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

// #define LOG_NDEBUG 0
#define LOG_TAG "SoundDoseManager_tests"

#include <SoundDoseManager.h>

#include <aidl/android/hardware/audio/core/sounddose/BnSoundDose.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <media/AidlConversionCppNdk.h>

namespace android {
namespace {

using aidl::android::hardware::audio::core::sounddose::BnSoundDose;
using aidl::android::media::audio::common::AudioDevice;
using aidl::android::media::audio::common::AudioDeviceAddress;

class HalSoundDoseMock : public BnSoundDose {
public:
    MOCK_METHOD(ndk::ScopedAStatus, getOutputRs2UpperBound, (float*), (override));
    MOCK_METHOD(ndk::ScopedAStatus, setOutputRs2UpperBound, (float), (override));
    MOCK_METHOD(ndk::ScopedAStatus, registerSoundDoseCallback,
                (const std::shared_ptr<ISoundDose::IHalSoundDoseCallback>&), (override));
};

class SoundDoseManagerTest : public ::testing::Test {
protected:
    void SetUp() override {
        mSoundDoseManager = sp<SoundDoseManager>::make();
        mHalSoundDose = ndk::SharedRefBase::make<HalSoundDoseMock>();

        ON_CALL(*mHalSoundDose.get(), setOutputRs2UpperBound)
            .WillByDefault([] (float rs2) {
                EXPECT_EQ(rs2, ISoundDose::DEFAULT_MAX_RS2);
                return ndk::ScopedAStatus::ok();
            });
    }

    sp<SoundDoseManager> mSoundDoseManager;
    std::shared_ptr<HalSoundDoseMock> mHalSoundDose;
};

TEST_F(SoundDoseManagerTest, GetProcessorForExistingStream) {
    sp<audio_utils::MelProcessor> processor1 =
        mSoundDoseManager->getOrCreateProcessorForDevice(/*deviceId=*/1,
            /*streamHandle=*/1,
            /*sampleRate*/44100,
            /*channelCount*/2,
            /*format*/AUDIO_FORMAT_PCM_FLOAT);
    sp<audio_utils::MelProcessor> processor2 =
        mSoundDoseManager->getOrCreateProcessorForDevice(/*deviceId=*/2,
            /*streamHandle=*/1,
            /*sampleRate*/44100,
            /*channelCount*/2,
            /*format*/AUDIO_FORMAT_PCM_FLOAT);

    EXPECT_EQ(processor1, processor2);
}

TEST_F(SoundDoseManagerTest, RemoveExistingStream) {
    sp<audio_utils::MelProcessor> processor1 =
        mSoundDoseManager->getOrCreateProcessorForDevice(/*deviceId=*/1,
            /*streamHandle=*/1,
            /*sampleRate*/44100,
            /*channelCount*/2,
            /*format*/AUDIO_FORMAT_PCM_FLOAT);

    mSoundDoseManager->removeStreamProcessor(1);
    sp<audio_utils::MelProcessor> processor2 =
        mSoundDoseManager->getOrCreateProcessorForDevice(/*deviceId=*/2,
            /*streamHandle=*/1,
            /*sampleRate*/44100,
            /*channelCount*/2,
            /*format*/AUDIO_FORMAT_PCM_FLOAT);

    EXPECT_NE(processor1, processor2);
}

TEST_F(SoundDoseManagerTest, NewMelValuesCacheNewRecord) {
    std::vector<float>mels{1, 1};

    mSoundDoseManager->onNewMelValues(mels, 0, mels.size(), /*deviceId=*/1);

    EXPECT_EQ(mSoundDoseManager->getCachedMelRecordsSize(), size_t{1});
}

TEST_F(SoundDoseManagerTest, InvalidHalInterfaceIsNotSet) {
    EXPECT_FALSE(mSoundDoseManager->setHalSoundDoseInterface(nullptr));
}

TEST_F(SoundDoseManagerTest, SetHalSoundDoseDisablesNewMelProcessorCallbacks) {
    EXPECT_CALL(*mHalSoundDose.get(), setOutputRs2UpperBound).Times(1);
    EXPECT_CALL(*mHalSoundDose.get(), registerSoundDoseCallback)
        .Times(1)
        .WillOnce([&] (const std::shared_ptr<ISoundDose::IHalSoundDoseCallback>& callback) {
            EXPECT_NE(nullptr, callback);
            return ndk::ScopedAStatus::ok();
        });

    EXPECT_TRUE(mSoundDoseManager->setHalSoundDoseInterface(mHalSoundDose));

    EXPECT_EQ(nullptr, mSoundDoseManager->getOrCreateProcessorForDevice(/*deviceId=*/2,
            /*streamHandle=*/1,
            /*sampleRate*/44100,
            /*channelCount*/2,
            /*format*/AUDIO_FORMAT_PCM_FLOAT));
}

TEST_F(SoundDoseManagerTest, SetHalSoundDoseRegistersHalCallbacks) {
    EXPECT_CALL(*mHalSoundDose.get(), setOutputRs2UpperBound).Times(1);
    EXPECT_CALL(*mHalSoundDose.get(), registerSoundDoseCallback)
        .Times(1)
        .WillOnce([&] (const std::shared_ptr<ISoundDose::IHalSoundDoseCallback>& callback) {
            EXPECT_NE(nullptr, callback);
            return ndk::ScopedAStatus::ok();
        });

    EXPECT_TRUE(mSoundDoseManager->setHalSoundDoseInterface(mHalSoundDose));
}

TEST_F(SoundDoseManagerTest, MomentaryExposureFromHalWithNoAddressIllegalArgument) {
    std::shared_ptr<ISoundDose::IHalSoundDoseCallback> halCallback;

    EXPECT_CALL(*mHalSoundDose.get(), setOutputRs2UpperBound).Times(1);
    EXPECT_CALL(*mHalSoundDose.get(), registerSoundDoseCallback)
       .Times(1)
       .WillOnce([&] (const std::shared_ptr<ISoundDose::IHalSoundDoseCallback>& callback) {
           halCallback = callback;
           return ndk::ScopedAStatus::ok();
       });

    EXPECT_TRUE(mSoundDoseManager->setHalSoundDoseInterface(mHalSoundDose));

    EXPECT_NE(nullptr, halCallback);
    AudioDevice audioDevice = {};
    audioDevice.address.set<AudioDeviceAddress::id>("test");
    auto status = halCallback->onMomentaryExposureWarning(
        /*in_currentDbA=*/101.f, audioDevice);
    EXPECT_FALSE(status.isOk());
}

TEST_F(SoundDoseManagerTest, MomentaryExposureFromHalAfterInternalSelectedReturnsException) {
    std::shared_ptr<ISoundDose::IHalSoundDoseCallback> halCallback;

    EXPECT_CALL(*mHalSoundDose.get(), setOutputRs2UpperBound).Times(1);
    EXPECT_CALL(*mHalSoundDose.get(), registerSoundDoseCallback)
       .Times(1)
       .WillOnce([&] (const std::shared_ptr<ISoundDose::IHalSoundDoseCallback>& callback) {
           halCallback = callback;
           return ndk::ScopedAStatus::ok();
       });

    EXPECT_TRUE(mSoundDoseManager->setHalSoundDoseInterface(mHalSoundDose));
    EXPECT_NE(nullptr, halCallback);
    EXPECT_FALSE(mSoundDoseManager->setHalSoundDoseInterface(nullptr));

    AudioDevice audioDevice = {};
    audioDevice.address.set<AudioDeviceAddress::id>("test");
    auto status = halCallback->onMomentaryExposureWarning(
        /*in_currentDbA=*/101.f, audioDevice);
    EXPECT_FALSE(status.isOk());
}

TEST_F(SoundDoseManagerTest, OnNewMelValuesFromHalWithNoAddressIllegalArgument) {
    std::shared_ptr<ISoundDose::IHalSoundDoseCallback> halCallback;

    EXPECT_CALL(*mHalSoundDose.get(), setOutputRs2UpperBound).Times(1);
    EXPECT_CALL(*mHalSoundDose.get(), registerSoundDoseCallback)
       .Times(1)
       .WillOnce([&] (const std::shared_ptr<ISoundDose::IHalSoundDoseCallback>& callback) {
           halCallback = callback;
           return ndk::ScopedAStatus::ok();
       });

    EXPECT_TRUE(mSoundDoseManager->setHalSoundDoseInterface(mHalSoundDose));

    EXPECT_NE(nullptr, halCallback);
    AudioDevice audioDevice = {};
    audioDevice.address.set<AudioDeviceAddress::id>("test");
    auto status = halCallback->onNewMelValues(/*in_melRecord=*/{}, audioDevice);
    EXPECT_FALSE(status.isOk());
}

TEST_F(SoundDoseManagerTest, GetIdReturnsMappedAddress) {
    const std::string address = "testAddress";
    const audio_port_handle_t deviceId = 2;
    const audio_devices_t deviceType = AUDIO_DEVICE_OUT_WIRED_HEADSET;
    const AudioDeviceTypeAddr adt{deviceType, address};
    auto audioDevice = aidl::android::legacy2aidl_audio_device_AudioDevice(
            deviceType, address.c_str());
    ASSERT_TRUE(audioDevice.ok());

    mSoundDoseManager->mapAddressToDeviceId(adt, deviceId);

    EXPECT_EQ(deviceId, mSoundDoseManager->getIdForAudioDevice(audioDevice.value()));
}

TEST_F(SoundDoseManagerTest, GetAfterClearIdReturnsNone) {
    const std::string address = "testAddress";
    const audio_devices_t deviceType = AUDIO_DEVICE_OUT_WIRED_HEADSET;
    const AudioDeviceTypeAddr adt{deviceType, address};
    const audio_port_handle_t deviceId = 2;
    auto audioDevice = aidl::android::legacy2aidl_audio_device_AudioDevice(
            deviceType, address.c_str());
    ASSERT_TRUE(audioDevice.ok());

    mSoundDoseManager->mapAddressToDeviceId(adt, deviceId);
    mSoundDoseManager->clearMapDeviceIdEntries(deviceId);

    EXPECT_EQ(AUDIO_PORT_HANDLE_NONE, mSoundDoseManager->getIdForAudioDevice(audioDevice.value()));
}

TEST_F(SoundDoseManagerTest, GetUnmappedIdReturnsHandleNone) {
    const std::string address = "testAddress";
    AudioDevice audioDevice;
    audioDevice.address.set<AudioDeviceAddress::id>(address);

    EXPECT_EQ(AUDIO_PORT_HANDLE_NONE, mSoundDoseManager->getIdForAudioDevice(audioDevice));
}

TEST_F(SoundDoseManagerTest, GetDefaultForceComputeCsdOnAllDevices) {
    EXPECT_FALSE(mSoundDoseManager->forceComputeCsdOnAllDevices());
}

TEST_F(SoundDoseManagerTest, GetDefaultForceUseFrameworkMel) {
    // TODO: for now dogfooding with internal MEL. Revert to false when using the HAL MELs
    EXPECT_TRUE(mSoundDoseManager->forceUseFrameworkMel());
}

}  // namespace
}  // namespace android
