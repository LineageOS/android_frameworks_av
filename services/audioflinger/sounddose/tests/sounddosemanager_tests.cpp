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

class MelReporterCallback : public IMelReporterCallback {
public:
    MOCK_METHOD(void, startMelComputationForDeviceId, (audio_port_handle_t), (override));
    MOCK_METHOD(void, stopMelComputationForDeviceId, (audio_port_handle_t), (override));
};

constexpr char kPrimaryModule[] = "primary";
constexpr char kSecondaryModule[] = "secondary";

class SoundDoseManagerTest : public ::testing::Test {
protected:
    void SetUp() override {
        mMelReporterCallback = sp<MelReporterCallback>::make();
        mSoundDoseManager = sp<SoundDoseManager>::make(mMelReporterCallback);
        mHalSoundDose = ndk::SharedRefBase::make<HalSoundDoseMock>();
        mSecondaryHalSoundDose = ndk::SharedRefBase::make<HalSoundDoseMock>();

        ON_CALL(*mHalSoundDose.get(), setOutputRs2UpperBound)
            .WillByDefault([] (float rs2) {
                EXPECT_EQ(rs2, ISoundDose::DEFAULT_MAX_RS2);
                return ndk::ScopedAStatus::ok();
            });
        ON_CALL(*mSecondaryHalSoundDose.get(), setOutputRs2UpperBound)
                .WillByDefault([] (float rs2) {
                    EXPECT_EQ(rs2, ISoundDose::DEFAULT_MAX_RS2);
                    return ndk::ScopedAStatus::ok();
                });
    }

    sp<MelReporterCallback> mMelReporterCallback;
    sp<SoundDoseManager> mSoundDoseManager;
    std::shared_ptr<HalSoundDoseMock> mHalSoundDose;
    std::shared_ptr<HalSoundDoseMock> mSecondaryHalSoundDose;
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
    EXPECT_FALSE(mSoundDoseManager->setHalSoundDoseInterface(kPrimaryModule, nullptr));
}

TEST_F(SoundDoseManagerTest, SetHalSoundDoseDisablesNewMelProcessorCallbacks) {
    EXPECT_CALL(*mHalSoundDose.get(), setOutputRs2UpperBound).Times(1);
    EXPECT_CALL(*mHalSoundDose.get(), registerSoundDoseCallback)
        .Times(1)
        .WillOnce([&] (const std::shared_ptr<ISoundDose::IHalSoundDoseCallback>& callback) {
            EXPECT_NE(nullptr, callback);
            return ndk::ScopedAStatus::ok();
        });

    EXPECT_TRUE(mSoundDoseManager->setHalSoundDoseInterface(kPrimaryModule, mHalSoundDose));

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
    EXPECT_CALL(*mSecondaryHalSoundDose.get(), setOutputRs2UpperBound).Times(1);
    EXPECT_CALL(*mSecondaryHalSoundDose.get(), registerSoundDoseCallback)
            .Times(1)
            .WillOnce([&] (const std::shared_ptr<ISoundDose::IHalSoundDoseCallback>& callback) {
                EXPECT_NE(nullptr, callback);
                return ndk::ScopedAStatus::ok();
        });

    EXPECT_TRUE(mSoundDoseManager->setHalSoundDoseInterface(kPrimaryModule, mHalSoundDose));
    EXPECT_TRUE(mSoundDoseManager->setHalSoundDoseInterface(kSecondaryModule,
                                                            mSecondaryHalSoundDose));
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

    EXPECT_TRUE(mSoundDoseManager->setHalSoundDoseInterface(kPrimaryModule, mHalSoundDose));

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

    EXPECT_TRUE(mSoundDoseManager->setHalSoundDoseInterface(kPrimaryModule, mHalSoundDose));
    EXPECT_NE(nullptr, halCallback);
    mSoundDoseManager->resetHalSoundDoseInterfaces();

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

    EXPECT_TRUE(mSoundDoseManager->setHalSoundDoseInterface(kPrimaryModule, mHalSoundDose));

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
    EXPECT_FALSE(mSoundDoseManager->forceUseFrameworkMel());
}

TEST_F(SoundDoseManagerTest, SetAudioDeviceCategoryStopsNonHeadphone) {
    media::ISoundDose::AudioDeviceCategory device1;
    device1.address = "dev1";
    device1.csdCompatible = false;
    device1.internalAudioType = AUDIO_DEVICE_OUT_BLUETOOTH_A2DP;
    const AudioDeviceTypeAddr dev1Adt{AUDIO_DEVICE_OUT_BLUETOOTH_A2DP, device1.address};

    // this will mark the device as active
    mSoundDoseManager->mapAddressToDeviceId(dev1Adt, /*deviceId=*/1);
    EXPECT_CALL(*mMelReporterCallback.get(), stopMelComputationForDeviceId).Times(1);

    mSoundDoseManager->setAudioDeviceCategory(device1);
}

TEST_F(SoundDoseManagerTest, SetAudioDeviceCategoryStartsHeadphone) {
    media::ISoundDose::AudioDeviceCategory device1;
    device1.address = "dev1";
    device1.csdCompatible = true;
    device1.internalAudioType = AUDIO_DEVICE_OUT_BLUETOOTH_A2DP;
    const AudioDeviceTypeAddr dev1Adt{AUDIO_DEVICE_OUT_BLUETOOTH_A2DP, device1.address};

        // this will mark the device as active
    mSoundDoseManager->mapAddressToDeviceId(dev1Adt, /*deviceId=*/1);
    EXPECT_CALL(*mMelReporterCallback.get(), startMelComputationForDeviceId).Times(1);

    mSoundDoseManager->setAudioDeviceCategory(device1);
}

TEST_F(SoundDoseManagerTest, InitCachedAudioDevicesStartsOnlyActiveDevices) {
    media::ISoundDose::AudioDeviceCategory device1;
    media::ISoundDose::AudioDeviceCategory device2;
    device1.address = "dev1";
    device1.csdCompatible = true;
    device1.internalAudioType = AUDIO_DEVICE_OUT_BLUETOOTH_A2DP;
    device2.address = "dev2";
    device2.csdCompatible = true;
    device2.internalAudioType = AUDIO_DEVICE_OUT_BLUETOOTH_A2DP;
    const AudioDeviceTypeAddr dev1Adt{AUDIO_DEVICE_OUT_BLUETOOTH_A2DP, device1.address};
    std::vector<media::ISoundDose::AudioDeviceCategory> btDevices = {device1, device2};

    // this will mark the device as active
    mSoundDoseManager->mapAddressToDeviceId(dev1Adt, /*deviceId=*/1);
    EXPECT_CALL(*mMelReporterCallback.get(), startMelComputationForDeviceId).Times(1);

    mSoundDoseManager->initCachedAudioDeviceCategories(btDevices);
}


}  // namespace
}  // namespace android
