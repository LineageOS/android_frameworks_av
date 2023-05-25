/*
 * Copyright 2023 The Android Open Source Project
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

#include <memory>

#define LOG_TAG "CoreAudioHalAidlTest"
#include <gtest/gtest.h>

#include <DeviceHalAidl.h>
#include <aidl/android/hardware/audio/core/BnModule.h>
#include <utils/Log.h>

namespace {

class ModuleMock : public ::aidl::android::hardware::audio::core::BnModule {
  public:
    bool isScreenTurnedOn() const { return mIsScreenTurnedOn; }
    ScreenRotation getScreenRotation() const { return mScreenRotation; }

  private:
    ndk::ScopedAStatus setModuleDebug(
            const ::aidl::android::hardware::audio::core::ModuleDebug&) override {
        return ndk::ScopedAStatus::ok();
    }
    ndk::ScopedAStatus getTelephony(
            std::shared_ptr<::aidl::android::hardware::audio::core::ITelephony>*) override {
        return ndk::ScopedAStatus::ok();
    }
    ndk::ScopedAStatus getBluetooth(
            std::shared_ptr<::aidl::android::hardware::audio::core::IBluetooth>*) override {
        return ndk::ScopedAStatus::ok();
    }
    ndk::ScopedAStatus getBluetoothA2dp(
            std::shared_ptr<::aidl::android::hardware::audio::core::IBluetoothA2dp>*) override {
        return ndk::ScopedAStatus::ok();
    }
    ndk::ScopedAStatus getBluetoothLe(
            std::shared_ptr<::aidl::android::hardware::audio::core::IBluetoothLe>*) override {
        return ndk::ScopedAStatus::ok();
    }
    ndk::ScopedAStatus connectExternalDevice(
            const ::aidl::android::media::audio::common::AudioPort&,
            ::aidl::android::media::audio::common::AudioPort*) override {
        return ndk::ScopedAStatus::ok();
    }
    ndk::ScopedAStatus disconnectExternalDevice(int32_t) override {
        return ndk::ScopedAStatus::ok();
    }
    ndk::ScopedAStatus getAudioPatches(
            std::vector<::aidl::android::hardware::audio::core::AudioPatch>*) override {
        return ndk::ScopedAStatus::ok();
    }
    ndk::ScopedAStatus getAudioPort(int32_t,
                                    ::aidl::android::media::audio::common::AudioPort*) override {
        return ndk::ScopedAStatus::ok();
    }
    ndk::ScopedAStatus getAudioPortConfigs(
            std::vector<::aidl::android::media::audio::common::AudioPortConfig>*) override {
        return ndk::ScopedAStatus::ok();
    }
    ndk::ScopedAStatus getAudioPorts(
            std::vector<::aidl::android::media::audio::common::AudioPort>*) override {
        return ndk::ScopedAStatus::ok();
    }
    ndk::ScopedAStatus getAudioRoutes(
            std::vector<::aidl::android::hardware::audio::core::AudioRoute>*) override {
        return ndk::ScopedAStatus::ok();
    }
    ndk::ScopedAStatus getAudioRoutesForAudioPort(
            int32_t, std::vector<::aidl::android::hardware::audio::core::AudioRoute>*) override {
        return ndk::ScopedAStatus::ok();
    }
    ndk::ScopedAStatus openInputStream(const OpenInputStreamArguments&,
                                       OpenInputStreamReturn*) override {
        return ndk::ScopedAStatus::ok();
    }
    ndk::ScopedAStatus openOutputStream(const OpenOutputStreamArguments&,
                                        OpenOutputStreamReturn*) override {
        return ndk::ScopedAStatus::ok();
    }
    ndk::ScopedAStatus getSupportedPlaybackRateFactors(SupportedPlaybackRateFactors*) override {
        return ndk::ScopedAStatus::ok();
    }
    ndk::ScopedAStatus setAudioPatch(const ::aidl::android::hardware::audio::core::AudioPatch&,
                                     ::aidl::android::hardware::audio::core::AudioPatch*) override {
        return ndk::ScopedAStatus::ok();
    }
    ndk::ScopedAStatus setAudioPortConfig(
            const ::aidl::android::media::audio::common::AudioPortConfig&,
            ::aidl::android::media::audio::common::AudioPortConfig*, bool*) override {
        return ndk::ScopedAStatus::ok();
    }
    ndk::ScopedAStatus resetAudioPatch(int32_t) override { return ndk::ScopedAStatus::ok(); }
    ndk::ScopedAStatus resetAudioPortConfig(int32_t) override { return ndk::ScopedAStatus::ok(); }
    ndk::ScopedAStatus getMasterMute(bool*) override { return ndk::ScopedAStatus::ok(); }
    ndk::ScopedAStatus setMasterMute(bool) override { return ndk::ScopedAStatus::ok(); }
    ndk::ScopedAStatus getMasterVolume(float*) override { return ndk::ScopedAStatus::ok(); }
    ndk::ScopedAStatus setMasterVolume(float) override { return ndk::ScopedAStatus::ok(); }
    ndk::ScopedAStatus getMicMute(bool*) override { return ndk::ScopedAStatus::ok(); }
    ndk::ScopedAStatus setMicMute(bool) override { return ndk::ScopedAStatus::ok(); }
    ndk::ScopedAStatus getMicrophones(
            std::vector<::aidl::android::media::audio::common::MicrophoneInfo>*) override {
        return ndk::ScopedAStatus::ok();
    }
    ndk::ScopedAStatus updateAudioMode(::aidl::android::media::audio::common::AudioMode) override {
        return ndk::ScopedAStatus::ok();
    }
    ndk::ScopedAStatus updateScreenRotation(ScreenRotation in_rotation) override {
        mScreenRotation = in_rotation;
        return ndk::ScopedAStatus::ok();
    }
    ndk::ScopedAStatus updateScreenState(bool in_isTurnedOn) override {
        mIsScreenTurnedOn = in_isTurnedOn;
        return ndk::ScopedAStatus::ok();
    }
    ndk::ScopedAStatus getSoundDose(
            std::shared_ptr<::aidl::android::hardware::audio::core::sounddose::ISoundDose>*)
            override {
        return ndk::ScopedAStatus::ok();
    }
    ndk::ScopedAStatus generateHwAvSyncId(int32_t*) override { return ndk::ScopedAStatus::ok(); }
    ndk::ScopedAStatus getVendorParameters(
            const std::vector<std::string>&,
            std::vector<::aidl::android::hardware::audio::core::VendorParameter>*) override {
        return ndk::ScopedAStatus::ok();
    }
    ndk::ScopedAStatus setVendorParameters(
            const std::vector<::aidl::android::hardware::audio::core::VendorParameter>&,
            bool) override {
        return ndk::ScopedAStatus::ok();
    }
    ndk::ScopedAStatus addDeviceEffect(
            int32_t,
            const std::shared_ptr<::aidl::android::hardware::audio::effect::IEffect>&) override {
        return ndk::ScopedAStatus::ok();
    }
    ndk::ScopedAStatus removeDeviceEffect(
            int32_t,
            const std::shared_ptr<::aidl::android::hardware::audio::effect::IEffect>&) override {
        return ndk::ScopedAStatus::ok();
    }
    ndk::ScopedAStatus getMmapPolicyInfos(
            ::aidl::android::media::audio::common::AudioMMapPolicyType,
            std::vector<::aidl::android::media::audio::common::AudioMMapPolicyInfo>*) override {
        return ndk::ScopedAStatus::ok();
    }
    ndk::ScopedAStatus supportsVariableLatency(bool*) override { return ndk::ScopedAStatus::ok(); }
    ndk::ScopedAStatus getAAudioMixerBurstCount(int32_t*) override {
        return ndk::ScopedAStatus::ok();
    }
    ndk::ScopedAStatus getAAudioHardwareBurstMinUsec(int32_t*) override {
        return ndk::ScopedAStatus::ok();
    }

    bool mIsScreenTurnedOn = false;
    ScreenRotation mScreenRotation = ScreenRotation::DEG_0;
};

android::String8 createParameterString(const char* key, const char* value) {
    android::AudioParameter params;
    params.add(android::String8(key), android::String8(value));
    return params.toString();
}

android::String8 createParameterString(const char* key, int value) {
    android::AudioParameter params;
    params.addInt(android::String8(key), value);
    return params.toString();
}

template <typename>
struct mf_traits {};
template <class T, class U>
struct mf_traits<U T::*> {
    using member_type = U;
};

}  // namespace

// Provide value printers for types generated from AIDL
// They need to be in the same namespace as the types we intend to print
namespace aidl::android::hardware::audio::core {
template <typename P>
std::enable_if_t<std::is_function_v<typename mf_traits<decltype(&P::toString)>::member_type>,
                 std::ostream&>
operator<<(std::ostream& os, const P& p) {
    return os << p.toString();
}
template <typename E>
std::enable_if_t<std::is_enum_v<E>, std::ostream&> operator<<(std::ostream& os, const E& e) {
    return os << toString(e);
}
}  // namespace aidl::android::hardware::audio::core

using namespace android;

class DeviceHalAidlTest : public testing::Test {
  public:
    void SetUp() override {
        mModule = ndk::SharedRefBase::make<ModuleMock>();
        mDevice = sp<DeviceHalAidl>::make("test", mModule);
    }
    void TearDown() override {
        mDevice.clear();
        mModule.reset();
    }

  protected:
    std::shared_ptr<ModuleMock> mModule;
    sp<DeviceHalAidl> mDevice;
};

TEST_F(DeviceHalAidlTest, ScreenState) {
    EXPECT_FALSE(mModule->isScreenTurnedOn());
    EXPECT_EQ(OK, mDevice->setParameters(createParameterString(AudioParameter::keyScreenState,
                                                               AudioParameter::valueOn)));
    EXPECT_TRUE(mModule->isScreenTurnedOn());
    EXPECT_EQ(OK, mDevice->setParameters(createParameterString(AudioParameter::keyScreenState,
                                                               AudioParameter::valueOff)));
    EXPECT_FALSE(mModule->isScreenTurnedOn());
    // The adaptation layer only logs a warning.
    EXPECT_EQ(OK, mDevice->setParameters(
                          createParameterString(AudioParameter::keyScreenState, "blah")));
    EXPECT_FALSE(mModule->isScreenTurnedOn());
}

TEST_F(DeviceHalAidlTest, ScreenRotation) {
    using ScreenRotation = ::aidl::android::hardware::audio::core::IModule::ScreenRotation;
    EXPECT_EQ(ScreenRotation::DEG_0, mModule->getScreenRotation());
    EXPECT_EQ(OK,
              mDevice->setParameters(createParameterString(AudioParameter::keyScreenRotation, 90)));
    EXPECT_EQ(ScreenRotation::DEG_90, mModule->getScreenRotation());
    EXPECT_EQ(OK,
              mDevice->setParameters(createParameterString(AudioParameter::keyScreenRotation, 0)));
    EXPECT_EQ(ScreenRotation::DEG_0, mModule->getScreenRotation());
    // The adaptation layer only logs a warning.
    EXPECT_EQ(OK,
              mDevice->setParameters(createParameterString(AudioParameter::keyScreenRotation, 42)));
    EXPECT_EQ(ScreenRotation::DEG_0, mModule->getScreenRotation());
}
