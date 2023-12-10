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
#include <string>
#include <vector>

#define LOG_TAG "CoreAudioHalAidlTest"
#include <gtest/gtest.h>

#include <DeviceHalAidl.h>
#include <StreamHalAidl.h>
#include <aidl/android/hardware/audio/core/BnModule.h>
#include <aidl/android/hardware/audio/core/BnStreamCommon.h>
#include <aidl/android/media/audio/BnHalAdapterVendorExtension.h>
#include <aidl/android/media/audio/common/Int.h>
#include <utils/Log.h>

namespace {

using ::aidl::android::hardware::audio::core::VendorParameter;

class VendorParameterMock {
  public:
    const std::vector<std::string>& getRetrievedParameterIds() const { return mGetParameterIds; }
    const std::vector<VendorParameter>& getAsyncParameters() const { return mAsyncParameters; }
    const std::vector<VendorParameter>& getSyncParameters() const { return mSyncParameters; }

  protected:
    ndk::ScopedAStatus getVendorParametersImpl(const std::vector<std::string>& in_parameterIds) {
        mGetParameterIds.insert(mGetParameterIds.end(), in_parameterIds.begin(),
                                in_parameterIds.end());
        return ndk::ScopedAStatus::ok();
    }
    ndk::ScopedAStatus setVendorParametersImpl(const std::vector<VendorParameter>& in_parameters,
                                               bool async) {
        if (async) {
            mAsyncParameters.insert(mAsyncParameters.end(), in_parameters.begin(),
                                    in_parameters.end());
        } else {
            mSyncParameters.insert(mSyncParameters.end(), in_parameters.begin(),
                                   in_parameters.end());
        }
        return ndk::ScopedAStatus::ok();
    }

  private:
    std::vector<std::string> mGetParameterIds;
    std::vector<VendorParameter> mAsyncParameters;
    std::vector<VendorParameter> mSyncParameters;
};

class ModuleMock : public ::aidl::android::hardware::audio::core::BnModule,
                   public VendorParameterMock {
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
    ndk::ScopedAStatus getVendorParameters(const std::vector<std::string>& in_parameterIds,
                                           std::vector<VendorParameter>*) override {
        return getVendorParametersImpl(in_parameterIds);
    }
    ndk::ScopedAStatus setVendorParameters(const std::vector<VendorParameter>& in_parameters,
                                           bool async) override {
        return setVendorParametersImpl(in_parameters, async);
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

class StreamCommonMock : public ::aidl::android::hardware::audio::core::BnStreamCommon,
                         public VendorParameterMock {
    ndk::ScopedAStatus close() override { return ndk::ScopedAStatus::ok(); }
    ndk::ScopedAStatus prepareToClose() override { return ndk::ScopedAStatus::ok(); }
    ndk::ScopedAStatus updateHwAvSyncId(int32_t) override { return ndk::ScopedAStatus::ok(); }
    ndk::ScopedAStatus getVendorParameters(const std::vector<std::string>& in_parameterIds,
                                           std::vector<VendorParameter>*) override {
        return getVendorParametersImpl(in_parameterIds);
    }
    ndk::ScopedAStatus setVendorParameters(const std::vector<VendorParameter>& in_parameters,
                                           bool async) override {
        return setVendorParametersImpl(in_parameters, async);
    }
    ndk::ScopedAStatus addEffect(
            const std::shared_ptr<::aidl::android::hardware::audio::effect::IEffect>&) override {
        return ndk::ScopedAStatus::ok();
    }
    ndk::ScopedAStatus removeEffect(
            const std::shared_ptr<::aidl::android::hardware::audio::effect::IEffect>&) override {
        return ndk::ScopedAStatus::ok();
    }
};

VendorParameter makeVendorParameter(const std::string& id, int value) {
    VendorParameter result{.id = id};
    // Note: in real life, a parcelable type defined by vendor must be used,
    // here we use Int just for test purposes.
    ::aidl::android::media::audio::common::Int vendorValue{.value = value};
    result.ext.setParcelable(std::move(vendorValue));
    return result;
}

android::status_t parseVendorParameter(const VendorParameter& param, int* value) {
    std::optional<::aidl::android::media::audio::common::Int> vendorValue;
    RETURN_STATUS_IF_ERROR(param.ext.getParcelable(&vendorValue));
    if (!vendorValue.has_value()) return android::BAD_VALUE;
    *value = vendorValue.value().value;
    return android::OK;
}

class TestHalAdapterVendorExtension
    : public ::aidl::android::media::audio::BnHalAdapterVendorExtension {
  public:
    static const std::string kLegacyParameterKey;
    static const std::string kLegacyAsyncParameterKey;
    static const std::string kModuleVendorParameterId;
    static const std::string kStreamVendorParameterId;

  private:
    ndk::ScopedAStatus parseVendorParameterIds(ParameterScope in_scope,
                                               const std::string& in_rawKeys,
                                               std::vector<std::string>* _aidl_return) override {
        android::AudioParameter keys(android::String8(in_rawKeys.c_str()));
        for (size_t i = 0; i < keys.size(); ++i) {
            android::String8 key;
            if (android::status_t status = keys.getAt(i, key); status != android::OK) {
                return ndk::ScopedAStatus::fromExceptionCode(EX_ILLEGAL_ARGUMENT);
            }
            switch (in_scope) {
                case ParameterScope::MODULE:
                    if (key == android::String8(kLegacyParameterKey.c_str()) ||
                        key == android::String8(kLegacyAsyncParameterKey.c_str())) {
                        _aidl_return->push_back(kModuleVendorParameterId);
                    } else {
                        return ndk::ScopedAStatus::fromExceptionCode(EX_ILLEGAL_ARGUMENT);
                    }
                    break;
                case ParameterScope::STREAM:
                    if (key == android::String8(kLegacyParameterKey.c_str()) ||
                        key == android::String8(kLegacyAsyncParameterKey.c_str())) {
                        _aidl_return->push_back(kStreamVendorParameterId);
                    } else {
                        return ndk::ScopedAStatus::fromExceptionCode(EX_ILLEGAL_ARGUMENT);
                    }
                    break;
            }
        }
        return ndk::ScopedAStatus::ok();
    }
    ndk::ScopedAStatus parseVendorParameters(
            ParameterScope in_scope, const std::string& in_rawKeysAndValues,
            std::vector<VendorParameter>* out_syncParameters,
            std::vector<VendorParameter>* out_asyncParameters) override {
        android::AudioParameter legacy(android::String8(in_rawKeysAndValues.c_str()));
        for (size_t i = 0; i < legacy.size(); ++i) {
            android::String8 key;
            if (android::status_t status = legacy.getAt(i, key); status != android::OK) {
                return ndk::ScopedAStatus::fromExceptionCode(EX_ILLEGAL_ARGUMENT);
            }
            int value;
            if (android::status_t status = legacy.getInt(key, value); status != android::OK) {
                return ndk::ScopedAStatus::fromExceptionCode(EX_ILLEGAL_ARGUMENT);
            }
            std::string parameterId;
            switch (in_scope) {
                case ParameterScope::MODULE:
                    parameterId = kModuleVendorParameterId;
                    break;
                case ParameterScope::STREAM:
                    parameterId = kStreamVendorParameterId;
                    break;
            }
            if (key == android::String8(kLegacyParameterKey.c_str())) {
                out_syncParameters->push_back(makeVendorParameter(parameterId, value));
            } else if (key == android::String8(kLegacyAsyncParameterKey.c_str())) {
                out_asyncParameters->push_back(makeVendorParameter(parameterId, value));
            } else {
                return ndk::ScopedAStatus::fromExceptionCode(EX_ILLEGAL_ARGUMENT);
            }
        }
        return ndk::ScopedAStatus::ok();
    }
    ndk::ScopedAStatus parseBluetoothA2dpReconfigureOffload(
            const std::string&, std::vector<VendorParameter>*) override {
        return ndk::ScopedAStatus::ok();
    }
    ndk::ScopedAStatus parseBluetoothLeReconfigureOffload(const std::string&,
                                                          std::vector<VendorParameter>*) override {
        return ndk::ScopedAStatus::ok();
    }
    ndk::ScopedAStatus processVendorParameters(ParameterScope in_scope,
                                               const std::vector<VendorParameter>& in_parameters,
                                               std::string* _aidl_return) override {
        android::AudioParameter legacy;
        for (const auto& vendorParam : in_parameters) {
            if ((in_scope == ParameterScope::MODULE &&
                 vendorParam.id == kModuleVendorParameterId) ||
                (in_scope == ParameterScope::STREAM &&
                 vendorParam.id == kStreamVendorParameterId)) {
                int value;
                if (android::status_t status = parseVendorParameter(vendorParam, &value);
                    status != android::OK) {
                    return ndk::ScopedAStatus::fromExceptionCode(EX_ILLEGAL_ARGUMENT);
                }
                legacy.addInt(android::String8(kLegacyParameterKey.c_str()), value);
            }
        }
        *_aidl_return = legacy.toString().c_str();
        return ndk::ScopedAStatus::ok();
    }
};

const std::string TestHalAdapterVendorExtension::kLegacyParameterKey = "aosp_test_param";
const std::string TestHalAdapterVendorExtension::kLegacyAsyncParameterKey = "aosp_test_param_async";
// Note: in real life, there is no need to explicitly separate "module" and "stream"
// parameters, here it's done just for test purposes.
const std::string TestHalAdapterVendorExtension::kModuleVendorParameterId =
        "aosp.test.module.parameter";
const std::string TestHalAdapterVendorExtension::kStreamVendorParameterId =
        "aosp.test.stream.parameter";

android::String8 createParameterString(const std::string& key, const std::string& value) {
    android::AudioParameter params;
    params.add(android::String8(key.c_str()), android::String8(value.c_str()));
    return params.toString();
}

android::String8 createParameterString(const std::string& key, int value) {
    android::AudioParameter params;
    params.addInt(android::String8(key.c_str()), value);
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
        mDevice = sp<DeviceHalAidl>::make("test", mModule, nullptr /*vext*/);
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

// Without a vendor extension, any unrecognized parameters must be ignored.
TEST_F(DeviceHalAidlTest, VendorParameterIgnored) {
    EXPECT_EQ(0UL, mModule->getAsyncParameters().size());
    EXPECT_EQ(0UL, mModule->getSyncParameters().size());
    EXPECT_EQ(OK, mDevice->setParameters(createParameterString("random_name", "random_value")));
    EXPECT_EQ(0UL, mModule->getAsyncParameters().size());
    EXPECT_EQ(0UL, mModule->getSyncParameters().size());

    EXPECT_EQ(0UL, mModule->getRetrievedParameterIds().size());
    String8 values;
    EXPECT_EQ(OK, mDevice->getParameters(String8("random_name"), &values));
    EXPECT_EQ(0UL, mModule->getRetrievedParameterIds().size());
    EXPECT_TRUE(values.empty());
}

class DeviceHalAidlVendorParametersTest : public testing::Test {
  public:
    void SetUp() override {
        mModule = ndk::SharedRefBase::make<ModuleMock>();
        mVendorExt = ndk::SharedRefBase::make<TestHalAdapterVendorExtension>();
        mDevice = sp<DeviceHalAidl>::make("test", mModule, mVendorExt);
    }
    void TearDown() override {
        mDevice.clear();
        mVendorExt.reset();
        mModule.reset();
    }

  protected:
    std::shared_ptr<ModuleMock> mModule;
    std::shared_ptr<TestHalAdapterVendorExtension> mVendorExt;
    sp<DeviceHalAidl> mDevice;
};

TEST_F(DeviceHalAidlVendorParametersTest, GetVendorParameter) {
    EXPECT_EQ(0UL, mModule->getRetrievedParameterIds().size());
    String8 values;
    EXPECT_EQ(OK, mDevice->getParameters(
                          String8(TestHalAdapterVendorExtension::kLegacyParameterKey.c_str()),
                          &values));
    EXPECT_EQ(1UL, mModule->getRetrievedParameterIds().size());
    if (mModule->getRetrievedParameterIds().size() >= 1) {
        EXPECT_EQ(TestHalAdapterVendorExtension::kModuleVendorParameterId,
                  mModule->getRetrievedParameterIds()[0]);
    }
}

TEST_F(DeviceHalAidlVendorParametersTest, SetVendorParameter) {
    EXPECT_EQ(0UL, mModule->getAsyncParameters().size());
    EXPECT_EQ(0UL, mModule->getSyncParameters().size());
    EXPECT_EQ(OK, mDevice->setParameters(createParameterString(
                          TestHalAdapterVendorExtension::kLegacyParameterKey, 42)));
    EXPECT_EQ(0UL, mModule->getAsyncParameters().size());
    EXPECT_EQ(1UL, mModule->getSyncParameters().size());
    EXPECT_EQ(OK, mDevice->setParameters(createParameterString(
                          TestHalAdapterVendorExtension::kLegacyAsyncParameterKey, 43)));
    EXPECT_EQ(1UL, mModule->getAsyncParameters().size());
    EXPECT_EQ(1UL, mModule->getSyncParameters().size());
    if (mModule->getSyncParameters().size() >= 1) {
        EXPECT_EQ(TestHalAdapterVendorExtension::kModuleVendorParameterId,
                  mModule->getSyncParameters()[0].id);
        int value{};
        EXPECT_EQ(android::OK, parseVendorParameter(mModule->getSyncParameters()[0], &value));
        EXPECT_EQ(42, value);
    }
    if (mModule->getAsyncParameters().size() >= 1) {
        EXPECT_EQ(TestHalAdapterVendorExtension::kModuleVendorParameterId,
                  mModule->getAsyncParameters()[0].id);
        int value{};
        EXPECT_EQ(android::OK, parseVendorParameter(mModule->getAsyncParameters()[0], &value));
        EXPECT_EQ(43, value);
    }
}

TEST_F(DeviceHalAidlVendorParametersTest, SetInvalidVendorParameters) {
    android::AudioParameter legacy;
    legacy.addInt(android::String8(TestHalAdapterVendorExtension::kLegacyParameterKey.c_str()), 42);
    legacy.addInt(android::String8(TestHalAdapterVendorExtension::kLegacyAsyncParameterKey.c_str()),
                  43);
    legacy.addInt(android::String8("random_name"), 44);
    EXPECT_EQ(0UL, mModule->getAsyncParameters().size());
    EXPECT_EQ(0UL, mModule->getSyncParameters().size());
    // TestHalAdapterVendorExtension throws an error for unknown parameters.
    EXPECT_EQ(android::BAD_VALUE, mDevice->setParameters(legacy.toString()));
    EXPECT_EQ(0UL, mModule->getAsyncParameters().size());
    EXPECT_EQ(0UL, mModule->getSyncParameters().size());
}

class StreamHalAidlVendorParametersTest : public testing::Test {
  public:
    void SetUp() override {
        mStreamCommon = ndk::SharedRefBase::make<StreamCommonMock>();
        mVendorExt = ndk::SharedRefBase::make<TestHalAdapterVendorExtension>();
        struct audio_config config = AUDIO_CONFIG_INITIALIZER;
        ::aidl::android::hardware::audio::core::StreamDescriptor descriptor;
        mStream = sp<StreamHalAidl>::make("test", false /*isInput*/, config, 0 /*nominalLatency*/,
                                          StreamContextAidl(descriptor, false /*isAsynchronous*/),
                                          mStreamCommon, mVendorExt);
    }
    void TearDown() override {
        mStream.clear();
        mVendorExt.reset();
        mStreamCommon.reset();
    }

  protected:
    std::shared_ptr<StreamCommonMock> mStreamCommon;
    std::shared_ptr<TestHalAdapterVendorExtension> mVendorExt;
    sp<StreamHalAidl> mStream;
};

TEST_F(StreamHalAidlVendorParametersTest, GetVendorParameter) {
    EXPECT_EQ(0UL, mStreamCommon->getRetrievedParameterIds().size());
    String8 values;
    EXPECT_EQ(OK, mStream->getParameters(
                          String8(TestHalAdapterVendorExtension::kLegacyParameterKey.c_str()),
                          &values));
    EXPECT_EQ(1UL, mStreamCommon->getRetrievedParameterIds().size());
    if (mStreamCommon->getRetrievedParameterIds().size() >= 1) {
        EXPECT_EQ(TestHalAdapterVendorExtension::kStreamVendorParameterId,
                  mStreamCommon->getRetrievedParameterIds()[0]);
    }
}

TEST_F(StreamHalAidlVendorParametersTest, SetVendorParameter) {
    EXPECT_EQ(0UL, mStreamCommon->getAsyncParameters().size());
    EXPECT_EQ(0UL, mStreamCommon->getSyncParameters().size());
    EXPECT_EQ(OK, mStream->setParameters(createParameterString(
                          TestHalAdapterVendorExtension::kLegacyParameterKey, 42)));
    EXPECT_EQ(0UL, mStreamCommon->getAsyncParameters().size());
    EXPECT_EQ(1UL, mStreamCommon->getSyncParameters().size());
    EXPECT_EQ(OK, mStream->setParameters(createParameterString(
                          TestHalAdapterVendorExtension::kLegacyAsyncParameterKey, 43)));
    EXPECT_EQ(1UL, mStreamCommon->getAsyncParameters().size());
    EXPECT_EQ(1UL, mStreamCommon->getSyncParameters().size());
    if (mStreamCommon->getSyncParameters().size() >= 1) {
        EXPECT_EQ(TestHalAdapterVendorExtension::kStreamVendorParameterId,
                  mStreamCommon->getSyncParameters()[0].id);
        int value{};
        EXPECT_EQ(android::OK, parseVendorParameter(mStreamCommon->getSyncParameters()[0], &value));
        EXPECT_EQ(42, value);
    }
    if (mStreamCommon->getAsyncParameters().size() >= 1) {
        EXPECT_EQ(TestHalAdapterVendorExtension::kStreamVendorParameterId,
                  mStreamCommon->getAsyncParameters()[0].id);
        int value{};
        EXPECT_EQ(android::OK,
                  parseVendorParameter(mStreamCommon->getAsyncParameters()[0], &value));
        EXPECT_EQ(43, value);
    }
}

TEST_F(StreamHalAidlVendorParametersTest, SetInvalidVendorParameters) {
    android::AudioParameter legacy;
    legacy.addInt(android::String8(TestHalAdapterVendorExtension::kLegacyParameterKey.c_str()), 42);
    legacy.addInt(android::String8(TestHalAdapterVendorExtension::kLegacyAsyncParameterKey.c_str()),
                  43);
    legacy.addInt(android::String8("random_name"), 44);
    EXPECT_EQ(0UL, mStreamCommon->getAsyncParameters().size());
    EXPECT_EQ(0UL, mStreamCommon->getSyncParameters().size());
    // TestHalAdapterVendorExtension throws an error for unknown parameters.
    EXPECT_EQ(android::BAD_VALUE, mStream->setParameters(legacy.toString()));
    EXPECT_EQ(0UL, mStreamCommon->getAsyncParameters().size());
    EXPECT_EQ(0UL, mStreamCommon->getSyncParameters().size());
}
