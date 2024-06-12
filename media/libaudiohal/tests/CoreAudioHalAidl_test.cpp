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

#include <algorithm>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

#define LOG_TAG "CoreAudioHalAidlTest"
#include <gtest/gtest.h>

#include <DeviceHalAidl.h>
#include <Hal2AidlMapper.h>
#include <StreamHalAidl.h>
#include <aidl/android/hardware/audio/core/BnModule.h>
#include <aidl/android/hardware/audio/core/BnStreamCommon.h>
#include <aidl/android/media/audio/BnHalAdapterVendorExtension.h>
#include <aidl/android/media/audio/common/AudioGainMode.h>
#include <aidl/android/media/audio/common/Int.h>
#include <utils/Log.h>

namespace {

using ::aidl::android::hardware::audio::core::AudioPatch;
using ::aidl::android::hardware::audio::core::AudioRoute;
using ::aidl::android::hardware::audio::core::VendorParameter;
using ::aidl::android::media::audio::common::AudioChannelLayout;
using ::aidl::android::media::audio::common::AudioConfig;
using ::aidl::android::media::audio::common::AudioDevice;
using ::aidl::android::media::audio::common::AudioDeviceDescription;
using ::aidl::android::media::audio::common::AudioDeviceType;
using ::aidl::android::media::audio::common::AudioFormatDescription;
using ::aidl::android::media::audio::common::AudioFormatType;
using ::aidl::android::media::audio::common::AudioGainConfig;
using ::aidl::android::media::audio::common::AudioGainMode;
using ::aidl::android::media::audio::common::AudioIoFlags;
using ::aidl::android::media::audio::common::AudioPort;
using ::aidl::android::media::audio::common::AudioPortConfig;
using ::aidl::android::media::audio::common::AudioPortDeviceExt;
using ::aidl::android::media::audio::common::AudioPortExt;
using ::aidl::android::media::audio::common::AudioPortMixExt;
using ::aidl::android::media::audio::common::AudioProfile;
using ::aidl::android::media::audio::common::AudioSource;
using ::aidl::android::media::audio::common::PcmType;

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

struct Configuration {
    std::vector<AudioPort> ports;
    std::vector<AudioPortConfig> portConfigs;
    std::vector<AudioRoute> routes;
    std::vector<AudioPatch> patches;
    int32_t nextPortId = 1;
    int32_t nextPatchId = 1;
};

void fillProfile(AudioProfile* profile, const std::vector<int32_t>& channelLayouts,
                 const std::vector<int32_t>& sampleRates) {
    for (auto layout : channelLayouts) {
        profile->channelMasks.push_back(
                AudioChannelLayout::make<AudioChannelLayout::layoutMask>(layout));
    }
    profile->sampleRates.insert(profile->sampleRates.end(), sampleRates.begin(), sampleRates.end());
}

AudioProfile createProfile(PcmType pcmType, const std::vector<int32_t>& channelLayouts,
                           const std::vector<int32_t>& sampleRates) {
    AudioProfile profile;
    profile.format.type = AudioFormatType::PCM;
    profile.format.pcm = pcmType;
    fillProfile(&profile, channelLayouts, sampleRates);
    return profile;
}

AudioPortExt createPortDeviceExt(AudioDeviceType devType, int32_t flags,
                                 std::string connection = "") {
    AudioPortDeviceExt deviceExt;
    deviceExt.device.type.type = devType;
    if (devType == AudioDeviceType::IN_MICROPHONE && connection.empty()) {
        deviceExt.device.address = "bottom";
    } else if (devType == AudioDeviceType::IN_MICROPHONE_BACK && connection.empty()) {
        deviceExt.device.address = "back";
    }
    deviceExt.device.type.connection = std::move(connection);
    deviceExt.flags = flags;
    return AudioPortExt::make<AudioPortExt::device>(deviceExt);
}

AudioPortExt createPortMixExt(int32_t maxOpenStreamCount, int32_t maxActiveStreamCount) {
    AudioPortMixExt mixExt;
    mixExt.maxOpenStreamCount = maxOpenStreamCount;
    mixExt.maxActiveStreamCount = maxActiveStreamCount;
    return AudioPortExt::make<AudioPortExt::mix>(mixExt);
}

AudioPort createPort(int32_t id, const std::string& name, int32_t flags, bool isInput,
                     const AudioPortExt& ext) {
    AudioPort port;
    port.id = id;
    port.name = name;
    port.flags = isInput ? AudioIoFlags::make<AudioIoFlags::input>(flags)
                         : AudioIoFlags::make<AudioIoFlags::output>(flags);
    port.ext = ext;
    return port;
}

AudioRoute createRoute(const std::vector<AudioPort>& sources, const AudioPort& sink) {
    AudioRoute route;
    route.sinkPortId = sink.id;
    std::transform(sources.begin(), sources.end(), std::back_inserter(route.sourcePortIds),
                   [](const auto& port) { return port.id; });
    return route;
}

template <typename T>
auto findById(std::vector<T>& v, int32_t id) {
    return std::find_if(v.begin(), v.end(), [&](const auto& e) { return e.id == id; });
}

Configuration getTestConfiguration() {
    const std::vector<AudioProfile> standardPcmAudioProfiles = {
            createProfile(PcmType::INT_16_BIT, {AudioChannelLayout::LAYOUT_STEREO}, {48000})};
    Configuration c;

    AudioPort micInDevice =
            createPort(c.nextPortId++, "Built-In Mic", 0, true,
                       createPortDeviceExt(AudioDeviceType::IN_MICROPHONE,
                                           1 << AudioPortDeviceExt::FLAG_INDEX_DEFAULT_DEVICE));
    micInDevice.profiles = standardPcmAudioProfiles;
    c.ports.push_back(micInDevice);

    AudioPort micInBackDevice =
            createPort(c.nextPortId++, "Built-In Back Mic", 0, true,
                       createPortDeviceExt(AudioDeviceType::IN_MICROPHONE_BACK, 0));
    micInDevice.profiles = standardPcmAudioProfiles;
    c.ports.push_back(micInBackDevice);

    AudioPort primaryInMix =
            createPort(c.nextPortId++, "primary input", 0, true, createPortMixExt(0, 1));
    primaryInMix.profiles = standardPcmAudioProfiles;
    c.ports.push_back(primaryInMix);

    AudioPort speakerOutDevice = createPort(c.nextPortId++, "Speaker", 0, false,
                                            createPortDeviceExt(AudioDeviceType::OUT_SPEAKER, 0));
    speakerOutDevice.profiles = standardPcmAudioProfiles;
    c.ports.push_back(speakerOutDevice);

    AudioPort btOutDevice =
            createPort(c.nextPortId++, "BT A2DP Out", 0, false,
                       createPortDeviceExt(AudioDeviceType::OUT_DEVICE, 0,
                                           AudioDeviceDescription::CONNECTION_BT_A2DP));
    btOutDevice.profiles = standardPcmAudioProfiles;
    c.ports.push_back(btOutDevice);

    AudioPort btOutMix =
            createPort(c.nextPortId++, "a2dp output", 0, false, createPortMixExt(1, 1));
    btOutMix.profiles = standardPcmAudioProfiles;
    c.ports.push_back(btOutMix);

    c.routes.push_back(createRoute({micInDevice, micInBackDevice}, primaryInMix));
    c.routes.push_back(createRoute({btOutMix}, btOutDevice));

    return c;
}

class ModuleMock : public ::aidl::android::hardware::audio::core::BnModule,
                   public VendorParameterMock {
  public:
    ModuleMock() = default;
    explicit ModuleMock(const Configuration& config) : mConfig(config) {}
    bool isScreenTurnedOn() const { return mIsScreenTurnedOn; }
    ScreenRotation getScreenRotation() const { return mScreenRotation; }
    std::vector<AudioPatch> getPatches() {
        std::vector<AudioPatch> result;
        getAudioPatches(&result);
        return result;
    }
    std::optional<AudioPortConfig> getPortConfig(int32_t id) {
        auto iter = findById<AudioPortConfig>(mConfig.portConfigs, id);
        if (iter != mConfig.portConfigs.end()) {
            return *iter;
        }
        return std::nullopt;
    }

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
            const ::aidl::android::media::audio::common::AudioPort& portIdAndData,
            ::aidl::android::media::audio::common::AudioPort* port) override {
        auto src = portIdAndData;  // Make a copy to mimic RPC behavior.
        auto iter = findById<AudioPort>(mConfig.ports, src.id);
        if (iter == mConfig.ports.end()) {
            return ndk::ScopedAStatus::fromExceptionCode(EX_ILLEGAL_ARGUMENT);
        }
        *port = *iter;
        port->ext = src.ext;
        port->id = mConfig.nextPortId++;
        ALOGD("%s: returning %s", __func__, port->toString().c_str());
        mConfig.ports.push_back(*port);
        std::vector<AudioRoute> newRoutes;
        for (auto& r : mConfig.routes) {
            if (r.sinkPortId == src.id) {
                newRoutes.push_back(AudioRoute{.sourcePortIds = r.sourcePortIds,
                                               .sinkPortId = port->id,
                                               .isExclusive = r.isExclusive});
            } else if (std::find(r.sourcePortIds.begin(), r.sourcePortIds.end(), src.id) !=
                       r.sourcePortIds.end()) {
                r.sourcePortIds.push_back(port->id);
            }
        }
        mConfig.routes.insert(mConfig.routes.end(), newRoutes.begin(), newRoutes.end());
        return ndk::ScopedAStatus::ok();
    }
    ndk::ScopedAStatus disconnectExternalDevice(int32_t portId) override {
        auto iter = findById<AudioPort>(mConfig.ports, portId);
        if (iter == mConfig.ports.end()) {
            return ndk::ScopedAStatus::fromExceptionCode(EX_ILLEGAL_ARGUMENT);
        }
        mConfig.ports.erase(iter);
        for (auto it = mConfig.routes.begin(); it != mConfig.routes.end();) {
            if (it->sinkPortId == portId) {
                it = mConfig.routes.erase(it);
            } else {
                if (auto srcIt =
                            std::find(it->sourcePortIds.begin(), it->sourcePortIds.end(), portId);
                    srcIt != it->sourcePortIds.end()) {
                    it->sourcePortIds.erase(srcIt);
                }
                ++it;
            }
        }
        return ndk::ScopedAStatus::ok();
    }
    ndk::ScopedAStatus getAudioPatches(
            std::vector<::aidl::android::hardware::audio::core::AudioPatch>* patches) override {
        *patches = mConfig.patches;
        return ndk::ScopedAStatus::ok();
    }
    ndk::ScopedAStatus getAudioPort(
            int32_t portId, ::aidl::android::media::audio::common::AudioPort* port) override {
        auto iter = findById<AudioPort>(mConfig.ports, portId);
        if (iter == mConfig.ports.end()) {
            return ndk::ScopedAStatus::fromExceptionCode(EX_ILLEGAL_ARGUMENT);
        }
        *port = *iter;
        return ndk::ScopedAStatus::ok();
    }
    ndk::ScopedAStatus getAudioPortConfigs(
            std::vector<::aidl::android::media::audio::common::AudioPortConfig>* configs) override {
        *configs = mConfig.portConfigs;
        return ndk::ScopedAStatus::ok();
    }
    ndk::ScopedAStatus getAudioPorts(
            std::vector<::aidl::android::media::audio::common::AudioPort>* ports) override {
        *ports = mConfig.ports;
        return ndk::ScopedAStatus::ok();
    }
    ndk::ScopedAStatus getAudioRoutes(
            std::vector<::aidl::android::hardware::audio::core::AudioRoute>* routes) override {
        *routes = mConfig.routes;
        return ndk::ScopedAStatus::ok();
    }
    ndk::ScopedAStatus getAudioRoutesForAudioPort(
            int32_t portId,
            std::vector<::aidl::android::hardware::audio::core::AudioRoute>* routes) override {
        for (auto& r : mConfig.routes) {
            const auto& srcs = r.sourcePortIds;
            if (r.sinkPortId == portId ||
                std::find(srcs.begin(), srcs.end(), portId) != srcs.end()) {
                routes->push_back(r);
            }
        }
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
    ndk::ScopedAStatus setAudioPatch(
            const ::aidl::android::hardware::audio::core::AudioPatch& requested,
            ::aidl::android::hardware::audio::core::AudioPatch* patch) override {
        if (requested.id == 0) {
            *patch = requested;
            patch->id = mConfig.nextPatchId++;
            mConfig.patches.push_back(*patch);
            ALOGD("%s: returning %s", __func__, patch->toString().c_str());
        } else {
            auto iter = findById<AudioPatch>(mConfig.patches, requested.id);
            if (iter == mConfig.patches.end()) {
                return ndk::ScopedAStatus::fromExceptionCode(EX_ILLEGAL_ARGUMENT);
            }
            *iter = *patch = requested;
            ALOGD("%s: updated %s", __func__, patch->toString().c_str());
        }
        return ndk::ScopedAStatus::ok();
    }
    ndk::ScopedAStatus setAudioPortConfig(
            const ::aidl::android::media::audio::common::AudioPortConfig& requested,
            ::aidl::android::media::audio::common::AudioPortConfig* config,
            bool* applied) override {
        *applied = false;
        auto src = requested;  // Make a copy to mimic RPC behavior.
        if (src.id == 0) {
            *config = src;
            if (config->ext.getTag() == AudioPortExt::unspecified) {
                auto iter = findById<AudioPort>(mConfig.ports, src.portId);
                if (iter == mConfig.ports.end()) {
                    return ndk::ScopedAStatus::fromExceptionCode(EX_ILLEGAL_ARGUMENT);
                }
                config->ext = iter->ext;
            }
            config->id = mConfig.nextPortId++;
            mConfig.portConfigs.push_back(*config);
            ALOGD("%s: returning %s", __func__, config->toString().c_str());
        } else {
            auto iter = findById<AudioPortConfig>(mConfig.portConfigs, src.id);
            if (iter == mConfig.portConfigs.end()) {
                return ndk::ScopedAStatus::fromExceptionCode(EX_ILLEGAL_ARGUMENT);
            }
            *iter = *config = src;
            ALOGD("%s: updated %s", __func__, config->toString().c_str());
        }
        *applied = true;
        return ndk::ScopedAStatus::ok();
    }
    ndk::ScopedAStatus resetAudioPatch(int32_t patchId) override {
        auto iter = findById<AudioPatch>(mConfig.patches, patchId);
        if (iter == mConfig.patches.end()) {
            return ndk::ScopedAStatus::fromExceptionCode(EX_ILLEGAL_ARGUMENT);
        }
        mConfig.patches.erase(iter);
        return ndk::ScopedAStatus::ok();
    }
    ndk::ScopedAStatus resetAudioPortConfig(int32_t portConfigId) override {
        auto iter = findById<AudioPortConfig>(mConfig.portConfigs, portConfigId);
        if (iter == mConfig.portConfigs.end()) {
            return ndk::ScopedAStatus::fromExceptionCode(EX_ILLEGAL_ARGUMENT);
        }
        mConfig.portConfigs.erase(iter);
        return ndk::ScopedAStatus::ok();
    }
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
    ndk::ScopedAStatus prepareToDisconnectExternalDevice(int32_t) override {
        return ndk::ScopedAStatus::ok();
    }

    Configuration mConfig;
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

namespace aidl::android::media::audio::common {
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
}  // namespace aidl::android::media::audio::common

using namespace android;

namespace {

class StreamHalMock : public virtual StreamHalInterface {
  public:
    StreamHalMock() = default;
    ~StreamHalMock() override = default;
    status_t getBufferSize(size_t*) override { return OK; }
    status_t getAudioProperties(audio_config_base_t*) override { return OK; }
    status_t setParameters(const String8&) override { return OK; }
    status_t getParameters(const String8&, String8*) override { return OK; }
    status_t getFrameSize(size_t*) override { return OK; }
    status_t addEffect(sp<EffectHalInterface>) override { return OK; }
    status_t removeEffect(sp<EffectHalInterface>) override { return OK; }
    status_t standby() override { return OK; }
    status_t dump(int, const Vector<String16>&) override { return OK; }
    status_t start() override { return OK; }
    status_t stop() override { return OK; }
    status_t createMmapBuffer(int32_t, struct audio_mmap_buffer_info*) override { return OK; }
    status_t getMmapPosition(struct audio_mmap_position*) override { return OK; }
    status_t setHalThreadPriority(int) override { return OK; }
    status_t legacyCreateAudioPatch(const struct audio_port_config&, std::optional<audio_source_t>,
                                    audio_devices_t) override {
        return OK;
    }
    status_t legacyReleaseAudioPatch() override { return OK; }
};

}  // namespace

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

class Hal2AidlMapperTest : public testing::Test {
  public:
    void SetUp() override {
        mModule = ndk::SharedRefBase::make<ModuleMock>(getTestConfiguration());
        mMapper = std::make_unique<Hal2AidlMapper>("test", mModule);
        ASSERT_EQ(OK, mMapper->initialize());

        mConnectedPort.ext = createPortDeviceExt(AudioDeviceType::OUT_DEVICE, 0,
                                                 AudioDeviceDescription::CONNECTION_BT_A2DP);
        mConnectedPort.ext.get<AudioPortExt::device>().device.address = "00:11:22:33:44:55";
        ASSERT_EQ(OK, mMapper->setDevicePortConnectedState(mConnectedPort, true /*connected*/));

        std::mutex mutex;  // Only needed for cleanups.
        auto mapperAccessor = std::make_unique<LockedAccessor<Hal2AidlMapper>>(*mMapper, mutex);
        Hal2AidlMapper::Cleanups cleanups(*mapperAccessor);
        AudioConfig config;
        config.base.channelMask = AudioChannelLayout::make<AudioChannelLayout::layoutMask>(
                AudioChannelLayout::LAYOUT_STEREO);
        config.base.format =
                AudioFormatDescription{.type = AudioFormatType::PCM, .pcm = PcmType::INT_16_BIT};
        config.base.sampleRate = 48000;
        ASSERT_EQ(OK,
                  mMapper->prepareToOpenStream(
                          42 /*ioHandle*/, mConnectedPort.ext.get<AudioPortExt::device>().device,
                          AudioIoFlags::make<AudioIoFlags::output>(0), AudioSource::DEFAULT,
                          &cleanups, &config, &mMixPortConfig, &mPatch));
        cleanups.disarmAll();
        ASSERT_NE(0, mPatch.id);
        ASSERT_NE(0, mMixPortConfig.id);
        mStream = sp<StreamHalMock>::make();
        mMapper->addStream(mStream, mMixPortConfig.id, mPatch.id);

        ASSERT_EQ(OK, mMapper->findPortConfig(mConnectedPort.ext.get<AudioPortExt::device>().device,
                                              &mDevicePortConfig));
        ASSERT_EQ(1UL, mPatch.sourcePortConfigIds.size());
        ASSERT_EQ(mMixPortConfig.id, mPatch.sourcePortConfigIds[0]);
        ASSERT_EQ(1UL, mPatch.sinkPortConfigIds.size());
        ASSERT_EQ(mDevicePortConfig.id, mPatch.sinkPortConfigIds[0]);
    }

    void TearDown() override {
        mStream.clear();
        mMapper.reset();
        mModule.reset();
    }

  protected:
    void CloseDisconnectImpl() {
        mStream.clear();
        ASSERT_NO_FATAL_FAILURE(DisconnectDevice());
    }

    void ConnectAnotherDevice() {
        mConnectedPort.ext.get<AudioPortExt::device>().device.address = "00:11:22:33:44:66";
        ASSERT_EQ(OK, mMapper->setDevicePortConnectedState(mConnectedPort, true /*connected*/));
    }

    void CreateFwkPatch(int32_t* patchId) {
        std::mutex mutex;  // Only needed for cleanups.
        auto mapperAccessor = std::make_unique<LockedAccessor<Hal2AidlMapper>>(*mMapper, mutex);
        Hal2AidlMapper::Cleanups cleanups(*mapperAccessor);
        ASSERT_EQ(OK, mMapper->createOrUpdatePatch({mMixPortConfig}, {mDevicePortConfig}, patchId,
                                                   &cleanups));
        cleanups.disarmAll();
    }

    void DisconnectDevice() {
        ASSERT_EQ(OK, mMapper->prepareToDisconnectExternalDevice(mConnectedPort));
        ASSERT_EQ(OK, mMapper->setDevicePortConnectedState(mConnectedPort, false /*connected*/));
    }

    void ReleaseFwkOnlyPatch(int32_t patchId) {
        // The patch only exists for the framework.
        EXPECT_EQ(patchId, mMapper->findFwkPatch(patchId));
        ASSERT_EQ(BAD_VALUE, mMapper->releaseAudioPatch(patchId));
        mMapper->eraseFwkPatch(patchId);
        // The patch is now erased.
        EXPECT_EQ(0, mMapper->findFwkPatch(patchId));
    }

    std::shared_ptr<ModuleMock> mModule;
    std::unique_ptr<Hal2AidlMapper> mMapper;
    AudioPort mConnectedPort;
    AudioPortConfig mMixPortConfig;
    AudioPortConfig mDevicePortConfig;
    AudioPatch mPatch;
    sp<StreamHalInterface> mStream;
};

/**
 * External device connections and patches tests diagram.
 *
 * [Connect device] -> [Create Stream]
 *                            |-> [ (1) Close Stream] -> [Disconnect Device]
 *                            |-> [ (2) Disconnect Device]
 *                            |          |-> [ (3) Close Stream]
 *                            |          \-> [ (4) Connect Another Device]
 *                            |                    |-> (1)
 *                            |                    |-> (2) -> (3)
 *                            |                    \-> (5) -> (7)
 *                            \-> [ (5) Create/Update Fwk Patch]
 *                                       |-> [(6) Release Fwk Patch]
 *                                       |        |-> (1)
 *                                       |        \-> (2) (including reconnection)
 *                                       \-> [(7) Disconnect Device]
 *                                                |-> [Release Fwk Patch] -> [Close Stream]
 *                                                \-> (4) -> (5) -> (6) -> (1)
 *
 * Note that the test (acting on behalf of DeviceHalAidl) is responsible
 * for calling `eraseFwkPatch` and `updateFwkPatch` when needed.
 */

// (1)
TEST_F(Hal2AidlMapperTest, CloseDisconnect) {
    ASSERT_NO_FATAL_FAILURE(CloseDisconnectImpl());
    // The patch is owned by HAL, must not be listed under fwkPatches after disconnection.
    EXPECT_EQ(0, mMapper->findFwkPatch(mPatch.id));
}

// (2) -> (3)
TEST_F(Hal2AidlMapperTest, DisconnectClose) {
    ASSERT_NO_FATAL_FAILURE(DisconnectDevice());
    // The patch is owned by HAL, must not be listed under fwkPatches after disconnection.
    EXPECT_EQ(0, mMapper->findFwkPatch(mPatch.id));
    mStream.clear();
}

// (2) -> (4) -> (1)
TEST_F(Hal2AidlMapperTest, DisconnectConnectCloseDisconnect) {
    ASSERT_NO_FATAL_FAILURE(DisconnectDevice());
    // The patch is owned by HAL, must not be listed under fwkPatches after disconnection.
    EXPECT_EQ(0, mMapper->findFwkPatch(mPatch.id));
    ASSERT_NO_FATAL_FAILURE(ConnectAnotherDevice());
    ASSERT_NO_FATAL_FAILURE(CloseDisconnectImpl());
    // The patch is owned by HAL, must not be listed under fwkPatches after disconnection.
    EXPECT_EQ(0, mMapper->findFwkPatch(mPatch.id));
}

// (2) -> (4) -> (2) -> (3)
TEST_F(Hal2AidlMapperTest, DisconnectConnectDisconnectClose) {
    ASSERT_NO_FATAL_FAILURE(DisconnectDevice());
    // The patch is owned by HAL, must not be listed under fwkPatches after disconnection.
    EXPECT_EQ(0, mMapper->findFwkPatch(mPatch.id));
    ASSERT_NO_FATAL_FAILURE(ConnectAnotherDevice());
    ASSERT_NO_FATAL_FAILURE(DisconnectDevice());
    // The patch is owned by HAL, must not be listed under fwkPatches after disconnection.
    EXPECT_EQ(0, mMapper->findFwkPatch(mPatch.id));
    mStream.clear();
}

// (5) -> (6) -> (1)
TEST_F(Hal2AidlMapperTest, CreateFwkPatchReleaseCloseDisconnect) {
    int32_t patchId;
    ASSERT_NO_FATAL_FAILURE(CreateFwkPatch(&patchId));
    // Must be the patch created during stream opening.
    ASSERT_EQ(mPatch.id, patchId);
    // The patch was not reset by HAL, must not be listed under fwkPatches.
    EXPECT_EQ(0, mMapper->findFwkPatch(mPatch.id));

    ASSERT_EQ(OK, mMapper->releaseAudioPatch(patchId));
    // The patch does not exist both for the fwk and the HAL, must not be listed under fwkPatches.
    EXPECT_EQ(0, mMapper->findFwkPatch(patchId));
    ASSERT_NO_FATAL_FAILURE(CloseDisconnectImpl());
    // The patch does not exist both for the fwk and the HAL, must not be listed under fwkPatches.
    EXPECT_EQ(0, mMapper->findFwkPatch(patchId));
}

// (5) -> (6) -> (2) -> (3)
TEST_F(Hal2AidlMapperTest, CreateFwkPatchReleaseDisconnectClose) {
    int32_t patchId;
    ASSERT_NO_FATAL_FAILURE(CreateFwkPatch(&patchId));
    // Must be the patch created during stream opening.
    ASSERT_EQ(mPatch.id, patchId);
    // The patch was not reset by HAL, must not be listed under fwkPatches.
    EXPECT_EQ(0, mMapper->findFwkPatch(mPatch.id));

    ASSERT_EQ(OK, mMapper->releaseAudioPatch(patchId));
    // The patch does not exist both for the fwk and the HAL, must not be listed under fwkPatches.
    EXPECT_EQ(0, mMapper->findFwkPatch(patchId));
    ASSERT_NO_FATAL_FAILURE(DisconnectDevice());
    // The patch does not exist both for the fwk and the HAL, must not be listed under fwkPatches.
    EXPECT_EQ(0, mMapper->findFwkPatch(mPatch.id));
    mStream.clear();
}

// (5) -> (6) -> (2) -> (4) -> (2) -> (3)
TEST_F(Hal2AidlMapperTest, CreateFwkPatchReleaseDisconnectConnectDisconnectClose) {
    int32_t patchId;
    ASSERT_NO_FATAL_FAILURE(CreateFwkPatch(&patchId));
    // Must be the patch created during stream opening.
    ASSERT_EQ(mPatch.id, patchId);
    // The patch was not reset by HAL, must not be listed under fwkPatches.
    EXPECT_EQ(0, mMapper->findFwkPatch(mPatch.id));

    ASSERT_EQ(OK, mMapper->releaseAudioPatch(patchId));
    // The patch does not exist both for the fwk and the HAL, must not be listed under fwkPatches.
    EXPECT_EQ(0, mMapper->findFwkPatch(patchId));
    ASSERT_NO_FATAL_FAILURE(DisconnectDevice());
    // The patch does not exist both for the fwk and the HAL, must not be listed under fwkPatches.
    EXPECT_EQ(0, mMapper->findFwkPatch(mPatch.id));

    ASSERT_NO_FATAL_FAILURE(ConnectAnotherDevice());
    ASSERT_NO_FATAL_FAILURE(DisconnectDevice());
    // The patch does not exist both for the fwk and the HAL, must not be listed under fwkPatches.
    EXPECT_EQ(0, mMapper->findFwkPatch(mPatch.id));
    mStream.clear();
}

// (5) -> (7) -> Release -> Close
TEST_F(Hal2AidlMapperTest, CreateFwkPatchDisconnectReleaseClose) {
    int32_t patchId;
    ASSERT_NO_FATAL_FAILURE(CreateFwkPatch(&patchId));
    // Must be the patch created during stream opening.
    ASSERT_EQ(mPatch.id, patchId);
    // The patch was not reset by HAL, must not be listed under fwkPatches.
    EXPECT_EQ(0, mMapper->findFwkPatch(mPatch.id));

    ASSERT_NO_FATAL_FAILURE(DisconnectDevice());
    ASSERT_NO_FATAL_FAILURE(ReleaseFwkOnlyPatch(patchId));

    mStream.clear();
    EXPECT_EQ(0, mMapper->findFwkPatch(patchId));
}

// (5) -> (7) -> (4) -> (5) -> (6) -> (1)
TEST_F(Hal2AidlMapperTest, CreateFwkPatchDisconnectConnectUpdateReleaseCloseDisconnect) {
    int32_t patchId;
    ASSERT_NO_FATAL_FAILURE(CreateFwkPatch(&patchId));
    // Must be the patch created during stream opening.
    ASSERT_EQ(mPatch.id, patchId);
    // The patch was not reset by HAL, must not be listed under fwkPatches.
    EXPECT_EQ(0, mMapper->findFwkPatch(mPatch.id));

    ASSERT_NO_FATAL_FAILURE(DisconnectDevice());
    // The patch now only exists for the framework.
    EXPECT_EQ(mPatch.id, mMapper->findFwkPatch(mPatch.id));

    ASSERT_NO_FATAL_FAILURE(ConnectAnotherDevice());
    // Change the device address locally, for patch update.
    mDevicePortConfig.ext.get<AudioPortExt::device>().device.address =
            mConnectedPort.ext.get<AudioPortExt::device>().device.address;
    int32_t newPatchId = patchId;
    ASSERT_NO_FATAL_FAILURE(CreateFwkPatch(&newPatchId));
    EXPECT_NE(patchId, newPatchId);
    mMapper->updateFwkPatch(patchId, newPatchId);
    EXPECT_EQ(newPatchId, mMapper->findFwkPatch(patchId));
    // Just in case, check that HAL patch ID is not listed as a fwk patch.
    EXPECT_EQ(0, mMapper->findFwkPatch(newPatchId));
    // Verify that device port config was updated.
    ASSERT_EQ(OK, mMapper->findPortConfig(mConnectedPort.ext.get<AudioPortExt::device>().device,
                                          &mDevicePortConfig));

    ASSERT_EQ(OK, mMapper->releaseAudioPatch(newPatchId));
    // The patch does not exist both for the fwk and the HAL, must not be listed under fwkPatches.
    EXPECT_EQ(0, mMapper->findFwkPatch(patchId));
    // Just in case, check that HAL patch ID is not listed.
    EXPECT_EQ(0, mMapper->findFwkPatch(newPatchId));

    ASSERT_NO_FATAL_FAILURE(CloseDisconnectImpl());
    EXPECT_EQ(0, mMapper->findFwkPatch(mPatch.id));
    EXPECT_EQ(0, mMapper->findFwkPatch(patchId));
    EXPECT_EQ(0, mMapper->findFwkPatch(newPatchId));
}

// (2) -> (4) -> (5) -> (7) -> Release -> Close
TEST_F(Hal2AidlMapperTest, DisconnectConnectCreateFwkPatchDisconnectReleaseClose) {
    const int32_t patchId = mPatch.id;
    ASSERT_NO_FATAL_FAILURE(DisconnectDevice());
    // The patch is owned by HAL, must not be listed under fwkPatches after disconnection.
    EXPECT_EQ(0, mMapper->findFwkPatch(mPatch.id));

    ASSERT_NO_FATAL_FAILURE(ConnectAnotherDevice());
    // Change the device address locally, for patch update.
    mDevicePortConfig.ext.get<AudioPortExt::device>().device.address =
            mConnectedPort.ext.get<AudioPortExt::device>().device.address;
    int32_t newPatchId = 0;  // Use 0 since the fwk does not know about the HAL patch.
    EXPECT_EQ(0, mMapper->findFwkPatch(newPatchId));
    ASSERT_NO_FATAL_FAILURE(CreateFwkPatch(&newPatchId));
    EXPECT_NE(0, newPatchId);
    EXPECT_NE(patchId, newPatchId);
    // Just in case, check that HAL patch ID is not listed as a fwk patch.
    EXPECT_EQ(0, mMapper->findFwkPatch(newPatchId));
    // Verify that device port config was updated.
    ASSERT_EQ(OK, mMapper->findPortConfig(mConnectedPort.ext.get<AudioPortExt::device>().device,
                                          &mDevicePortConfig));

    ASSERT_NO_FATAL_FAILURE(DisconnectDevice());
    ASSERT_NO_FATAL_FAILURE(ReleaseFwkOnlyPatch(newPatchId));

    mStream.clear();
    EXPECT_EQ(0, mMapper->findFwkPatch(mPatch.id));
    EXPECT_EQ(0, mMapper->findFwkPatch(newPatchId));
}

TEST_F(Hal2AidlMapperTest, ChangeTransientPatchDevice) {
    std::mutex mutex;  // Only needed for cleanups.
    auto mapperAccessor = std::make_unique<LockedAccessor<Hal2AidlMapper>>(*mMapper, mutex);
    Hal2AidlMapper::Cleanups cleanups(*mapperAccessor);
    AudioConfig config;
    config.base.channelMask = AudioChannelLayout::make<AudioChannelLayout::layoutMask>(
            AudioChannelLayout::LAYOUT_STEREO);
    config.base.format =
            AudioFormatDescription{.type = AudioFormatType::PCM, .pcm = PcmType::INT_16_BIT};
    config.base.sampleRate = 48000;
    AudioDevice defaultDevice;
    defaultDevice.type.type = AudioDeviceType::IN_DEFAULT;
    AudioPortConfig mixPortConfig;
    AudioPatch transientPatch;
    ASSERT_EQ(OK, mMapper->prepareToOpenStream(43 /*ioHandle*/, defaultDevice,
                                               AudioIoFlags::make<AudioIoFlags::input>(0),
                                               AudioSource::DEFAULT, &cleanups, &config,
                                               &mixPortConfig, &transientPatch));
    cleanups.disarmAll();
    ASSERT_NE(0, transientPatch.id);
    ASSERT_NE(0, mixPortConfig.id);
    sp<StreamHalInterface> stream = sp<StreamHalMock>::make();
    mMapper->addStream(stream, mixPortConfig.id, transientPatch.id);

    AudioPatch patch{};
    int32_t patchId;
    AudioPortConfig backMicPortConfig;
    backMicPortConfig.channelMask = config.base.channelMask;
    backMicPortConfig.format = config.base.format;
    backMicPortConfig.sampleRate = aidl::android::media::audio::common::Int{config.base.sampleRate};
    backMicPortConfig.flags = AudioIoFlags::make<AudioIoFlags::input>(0);
    backMicPortConfig.ext = createPortDeviceExt(AudioDeviceType::IN_MICROPHONE_BACK, 0);
    ASSERT_EQ(OK, mMapper->createOrUpdatePatch({backMicPortConfig}, {mixPortConfig}, &patchId,
                                               &cleanups));
    cleanups.disarmAll();
    ASSERT_EQ(android::OK,
              mMapper->findPortConfig(backMicPortConfig.ext.get<AudioPortExt::device>().device,
                                      &backMicPortConfig));
    EXPECT_NE(0, backMicPortConfig.id);

    EXPECT_EQ(transientPatch.id, patchId);
    auto patches = mModule->getPatches();
    auto patchIt = findById(patches, patchId);
    ASSERT_NE(patchIt, patches.end());
    EXPECT_EQ(std::vector<int32_t>{backMicPortConfig.id}, patchIt->sourcePortConfigIds);
    EXPECT_EQ(std::vector<int32_t>{mixPortConfig.id}, patchIt->sinkPortConfigIds);
}

TEST_F(Hal2AidlMapperTest, SetAudioPortConfigGainChangeExistingPortConfig) {
    // First set config, then update gain.
    AudioPortConfig speakerPortConfig;
    speakerPortConfig.ext = createPortDeviceExt(AudioDeviceType::OUT_SPEAKER, 0);
    speakerPortConfig.channelMask = AudioChannelLayout::make<AudioChannelLayout::layoutMask>(
            AudioChannelLayout::LAYOUT_STEREO);
    speakerPortConfig.format =
            AudioFormatDescription{.type = AudioFormatType::PCM, .pcm = PcmType::INT_16_BIT};
    speakerPortConfig.sampleRate = ::aidl::android::media::audio::common::Int(48000);
    AudioPortConfig resultingPortConfig;
    ASSERT_EQ(OK,
              mMapper->setPortConfig(speakerPortConfig, std::set<int32_t>(), &resultingPortConfig));
    EXPECT_NE(0, resultingPortConfig.id);
    EXPECT_NE(0, resultingPortConfig.portId);

    AudioPortConfig gainUpdate;
    gainUpdate.ext = createPortDeviceExt(AudioDeviceType::OUT_SPEAKER, 0);
    AudioGainConfig gainConfig{.index = -1,
                               .mode = 1 << static_cast<int>(AudioGainMode::JOINT),
                               .channelMask = AudioChannelLayout{},
                               .values = std::vector<int32_t>{-3200},
                               .rampDurationMs = 0};
    gainUpdate.gain = gainConfig;
    AudioPortConfig resultingGainUpdate;
    ASSERT_EQ(OK, mMapper->setPortConfig(gainUpdate, std::set<int32_t>(), &resultingGainUpdate));
    EXPECT_EQ(resultingPortConfig.id, resultingGainUpdate.id);
    auto updatedPortConfig = mModule->getPortConfig(resultingGainUpdate.id);
    ASSERT_TRUE(updatedPortConfig.has_value());
    ASSERT_TRUE(updatedPortConfig->gain.has_value());
    EXPECT_EQ(gainConfig, updatedPortConfig->gain);
}

TEST_F(Hal2AidlMapperTest, SetAudioPortConfigGainChangeFromScratch) {
    // Set gain as the first operation, the HAL should suggest the rest of the configuration.
    AudioPortConfig gainSet;
    gainSet.ext = createPortDeviceExt(AudioDeviceType::OUT_SPEAKER, 0);
    AudioGainConfig gainConfig{.index = -1,
                               .mode = 1 << static_cast<int>(AudioGainMode::JOINT),
                               .channelMask = AudioChannelLayout{},
                               .values = std::vector<int32_t>{-3200},
                               .rampDurationMs = 0};
    gainSet.gain = gainConfig;
    AudioPortConfig resultingPortConfig;
    ASSERT_EQ(OK, mMapper->setPortConfig(gainSet, std::set<int32_t>(), &resultingPortConfig));
    EXPECT_NE(0, resultingPortConfig.id);
    EXPECT_NE(0, resultingPortConfig.portId);
    auto portConfig = mModule->getPortConfig(resultingPortConfig.id);
    ASSERT_TRUE(portConfig.has_value());
    ASSERT_TRUE(portConfig->gain.has_value());
    EXPECT_EQ(gainConfig, portConfig->gain);
}
