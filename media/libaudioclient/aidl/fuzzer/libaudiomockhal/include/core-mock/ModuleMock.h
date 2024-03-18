/*
 * Copyright (C) 2024 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */
#include <aidl/android/hardware/audio/core/BnModule.h>

using namespace aidl::android::media::audio::common;
using namespace aidl::android::hardware::audio::core;
using namespace aidl::android::hardware::audio::core::sounddose;
using namespace aidl::android::hardware::audio::effect;

namespace aidl::android::hardware::audio::core {

class ModuleMock : public BnModule {
  public:
    ModuleMock();

  private:
    ndk::ScopedAStatus getTelephony(std::shared_ptr<ITelephony>*) override;
    ndk::ScopedAStatus getBluetooth(std::shared_ptr<IBluetooth>*) override;
    ndk::ScopedAStatus getBluetoothA2dp(std::shared_ptr<IBluetoothA2dp>*) override;
    ndk::ScopedAStatus getBluetoothLe(std::shared_ptr<IBluetoothLe>*) override;
    ndk::ScopedAStatus openInputStream(const OpenInputStreamArguments&,
                                       OpenInputStreamReturn*) override;
    ndk::ScopedAStatus openOutputStream(const OpenOutputStreamArguments&,
                                        OpenOutputStreamReturn*) override;
    ndk::ScopedAStatus getMasterMute(bool*) override;
    ndk::ScopedAStatus setMasterMute(bool) override;
    ndk::ScopedAStatus getMasterVolume(float*) override;
    ndk::ScopedAStatus setMasterVolume(float) override;
    ndk::ScopedAStatus getMicMute(bool*) override;
    ndk::ScopedAStatus setMicMute(bool) override;
    ndk::ScopedAStatus getSoundDose(std::shared_ptr<ISoundDose>*) override;
    ndk::ScopedAStatus getMmapPolicyInfos(AudioMMapPolicyType,
                                          std::vector<AudioMMapPolicyInfo>*) override;
    ndk::ScopedAStatus supportsVariableLatency(bool*) override;

    ndk::ScopedAStatus setModuleDebug(const ModuleDebug&) override {
        return ndk::ScopedAStatus::ok();
    }
    ndk::ScopedAStatus connectExternalDevice(const AudioPort&, AudioPort*) override {
        return ndk::ScopedAStatus::ok();
    }
    ndk::ScopedAStatus disconnectExternalDevice(int32_t) override {
        return ndk::ScopedAStatus::ok();
    }
    ndk::ScopedAStatus getAudioPatches(std::vector<AudioPatch>*) override {
        return ndk::ScopedAStatus::ok();
    }
    ndk::ScopedAStatus getAudioPort(int32_t, AudioPort*) override {
        return ndk::ScopedAStatus::ok();
    }
    ndk::ScopedAStatus getAudioPortConfigs(std::vector<AudioPortConfig>*) override {
        return ndk::ScopedAStatus::ok();
    }
    ndk::ScopedAStatus getAudioPorts(std::vector<AudioPort>*) override {
        return ndk::ScopedAStatus::ok();
    }
    ndk::ScopedAStatus getAudioRoutes(std::vector<AudioRoute>*) override {
        return ndk::ScopedAStatus::ok();
    }
    ndk::ScopedAStatus getAudioRoutesForAudioPort(int32_t, std::vector<AudioRoute>*) override {
        return ndk::ScopedAStatus::ok();
    }
    ndk::ScopedAStatus getSupportedPlaybackRateFactors(SupportedPlaybackRateFactors*) override {
        return ndk::ScopedAStatus::ok();
    }
    ndk::ScopedAStatus setAudioPatch(const AudioPatch&, AudioPatch*) override {
        return ndk::ScopedAStatus::ok();
    }
    ndk::ScopedAStatus setAudioPortConfig(const AudioPortConfig&, AudioPortConfig*,
                                          bool*) override {
        return ndk::ScopedAStatus::ok();
    }
    ndk::ScopedAStatus resetAudioPatch(int32_t) override { return ndk::ScopedAStatus::ok(); }
    ndk::ScopedAStatus resetAudioPortConfig(int32_t) override { return ndk::ScopedAStatus::ok(); }
    ndk::ScopedAStatus getMicrophones(std::vector<MicrophoneInfo>*) override {
        return ndk::ScopedAStatus::ok();
    }
    ndk::ScopedAStatus updateAudioMode(AudioMode) override { return ndk::ScopedAStatus::ok(); }
    ndk::ScopedAStatus updateScreenRotation(ScreenRotation) override {
        return ndk::ScopedAStatus::ok();
    }
    ndk::ScopedAStatus updateScreenState(bool) override { return ndk::ScopedAStatus::ok(); }
    ndk::ScopedAStatus generateHwAvSyncId(int32_t*) override {
        return ndk::ScopedAStatus::fromExceptionCode(EX_UNSUPPORTED_OPERATION);
    }
    ndk::ScopedAStatus getVendorParameters(const std::vector<std::string>&,
                                           std::vector<VendorParameter>*) override {
        return ndk::ScopedAStatus::fromExceptionCode(EX_UNSUPPORTED_OPERATION);
    }
    ndk::ScopedAStatus setVendorParameters(const std::vector<VendorParameter>&, bool) override {
        return ndk::ScopedAStatus::fromExceptionCode(EX_UNSUPPORTED_OPERATION);
    }
    ndk::ScopedAStatus addDeviceEffect(int32_t, const std::shared_ptr<IEffect>&) override {
        return ndk::ScopedAStatus::ok();
    }
    ndk::ScopedAStatus removeDeviceEffect(int32_t, const std::shared_ptr<IEffect>&) override {
        return ndk::ScopedAStatus::ok();
    }
    ndk::ScopedAStatus getAAudioMixerBurstCount(int32_t*) override {
        return ndk::ScopedAStatus::fromExceptionCode(EX_UNSUPPORTED_OPERATION);
    }
    ndk::ScopedAStatus getAAudioHardwareBurstMinUsec(int32_t*) override {
        return ndk::ScopedAStatus::fromExceptionCode(EX_UNSUPPORTED_OPERATION);
    }
    ndk::ScopedAStatus prepareToDisconnectExternalDevice(int32_t) override {
        return ndk::ScopedAStatus::ok();
    }

    AudioPortExt createDeviceExt(AudioDeviceType devType, int32_t flags);
    AudioPort createPort(int32_t id, const std::string& name, int32_t flags, bool isInput,
                         const AudioPortExt& ext);

    bool mMasterMute;
    float mMasterVolume;
    bool mMicMute;
    std::vector<AudioPort> mPorts;
};

}  // namespace aidl::android::hardware::audio::core
