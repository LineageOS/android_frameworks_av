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

#define LOG_TAG "DeviceHalAidl"

#include <algorithm>
#include <forward_list>

#include <aidl/android/hardware/audio/core/StreamDescriptor.h>
#include <error/expected_utils.h>
#include <media/AidlConversionCppNdk.h>
#include <media/AidlConversionUtil.h>
#include <mediautils/TimeCheck.h>
#include <utils/Log.h>

#include "DeviceHalAidl.h"
#include "StreamHalAidl.h"

using aidl::android::aidl_utils::statusTFromBinderStatus;
using aidl::android::media::audio::common::AudioConfig;
using aidl::android::media::audio::common::AudioDevice;
using aidl::android::media::audio::common::AudioIoFlags;
using aidl::android::media::audio::common::AudioMode;
using aidl::android::media::audio::common::AudioOutputFlags;
using aidl::android::media::audio::common::AudioPort;
using aidl::android::media::audio::common::AudioPortConfig;
using aidl::android::media::audio::common::AudioPortExt;
using aidl::android::media::audio::common::AudioSource;
using aidl::android::media::audio::common::Int;
using aidl::android::media::audio::common::Float;
using aidl::android::hardware::audio::common::RecordTrackMetadata;
using aidl::android::hardware::audio::core::AudioPatch;
using aidl::android::hardware::audio::core::IModule;
using aidl::android::hardware::audio::core::ITelephony;
using aidl::android::hardware::audio::core::StreamDescriptor;

namespace android {

namespace {

bool isConfigEqualToPortConfig(const AudioConfig& config, const AudioPortConfig& portConfig) {
    return portConfig.sampleRate.value().value == config.base.sampleRate &&
            portConfig.channelMask.value() == config.base.channelMask &&
            portConfig.format.value() == config.base.format;
}

void setConfigFromPortConfig(AudioConfig* config, const AudioPortConfig& portConfig) {
    config->base.sampleRate = portConfig.sampleRate.value().value;
    config->base.channelMask = portConfig.channelMask.value();
    config->base.format = portConfig.format.value();
}

void setPortConfigFromConfig(AudioPortConfig* portConfig, const AudioConfig& config) {
    portConfig->sampleRate = Int{ .value = config.base.sampleRate };
    portConfig->channelMask = config.base.channelMask;
    portConfig->format = config.base.format;
}

}  // namespace

status_t DeviceHalAidl::getSupportedDevices(uint32_t*) {
    // Obsolete.
    return INVALID_OPERATION;
}

status_t DeviceHalAidl::initCheck() {
    TIME_CHECK();
    if (mModule == nullptr) return NO_INIT;
    std::vector<AudioPort> ports;
    RETURN_STATUS_IF_ERROR(
            statusTFromBinderStatus(mModule->getAudioPorts(&ports)));
    ALOGW_IF(ports.empty(), "%s: module %s returned an empty list of audio ports",
            __func__, mInstance.c_str());
    std::transform(ports.begin(), ports.end(), std::inserter(mPorts, mPorts.end()),
            [](const auto& p) { return std::make_pair(p.id, p); });
    std::vector<AudioPortConfig> portConfigs;
    RETURN_STATUS_IF_ERROR(
            statusTFromBinderStatus(mModule->getAudioPortConfigs(&portConfigs)));  // OK if empty
    std::transform(portConfigs.begin(), portConfigs.end(),
            std::inserter(mPortConfigs, mPortConfigs.end()),
            [](const auto& p) { return std::make_pair(p.id, p); });
    std::vector<AudioPatch> patches;
    RETURN_STATUS_IF_ERROR(
            statusTFromBinderStatus(mModule->getAudioPatches(&patches)));  // OK if empty
    std::transform(patches.begin(), patches.end(),
            std::inserter(mPatches, mPatches.end()),
            [](const auto& p) { return std::make_pair(p.id, p); });
    return OK;
}

status_t DeviceHalAidl::setVoiceVolume(float volume) {
    TIME_CHECK();
    if (!mModule) return NO_INIT;
    std::shared_ptr<ITelephony> telephony;
    if (ndk::ScopedAStatus status = mModule->getTelephony(&telephony);
            status.isOk() && telephony != nullptr) {
        ITelephony::TelecomConfig inConfig{ .voiceVolume = Float{volume} }, outConfig;
        RETURN_STATUS_IF_ERROR(
                statusTFromBinderStatus(telephony->setTelecomConfig(inConfig, &outConfig)));
        ALOGW_IF(outConfig.voiceVolume.has_value() && volume != outConfig.voiceVolume.value().value,
                "%s: the resulting voice volume %f is not the same as requested %f",
                __func__, outConfig.voiceVolume.value().value, volume);
    }
    return INVALID_OPERATION;
}

status_t DeviceHalAidl::setMasterVolume(float volume) {
    TIME_CHECK();
    if (!mModule) return NO_INIT;
    return statusTFromBinderStatus(mModule->setMasterVolume(volume));
}

status_t DeviceHalAidl::getMasterVolume(float *volume) {
    TIME_CHECK();
    if (!mModule) return NO_INIT;
    return statusTFromBinderStatus(mModule->getMasterVolume(volume));
}

status_t DeviceHalAidl::setMode(audio_mode_t mode) {
    TIME_CHECK();
    if (!mModule) return NO_INIT;
    AudioMode audioMode = VALUE_OR_FATAL(::aidl::android::legacy2aidl_audio_mode_t_AudioMode(mode));
    std::shared_ptr<ITelephony> telephony;
    if (ndk::ScopedAStatus status = mModule->getTelephony(&telephony);
            status.isOk() && telephony != nullptr) {
        RETURN_STATUS_IF_ERROR(statusTFromBinderStatus(telephony->switchAudioMode(audioMode)));
    }
    return statusTFromBinderStatus(mModule->updateAudioMode(audioMode));
}

status_t DeviceHalAidl::setMicMute(bool state) {
    TIME_CHECK();
    if (!mModule) return NO_INIT;
    return statusTFromBinderStatus(mModule->setMicMute(state));
}

status_t DeviceHalAidl::getMicMute(bool *state) {
    TIME_CHECK();
    if (!mModule) return NO_INIT;
    return statusTFromBinderStatus(mModule->getMicMute(state));
}

status_t DeviceHalAidl::setMasterMute(bool state) {
    TIME_CHECK();
    if (!mModule) return NO_INIT;
    return statusTFromBinderStatus(mModule->setMasterMute(state));
}

status_t DeviceHalAidl::getMasterMute(bool *state) {
    TIME_CHECK();
    if (!mModule) return NO_INIT;
    return statusTFromBinderStatus(mModule->getMasterMute(state));
}

status_t DeviceHalAidl::setParameters(const String8& kvPairs __unused) {
    TIME_CHECK();
    if (!mModule) return NO_INIT;
    ALOGE("%s not implemented yet", __func__);
    return OK;
}

status_t DeviceHalAidl::getParameters(const String8& keys __unused, String8 *values) {
    TIME_CHECK();
    values->clear();
    if (!mModule) return NO_INIT;
    ALOGE("%s not implemented yet", __func__);
    return OK;
}

status_t DeviceHalAidl::getInputBufferSize(
        const struct audio_config* config __unused, size_t* size __unused) {
    TIME_CHECK();
    if (!mModule) return NO_INIT;
    ALOGE("%s not implemented yet", __func__);
    return OK;
}

namespace {

class Cleanup {
  public:
    typedef void (DeviceHalAidl::*Cleaner)(int32_t);

    Cleanup(DeviceHalAidl* device, Cleaner cleaner, int32_t id) :
            mDevice(device), mCleaner(cleaner), mId(id) {}
    ~Cleanup() { clean(); }
    void clean() {
        if (mDevice != nullptr) (mDevice->*mCleaner)(mId);
        disarm();
    }
    void disarm() { mDevice = nullptr; }

  private:
    DeviceHalAidl* mDevice;
    const Cleaner mCleaner;
    const int32_t mId;
};

}  // namespace

// Since the order of container elements destruction is unspecified,
// ensure that cleanups are performed from the most recent one and upwards.
// This is the same as if there were individual Cleanup instances on the stack,
// however the bonus is that we can disarm all of them with just one statement.
class DeviceHalAidl::Cleanups : public std::forward_list<Cleanup> {
  public:
    ~Cleanups() { for (auto& c : *this) c.clean(); }
    void disarmAll() { for (auto& c : *this) c.disarm(); }
};

status_t DeviceHalAidl::prepareToOpenStream(
        int32_t aidlHandle, const AudioDevice& aidlDevice, const AudioIoFlags& aidlFlags,
        struct audio_config* config,
        Cleanups* cleanups, AudioConfig* aidlConfig, AudioPortConfig* mixPortConfig) {
    const bool isInput = aidlFlags.getTag() == AudioIoFlags::Tag::input;
    // Find / create AudioPortConfigs for the device port and the mix port,
    // then find / create a patch between them, and open a stream on the mix port.
    AudioPortConfig devicePortConfig;
    bool created = false;
    RETURN_STATUS_IF_ERROR(findOrCreatePortConfig(aidlDevice, &devicePortConfig, &created));
    if (created) {
        cleanups->emplace_front(this, &DeviceHalAidl::resetPortConfig, devicePortConfig.id);
    }
    RETURN_STATUS_IF_ERROR(findOrCreatePortConfig(*aidlConfig, aidlFlags, aidlHandle,
                    mixPortConfig, &created));
    if (created) {
        cleanups->emplace_front(this, &DeviceHalAidl::resetPortConfig, mixPortConfig->id);
    }
    setConfigFromPortConfig(aidlConfig, *mixPortConfig);
    AudioPatch patch;
    if (isInput) {
        RETURN_STATUS_IF_ERROR(findOrCreatePatch(
                        {devicePortConfig.id}, {mixPortConfig->id}, &patch, &created));
    } else {
        RETURN_STATUS_IF_ERROR(findOrCreatePatch(
                        {mixPortConfig->id}, {devicePortConfig.id}, &patch, &created));
    }
    if (created) {
        cleanups->emplace_front(this, &DeviceHalAidl::resetPatch, patch.id);
    }
    if (aidlConfig->frameCount <= 0) {
        aidlConfig->frameCount = patch.minimumStreamBufferSizeFrames;
    }
    *config = VALUE_OR_RETURN_STATUS(
            ::aidl::android::aidl2legacy_AudioConfig_audio_config_t(*aidlConfig, isInput));
    return OK;
}

status_t DeviceHalAidl::openOutputStream(
        audio_io_handle_t handle, audio_devices_t devices,
        audio_output_flags_t flags, struct audio_config* config,
        const char* address,
        sp<StreamOutHalInterface>* outStream) {
    if (!outStream || !config) {
        return BAD_VALUE;
    }
    TIME_CHECK();
    if (!mModule) return NO_INIT;
    int32_t aidlHandle = VALUE_OR_RETURN_STATUS(
            ::aidl::android::legacy2aidl_audio_io_handle_t_int32_t(handle));
    AudioConfig aidlConfig = VALUE_OR_RETURN_STATUS(
            ::aidl::android::legacy2aidl_audio_config_t_AudioConfig(*config, false /*isInput*/));
    AudioDevice aidlDevice = VALUE_OR_RETURN_STATUS(
            ::aidl::android::legacy2aidl_audio_device_AudioDevice(devices, address));
    int32_t aidlOutputFlags = VALUE_OR_RETURN_STATUS(
            ::aidl::android::legacy2aidl_audio_output_flags_t_int32_t_mask(flags));
    AudioIoFlags aidlFlags = AudioIoFlags::make<AudioIoFlags::Tag::output>(aidlOutputFlags);
    AudioPortConfig mixPortConfig;
    Cleanups cleanups;
    RETURN_STATUS_IF_ERROR(prepareToOpenStream(aidlHandle, aidlDevice, aidlFlags, config,
                    &cleanups, &aidlConfig, &mixPortConfig));
    ::aidl::android::hardware::audio::core::IModule::OpenOutputStreamArguments args;
    args.portConfigId = mixPortConfig.id;
    args.offloadInfo = aidlConfig.offloadInfo;
    args.bufferSizeFrames = aidlConfig.frameCount;
    ::aidl::android::hardware::audio::core::IModule::OpenOutputStreamReturn ret;
    RETURN_STATUS_IF_ERROR(statusTFromBinderStatus(mModule->openOutputStream(args, &ret)));
    *outStream = sp<StreamOutHalAidl>::make(*config, std::move(ret.desc), std::move(ret.stream));
    cleanups.disarmAll();
    return OK;
}

status_t DeviceHalAidl::openInputStream(
        audio_io_handle_t handle, audio_devices_t devices,
        struct audio_config* config, audio_input_flags_t flags,
        const char* address, audio_source_t source,
        audio_devices_t outputDevice, const char* outputDeviceAddress,
        sp<StreamInHalInterface>* inStream) {
    if (!inStream || !config) {
        return BAD_VALUE;
    }
    TIME_CHECK();
    if (!mModule) return NO_INIT;
    int32_t aidlHandle = VALUE_OR_RETURN_STATUS(
            ::aidl::android::legacy2aidl_audio_io_handle_t_int32_t(handle));
    AudioConfig aidlConfig = VALUE_OR_RETURN_STATUS(
            ::aidl::android::legacy2aidl_audio_config_t_AudioConfig(*config, true /*isInput*/));
    AudioDevice aidlDevice = VALUE_OR_RETURN_STATUS(
            ::aidl::android::legacy2aidl_audio_device_AudioDevice(devices, address));
    int32_t aidlInputFlags = VALUE_OR_RETURN_STATUS(
            ::aidl::android::legacy2aidl_audio_input_flags_t_int32_t_mask(flags));
    AudioIoFlags aidlFlags = AudioIoFlags::make<AudioIoFlags::Tag::input>(aidlInputFlags);
    AudioSource aidlSource = VALUE_OR_RETURN_STATUS(
            ::aidl::android::legacy2aidl_audio_source_t_AudioSource(source));
    AudioPortConfig mixPortConfig;
    Cleanups cleanups;
    RETURN_STATUS_IF_ERROR(prepareToOpenStream(aidlHandle, aidlDevice, aidlFlags, config,
                    &cleanups, &aidlConfig, &mixPortConfig));
    ::aidl::android::hardware::audio::core::IModule::OpenInputStreamArguments args;
    args.portConfigId = mixPortConfig.id;
    RecordTrackMetadata aidlTrackMetadata{
        .source = aidlSource, .gain = 1, .channelMask = aidlConfig.base.channelMask };
    if (outputDevice != AUDIO_DEVICE_NONE) {
        aidlTrackMetadata.destinationDevice = VALUE_OR_RETURN_STATUS(
            ::aidl::android::legacy2aidl_audio_device_AudioDevice(
                    outputDevice, outputDeviceAddress));
    }
    args.sinkMetadata.tracks.push_back(std::move(aidlTrackMetadata));
    args.bufferSizeFrames = aidlConfig.frameCount;
    ::aidl::android::hardware::audio::core::IModule::OpenInputStreamReturn ret;
    RETURN_STATUS_IF_ERROR(statusTFromBinderStatus(mModule->openInputStream(args, &ret)));
    *inStream = sp<StreamInHalAidl>::make(*config, std::move(ret.desc), std::move(ret.stream));
    cleanups.disarmAll();
    return OK;
}

status_t DeviceHalAidl::supportsAudioPatches(bool* supportsPatches) {
    *supportsPatches = true;
    return OK;
}

status_t DeviceHalAidl::createAudioPatch(unsigned int num_sources,
                                         const struct audio_port_config* sources,
                                         unsigned int num_sinks,
                                         const struct audio_port_config* sinks,
                                         audio_patch_handle_t* patch) {
    TIME_CHECK();
    if (!mModule) return NO_INIT;
    if (num_sinks > AUDIO_PATCH_PORTS_MAX || num_sources > AUDIO_PATCH_PORTS_MAX ||
        sources == nullptr || sinks == nullptr || patch == nullptr) {
        return BAD_VALUE;
    }
    // Note that the patch handle (*patch) is provided by the framework.
    // In tests it's possible that its value is AUDIO_PATCH_HANDLE_NONE.

    // Upon conversion, mix port configs contain audio configuration, while
    // device port configs contain device address. This data is used to find
    // or create HAL configs.
    std::vector<AudioPortConfig> aidlSources, aidlSinks;
    for (unsigned int i = 0; i < num_sources; ++i) {
        bool isInput = VALUE_OR_RETURN_STATUS(::aidl::android::portDirection(
                        sources[i].role, sources[i].type)) ==
                ::aidl::android::AudioPortDirection::INPUT;
        aidlSources.push_back(VALUE_OR_RETURN_STATUS(
                        ::aidl::android::legacy2aidl_audio_port_config_AudioPortConfig(
                                sources[i], isInput, 0)));
    }
    for (unsigned int i = 0; i < num_sinks; ++i) {
        bool isInput = VALUE_OR_RETURN_STATUS(::aidl::android::portDirection(
                        sinks[i].role, sinks[i].type)) ==
                ::aidl::android::AudioPortDirection::INPUT;
        aidlSinks.push_back(VALUE_OR_RETURN_STATUS(
                        ::aidl::android::legacy2aidl_audio_port_config_AudioPortConfig(
                                sinks[i], isInput, 0)));
    }
    Cleanups cleanups;
    auto existingPatchIt = mPatches.end();
    auto fwkHandlesIt = *patch != AUDIO_PATCH_HANDLE_NONE ?
            mFwkHandles.find(*patch) : mFwkHandles.end();
    AudioPatch aidlPatch;
    if (fwkHandlesIt != mFwkHandles.end()) {
        existingPatchIt = mPatches.find(fwkHandlesIt->second);
        if (existingPatchIt != mPatches.end()) {
            aidlPatch = existingPatchIt->second;
            aidlPatch.sourcePortConfigIds.clear();
            aidlPatch.sinkPortConfigIds.clear();
        }
    }
    auto fillPortConfigs = [&](
            const std::vector<AudioPortConfig>& configs, std::vector<int32_t>* ids) -> status_t {
        for (const auto& s : configs) {
            AudioPortConfig portConfig;
            bool created = false;
            RETURN_STATUS_IF_ERROR(findOrCreatePortConfig(s, &portConfig, &created));
            if (created) {
                cleanups.emplace_front(this, &DeviceHalAidl::resetPortConfig, portConfig.id);
            }
            ids->push_back(portConfig.id);
        }
        return OK;
    };
    RETURN_STATUS_IF_ERROR(fillPortConfigs(aidlSources, &aidlPatch.sourcePortConfigIds));
    RETURN_STATUS_IF_ERROR(fillPortConfigs(aidlSinks, &aidlPatch.sinkPortConfigIds));
    if (existingPatchIt != mPatches.end()) {
        RETURN_STATUS_IF_ERROR(statusTFromBinderStatus(
                        mModule->setAudioPatch(aidlPatch, &aidlPatch)));
        existingPatchIt->second = aidlPatch;
    } else {
        bool created = false;
        RETURN_STATUS_IF_ERROR(findOrCreatePatch(aidlPatch, &aidlPatch, &created));
        // Since no cleanup of the patch is needed, 'created' is ignored.
        if (fwkHandlesIt != mFwkHandles.end()) {
            fwkHandlesIt->second = aidlPatch.id;
            // Patch handle (*patch) stays the same.
        } else {
            if (*patch == AUDIO_PATCH_HANDLE_NONE) {
                // This isn't good as the module can't provide a handle which is really unique.
                // However, this situation should only happen in tests.
                *patch = aidlPatch.id;
                LOG_ALWAYS_FATAL_IF(mFwkHandles.count(*patch) > 0,
                        "%s: patch id %d clashes with another framework patch handle",
                        __func__, *patch);
            }
            mFwkHandles.emplace(*patch, aidlPatch.id);
        }
    }
    cleanups.disarmAll();
    return OK;
}

status_t DeviceHalAidl::releaseAudioPatch(audio_patch_handle_t patch) {
    TIME_CHECK();
    if (!mModule) return NO_INIT;
    auto idMapIt = mFwkHandles.find(patch);
    if (idMapIt == mFwkHandles.end()) {
        return BAD_VALUE;
    }
    RETURN_STATUS_IF_ERROR(statusTFromBinderStatus(mModule->resetAudioPatch(idMapIt->second)));
    mFwkHandles.erase(idMapIt);
    return OK;
}

status_t DeviceHalAidl::getAudioPort(struct audio_port* port __unused) {
    TIME_CHECK();
    ALOGE("%s not implemented yet", __func__);
    return INVALID_OPERATION;
}

status_t DeviceHalAidl::getAudioPort(struct audio_port_v7 *port __unused) {
    TIME_CHECK();
    ALOGE("%s not implemented yet", __func__);
    return INVALID_OPERATION;
}

status_t DeviceHalAidl::setAudioPortConfig(const struct audio_port_config* config __unused) {
    TIME_CHECK();
    if (!mModule) return NO_INIT;
    ALOGE("%s not implemented yet", __func__);
    return OK;
}

status_t DeviceHalAidl::getMicrophones(
        std::vector<audio_microphone_characteristic_t>* microphones __unused) {
    TIME_CHECK();
    if (!mModule) return NO_INIT;
    ALOGE("%s not implemented yet", __func__);
    return OK;
}

status_t DeviceHalAidl::addDeviceEffect(audio_port_handle_t device __unused,
        sp<EffectHalInterface> effect) {
    if (!effect) {
        return BAD_VALUE;
    }
    TIME_CHECK();
    if (!mModule) return NO_INIT;
    ALOGE("%s not implemented yet", __func__);
    return OK;
}
status_t DeviceHalAidl::removeDeviceEffect(audio_port_handle_t device __unused,
                            sp<EffectHalInterface> effect) {
    if (!effect) {
        return BAD_VALUE;
    }
    TIME_CHECK();
    if (!mModule) return NO_INIT;
    ALOGE("%s not implemented yet", __func__);
    return OK;
}

status_t DeviceHalAidl::getMmapPolicyInfos(
        media::audio::common::AudioMMapPolicyType policyType __unused,
        std::vector<media::audio::common::AudioMMapPolicyInfo>* policyInfos __unused) {
    TIME_CHECK();
    ALOGE("%s not implemented yet", __func__);
    return OK;
}

int32_t DeviceHalAidl::getAAudioMixerBurstCount() {
    TIME_CHECK();
    ALOGE("%s not implemented yet", __func__);
    return OK;
}

int32_t DeviceHalAidl::getAAudioHardwareBurstMinUsec() {
    TIME_CHECK();
    ALOGE("%s not implemented yet", __func__);
    return OK;
}

error::Result<audio_hw_sync_t> DeviceHalAidl::getHwAvSync() {
    TIME_CHECK();
    ALOGE("%s not implemented yet", __func__);
    return base::unexpected(INVALID_OPERATION);
}

status_t DeviceHalAidl::dump(int fd, const Vector<String16>& args) {
    TIME_CHECK();
    if (!mModule) return NO_INIT;
    return mModule->dump(fd, Args(args).args(), args.size());
};

int32_t DeviceHalAidl::supportsBluetoothVariableLatency(bool* supports __unused) {
    TIME_CHECK();
    ALOGE("%s not implemented yet", __func__);
    return INVALID_OPERATION;
}

status_t DeviceHalAidl::createPortConfig(const AudioPortConfig& requestedPortConfig,
        AudioPortConfig* appliedPortConfig) {
    TIME_CHECK();
    bool applied = false;
    RETURN_STATUS_IF_ERROR(statusTFromBinderStatus(mModule->setAudioPortConfig(
                            requestedPortConfig, appliedPortConfig, &applied)));
    if (!applied) {
        RETURN_STATUS_IF_ERROR(statusTFromBinderStatus(mModule->setAudioPortConfig(
                                *appliedPortConfig, appliedPortConfig, &applied)));
        if (!applied) {
            ALOGE("%s: module %s did not apply suggested config %s",
                    __func__, mInstance.c_str(), appliedPortConfig->toString().c_str());
            return NO_INIT;
        }
    }
    mPortConfigs.emplace(appliedPortConfig->id, *appliedPortConfig);
    return OK;
}

status_t DeviceHalAidl::findOrCreatePatch(
        const AudioPatch& requestedPatch, AudioPatch* patch, bool* created) {
    std::set<int32_t> sourcePortConfigIds(requestedPatch.sourcePortConfigIds.begin(),
            requestedPatch.sourcePortConfigIds.end());
    std::set<int32_t> sinkPortConfigIds(requestedPatch.sinkPortConfigIds.begin(),
            requestedPatch.sinkPortConfigIds.end());
    return findOrCreatePatch(sourcePortConfigIds, sinkPortConfigIds, patch, created);
}

status_t DeviceHalAidl::findOrCreatePatch(
        const std::set<int32_t>& sourcePortConfigIds, const std::set<int32_t>& sinkPortConfigIds,
        AudioPatch* patch, bool* created) {
    auto patchIt = findPatch(sourcePortConfigIds, sinkPortConfigIds);
    if (patchIt == mPatches.end()) {
        TIME_CHECK();
        AudioPatch requestedPatch, appliedPatch;
        requestedPatch.sourcePortConfigIds.insert(requestedPatch.sourcePortConfigIds.end(),
                sourcePortConfigIds.begin(), sourcePortConfigIds.end());
        requestedPatch.sinkPortConfigIds.insert(requestedPatch.sinkPortConfigIds.end(),
                sinkPortConfigIds.begin(), sinkPortConfigIds.end());
        RETURN_STATUS_IF_ERROR(statusTFromBinderStatus(mModule->setAudioPatch(
                                requestedPatch, &appliedPatch)));
        patchIt = mPatches.insert(mPatches.end(), std::make_pair(appliedPatch.id, appliedPatch));
        *created = true;
    } else {
        *created = false;
    }
    *patch = patchIt->second;
    return OK;
}

status_t DeviceHalAidl::findOrCreatePortConfig(const AudioDevice& device,
        AudioPortConfig* portConfig, bool* created) {
    auto portConfigIt = findPortConfig(device);
    if (portConfigIt == mPortConfigs.end()) {
        auto portsIt = findPort(device);
        if (portsIt == mPorts.end()) {
            ALOGE("%s: device port for device %s is not found in the module %s",
                    __func__, device.toString().c_str(), mInstance.c_str());
            return BAD_VALUE;
        }
        AudioPortConfig requestedPortConfig;
        requestedPortConfig.portId = portsIt->first;
        AudioPortConfig appliedPortConfig;
        RETURN_STATUS_IF_ERROR(createPortConfig(requestedPortConfig, &appliedPortConfig));
        portConfigIt = mPortConfigs.insert(
                mPortConfigs.end(), std::make_pair(appliedPortConfig.id, appliedPortConfig));
        *created = true;
    } else {
        *created = false;
    }
    *portConfig = portConfigIt->second;
    return OK;
}

status_t DeviceHalAidl::findOrCreatePortConfig(
        const AudioConfig& config, const AudioIoFlags& flags, int32_t ioHandle,
        AudioPortConfig* portConfig, bool* created) {
    auto portConfigIt = findPortConfig(config, flags, ioHandle);
    if (portConfigIt == mPortConfigs.end()) {
        auto portsIt = findPort(config, flags);
        if (portsIt == mPorts.end()) {
            ALOGE("%s: mix port for config %s, flags %s is not found in the module %s",
                    __func__, config.toString().c_str(), flags.toString().c_str(),
                    mInstance.c_str());
            return BAD_VALUE;
        }
        AudioPortConfig requestedPortConfig;
        requestedPortConfig.portId = portsIt->first;
        setPortConfigFromConfig(&requestedPortConfig, config);
        AudioPortConfig appliedPortConfig;
        RETURN_STATUS_IF_ERROR(createPortConfig(requestedPortConfig, &appliedPortConfig));
        appliedPortConfig.ext.get<AudioPortExt::Tag::mix>().handle = ioHandle;
        portConfigIt = mPortConfigs.insert(
                mPortConfigs.end(), std::make_pair(appliedPortConfig.id, appliedPortConfig));
        *created = true;
    } else {
        *created = false;
    }
    *portConfig = portConfigIt->second;
    return OK;
}

status_t DeviceHalAidl::findOrCreatePortConfig(
        const AudioPortConfig& requestedPortConfig, AudioPortConfig* portConfig, bool* created) {
    using Tag = AudioPortExt::Tag;
    if (requestedPortConfig.ext.getTag() == Tag::mix) {
        if (const auto& p = requestedPortConfig;
                !p.sampleRate.has_value() || !p.channelMask.has_value() ||
                !p.format.has_value() || !p.flags.has_value()) {
            ALOGW("%s: provided mix port config is not fully specified: %s",
                    __func__, p.toString().c_str());
            return BAD_VALUE;
        }
        AudioConfig config;
        setConfigFromPortConfig(&config, requestedPortConfig);
        return findOrCreatePortConfig(config, requestedPortConfig.flags.value(),
                requestedPortConfig.ext.get<Tag::mix>().handle, portConfig, created);
    } else if (requestedPortConfig.ext.getTag() == Tag::device) {
        return findOrCreatePortConfig(
                requestedPortConfig.ext.get<Tag::device>().device, portConfig, created);
    }
    ALOGW("%s: unsupported audio port config: %s",
            __func__, requestedPortConfig.toString().c_str());
    return BAD_VALUE;
}

DeviceHalAidl::Patches::iterator DeviceHalAidl::findPatch(
        const std::set<int32_t>& sourcePortConfigIds, const std::set<int32_t>& sinkPortConfigIds) {
    return std::find_if(mPatches.begin(), mPatches.end(),
            [&](const auto& pair) {
                const auto& p = pair.second;
                std::set<int32_t> patchSrcs(
                        p.sourcePortConfigIds.begin(), p.sourcePortConfigIds.end());
                std::set<int32_t> patchSinks(
                        p.sinkPortConfigIds.begin(), p.sinkPortConfigIds.end());
                return sourcePortConfigIds == patchSrcs && sinkPortConfigIds == patchSinks; });
}

DeviceHalAidl::Ports::iterator DeviceHalAidl::findPort(const AudioDevice& device) {
    using Tag = AudioPortExt::Tag;
    return std::find_if(mPorts.begin(), mPorts.end(),
            [&](const auto& pair) {
                const auto& p = pair.second;
                return p.ext.getTag() == Tag::device &&
                        p.ext.template get<Tag::device>().device == device; });
}

DeviceHalAidl::Ports::iterator DeviceHalAidl::findPort(
            const AudioConfig& config, const AudioIoFlags& flags) {
    using Tag = AudioPortExt::Tag;
    return std::find_if(mPorts.begin(), mPorts.end(),
            [&](const auto& pair) {
                const auto& p = pair.second;
                return p.ext.getTag() == Tag::mix &&
                        p.flags == flags &&
                        std::find_if(p.profiles.begin(), p.profiles.end(),
                                [&](const auto& prof) {
                                    return prof.format == config.base.format &&
                                            std::find(prof.channelMasks.begin(),
                                                    prof.channelMasks.end(),
                                                    config.base.channelMask) !=
                                            prof.channelMasks.end() &&
                                            std::find(prof.sampleRates.begin(),
                                                    prof.sampleRates.end(),
                                                    config.base.sampleRate) !=
                                            prof.sampleRates.end();
                                }) != p.profiles.end(); });
}

DeviceHalAidl::PortConfigs::iterator DeviceHalAidl::findPortConfig(const AudioDevice& device) {
    using Tag = AudioPortExt::Tag;
    return std::find_if(mPortConfigs.begin(), mPortConfigs.end(),
            [&](const auto& pair) {
                const auto& p = pair.second;
                return p.ext.getTag() == Tag::device &&
                        p.ext.template get<Tag::device>().device == device; });
}

DeviceHalAidl::PortConfigs::iterator DeviceHalAidl::findPortConfig(
            const AudioConfig& config, const AudioIoFlags& flags, int32_t ioHandle) {
    using Tag = AudioPortExt::Tag;
    return std::find_if(mPortConfigs.begin(), mPortConfigs.end(),
            [&](const auto& pair) {
                const auto& p = pair.second;
                LOG_ALWAYS_FATAL_IF(p.ext.getTag() == Tag::mix &&
                        !p.sampleRate.has_value() || !p.channelMask.has_value() ||
                        !p.format.has_value() || !p.flags.has_value(),
                        "%s: stored mix port config is not fully specified: %s",
                        __func__, p.toString().c_str());
                return p.ext.getTag() == Tag::mix &&
                        isConfigEqualToPortConfig(config, p) &&
                        p.flags.value() == flags &&
                        p.ext.template get<Tag::mix>().handle == ioHandle; });
}
/*
DeviceHalAidl::PortConfigs::iterator DeviceHalAidl::findPortConfig(
        const AudioPortConfig& portConfig) {
    using Tag = AudioPortExt::Tag;
    if (portConfig.ext.getTag() == Tag::mix) {
        return std::find_if(mPortConfigs.begin(), mPortConfigs.end(),
                [&](const auto& pair) {
                    const auto& p = pair.second;
                    LOG_ALWAYS_FATAL_IF(p.ext.getTag() == Tag::mix &&
                            !p.sampleRate.has_value() || !p.channelMask.has_value() ||
                            !p.format.has_value() || !p.flags.has_value(),
                            "%s: stored mix port config is not fully specified: %s",
                            __func__, p.toString().c_str());
                    return p.ext.getTag() == Tag::mix &&
                            (!portConfig.sampleRate.has_value() ||
                                    p.sampleRate == portConfig.sampleRate) &&
                            (!portConfig.channelMask.has_value() ||
                                    p.channelMask == portConfig.channelMask) &&
                            (!portConfig.format.has_value() || p.format == portConfig.format) &&
                            (!portConfig.flags.has_value() || p.flags == portConfig.flags) &&
                            p.ext.template get<Tag::mix>().handle ==
                            portConfig.ext.template get<Tag::mix>().handle; });
    } else if (portConfig.ext.getTag() == Tag::device) {
        return findPortConfig(portConfig.ext.get<Tag::device>().device);
    }
    return mPortConfigs.end();
}
*/
void DeviceHalAidl::resetPatch(int32_t patchId) {
    if (auto it = mPatches.find(patchId); it != mPatches.end()) {
        mPatches.erase(it);
        TIME_CHECK();
        if (ndk::ScopedAStatus status = mModule->resetAudioPatch(patchId); !status.isOk()) {
            ALOGE("%s: error while resetting patch %d: %s",
                    __func__, patchId, status.getDescription().c_str());
        }
        return;
    }
    ALOGE("%s: patch id %d not found", __func__, patchId);
}

void DeviceHalAidl::resetPortConfig(int32_t portConfigId) {
    if (auto it = mPortConfigs.find(portConfigId); it != mPortConfigs.end()) {
        mPortConfigs.erase(it);
        TIME_CHECK();
        if (ndk::ScopedAStatus status = mModule->resetAudioPortConfig(portConfigId);
                !status.isOk()) {
            ALOGE("%s: error while resetting port config %d: %s",
                    __func__, portConfigId, status.getDescription().c_str());
        }
        return;
    }
    ALOGE("%s: port config id %d not found", __func__, portConfigId);
}

} // namespace android
