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

#include <aidl/android/hardware/audio/core/StreamDescriptor.h>
#include <error/expected_utils.h>
#include <media/AidlConversionCppNdk.h>
#include <media/AidlConversionUtil.h>
#include <mediautils/TimeCheck.h>
#include <utils/Log.h>

#include "DeviceHalAidl.h"
#include "StreamHalAidl.h"

using aidl::android::aidl_utils::statusTFromBinderStatus;
using aidl::android::media::audio::common::AudioMode;
using aidl::android::media::audio::common::Float;
using aidl::android::hardware::audio::core::IModule;
using aidl::android::hardware::audio::core::ITelephony;
using aidl::android::hardware::audio::core::StreamDescriptor;

namespace android {

status_t DeviceHalAidl::getSupportedDevices(uint32_t*) {
    // Obsolete.
    return INVALID_OPERATION;
}

status_t DeviceHalAidl::initCheck() {
    if (mModule == nullptr) return NO_INIT;
    // HAL modules are already initialized by the time they are published to the SM.
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

status_t DeviceHalAidl::openOutputStream(
        audio_io_handle_t handle __unused, audio_devices_t devices __unused,
        audio_output_flags_t flags __unused, struct audio_config* config,
        const char* address __unused,
        sp<StreamOutHalInterface>* outStream) {
    if (!outStream || !config) {
        return BAD_VALUE;
    }
    TIME_CHECK();
    if (!mModule) return NO_INIT;
    config->sample_rate = 48000;
    config->format = AUDIO_FORMAT_PCM_24_BIT_PACKED;
    config->channel_mask = AUDIO_CHANNEL_OUT_STEREO;
    StreamDescriptor descriptor;
    descriptor.frameSizeBytes = audio_bytes_per_sample(config->format) *
            audio_channel_count_from_out_mask(config->channel_mask);
    descriptor.bufferSizeFrames = 600;
    *outStream = sp<StreamOutHalAidl>::make(descriptor, nullptr);
    return OK;
}

status_t DeviceHalAidl::openInputStream(
        audio_io_handle_t handle __unused, audio_devices_t devices __unused,
        struct audio_config* config, audio_input_flags_t flags __unused,
        const char* address __unused, audio_source_t source __unused,
        audio_devices_t outputDevice __unused,
        const char* outputDeviceAddress __unused,
        sp<StreamInHalInterface>* inStream) {
    if (!inStream || !config) {
        return BAD_VALUE;
    }
    TIME_CHECK();
    if (!mModule) return NO_INIT;
    config->sample_rate = 48000;
    config->format = AUDIO_FORMAT_PCM_24_BIT_PACKED;
    config->channel_mask = AUDIO_CHANNEL_IN_STEREO;
    StreamDescriptor descriptor;
    descriptor.frameSizeBytes = audio_bytes_per_sample(config->format) *
            audio_channel_count_from_out_mask(config->channel_mask);
    descriptor.bufferSizeFrames = 600;
    *inStream = sp<StreamInHalAidl>::make(descriptor, nullptr);
    return OK;
}

status_t DeviceHalAidl::supportsAudioPatches(bool* supportsPatches) {
    *supportsPatches = true;
    return OK;
}

status_t DeviceHalAidl::createAudioPatch(unsigned int num_sources __unused,
                                         const struct audio_port_config* sources __unused,
                                         unsigned int num_sinks __unused,
                                         const struct audio_port_config* sinks __unused,
                                         audio_patch_handle_t* patch __unused) {
    TIME_CHECK();
    if (!mModule) return NO_INIT;
    ALOGE("%s not implemented yet", __func__);
    return OK;
}

status_t DeviceHalAidl::releaseAudioPatch(audio_patch_handle_t patch __unused) {
    TIME_CHECK();
    if (!mModule) return NO_INIT;
    ALOGE("%s not implemented yet", __func__);
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

} // namespace android
