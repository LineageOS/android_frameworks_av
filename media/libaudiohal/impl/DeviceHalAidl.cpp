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

#include "DeviceHalAidl.h"

status_t DeviceHalAidl::getSupportedDevices(uint32_t* devices) {
    ALOGE("%s not implemented yet devices %p", __func__, devices);
    return OK;
}

status_t DeviceHalAidl::initCheck() {
    ALOGE("%s not implemented yet", __func__);
    return OK;
}

status_t DeviceHalAidl::setVoiceVolume(float volume) {
    mVoiceVolume = volume;
    ALOGE("%s not implemented yet %f", __func__, volume);
    return OK;
}

status_t DeviceHalAidl::setMasterVolume(float volume) {
    mMasterVolume = volume;
    ALOGE("%s not implemented yet %f", __func__, volume);
    return OK;
}

status_t DeviceHalAidl::getMasterVolume(float *volume) {
    *volume = mMasterVolume;
    ALOGE("%s not implemented yet %f", __func__, *volume);
    return OK;
}

status_t DeviceHalAidl::setMode(audio_mode_t mode) {
    ALOGE("%s not implemented yet %u", __func__, mode);
    return OK;
}

status_t DeviceHalAidl::setMicMute(bool state) {
    mMicMute = state;
    ALOGE("%s not implemented yet %d", __func__, state);
    return OK;
}
status_t DeviceHalAidl::getMicMute(bool *state) {
    *state = mMicMute;
    ALOGE("%s not implemented yet %d", __func__, *state);
    return OK;
}
status_t DeviceHalAidl::setMasterMute(bool state) {
    mMasterMute = state;
    ALOGE("%s not implemented yet %d", __func__, state);
    return OK;
}
status_t DeviceHalAidl::getMasterMute(bool *state) {
    *state = mMasterMute;
    ALOGE("%s not implemented yet %d", __func__, *state);
    return OK;
}

status_t DeviceHalAidl::setParameters(const String8& kvPairs) {
    ALOGE("%s not implemented yet %s", __func__, kvPairs.c_str());
    return OK;
}

status_t DeviceHalAidl::getParameters(const String8& keys, String8 *values) {
    ALOGE("%s not implemented yet %s %s", __func__, keys.c_str(), values->c_str());
    return OK;
}

status_t DeviceHalAidl::getInputBufferSize(const struct audio_config* config, size_t* size) {
    ALOGE("%s not implemented yet %p %zu", __func__, config, *size);
    return OK;
}

status_t DeviceHalAidl::openOutputStream(audio_io_handle_t handle, audio_devices_t devices,
                                         audio_output_flags_t flags, struct audio_config* config,
                                         const char* address,
                                         sp<StreamOutHalInterface>* outStream) {
    ALOGE("%s not implemented yet %d %u %u %p %s %p", __func__, handle, devices, flags, config,
          address, outStream);
    return OK;
}

status_t DeviceHalAidl::openInputStream(audio_io_handle_t handle, audio_devices_t devices,
                                        struct audio_config* config, audio_input_flags_t flags,
                                        const char* address, audio_source_t source,
                                        audio_devices_t outputDevice,
                                        const char* outputDeviceAddress,
                                        sp<StreamInHalInterface>* inStream) {
    ALOGE("%s not implemented yet %d %u %u %u %p %s %s %p %d", __func__, handle, devices,
          outputDevice, flags, config, address, outputDeviceAddress, inStream, source);
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
    ALOGE("%s not implemented yet %d %p %d %p %p", __func__, num_sources, sources, num_sinks,
            sinks, patch);
    return OK;
}

status_t DeviceHalAidl::releaseAudioPatch(audio_patch_handle_t patch) {
    ALOGE("%s not implemented yet patch %d", __func__, patch);
    return OK;
}

status_t DeviceHalAidl::setAudioPortConfig(const struct audio_port_config* config) {
    ALOGE("%s not implemented yet config %p", __func__, config);
    return OK;
}

status_t DeviceHalAidl::getMicrophones(
        std::vector<audio_microphone_characteristic_t>* microphones) {
    ALOGE("%s not implemented yet microphones %p", __func__, microphones);
    return OK;
}

status_t DeviceHalAidl::addDeviceEffect(audio_port_handle_t device, sp<EffectHalInterface> effect) {
    if (!effect) {
        return BAD_VALUE;
    }
    ALOGE("%s not implemented yet device %d", __func__, device);
    return OK;
}
status_t DeviceHalAidl::removeDeviceEffect(audio_port_handle_t device,
                            sp<EffectHalInterface> effect) {
    if (!effect) {
        return BAD_VALUE;
    }
    ALOGE("%s not implemented yet device %d", __func__, device);
    return OK;
}

status_t DeviceHalAidl::getMmapPolicyInfos(
        media::audio::common::AudioMMapPolicyType policyType __unused,
        std::vector<media::audio::common::AudioMMapPolicyInfo>* policyInfos __unused) {
    ALOGE("%s not implemented yet", __func__);
    return OK;
}

int32_t DeviceHalAidl::getAAudioMixerBurstCount() {
    ALOGE("%s not implemented yet", __func__);
    return OK;
}

int32_t DeviceHalAidl::getAAudioHardwareBurstMinUsec() {
    ALOGE("%s not implemented yet", __func__);
    return OK;
}

error::Result<audio_hw_sync_t> DeviceHalAidl::getHwAvSync() {
    ALOGE("%s not implemented yet", __func__);
    return base::unexpected(INVALID_OPERATION);
}

status_t DeviceHalAidl::dump(int __unused, const Vector<String16>& __unused) {
    ALOGE("%s not implemented yet", __func__);
    return OK;
};

int32_t DeviceHalAidl::supportsBluetoothVariableLatency(bool* supports __unused) override {
    ALOGE("%s not implemented yet", __func__);
    return INVALID_OPERATION;
}
