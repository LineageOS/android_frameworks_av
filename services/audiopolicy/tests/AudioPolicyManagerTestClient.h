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

#include <map>
#include <set>

#include <com_android_media_audio.h>
#include <com_android_media_audioserver.h>
#include <media/TypeConverter.h>
#include <system/audio.h>
#include <utils/Log.h>
#include <utils/String8.h>

#include "AudioPolicyTestClient.h"

namespace android {

class AudioPolicyManagerTestClient : public AudioPolicyTestClient {
public:
    // AudioPolicyClientInterface implementation
    audio_module_handle_t loadHwModule(const char* name) override {
        if (!mAllowedModuleNames.empty() && !mAllowedModuleNames.count(name)) {
            return AUDIO_MODULE_HANDLE_NONE;
        }
        return mNextModuleHandle++;
    }

    status_t openOutput(audio_module_handle_t module,
                        audio_io_handle_t *output,
                        audio_config_t *halConfig,
                        audio_config_base_t *mixerConfig,
                        const sp<DeviceDescriptorBase>& device,
                        uint32_t * /*latencyMs*/,
                        audio_output_flags_t *flags,
                        audio_attributes_t /*attributes*/,
                        int32_t mixPortId) override {
        if (module >= mNextModuleHandle) {
            ALOGE("%s: Module handle %d has not been allocated yet (next is %d)",
                  __func__, module, mNextModuleHandle);
            return BAD_VALUE;
        }

        const auto deviceKey = std::make_pair(device->type(), device->address());
        // Check if the route is artificially forbidden in the test case.
        if (mNonRoutableMixPortsForDevice.count(deviceKey) &&
              mNonRoutableMixPortsForDevice[deviceKey].count(mixPortId)) {
            return INVALID_OPERATION;
        }

        *output = mNextIoHandle++;
        mOpenedOutputs[*output] = *flags;
        mIoHandleToMixPortId[*output] = mixPortId;
        ALOGD("%s: opened output %d: HAL(%s %s %d) Mixer(%s %s %d) %s", __func__, *output,
              audio_channel_out_mask_to_string(halConfig->channel_mask),
              audio_format_to_string(halConfig->format), halConfig->sample_rate,
              audio_channel_out_mask_to_string(mixerConfig->channel_mask),
              audio_format_to_string(mixerConfig->format), mixerConfig->sample_rate,
              android::toString(*flags).c_str());
        return NO_ERROR;
    }

    audio_io_handle_t openDuplicateOutput(audio_io_handle_t /*output1*/,
                                          audio_io_handle_t /*output2*/) override {
        audio_io_handle_t id = mNextIoHandle++;
        return id;
    }

    status_t closeOutput(audio_io_handle_t output) override {
        if (auto iter = mOpenedOutputs.find(output); iter != mOpenedOutputs.end()) {
            mOpenedOutputs.erase(iter);
            mIoHandleToMixPortId.erase(output);
            return NO_ERROR;
        } else {
            ALOGE("%s: Unknown output %d", __func__, output);
            return BAD_VALUE;
        }
    }

    status_t openInput(audio_module_handle_t module,
                       audio_io_handle_t *input,
                       audio_config_t * /*config*/,
                       audio_devices_t *device,
                       const String8 &address,
                       audio_source_t /*source*/,
                       audio_input_flags_t /*flags*/,
                       int32_t mixPortId) override {
        if (module >= mNextModuleHandle) {
            ALOGE("%s: Module handle %d has not been allocated yet (next is %d)",
                  __func__, module, mNextModuleHandle);
            return BAD_VALUE;
        }

        const auto deviceKey = std::make_pair(*device, std::string(address.c_str()));
        // Check if the route is artificially forbidden in the test case.
        if (mNonRoutableMixPortsForDevice.count(deviceKey) &&
              mNonRoutableMixPortsForDevice[deviceKey].count(mixPortId)) {
            return INVALID_OPERATION;
        }

        *input = mNextIoHandle++;
        mOpenedInputs.insert(*input);
        mIoHandleToMixPortId[*input] = mixPortId;
        ALOGD("%s: opened input %d", __func__, *input);
        mOpenInputCallsCount++;
        return NO_ERROR;
    }

    status_t closeInput(audio_io_handle_t input) override {
        if (mOpenedInputs.erase(input) != 1) {
            if (input >= mNextIoHandle) {
                ALOGE("%s: I/O handle %d has not been allocated yet (next is %d)",
                      __func__, input, mNextIoHandle);
            } else {
                ALOGE("%s: Attempt to close input %d twice", __func__, input);
            }
            return BAD_VALUE;
        }
        mIoHandleToMixPortId.erase(input);
        ALOGD("%s: closed input %d", __func__, input);
        mCloseInputCallsCount++;
        return NO_ERROR;
    }

    status_t createAudioPatch(const struct audio_patch *patch,
                              audio_patch_handle_t *handle,
                              int /*delayMs*/) override {
        auto iter = mActivePatches.find(*handle);
        if (iter != mActivePatches.end()) {
            mActivePatches.erase(*handle);
        }
        *handle = mNextPatchHandle++;
        mActivePatches.insert(std::make_pair(*handle, *patch));
        return NO_ERROR;
    }

    status_t releaseAudioPatch(audio_patch_handle_t handle,
                               int /*delayMs*/) override {
        if (mActivePatches.erase(handle) != 1) {
            if (handle >= mNextPatchHandle) {
                ALOGE("%s: Patch handle %d has not been allocated yet (next is %d)",
                      __func__, handle, mNextPatchHandle);
            } else {
                ALOGE("%s: Attempt to release patch %d twice", __func__, handle);
            }
            return BAD_VALUE;
        }
        return NO_ERROR;
    }

    void onAudioPortListUpdate() override {
        ++mAudioPortListUpdateCount;
    }

    status_t setDeviceConnectedState(const struct audio_port_v7 *port,
                                     media::DeviceConnectedState state) override {
        if (state == media::DeviceConnectedState::CONNECTED) {
            mConnectedDevicePorts.push_back(*port);
        } else if (state == media::DeviceConnectedState::DISCONNECTED){
            mDisconnectedDevicePorts.push_back(*port);
        }
        return NO_ERROR;
    }

    status_t setPortsVolume(const std::vector<audio_port_handle_t> & ports, float volume,
                            bool /*muted*/, audio_io_handle_t /*output*/,
                            int /*delayMs*/) override {
        for (auto port : ports) {
            mPortVolumes.insert_or_assign(port, volume);
        }
        return OK;
    }

    float getPortVolume(audio_port_handle_t portId) const {
        auto it = mPortVolumes.find(portId);
        return it == mPortVolumes.end() ? -1. : it->second;
    }

    void resetPortVolumes() {
        mPortVolumes.clear();
    }

    status_t setAudioPortConfig(const struct audio_port_config* config,
                                int /*delayMs*/) override {
        mPortConfigurations.insert_or_assign(config->id, *config);
        return OK;
    }

    struct audio_port_config *getPortConfiguration(audio_port_handle_t portId) {
        auto it = mPortConfigurations.find(portId);
        return it == mPortConfigurations.end() ? nullptr : &(it->second);
    }

    void resetPortConfigurations() {
        mPortConfigurations.clear();
    }

    // Helper methods for tests
    size_t getActivePatchesCount() const { return mActivePatches.size(); }

    const struct audio_patch *getLastAddedPatch() const {
        if (mActivePatches.empty()) {
            return nullptr;
        }
        auto it = --mActivePatches.end();
        return &it->second;
    };

    size_t getOpenedInputsCount() const { return mOpenedInputs.size(); }

    audio_module_handle_t peekNextModuleHandle() const { return mNextModuleHandle; }

    void swapAllowedModuleNames(std::set<std::string>&& names = {}) {
        mAllowedModuleNames.swap(names);
    }

    size_t getAudioPortListUpdateCount() const { return mAudioPortListUpdateCount; }

    void onRoutingUpdated() override {
        mRoutingUpdatedUpdateCount++;
    }

    void resetRoutingUpdatedCounter() {
        mRoutingUpdatedUpdateCount = 0;
    }

    size_t getRoutingUpdatedCounter() const {
        return mRoutingUpdatedUpdateCount;
    }

    void onVolumeRangeInitRequest() override {

    }

    status_t updateSecondaryOutputs(
            const TrackSecondaryOutputsMap& trackSecondaryOutputs __unused) override {
        return NO_ERROR;
    }

    size_t getConnectedDevicePortCount() const {
        return mConnectedDevicePorts.size();
    }

    const struct audio_port_v7 *getLastConnectedDevicePort() const {
        if (mConnectedDevicePorts.empty()) {
            return nullptr;
        }
        auto it = --mConnectedDevicePorts.end();
        return &(*it);
    }

    size_t getDisconnectedDevicePortCount() const {
        return mDisconnectedDevicePorts.size();
    }

    const struct audio_port_v7 *getLastDisconnectedDevicePort() const {
        if (mDisconnectedDevicePorts.empty()) {
            return nullptr;
        }
        auto it = --mDisconnectedDevicePorts.end();
        return &(*it);
    }

    String8 getParameters(audio_io_handle_t /* ioHandle */, const String8&  /* keys*/ ) override {
        AudioParameter mAudioParameters;
        std::string formats;
        for (const auto& f : mSupportedFormats) {
            if (!formats.empty()) formats += AUDIO_PARAMETER_VALUE_LIST_SEPARATOR;
            formats += audio_format_to_string(f);
        }
        mAudioParameters.add(
                String8(AudioParameter::keyStreamSupportedFormats),
                String8(formats.c_str()));
        std::string sampleRates;
        for (auto sr : mSupportedSamplingRates) {
            if (!sampleRates.empty()) sampleRates += AUDIO_PARAMETER_VALUE_LIST_SEPARATOR;
            sampleRates += std::to_string(sr);
        }
        mAudioParameters.add(
                String8(AudioParameter::keyStreamSupportedSamplingRates),
                String8(sampleRates.c_str()));
        std::string channelMasks;
        for (const auto& cm : mSupportedChannelMasks) {
            if (!audio_channel_mask_is_valid(cm)) {
                continue;
            }
            if (!channelMasks.empty()) channelMasks += AUDIO_PARAMETER_VALUE_LIST_SEPARATOR;
            channelMasks += audio_channel_mask_to_string(cm);
        }
        mAudioParameters.add(
                String8(AudioParameter::keyStreamSupportedChannels), String8(channelMasks.c_str()));
        return mAudioParameters.toString();
    }

    status_t getAudioMixPort(const struct audio_port_v7 *devicePort,
                             struct audio_port_v7 *mixPort,
                             int32_t mixPortHalId) override {
        const audio_io_handle_t ioHandle = mixPort->ext.mix.handle;

        // Preserve the same behavior as the corresponding pre-flag logic.
        if ((!com::android::media::audioserver::enable_strict_port_routing_checks() ||
                !com::android::media::audio::check_route_in_get_audio_mix_port())
              && ioHandle == AUDIO_IO_HANDLE_NONE) {
            // If ioHandle is not supplied, this is certainly from a caller added after
            // the change this flag is introducing, and will anticipate routing checks.
            // However, in such an event, if the flag is disabled, the real pre-flag implementation
            // will end up in `BAD_VALUE`, and we want to align to that for now in this mocked
            // implementation. The trade-off is that the aformentioned caller must do the flag
            // check before calling into `getAudioMixPort`.
            return BAD_VALUE;
        } else {
            // Derive port ID from IO handle if specified.
            if (mixPortHalId == AUDIO_PORT_HANDLE_NONE && ioHandle != AUDIO_IO_HANDLE_NONE) {
                if (!mIoHandleToMixPortId.count(ioHandle)) {
                    return BAD_VALUE;
                }
                mixPortHalId = mIoHandleToMixPortId[ioHandle];
            }
        }

        // Check routing if port is identifiable by ID.
        // Note it is possible that we don't have the ID, in which case this
        // is not from an AIDL config, and we will just assume routable.
        if (mixPortHalId != AUDIO_PORT_HANDLE_NONE) {
            audio_devices_t deviceType = devicePort->ext.device.type;
            std::string deviceAddr = devicePort->ext.device.address;
            const auto deviceKey = std::make_pair(deviceType, deviceAddr);
            // Check if the route is artificially forbidden in the test case.
            if (mNonRoutableMixPortsForDevice.count(deviceKey) &&
                  mNonRoutableMixPortsForDevice[deviceKey].count(mixPortHalId)) {
                return INVALID_OPERATION;
            }
        }

        mixPort->num_audio_profiles = 0;
        const bool isInput = mixPort->role == AUDIO_PORT_ROLE_SINK;
        for (auto format : mSupportedFormats) {
            const int i = mixPort->num_audio_profiles;
            mixPort->audio_profiles[i].format = format;
            mixPort->audio_profiles[i].num_sample_rates = 0;
            for (auto sr : mSupportedSamplingRates) {
                mixPort->audio_profiles[i].sample_rates[
                        mixPort->audio_profiles[i].num_sample_rates++] = sr;
            }
            mixPort->audio_profiles[i].num_channel_masks = 0;
            for (const auto& cm : mSupportedChannelMasks) {
                if (audio_channel_mask_is_valid(cm) && audio_is_input_channel(cm) == isInput) {
                    mixPort->audio_profiles[i].channel_masks[
                            mixPort->audio_profiles[i].num_channel_masks++] = cm;
                }
            }
            mixPort->num_audio_profiles++;
        }
        return NO_ERROR;
    }

    status_t setTracksInternalMute(
            const std::vector<media::TrackInternalMuteInfo>& tracksInternalMute) override {
        for (const auto& trackInternalMute : tracksInternalMute) {
            mTracksInternalMute[(audio_port_handle_t)trackInternalMute.portId] =
                    trackInternalMute.muted;
        }
        return NO_ERROR;
    }

    void addSupportedFormat(audio_format_t format) {
        mSupportedFormats.insert(format);
    }

    void addSupportedChannelMask(audio_channel_mask_t channelMask) {
        mSupportedChannelMasks.insert(channelMask);
    }

    void addSupportedSamplingRate(int sampleRate) {
        mSupportedSamplingRates.insert(sampleRate);
    }

    bool getTrackInternalMute(audio_port_handle_t portId) {
        auto it = mTracksInternalMute.find(portId);
        return it == mTracksInternalMute.end() ? false : it->second;
    }
    void resetInputApiCallsCounters() {
        mOpenInputCallsCount = 0;
        mCloseInputCallsCount = 0;
    }

    size_t getCloseInputCallsCount() const {
        return mCloseInputCallsCount;
    }

    size_t getOpenInputCallsCount() const {
        return mOpenInputCallsCount;
    }

    std::optional<audio_output_flags_t> getOpenOutputFlags(audio_io_handle_t output) const {
        if (auto iter = mOpenedOutputs.find(output); iter != mOpenedOutputs.end()) {
            return iter->second;
        }
        return std::nullopt;
    }

    int32_t getMixPortIdByIoHandle(audio_io_handle_t ioHandle) {
        if (auto iter = mIoHandleToMixPortId.find(ioHandle); iter != mIoHandleToMixPortId.end()) {
            return iter->second;
        }
        return -1;
    }

    void setNonRoutableMixPortsForDevice(audio_devices_t type, std::string addr,
                                         const std::set<int32_t> &mixPortIds) {
        mNonRoutableMixPortsForDevice[std::make_pair(type, addr)] = mixPortIds;
    }

private:
    audio_module_handle_t mNextModuleHandle = AUDIO_MODULE_HANDLE_NONE + 1;
    audio_io_handle_t mNextIoHandle = AUDIO_IO_HANDLE_NONE + 1;
    audio_patch_handle_t mNextPatchHandle = AUDIO_PATCH_HANDLE_NONE + 1;
    std::map<audio_patch_handle_t, struct audio_patch> mActivePatches;
    std::set<std::string> mAllowedModuleNames;
    size_t mAudioPortListUpdateCount = 0;
    size_t mRoutingUpdatedUpdateCount = 0;
    std::vector<struct audio_port_v7> mConnectedDevicePorts;
    std::vector<struct audio_port_v7> mDisconnectedDevicePorts;
    std::set<audio_format_t> mSupportedFormats;
    std::set<audio_channel_mask_t> mSupportedChannelMasks;
    std::set<int> mSupportedSamplingRates;
    std::map<audio_port_handle_t, bool> mTracksInternalMute;
    std::set<audio_io_handle_t> mOpenedInputs;
    std::map<audio_port_handle_t, float> mPortVolumes;
    std::map<audio_port_handle_t, struct audio_port_config> mPortConfigurations;
    size_t mOpenInputCallsCount = 0;
    size_t mCloseInputCallsCount = 0;
    std::map<audio_io_handle_t, audio_output_flags_t> mOpenedOutputs;
    std::map<audio_io_handle_t, int32_t> mIoHandleToMixPortId;
    // This allows each test case to artificially decide if certain routes are
    // unavailable for a device described by its legacy type and address.
    std::map<std::pair<audio_devices_t, std::string>,
          std::set<int32_t>> mNonRoutableMixPortsForDevice;
};

} // namespace android
