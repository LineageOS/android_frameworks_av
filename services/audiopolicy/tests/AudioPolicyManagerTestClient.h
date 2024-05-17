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
                        audio_config_t * /*halConfig*/,
                        audio_config_base_t * /*mixerConfig*/,
                        const sp<DeviceDescriptorBase>& /*device*/,
                        uint32_t * /*latencyMs*/,
                        audio_output_flags_t /*flags*/) override {
        if (module >= mNextModuleHandle) {
            ALOGE("%s: Module handle %d has not been allocated yet (next is %d)",
                  __func__, module, mNextModuleHandle);
            return BAD_VALUE;
        }
        *output = mNextIoHandle++;
        return NO_ERROR;
    }

    audio_io_handle_t openDuplicateOutput(audio_io_handle_t /*output1*/,
                                          audio_io_handle_t /*output2*/) override {
        audio_io_handle_t id = mNextIoHandle++;
        return id;
    }

    status_t openInput(audio_module_handle_t module,
                       audio_io_handle_t *input,
                       audio_config_t * /*config*/,
                       audio_devices_t * /*device*/,
                       const String8 & /*address*/,
                       audio_source_t /*source*/,
                       audio_input_flags_t /*flags*/) override {
        if (module >= mNextModuleHandle) {
            ALOGE("%s: Module handle %d has not been allocated yet (next is %d)",
                  __func__, module, mNextModuleHandle);
            return BAD_VALUE;
        }
        *input = mNextIoHandle++;
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

    // Helper methods for tests
    size_t getActivePatchesCount() const { return mActivePatches.size(); }

    const struct audio_patch *getLastAddedPatch() const {
        if (mActivePatches.empty()) {
            return nullptr;
        }
        auto it = --mActivePatches.end();
        return &it->second;
    };

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
        mAudioParameters.addInt(String8(AudioParameter::keyStreamSupportedSamplingRates), 48000);
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

    status_t getAudioMixPort(const struct audio_port_v7 *devicePort __unused,
                             struct audio_port_v7 *mixPort) override {
        mixPort->num_audio_profiles = 0;
        for (auto format : mSupportedFormats) {
            const int i = mixPort->num_audio_profiles;
            mixPort->audio_profiles[i].format = format;
            mixPort->audio_profiles[i].num_sample_rates = 1;
            mixPort->audio_profiles[i].sample_rates[0] = 48000;
            mixPort->audio_profiles[i].num_channel_masks = 0;
            for (const auto& cm : mSupportedChannelMasks) {
                if (audio_channel_mask_is_valid(cm)) {
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

    bool getTrackInternalMute(audio_port_handle_t portId) {
        auto it = mTracksInternalMute.find(portId);
        return it == mTracksInternalMute.end() ? false : it->second;
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
    std::map<audio_port_handle_t, bool> mTracksInternalMute;
};

} // namespace android
