/*
 * Copyright (C) 2016 The Android Open Source Project
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

#ifndef ANDROID_HARDWARE_DEVICE_HAL_HIDL_H
#define ANDROID_HARDWARE_DEVICE_HAL_HIDL_H

#include PATH(android/hardware/audio/FILE_VERSION/IDevice.h)
#include PATH(android/hardware/audio/FILE_VERSION/IPrimaryDevice.h)
#include <media/audiohal/DeviceHalInterface.h>
#include <media/audiohal/EffectHalInterface.h>

#include "CoreConversionHelperHidl.h"

namespace android {

class DeviceHalHidl : public DeviceHalInterface, public CoreConversionHelperHidl
{
  public:
    status_t getAudioPorts(std::vector<media::audio::common::AudioPort> *ports) override;

    status_t getAudioRoutes(std::vector<media::AudioRoute> *routes) override;

    status_t getSupportedModes(std::vector<media::audio::common::AudioMode> *modes) override;

    // Sets the value of 'devices' to a bitmask of 1 or more values of audio_devices_t.
    status_t getSupportedDevices(uint32_t *devices) override;

    // Check to see if the audio hardware interface has been initialized.
    status_t initCheck() override;

    // Set the audio volume of a voice call. Range is between 0.0 and 1.0.
    status_t setVoiceVolume(float volume) override;

    // Set the audio volume for all audio activities other than voice call.
    status_t setMasterVolume(float volume) override;

    // Get the current master volume value for the HAL.
    status_t getMasterVolume(float *volume) override;

    // Called when the audio mode changes.
    status_t setMode(audio_mode_t mode) override;

    // Muting control.
    status_t setMicMute(bool state) override;
    status_t getMicMute(bool *state) override;
    status_t setMasterMute(bool state) override;
    status_t getMasterMute(bool *state) override;

    // Set global audio parameters.
    status_t setParameters(const String8& kvPairs) override;

    // Get global audio parameters.
    status_t getParameters(const String8& keys, String8 *values) override;

    // Returns audio input buffer size according to parameters passed.
    status_t getInputBufferSize(const struct audio_config* config, size_t* size) override;

    // Creates and opens the audio hardware output stream. The stream is closed
    // by releasing all references to the returned object.
    status_t openOutputStream(audio_io_handle_t handle, audio_devices_t devices,
                              audio_output_flags_t flags, struct audio_config* config,
                              const char* address, sp<StreamOutHalInterface>* outStream) override;

    // Creates and opens the audio hardware input stream. The stream is closed
    // by releasing all references to the returned object.
    status_t openInputStream(audio_io_handle_t handle, audio_devices_t devices,
                             struct audio_config* config, audio_input_flags_t flags,
                             const char* address, audio_source_t source,
                             audio_devices_t outputDevice, const char* outputDeviceAddress,
                             sp<StreamInHalInterface>* inStream) override;

    // Returns whether createAudioPatch and releaseAudioPatch operations are supported.
    status_t supportsAudioPatches(bool* supportsPatches) override;

    // Creates an audio patch between several source and sink ports.
    status_t createAudioPatch(unsigned int num_sources, const struct audio_port_config* sources,
                              unsigned int num_sinks, const struct audio_port_config* sinks,
                              audio_patch_handle_t* patch) override;

    // Releases an audio patch.
    status_t releaseAudioPatch(audio_patch_handle_t patch) override;

    // Fills the list of supported attributes for a given audio port.
    status_t getAudioPort(struct audio_port *port) override;

    // Fills the list of supported attributes for a given audio port.
    status_t getAudioPort(struct audio_port_v7 *port) override;

    // Set audio port configuration.
    status_t setAudioPortConfig(const struct audio_port_config *config) override;

    // List microphones
    status_t getMicrophones(std::vector<audio_microphone_characteristic_t>* microphones) override;

    status_t addDeviceEffect(
            const struct audio_port_config *device, sp<EffectHalInterface> effect) override;
    status_t removeDeviceEffect(
            const struct audio_port_config *device, sp<EffectHalInterface> effect) override;

    status_t getMmapPolicyInfos(
            media::audio::common::AudioMMapPolicyType policyType __unused,
            std::vector<media::audio::common::AudioMMapPolicyInfo> *policyInfos __unused) override {
        // TODO: Implement the HAL query when moving to AIDL HAL.
        return INVALID_OPERATION;
    }

    int32_t getAAudioMixerBurstCount() override {
        // TODO: Implement the HAL query when moving to AIDL HAL.
        return INVALID_OPERATION;
    }

    int32_t getAAudioHardwareBurstMinUsec() override {
        // TODO: Implement the HAL query when moving to AIDL HAL.
        return INVALID_OPERATION;
    }

    status_t supportsBluetoothVariableLatency(bool* supports) override;

    status_t setConnectedState(const struct audio_port_v7 *port, bool connected) override;

    status_t setSimulateDeviceConnections(bool enabled __unused) override {
        // Only supported by AIDL HALs.
        return INVALID_OPERATION;
    }

    error::Result<audio_hw_sync_t> getHwAvSync() override;

    status_t dump(int fd, const Vector<String16>& args) override;

    status_t getSoundDoseInterface(const std::string& module,
                                   ::ndk::SpAIBinder* soundDoseBinder) override;

    status_t prepareToDisconnectExternalDevice(const struct audio_port_v7* port) override;

  private:
    friend class DevicesFactoryHalHidl;
    sp<::android::hardware::audio::CPP_VERSION::IDevice> mDevice;
    // Null if it's not a primary device.
    sp<::android::hardware::audio::CPP_VERSION::IPrimaryDevice> mPrimaryDevice;
    bool supportsSetConnectedState7_1 = true;
    class SoundDoseWrapper;
    const std::unique_ptr<SoundDoseWrapper> mSoundDoseWrapper;
    std::set<audio_port_handle_t> mDeviceDisconnectionNotified;

    // Can not be constructed directly by clients.
    explicit DeviceHalHidl(const sp<::android::hardware::audio::CPP_VERSION::IDevice>& device);
    explicit DeviceHalHidl(
            const sp<::android::hardware::audio::CPP_VERSION::IPrimaryDevice>& device);

    // The destructor automatically closes the device.
    virtual ~DeviceHalHidl();

    template <typename HalPort> status_t getAudioPortImpl(HalPort *port);
};

} // namespace android

#endif // ANDROID_HARDWARE_DEVICE_HAL_HIDL_H
