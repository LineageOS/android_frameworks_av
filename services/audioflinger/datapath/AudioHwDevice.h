/*
 *
 * Copyright 2007, The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#pragma once

#include <stdint.h>
#include <stdlib.h>
#include <sys/types.h>

#include <android/media/audio/common/AudioMMapPolicyInfo.h>
#include <android/media/audio/common/AudioMMapPolicyType.h>
#include <media/audiohal/DeviceHalInterface.h>
#include <utils/Errors.h>
#include <system/audio.h>

namespace android {

class AudioStreamIn;
class AudioStreamOut;

class AudioHwDevice {
public:
    enum Flags {
        AHWD_CAN_SET_MASTER_VOLUME  = 0x1,
        AHWD_CAN_SET_MASTER_MUTE    = 0x2,
        // Means that this isn't a terminal module, and software patches
        // are used to transport audio data further.
        AHWD_IS_INSERT              = 0x4,
        // This Module supports BT Latency mode control
        AHWD_SUPPORTS_BT_LATENCY_MODES = 0x8,
    };

    AudioHwDevice(audio_module_handle_t handle,
                  const char *moduleName,
                  const sp<DeviceHalInterface>& hwDevice,
                  Flags flags)
        : mHandle(handle)
        , mModuleName(strdup(moduleName))
        , mHwDevice(hwDevice)
        , mFlags(flags) { }
    virtual ~AudioHwDevice() { free((void *)mModuleName); }

    [[nodiscard]] bool canSetMasterVolume() const {
        return (0 != (mFlags & AHWD_CAN_SET_MASTER_VOLUME));
    }

    [[nodiscard]] bool canSetMasterMute() const {
        return (0 != (mFlags & AHWD_CAN_SET_MASTER_MUTE));
    }

    [[nodiscard]] bool isInsert() const {
        return (0 != (mFlags & AHWD_IS_INSERT));
    }

    [[nodiscard]] bool supportsBluetoothVariableLatency() const {
        return (0 != (mFlags & AHWD_SUPPORTS_BT_LATENCY_MODES));
    }

   [[nodiscard]] audio_module_handle_t handle() const { return mHandle; }
   [[nodiscard]] const char *moduleName() const { return mModuleName; }
   [[nodiscard]] sp<DeviceHalInterface> hwDevice() const { return mHwDevice; }

    /** This method creates and opens the audio hardware output stream.
     * The "address" parameter qualifies the "devices" audio device type if needed.
     * The format format depends on the device type:
     * - Bluetooth devices use the MAC address of the device in the form "00:11:22:AA:BB:CC"
     * - USB devices use the ALSA card and device numbers in the form  "card=X;device=Y"
     * - Other devices may use a number or any other string.
     */
    status_t openOutputStream(
            AudioStreamOut **ppStreamOut,
            audio_io_handle_t handle,
            audio_devices_t deviceType,
            audio_output_flags_t flags,
            struct audio_config *config,
            const char *address);

    status_t openInputStream(
            AudioStreamIn **ppStreamIn,
            audio_io_handle_t handle,
            audio_devices_t deviceType,
            audio_input_flags_t flags,
            struct audio_config *config,
            const char *address,
            audio_source_t source,
            audio_devices_t outputDevice,
            const char *outputDeviceAddress);

    [[nodiscard]] bool supportsAudioPatches() const;

    [[nodiscard]] status_t getAudioPort(struct audio_port_v7 *port) const;

    [[nodiscard]] status_t getMmapPolicyInfos(
            media::audio::common::AudioMMapPolicyType policyType,
            std::vector<media::audio::common::AudioMMapPolicyInfo> *policyInfos) const;

    [[nodiscard]] int32_t getAAudioMixerBurstCount() const;

    [[nodiscard]] int32_t getAAudioHardwareBurstMinUsec() const;

    [[nodiscard]] status_t getAudioMixPort(const struct audio_port_v7 *devicePort,
                                           struct audio_port_v7 *mixPort) const;

private:
    const audio_module_handle_t mHandle;
    const char * const          mModuleName;
    sp<DeviceHalInterface>      mHwDevice;
    const Flags                 mFlags;
};

} // namespace android
