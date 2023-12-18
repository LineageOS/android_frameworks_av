/*
 * Copyright (C) 2023 The Android Open Source Project
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

#pragma once

#include "AudioHwDevice.h"
#include <media/audiohal/DeviceHalInterface.h>
#include <media/audiohal/StreamHalInterface.h>

namespace android {

// Abstraction for the Audio Source for the RecordThread (HAL or PassthruPatchRecord).
struct Source {
    virtual ~Source() = default;
    // The following methods have the same signatures as in StreamHalInterface.
    virtual status_t read(void* buffer, size_t bytes, size_t* read) = 0;
    virtual status_t getCapturePosition(int64_t* frames, int64_t* time) = 0;
    virtual status_t standby() = 0;
};

/**
 * Managed access to a HAL input stream.
 */
class AudioStreamIn : public Source {
public:
    const AudioHwDevice* const audioHwDev;
    sp<StreamInHalInterface> stream;
    const audio_input_flags_t flags;

    [[nodiscard]] sp<DeviceHalInterface> hwDev() const;

    AudioStreamIn(AudioHwDevice *dev, audio_input_flags_t flags);

    virtual status_t open(
            audio_io_handle_t handle,
            audio_devices_t deviceType,
            struct audio_config *config,
            const char *address,
            audio_source_t source,
            audio_devices_t outputDevice,
            const char *outputDeviceAddress);

    ~AudioStreamIn() override;

    status_t getCapturePosition(int64_t* frames, int64_t* time) override;

    status_t read(void* buffer, size_t bytes, size_t* read) override;

    /**
     * @return frame size from the perspective of the application and the AudioFlinger.
     */
    [[nodiscard]] virtual size_t getFrameSize() const { return mHalFrameSize; }

    /**
     * @return audio stream configuration: channel mask, format, sample rate:
     *   - channel mask from the perspective of the application and the AudioFlinger,
     *     The HAL is in stereo mode when playing multi-channel compressed audio over HDMI;
     *   - format from the perspective of the application and the AudioFlinger;
     *   - sample rate from the perspective of the application and the AudioFlinger,
     *     The HAL may be running at a higher sample rate if, for example, playing wrapped EAC3.
     */
    [[nodiscard]] virtual audio_config_base_t getAudioProperties() const;

    status_t standby() override;

protected:
    uint64_t mFramesRead = 0;
    int64_t mFramesReadAtStandby = 0;
    int mRateMultiplier = 1;
    bool mHalFormatHasProportionalFrames = false;
    size_t mHalFrameSize = 0;
};

}  // namespace android
