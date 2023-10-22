/*
 *
 * Copyright 2015, The Android Open Source Project
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
#include <sys/types.h>

#include <system/audio.h>
#include <utils/Errors.h>
#include <utils/RefBase.h>

namespace android {

class AudioHwDevice;
class DeviceHalInterface;
class StreamOutHalInterface;

/**
 * Managed access to a HAL output stream.
 */
class AudioStreamOut {
public:
    AudioHwDevice * const audioHwDev;
    sp<StreamOutHalInterface> stream;
    const audio_output_flags_t flags;

    [[nodiscard]] sp<DeviceHalInterface> hwDev() const;

    AudioStreamOut(AudioHwDevice *dev, audio_output_flags_t flags);

    virtual status_t open(
            audio_io_handle_t handle,
            audio_devices_t deviceType,
            struct audio_config *config,
            const char *address);

    virtual ~AudioStreamOut();

    // Get the bottom 32-bits of the 64-bit render position.
    status_t getRenderPosition(uint32_t *frames);

    virtual status_t getRenderPosition(uint64_t *frames);

    virtual status_t getPresentationPosition(uint64_t *frames, struct timespec *timestamp);

    /**
    * Write audio buffer to driver. Returns number of bytes written, or a
    * negative status_t. If at least one frame was written successfully prior to the error,
    * it is suggested that the driver return that successful (short) byte count
    * and then return an error in the subsequent call.
    *
    * If set_callback() has previously been called to enable non-blocking mode
    * the write() is not allowed to block. It must write only the number of
    * bytes that currently fit in the driver/hardware buffer and then return
    * this byte count. If this is less than the requested write size the
    * callback function must be called when more space is available in the
    * driver/hardware buffer.
    */
    virtual ssize_t write(const void *buffer, size_t bytes);

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

    virtual status_t flush();
    virtual status_t standby();

    // Avoid suppressing retrograde motion in mRenderPosition for gapless offload/direct when
    // transitioning between tracks.
    // The HAL resets the frame position without flush/stop being called, but calls back prior to
    // this event. So, on the next occurrence of retrograde motion, we permit backwards movement of
    // mRenderPosition.
    virtual void presentationComplete() { mExpectRetrograde = true; }

protected:
    uint64_t mFramesWritten = 0; // reset by flush
    uint64_t mFramesWrittenAtStandby = 0;
    uint64_t mRenderPosition = 0; // reset by flush, standby, or presentation complete
    int mRateMultiplier = 1;
    bool mHalFormatHasProportionalFrames = false;
    size_t mHalFrameSize = 0;
    bool mExpectRetrograde = false; // see presentationComplete
};

} // namespace android
