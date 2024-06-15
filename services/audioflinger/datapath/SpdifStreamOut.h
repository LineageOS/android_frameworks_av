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

#include "AudioStreamOut.h"

#include <afutils/NBAIO_Tee.h>
#include <audio_utils/spdif/SPDIFEncoder.h>

namespace android {

/**
 * Stream that is a PCM data burst in the HAL but looks like an encoded stream
 * to the AudioFlinger. Wraps encoded data in an SPDIF wrapper per IEC61973-3.
 */
class SpdifStreamOut : public AudioStreamOut {
public:

    SpdifStreamOut(AudioHwDevice *dev, audio_output_flags_t flags,
            audio_format_t format);

    status_t open(
            audio_io_handle_t handle,
            audio_devices_t devices,
            struct audio_config *config,
            const char *address) override;

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
    ssize_t write(const void* buffer, size_t bytes) override;

    /**
     * @return frame size from the perspective of the application and the AudioFlinger.
     */
    [[nodiscard]] size_t getFrameSize() const override { return sizeof(int8_t); }

    /**
     * @return audio_config_base_t from the perspective of the application and the AudioFlinger.
     */
    [[nodiscard]] audio_config_base_t getAudioProperties() const override {
        return mApplicationConfig;
    }

    /**
     * @return format from the perspective of the application and the AudioFlinger.
     */
    [[nodiscard]] virtual audio_format_t getFormat() const { return mApplicationConfig.format; }

    /**
     * The HAL may be running at a higher sample rate if, for example, playing wrapped EAC3.
     * @return sample rate from the perspective of the application and the AudioFlinger.
     */
    [[nodiscard]] virtual uint32_t getSampleRate() const { return mApplicationConfig.sample_rate; }

    /**
     * The HAL is in stereo mode when playing multi-channel compressed audio over HDMI.
     * @return channel mask from the perspective of the application and the AudioFlinger.
     */
    [[nodiscard]] virtual audio_channel_mask_t getChannelMask() const {
        return mApplicationConfig.channel_mask;
    }

    status_t flush() override;
    status_t standby() override;

private:

    class MySPDIFEncoder : public SPDIFEncoder
    {
    public:
        MySPDIFEncoder(SpdifStreamOut *spdifStreamOut, audio_format_t format)
          :  SPDIFEncoder(format)
          , mSpdifStreamOut(spdifStreamOut)
        {
        }

        ssize_t writeOutput(const void* buffer, size_t bytes) override
        {
            return mSpdifStreamOut->writeDataBurst(buffer, bytes);
        }
    protected:
        SpdifStreamOut * const mSpdifStreamOut;
    };

    MySPDIFEncoder mSpdifEncoder;
    audio_config_base_t mApplicationConfig = AUDIO_CONFIG_BASE_INITIALIZER;

    ssize_t writeDataBurst(const void* data, size_t bytes);

#ifdef TEE_SINK
    NBAIO_Tee mTee;
#endif

};

} // namespace android
