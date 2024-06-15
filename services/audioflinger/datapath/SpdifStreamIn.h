/*
 *
 * Copyright 2023, The Android Open Source Project
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

#include "AudioStreamIn.h"

#include <audio_utils/spdif/SPDIFDecoder.h>
#include <afutils/NBAIO_Tee.h>

namespace android {

/**
 * Stream that is a PCM data burst in the HAL but looks like an encoded stream
 * to the AudioFlinger. Wraps encoded data in an SPDIF wrapper per IEC61973-3.
 */
class SpdifStreamIn : public AudioStreamIn {
public:

    SpdifStreamIn(AudioHwDevice *dev, audio_input_flags_t flags,
            audio_format_t format);

    status_t open(
            audio_io_handle_t handle,
            audio_devices_t devices,
            struct audio_config *config,
            const char *address,
            audio_source_t source,
            audio_devices_t outputDevice,
            const char* outputDeviceAddress) override;

    /**
    * Read audio buffer from driver. If at least one frame was read successfully prior to the error,
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
    status_t read(void* buffer, size_t bytes, size_t* read) override;

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
     * The HAL may be running at a higher sample rate if, for example, reading wrapped EAC3.
     * @return sample rate from the perspective of the application and the AudioFlinger.
     */
    [[nodiscard]] virtual uint32_t getSampleRate() const { return mApplicationConfig.sample_rate; }

    /**
     * The HAL is in stereo mode when reading multi-channel compressed audio.
     * @return channel mask from the perspective of the application and the AudioFlinger.
     */
    [[nodiscard]] virtual audio_channel_mask_t getChannelMask() const {
        return mApplicationConfig.channel_mask;
    }

    status_t standby() override;

private:

    class MySPDIFDecoder : public SPDIFDecoder
    {
    public:
        MySPDIFDecoder(SpdifStreamIn *spdifStreamIn, audio_format_t format)
          :  SPDIFDecoder(format)
          , mSpdifStreamIn(spdifStreamIn)
        {
        }

        ssize_t readInput(void* buffer, size_t bytes) override
        {
            size_t bytesRead = 0;
            const auto result = mSpdifStreamIn->readDataBurst(buffer, bytes, &bytesRead);
            if (result < 0) {
                return result;
            }
            return bytesRead;
        }

    protected:
        SpdifStreamIn * const mSpdifStreamIn;
    };

    MySPDIFDecoder mSpdifDecoder;
    audio_config_base_t mApplicationConfig = AUDIO_CONFIG_BASE_INITIALIZER;

    status_t readDataBurst(void* data, size_t bytes, size_t* read);

#ifdef TEE_SINK
    NBAIO_Tee mTee;
#endif

};

} // namespace android
