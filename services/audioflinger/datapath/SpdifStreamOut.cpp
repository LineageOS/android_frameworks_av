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

#define LOG_TAG "AudioFlinger"
//#define LOG_NDEBUG 0
#include "Configuration.h"
#include <system/audio.h>
#include <utils/Log.h>

#include <audio_utils/spdif/SPDIFEncoder.h>

#include "AudioHwDevice.h"
#include "SpdifStreamOut.h"

namespace android {

/**
 * If the AudioFlinger is processing encoded data and the HAL expects
 * PCM then we need to wrap the data in an SPDIF wrapper.
 */
SpdifStreamOut::SpdifStreamOut(AudioHwDevice *dev,
            audio_output_flags_t flags,
            audio_format_t format)
        // Tell the HAL that the data will be compressed audio wrapped in a data burst.
        : AudioStreamOut(dev, (audio_output_flags_t) (flags | AUDIO_OUTPUT_FLAG_IEC958_NONAUDIO))
        , mSpdifEncoder(this, format)
{
}

status_t SpdifStreamOut::open(
        audio_io_handle_t handle,
        audio_devices_t devices,
        struct audio_config *config,
        const char *address)
{
    struct audio_config customConfig = *config;

    mApplicationConfig.format = config->format;
    mApplicationConfig.sample_rate = config->sample_rate;
    mApplicationConfig.channel_mask = config->channel_mask;

    mRateMultiplier = spdif_rate_multiplier(config->format);
    if (mRateMultiplier <= 0) {
        ALOGE("ERROR SpdifStreamOut::open() unrecognized format 0x%08X\n", config->format);
        return BAD_VALUE;
    }
    customConfig.sample_rate = config->sample_rate * mRateMultiplier;

    customConfig.format = AUDIO_FORMAT_PCM_16_BIT;
    customConfig.channel_mask = AUDIO_CHANNEL_OUT_STEREO;

    // Always print this because otherwise it could be very confusing if the
    // HAL and AudioFlinger are using different formats.
    // Print before open() because HAL may modify customConfig.
    ALOGI("SpdifStreamOut::open() AudioFlinger requested sampleRate %d, format %#x,"
            " channelMask %#x", config->sample_rate, config->format, config->channel_mask);
    ALOGI("SpdifStreamOut::open() HAL configured for sampleRate %d, format %#x, channelMask %#x",
            customConfig.sample_rate, customConfig.format, customConfig.channel_mask);

    const status_t status = AudioStreamOut::open(
            handle,
            devices,
            &customConfig,
            address);

    ALOGI("SpdifStreamOut::open() status = %d", status);

#ifdef TEE_SINK
    if (status == OK) {
        // Don't use PCM 16-bit format to avoid WAV encoding IEC61937 data.
        mTee.set(customConfig.sample_rate,
                audio_channel_count_from_out_mask(customConfig.channel_mask),
                AUDIO_FORMAT_IEC61937, NBAIO_Tee::TEE_FLAG_OUTPUT_THREAD);
        mTee.setId(std::string("_") + std::to_string(handle) + "_D");
    }
#endif

    return status;
}

int SpdifStreamOut::flush()
{
    mSpdifEncoder.reset();
    return AudioStreamOut::flush();
}

int SpdifStreamOut::standby()
{
    mSpdifEncoder.reset();
    return AudioStreamOut::standby();
}

ssize_t SpdifStreamOut::writeDataBurst(const void* buffer, size_t bytes)
{
    const ssize_t written = AudioStreamOut::write(buffer, bytes);

#ifdef TEE_SINK
    if (written > 0) {
        mTee.write(reinterpret_cast<const char *>(buffer),
                written / AudioStreamOut::getFrameSize());
    }
#endif
    return written;
}

ssize_t SpdifStreamOut::write(const void* buffer, size_t numBytes)
{
    // Write to SPDIF wrapper. It will call back to writeDataBurst().
    return mSpdifEncoder.write(buffer, numBytes);
}

} // namespace android
