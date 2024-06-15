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

#define LOG_TAG "AudioFlinger"
//#define LOG_NDEBUG 0
#include "Configuration.h"
#include <system/audio.h>
#include <utils/Log.h>

#include <audio_utils/spdif/SPDIFDecoder.h>

#include "AudioHwDevice.h"
#include "SpdifStreamIn.h"

namespace android {

/**
 * If the HAL is generating IEC61937 data and AudioFlinger expects elementary stream then we need to
 * extract the data using an SPDIF decoder.
 */
SpdifStreamIn::SpdifStreamIn(AudioHwDevice *dev,
            audio_input_flags_t flags,
            audio_format_t format)
        : AudioStreamIn(dev, flags)
        , mSpdifDecoder(this, format)
{
}

status_t SpdifStreamIn::open(
        audio_io_handle_t handle,
        audio_devices_t devices,
        struct audio_config *config,
        const char *address,
        audio_source_t source,
        audio_devices_t outputDevice,
        const char* outputDeviceAddress)
{
    struct audio_config customConfig = *config;

    mApplicationConfig.format = config->format;
    mApplicationConfig.sample_rate = config->sample_rate;
    mApplicationConfig.channel_mask = config->channel_mask;

    mRateMultiplier = spdif_rate_multiplier(config->format);
    if (mRateMultiplier <= 0) {
        ALOGE("ERROR SpdifStreamIn::open() unrecognized format 0x%08X\n", config->format);
        return BAD_VALUE;
    }
    customConfig.sample_rate = config->sample_rate * mRateMultiplier;
    customConfig.format = AUDIO_FORMAT_PCM_16_BIT;
    customConfig.channel_mask = AUDIO_CHANNEL_IN_STEREO;

    // Always print this because otherwise it could be very confusing if the
    // HAL and AudioFlinger are using different formats.
    // Print before open() because HAL may modify customConfig.
    ALOGI("SpdifStreamIn::open() AudioFlinger requested sampleRate %d, format %#x, channelMask %#x",
            config->sample_rate, config->format, config->channel_mask);
    ALOGI("SpdifStreamIn::open() HAL configured for sampleRate %d, format %#x, channelMask %#x",
            customConfig.sample_rate, customConfig.format, customConfig.channel_mask);

    const status_t status = AudioStreamIn::open(
            handle,
            devices,
            &customConfig,
            address,
            source,
            outputDevice,
            outputDeviceAddress);

    ALOGI("SpdifStreamIn::open() status = %d", status);

#ifdef TEE_SINK
    if (status == OK) {
        // Don't use PCM 16-bit format to avoid WAV encoding IEC61937 data.
        mTee.set(customConfig.sample_rate,
                audio_channel_count_from_in_mask(customConfig.channel_mask),
                AUDIO_FORMAT_IEC61937, NBAIO_Tee::TEE_FLAG_INPUT_THREAD);
        mTee.setId(std::string("_") + std::to_string(handle) + "_C");
    }
#endif

    return status;
}

int SpdifStreamIn::standby()
{
    mSpdifDecoder.reset();
    return AudioStreamIn::standby();
}

status_t SpdifStreamIn::readDataBurst(void* buffer, size_t bytes, size_t* read)
{
    status_t status = AudioStreamIn::read(buffer, bytes, read);

#ifdef TEE_SINK
    if (*read > 0) {
        mTee.write(reinterpret_cast<const char *>(buffer), *read / AudioStreamIn::getFrameSize());
    }
#endif
    return status;
}

status_t SpdifStreamIn::read(void* buffer, size_t numBytes, size_t* read)
{
    // Read from SPDIF extractor. It will call back to readDataBurst().
    const auto bytesRead = mSpdifDecoder.read(buffer, numBytes);
    if (bytesRead >= 0) {
        *read = bytesRead;
        return OK;
    }
    return NOT_ENOUGH_DATA;
}

} // namespace android
