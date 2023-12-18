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
#include "AudioStreamIn.h"

#include <media/audiohal/DeviceHalInterface.h>
#include <media/audiohal/StreamHalInterface.h>
#include <system/audio.h>
#include <utils/Log.h>

#include "AudioHwDevice.h"

namespace android {

// ----------------------------------------------------------------------------
AudioStreamIn::AudioStreamIn(AudioHwDevice *dev, audio_input_flags_t flags)
        : audioHwDev(dev)
        , flags(flags)
{
}

// This must be defined here together with the HAL includes above and
// not solely in the header.
AudioStreamIn::~AudioStreamIn() = default;

sp<DeviceHalInterface> AudioStreamIn::hwDev() const
{
    return audioHwDev->hwDevice();
}

status_t AudioStreamIn::getCapturePosition(int64_t* frames, int64_t* time)
{
    if (stream == nullptr) {
        return NO_INIT;
    }

    int64_t halPosition = 0;
    const status_t status = stream->getCapturePosition(&halPosition, time);
    if (status != NO_ERROR) {
        return status;
    }

    // Adjust for standby using HAL rate frames.
    // Only apply this correction if the HAL is getting PCM frames.
    if (mHalFormatHasProportionalFrames) {
        const uint64_t adjustedPosition = (halPosition <= mFramesReadAtStandby) ?
                0 : (halPosition - mFramesReadAtStandby);
        // Scale from HAL sample rate to application rate.
        *frames = adjustedPosition / mRateMultiplier;
    } else {
        // For compressed formats.
        *frames = halPosition;
    }

    return status;
}

status_t AudioStreamIn::open(
        audio_io_handle_t handle,
        audio_devices_t deviceType,
        struct audio_config *config,
        const char *address,
        audio_source_t source,
        audio_devices_t outputDevice,
        const char *outputDeviceAddress)
{
    sp<StreamInHalInterface> inStream;

    int status = hwDev()->openInputStream(
            handle,
            deviceType,
            config,
            flags,
            address,
            source,
            outputDevice,
            outputDeviceAddress,
            &inStream);
    ALOGV("AudioStreamIn::open(), HAL returned stream %p, sampleRate %d, format %#x,"
            " channelMask %#x, status %d", inStream.get(), config->sample_rate, config->format,
            config->channel_mask, status);

    if (status == NO_ERROR) {
        stream = inStream;
        mHalFormatHasProportionalFrames = audio_has_proportional_frames(config->format);
        status = stream->getFrameSize(&mHalFrameSize);
        LOG_ALWAYS_FATAL_IF(status != OK, "Error retrieving frame size from HAL: %d", status);
        LOG_ALWAYS_FATAL_IF(mHalFrameSize == 0, "Error frame size was %zu but must be greater than"
                " zero", mHalFrameSize);
    }

    return status;
}

audio_config_base_t AudioStreamIn::getAudioProperties() const
{
    audio_config_base_t result = AUDIO_CONFIG_BASE_INITIALIZER;
    if (stream->getAudioProperties(&result) != OK) {
        result.sample_rate = 0;
        result.channel_mask = AUDIO_CHANNEL_INVALID;
        result.format = AUDIO_FORMAT_INVALID;
    }
    return result;
}

status_t AudioStreamIn::standby()
{
    mFramesReadAtStandby = mFramesRead;
    return stream->standby();
}

status_t AudioStreamIn::read(void* buffer, size_t bytes, size_t* read)
{
    const status_t result = stream->read(buffer, bytes, read);
    if (result == OK && *read > 0 && mHalFrameSize > 0) {
        mFramesRead += *read / mHalFrameSize;
    }
    return result;
}

} // namespace android
