/*
 * Copyright (C) 2022 The Android Open Source Project
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

#include <utility>

#define LOG_TAG "AidlConversionNdk"
//#define LOG_NDEBUG 0
#include <utils/Log.h>

#include <media/AidlConversionCppNdk.h>
#include <media/AidlConversionNdk.h>

////////////////////////////////////////////////////////////////////////////////////////////////////
// AIDL NDK backend to legacy audio data structure conversion utilities.

namespace aidl {
namespace android {

// buffer_provider_t is not supported thus skipped
ConversionResult<buffer_config_t> aidl2legacy_AudioConfigBase_buffer_config_t(
        const media::audio::common::AudioConfigBase& aidl, bool isInput) {
    buffer_config_t legacy;

    legacy.samplingRate = VALUE_OR_RETURN(convertIntegral<uint32_t>(aidl.sampleRate));
    legacy.mask |= EFFECT_CONFIG_SMP_RATE;

    legacy.channels = VALUE_OR_RETURN(
            aidl2legacy_AudioChannelLayout_audio_channel_mask_t(aidl.channelMask, isInput));
    legacy.mask |= EFFECT_CONFIG_CHANNELS;

    legacy.format = VALUE_OR_RETURN(aidl2legacy_AudioFormatDescription_audio_format_t(aidl.format));
    legacy.mask |= EFFECT_CONFIG_FORMAT;

    // TODO: add accessMode and mask
    return legacy;
}

ConversionResult<media::audio::common::AudioConfigBase>
legacy2aidl_buffer_config_t_AudioConfigBase(const buffer_config_t& legacy, bool isInput) {
    media::audio::common::AudioConfigBase aidl;

    if (legacy.mask & EFFECT_CONFIG_SMP_RATE) {
        aidl.sampleRate = VALUE_OR_RETURN(convertIntegral<int32_t>(legacy.samplingRate));
    }
    if (legacy.mask & EFFECT_CONFIG_CHANNELS) {
        aidl.channelMask = VALUE_OR_RETURN(legacy2aidl_audio_channel_mask_t_AudioChannelLayout(
                static_cast<audio_channel_mask_t>(legacy.channels), isInput));
    }
    if (legacy.mask & EFFECT_CONFIG_FORMAT) {
        aidl.format = VALUE_OR_RETURN(legacy2aidl_audio_format_t_AudioFormatDescription(
                static_cast<audio_format_t>(legacy.format)));
    }

    // TODO: add accessMode and mask
    return aidl;
}

}  // namespace android
}  // aidl
