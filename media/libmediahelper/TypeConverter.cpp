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

#include <media/TypeConverter.h>

namespace android {

#define MAKE_STRING_FROM_ENUM(enumval) { #enumval, enumval }
#define TERMINATOR { .literal = nullptr }

template<>
const AudioModeConverter::Table AudioModeConverter::mTable[] = {
    MAKE_STRING_FROM_ENUM(AUDIO_MODE_INVALID),
    MAKE_STRING_FROM_ENUM(AUDIO_MODE_CURRENT),
    MAKE_STRING_FROM_ENUM(AUDIO_MODE_NORMAL),
    MAKE_STRING_FROM_ENUM(AUDIO_MODE_RINGTONE),
    MAKE_STRING_FROM_ENUM(AUDIO_MODE_IN_CALL),
    MAKE_STRING_FROM_ENUM(AUDIO_MODE_IN_COMMUNICATION),
    MAKE_STRING_FROM_ENUM(AUDIO_MODE_CALL_SCREEN),
    TERMINATOR
};

template <>
const AudioFlagConverter::Table AudioFlagConverter::mTable[] = {
    MAKE_STRING_FROM_ENUM(AUDIO_FLAG_NONE),
    MAKE_STRING_FROM_ENUM(AUDIO_FLAG_AUDIBILITY_ENFORCED),
    MAKE_STRING_FROM_ENUM(AUDIO_FLAG_SECURE),
    MAKE_STRING_FROM_ENUM(AUDIO_FLAG_SCO),
    MAKE_STRING_FROM_ENUM(AUDIO_FLAG_BEACON),
    MAKE_STRING_FROM_ENUM(AUDIO_FLAG_HW_AV_SYNC),
    MAKE_STRING_FROM_ENUM(AUDIO_FLAG_HW_HOTWORD),
    MAKE_STRING_FROM_ENUM(AUDIO_FLAG_BYPASS_INTERRUPTION_POLICY),
    MAKE_STRING_FROM_ENUM(AUDIO_FLAG_BYPASS_MUTE),
    MAKE_STRING_FROM_ENUM(AUDIO_FLAG_LOW_LATENCY),
    MAKE_STRING_FROM_ENUM(AUDIO_FLAG_DEEP_BUFFER),
    MAKE_STRING_FROM_ENUM(AUDIO_FLAG_NO_MEDIA_PROJECTION),
    MAKE_STRING_FROM_ENUM(AUDIO_FLAG_MUTE_HAPTIC),
    MAKE_STRING_FROM_ENUM(AUDIO_FLAG_NO_SYSTEM_CAPTURE),
    MAKE_STRING_FROM_ENUM(AUDIO_FLAG_CAPTURE_PRIVATE),
    TERMINATOR
};

template class TypeConverter<OutputDeviceTraits>;
template class TypeConverter<InputDeviceTraits>;
template class TypeConverter<DeviceTraits>;
template class TypeConverter<OutputFlagTraits>;
template class TypeConverter<InputFlagTraits>;
template class TypeConverter<FormatTraits>;
template class TypeConverter<OutputChannelTraits>;
template class TypeConverter<InputChannelTraits>;
template class TypeConverter<ChannelIndexTraits>;
template class TypeConverter<GainModeTraits>;
template class TypeConverter<StreamTraits>;
template class TypeConverter<AudioModeTraits>;
template class TypeConverter<UsageTraits>;
template class TypeConverter<SourceTraits>;
template class TypeConverter<AudioFlagTraits>;

SampleRateTraits::Collection samplingRatesFromString(
        const std::string &samplingRates, const char *del)
{
    SampleRateTraits::Collection samplingRateCollection;
    collectionFromString<SampleRateTraits>(samplingRates, samplingRateCollection, del);
    return samplingRateCollection;
}

FormatTraits::Collection formatsFromString(
        const std::string &formats, const char *del)
{
    FormatTraits::Collection formatCollection;
    FormatConverter::collectionFromString(formats, formatCollection, del);
    return formatCollection;
}

audio_format_t formatFromString(const std::string &literalFormat, audio_format_t defaultFormat)
{
    audio_format_t format;
    if (!literalFormat.empty() && FormatConverter::fromString(literalFormat, format)) {
        return format;
    }
    return defaultFormat;
}

audio_channel_mask_t channelMaskFromString(const std::string &literalChannels)
{
    audio_channel_mask_t channels;
    if (!literalChannels.empty() &&
            audio_channel_mask_from_string(literalChannels.c_str(), &channels)) {
        return channels;
    }
    return AUDIO_CHANNEL_INVALID;
}

ChannelTraits::Collection channelMasksFromString(
        const std::string &channels, const char *del)
{
    ChannelTraits::Collection channelMaskCollection;
    OutputChannelConverter::collectionFromString(channels, channelMaskCollection, del);
    InputChannelConverter::collectionFromString(channels, channelMaskCollection, del);
    ChannelIndexConverter::collectionFromString(channels, channelMaskCollection, del);
    return channelMaskCollection;
}

InputChannelTraits::Collection inputChannelMasksFromString(
        const std::string &inChannels, const char *del)
{
    InputChannelTraits::Collection inputChannelMaskCollection;
    InputChannelConverter::collectionFromString(inChannels, inputChannelMaskCollection, del);
    ChannelIndexConverter::collectionFromString(inChannels, inputChannelMaskCollection, del);
    return inputChannelMaskCollection;
}

OutputChannelTraits::Collection outputChannelMasksFromString(
        const std::string &outChannels, const char *del)
{
    OutputChannelTraits::Collection outputChannelMaskCollection;
    OutputChannelConverter::collectionFromString(outChannels, outputChannelMaskCollection, del);
    ChannelIndexConverter::collectionFromString(outChannels, outputChannelMaskCollection, del);
    return outputChannelMaskCollection;
}

}; // namespace android
