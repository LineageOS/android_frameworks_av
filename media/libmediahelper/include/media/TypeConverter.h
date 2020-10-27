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

#ifndef ANDROID_TYPE_CONVERTER_H_
#define ANDROID_TYPE_CONVERTER_H_

#include <set>
#include <string>
#include <string.h>
#include <vector>

#include <system/audio.h>
#include <utils/Log.h>

#include <media/AudioParameter.h>
#include "convert.h"

namespace android {

template <typename T>
struct DefaultTraits
{
    typedef T Type;
    typedef std::vector<Type> Collection;
    static void add(Collection &collection, Type value)
    {
        collection.push_back(value);
    }
};
template <typename T>
struct SetTraits
{
    typedef T Type;
    typedef std::set<Type> Collection;
    static void add(Collection &collection, Type value)
    {
        collection.insert(value);
    }
};

using SampleRateTraits = SetTraits<uint32_t>;
using DeviceTraits = DefaultTraits<audio_devices_t>;
struct OutputDeviceTraits : public DeviceTraits {};
struct InputDeviceTraits : public DeviceTraits {};
using ChannelTraits = SetTraits<audio_channel_mask_t>;
struct OutputChannelTraits : public ChannelTraits {};
struct InputChannelTraits : public ChannelTraits {};
struct ChannelIndexTraits : public ChannelTraits {};
using InputFlagTraits = DefaultTraits<audio_input_flags_t>;
using OutputFlagTraits = DefaultTraits<audio_output_flags_t>;
using FormatTraits = DefaultTraits<audio_format_t>;
using GainModeTraits = DefaultTraits<audio_gain_mode_t>;
using StreamTraits = DefaultTraits<audio_stream_type_t>;
using AudioModeTraits = DefaultTraits<audio_mode_t>;
using AudioContentTraits = DefaultTraits<audio_content_type_t>;
using UsageTraits = DefaultTraits<audio_usage_t>;
using SourceTraits = DefaultTraits<audio_source_t>;
struct AudioFlagTraits : public DefaultTraits<audio_flags_mask_t> {};

template <class Traits>
static void collectionFromString(const std::string &str, typename Traits::Collection &collection,
                                 const char *del = AudioParameter::valueListSeparator)
{
    char *literal = strdup(str.c_str());
    for (const char *cstr = strtok(literal, del); cstr != NULL; cstr = strtok(NULL, del)) {
        typename Traits::Type value;
        if (utilities::convertTo<std::string, typename Traits::Type >(cstr, value)) {
            Traits::add(collection, value);
        }
    }
    free(literal);
}

template <class Traits>
class TypeConverter
{
public:
    static bool toString(const typename Traits::Type &value, std::string &str);

    static bool fromString(const std::string &str, typename Traits::Type &result);

    static void collectionFromString(const std::string &str,
                                     typename Traits::Collection &collection,
                                     const char *del = AudioParameter::valueListSeparator);

    static typename Traits::Type maskFromString(
            const std::string &str, const char *del = AudioParameter::valueListSeparator);

    static void maskToString(
            typename Traits::Type mask, std::string &str,
            const char *del = AudioParameter::valueListSeparator);

protected:
    // Default implementations use mTable for to/from string conversions
    // of each individual enum value.
    // These functions may be specialized to use external converters instead.
    static bool toStringImpl(const typename Traits::Type &value, std::string &str);
    static bool fromStringImpl(const std::string &str, typename Traits::Type &result);

    struct Table {
        const char *literal;
        typename Traits::Type value;
    };

    static const Table mTable[];
};

template <class Traits>
inline bool TypeConverter<Traits>::toStringImpl(
        const typename Traits::Type &value, std::string &str) {
    for (size_t i = 0; mTable[i].literal; i++) {
        if (mTable[i].value == value) {
            str = mTable[i].literal;
            return true;
        }
    }
    return false;
}

template <class Traits>
inline bool TypeConverter<Traits>::fromStringImpl(
        const std::string &str, typename Traits::Type &result) {
    for (size_t i = 0; mTable[i].literal; i++) {
        if (strcmp(mTable[i].literal, str.c_str()) == 0) {
            result = mTable[i].value;
            return true;
        }
    }
    return false;
}

template <class Traits>
inline bool TypeConverter<Traits>::toString(const typename Traits::Type &value, std::string &str)
{
    const bool success = toStringImpl(value, str);
    if (!success) {
        char result[64];
        snprintf(result, sizeof(result), "Unknown enum value %d", value);
        str = result;
    }
    return success;
}

template <class Traits>
inline bool TypeConverter<Traits>::fromString(const std::string &str, typename Traits::Type &result)
{
    const bool success = fromStringImpl(str, result);
    ALOGV_IF(success, "stringToEnum() found %s", str.c_str());
    return success;
}

template <class Traits>
inline void TypeConverter<Traits>::collectionFromString(const std::string &str,
        typename Traits::Collection &collection,
        const char *del)
{
    char *literal = strdup(str.c_str());

    for (const char *cstr = strtok(literal, del); cstr != NULL; cstr = strtok(NULL, del)) {
        typename Traits::Type value;
        if (fromString(cstr, value)) {
            Traits::add(collection, value);
        }
    }
    free(literal);
}

template <class Traits>
inline typename Traits::Type TypeConverter<Traits>::maskFromString(
        const std::string &str, const char *del)
{
    char *literal = strdup(str.c_str());
    uint32_t value = 0;
    for (const char *cstr = strtok(literal, del); cstr != NULL; cstr = strtok(NULL, del)) {
        typename Traits::Type type;
        if (fromString(cstr, type)) {
            value |= static_cast<uint32_t>(type);
        }
    }
    free(literal);
    return static_cast<typename Traits::Type>(value);
}

template <class Traits>
inline void TypeConverter<Traits>::maskToString(
        typename Traits::Type mask, std::string &str, const char *del)
{
    if (mask != 0) {
        bool first_flag = true;
        for (size_t bit = 0; bit < sizeof(uint32_t) * 8; ++bit) {
            uint32_t flag = 1u << bit;
            if ((flag & mask) == flag) {
                std::string flag_str;
                if (toString(static_cast<typename Traits::Type>(flag), flag_str)) {
                    if (!first_flag) str += del;
                    first_flag = false;
                    str += flag_str;
                }
            }
        }
    } else {
        toString(static_cast<typename Traits::Type>(0), str);
    }
}

typedef TypeConverter<DeviceTraits> DeviceConverter;
typedef TypeConverter<OutputDeviceTraits> OutputDeviceConverter;
typedef TypeConverter<InputDeviceTraits> InputDeviceConverter;
typedef TypeConverter<OutputFlagTraits> OutputFlagConverter;
typedef TypeConverter<InputFlagTraits> InputFlagConverter;
typedef TypeConverter<FormatTraits> FormatConverter;
typedef TypeConverter<OutputChannelTraits> OutputChannelConverter;
typedef TypeConverter<InputChannelTraits> InputChannelConverter;
typedef TypeConverter<ChannelIndexTraits> ChannelIndexConverter;
typedef TypeConverter<GainModeTraits> GainModeConverter;
typedef TypeConverter<StreamTraits> StreamTypeConverter;
typedef TypeConverter<AudioModeTraits> AudioModeConverter;
typedef TypeConverter<AudioContentTraits> AudioContentTypeConverter;
typedef TypeConverter<UsageTraits> UsageTypeConverter;
typedef TypeConverter<SourceTraits> SourceTypeConverter;
typedef TypeConverter<AudioFlagTraits> AudioFlagConverter;

template<> const AudioModeConverter::Table AudioModeConverter::mTable[];
template<> const AudioFlagConverter::Table AudioFlagConverter::mTable[];

template <>
inline bool TypeConverter<DeviceTraits>::toStringImpl(
        const DeviceTraits::Type &value, std::string &str) {
    str = audio_device_to_string(value);
    return !str.empty();
}

template <>
inline bool TypeConverter<DeviceTraits>::fromStringImpl(
        const std::string &str, DeviceTraits::Type &result) {
    return audio_device_from_string(str.c_str(), &result);
}

template <>
inline bool TypeConverter<OutputDeviceTraits>::toStringImpl(
        const OutputDeviceTraits::Type &value, std::string &str) {
    if (audio_is_output_device(value)) {
        str = audio_device_to_string(value);
        return !str.empty();
    }
    return false;
}

template <>
inline bool TypeConverter<OutputDeviceTraits>::fromStringImpl(
        const std::string &str, OutputDeviceTraits::Type &result) {
    OutputDeviceTraits::Type temp;
    if (audio_device_from_string(str.c_str(), &temp) &&
            audio_is_output_device(temp)) {
        result = temp;
        return true;
    }
    return false;
}

template <>
inline bool TypeConverter<InputDeviceTraits>::toStringImpl(
        const InputDeviceTraits::Type &value, std::string &str) {
    if (audio_is_input_device(value)) {
        str = audio_device_to_string(value);
        return !str.empty();
    }
    return false;
}

template <>
inline bool TypeConverter<InputDeviceTraits>::fromStringImpl(
        const std::string &str, InputDeviceTraits::Type &result) {
    InputDeviceTraits::Type temp;
    if (audio_device_from_string(str.c_str(), &temp) &&
            audio_is_input_device(temp)) {
        result = temp;
        return true;
    }
    return false;
}

template <>
inline bool TypeConverter<InputFlagTraits>::toStringImpl(
        const audio_input_flags_t &value, std::string &str) {
    str = audio_input_flag_to_string(value);
    return !str.empty();
}

template <>
inline bool TypeConverter<InputFlagTraits>::fromStringImpl(
        const std::string &str, audio_input_flags_t &result) {
    return audio_input_flag_from_string(str.c_str(), &result);
}

template <>
inline bool TypeConverter<OutputFlagTraits>::toStringImpl(
        const audio_output_flags_t &value, std::string &str) {
    str = audio_output_flag_to_string(value);
    return !str.empty();
}

template <>
inline bool TypeConverter<OutputFlagTraits>::fromStringImpl(
        const std::string &str, audio_output_flags_t &result) {
    return audio_output_flag_from_string(str.c_str(), &result);
}

template <>
inline bool TypeConverter<FormatTraits>::toStringImpl(
        const audio_format_t &value, std::string &str) {
    str = audio_format_to_string(value);
    return !str.empty();
}

template <>
inline bool TypeConverter<FormatTraits>::fromStringImpl(
        const std::string &str, audio_format_t &result) {
    return audio_format_from_string(str.c_str(), &result);
}

template <>
inline bool TypeConverter<OutputChannelTraits>::toStringImpl(
        const audio_channel_mask_t &value, std::string &str) {
    str = audio_channel_out_mask_to_string(value);
    return !str.empty();
}

template <>
inline bool TypeConverter<OutputChannelTraits>::fromStringImpl(
        const std::string &str, audio_channel_mask_t &result) {
    OutputChannelTraits::Type temp;
    if (audio_channel_mask_from_string(str.c_str(), &temp) &&
            audio_is_output_channel(temp)) {
        result = temp;
        return true;
    }
    return false;
}

template <>
inline bool TypeConverter<InputChannelTraits>::toStringImpl(
        const audio_channel_mask_t &value, std::string &str) {
    str = audio_channel_in_mask_to_string(value);
    return !str.empty();
}

template <>
inline bool TypeConverter<InputChannelTraits>::fromStringImpl(
        const std::string &str, audio_channel_mask_t &result) {
    InputChannelTraits::Type temp;
    if (audio_channel_mask_from_string(str.c_str(), &temp) &&
            audio_is_input_channel(temp)) {
        result = temp;
        return true;
    }
    return false;
}

template <>
inline bool TypeConverter<ChannelIndexTraits>::toStringImpl(
        const audio_channel_mask_t &value, std::string &str) {
    str = audio_channel_index_mask_to_string(value);
    return !str.empty();
}

template <>
inline bool TypeConverter<ChannelIndexTraits>::fromStringImpl(
        const std::string &str, audio_channel_mask_t &result) {
    ChannelIndexTraits::Type temp;
    if (audio_channel_mask_from_string(str.c_str(), &temp) &&
            audio_channel_mask_get_representation(temp) == AUDIO_CHANNEL_REPRESENTATION_INDEX) {
        result = temp;
        return true;
    }
    return false;
}

template <>
inline bool TypeConverter<StreamTraits>::toStringImpl(
        const audio_stream_type_t &value, std::string &str) {
    str = audio_stream_type_to_string(value);
    return !str.empty();
}

template <>
inline bool TypeConverter<StreamTraits>::fromStringImpl(
        const std::string &str, audio_stream_type_t &result)
{
    return audio_stream_type_from_string(str.c_str(), &result);
}

template <>
inline bool TypeConverter<GainModeTraits>::toStringImpl(
        const audio_gain_mode_t &value, std::string &str) {
    str = audio_gain_mode_to_string(value);
    return !str.empty();
}

template <>
inline bool TypeConverter<GainModeTraits>::fromStringImpl(
        const std::string &str, audio_gain_mode_t &result) {
    return audio_gain_mode_from_string(str.c_str(), &result);
}

template <>
inline bool TypeConverter<AudioContentTraits>::toStringImpl(
        const audio_content_type_t &value, std::string &str) {
    str = audio_content_type_to_string(value);
    return !str.empty();
}

template <>
inline bool TypeConverter<AudioContentTraits>::fromStringImpl(
        const std::string &str, audio_content_type_t &result) {
    return audio_content_type_from_string(str.c_str(), &result);
}

template <>
inline bool TypeConverter<UsageTraits>::toStringImpl(const audio_usage_t &value, std::string &str)
{
    str = audio_usage_to_string(value);
    return !str.empty();
}

template <>
inline bool TypeConverter<UsageTraits>::fromStringImpl(
        const std::string &str, audio_usage_t &result) {
    return audio_usage_from_string(str.c_str(), &result);
}

template <>
inline bool TypeConverter<SourceTraits>::toStringImpl(const audio_source_t &value, std::string &str)
{
    str = audio_source_to_string(value);
    return !str.empty();
}

template <>
inline bool TypeConverter<SourceTraits>::fromStringImpl(
        const std::string &str, audio_source_t &result) {
    return audio_source_from_string(str.c_str(), &result);
}

SampleRateTraits::Collection samplingRatesFromString(
        const std::string &samplingRates, const char *del = AudioParameter::valueListSeparator);

FormatTraits::Collection formatsFromString(
        const std::string &formats, const char *del = AudioParameter::valueListSeparator);

audio_format_t formatFromString(
        const std::string &literalFormat, audio_format_t defaultFormat = AUDIO_FORMAT_DEFAULT);

audio_channel_mask_t channelMaskFromString(const std::string &literalChannels);

ChannelTraits::Collection channelMasksFromString(
        const std::string &channels, const char *del = AudioParameter::valueListSeparator);

InputChannelTraits::Collection inputChannelMasksFromString(
        const std::string &inChannels, const char *del = AudioParameter::valueListSeparator);

OutputChannelTraits::Collection outputChannelMasksFromString(
        const std::string &outChannels, const char *del = AudioParameter::valueListSeparator);

// counting enumerations
template <typename T, std::enable_if_t<std::is_same<T, audio_content_type_t>::value
                                    || std::is_same<T, audio_devices_t>::value
                                    || std::is_same<T, audio_mode_t>::value
                                    || std::is_same<T, audio_source_t>::value
                                    || std::is_same<T, audio_stream_type_t>::value
                                    || std::is_same<T, audio_usage_t>::value
                                    || std::is_same<T, audio_format_t>::value
                                    , int> = 0>
static inline std::string toString(const T& value)
{
    std::string result;
    return TypeConverter<DefaultTraits<T>>::toString(value, result)
            ? result : std::to_string(static_cast<int>(value));

}

// flag enumerations
template <typename T, std::enable_if_t<std::is_same<T, audio_gain_mode_t>::value
                                    || std::is_same<T, audio_input_flags_t>::value
                                    || std::is_same<T, audio_output_flags_t>::value
                                    , int> = 0>
static inline std::string toString(const T& value)
{
    std::string result;
    TypeConverter<DefaultTraits<T>>::maskToString(value, result);
    return result;
}

static inline std::string toString(const audio_attributes_t& attributes)
{
    std::ostringstream result;
    result << "{ Content type: " << toString(attributes.content_type)
           << " Usage: " << toString(attributes.usage)
           << " Source: " << toString(attributes.source)
           << std::hex << " Flags: 0x" << attributes.flags
           << std::dec << " Tags: " << attributes.tags
           << " }";

    return result.str();
}

}; // namespace android

#endif  /*ANDROID_TYPE_CONVERTER_H_*/
