/*
 * Copyright (C) 2020 The Android Open Source Project
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

#include <gtest/gtest.h>

#define LOG_TAG "TypeConverter_Test"
#include <log/log.h>

#include <android_audio_policy_configuration_V7_0.h>
#include <media/TypeConverter.h>
#include <system/audio.h>
#include <xsdc/XsdcSupport.h>

using namespace android;
namespace xsd {
using namespace android::audio::policy::configuration::V7_0;
}

TEST(TypeConverter, ParseChannelMasks) {
    for (const auto enumVal : xsdc_enum_range<xsd::AudioChannelMask>{}) {
        const std::string stringVal = toString(enumVal);
        audio_channel_mask_t channelMask = channelMaskFromString(stringVal);
        EXPECT_EQ(enumVal != xsd::AudioChannelMask::AUDIO_CHANNEL_NONE,
                audio_channel_mask_is_valid(channelMask))
                << "Validity of \"" << stringVal << "\" is not as expected";
    }
}

TEST(TypeConverter, ParseInputOutputIndexChannelMask) {
    for (const auto enumVal : xsdc_enum_range<xsd::AudioChannelMask>{}) {
        const std::string stringVal = toString(enumVal);
        audio_channel_mask_t channelMask, channelMaskBack;
        std::string stringValBack;
        if (stringVal.find("_CHANNEL_IN_") != std::string::npos) {
            EXPECT_TRUE(InputChannelConverter::fromString(stringVal, channelMask))
                    << "Conversion of \"" << stringVal << "\" failed (as input channel mask)";
            EXPECT_TRUE(InputChannelConverter::toString(channelMask, stringValBack))
                    << "Conversion of input channel mask " << channelMask << " failed";
            // Due to aliased values, the result of 'toString' might not be the same
            // as 'stringVal', thus we need to compare the results of parsing instead.
            EXPECT_TRUE(InputChannelConverter::fromString(stringValBack, channelMaskBack))
                    << "Conversion of \"" << stringValBack << "\" failed (as input channel mask)";
            EXPECT_EQ(channelMask, channelMaskBack);
        } else if (stringVal.find("_CHANNEL_OUT_") != std::string::npos) {
            EXPECT_TRUE(OutputChannelConverter::fromString(stringVal, channelMask))
                    << "Conversion of \"" << stringVal << "\" failed (as output channel mask)";
            EXPECT_TRUE(OutputChannelConverter::toString(channelMask, stringValBack))
                    << "Conversion of output channel mask " << channelMask << " failed";
            EXPECT_TRUE(OutputChannelConverter::fromString(stringValBack, channelMaskBack))
                    << "Conversion of \"" << stringValBack << "\" failed (as output channel mask)";
            EXPECT_EQ(channelMask, channelMaskBack);
        } else if (stringVal.find("_CHANNEL_INDEX_") != std::string::npos) {
            EXPECT_TRUE(ChannelIndexConverter::fromString(stringVal, channelMask))
                    << "Conversion of \"" << stringVal << "\" failed (as indexed channel mask)";
            EXPECT_TRUE(ChannelIndexConverter::toString(channelMask, stringValBack))
                    << "Conversion of indexed channel mask " << channelMask << " failed";
            EXPECT_EQ(stringVal, stringValBack);
        } else if (stringVal == toString(xsd::AudioChannelMask::AUDIO_CHANNEL_NONE)) {
            EXPECT_FALSE(InputChannelConverter::fromString(stringVal, channelMask))
                    << "Conversion of \"" << stringVal << "\" succeeded (as input channel mask)";
            EXPECT_FALSE(OutputChannelConverter::fromString(stringVal, channelMask))
                    << "Conversion of \"" << stringVal << "\" succeeded (as output channel mask)";
            EXPECT_FALSE(ChannelIndexConverter::fromString(stringVal, channelMask))
                    << "Conversion of \"" << stringVal << "\" succeeded (as index channel mask)";
            // None of Converters could parse this because 'NONE' isn't a 'valid' channel mask.
            channelMask = AUDIO_CHANNEL_NONE;
            // However they all must succeed in converting it back.
            EXPECT_TRUE(InputChannelConverter::toString(channelMask, stringValBack))
                    << "Conversion of input channel mask " << channelMask << " failed";
            EXPECT_EQ(stringVal, stringValBack);
            EXPECT_TRUE(OutputChannelConverter::toString(channelMask, stringValBack))
                    << "Conversion of output channel mask " << channelMask << " failed";
            EXPECT_EQ(stringVal, stringValBack);
            EXPECT_TRUE(ChannelIndexConverter::toString(channelMask, stringValBack))
                    << "Conversion of indexed channel mask " << channelMask << " failed";
            EXPECT_EQ(stringVal, stringValBack);
        } else {
            FAIL() << "Unrecognized channel mask \"" << stringVal << "\"";
        }
    }
}

TEST(TypeConverter, ParseContentTypes) {
    for (const auto enumVal : xsdc_enum_range<xsd::AudioContentType>{}) {
        const std::string stringVal = toString(enumVal);
        audio_content_type_t contentType;
        EXPECT_TRUE(AudioContentTypeConverter::fromString(stringVal, contentType))
                << "Conversion of \"" << stringVal << "\" failed";
        EXPECT_EQ(stringVal, toString(contentType));
    }
}

TEST(TypeConverter, ParseDevices) {
    for (const auto enumVal : xsdc_enum_range<xsd::AudioDevice>{}) {
        const std::string stringVal = toString(enumVal);
        audio_devices_t device, deviceBack;
        std::string stringValBack;
        EXPECT_TRUE(DeviceConverter::fromString(stringVal, device))
                << "Conversion of \"" << stringVal << "\" failed";
        if (enumVal != xsd::AudioDevice::AUDIO_DEVICE_NONE) {
            EXPECT_TRUE(audio_is_input_device(device) || audio_is_output_device(device))
                    << "Device \"" << stringVal << "\" is neither input, nor output device";
        } else {
            EXPECT_FALSE(audio_is_input_device(device));
            EXPECT_FALSE(audio_is_output_device(device));
        }
        // Due to aliased values, the result of 'toString' might not be the same
        // as 'stringVal', thus we need to compare the results of parsing instead.
        stringValBack = toString(device);
        EXPECT_TRUE(DeviceConverter::fromString(stringValBack, deviceBack))
                << "Conversion of \"" << stringValBack << "\" failed";
        EXPECT_EQ(device, deviceBack);
    }
}

TEST(TypeConverter, ParseInOutDevices) {
    for (const auto enumVal : xsdc_enum_range<xsd::AudioDevice>{}) {
        const std::string stringVal = toString(enumVal);
        audio_devices_t device, deviceBack;
        std::string stringValBack;
        if (stringVal.find("_DEVICE_IN_") != std::string::npos) {
            EXPECT_TRUE(InputDeviceConverter::fromString(stringVal, device))
                    << "Conversion of \"" << stringVal << "\" failed (as input device)";
            // Due to aliased values, the result of 'toString' might not be the same
            // as 'stringVal', thus we need to compare the results of parsing instead.
            stringValBack = toString(device);
            EXPECT_TRUE(InputDeviceConverter::fromString(stringValBack, deviceBack))
                    << "Conversion of \"" << stringValBack << "\" failed";
            EXPECT_EQ(device, deviceBack);
        } else if (stringVal.find("_DEVICE_OUT_") != std::string::npos) {
            EXPECT_TRUE(OutputDeviceConverter::fromString(stringVal, device))
                    << "Conversion of \"" << stringVal << "\" failed (as output device)";
            stringValBack = toString(device);
            EXPECT_TRUE(OutputDeviceConverter::fromString(stringValBack, deviceBack))
                    << "Conversion of \"" << stringValBack << "\" failed";
            EXPECT_EQ(device, deviceBack);
        } else if (stringVal == toString(xsd::AudioDevice::AUDIO_DEVICE_NONE)) {
            EXPECT_FALSE(InputDeviceConverter::fromString(stringVal, device))
                    << "Conversion of \"" << stringVal << "\" succeeded (as input device)";
            EXPECT_FALSE(OutputDeviceConverter::fromString(stringVal, device))
                    << "Conversion of \"" << stringVal << "\" succeeded (as output device)";
            EXPECT_EQ(stringVal, toString(device));
        } else {
            FAIL() << "Unrecognized audio device \"" << stringVal << "\"";
        }
    }
}

TEST(TypeConverter, ParseInOutFlags) {
    for (const auto enumVal : xsdc_enum_range<xsd::AudioInOutFlag>{}) {
        const std::string stringVal = toString(enumVal);
        if (stringVal.find("_INPUT_FLAG_") != std::string::npos) {
            audio_input_flags_t flag;
            EXPECT_TRUE(InputFlagConverter::fromString(stringVal, flag))
                    << "Conversion of \"" << stringVal << "\" failed (as input flag)";
            EXPECT_EQ(stringVal, toString(flag));
        } else {
            audio_output_flags_t flag;
            EXPECT_TRUE(OutputFlagConverter::fromString(stringVal, flag))
                    << "Conversion of \"" << stringVal << "\" failed (as output flag)";
            EXPECT_EQ(stringVal, toString(flag));
        }
    }
}

TEST(TypeConverter, ParseFormats) {
    for (const auto enumVal : xsdc_enum_range<xsd::AudioFormat>{}) {
        const std::string stringVal = toString(enumVal);
        audio_format_t format;
        EXPECT_TRUE(FormatConverter::fromString(stringVal, format))
                << "Conversion of \"" << stringVal << "\" failed";
        EXPECT_EQ(enumVal != xsd::AudioFormat::AUDIO_FORMAT_DEFAULT,
                audio_is_valid_format(format))
                << "Validity of \"" << stringVal << "\" is not as expected";
        EXPECT_EQ(stringVal, toString(format));
    }
}

TEST(TypeConverter, ParseGainModes) {
    for (const auto enumVal : xsdc_enum_range<xsd::AudioGainMode>{}) {
        const std::string stringVal = toString(enumVal);
        audio_gain_mode_t gainMode;
        EXPECT_TRUE(GainModeConverter::fromString(stringVal, gainMode))
                << "Conversion of \"" << stringVal << "\" failed";
        EXPECT_EQ(stringVal, toString(gainMode));
    }
}

TEST(TypeConverter, ParseSources) {
    for (const auto enumVal : xsdc_enum_range<xsd::AudioSource>{}) {
        const std::string stringVal = toString(enumVal);
        audio_source_t source;
        EXPECT_TRUE(SourceTypeConverter::fromString(stringVal, source))
                << "Conversion of \"" << stringVal << "\" failed";
        EXPECT_EQ(source != AUDIO_SOURCE_DEFAULT, audio_is_valid_audio_source(source))
                << "Validity of \"" << stringVal << "\" is not as expected";
        EXPECT_EQ(stringVal, toString(source));
    }
}

TEST(TypeConverter, ParseStreamTypes) {
    for (const auto enumVal : xsdc_enum_range<xsd::AudioStreamType>{}) {
        const std::string stringVal = toString(enumVal);
        audio_stream_type_t streamType;
        EXPECT_TRUE(StreamTypeConverter::fromString(stringVal, streamType))
                << "Conversion of \"" << stringVal << "\" failed";
        EXPECT_EQ(stringVal, toString(streamType));
    }
}

TEST(TypeConverter, ParseUsages) {
    for (const auto enumVal : xsdc_enum_range<xsd::AudioUsage>{}) {
        const std::string stringVal = toString(enumVal);
        audio_usage_t usage;
        EXPECT_TRUE(UsageTypeConverter::fromString(stringVal, usage))
                << "Conversion of \"" << stringVal << "\" failed";
        EXPECT_EQ(stringVal, toString(usage));
    }
}
