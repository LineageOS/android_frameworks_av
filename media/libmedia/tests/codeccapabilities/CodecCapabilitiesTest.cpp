/*
 * Copyright (C) 2024 The Android Open Source Project
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

//#define LOG_NDEBUG 0
#define LOG_TAG "CodecCapabilitiesTest"

#include <utils/Log.h>

#include <memory>

#include <gtest/gtest.h>

#include <binder/Parcel.h>

#include <media/CodecCapabilities.h>
#include <media/CodecCapabilitiesUtils.h>
#include <media/MediaCodecInfo.h>

#include <media/stagefright/MediaCodecConstants.h>
#include <media/stagefright/MediaCodecList.h>
#include <media/stagefright/foundation/ABuffer.h>
#include <media/stagefright/foundation/AString.h>

using namespace android;

class AudioCapsIamfTest1 : public testing::Test {
protected:
    AudioCapsIamfTest1() {
        std::string mediaType = MIMETYPE_AUDIO_IAMF;

        sp<AMessage> details = new AMessage;

        std::vector<ProfileLevel> profileLevel {
            ProfileLevel(IAMF_PROFILE_SIMPLE | IAMF_CODEC_OPUS, 0),
        };

        audioCaps = AudioCapabilities::Create(mediaType, profileLevel, details);
    }

    std::shared_ptr<AudioCapabilities> audioCaps;
};

TEST_F(AudioCapsIamfTest1, AudioCaps_Iamf_Bitrate) {
    const Range<int32_t>& bitrateRange = audioCaps->getBitrateRange();
    EXPECT_EQ(bitrateRange.lower(), 6000);
    EXPECT_EQ(bitrateRange.upper(), 128000 * 16);
}

// Note: This test assumes that the device does not restrict the sample rates smaller than
// the framework limit (7350, 192000).
TEST_F(AudioCapsIamfTest1, AudioCaps_Iamf_SupportedSampleRates) {
    const std::vector<Range<int32_t>>& sampleRateRanges = audioCaps->getSupportedSampleRateRanges();
    EXPECT_EQ(sampleRateRanges.size(), 1);
    EXPECT_EQ(sampleRateRanges.at(0).lower(), 48000);
    EXPECT_EQ(sampleRateRanges.at(0).upper(), 48000);
}

class AudioCapsIamfTest2 : public testing::Test {
protected:
    AudioCapsIamfTest2() {
        std::string mediaType = MIMETYPE_AUDIO_IAMF;

        sp<AMessage> details = new AMessage;

        std::vector<ProfileLevel> profileLevel {
            ProfileLevel(IAMF_PROFILE_SIMPLE | IAMF_CODEC_OPUS, 0),
            ProfileLevel(IAMF_PROFILE_BASE | IAMF_CODEC_FLAC, 0),
            ProfileLevel(IAMF_PROFILE_BASE_ENHANCED | IAMF_CODEC_PCM, 0),
        };

        audioCaps = AudioCapabilities::Create(mediaType, profileLevel, details);
    }

    std::shared_ptr<AudioCapabilities> audioCaps;
};

TEST_F(AudioCapsIamfTest2, AudioCaps_Iamf_Bitrate) {
    const Range<int32_t>& bitrateRange = audioCaps->getBitrateRange();
    EXPECT_EQ(bitrateRange.lower(), 1);
    EXPECT_EQ(bitrateRange.upper(), 21000000);
}

// Note: This test assumes that the device does not restrict the sample rates smaller than
// the framework limit (7350, 192000).
TEST_F(AudioCapsIamfTest2, AudioCaps_Iamf_SupportedSampleRates) {
    const std::vector<Range<int32_t>>& sampleRateRanges = audioCaps->getSupportedSampleRateRanges();
    EXPECT_EQ(sampleRateRanges.size(), 1);
    EXPECT_EQ(sampleRateRanges.at(0).lower(), 7350);
    EXPECT_EQ(sampleRateRanges.at(0).upper(), 192000);
}

TEST_F(AudioCapsIamfTest2, AudioCaps_Iamf_InputChannelCountRanges) {
    const std::vector<Range<int32_t>>& inputChannelCountRanges
            = audioCaps->getInputChannelCountRanges();

    EXPECT_EQ(inputChannelCountRanges.size(), 1);
    EXPECT_EQ(inputChannelCountRanges.at(0).lower(), 1);
    EXPECT_EQ(inputChannelCountRanges.at(0).upper(), 28);
}

class AudioCapsDtsUhdTest : public testing::Test {
protected:
    AudioCapsDtsUhdTest() {
        std::string mediaType = MIMETYPE_AUDIO_DTS_UHD;

        sp<AMessage> details = new AMessage;

        std::vector<ProfileLevel> profileLevel {
            ProfileLevel(DTS_UHDProfileP2, 0),
            ProfileLevel(DTS_UHDProfileP1, 0),
        };

        audioCaps = AudioCapabilities::Create(mediaType, profileLevel, details);
    }

    std::shared_ptr<AudioCapabilities> audioCaps;
};

TEST_F(AudioCapsDtsUhdTest, AudioCaps_DtsUhd_Bitrate) {
    const Range<int32_t>& bitrateRange = audioCaps->getBitrateRange();
    EXPECT_EQ(bitrateRange.lower(), 96000);
    EXPECT_EQ(bitrateRange.upper(), 24500000);
}

// Note: This test assumes that the device does not restrict the sample rates smaller than
// the framework limit (7350, 192000).
TEST_F(AudioCapsDtsUhdTest, AudioCaps_DtsUhd_SupportedSampleRates) {
    const std::vector<Range<int32_t>>& sampleRateRanges = audioCaps->getSupportedSampleRateRanges();
    EXPECT_EQ(sampleRateRanges.size(), 6);
    EXPECT_EQ(sampleRateRanges.at(0).lower(), 44100);
    EXPECT_EQ(sampleRateRanges.at(0).upper(), 44100);
    EXPECT_EQ(sampleRateRanges.at(1).lower(), 48000);
    EXPECT_EQ(sampleRateRanges.at(1).upper(), 48000);
    EXPECT_EQ(sampleRateRanges.at(2).lower(), 88200);
    EXPECT_EQ(sampleRateRanges.at(2).upper(), 88200);
    EXPECT_EQ(sampleRateRanges.at(3).lower(), 96000);
    EXPECT_EQ(sampleRateRanges.at(3).upper(), 96000);
    EXPECT_EQ(sampleRateRanges.at(4).lower(), 176400);
    EXPECT_EQ(sampleRateRanges.at(4).upper(), 176400);
    EXPECT_EQ(sampleRateRanges.at(5).lower(), 192000);
    EXPECT_EQ(sampleRateRanges.at(5).upper(), 192000);
}

TEST_F(AudioCapsDtsUhdTest, AudioCaps_DtsUhd_InputChannelCountRanges) {
    const std::vector<Range<int32_t>>& inputChannelCountRanges
            = audioCaps->getInputChannelCountRanges();
    EXPECT_EQ(inputChannelCountRanges.size(), 1);
    EXPECT_EQ(inputChannelCountRanges.at(0).lower(), 1);
    EXPECT_EQ(inputChannelCountRanges.at(0).upper(), 30);
}

class AudioCapsAacTest : public testing::Test {
protected:
    AudioCapsAacTest() {
        std::string mediaType = MIMETYPE_AUDIO_AAC;

        sp<AMessage> details = new AMessage;
        details->setString("bitrate-range", "8000-960000");
        details->setString("max-channel-count", "8");
        details->setString("sample-rate-ranges",
                "7350,8000,11025,12000,16000,22050,24000,32000,44100,48000");

        std::vector<ProfileLevel> profileLevel{
            ProfileLevel(2, 0),
            ProfileLevel(5, 0),
            ProfileLevel(29, 0),
            ProfileLevel(23, 0),
            ProfileLevel(39, 0),
            ProfileLevel(20, 0),
            ProfileLevel(42, 0),
        };

        audioCaps = AudioCapabilities::Create(mediaType, profileLevel, details);
    }

    std::shared_ptr<AudioCapabilities> audioCaps;
};

TEST_F(AudioCapsAacTest, AudioCaps_Aac_Bitrate) {
    const Range<int32_t>& bitrateRange = audioCaps->getBitrateRange();
    EXPECT_EQ(bitrateRange.lower(), 8000) << "bitrate range1 does not match. lower: "
            << bitrateRange.lower();
    EXPECT_EQ(bitrateRange.upper(), 510000) << "bitrate range1 does not match. upper: "
            << bitrateRange.upper();
}

TEST_F(AudioCapsAacTest, AudioCaps_Aac_InputChannelCount) {
    int32_t maxInputChannelCount = audioCaps->getMaxInputChannelCount();
    EXPECT_EQ(maxInputChannelCount, 8);
    int32_t minInputChannelCount = audioCaps->getMinInputChannelCount();
    EXPECT_EQ(minInputChannelCount, 1);
}

TEST_F(AudioCapsAacTest, AudioCaps_Aac_SupportedSampleRates) {
    const std::vector<int32_t>& sampleRates = audioCaps->getSupportedSampleRates();
    EXPECT_EQ(sampleRates, std::vector<int32_t>({7350, 8000, 11025, 12000, 16000, 22050,
            24000, 32000, 44100, 48000}));

    EXPECT_FALSE(audioCaps->isSampleRateSupported(6000))
            << "isSampleRateSupported returned true for unsupported sample rate";
    EXPECT_TRUE(audioCaps->isSampleRateSupported(8000))
            << "isSampleRateSupported returned false for supported sample rate";
    EXPECT_TRUE(audioCaps->isSampleRateSupported(12000))
            << "isSampleRateSupported returned false for supported sample rate";
    EXPECT_FALSE(audioCaps->isSampleRateSupported(44000))
            << "isSampleRateSupported returned true for unsupported sample rate";
    EXPECT_TRUE(audioCaps->isSampleRateSupported(48000))
            << "isSampleRateSupported returned true for unsupported sample rate";
}

class AudioCapsRawTest : public testing::Test {
protected:
    AudioCapsRawTest() {
        std::string mediaType = MIMETYPE_AUDIO_RAW;

        sp<AMessage> details = new AMessage;
        details->setString("bitrate-range", "1-10000000");
        details->setString("channel-ranges", "1,2,3,4,5,6,7,8,9,10,11,12");
        details->setString("sample-rate-ranges", "8000-192000");

        std::vector<ProfileLevel> profileLevel;

        audioCaps = AudioCapabilities::Create(mediaType, profileLevel, details);
    }

    std::shared_ptr<AudioCapabilities> audioCaps;
};

TEST_F(AudioCapsRawTest, AudioCaps_Raw_Bitrate) {
    const Range<int32_t>& bitrateRange = audioCaps->getBitrateRange();
    EXPECT_EQ(bitrateRange.lower(), 1);
    EXPECT_EQ(bitrateRange.upper(), 10000000);
}

TEST_F(AudioCapsRawTest, AudioCaps_Raw_InputChannelCount) {
    int32_t maxInputChannelCount = audioCaps->getMaxInputChannelCount();
    EXPECT_EQ(maxInputChannelCount, 12);
    int32_t minInputChannelCount = audioCaps->getMinInputChannelCount();
    EXPECT_EQ(minInputChannelCount, 1);
}

TEST_F(AudioCapsRawTest, AudioCaps_Raw_InputChannelCountRanges) {
    const std::vector<Range<int32_t>>& inputChannelCountRanges
            = audioCaps->getInputChannelCountRanges();
    std::vector<Range<int32_t>> expectedOutput({{1,1}, {2,2}, {3,3}, {4,4}, {5,5},
            {6,6}, {7,7}, {8,8}, {9,9}, {10,10}, {11,11}, {12,12}});
    ASSERT_EQ(inputChannelCountRanges.size(), expectedOutput.size());
    for (int i = 0; i < inputChannelCountRanges.size(); i++) {
        EXPECT_EQ(inputChannelCountRanges.at(i).lower(), expectedOutput.at(i).lower());
        EXPECT_EQ(inputChannelCountRanges.at(i).upper(), expectedOutput.at(i).upper());
    }
}

TEST_F(AudioCapsRawTest, AudioCaps_Raw_SupportedSampleRates) {
    const std::vector<Range<int32_t>>& sampleRateRanges = audioCaps->getSupportedSampleRateRanges();
    EXPECT_EQ(sampleRateRanges.size(), 1);
    EXPECT_EQ(sampleRateRanges.at(0).lower(), 8000);
    EXPECT_EQ(sampleRateRanges.at(0).upper(), 192000);

    EXPECT_EQ(audioCaps->isSampleRateSupported(7000), false);
    EXPECT_EQ(audioCaps->isSampleRateSupported(10000), true);
    EXPECT_EQ(audioCaps->isSampleRateSupported(193000), false);
}

class VideoCapsHevcTest : public testing::Test {
protected:
    VideoCapsHevcTest() {
        std::string mediaType = MIMETYPE_VIDEO_HEVC;

        sp<AMessage> details = new AMessage;
        details->setString("alignment", "2x2");
        details->setString("bitrate-range", "1-120000000");
        details->setString("block-count-range", "1-32640");
        details->setString("block-size", "16x16");
        details->setString("blocks-per-second-range", "1-3916800");
        details->setInt32("feature-adaptive-playback", 0);
        details->setInt32("feature-can-swap-width-height", 1);
        details->setString("max-concurrent-instances", "16");
        details->setString("measured-frame-rate-1280x720-range", "547-553");
        details->setString("measured-frame-rate-1920x1080-range", "569-572");
        details->setString("measured-frame-rate-352x288-range", "1150-1250");
        details->setString("measured-frame-rate-3840x2160-range", "159-159");
        details->setString("measured-frame-rate-640x360-range", "528-529");
        details->setString("measured-frame-rate-720x480-range", "546-548");
        details->setString("performance-point-1280x720-range", "240");
        details->setString("performance-point-3840x2160-range", "120");
        details->setString("size-range", "64x64-3840x2176");

        std::vector<ProfileLevel> profileLevel{
            ProfileLevel(1, 8388608),
            ProfileLevel(2, 8388608),
            ProfileLevel(4096, 8388608),
            ProfileLevel(8192, 8388608),
        };

        videoCaps = VideoCapabilities::Create(mediaType, profileLevel, details);
    }

    std::shared_ptr<VideoCapabilities> videoCaps;
};

TEST_F(VideoCapsHevcTest, VideoCaps_HEVC_Alignment) {
    int32_t widthAlignment = videoCaps->getWidthAlignment();
    EXPECT_EQ(widthAlignment, 2);
    int32_t heightAlignment = videoCaps->getHeightAlignment();
    EXPECT_EQ(heightAlignment, 2);
}

TEST_F(VideoCapsHevcTest, VideoCaps_HEVC_BitrateRange) {
    const Range<int32_t>& bitrateRange = videoCaps->getBitrateRange();
    EXPECT_EQ(bitrateRange.lower(), 1);
    EXPECT_EQ(bitrateRange.upper(), 120000000);
}

TEST_F(VideoCapsHevcTest, VideoCaps_HEVC_SupportedWidthsAndHeights) {
    const Range<int32_t>& supportedWidths = videoCaps->getSupportedWidths();
    EXPECT_EQ(supportedWidths.upper(), 3840);
    const Range<int32_t>& supportedHeights = videoCaps->getSupportedHeights();
    EXPECT_EQ(supportedHeights.upper(), 3840);
}

TEST_F(VideoCapsHevcTest, VideoCaps_HEVC_SupportedFrameRates) {
    const Range<int32_t>& supportedFrameRates = videoCaps->getSupportedFrameRates();
    EXPECT_EQ(supportedFrameRates.lower(), 0);
    EXPECT_EQ(supportedFrameRates.upper(), 960);

    std::optional<Range<double>> supportedFR720p = videoCaps->getSupportedFrameRatesFor(1280, 720);
    EXPECT_EQ(supportedFR720p.value().upper(), 960.0);
    std::optional<Range<double>> supportedFR1080p
            = videoCaps->getSupportedFrameRatesFor(1920, 1080);
    EXPECT_EQ(supportedFR1080p.value().upper(), 480.0);
    std::optional<Range<double>> supportedFR4k = videoCaps->getSupportedFrameRatesFor(3840, 2160);
    EXPECT_EQ(std::round(supportedFR4k.value().upper()), 121);
}

TEST_F(VideoCapsHevcTest, VideoCaps_HEVC_AchievableFrameRates) {
    std::optional<Range<double>> achievableFR1080p
            = videoCaps->getAchievableFrameRatesFor(1920, 1080);
    ASSERT_NE(achievableFR1080p, std::nullopt) << "resolution not supported";
    EXPECT_EQ(achievableFR1080p.value().lower(), 569);
    EXPECT_EQ(achievableFR1080p.value().upper(), 572);
}

class EncoderCapsAacTest : public testing::Test {
protected:
    EncoderCapsAacTest() {
        std::string mediaType = MIMETYPE_AUDIO_AAC;

        sp<AMessage> details = new AMessage;
        details->setString("bitrate-range", "8000-960000");
        details->setString("max-channel-count", "6");
        details->setString("sample-rate-ranges",
                "8000,11025,12000,16000,22050,24000,32000,44100,48000");

        std::vector<ProfileLevel> profileLevel{
            ProfileLevel(2, 0),
            ProfileLevel(5, 0),
            ProfileLevel(29, 0),
            ProfileLevel(23, 0),
            ProfileLevel(39, 0),
        };

        encoderCaps = EncoderCapabilities::Create(mediaType, profileLevel, details);
    }

    std::shared_ptr<EncoderCapabilities> encoderCaps;
};


TEST_F(EncoderCapsAacTest, EncoderCaps_AAC_ComplexityRange) {
    const Range<int>& complexityRange = encoderCaps->getComplexityRange();
    EXPECT_EQ(complexityRange.lower(), 0);
    EXPECT_EQ(complexityRange.upper(), 0);
}

TEST_F(EncoderCapsAacTest, EncoderCaps_AAC_QualityRange) {
    const Range<int>& qualityRange = encoderCaps->getQualityRange();
    EXPECT_EQ(qualityRange.lower(), 0);
    EXPECT_EQ(qualityRange.upper(), 0);
}

TEST_F(EncoderCapsAacTest, EncoderCaps_AAC_SupportedBitrateMode) {
    EXPECT_FALSE(encoderCaps->isBitrateModeSupported(BITRATE_MODE_CBR));
    EXPECT_TRUE(encoderCaps->isBitrateModeSupported(BITRATE_MODE_VBR));
    EXPECT_FALSE(encoderCaps->isBitrateModeSupported(BITRATE_MODE_CQ));
    EXPECT_FALSE(encoderCaps->isBitrateModeSupported(BITRATE_MODE_CBR_FD));
}

class EncoderCapsFlacTest : public testing::Test {
protected:
    EncoderCapsFlacTest() {
        std::string mediaType = MIMETYPE_AUDIO_FLAC;

        sp<AMessage> details = new AMessage;
        details->setString("bitrate-range", "1-21000000");
        details->setString("complexity-default", "5");
        details->setString("complexity-range", "0-8");
        details->setString("feature-bitrate-modes", "CQ");
        details->setString("max-channel-count", "2");
        details->setString("sample-rate-ranges", "1-655350");

        std::vector<ProfileLevel> profileLevel;

        encoderCaps = EncoderCapabilities::Create(mediaType, profileLevel, details);
    }

    std::shared_ptr<EncoderCapabilities> encoderCaps;
};

TEST_F(EncoderCapsFlacTest, EncoderCaps_FLAC_ComplexityRange) {
    const Range<int>& complexityRange = encoderCaps->getComplexityRange();
    EXPECT_EQ(complexityRange.lower(), 0);
    EXPECT_EQ(complexityRange.upper(), 8);
}

TEST_F(EncoderCapsFlacTest, EncoderCaps_FLAC_QualityRange) {
    const Range<int>& qualityRange = encoderCaps->getQualityRange();
    EXPECT_EQ(qualityRange.lower(), 0);
    EXPECT_EQ(qualityRange.upper(), 0);
}

TEST_F(EncoderCapsFlacTest, EncoderCaps_FLAC_SupportedBitrateMode) {
    EXPECT_FALSE(encoderCaps->isBitrateModeSupported(BITRATE_MODE_CBR));
    EXPECT_FALSE(encoderCaps->isBitrateModeSupported(BITRATE_MODE_VBR));
    EXPECT_TRUE(encoderCaps->isBitrateModeSupported(BITRATE_MODE_CQ));
    EXPECT_FALSE(encoderCaps->isBitrateModeSupported(BITRATE_MODE_CBR_FD));
}

class EncoderCapsHevcTest : public testing::Test {
protected:
    EncoderCapsHevcTest() {
        std::string mediaType = MIMETYPE_VIDEO_HEVC;

        sp<AMessage> details = new AMessage;
        details->setString("alignment", "2x2");
        details->setString("bitrate-range", "1-120000000");
        details->setString("block-count-range", "1-8160");
        details->setString("block-size", "32x32");
        details->setString("blocks-per-second-range", "1-979200");
        details->setString("feature-bitrate-modes", "VBR,CBR,CQ,CBR-FD");
        details->setInt32("feature-can-swap-width-height", 1);
        details->setInt32("feature-qp-bounds", 0);
        details->setInt32("feature-vq-minimum-quality", 0);
        details->setString("max-concurrent-instances", "16");
        details->setString("measured-frame-rate-1280x720-range", "154-198");
        details->setString("measured-frame-rate-1920x1080-range", "46-97");
        details->setString("measured-frame-rate-320x240-range", "371-553");
        details->setString("measured-frame-rate-720x480-range", "214-305");
        details->setString("performance-point-1280x720-range", "240");
        details->setString("performance-point-3840x2160-range", "120");
        details->setString("quality-default", "57");
        details->setString("quality-range", "0-100");
        details->setString("quality-scale", "linear");
        details->setString("size-range", "64x64-3840x2176");
        details->setString("ts-schemas",
                           "android.generic.2+0;android.generic.3+1;webrtc.vp8.2-layer;"
                           "webrtc.svc.l1t2;webrtc.svc.l1t3");

        std::vector<ProfileLevel> profileLevel{
            ProfileLevel(1, 2097152),
            ProfileLevel(2, 2097152),
            ProfileLevel(4096, 2097152),
            ProfileLevel(8192, 2097152),
        };

        encoderCaps = EncoderCapabilities::Create(mediaType, profileLevel, details);
    }

    std::shared_ptr<EncoderCapabilities> encoderCaps;
};

TEST_F(EncoderCapsHevcTest, EncoderCaps_HEVC_ComplexityRange) {
    const Range<int>& complexityRange = encoderCaps->getComplexityRange();
    EXPECT_EQ(complexityRange.lower(), 0);
    EXPECT_EQ(complexityRange.upper(), 0);
}

TEST_F(EncoderCapsHevcTest, EncoderCaps_HEVC_QualityRange) {
    const Range<int>& qualityRange = encoderCaps->getQualityRange();
    EXPECT_EQ(qualityRange.lower(), 0);
    EXPECT_EQ(qualityRange.upper(), 100);
}

TEST_F(EncoderCapsHevcTest, EncoderCaps_HEVC_SupportedBitrateMode) {
    EXPECT_TRUE(encoderCaps->isBitrateModeSupported(BITRATE_MODE_CBR));
    EXPECT_TRUE(encoderCaps->isBitrateModeSupported(BITRATE_MODE_VBR));
    EXPECT_TRUE(encoderCaps->isBitrateModeSupported(BITRATE_MODE_CQ));
    EXPECT_TRUE(encoderCaps->isBitrateModeSupported(BITRATE_MODE_CBR_FD));
}

TEST_F(EncoderCapsHevcTest, EncoderCaps_HEVC_SupportedLayeringSchemas) {
    const std::set<std::string> expectedSchemas = {
            "android.generic.2+0", "android.generic.3+1", "webrtc.vp8.2-layer",
            "webrtc.svc.l1t2",     "webrtc.svc.l1t3",
    };
    const std::vector<const char*> schemas = encoderCaps->getSupportedLayeringSchemasPointers();
    std::set<std::string> actualSchemas;
    for (const auto& schema : schemas) {
        actualSchemas.insert(std::string(schema));
    }
    EXPECT_EQ(actualSchemas, expectedSchemas);
}
