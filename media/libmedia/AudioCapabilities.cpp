/*
 * Copyright 2024, The Android Open Source Project
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

//#define LOG_NDEBUG 0
#define LOG_TAG "AudioCapabilities"

#include <android-base/strings.h>
#include <android-base/properties.h>

#include <media/AudioCapabilities.h>
#include <media/CodecCapabilities.h>
#include <media/stagefright/MediaCodecConstants.h>

namespace android {

// Merges one sorted vector into another without duplicates.
static std::vector<int32_t> MergeSortedVectorsAndRemoveDuplicates(std::vector<int32_t> &one,
        std::vector<int32_t> &another) {
    std::set<int32_t> res;
    res.insert(one.begin(), one.end());
    res.insert(another.begin(), another.end());
    return std::vector<int32_t>(res.begin(), res.end());
}

static std::vector<Range<int32_t>> ConvertDiscreateSampleRatesToRanges(
        std::vector<int32_t> &rates) {
    std::vector<Range<int32_t>> sampleRateRanges;
    std::sort(rates.begin(), rates.end());
    for (int32_t rate : rates) {
        sampleRateRanges.push_back(Range<int32_t>(rate, rate));
    }
    return sampleRateRanges;
}

const Range<int32_t>& AudioCapabilities::getBitrateRange() const {
    return mBitrateRange;
}

const std::vector<int32_t>& AudioCapabilities::getSupportedSampleRates() const {
    return mSampleRates;
}

const std::vector<Range<int32_t>>&
        AudioCapabilities::getSupportedSampleRateRanges() const {
    return mSampleRateRanges;
}

int32_t AudioCapabilities::getMaxInputChannelCount() const {
    int32_t overallMax = 0;
    for (int i = mInputChannelRanges.size() - 1; i >= 0; i--) {
        int32_t lmax = mInputChannelRanges[i].upper();
        if (lmax > overallMax) {
            overallMax = lmax;
        }
    }
    return overallMax;
}

int32_t AudioCapabilities::getMinInputChannelCount() const {
    int32_t overallMin = MAX_INPUT_CHANNEL_COUNT;
    for (int i = mInputChannelRanges.size() - 1; i >= 0; i--) {
        int32_t lmin = mInputChannelRanges[i].lower();
        if (lmin < overallMin) {
            overallMin = lmin;
        }
    }
    return overallMin;
}

const std::vector<Range<int32_t>>&
        AudioCapabilities::getInputChannelCountRanges() const {
    return mInputChannelRanges;
}

// static
std::shared_ptr<AudioCapabilities> AudioCapabilities::Create(std::string mediaType,
        std::vector<ProfileLevel> profLevs, const sp<AMessage> &format) {
    std::shared_ptr<AudioCapabilities> caps(new AudioCapabilities());
    caps->init(mediaType, profLevs, format);
    return caps;
}

void AudioCapabilities::init(std::string mediaType, std::vector<ProfileLevel> profLevs,
        const sp<AMessage> &format) {
    mMediaType = mediaType;
    mProfileLevels = profLevs;
    mError = 0;

    initWithPlatformLimits();
    applyLevelLimits();
    parseFromInfo(format);
}

void AudioCapabilities::initWithPlatformLimits() {
    mBitrateRange = Range<int32_t>(1, INT32_MAX);
    mInputChannelRanges.push_back(Range<int32_t>(1, MAX_INPUT_CHANNEL_COUNT));

    const int32_t minSampleRate = base::GetIntProperty("ro.mediacodec.min_sample_rate", 7350);
    const int32_t maxSampleRate = base::GetIntProperty("ro.mediacodec.max_sample_rate", 192000);
    mSampleRateRanges.push_back(Range<int32_t>(minSampleRate, maxSampleRate));
}

bool AudioCapabilities::supports(std::optional<int32_t> sampleRate,
        std::optional<int32_t> inputChannels) {
    // channels and sample rates are checked orthogonally
    if (inputChannels
            && !std::any_of(mInputChannelRanges.begin(), mInputChannelRanges.end(),
            [inputChannels](const Range<int32_t> &a) {
                    return a.contains(inputChannels.value()); })) {
        return false;
    }
    if (sampleRate
            && !std::any_of(mSampleRateRanges.begin(), mSampleRateRanges.end(),
            [sampleRate](const Range<int32_t> &a) { return a.contains(sampleRate.value()); })) {
        return false;
    }
    return true;
}

bool AudioCapabilities::isSampleRateSupported(int32_t sampleRate) {
    return supports(std::make_optional<int32_t>(sampleRate), std::nullopt);
}

void AudioCapabilities::limitSampleRates(std::vector<int32_t> rates) {
    std::vector<Range<int32_t>> sampleRateRanges;
    std::sort(rates.begin(), rates.end());
    for (int32_t rate : rates) {
        if (supports(std::make_optional<int32_t>(rate), std::nullopt /* channels */)) {
            sampleRateRanges.push_back(Range<int32_t>(rate, rate));
        }
    }
    mSampleRateRanges = intersectSortedDistinctRanges(mSampleRateRanges, sampleRateRanges);
    createDiscreteSampleRates();
}

void AudioCapabilities::createDiscreteSampleRates() {
    mSampleRates.clear();
    for (int i = 0; i < mSampleRateRanges.size(); i++) {
        mSampleRates.push_back(mSampleRateRanges[i].lower());
    }
}

void AudioCapabilities::limitSampleRates(std::vector<Range<int32_t>> rateRanges) {
    sortDistinctRanges(&rateRanges);
    mSampleRateRanges = intersectSortedDistinctRanges(mSampleRateRanges, rateRanges);
    // check if all values are discrete
    for (Range<int32_t> range: mSampleRateRanges) {
        if (range.lower() != range.upper()) {
            mSampleRates.clear();
            return;
        }
    }
    createDiscreteSampleRates();
}

void AudioCapabilities::applyLevelLimits() {
    std::vector<int32_t> sampleRates;
    std::vector<Range<int32_t>> sampleRateRanges;
    std::optional<Range<int32_t>> bitRates;
    int32_t maxChannels = 1;

    // const char *mediaType = mMediaType.c_str();
    if (base::EqualsIgnoreCase(mMediaType, MIMETYPE_AUDIO_MPEG)) {
        sampleRates = {
                8000, 11025, 12000,
                16000, 22050, 24000,
                32000, 44100, 48000 };
        bitRates = Range<int32_t>(8000, 320000);
        maxChannels = 2;
    } else if (base::EqualsIgnoreCase(mMediaType, MIMETYPE_AUDIO_AMR_NB)) {
        sampleRates = { 8000 };
        bitRates = Range<int32_t>(4750, 12200);
        maxChannels = 1;
    } else if (base::EqualsIgnoreCase(mMediaType, MIMETYPE_AUDIO_AMR_WB)) {
        sampleRates = { 16000 };
        bitRates = Range<int32_t>(6600, 23850);
        maxChannels = 1;
    } else if (base::EqualsIgnoreCase(mMediaType, MIMETYPE_AUDIO_AAC)) {
        sampleRates = {
                7350, 8000,
                11025, 12000, 16000,
                22050, 24000, 32000,
                44100, 48000, 64000,
                88200, 96000 };
        bitRates = Range<int32_t>(8000, 510000);
        maxChannels = 48;
    } else if (base::EqualsIgnoreCase(mMediaType, MIMETYPE_AUDIO_VORBIS)) {
        bitRates = Range<int32_t>(32000, 500000);
        sampleRateRanges = { Range<int32_t>(8000, 192000) };
        maxChannels = 255;
    } else if (base::EqualsIgnoreCase(mMediaType, MIMETYPE_AUDIO_OPUS)) {
        bitRates = Range<int32_t>(6000, 510000);
        sampleRates = { 8000, 12000, 16000, 24000, 48000 };
        maxChannels = 255;
    } else if (base::EqualsIgnoreCase(mMediaType, MIMETYPE_AUDIO_RAW)) {
        sampleRateRanges = { Range<int32_t>(1, 192000) };
        bitRates = Range<int32_t>(1, 10000000);
        maxChannels = MAX_NUM_CHANNELS;
    } else if (base::EqualsIgnoreCase(mMediaType, MIMETYPE_AUDIO_FLAC)) {
        sampleRateRanges = { Range<int32_t>(1, 655350) };
        // lossless codec, so bitrate is ignored
        maxChannels = 255;
    } else if (base::EqualsIgnoreCase(mMediaType, MIMETYPE_AUDIO_G711_ALAW)
            || base::EqualsIgnoreCase(mMediaType, MIMETYPE_AUDIO_G711_MLAW)) {
        sampleRates = { 8000 };
        bitRates = Range<int32_t>(64000, 64000);
        // platform allows multiple channels for this format
        maxChannels = MAX_INPUT_CHANNEL_COUNT;
    } else if (base::EqualsIgnoreCase(mMediaType, MIMETYPE_AUDIO_MSGSM)) {
        sampleRates = { 8000 };
        bitRates = Range<int32_t>(13000, 13000);
        maxChannels = 1;
    } else if (base::EqualsIgnoreCase(mMediaType, MIMETYPE_AUDIO_AC3)) {
        maxChannels = 6;
    } else if (base::EqualsIgnoreCase(mMediaType, MIMETYPE_AUDIO_EAC3)) {
        maxChannels = 16;
    } else if (base::EqualsIgnoreCase(mMediaType, MIMETYPE_AUDIO_EAC3_JOC)) {
        sampleRates = { 48000 };
        bitRates = Range<int32_t>(32000, 6144000);
        maxChannels = 16;
    } else if (base::EqualsIgnoreCase(mMediaType, MIMETYPE_AUDIO_AC4)) {
        sampleRates = { 44100, 48000, 96000, 192000 };
        bitRates = Range<int32_t>(16000, 2688000);
        maxChannels = 24;
    } else if (base::EqualsIgnoreCase(mMediaType, MIMETYPE_AUDIO_DTS)) {
        sampleRates = { 44100, 48000 };
        bitRates = Range<int32_t>(96000, 1524000);
        maxChannels = 6;
    } else if (base::EqualsIgnoreCase(mMediaType, MIMETYPE_AUDIO_DTS_HD)) {
        for (ProfileLevel profileLevel: mProfileLevels) {
            std::vector<int32_t> SR;
            Range<int32_t> BR;
            switch (profileLevel.mProfile) {
                case DTS_HDProfileLBR:
                    SR = { 22050, 24000, 44100, 48000 };
                    BR = Range<int32_t>(32000, 768000);
                    break;
                case DTS_HDProfileHRA:
                case DTS_HDProfileMA:
                    SR = { 44100, 48000, 88200, 96000, 176400, 192000 };
                    BR = Range<int32_t>(96000, 24500000);
                    break;
                default:
                    ALOGW("Unrecognized profile %d for %s", profileLevel.mProfile,
                            mMediaType.c_str());
                    mError |= ERROR_CAPABILITIES_UNRECOGNIZED;
                    SR = { 44100, 48000, 88200, 96000, 176400, 192000 };
                    BR = Range<int32_t>(96000, 24500000);
            }
            sampleRates = MergeSortedVectorsAndRemoveDuplicates(sampleRates, SR);
            bitRates = bitRates ? bitRates.value().extend(BR) : BR;
        }
        maxChannels = 8;
    } else if (base::EqualsIgnoreCase(mMediaType, MIMETYPE_AUDIO_DTS_UHD)) {
        for (ProfileLevel profileLevel: mProfileLevels) {
            std::vector<int32_t> SR;
            Range<int32_t> BR;
            int32_t MC = 0;
            switch (profileLevel.mProfile) {
                case DTS_UHDProfileP2:
                    SR = { 48000 };
                    BR = Range<int32_t>(96000, 768000);
                    MC = 10;
                    break;
                case DTS_UHDProfileP1:
                    SR = { 44100, 48000, 88200, 96000, 176400, 192000 };
                    BR = Range<int32_t>(96000, 24500000);
                    MC = 32;
                    break;
                default:
                    ALOGW("Unrecognized profile %d for %s", profileLevel.mProfile,
                            mMediaType.c_str());
                    mError |= ERROR_CAPABILITIES_UNRECOGNIZED;
                    SR = { 44100, 48000, 88200, 96000, 176400, 192000 };
                    BR = Range<int32_t>(96000, 24500000);
                    MC = 32;
            }
            sampleRates = MergeSortedVectorsAndRemoveDuplicates(sampleRates, SR);
            bitRates = bitRates ? bitRates.value().extend(BR) : BR;
            maxChannels = std::max(MC, maxChannels);
        }
    } else if (base::EqualsIgnoreCase(mMediaType, MIMETYPE_AUDIO_IAMF)) {
        for (ProfileLevel profileLevel : mProfileLevels) {
            std::vector<int32_t> SR;
            std::vector<Range<int32_t>> SRR;
            Range<int32_t> BR;
            int32_t MC = 0;
            auto iamfEncoding = profileLevel.mProfile & 0xff;
            auto iamfProfile = profileLevel.mProfile & (0xff << 16);
            switch (iamfProfile) {
                case IAMF_PROFILE_SIMPLE:
                    // Per the IAMF spec, the Simple profile can have only one Audio Element and 16
                    // input channels.
                    MC = 16;
                    break;
                case IAMF_PROFILE_BASE:
                    // The Base profile can have up to 18 input channels.
                    MC = 18;
                    break;
                case IAMF_PROFILE_BASE_ENHANCED:
                    // The Base Enhanced profile can have up to 28 input channels.
                    MC = 28;
                    break;
                default:
                    // Set maxChannels to the max known for unknown profiles.
                    MC = 28;
                    ALOGW("Unrecognized IAMF profile %d for %s", iamfProfile, mMediaType.c_str());
                    mError |= ERROR_CAPABILITIES_UNRECOGNIZED;
            }
            // Samplerate and bitrate are only restricted by the underlying codecs, so for AAC,
            // FLAC, and Opus these numbers match their numbers above.
            switch (iamfEncoding) {
                case IAMF_CODEC_OPUS:
                    SR = {48000};
                    SRR = ConvertDiscreateSampleRatesToRanges(SR);
                    BR = Range<int32_t>(6000, 128000 * MC);
                    break;
                case IAMF_CODEC_AAC:
                    SR = {7350,  8000,  11025, 12000, 16000, 22050, 24000,
                                   32000, 44100, 48000, 64000, 88200, 96000};
                    SRR = ConvertDiscreateSampleRatesToRanges(SR);
                    BR = Range<int32_t>(6000, 128000 * MC);
                    break;
                case IAMF_CODEC_FLAC:
                    SRR = { Range<int32_t>(1, 655350) };
                    // Lossless, bitrate range ignored.  Possibly as wide as
                    // Range<int32_t>(1, 21000000).
                    BR = Range<int32_t>(1, 21000000);
                    break;
                case IAMF_CODEC_PCM:
                    // PCM is limited by the IAMF spec to the following.
                    SR = {16000, 32000, 44100, 48000, 96000};
                    SRR = ConvertDiscreateSampleRatesToRanges(SR);
                    // Lossless, no bitrate range.
                    BR = Range<int32_t>(1, 21000000);
                    break;
                default:
                    ALOGW("Unrecognized encoding %d for %s", iamfEncoding, mMediaType.c_str());
                    mError |= ERROR_CAPABILITIES_UNRECOGNIZED;
            }
            sampleRateRanges = unionSortedDistinctRanges(sampleRateRanges, SRR);
            bitRates = BR.empty() ? bitRates
                                  : bitRates ? bitRates.value().extend(BR)
                                             : BR;
            maxChannels = std::max(MC, maxChannels);
        }
    } else {
        ALOGW("Unsupported mediaType %s", mMediaType.c_str());
        maxChannels = MAX_INPUT_CHANNEL_COUNT;
        mError |= ERROR_CAPABILITIES_UNSUPPORTED;
    }

    // restrict ranges
    if (!sampleRates.empty()) {
        limitSampleRates(sampleRates);
    } else if (!sampleRateRanges.empty()) {
        limitSampleRates(sampleRateRanges);
    }

    Range<int32_t> channelRange = Range<int32_t>(1, maxChannels);
    std::vector<Range<int32_t>> inputChannels = { channelRange };
    applyLimits(inputChannels, bitRates);
}

void AudioCapabilities::applyLimits(
        const std::vector<Range<int32_t>> &inputChannels,
        const std::optional<Range<int32_t>> &bitRates) {
    // clamp & make a local copy
    std::vector<Range<int32_t>> inputChannelsCopy(inputChannels.size());
    for (int i = 0; i < inputChannels.size(); i++) {
        int32_t lower = inputChannels[i].clamp(1);
        int32_t upper = inputChannels[i].clamp(MAX_INPUT_CHANNEL_COUNT);
        inputChannelsCopy[i] = Range<int32_t>(lower, upper);
    }

    // sort, intersect with existing, & save channel list
    sortDistinctRanges(&inputChannelsCopy);
    mInputChannelRanges = intersectSortedDistinctRanges(inputChannelsCopy, mInputChannelRanges);

    if (bitRates) {
        mBitrateRange = mBitrateRange.intersect(bitRates.value());
    }
}

void AudioCapabilities::parseFromInfo(const sp<AMessage> &format) {
    int32_t maxInputChannels = MAX_INPUT_CHANNEL_COUNT;
    std::vector<Range<int32_t>> channels = { Range<int32_t>(1, maxInputChannels) };
    std::optional<Range<int32_t>> bitRates = POSITIVE_INT32;

    AString rateAString;
    if (format->findString("sample-rate-ranges", &rateAString)) {
        std::vector<std::string> rateStrings = base::Split(std::string(rateAString.c_str()), ",");
        std::vector<Range<int32_t>> rateRanges;
        for (std::string rateString : rateStrings) {
            std::optional<Range<int32_t>> rateRange = Range<int32_t>::Parse(rateString);
            if (!rateRange) {
                continue;
            }
            rateRanges.push_back(rateRange.value());
        }
        limitSampleRates(rateRanges);
    }

    // we will prefer channel-ranges over max-channel-count
    AString valueStr;
    if (format->findString("channel-ranges", &valueStr)) {
        std::vector<std::string> channelStrings = base::Split(std::string(valueStr.c_str()), ",");
        std::vector<Range<int32_t>> channelRanges;
        for (std::string channelString : channelStrings) {
            std::optional<Range<int32_t>> channelRange = Range<int32_t>::Parse(channelString);
            if (!channelRange) {
                continue;
            }
            channelRanges.push_back(channelRange.value());
        }
        channels = channelRanges;
    } else if (format->findString("channel-range", &valueStr)) {
        std::optional<Range<int32_t>> oneRange
                = Range<int32_t>::Parse(std::string(valueStr.c_str()));
        if (oneRange) {
            channels = { oneRange.value() };
        }
    } else if (format->findString("max-channel-count", &valueStr)) {
        maxInputChannels = std::atoi(valueStr.c_str());
        if (maxInputChannels == 0) {
            channels = { Range<int32_t>(0, 0) };
        } else {
            channels = { Range<int32_t>(1, maxInputChannels) };
        }
    } else if ((mError & ERROR_CAPABILITIES_UNSUPPORTED) != 0) {
        maxInputChannels = 0;
        channels = { Range<int32_t>(0, 0) };
    }

    if (format->findString("bitrate-range", &valueStr)) {
        std::optional<Range<int32_t>> parsedBitrate = Range<int32_t>::Parse(valueStr.c_str());
        if (parsedBitrate) {
            bitRates = bitRates.value().intersect(parsedBitrate.value());
        }
    }

    applyLimits(channels, bitRates);
}

void AudioCapabilities::getDefaultFormat(sp<AMessage> &format) {
    // report settings that have only a single choice
    if (mBitrateRange.lower() == mBitrateRange.upper()) {
        format->setInt32(KEY_BIT_RATE, mBitrateRange.lower());
    }
    if (getMaxInputChannelCount() == 1) {
        // mono-only format
        format->setInt32(KEY_CHANNEL_COUNT, 1);
    }
    if (!mSampleRates.empty() && mSampleRates.size() == 1) {
        format->setInt32(KEY_SAMPLE_RATE, mSampleRates[0]);
    }
}

bool AudioCapabilities::supportsFormat(const sp<AMessage> &format) {
    int32_t sampleRateValue;
    std::optional<int32_t> sampleRate = format->findInt32(KEY_SAMPLE_RATE, &sampleRateValue)
            ? std::make_optional<int32_t>(sampleRateValue) : std::nullopt;
    int32_t channelsValue;
    std::optional<int32_t> channels = format->findInt32(KEY_CHANNEL_COUNT, &channelsValue)
            ? std::make_optional<int32_t>(channelsValue) : std::nullopt;

    if (!supports(sampleRate, channels)) {
        return false;
    }

    if (!CodecCapabilities::SupportsBitrate(mBitrateRange, format)) {
        return false;
    }

    // nothing to do for:
    // KEY_CHANNEL_MASK: codecs don't get this
    // KEY_IS_ADTS:      required feature for all AAC decoders
    return true;
}

}  // namespace android