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
#define LOG_TAG "EncoderCapabilities"

#include <android-base/strings.h>

#include <media/CodecCapabilities.h>
#include <media/EncoderCapabilities.h>
#include <media/stagefright/MediaCodecConstants.h>

namespace android {

const Range<int>& EncoderCapabilities::getQualityRange() {
    return mQualityRange;
}

const Range<int>& EncoderCapabilities::getComplexityRange() {
    return mComplexityRange;
}

// static
int EncoderCapabilities::ParseBitrateMode(std::string mode) {
    for (Feature feat: sBitrateModes) {
        if (base::EqualsIgnoreCase(feat.mName, mode)) {
            return feat.mValue;
        }
    }
    return 0;
}

bool EncoderCapabilities::isBitrateModeSupported(int mode) {
    for (Feature feat : sBitrateModes) {
        if (mode == feat.mValue) {
            return (mBitControl & (1 << mode)) != 0;
        }
    }
    return false;
}

const std::vector<const char*>& EncoderCapabilities::getSupportedLayeringSchemasPointers() {
    return mLayeringSchemaPointerArray;
}

// static
std::shared_ptr<EncoderCapabilities> EncoderCapabilities::Create(std::string mediaType,
        std::vector<ProfileLevel> profLevs, const sp<AMessage> &format) {
    std::shared_ptr<EncoderCapabilities> caps(new EncoderCapabilities());
    caps->init(mediaType, profLevs, format);
    return caps;
}

void EncoderCapabilities::init(std::string mediaType, std::vector<ProfileLevel> profLevs,
        const sp<AMessage> &format) {
    // no support for complexity or quality yet
    mMediaType = mediaType;
    mProfileLevels = profLevs;
    mComplexityRange = Range(0, 0);
    mQualityRange = Range(0, 0);
    mLayeringSchemaPointerArray.clear();
    mLayeringSchemas.clear();
    mBitControl = (1 << BITRATE_MODE_VBR);

    applyLevelLimits();
    parseFromInfo(format);
}

void EncoderCapabilities::applyLevelLimits() {
    if (base::EqualsIgnoreCase(mMediaType, MIMETYPE_AUDIO_FLAC)) {
        mComplexityRange = Range(0, 8);
        mBitControl = (1 << BITRATE_MODE_CQ);
    } else if (base::EqualsIgnoreCase(mMediaType, MIMETYPE_AUDIO_AMR_NB)
            || base::EqualsIgnoreCase(mMediaType, MIMETYPE_AUDIO_AMR_WB)
            || base::EqualsIgnoreCase(mMediaType, MIMETYPE_AUDIO_G711_ALAW)
            || base::EqualsIgnoreCase(mMediaType, MIMETYPE_AUDIO_G711_MLAW)
            || base::EqualsIgnoreCase(mMediaType, MIMETYPE_AUDIO_MSGSM)) {
        mBitControl = (1 << BITRATE_MODE_CBR);
    }
}

void EncoderCapabilities::parseFromInfo(const sp<AMessage> &format) {
    AString complexityRangeAStr;
    if (format->findString("complexity-range", &complexityRangeAStr)) {
        std::optional<Range<int>> complexityRangeOpt
                = Range<int32_t>::Parse(std::string(complexityRangeAStr.c_str()));
        mComplexityRange = complexityRangeOpt.value_or(mComplexityRange);
        // TODO should we limit this to level limits?
    }
    AString qualityRangeAStr;
    if (format->findString("quality-range", &qualityRangeAStr)) {
        std::optional<Range<int>> qualityRangeOpt
                = Range<int32_t>::Parse(std::string(qualityRangeAStr.c_str()));
        mQualityRange = qualityRangeOpt.value_or(mQualityRange);
    }
    AString supportedLayeringSchemasAsStr;
    if (format->findString("ts-schemas", &supportedLayeringSchemasAsStr)) {
        if (supportedLayeringSchemasAsStr.size() > 0) {
            mLayeringSchemaPointerArray.clear();
            mLayeringSchemas = base::Split(std::string(supportedLayeringSchemasAsStr.c_str()), ";");
            for (const std::string& schema : mLayeringSchemas) {
                mLayeringSchemaPointerArray.push_back(schema.c_str());
            }
        }
    }

    AString bitrateModesAStr;
    if (format->findString("feature-bitrate-modes", &bitrateModesAStr)) {
        mBitControl = 0;
        for (std::string mode: base::Split(std::string(bitrateModesAStr.c_str()), ",")) {
            mBitControl |= (1 << ParseBitrateMode(mode));
        }
    }
    format->findInt32("complexity-default", &mDefaultComplexity);
    format->findInt32("quality-default", &mDefaultQuality);
    AString qualityScaleAStr;
    if (format->findString("quality-scale", &qualityScaleAStr)) {
        mQualityScale = std::string(qualityScaleAStr.c_str());
    }
}

bool EncoderCapabilities::supports(
        std::optional<int> complexity, std::optional<int> quality, std::optional<int> profile) {
    bool ok = true;
    if (complexity) {
        ok &= mComplexityRange.contains(complexity.value());
    }
    if (quality) {
        ok &= mQualityRange.contains(quality.value());
    }
    if (profile) {
        ok &= std::any_of(mProfileLevels.begin(), mProfileLevels.end(),
                [&profile](ProfileLevel pl){ return pl.mProfile == profile.value(); });
    }
    return ok;
}

void EncoderCapabilities::getDefaultFormat(sp<AMessage> &format) {
    // don't list trivial quality/complexity as default for now
    if (mQualityRange.upper() != mQualityRange.lower()
            && mDefaultQuality != 0) {
        format->setInt32(KEY_QUALITY, mDefaultQuality);
    }
    if (mComplexityRange.upper() != mComplexityRange.lower()
            && mDefaultComplexity != 0) {
        format->setInt32(KEY_COMPLEXITY, mDefaultComplexity);
    }
    // bitrates are listed in order of preference
    for (Feature feat : sBitrateModes) {
        if ((mBitControl & (1 << feat.mValue)) != 0) {
            format->setInt32(KEY_BITRATE_MODE, feat.mValue);
            break;
        }
    }
}

bool EncoderCapabilities::supportsFormat(const sp<AMessage> &format) {
    int32_t mode;
    if (format->findInt32(KEY_BITRATE_MODE, &mode) && !isBitrateModeSupported(mode)) {
        return false;
    }

    int tmp;
    std::optional<int> complexity = std::nullopt;
    if (format->findInt32(KEY_COMPLEXITY, &tmp)) {
        complexity = tmp;
    }

    if (base::EqualsIgnoreCase(mMediaType, MIMETYPE_AUDIO_FLAC)) {
        int flacComplexity;
        if (format->findInt32(KEY_FLAC_COMPRESSION_LEVEL, &flacComplexity)) {
            if (!complexity) {
                complexity = flacComplexity;
            } else if (flacComplexity != complexity.value()) {
                ALOGE("Conflicting values for complexity and flac-compression-level,"
                        " which are %d and %d", complexity.value(), flacComplexity);
                return false;
            }
        }
    }

    // other audio parameters
    std::optional<int> profile = std::nullopt;
    if (format->findInt32(KEY_PROFILE, &tmp)) {
        profile = tmp;
    }

    if (base::EqualsIgnoreCase(mMediaType, MIMETYPE_AUDIO_AAC)) {
        int aacProfile;
        if (format->findInt32(KEY_AAC_PROFILE, &aacProfile)) {
            if (!profile) {
                profile = aacProfile;
            } else if (aacProfile != profile.value()) {
                ALOGE("Conflicting values for profile and aac-profile, which are %d and %d",
                        profile.value(), aacProfile);
                return false;
            }
        }
    }

    std::optional<int> quality = std::nullopt;
    if (format->findInt32(KEY_QUALITY, &tmp)) {
        quality = tmp;
    }

    return supports(complexity, quality, profile);
}

}  // namespace android
