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
#define LOG_TAG "CodecCapabilities"

#include <android-base/strings.h>
#include <utils/Log.h>
#include <media/CodecCapabilities.h>
#include <media/CodecCapabilitiesUtils.h>
#include <media/stagefright/foundation/ADebug.h>
#include <media/stagefright/foundation/AMessage.h>

namespace android {

static const int32_t HEVCHighTierLevels =
        HEVCHighTierLevel1 | HEVCHighTierLevel2 | HEVCHighTierLevel21 | HEVCHighTierLevel3 |
        HEVCHighTierLevel31 | HEVCHighTierLevel4 | HEVCHighTierLevel41 | HEVCHighTierLevel5 |
        HEVCHighTierLevel51 | HEVCHighTierLevel52 | HEVCHighTierLevel6 | HEVCHighTierLevel61 |
        HEVCHighTierLevel62;

static const int32_t DEFAULT_MAX_SUPPORTED_INSTANCES = 32;
static const int32_t MAX_SUPPORTED_INSTANCES_LIMIT = 256;

// must not contain KEY_PROFILE
static const std::set<std::pair<std::string, AMessage::Type>> AUDIO_LEVEL_CRITICAL_FORMAT_KEYS = {
    // We don't set level-specific limits for audio codecs today. Key candidates would
    // be sample rate, bit rate or channel count.
    // MediaFormat.KEY_SAMPLE_RATE,
    // MediaFormat.KEY_CHANNEL_COUNT,
    // MediaFormat.KEY_BIT_RATE,
    { KEY_MIME, AMessage::kTypeString }
};

// CodecCapabilities Features
static const std::vector<Feature> DECODER_FEATURES = {
    Feature(FEATURE_AdaptivePlayback, (1 << 0), true),
    Feature(FEATURE_SecurePlayback,   (1 << 1), false),
    Feature(FEATURE_TunneledPlayback, (1 << 2), false),
    Feature(FEATURE_PartialFrame,     (1 << 3), false),
    Feature(FEATURE_FrameParsing,     (1 << 4), false),
    Feature(FEATURE_MultipleFrames,   (1 << 5), false),
    Feature(FEATURE_DynamicTimestamp, (1 << 6), false),
    Feature(FEATURE_LowLatency,       (1 << 7), true),
    Feature(FEATURE_DynamicColorAspects, (1 << 8), true),
    Feature(FEATURE_DetachedSurface,     (1 << 9), true),
    // feature to exclude codec from REGULAR codec list
    Feature(FEATURE_SpecialCodec,     (1 << 30), false, true),
};
static const std::vector<Feature> ENCODER_FEATURES = {
    Feature(FEATURE_IntraRefresh, (1 << 0), false),
    Feature(FEATURE_MultipleFrames, (1 << 1), false),
    Feature(FEATURE_DynamicTimestamp, (1 << 2), false),
    Feature(FEATURE_QpBounds, (1 << 3), false),
    Feature(FEATURE_EncodingStatistics, (1 << 4), false),
    Feature(FEATURE_HdrEditing, (1 << 5), false),
    Feature(FEATURE_HlgEditing, (1 << 6), true),
    Feature(FEATURE_Roi, (1 << 7), true),
    // feature to exclude codec from REGULAR codec list
    Feature(FEATURE_SpecialCodec,     (1 << 30), false, true),
};

// must not contain KEY_PROFILE
static const std::set<std::pair<std::string, AMessage::Type>> VIDEO_LEVEL_CRITICAL_FORMAT_KEYS = {
    { KEY_WIDTH, AMessage::kTypeInt32 },
    { KEY_HEIGHT, AMessage::kTypeInt32 },
    { KEY_FRAME_RATE, AMessage::kTypeInt32 },
    { KEY_FRAME_RATE, AMessage::kTypeFloat },
    { KEY_BIT_RATE, AMessage::kTypeInt32 },
    { KEY_MIME, AMessage::kTypeString }
};

bool CodecCapabilities::SupportsBitrate(Range<int32_t> bitrateRange,
        const sp<AMessage> &format) {
    // consider max bitrate over average bitrate for support
    int32_t maxBitrate = 0;
    format->findInt32(KEY_MAX_BIT_RATE, &maxBitrate);
    int32_t bitrate = 0;
    format->findInt32(KEY_BIT_RATE, &bitrate);

    if (bitrate == 0) {
        bitrate = maxBitrate;
    } else if (maxBitrate != 0) {
        bitrate = std::max(bitrate, maxBitrate);
    }

    if (bitrate > 0) {
        return bitrateRange.contains(bitrate);
    }

    return true;
}

bool CodecCapabilities::isFeatureSupported(const std::string &name) const {
    return mFeaturesSupported.contains(name);
}

bool CodecCapabilities::isFeatureRequired(const std::string &name) const {
    return mFeaturesRequired.contains(name);
}

std::vector<std::string> CodecCapabilities::validFeatures() const {
    std::vector<std::string> res;
    for (const Feature& feature : getValidFeatures()) {
        if (!feature.mInternal) {
            res.push_back(feature.mName);
        }
    }
    return res;
}

std::vector<Feature> CodecCapabilities::getValidFeatures() const {
    if (isEncoder()) {
        return ENCODER_FEATURES;
    } else {
        return DECODER_FEATURES;
    }
}

bool CodecCapabilities::isRegular() const {
    // regular codecs only require default features
    std::vector<Feature> features = getValidFeatures();
    return std::all_of(features.begin(), features.end(),
            [this](Feature feat){ return (feat.mDefault || !isFeatureRequired(feat.mName)); });
}

bool CodecCapabilities::isFormatSupported(const sp<AMessage> &format) const {
    AString mediaType;
    format->findString(KEY_MIME, &mediaType);
    // mediaType must match if present
    if (!base::EqualsIgnoreCase(mMediaType, mediaType.c_str())) {
        return false;
    }

    // check feature support
    for (Feature feat: getValidFeatures()) {
        if (feat.mInternal) {
            continue;
        }

        int32_t yesNo;
        std::string key = KEY_FEATURE_;
        key = key + feat.mName;
        if (!format->findInt32(key.c_str(), &yesNo)) {
            continue;
        }
        if ((yesNo == 1 && !isFeatureSupported(feat.mName)) ||
                (yesNo == 0 && isFeatureRequired(feat.mName))) {
            return false;
        }
    }

    int32_t profile;
    if (format->findInt32(KEY_PROFILE, &profile)) {
        int32_t level = -1;
        format->findInt32(KEY_LEVEL, &level);
        if (!supportsProfileLevel(profile, level)) {
            return false;
        }

        // If we recognize this profile, check that this format is supported by the
        // highest level supported by the codec for that profile. (Ignore specified
        // level beyond the above profile/level check as level is only used as a
        // guidance. E.g. AVC Level 1 CIF format is supported if codec supports level 1.1
        // even though max size for Level 1 is QCIF. However, MPEG2 Simple Profile
        // 1080p format is not supported even if codec supports Main Profile Level High,
        // as Simple Profile does not support 1080p.
        int32_t maxLevel = 0;
        for (ProfileLevel pl : mProfileLevels) {
            if (pl.mProfile == profile && pl.mLevel > maxLevel) {
                // H.263 levels are not completely ordered:
                // Level45 support only implies Level10 support
                if (!base::EqualsIgnoreCase(mMediaType, MIMETYPE_VIDEO_H263)
                        || pl.mLevel != H263Level45
                        || maxLevel == H263Level10) {
                    maxLevel = pl.mLevel;
                }
            }
        }
        std::shared_ptr<CodecCapabilities> levelCaps
                = CreateFromProfileLevel(mMediaType, profile, maxLevel);
        // We must remove the profile from this format otherwise levelCaps.isFormatSupported
        // will get into this same condition and loop forever. Furthermore, since levelCaps
        // does not contain features and bitrate specific keys, keep only keys relevant for
        // a level check.
        sp<AMessage> levelCriticalFormat = new AMessage;

        // critical keys will always contain KEY_MIME, but should also contain others to be
        // meaningful
        if ((isVideo() || isAudio()) && levelCaps != nullptr) {
            const std::set<std::pair<std::string, AMessage::Type>> criticalKeys =
                isVideo() ? VIDEO_LEVEL_CRITICAL_FORMAT_KEYS : AUDIO_LEVEL_CRITICAL_FORMAT_KEYS;
            for (std::pair<std::string, AMessage::Type> key : criticalKeys) {
                if (format->contains(key.first.c_str())) {
                    // AMessage::ItemData value = format->findItem(key.c_str());
                    // levelCriticalFormat->setItem(key.c_str(), value);
                    switch (key.second) {
                        case AMessage::kTypeInt32: {
                            int32_t value;
                            if (format->findInt32(key.first.c_str(), &value)) {
                                levelCriticalFormat->setInt32(key.first.c_str(), value);
                            }
                            break;
                        }
                        case AMessage::kTypeString: {
                            AString value;
                            if (format->findString(key.first.c_str(), &value)) {
                                levelCriticalFormat->setString(key.first.c_str(), value);
                            }
                            break;
                        }
                        case AMessage::kTypeFloat: {
                            float value;
                            if (format->findFloat(key.first.c_str(), &value)) {
                                levelCriticalFormat->setFloat(key.first.c_str(), value);
                            }
                            break;
                        }
                        default:
                            ALOGE("Unsupported type");
                    }
                }
            }
            if (!levelCaps->isFormatSupported(levelCriticalFormat)) {
                return false;
            }
        }
    }
    if (mAudioCaps && !mAudioCaps->supportsFormat(format)) {
        return false;
    }
    if (mVideoCaps && !mVideoCaps->supportsFormat(format)) {
        return false;
    }
    if (mEncoderCaps && !mEncoderCaps->supportsFormat(format)) {
        return false;
    }
    return true;
}

bool CodecCapabilities::supportsProfileLevel(int32_t profile, int32_t level) const {
    for (ProfileLevel pl: mProfileLevels) {
        if (pl.mProfile != profile) {
            continue;
        }

        // No specific level requested
        if (level == -1) {
            return true;
        }

        // AAC doesn't use levels
        if (base::EqualsIgnoreCase(mMediaType, MIMETYPE_AUDIO_AAC)) {
            return true;
        }

        // DTS doesn't use levels
        if (base::EqualsIgnoreCase(mMediaType, MIMETYPE_AUDIO_DTS)
                || base::EqualsIgnoreCase(mMediaType, MIMETYPE_AUDIO_DTS_HD)
                || base::EqualsIgnoreCase(mMediaType, MIMETYPE_AUDIO_DTS_UHD)) {
            return true;
        }

        // H.263 levels are not completely ordered:
        // Level45 support only implies Level10 support
        if (base::EqualsIgnoreCase(mMediaType, MIMETYPE_VIDEO_H263)) {
            if (pl.mLevel != level && pl.mLevel == H263Level45
                    && level > H263Level10) {
                continue;
            }
        }

        // MPEG4 levels are not completely ordered:
        // Level1 support only implies Level0 (and not Level0b) support
        if (base::EqualsIgnoreCase(mMediaType, MIMETYPE_VIDEO_MPEG4)) {
            if (pl.mLevel != level && pl.mLevel == MPEG4Level1
                    && level > MPEG4Level0) {
                continue;
            }
        }

        // HEVC levels incorporate both tiers and levels. Verify tier support.
        if (base::EqualsIgnoreCase(mMediaType, MIMETYPE_VIDEO_HEVC)) {
            bool supportsHighTier =
                (pl.mLevel & HEVCHighTierLevels) != 0;
            bool checkingHighTier = (level & HEVCHighTierLevels) != 0;
            // high tier levels are only supported by other high tier levels
            if (checkingHighTier && !supportsHighTier) {
                continue;
            }
        }

        if (pl.mLevel >= level) {
            // if we recognize the listed profile/level, we must also recognize the
            // profile/level arguments.
            if (CreateFromProfileLevel(mMediaType, profile, pl.mLevel) != nullptr) {
                return CreateFromProfileLevel(mMediaType, profile, level) != nullptr;
            }
            return true;
        }
    }
    return false;
}

sp<AMessage> CodecCapabilities::getDefaultFormat() const {
    return mDefaultFormat;
}

const std::string& CodecCapabilities::getMediaType() {
    return mMediaType;
}

const std::vector<ProfileLevel>& CodecCapabilities::getProfileLevels() {
    return mProfileLevels;
}

std::vector<uint32_t> CodecCapabilities::getColorFormats() const {
    return mColorFormats;
}

int32_t CodecCapabilities::getMaxSupportedInstances() const {
    return mMaxSupportedInstances;
}

bool CodecCapabilities::isAudio() const {
    return mAudioCaps != nullptr;
}

std::shared_ptr<AudioCapabilities>
        CodecCapabilities::getAudioCapabilities() const {
    return mAudioCaps;
}

bool CodecCapabilities::isEncoder() const {
    return mEncoderCaps != nullptr;
}

std::shared_ptr<EncoderCapabilities>
        CodecCapabilities::getEncoderCapabilities() const {
    return mEncoderCaps;
}

bool CodecCapabilities::isVideo() const {
    return mVideoCaps != nullptr;
}

std::shared_ptr<VideoCapabilities> CodecCapabilities::getVideoCapabilities() const {
    return mVideoCaps;
}

// static
std::shared_ptr<CodecCapabilities> CodecCapabilities::CreateFromProfileLevel(
        std::string mediaType, int32_t profile, int32_t level, int32_t maxConcurrentInstances) {
    ProfileLevel pl;
    pl.mProfile = profile;
    pl.mLevel = level;
    sp<AMessage> defaultFormat = new AMessage;
    defaultFormat->setString(KEY_MIME, mediaType.c_str());

    std::vector<ProfileLevel> pls;
    pls.push_back(pl);
    std::vector<uint32_t> colFmts;
    sp<AMessage> capabilitiesInfo = new AMessage;
    std::shared_ptr<CodecCapabilities> ret(new CodecCapabilities());
    ret->init(pls, colFmts, true /* encoder */, defaultFormat, capabilitiesInfo,
            maxConcurrentInstances);
    if (ret->getErrors() != 0) {
        return nullptr;
    }
    return ret;
}

void CodecCapabilities::init(std::vector<ProfileLevel> profLevs, std::vector<uint32_t> colFmts,
        bool encoder, sp<AMessage> &defaultFormat, sp<AMessage> &capabilitiesInfo,
        int32_t maxConcurrentInstances) {
    mColorFormats = colFmts;
    mDefaultFormat = defaultFormat;
    mCapabilitiesInfo = capabilitiesInfo;

    AString mediaTypeAStr;
    mDefaultFormat->findString(KEY_MIME, &mediaTypeAStr);
    mMediaType = mediaTypeAStr.c_str();

    /* VP9 introduced profiles around 2016, so some VP9 codecs may not advertise any
       supported profiles. Determine the level for them using the info they provide. */
    if (profLevs.size() == 0 && mMediaType == MIMETYPE_VIDEO_VP9) {
        ProfileLevel profLev;
        profLev.mProfile = VP9Profile0;
        profLev.mLevel = VideoCapabilities::EquivalentVP9Level(capabilitiesInfo);
        profLevs.push_back(profLev);
    }
    mProfileLevels = profLevs;

    if (mediaTypeAStr.startsWithIgnoreCase("audio/")) {
        mAudioCaps = AudioCapabilities::Create(mMediaType, profLevs, capabilitiesInfo);
        mAudioCaps->getDefaultFormat(mDefaultFormat);
    } else if (mediaTypeAStr.startsWithIgnoreCase("video/")
            || mediaTypeAStr.equalsIgnoreCase(MIMETYPE_IMAGE_ANDROID_HEIC)) {
        mVideoCaps = VideoCapabilities::Create(mMediaType, profLevs, capabilitiesInfo);
    }

    if (encoder) {
        mEncoderCaps = EncoderCapabilities::Create(mMediaType, profLevs, capabilitiesInfo);
        mEncoderCaps->getDefaultFormat(mDefaultFormat);
    }

    mMaxSupportedInstances = maxConcurrentInstances > 0
            ? maxConcurrentInstances : DEFAULT_MAX_SUPPORTED_INSTANCES;
    AString maxConcurrentInstancesStr;
    int32_t maxInstances
            = capabilitiesInfo->findString("max-concurrent-instances", &maxConcurrentInstancesStr)
            ? (int32_t)strtol(maxConcurrentInstancesStr.c_str(), NULL, 10)
            : mMaxSupportedInstances;
    mMaxSupportedInstances =
            Range(1, MAX_SUPPORTED_INSTANCES_LIMIT).clamp(maxInstances);

    mFeaturesRequired.clear();
    mFeaturesSupported.clear();
    for (Feature feat: getValidFeatures()) {
        std::string key = KEY_FEATURE_;
        key = key + feat.mName;
        int yesNo = -1;
        if (!capabilitiesInfo->findInt32(key.c_str(), &yesNo)) {
            continue;
        }
        if (yesNo > 0) {
            mFeaturesRequired.insert(feat.mName);
        }
        mFeaturesSupported.insert(feat.mName);
        if (!feat.mInternal) {
            mDefaultFormat->setInt32(key.c_str(), 1);
        }
    }
}

int32_t CodecCapabilities::getErrors() const {
    if (mAudioCaps) {
        return mAudioCaps->mError;
    } else if (mVideoCaps) {
        return mVideoCaps->mError;
    }
    return 0;
}

}  // namespace android
