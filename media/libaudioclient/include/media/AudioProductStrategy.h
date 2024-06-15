/*
 * Copyright (C) 2018 The Android Open Source Project
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


#pragma once

#include <android/media/AudioProductStrategy.h>
#include <media/AidlConversionUtil.h>
#include <media/AudioCommonTypes.h>
#include <media/VolumeGroupAttributes.h>
#include <system/audio.h>
#include <system/audio_policy.h>
#include <binder/Parcelable.h>

namespace android {

class AudioProductStrategy : public Parcelable
{
public:
    AudioProductStrategy() {}
    AudioProductStrategy(const std::string &name,
                         const std::vector<VolumeGroupAttributes> &attributes,
                         product_strategy_t id) :
        mName(name), mVolumeGroupAttributes(attributes), mId(id) {}

    const std::string &getName() const { return mName; }
    std::vector<VolumeGroupAttributes> getVolumeGroupAttributes() const {
        return mVolumeGroupAttributes;
    }
    product_strategy_t getId() const { return mId; }

    status_t readFromParcel(const Parcel *parcel) override;
    status_t writeToParcel(Parcel *parcel) const override;

    /**
     * @brief attributesMatchesScore: checks if client attributes matches with a reference
     * attributes "matching" means the usage shall match if reference attributes has a defined
     * usage, AND content type shall match if reference attributes has a defined content type AND
     * flags shall match if reference attributes has defined flags AND
     * tags shall match if reference attributes has defined tags.
     * Reference attributes "default" shall be considered as a weak match case. This convention
     * is used to identify the default strategy.
     * @param refAttributes to be considered
     * @param clientAttritubes to be considered
     * @return {@code INVALID_SCORE} if not matching, {@code MATCH_ON_DEFAULT_SCORE} if matching
     * to default strategy, non zero positive score if matching a strategy.
     */
    static int attributesMatchesScore(audio_attributes_t refAttributes,
                                      audio_attributes_t clientAttritubes);

    static bool attributesMatches(audio_attributes_t refAttributes,
                                  audio_attributes_t clientAttritubes) {
        return attributesMatchesScore(refAttributes, clientAttritubes) > 0;
    }

    static const int MATCH_ON_TAGS_SCORE = 1 << 3;
    static const int MATCH_ON_FLAGS_SCORE = 1 << 2;
    static const int MATCH_ON_USAGE_SCORE = 1 << 1;
    static const int MATCH_ON_CONTENT_TYPE_SCORE = 1 << 0;
    static const int MATCH_ON_DEFAULT_SCORE = 0;
    static const int MATCH_EQUALS = MATCH_ON_TAGS_SCORE | MATCH_ON_FLAGS_SCORE
            | MATCH_ON_USAGE_SCORE | MATCH_ON_CONTENT_TYPE_SCORE;
    static const int NO_MATCH = -1;

private:
    std::string mName;
    std::vector<VolumeGroupAttributes> mVolumeGroupAttributes;
    product_strategy_t mId;
};

using AudioProductStrategyVector = std::vector<AudioProductStrategy>;

// AIDL conversion routines.
ConversionResult<media::AudioProductStrategy>
legacy2aidl_AudioProductStrategy(const AudioProductStrategy& legacy);
ConversionResult<AudioProductStrategy>
aidl2legacy_AudioProductStrategy(const media::AudioProductStrategy& aidl);

} // namespace android

