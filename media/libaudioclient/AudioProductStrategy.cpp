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

#define LOG_TAG "AudioProductStrategy"
//#define LOG_NDEBUG 0
#include <utils/Log.h>
#include <media/AudioProductStrategy.h>
#include <media/AudioAttributes.h>
#include <media/PolicyAidlConversion.h>

#define RETURN_STATUS_IF_ERROR(x) \
    { auto _tmp = (x); if (_tmp != OK) return _tmp; }

namespace android {

status_t AudioProductStrategy::readFromParcel(const Parcel* parcel) {
    media::AudioProductStrategy aidl;
    RETURN_STATUS_IF_ERROR(aidl.readFromParcel(parcel));
    *this = VALUE_OR_RETURN_STATUS(aidl2legacy_AudioProductStrategy(aidl));
    return OK;
}

status_t AudioProductStrategy::writeToParcel(Parcel* parcel) const {
    media::AudioProductStrategy aidl = VALUE_OR_RETURN_STATUS(
            legacy2aidl_AudioProductStrategy(*this));
    return aidl.writeToParcel(parcel);
}

ConversionResult<media::AudioProductStrategy>
legacy2aidl_AudioProductStrategy(const AudioProductStrategy& legacy) {
    media::AudioProductStrategy aidl;
    aidl.name = legacy.getName();
    aidl.audioAttributes = VALUE_OR_RETURN(
            convertContainer<std::vector<media::AudioAttributesEx>>(
                    legacy.getAudioAttributes(),
                    legacy2aidl_AudioAttributes_AudioAttributesEx));
    aidl.id = VALUE_OR_RETURN(legacy2aidl_product_strategy_t_int32_t(legacy.getId()));
    return aidl;
}

ConversionResult<AudioProductStrategy>
aidl2legacy_AudioProductStrategy(const media::AudioProductStrategy& aidl) {
    return AudioProductStrategy(
            aidl.name,
            VALUE_OR_RETURN(
                    convertContainer<std::vector<AudioAttributes>>(
                            aidl.audioAttributes,
                            aidl2legacy_AudioAttributesEx_AudioAttributes)),
            VALUE_OR_RETURN(aidl2legacy_int32_t_product_strategy_t(aidl.id)));
}

// Keep in sync with android/media/audiopolicy/AudioProductStrategy#attributeMatches
bool AudioProductStrategy::attributesMatches(const audio_attributes_t refAttributes,
                                        const audio_attributes_t clientAttritubes)
{
    if (refAttributes == AUDIO_ATTRIBUTES_INITIALIZER) {
        // The default product strategy is the strategy that holds default attributes by convention.
        // All attributes that fail to match will follow the default strategy for routing.
        // Choosing the default must be done as a fallback, the attributes match shall not
        // select the default.
        return false;
    }
    return ((refAttributes.usage == AUDIO_USAGE_UNKNOWN) ||
            (clientAttritubes.usage == refAttributes.usage)) &&
            ((refAttributes.content_type == AUDIO_CONTENT_TYPE_UNKNOWN) ||
             (clientAttritubes.content_type == refAttributes.content_type)) &&
            ((refAttributes.flags == AUDIO_FLAG_NONE) ||
             (clientAttritubes.flags != AUDIO_FLAG_NONE &&
            (clientAttritubes.flags & refAttributes.flags) == refAttributes.flags)) &&
            ((strlen(refAttributes.tags) == 0) ||
             (std::strcmp(clientAttritubes.tags, refAttributes.tags) == 0));
}

} // namespace android
