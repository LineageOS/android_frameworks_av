/*
 * Copyright (C) 2021 The Android Open Source Project
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

#include <android/media/AudioMMapPolicy.h>
#include <cutils/properties.h>

#include "PropertyUtils.h"

namespace android {
namespace CPP_VERSION {
namespace utils {

std::string getMmapPolicyProperty(media::AudioMMapPolicyType policyType) {
    switch (policyType) {
        case media::AudioMMapPolicyType::DEFAULT:
            return "aaudio.mmap_policy";
        case media::AudioMMapPolicyType::EXCLUSIVE:
            return "aaudio.mmap_exclusive_policy";
        default:
            return "";
    }
}

#define MMAP_POLICY_UNSPECIFIED 0
#define MMAP_POLICY_NEVER 1
#define MMAP_POLICY_AUTO 2
#define MMAP_POLICY_ALWAYS 3

int getDefaultPolicyFromType(media::AudioMMapPolicyType policyType) {
    switch (policyType) {
        case media::AudioMMapPolicyType::EXCLUSIVE:
            return MMAP_POLICY_UNSPECIFIED;
        case media::AudioMMapPolicyType::DEFAULT:
        default:
            return MMAP_POLICY_NEVER;
    }
}

media::AudioMMapPolicy legacy2aidlAudioMMapPolicy(int legacy) {
    switch (legacy) {
        case MMAP_POLICY_NEVER:
            return media::AudioMMapPolicy::NEVER;
        case MMAP_POLICY_AUTO:
            return media::AudioMMapPolicy::AUTO;
        case MMAP_POLICY_ALWAYS:
            return media::AudioMMapPolicy::ALWAYS;
        case MMAP_POLICY_UNSPECIFIED:
        default:
            return media::AudioMMapPolicy::UNSPECIFIED;
    }
}

status_t getMmapPolicyInfosFromSystemProperty(
        media::AudioMMapPolicyType policyType,
        std::vector<media::AudioMMapPolicyInfo> *policyInfos) {
    media::AudioMMapPolicyInfo policyInfo;
    const std::string propertyStr = getMmapPolicyProperty(policyType);
    if (propertyStr.empty()) {
        return BAD_VALUE;
    }
    policyInfo.mmapPolicy = utils::legacy2aidlAudioMMapPolicy(
            property_get_int32(propertyStr.c_str(), utils::getDefaultPolicyFromType(policyType)));
    policyInfos->push_back(policyInfo);
    return NO_ERROR;
}

} // namespace utils
} // namespace CPP_VERSION
} // namespace android