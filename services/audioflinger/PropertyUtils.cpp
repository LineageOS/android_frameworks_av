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

#include <aaudio/AAudio.h>
#include <aaudio/AAudioTesting.h>
#include <android/media/audio/common/AudioMMapPolicy.h>
#include <cutils/properties.h>

#include "PropertyUtils.h"

namespace android {

using media::audio::common::AudioMMapPolicy;
using media::audio::common::AudioMMapPolicyType;
using media::audio::common::AudioMMapPolicyInfo;

std::string getMmapPolicyProperty(AudioMMapPolicyType policyType) {
    switch (policyType) {
        case AudioMMapPolicyType::DEFAULT:
            return "aaudio.mmap_policy";
        case AudioMMapPolicyType::EXCLUSIVE:
            return "aaudio.mmap_exclusive_policy";
        default:
            return "";
    }
}

int getDefaultPolicyFromType(AudioMMapPolicyType policyType) {
    switch (policyType) {
        case AudioMMapPolicyType::EXCLUSIVE:
            return AAUDIO_UNSPECIFIED;
        case AudioMMapPolicyType::DEFAULT:
        default:
            return AAUDIO_POLICY_NEVER;
    }
}

AudioMMapPolicy legacy2aidl_aaudio_policy_t_AudioMMapPolicy(aaudio_policy_t legacy) {
    switch (legacy) {
        case AAUDIO_POLICY_NEVER:
            return AudioMMapPolicy::NEVER;
        case AAUDIO_POLICY_AUTO:
            return AudioMMapPolicy::AUTO;
        case AAUDIO_POLICY_ALWAYS:
            return AudioMMapPolicy::ALWAYS;
        case AAUDIO_UNSPECIFIED:
            return AudioMMapPolicy::UNSPECIFIED;
        default:
            ALOGE("%s unknown aaudio policy: %d", __func__, legacy);
            return AudioMMapPolicy::UNSPECIFIED;
    }
}

status_t getMmapPolicyInfosFromSystemProperty(
        AudioMMapPolicyType policyType, std::vector<AudioMMapPolicyInfo> *policyInfos) {
    AudioMMapPolicyInfo policyInfo;
    const std::string propertyStr = getMmapPolicyProperty(policyType);
    if (propertyStr.empty()) {
        return BAD_VALUE;
    }
    policyInfo.mmapPolicy = legacy2aidl_aaudio_policy_t_AudioMMapPolicy(
            property_get_int32(propertyStr.c_str(), getDefaultPolicyFromType(policyType)));
    policyInfos->push_back(policyInfo);
    return NO_ERROR;
}

int32_t getAAudioMixerBurstCountFromSystemProperty() {
    static const int32_t sDefaultBursts = 2; // arbitrary, use 2 for double buffered
    static const int32_t sMaxBursts = 1024; // arbitrary
    static const char* sPropMixerBursts = "aaudio.mixer_bursts";
    int32_t prop = property_get_int32(sPropMixerBursts, sDefaultBursts);
    if (prop <= 0 || prop > sMaxBursts) {
        ALOGE("%s: invalid value %d, use default %d", __func__, prop, sDefaultBursts);
        prop = sDefaultBursts;
    }
    return prop;
}

int32_t getAAudioHardwareBurstMinUsecFromSystemProperty() {
    static const int32_t sDefaultMicros = 1000; // arbitrary
    static const int32_t sMaxMicros = 1000 * 1000; // arbitrary
    static const char* sPropHwBurstMinUsec = "aaudio.hw_burst_min_usec";
    int32_t prop = property_get_int32(sPropHwBurstMinUsec, sDefaultMicros);
    if (prop <= 0 || prop > sMaxMicros) {
        ALOGE("%s invalid value %d, use default %d", __func__, prop, sDefaultMicros);
        prop = sDefaultMicros;
    }
    return prop;
}

} // namespace android
