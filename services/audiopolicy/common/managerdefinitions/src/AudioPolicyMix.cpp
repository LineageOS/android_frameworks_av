/*
 * Copyright (C) 2015 The Android Open Source Project
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

#define LOG_TAG "APM_AudioPolicyMix"
// #define LOG_NDEBUG 0

#include <algorithm>
#include <iterator>
#include <optional>
#include <regex>
#include "AudioPolicyMix.h"
#include "TypeConverter.h"
#include "HwModule.h"
#include "PolicyAudioPort.h"
#include "IOProfile.h"
#include <AudioOutputDescriptor.h>

namespace android {
namespace {

bool matchAddressToTags(const audio_attributes_t& attr, const String8& addr) {
    std::optional<std::string> tagAddress = extractAddressFromAudioAttributes(attr);
    return tagAddress.has_value() && tagAddress->compare(addr.c_str()) == 0;
}

// Returns true if the criterion matches.
// The exclude criteria are handled in the same way as positive
// ones - only condition is matched (the function will return
// same result both for RULE_MATCH_X and RULE_EXCLUDE_X).
bool isCriterionMatched(const AudioMixMatchCriterion& criterion,
                        const audio_attributes_t& attr,
                        const uid_t uid,
                        const audio_session_t session) {
    uint32_t ruleWithoutExclusion = criterion.mRule & ~RULE_EXCLUSION_MASK;
    switch(ruleWithoutExclusion) {
        case RULE_MATCH_ATTRIBUTE_USAGE:
            return criterion.mValue.mUsage == attr.usage;
        case RULE_MATCH_ATTRIBUTE_CAPTURE_PRESET:
            return criterion.mValue.mSource == attr.source;
        case RULE_MATCH_UID:
            return criterion.mValue.mUid == uid;
        case RULE_MATCH_USERID:
            {
                userid_t userId = multiuser_get_user_id(uid);
                return criterion.mValue.mUserId == userId;
            }
        case RULE_MATCH_AUDIO_SESSION_ID:
            return criterion.mValue.mAudioSessionId == session;
    }
    ALOGE("Encountered invalid mix rule 0x%x", criterion.mRule);
    return false;
}

// Returns true if vector of criteria is matched:
// - If any of the exclude criteria is matched the criteria doesn't match.
// - Otherwise, for each 'dimension' of positive rule present
//   (usage, capture preset, uid, userid...) at least one rule must match
//   for the criteria to match.
bool areMixCriteriaMatched(const std::vector<AudioMixMatchCriterion>& criteria,
                           const audio_attributes_t& attr,
                           const uid_t uid,
                           const audio_session_t session) {
    // If any of the exclusion criteria are matched the mix doesn't match.
    auto isMatchingExcludeCriterion = [&](const AudioMixMatchCriterion& c) {
        return c.isExcludeCriterion() && isCriterionMatched(c, attr, uid, session);
    };
    if (std::any_of(criteria.begin(), criteria.end(), isMatchingExcludeCriterion)) {
        return false;
    }

    uint32_t presentPositiveRules = 0; // Bitmask of all present positive criteria.
    uint32_t matchedPositiveRules = 0; // Bitmask of all matched positive criteria.
    for (const auto& criterion : criteria) {
        if (criterion.isExcludeCriterion()) {
            continue;
        }
        presentPositiveRules |= criterion.mRule;
        if (isCriterionMatched(criterion, attr, uid, session)) {
            matchedPositiveRules |= criterion.mRule;
        }
    }
    return presentPositiveRules == matchedPositiveRules;
}

// Consistency checks: for each "dimension" of rules (usage, uid...), we can
// only have MATCH rules, or EXCLUDE rules in each dimension, not a combination.
bool areMixCriteriaConsistent(const std::vector<AudioMixMatchCriterion>& criteria) {
    std::set<uint32_t> positiveCriteria;
    for (const AudioMixMatchCriterion& c : criteria) {
        if (c.isExcludeCriterion()) {
            continue;
        }
        positiveCriteria.insert(c.mRule);
    }

    auto isConflictingCriterion = [&positiveCriteria](const AudioMixMatchCriterion& c) {
        uint32_t ruleWithoutExclusion = c.mRule & ~RULE_EXCLUSION_MASK;
        return c.isExcludeCriterion() &&
               (positiveCriteria.find(ruleWithoutExclusion) != positiveCriteria.end());
    };
    return std::none_of(criteria.begin(), criteria.end(), isConflictingCriterion);
}

template <typename Predicate>
void EraseCriteriaIf(std::vector<AudioMixMatchCriterion>& v,
                     const Predicate& predicate) {
    v.erase(std::remove_if(v.begin(), v.end(), predicate), v.end());
}

} // namespace

void AudioPolicyMix::dump(String8 *dst, int spaces, int index) const
{
    dst->appendFormat("%*sAudio Policy Mix %d (%p):\n", spaces, "", index + 1, this);
    std::string mixTypeLiteral;
    if (!MixTypeConverter::toString(mMixType, mixTypeLiteral)) {
        ALOGE("%s: failed to convert mix type %d", __FUNCTION__, mMixType);
        return;
    }
    dst->appendFormat("%*s- mix type: %s\n", spaces, "", mixTypeLiteral.c_str());

    std::string routeFlagLiteral;
    RouteFlagTypeConverter::maskToString(mRouteFlags, routeFlagLiteral);
    dst->appendFormat("%*s- Route Flags: %s\n", spaces, "", routeFlagLiteral.c_str());

    dst->appendFormat("%*s- device type: %s\n", spaces, "", toString(mDeviceType).c_str());

    dst->appendFormat("%*s- device address: %s\n", spaces, "", mDeviceAddress.string());

    dst->appendFormat("%*s- output: %d\n", spaces, "",
            mOutput == nullptr ? 0 : mOutput->mIoHandle);

    int indexCriterion = 0;
    for (const auto &criterion : mCriteria) {
        dst->appendFormat("%*s- Criterion %d: ", spaces + 2, "", indexCriterion++);

        std::string ruleType, ruleValue;
        bool unknownRule = !RuleTypeConverter::toString(criterion.mRule, ruleType);
        switch (criterion.mRule & ~RULE_EXCLUSION_MASK) { // no need to match RULE_EXCLUDE_...
        case RULE_MATCH_ATTRIBUTE_USAGE:
            UsageTypeConverter::toString(criterion.mValue.mUsage, ruleValue);
            break;
        case RULE_MATCH_ATTRIBUTE_CAPTURE_PRESET:
            SourceTypeConverter::toString(criterion.mValue.mSource, ruleValue);
            break;
        case RULE_MATCH_UID:
            ruleValue = std::to_string(criterion.mValue.mUid);
            break;
        case RULE_MATCH_USERID:
            ruleValue = std::to_string(criterion.mValue.mUserId);
            break;
        case RULE_MATCH_AUDIO_SESSION_ID:
            ruleValue = std::to_string(criterion.mValue.mAudioSessionId);
            break;
        default:
            unknownRule = true;
        }

        if (!unknownRule) {
            dst->appendFormat("%s %s\n", ruleType.c_str(), ruleValue.c_str());
        } else {
            dst->appendFormat("Unknown rule type value 0x%x\n", criterion.mRule);
        }
    }
}

status_t AudioPolicyMixCollection::registerMix(const AudioMix& mix,
                                               const sp<SwAudioOutputDescriptor>& desc)
{
    for (size_t i = 0; i < size(); i++) {
        const sp<AudioPolicyMix>& registeredMix = itemAt(i);
        if (mix.mDeviceType == registeredMix->mDeviceType
                && mix.mDeviceAddress.compare(registeredMix->mDeviceAddress) == 0
                && is_mix_loopback(mix.mRouteFlags)) {
            ALOGE("registerMix(): mix already registered for dev=0x%x addr=%s",
                    mix.mDeviceType, mix.mDeviceAddress.string());
            return BAD_VALUE;
        }
    }
    if (!areMixCriteriaConsistent(mix.mCriteria)) {
        ALOGE("registerMix(): Mix contains inconsistent criteria "
              "(MATCH & EXCLUDE criteria of the same type)");
        return BAD_VALUE;
    }
    sp<AudioPolicyMix> policyMix = sp<AudioPolicyMix>::make(mix);
    add(policyMix);
    ALOGD("registerMix(): adding mix for dev=0x%x addr=%s",
            policyMix->mDeviceType, policyMix->mDeviceAddress.string());

    if (desc != nullptr) {
        desc->mPolicyMix = policyMix;
        policyMix->setOutput(desc);
    }
    return NO_ERROR;
}

status_t AudioPolicyMixCollection::unregisterMix(const AudioMix& mix)
{
    for (size_t i = 0; i < size(); i++) {
        const sp<AudioPolicyMix>& registeredMix = itemAt(i);
        if (mix.mDeviceType == registeredMix->mDeviceType
                && mix.mDeviceAddress.compare(registeredMix->mDeviceAddress) == 0) {
            ALOGD("unregisterMix(): removing mix for dev=0x%x addr=%s",
                    mix.mDeviceType, mix.mDeviceAddress.string());
            removeAt(i);
            return NO_ERROR;
        }
    }

    ALOGE("unregisterMix(): mix not registered for dev=0x%x addr=%s",
            mix.mDeviceType, mix.mDeviceAddress.string());
    return BAD_VALUE;
}

status_t AudioPolicyMixCollection::getAudioPolicyMix(audio_devices_t deviceType,
        const String8& address, sp<AudioPolicyMix> &policyMix) const
{

    ALOGV("getAudioPolicyMix() for dev=0x%x addr=%s", deviceType, address.string());
    for (ssize_t i = 0; i < size(); i++) {
        // Workaround: when an in audio policy is registered, it opens an output
        // that tries to find the audio policy, thus the device must be ignored.
        if (itemAt(i)->mDeviceAddress.compare(address) == 0) {
            policyMix = itemAt(i);
            ALOGV("getAudioPolicyMix: found mix %zu match (devType=0x%x addr=%s)",
                    i, deviceType, address.string());
            return NO_ERROR;
        }
    }

    ALOGE("getAudioPolicyMix(): mix not registered for dev=0x%x addr=%s",
            deviceType, address.string());
    return BAD_VALUE;
}

void AudioPolicyMixCollection::closeOutput(sp<SwAudioOutputDescriptor> &desc)
{
    for (size_t i = 0; i < size(); i++) {
        sp<AudioPolicyMix> policyMix = itemAt(i);
        if (policyMix->getOutput() == desc) {
            policyMix->clearOutput();
        }
    }
}

status_t AudioPolicyMixCollection::getOutputForAttr(
        const audio_attributes_t& attributes, const audio_config_base_t& config, const uid_t uid,
        const audio_session_t session,
        audio_output_flags_t flags,
        const DeviceVector &availableOutputDevices,
        const sp<DeviceDescriptor>& requestedDevice,
        sp<AudioPolicyMix> &primaryMix,
        std::vector<sp<AudioPolicyMix>> *secondaryMixes,
        bool& usePrimaryOutputFromPolicyMixes)
{
    ALOGV("getOutputForAttr() querying %zu mixes:", size());
    primaryMix.clear();
    bool mixesDisallowsRequestedDevice = false;
    for (size_t i = 0; i < size(); i++) {
        sp<AudioPolicyMix> policyMix = itemAt(i);
        const bool primaryOutputMix = !is_mix_loopback_render(policyMix->mRouteFlags);
        sp<DeviceDescriptor> mixDevice = getOutputDeviceForMix(policyMix.get(),
            availableOutputDevices);
        if (mixDisallowsRequestedDevice(policyMix.get(), requestedDevice, mixDevice, uid)) {
            ALOGV("%s: Mix %zu: does not allows device", __func__, i);
            mixesDisallowsRequestedDevice = true;
        }

        if (primaryOutputMix && primaryMix != nullptr) {
            ALOGV("%s: Skiping %zu: Primary output already found", __func__, i);
            continue; // Primary output already found
        }

        if(!mixMatch(policyMix.get(), i, attributes, config, uid, session)) {
            ALOGV("%s: Mix %zu: does not match", __func__, i);
            continue; // skip the mix
        }

        if ((flags & AUDIO_OUTPUT_FLAG_MMAP_NOIRQ) && is_mix_loopback(policyMix->mRouteFlags)) {
            // AAudio MMAP_NOIRQ streams cannot be routed to loopback/loopback+render
            // using dynamic audio policy.
            ALOGD("%s: Rejecting MMAP_NOIRQ request matched to loopback dynamic audio policy mix.",
                __func__);
            return INVALID_OPERATION;
        }

        if (mixDevice != nullptr && mixDevice->equals(requestedDevice)) {
            ALOGV("%s: Mix %zu: requested device mathches", __func__, i);
            mixesDisallowsRequestedDevice = false;
        }

        if (primaryOutputMix) {
            primaryMix = policyMix;
            ALOGV("%s: Mix %zu: set primary desc", __func__, i);
        } else {
            ALOGV("%s: Add a secondary desc %zu", __func__, i);
            if (secondaryMixes != nullptr) {
                secondaryMixes->push_back(policyMix);
            }
        }
    }

    // Explicit routing is higher priority than dynamic policy primary output, but policy may
    // explicitly deny it
    usePrimaryOutputFromPolicyMixes =
        (mixesDisallowsRequestedDevice || requestedDevice == nullptr) && primaryMix != nullptr;

    return NO_ERROR;
}

sp<DeviceDescriptor> AudioPolicyMixCollection::getOutputDeviceForMix(const AudioMix* mix,
                                                    const DeviceVector& availableOutputDevices) {
    ALOGV("%s: device (0x%x, addr=%s) forced by mix", __func__, mix->mDeviceType,
        mix->mDeviceAddress.c_str());
    return availableOutputDevices.getDevice(mix->mDeviceType, mix->mDeviceAddress,
        AUDIO_FORMAT_DEFAULT);
}

bool AudioPolicyMixCollection::mixDisallowsRequestedDevice(const AudioMix* mix,
                                                     const sp<DeviceDescriptor>& requestedDevice,
                                                     const sp<DeviceDescriptor>& mixDevice,
                                                     const uid_t uid) {
    if (requestedDevice == nullptr || mixDevice == nullptr) {
        return false;
    }

    return is_mix_disallows_preferred_device(mix->mRouteFlags)
        && requestedDevice->equals(mixDevice)
        && mix->hasUserIdRule(false /* match */, multiuser_get_user_id(uid));
}

bool AudioPolicyMixCollection::mixMatch(const AudioMix* mix, size_t mixIndex,
    const audio_attributes_t& attributes, const audio_config_base_t& config,
    uid_t uid, audio_session_t session) {

    if (mix->mMixType == MIX_TYPE_PLAYERS) {
        // Loopback render mixes are created from a public API and thus restricted
        // to non sensible audio that have not opted out.
        if (is_mix_loopback_render(mix->mRouteFlags)) {
            if (!(attributes.usage == AUDIO_USAGE_UNKNOWN ||
                  attributes.usage == AUDIO_USAGE_MEDIA ||
                  attributes.usage == AUDIO_USAGE_GAME ||
                  attributes.usage == AUDIO_USAGE_VOICE_COMMUNICATION)) {
                return false;
            }
            auto hasFlag = [](auto flags, auto flag) { return (flags & flag) == flag; };
            if (hasFlag(attributes.flags, AUDIO_FLAG_NO_SYSTEM_CAPTURE)) {
                return false;
            }

            if (attributes.usage == AUDIO_USAGE_VOICE_COMMUNICATION) {
                if (!mix->mVoiceCommunicationCaptureAllowed) {
                    return false;
                }
            } else if (!mix->mAllowPrivilegedMediaPlaybackCapture &&
                hasFlag(attributes.flags, AUDIO_FLAG_NO_MEDIA_PROJECTION)) {
                return false;
            }
        }

        // Permit match only if requested format and mix format are PCM and can be format
        // adapted by the mixer, or are the same (compressed) format.
        if (!is_mix_loopback(mix->mRouteFlags) &&
            !((audio_is_linear_pcm(config.format) && audio_is_linear_pcm(mix->mFormat.format)) ||
              (config.format == mix->mFormat.format)) &&
              config.format != AUDIO_CONFIG_BASE_INITIALIZER.format) {
            return false;
        }

        // if there is an address match, prioritize that match
        if (matchAddressToTags(attributes, mix->mDeviceAddress)
            || areMixCriteriaMatched(mix->mCriteria, attributes, uid, session)) {
                ALOGV("\tgetOutputForAttr will use mix %zu", mixIndex);
                return true;
        }
    } else if (mix->mMixType == MIX_TYPE_RECORDERS) {
        if (attributes.usage == AUDIO_USAGE_VIRTUAL_SOURCE &&
            matchAddressToTags(attributes, mix->mDeviceAddress)) {
            return true;
        }
    }
    return false;
}

sp<DeviceDescriptor> AudioPolicyMixCollection::getDeviceAndMixForOutput(
        const sp<SwAudioOutputDescriptor> &output,
        const DeviceVector &availableOutputDevices)
{
    for (size_t i = 0; i < size(); i++) {
        if (itemAt(i)->getOutput() == output) {
            // This Desc is involved in a Mix, which has the highest prio
            return getOutputDeviceForMix(itemAt(i).get(), availableOutputDevices);
        }
    }
    return nullptr;
}

sp<DeviceDescriptor> AudioPolicyMixCollection::getDeviceAndMixForInputSource(
        const audio_attributes_t& attributes,
        const DeviceVector &availDevices,
        uid_t uid,
        audio_session_t session,
        sp<AudioPolicyMix> *policyMix) const
{
    for (size_t i = 0; i < size(); i++) {
        AudioPolicyMix *mix = itemAt(i).get();
        if (mix->mMixType != MIX_TYPE_RECORDERS) {
            continue;
        }
        if (areMixCriteriaMatched(mix->mCriteria, attributes, uid, session)) {
            // Assuming PolicyMix only for remote submix for input
            // so mix->mDeviceType can only be AUDIO_DEVICE_OUT_REMOTE_SUBMIX.
            auto mixDevice = availDevices.getDevice(AUDIO_DEVICE_IN_REMOTE_SUBMIX,
             mix->mDeviceAddress, AUDIO_FORMAT_DEFAULT);
                if (mixDevice != nullptr) {
                    if (policyMix != nullptr) {
                        *policyMix = mix;
                    }
                    return mixDevice;
                }
        }
    }
    return nullptr;
}

status_t AudioPolicyMixCollection::getInputMixForAttr(
        audio_attributes_t attr, sp<AudioPolicyMix> *policyMix)
{
    std::optional<std::string> address = extractAddressFromAudioAttributes(attr);
    if (!address.has_value()) {
        return BAD_VALUE;
    }

#ifdef LOG_NDEBUG
    ALOGV("getInputMixForAttr looking for address %s for source %d\n  mixes available:",
            address->c_str(), attr.source);
    for (size_t i = 0; i < size(); i++) {
        const sp<AudioPolicyMix> audioPolicyMix = itemAt(i);
        ALOGV("\tmix %zu address=%s", i, audioPolicyMix->mDeviceAddress.string());
    }
#endif

    size_t index;
    for (index = 0; index < size(); index++) {
        const sp<AudioPolicyMix>& registeredMix = itemAt(index);
        if (address->compare(registeredMix->mDeviceAddress.c_str()) == 0) {
            ALOGD("getInputMixForAttr found addr=%s dev=0x%x",
                    registeredMix->mDeviceAddress.string(), registeredMix->mDeviceType);
            break;
        }
    }
    if (index == size()) {
        ALOGW("getInputMixForAttr() no policy for address %s", address->c_str());
        return BAD_VALUE;
    }
    const sp<AudioPolicyMix> audioPolicyMix = itemAt(index);

    if (audioPolicyMix->mMixType != MIX_TYPE_PLAYERS) {
        ALOGW("getInputMixForAttr() bad policy mix type for address %s", address->c_str());
        return BAD_VALUE;
    }
    if (policyMix != nullptr) {
        *policyMix = audioPolicyMix;
    }
    return NO_ERROR;
}

status_t AudioPolicyMixCollection::setUidDeviceAffinities(uid_t uid,
        const AudioDeviceTypeAddrVector& devices) {
    // verify feasibility: for each player mix: if it already contains a
    //    "match uid" rule for this uid, return an error
    //    (adding a uid-device affinity would result in contradictory rules)
    for (size_t i = 0; i < size(); i++) {
        const AudioPolicyMix* mix = itemAt(i).get();
        if (!mix->isDeviceAffinityCompatible()) {
            continue;
        }
        if (mix->hasUidRule(true /*match*/, uid)) {
            return INVALID_OPERATION;
        }
    }

    // remove existing rules for this uid
    removeUidDeviceAffinities(uid);

    // for each player mix:
    //   IF    device is not a target for the mix,
    //     AND it doesn't have a "match uid" rule
    //   THEN add a rule to exclude the uid
    for (size_t i = 0; i < size(); i++) {
        AudioPolicyMix *mix = itemAt(i).get();
        if (!mix->isDeviceAffinityCompatible()) {
            continue;
        }
        // check if this mix goes to a device in the list of devices
        bool deviceMatch = false;
        const AudioDeviceTypeAddr mixDevice(mix->mDeviceType, mix->mDeviceAddress.string());
        for (size_t j = 0; j < devices.size(); j++) {
            if (mixDevice.equals(devices[j])) {
                deviceMatch = true;
                break;
            }
        }
        if (!deviceMatch && !mix->hasMatchUidRule()) {
            // this mix doesn't go to one of the listed devices for the given uid,
            // and it's not already restricting the mix on a uid,
            // modify its rules to exclude the uid
            if (!mix->hasUidRule(false /*match*/, uid)) {
                // no need to do it again if uid is already excluded
                mix->setExcludeUid(uid);
            }
        }
    }

    return NO_ERROR;
}

status_t AudioPolicyMixCollection::removeUidDeviceAffinities(uid_t uid) {
    // for each player mix: remove existing rules that match or exclude this uid
    for (size_t i = 0; i < size(); i++) {
        AudioPolicyMix *mix = itemAt(i).get();
        if (!mix->isDeviceAffinityCompatible()) {
            continue;
        }

        // is this rule excluding the uid? (not considering uid match rules
        // as those are not used for uid-device affinity)
        EraseCriteriaIf(mix->mCriteria, [uid](const AudioMixMatchCriterion& c) {
            return c.mRule == RULE_EXCLUDE_UID && c.mValue.mUid == uid;
        });
    }
    return NO_ERROR;
}

status_t AudioPolicyMixCollection::getDevicesForUid(uid_t uid,
        Vector<AudioDeviceTypeAddr>& devices) const {
    // for each player mix: find rules that don't exclude this uid, and add the device to the list
    for (size_t i = 0; i < size(); i++) {
        bool ruleAllowsUid = true;
        const AudioPolicyMix *mix = itemAt(i).get();
        if (mix->mMixType != MIX_TYPE_PLAYERS) {
            continue;
        }
        for (size_t j = 0; j < mix->mCriteria.size(); j++) {
            const uint32_t rule = mix->mCriteria[j].mRule;
            if (rule == RULE_EXCLUDE_UID
                    && uid == mix->mCriteria[j].mValue.mUid) {
                ruleAllowsUid = false;
                break;
            }
        }
        if (ruleAllowsUid) {
            devices.add(AudioDeviceTypeAddr(mix->mDeviceType, mix->mDeviceAddress.string()));
        }
    }
    return NO_ERROR;
}

status_t AudioPolicyMixCollection::setUserIdDeviceAffinities(int userId,
        const AudioDeviceTypeAddrVector& devices) {
    // verify feasibility: for each player mix: if it already contains a
    //    "match userId" rule for this userId, return an error
    //    (adding a userId-device affinity would result in contradictory rules)
    for (size_t i = 0; i < size(); i++) {
        AudioPolicyMix* mix = itemAt(i).get();
        if (!mix->isDeviceAffinityCompatible()) {
            continue;
        }
        if (mix->hasUserIdRule(true /*match*/, userId)) {
            return INVALID_OPERATION;
        }
    }

    // remove existing rules for this userId
    removeUserIdDeviceAffinities(userId);

    // for each player mix:
    //   IF    device is not a target for the mix,
    //     AND it doesn't have a "match userId" rule
    //   THEN add a rule to exclude the userId
    for (size_t i = 0; i < size(); i++) {
        AudioPolicyMix *mix = itemAt(i).get();
        if (!mix->isDeviceAffinityCompatible()) {
            continue;
        }
        // check if this mix goes to a device in the list of devices
        bool deviceMatch = false;
        const AudioDeviceTypeAddr mixDevice(mix->mDeviceType, mix->mDeviceAddress.string());
        for (size_t j = 0; j < devices.size(); j++) {
            if (mixDevice.equals(devices[j])) {
                deviceMatch = true;
                break;
            }
        }
        if (!deviceMatch && !mix->hasUserIdRule(true /*match*/)) {
            // this mix doesn't go to one of the listed devices for the given userId,
            // and it's not already restricting the mix on a userId,
            // modify its rules to exclude the userId
            if (!mix->hasUserIdRule(false /* match */, userId)) {
                // no need to do it again if userId is already excluded
                mix->setExcludeUserId(userId);
                mix->mRouteFlags = mix->mRouteFlags | MIX_ROUTE_FLAG_DISALLOWS_PREFERRED_DEVICE;
            }
        }
    }

    return NO_ERROR;
}

status_t AudioPolicyMixCollection::removeUserIdDeviceAffinities(int userId) {
    // for each player mix: remove existing rules that match or exclude this userId
    for (size_t i = 0; i < size(); i++) {
        AudioPolicyMix *mix = itemAt(i).get();
        if (!mix->isDeviceAffinityCompatible()) {
            continue;
        }

        // is this rule excluding the userId? (not considering userId match rules
        // as those are not used for userId-device affinity)
        EraseCriteriaIf(mix->mCriteria, [userId](const AudioMixMatchCriterion& c) {
            return c.mRule == RULE_EXCLUDE_USERID && c.mValue.mUserId == userId;
        });

        if (!mix->hasUserIdRule(false /* match */)) {
            mix->mRouteFlags = mix->mRouteFlags & ~MIX_ROUTE_FLAG_DISALLOWS_PREFERRED_DEVICE;
        }
    }
    return NO_ERROR;
}

status_t AudioPolicyMixCollection::getDevicesForUserId(int userId,
        AudioDeviceTypeAddrVector& devices) const {
    // for each player mix:
    // find rules that don't exclude this userId, and add the device to the list
    for (size_t i = 0; i < size(); i++) {
        bool ruleAllowsUserId = true;
        const AudioPolicyMix *mix = itemAt(i).get();
        if (mix->mMixType != MIX_TYPE_PLAYERS) {
            continue;
        }
        for (size_t j = 0; j < mix->mCriteria.size(); j++) {
            const uint32_t rule = mix->mCriteria[j].mRule;
            if (rule == RULE_EXCLUDE_USERID
                    && userId == mix->mCriteria[j].mValue.mUserId) {
                ruleAllowsUserId = false;
                break;
            }
        }
        if (ruleAllowsUserId) {
            devices.push_back(AudioDeviceTypeAddr(mix->mDeviceType, mix->mDeviceAddress.string()));
        }
    }
    return NO_ERROR;
}

void AudioPolicyMixCollection::dump(String8 *dst) const
{
    dst->append("\n Audio Policy Mix:\n");
    for (size_t i = 0; i < size(); i++) {
        itemAt(i)->dump(dst, 2, i);
    }
}

std::optional<std::string> extractAddressFromAudioAttributes(const audio_attributes_t& attr) {
    static const std::regex addrTagRegex("addr=([^;]+)");

    std::cmatch match;
    if (std::regex_search(attr.tags, match, addrTagRegex)) {
        return match[1].str();
    }
    return std::nullopt;
}

}; //namespace android
