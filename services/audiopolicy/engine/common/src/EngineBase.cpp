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

#define LOG_TAG "APM::AudioPolicyEngine/Base"
//#define LOG_NDEBUG 0

#include <functional>
#include <string>
#include <sys/stat.h>

#include "EngineBase.h"
#include "EngineDefaultConfig.h"
#include <TypeConverter.h>

namespace android {
namespace audio_policy {

void EngineBase::setObserver(AudioPolicyManagerObserver *observer)
{
    ALOG_ASSERT(observer != NULL, "Invalid Audio Policy Manager observer");
    mApmObserver = observer;
}

status_t EngineBase::initCheck()
{
    return (mApmObserver != nullptr)? NO_ERROR : NO_INIT;
}

status_t EngineBase::setPhoneState(audio_mode_t state)
{
    ALOGV("setPhoneState() state %d", state);

    if (state < 0 || uint32_t(state) >= AUDIO_MODE_CNT) {
        ALOGW("setPhoneState() invalid state %d", state);
        return BAD_VALUE;
    }

    if (state == mPhoneState ) {
        ALOGW("setPhoneState() setting same state %d", state);
        return BAD_VALUE;
    }

    // store previous phone state for management of sonification strategy below
    int oldState = mPhoneState;
    mPhoneState = state;

    if (!is_state_in_call(oldState) && is_state_in_call(state)) {
        ALOGV("  Entering call in setPhoneState()");
        switchVolumeCurve(AUDIO_STREAM_VOICE_CALL, AUDIO_STREAM_DTMF);
    } else if (is_state_in_call(oldState) && !is_state_in_call(state)) {
        ALOGV("  Exiting call in setPhoneState()");
        restoreOriginVolumeCurve(AUDIO_STREAM_DTMF);
    }
    return NO_ERROR;
}

status_t EngineBase::setDeviceConnectionState(const sp<DeviceDescriptor> devDesc,
                                              audio_policy_dev_state_t state)
{
    audio_devices_t deviceType = devDesc->type();
    if ((deviceType != AUDIO_DEVICE_NONE) && audio_is_output_device(deviceType)
            && deviceType != AUDIO_DEVICE_OUT_DGTL_DOCK_HEADSET
            && deviceType != AUDIO_DEVICE_OUT_BLE_BROADCAST) {
        // USB dock does not follow the rule of last removable device connected wins.
        // It is only used if no removable device is connected or if set as preferred device
        // LE audio broadcast device has a specific policy depending on active strategies and
        // devices and does not follow the rule of last connected removable device.
        mLastRemovableMediaDevices.setRemovableMediaDevices(devDesc, state);
    }

    return NO_ERROR;
}

product_strategy_t EngineBase::getProductStrategyForAttributes(
        const audio_attributes_t &attr, bool fallbackOnDefault) const
{
    return mProductStrategies.getProductStrategyForAttributes(attr, fallbackOnDefault);
}

audio_stream_type_t EngineBase::getStreamTypeForAttributes(const audio_attributes_t &attr) const
{
    return mProductStrategies.getStreamTypeForAttributes(attr);
}

audio_attributes_t EngineBase::getAttributesForStreamType(audio_stream_type_t stream) const
{
    return mProductStrategies.getAttributesForStreamType(stream);
}

product_strategy_t EngineBase::getProductStrategyForStream(audio_stream_type_t stream) const
{
    return mProductStrategies.getProductStrategyForStream(stream);
}

product_strategy_t EngineBase::getProductStrategyByName(const std::string &name) const
{
    for (const auto &iter : mProductStrategies) {
        if (iter.second->getName() == name) {
            return iter.second->getId();
        }
    }
    return PRODUCT_STRATEGY_NONE;
}

engineConfig::ParsingResult EngineBase::loadAudioPolicyEngineConfig(
        const media::audio::common::AudioHalEngineConfig& aidlConfig)
{
    engineConfig::ParsingResult result = engineConfig::convert(aidlConfig);
    if (result.parsedConfig == nullptr) {
        ALOGE("%s: There was an error parsing AIDL data", __func__);
        result = {std::make_unique<engineConfig::Config>(gDefaultEngineConfig), 1};
    } else {
        // It is allowed for the HAL to return an empty list of strategies.
        if (result.parsedConfig->productStrategies.empty()) {
            result.parsedConfig->productStrategies = gDefaultEngineConfig.productStrategies;
        }
    }
    return processParsingResult(std::move(result));
}

engineConfig::ParsingResult EngineBase::loadAudioPolicyEngineConfig(const std::string& xmlFilePath)
{
    auto fileExists = [](const char* path) {
        struct stat fileStat;
        return stat(path, &fileStat) == 0 && S_ISREG(fileStat.st_mode);
    };
    const std::string filePath = xmlFilePath.empty() ? engineConfig::DEFAULT_PATH : xmlFilePath;
    engineConfig::ParsingResult result =
            fileExists(filePath.c_str()) ?
            engineConfig::parse(filePath.c_str()) : engineConfig::ParsingResult{};
    if (result.parsedConfig == nullptr) {
        ALOGD("%s: No configuration found, using default matching phone experience.", __FUNCTION__);
        engineConfig::Config config = gDefaultEngineConfig;
        android::status_t ret = engineConfig::parseLegacyVolumes(config.volumeGroups);
        result = {std::make_unique<engineConfig::Config>(config),
                  static_cast<size_t>(ret == NO_ERROR ? 0 : 1)};
    } else {
        // Append for internal use only volume groups (e.g. rerouting/patch)
        result.parsedConfig->volumeGroups.insert(
                    std::end(result.parsedConfig->volumeGroups),
                    std::begin(gSystemVolumeGroups), std::end(gSystemVolumeGroups));
    }
    ALOGE_IF(result.nbSkippedElement != 0, "skipped %zu elements", result.nbSkippedElement);
    return processParsingResult(std::move(result));
}

engineConfig::ParsingResult EngineBase::processParsingResult(
        engineConfig::ParsingResult&& rawResult)
{
    auto loadVolumeConfig = [](auto &volumeGroups, auto &volumeConfig) {
        // Ensure volume group name uniqueness.
        LOG_ALWAYS_FATAL_IF(std::any_of(std::begin(volumeGroups), std::end(volumeGroups),
                                     [&volumeConfig](const auto &volumeGroup) {
                return volumeConfig.name == volumeGroup.second->getName(); }),
                            "group name %s defined twice, review the configuration",
                            volumeConfig.name.c_str());

        sp<VolumeGroup> volumeGroup = new VolumeGroup(volumeConfig.name, volumeConfig.indexMin,
                                                      volumeConfig.indexMax);
        volumeGroups[volumeGroup->getId()] = volumeGroup;

        for (auto &configCurve : volumeConfig.volumeCurves) {
            device_category deviceCat = DEVICE_CATEGORY_SPEAKER;
            if (!DeviceCategoryConverter::fromString(configCurve.deviceCategory, deviceCat)) {
                ALOGE("%s: Invalid %s", __FUNCTION__, configCurve.deviceCategory.c_str());
                continue;
            }
            sp<VolumeCurve> curve = new VolumeCurve(deviceCat);
            for (auto &point : configCurve.curvePoints) {
                curve->add({point.index, point.attenuationInMb});
            }
            volumeGroup->add(curve);
        }
        return volumeGroup;
    };
    auto addSupportedAttributesToGroup = [](auto &group, auto &volumeGroup, auto &strategy) {
        for (const auto &attr : group.attributesVect) {
            strategy->addAttributes({volumeGroup->getId(), group.stream, attr});
            volumeGroup->addSupportedAttributes(attr);
        }
    };
    auto checkStreamForGroups = [](auto streamType, const auto &volumeGroups) {
        const auto &iter = std::find_if(std::begin(volumeGroups), std::end(volumeGroups),
                                     [&streamType](const auto &volumeGroup) {
            const auto& streams = volumeGroup.second->getStreamTypes();
            return std::find(std::begin(streams), std::end(streams), streamType) !=
                    std::end(streams);
        });
        return iter != end(volumeGroups);
    };

    auto result = std::move(rawResult);
    // Append for internal use only strategies (e.g. rerouting/patch)
    result.parsedConfig->productStrategies.insert(
                std::end(result.parsedConfig->productStrategies),
                std::begin(gOrderedSystemStrategies), std::end(gOrderedSystemStrategies));

    engineConfig::VolumeGroup defaultVolumeConfig;
    engineConfig::VolumeGroup defaultSystemVolumeConfig;
    for (auto &volumeConfig : result.parsedConfig->volumeGroups) {
        // save default volume config for streams not defined in configuration
        if (volumeConfig.name.compare(audio_stream_type_to_string(AUDIO_STREAM_MUSIC)) == 0) {
            defaultVolumeConfig = volumeConfig;
        }
        if (volumeConfig.name.compare(audio_stream_type_to_string(AUDIO_STREAM_PATCH)) == 0) {
            defaultSystemVolumeConfig = volumeConfig;
        }
        loadVolumeConfig(mVolumeGroups, volumeConfig);
    }
    for (auto& strategyConfig : result.parsedConfig->productStrategies) {
        sp<ProductStrategy> strategy = new ProductStrategy(strategyConfig.name);
        for (const auto &group : strategyConfig.attributesGroups) {
            const auto &iter = std::find_if(begin(mVolumeGroups), end(mVolumeGroups),
                                         [&group](const auto &volumeGroup) {
                    return group.volumeGroup == volumeGroup.second->getName(); });
            sp<VolumeGroup> volumeGroup = nullptr;
            // If no volume group provided for this strategy, creates a new one using
            // Music Volume Group configuration (considered as the default)
            if (iter == end(mVolumeGroups)) {
                engineConfig::VolumeGroup volumeConfig;
                if (group.stream >= AUDIO_STREAM_PUBLIC_CNT) {
                    volumeConfig = defaultSystemVolumeConfig;
                } else {
                    volumeConfig = defaultVolumeConfig;
                }
                ALOGW("%s: No configuration of %s found, using default volume configuration"
                        , __FUNCTION__, group.volumeGroup.c_str());
                volumeConfig.name = group.volumeGroup;
                volumeGroup = loadVolumeConfig(mVolumeGroups, volumeConfig);
            } else {
                volumeGroup = iter->second;
            }
            if (group.stream != AUDIO_STREAM_DEFAULT) {
                // A legacy stream can be assigned once to a volume group
                LOG_ALWAYS_FATAL_IF(checkStreamForGroups(group.stream, mVolumeGroups),
                                    "stream %s already assigned to a volume group, "
                                    "review the configuration", toString(group.stream).c_str());
                volumeGroup->addSupportedStream(group.stream);
            }
            addSupportedAttributesToGroup(group, volumeGroup, strategy);
        }
        product_strategy_t strategyId = strategy->getId();
        mProductStrategies[strategyId] = strategy;
    }
    mProductStrategies.initialize();
    return result;
}

StrategyVector EngineBase::getOrderedProductStrategies() const
{
    auto findByFlag = [](const auto &productStrategies, auto flag) {
        return std::find_if(begin(productStrategies), end(productStrategies),
                            [&](const auto &strategy) {
            for (const auto &attributes : strategy.second->getAudioAttributes()) {
                if ((attributes.flags & flag) == flag) {
                    return true;
                }
            }
            return false;
        });
    };
    auto strategies = mProductStrategies;
    auto enforcedAudibleStrategyIter = findByFlag(strategies, AUDIO_FLAG_AUDIBILITY_ENFORCED);

    if (getForceUse(AUDIO_POLICY_FORCE_FOR_SYSTEM) == AUDIO_POLICY_FORCE_SYSTEM_ENFORCED &&
            enforcedAudibleStrategyIter != strategies.end()) {
        auto enforcedAudibleStrategy = *enforcedAudibleStrategyIter;
        strategies.erase(enforcedAudibleStrategyIter);
        strategies.insert(begin(strategies), enforcedAudibleStrategy);
    }
    StrategyVector orderedStrategies;
    for (const auto &iter : strategies) {
        orderedStrategies.push_back(iter.second->getId());
    }
    return orderedStrategies;
}

StreamTypeVector EngineBase::getStreamTypesForProductStrategy(product_strategy_t ps) const
{
    // @TODO default music stream to control volume if no group?
    return (mProductStrategies.find(ps) != end(mProductStrategies)) ?
                mProductStrategies.at(ps)->getSupportedStreams() :
                StreamTypeVector(AUDIO_STREAM_MUSIC);
}

AttributesVector EngineBase::getAllAttributesForProductStrategy(product_strategy_t ps) const
{
    return (mProductStrategies.find(ps) != end(mProductStrategies)) ?
                mProductStrategies.at(ps)->getAudioAttributes() : AttributesVector();
}

status_t EngineBase::listAudioProductStrategies(AudioProductStrategyVector &strategies) const
{
    for (const auto &iter : mProductStrategies) {
        const auto &productStrategy = iter.second;
        strategies.push_back(
        {productStrategy->getName(), productStrategy->listVolumeGroupAttributes(),
         productStrategy->getId()});
    }
    return NO_ERROR;
}

VolumeCurves *EngineBase::getVolumeCurvesForAttributes(const audio_attributes_t &attr) const
{
    volume_group_t volGr = mProductStrategies.getVolumeGroupForAttributes(attr);
    const auto &iter = mVolumeGroups.find(volGr);
    LOG_ALWAYS_FATAL_IF(iter == std::end(mVolumeGroups), "No volume groups for %s", toString(attr).c_str());
    return mVolumeGroups.at(volGr)->getVolumeCurves();
}

VolumeCurves *EngineBase::getVolumeCurvesForStreamType(audio_stream_type_t stream) const
{
    volume_group_t volGr = mProductStrategies.getVolumeGroupForStreamType(stream);
    if (volGr == VOLUME_GROUP_NONE) {
        volGr = mProductStrategies.getDefaultVolumeGroup();
    }
    const auto &iter = mVolumeGroups.find(volGr);
    LOG_ALWAYS_FATAL_IF(iter == std::end(mVolumeGroups), "No volume groups for %s",
                toString(stream).c_str());
    return mVolumeGroups.at(volGr)->getVolumeCurves();
}

status_t EngineBase::switchVolumeCurve(audio_stream_type_t streamSrc, audio_stream_type_t streamDst)
{
    auto srcCurves = getVolumeCurvesForStreamType(streamSrc);
    auto dstCurves = getVolumeCurvesForStreamType(streamDst);

    if (srcCurves == nullptr || dstCurves == nullptr) {
        return BAD_VALUE;
    }
    return dstCurves->switchCurvesFrom(*srcCurves);
}

status_t EngineBase::restoreOriginVolumeCurve(audio_stream_type_t stream)
{
    VolumeCurves *curves = getVolumeCurvesForStreamType(stream);
    return curves != nullptr ? curves->switchCurvesFrom(*curves) : BAD_VALUE;
}

VolumeGroupVector EngineBase::getVolumeGroups() const
{
    VolumeGroupVector group;
    for (const auto &iter : mVolumeGroups) {
        group.push_back(iter.first);
    }
    return group;
}

volume_group_t EngineBase::getVolumeGroupForAttributes(
        const audio_attributes_t &attr, bool fallbackOnDefault) const
{
    return mProductStrategies.getVolumeGroupForAttributes(attr, fallbackOnDefault);
}

volume_group_t EngineBase::getVolumeGroupForStreamType(
        audio_stream_type_t stream, bool fallbackOnDefault) const
{
    return mProductStrategies.getVolumeGroupForStreamType(stream, fallbackOnDefault);
}

status_t EngineBase::listAudioVolumeGroups(AudioVolumeGroupVector &groups) const
{
    for (const auto &iter : mVolumeGroups) {
        groups.push_back({iter.second->getName(), iter.second->getId(),
                          iter.second->getSupportedAttributes(), iter.second->getStreamTypes()});
    }
    return NO_ERROR;
}

namespace {
template <typename T>
status_t setDevicesRoleForT(
        std::map<std::pair<T, device_role_t>, AudioDeviceTypeAddrVector>& tDevicesRoleMap,
        T t, device_role_t role, const AudioDeviceTypeAddrVector &devices,
        const std::string& logStr, std::function<bool(T)> p) {
    if (!p(t)) {
        ALOGE("%s invalid %s %u", __func__, logStr.c_str(), t);
        return BAD_VALUE;
    }

    switch (role) {
    case DEVICE_ROLE_PREFERRED: {
        tDevicesRoleMap[std::make_pair(t, role)] = devices;
        // The preferred devices and disabled devices are mutually exclusive. Once a device is added
        // the a list, it must be removed from the other one.
        const device_role_t roleToRemove = DEVICE_ROLE_DISABLED;
        auto it = tDevicesRoleMap.find(std::make_pair(t, roleToRemove));
        if (it != tDevicesRoleMap.end()) {
            it->second = excludeDeviceTypeAddrsFrom(it->second, devices);
            if (it->second.empty()) {
                tDevicesRoleMap.erase(it);
            }
        }
    } break;
    case DEVICE_ROLE_DISABLED: {
        auto it = tDevicesRoleMap.find(std::make_pair(t, role));
        if (it != tDevicesRoleMap.end()) {
            it->second = joinDeviceTypeAddrs(it->second, devices);
        } else {
            tDevicesRoleMap[std::make_pair(t, role)] = devices;
        }

        // The preferred devices and disabled devices are mutually exclusive. Once a device is added
        // the a list, it must be removed from the other one.
        const device_role_t roleToRemove = DEVICE_ROLE_PREFERRED;
        it = tDevicesRoleMap.find(std::make_pair(t, roleToRemove));
        if (it != tDevicesRoleMap.end()) {
            it->second = excludeDeviceTypeAddrsFrom(it->second, devices);
            if (it->second.empty()) {
                tDevicesRoleMap.erase(it);
            }
        }
    } break;
    case DEVICE_ROLE_NONE:
        // Intentionally fall-through as it is no need to set device role as none for a strategy.
    default:
        ALOGE("%s invalid role %d", __func__, role);
        return BAD_VALUE;
    }
    return NO_ERROR;
}

template <typename T>
status_t removeDevicesRoleForT(
        std::map<std::pair<T, device_role_t>, AudioDeviceTypeAddrVector>& tDevicesRoleMap,
        T t, device_role_t role, const AudioDeviceTypeAddrVector &devices,
        const std::string& logStr, std::function<bool(T)> p) {
    if (!p(t)) {
        ALOGE("%s invalid %s %u", __func__, logStr.c_str(), t);
        return BAD_VALUE;
    }

    switch (role) {
    case DEVICE_ROLE_PREFERRED:
    case DEVICE_ROLE_DISABLED: {
        auto it = tDevicesRoleMap.find(std::make_pair(t, role));
        if (it != tDevicesRoleMap.end()) {
            it->second = excludeDeviceTypeAddrsFrom(it->second, devices);
            if (it->second.empty()) {
                tDevicesRoleMap.erase(it);
            }
        }
    } break;
    case DEVICE_ROLE_NONE:
        // Intentionally fall-through as it is not needed to set device role as none for a strategy.
    default:
        ALOGE("%s invalid role %d", __func__, role);
        return BAD_VALUE;
    }
    return NO_ERROR;
}

template <typename T>
status_t removeAllDevicesRoleForT(
        std::map<std::pair<T, device_role_t>, AudioDeviceTypeAddrVector>& tDevicesRoleMap,
        T t, device_role_t role, const std::string& logStr, std::function<bool(T)> p) {
    if (!p(t)) {
        ALOGE("%s invalid %s %u", __func__, logStr.c_str(), t);
        return BAD_VALUE;
    }

    switch (role) {
    case DEVICE_ROLE_PREFERRED:
    case DEVICE_ROLE_DISABLED:
        if (tDevicesRoleMap.erase(std::make_pair(t, role)) == 0) {
            // no preferred/disabled device was set
            return NAME_NOT_FOUND;
        }
        break;
    case DEVICE_ROLE_NONE:
        // Intentionally fall-through as it makes no sense to remove devices with
        // role as DEVICE_ROLE_NONE
    default:
        ALOGE("%s invalid role %d", __func__, role);
        return BAD_VALUE;
    }
    return NO_ERROR;
}

template <typename T>
status_t getDevicesRoleForT(
        const std::map<std::pair<T, device_role_t>, AudioDeviceTypeAddrVector>& tDevicesRoleMap,
        T t, device_role_t role, AudioDeviceTypeAddrVector &devices, const std::string& logStr,
        std::function<bool(T)> p) {
    if (!p(t)) {
        ALOGE("%s invalid %s %u", __func__, logStr.c_str(), t);
        return BAD_VALUE;
    }

    switch (role) {
    case DEVICE_ROLE_PREFERRED:
    case DEVICE_ROLE_DISABLED: {
        auto it = tDevicesRoleMap.find(std::make_pair(t, role));
        if (it == tDevicesRoleMap.end()) {
            ALOGV("%s no device as role %u for %s %u", __func__, role, logStr.c_str(), t);
            return NAME_NOT_FOUND;
        }

        devices = it->second;
    } break;
    case DEVICE_ROLE_NONE:
        // Intentionally fall-through as the DEVICE_ROLE_NONE is never set
    default:
        ALOGE("%s invalid role %d", __func__, role);
        return BAD_VALUE;
    }
    return NO_ERROR;
}

} // namespace

status_t EngineBase::setDevicesRoleForStrategy(product_strategy_t strategy, device_role_t role,
            const AudioDeviceTypeAddrVector &devices)
{
    std::function<bool(product_strategy_t)> p = [this](product_strategy_t strategy) {
        return mProductStrategies.find(strategy) != mProductStrategies.end();
    };
    return setDevicesRoleForT(
            mProductStrategyDeviceRoleMap, strategy, role, devices, "strategy" /*logStr*/, p);
}

status_t EngineBase::removeDevicesRoleForStrategy(product_strategy_t strategy, device_role_t role,
            const AudioDeviceTypeAddrVector &devices)
{
    std::function<bool(product_strategy_t)> p = [this](product_strategy_t strategy) {
        return mProductStrategies.find(strategy) != mProductStrategies.end();
    };
    return removeDevicesRoleForT(
            mProductStrategyDeviceRoleMap, strategy, role, devices, "strategy" /*logStr*/, p);
}

status_t EngineBase::clearDevicesRoleForStrategy(product_strategy_t strategy,
            device_role_t role)
{
    std::function<bool(product_strategy_t)> p = [this](product_strategy_t strategy) {
        return mProductStrategies.find(strategy) != mProductStrategies.end();
    };
    return removeAllDevicesRoleForT(
            mProductStrategyDeviceRoleMap, strategy, role, "strategy" /*logStr*/, p);
}

status_t EngineBase::getDevicesForRoleAndStrategy(product_strategy_t strategy, device_role_t role,
            AudioDeviceTypeAddrVector &devices) const
{
    std::function<bool(product_strategy_t)> p = [this](product_strategy_t strategy) {
        return mProductStrategies.find(strategy) != mProductStrategies.end();
    };
    return getDevicesRoleForT(
            mProductStrategyDeviceRoleMap, strategy, role, devices, "strategy" /*logStr*/, p);
}

status_t EngineBase::setDevicesRoleForCapturePreset(audio_source_t audioSource, device_role_t role,
        const AudioDeviceTypeAddrVector &devices)
{
    std::function<bool(audio_source_t)> p = [](audio_source_t audioSource) {
        return audio_is_valid_audio_source(audioSource);
    };
    return setDevicesRoleForT(
            mCapturePresetDevicesRoleMap, audioSource, role, devices, "audio source" /*logStr*/, p);
}

status_t EngineBase::addDevicesRoleForCapturePreset(audio_source_t audioSource, device_role_t role,
        const AudioDeviceTypeAddrVector &devices)
{
    // verify if the audio source is valid
    if (!audio_is_valid_audio_source(audioSource)) {
        ALOGE("%s unknown audio source %u", __func__, audioSource);
    }

    switch (role) {
    case DEVICE_ROLE_PREFERRED:
    case DEVICE_ROLE_DISABLED: {
        const auto audioSourceRole = std::make_pair(audioSource, role);
        mCapturePresetDevicesRoleMap[audioSourceRole] = excludeDeviceTypeAddrsFrom(
                mCapturePresetDevicesRoleMap[audioSourceRole], devices);
        for (const auto &device : devices) {
            mCapturePresetDevicesRoleMap[audioSourceRole].push_back(device);
        }
        // When the devices are set as preferred devices, remove them from the disabled devices.
        doRemoveDevicesRoleForCapturePreset(
                audioSource,
                role == DEVICE_ROLE_PREFERRED ? DEVICE_ROLE_DISABLED : DEVICE_ROLE_PREFERRED,
                devices,
                false /*forceMatched*/);
    } break;
    case DEVICE_ROLE_NONE:
        // Intentionally fall-through as it is no need to set device role as none
    default:
        ALOGE("%s invalid role %d", __func__, role);
        return BAD_VALUE;
    }
    return NO_ERROR;
}

status_t EngineBase::removeDevicesRoleForCapturePreset(
        audio_source_t audioSource, device_role_t role, const AudioDeviceTypeAddrVector& devices) {
    return doRemoveDevicesRoleForCapturePreset(audioSource, role, devices);
}

status_t EngineBase::doRemoveDevicesRoleForCapturePreset(audio_source_t audioSource,
        device_role_t role, const AudioDeviceTypeAddrVector& devices, bool forceMatched)
{
    // verify if the audio source is valid
    if (!audio_is_valid_audio_source(audioSource)) {
        ALOGE("%s unknown audio source %u", __func__, audioSource);
    }

    switch (role) {
    case DEVICE_ROLE_PREFERRED:
    case DEVICE_ROLE_DISABLED: {
        const auto audioSourceRole = std::make_pair(audioSource, role);
        if (mCapturePresetDevicesRoleMap.find(audioSourceRole) ==
                mCapturePresetDevicesRoleMap.end()) {
            return NAME_NOT_FOUND;
        }
        AudioDeviceTypeAddrVector remainingDevices = excludeDeviceTypeAddrsFrom(
                mCapturePresetDevicesRoleMap[audioSourceRole], devices);
        if (forceMatched && remainingDevices.size() !=
                mCapturePresetDevicesRoleMap[audioSourceRole].size() - devices.size()) {
            // There are some devices from `devicesToRemove` that are not shown in the cached record
            return BAD_VALUE;
        }
        mCapturePresetDevicesRoleMap[audioSourceRole] = remainingDevices;
        if (mCapturePresetDevicesRoleMap[audioSourceRole].empty()) {
            // Remove the role when device list is empty
            mCapturePresetDevicesRoleMap.erase(audioSourceRole);
        }
    } break;
    case DEVICE_ROLE_NONE:
        // Intentionally fall-through as it makes no sense to remove devices with
        // role as DEVICE_ROLE_NONE
    default:
        ALOGE("%s invalid role %d", __func__, role);
        return BAD_VALUE;
    }
    return NO_ERROR;
}

status_t EngineBase::clearDevicesRoleForCapturePreset(audio_source_t audioSource,
                                                      device_role_t role)
{
    std::function<bool(audio_source_t)> p = [](audio_source_t audioSource) {
        return audio_is_valid_audio_source(audioSource);
    };
    return removeAllDevicesRoleForT(
            mCapturePresetDevicesRoleMap, audioSource, role, "audio source" /*logStr*/, p);
}

status_t EngineBase::getDevicesForRoleAndCapturePreset(audio_source_t audioSource,
        device_role_t role, AudioDeviceTypeAddrVector &devices) const
{
    std::function<bool(audio_source_t)> p = [](audio_source_t audioSource) {
        return audio_is_valid_audio_source(audioSource);
    };
    return getDevicesRoleForT(
            mCapturePresetDevicesRoleMap, audioSource, role, devices, "audio source" /*logStr*/, p);
}

status_t EngineBase::getMediaDevicesForRole(device_role_t role,
        const DeviceVector& availableDevices, DeviceVector& devices) const
{
    product_strategy_t strategy = getProductStrategyByName("STRATEGY_MEDIA" /*name*/);
    if (strategy == PRODUCT_STRATEGY_NONE) {
        strategy = getProductStrategyForStream(AUDIO_STREAM_MUSIC);
    }
    if (strategy == PRODUCT_STRATEGY_NONE) {
        return NAME_NOT_FOUND;
    }
    AudioDeviceTypeAddrVector deviceAddrVec;
    status_t status = getDevicesForRoleAndStrategy(strategy, role, deviceAddrVec);
    if (status != NO_ERROR) {
        return status;
    }
    devices = availableDevices.getDevicesFromDeviceTypeAddrVec(deviceAddrVec);
    return deviceAddrVec.size() == devices.size() ? NO_ERROR : NOT_ENOUGH_DATA;
}

DeviceVector EngineBase::getActiveMediaDevices(const DeviceVector& availableDevices) const
{
    // The priority of active devices as follows:
    // 1: the available preferred devices for media
    // 2: the latest connected removable media device that is enabled
    DeviceVector activeDevices;
    if (getMediaDevicesForRole(
            DEVICE_ROLE_PREFERRED, availableDevices, activeDevices) != NO_ERROR) {
        activeDevices.clear();
        DeviceVector disabledDevices;
        getMediaDevicesForRole(DEVICE_ROLE_DISABLED, availableDevices, disabledDevices);
        sp<DeviceDescriptor> device =
                mLastRemovableMediaDevices.getLastRemovableMediaDevice(disabledDevices);
        if (device != nullptr) {
            activeDevices.add(device);
        }
    }
    return activeDevices;
}

void EngineBase::initializeDeviceSelectionCache() {
    // Initializing the device selection cache with default device won't be harmful, it will be
    // updated after the audio modules are initialized.
    auto defaultDevices = DeviceVector(getApmObserver()->getDefaultOutputDevice());
    for (const auto &iter : getProductStrategies()) {
        const auto &strategy = iter.second;
        mDevicesForStrategies[strategy->getId()] = defaultDevices;
        setStrategyDevices(strategy, defaultDevices);
    }
}

void EngineBase::updateDeviceSelectionCache() {
    for (const auto &iter : getProductStrategies()) {
        const auto& strategy = iter.second;
        auto devices = getDevicesForProductStrategy(strategy->getId());
        mDevicesForStrategies[strategy->getId()] = devices;
        setStrategyDevices(strategy, devices);
    }
}

DeviceVector EngineBase::getPreferredAvailableDevicesForProductStrategy(
        const DeviceVector& availableOutputDevices, product_strategy_t strategy) const {
    DeviceVector preferredAvailableDevVec = {};
    AudioDeviceTypeAddrVector preferredStrategyDevices;
    const status_t status = getDevicesForRoleAndStrategy(
            strategy, DEVICE_ROLE_PREFERRED, preferredStrategyDevices);
    if (status == NO_ERROR) {
        // there is a preferred device, is it available?
        preferredAvailableDevVec =
                availableOutputDevices.getDevicesFromDeviceTypeAddrVec(preferredStrategyDevices);
        if (preferredAvailableDevVec.size() == preferredStrategyDevices.size()) {
            ALOGV("%s using pref device %s for strategy %u",
                   __func__, preferredAvailableDevVec.toString().c_str(), strategy);
            return preferredAvailableDevVec;
        }
    }
    return preferredAvailableDevVec;
}

DeviceVector EngineBase::getDisabledDevicesForProductStrategy(
        const DeviceVector &availableOutputDevices, product_strategy_t strategy) const {
    DeviceVector disabledDevices = {};
    AudioDeviceTypeAddrVector disabledDevicesTypeAddr;
    const status_t status = getDevicesForRoleAndStrategy(
            strategy, DEVICE_ROLE_DISABLED, disabledDevicesTypeAddr);
    if (status == NO_ERROR) {
        disabledDevices =
                availableOutputDevices.getDevicesFromDeviceTypeAddrVec(disabledDevicesTypeAddr);
    }
    return disabledDevices;
}

void EngineBase::dumpCapturePresetDevicesRoleMap(String8 *dst, int spaces) const
{
    dst->appendFormat("\n%*sDevice role per capture preset dump:", spaces, "");
    for (const auto& [capturePresetRolePair, devices] : mCapturePresetDevicesRoleMap) {
        dst->appendFormat("\n%*sCapture preset(%u) Device Role(%u) Devices(%s)", spaces + 2, "",
                capturePresetRolePair.first, capturePresetRolePair.second,
                dumpAudioDeviceTypeAddrVector(devices, true /*includeSensitiveInfo*/).c_str());
    }
    dst->appendFormat("\n");
}

void EngineBase::dump(String8 *dst) const
{
    mProductStrategies.dump(dst, 2);
    dumpProductStrategyDevicesRoleMap(mProductStrategyDeviceRoleMap, dst, 2);
    dumpCapturePresetDevicesRoleMap(dst, 2);
    mVolumeGroups.dump(dst, 2);
}

} // namespace audio_policy
} // namespace android
