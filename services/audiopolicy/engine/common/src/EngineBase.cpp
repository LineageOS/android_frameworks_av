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
    if ((deviceType != AUDIO_DEVICE_NONE) && audio_is_output_device(deviceType)) {
        mLastRemovableMediaDevices.setRemovableMediaDevices(devDesc, state);
    }

    return NO_ERROR;
}

product_strategy_t EngineBase::getProductStrategyForAttributes(const audio_attributes_t &attr) const
{
    return mProductStrategies.getProductStrategyForAttributes(attr);
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

engineConfig::ParsingResult EngineBase::loadAudioPolicyEngineConfig()
{
    auto loadVolumeConfig = [](auto &volumeGroups, auto &volumeConfig) {
        // Ensure name unicity to prevent duplicate
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
            strategy->addAttributes({group.stream, volumeGroup->getId(), attr});
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

    auto result = engineConfig::parse();
    if (result.parsedConfig == nullptr) {
        ALOGW("%s: No configuration found, using default matching phone experience.", __FUNCTION__);
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
    // Append for internal use only strategies (e.g. rerouting/patch)
    result.parsedConfig->productStrategies.insert(
                std::end(result.parsedConfig->productStrategies),
                std::begin(gOrderedSystemStrategies), std::end(gOrderedSystemStrategies));


    ALOGE_IF(result.nbSkippedElement != 0, "skipped %zu elements", result.nbSkippedElement);

    engineConfig::VolumeGroup defaultVolumeConfig;
    engineConfig::VolumeGroup defaultSystemVolumeConfig;
    for (auto &volumeConfig : result.parsedConfig->volumeGroups) {
        // save default volume config for streams not defined in configuration
        if (volumeConfig.name.compare("AUDIO_STREAM_MUSIC") == 0) {
            defaultVolumeConfig = volumeConfig;
        }
        if (volumeConfig.name.compare("AUDIO_STREAM_PATCH") == 0) {
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
        {productStrategy->getName(), productStrategy->listAudioAttributes(),
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

volume_group_t EngineBase::getVolumeGroupForAttributes(const audio_attributes_t &attr) const
{
    return mProductStrategies.getVolumeGroupForAttributes(attr);
}

volume_group_t EngineBase::getVolumeGroupForStreamType(audio_stream_type_t stream) const
{
    return mProductStrategies.getVolumeGroupForStreamType(stream);
}

status_t EngineBase::listAudioVolumeGroups(AudioVolumeGroupVector &groups) const
{
    for (const auto &iter : mVolumeGroups) {
        groups.push_back({iter.second->getName(), iter.second->getId(),
                          iter.second->getSupportedAttributes(), iter.second->getStreamTypes()});
    }
    return NO_ERROR;
}

status_t EngineBase::setPreferredDeviceForStrategy(product_strategy_t strategy,
            const AudioDeviceTypeAddr &device)
{
    // verify strategy exists
    if (mProductStrategies.find(strategy) == mProductStrategies.end()) {
        ALOGE("%s invalid strategy %u", __func__, strategy);
        return BAD_VALUE;
    }

    mProductStrategyPreferredDevices[strategy] = device;
    return NO_ERROR;
}

status_t EngineBase::removePreferredDeviceForStrategy(product_strategy_t strategy)
{
    // verify strategy exists
    if (mProductStrategies.find(strategy) == mProductStrategies.end()) {
        ALOGE("%s invalid strategy %u", __func__, strategy);
        return BAD_VALUE;
    }

    if (mProductStrategyPreferredDevices.erase(strategy) == 0) {
        // no preferred device was set
        return NAME_NOT_FOUND;
    }
    return NO_ERROR;
}

status_t EngineBase::getPreferredDeviceForStrategy(product_strategy_t strategy,
            AudioDeviceTypeAddr &device) const
{
    // verify strategy exists
    if (mProductStrategies.find(strategy) == mProductStrategies.end()) {
        ALOGE("%s unknown strategy %u", __func__, strategy);
        return BAD_VALUE;
    }
    // preferred device for this strategy?
    auto devIt = mProductStrategyPreferredDevices.find(strategy);
    if (devIt == mProductStrategyPreferredDevices.end()) {
        ALOGV("%s no preferred device for strategy %u", __func__, strategy);
        return NAME_NOT_FOUND;
    }

    device = devIt->second;
    return NO_ERROR;
}

void EngineBase::dump(String8 *dst) const
{
    mProductStrategies.dump(dst, 2);
    mProductStrategyPreferredDevices.dump(dst, 2);
    mVolumeGroups.dump(dst, 2);
}

} // namespace audio_policy
} // namespace android
