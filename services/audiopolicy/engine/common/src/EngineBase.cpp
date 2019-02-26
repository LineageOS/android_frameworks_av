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
#define LOG_NDEBUG 0

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

    if (state < 0 || state >= AUDIO_MODE_CNT) {
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
    auto loadProductStrategies =
            [](auto& strategyConfigs, auto& productStrategies) {
        uint32_t groupid = 0;
        for (auto& strategyConfig : strategyConfigs) {
            sp<ProductStrategy> strategy = new ProductStrategy(strategyConfig.name);
            for (const auto &group : strategyConfig.attributesGroups) {
                for (const auto &attr : group.attributesVect) {
                    strategy->addAttributes({group.stream, groupid, attr});
                }
                groupid += 1;
            }
            product_strategy_t strategyId = strategy->getId();
            productStrategies[strategyId] = strategy;
        }
    };
    auto loadVolumeCurves = [](const auto &configVolumes, auto &streamVolumeCollection) {
        for (auto &configVolume : configVolumes) {
            audio_stream_type_t streamType = AUDIO_STREAM_DEFAULT;
            if (configVolume.stream.empty() ||
                    !StreamTypeConverter::fromString(configVolume.stream, streamType)) {
                ALOGE("%s: Invalid stream type", __FUNCTION__);
                continue;
            }
            VolumeCurves volumeCurves(streamType, configVolume.indexMin, configVolume.indexMax);
            for (auto &configCurve : configVolume.volumeCurves) {
                device_category deviceCategory = DEVICE_CATEGORY_SPEAKER;
                if (!DeviceCategoryConverter::fromString(configCurve.deviceCategory,
                                                         deviceCategory)) {
                    ALOGE("%s: Invalid %s", __FUNCTION__, configCurve.deviceCategory.c_str());
                    continue;
                }
                sp<VolumeCurve> curve = new VolumeCurve(deviceCategory);
                for (auto &point : configCurve.curvePoints) {
                    curve->add({point.index, point.attenuationInMb});
                }
                volumeCurves.add(curve);
            }
            streamVolumeCollection.add(volumeCurves, streamType);
        }
    };

    auto result = engineConfig::parse();
    if (result.parsedConfig == nullptr) {
        ALOGW("%s: No configuration found, using default matching phone experience.", __FUNCTION__);
        engineConfig::Config config = gDefaultEngineConfig;
        android::status_t ret = engineConfig::parseLegacyVolumes(config.volumeGroups);
        result = {std::make_unique<engineConfig::Config>(config),
                  static_cast<size_t>(ret == NO_ERROR ? 0 : 1)};
    }
    ALOGE_IF(result.nbSkippedElement != 0, "skipped %zu elements", result.nbSkippedElement);
    loadProductStrategies(result.parsedConfig->productStrategies, mProductStrategies);
    loadVolumeCurves(result.parsedConfig->volumeGroups, mStreamVolumeCurves);
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

VolumeCurves *EngineBase::getVolumeCurvesForAttributes(const audio_attributes_t &attr)
{
    return &mStreamVolumeCurves.getVolumeCurvesForStream(getStreamTypeForAttributes(attr));
}

VolumeCurves *EngineBase::getVolumeCurvesForStreamType(audio_stream_type_t stream)
{
    return &mStreamVolumeCurves.getVolumeCurvesForStream(stream);
}

status_t EngineBase::switchVolumeCurve(audio_stream_type_t streamSrc, audio_stream_type_t streamDst)
{
    return mStreamVolumeCurves.switchVolumeCurve(streamSrc, streamDst);;
}

status_t EngineBase::restoreOriginVolumeCurve(audio_stream_type_t stream)
{
    return mStreamVolumeCurves.restoreOriginVolumeCurve(stream);
}

void EngineBase::dump(String8 *dst) const
{
    mProductStrategies.dump(dst, 2);
    mStreamVolumeCurves.dump(dst, 2);
}

} // namespace audio_policy
} // namespace android
