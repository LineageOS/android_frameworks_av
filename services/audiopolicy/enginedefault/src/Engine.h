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

#pragma once

#include "EngineBase.h"
#include "EngineInterface.h"
#include <policy.h>

namespace android
{

class AudioPolicyManagerObserver;

namespace audio_policy
{

enum legacy_strategy {
    STRATEGY_NONE = -1,
    STRATEGY_MEDIA,
    STRATEGY_PHONE,
    STRATEGY_SONIFICATION,
    STRATEGY_SONIFICATION_RESPECTFUL,
    STRATEGY_DTMF,
    STRATEGY_ENFORCED_AUDIBLE,
    STRATEGY_TRANSMITTED_THROUGH_SPEAKER,
    STRATEGY_ACCESSIBILITY,
    STRATEGY_REROUTING,
    STRATEGY_CALL_ASSISTANT,
};

class Engine : public EngineBase
{
public:
    Engine() = default;
    virtual ~Engine() = default;
    Engine(const Engine &object) = delete;
    Engine &operator=(const Engine &object) = delete;

    ///
    /// from EngineInterface
    ///
    status_t loadFromHalConfigWithFallback(
            const media::audio::common::AudioHalEngineConfig& config) override;
    status_t loadFromXmlConfigWithFallback(const std::string& xmlFilePath = "") override;

private:
    ///
    /// from EngineBase, so from EngineInterface
    ///
    status_t setForceUse(audio_policy_force_use_t usage,
                         audio_policy_forced_cfg_t config) override;

    DeviceVector getOutputDevicesForAttributes(const audio_attributes_t &attr,
                                               const sp<DeviceDescriptor> &preferedDevice = nullptr,
                                               bool fromCache = false) const override;

    DeviceVector getOutputDevicesForStream(audio_stream_type_t stream,
                                           bool fromCache = false) const override;

    sp<DeviceDescriptor> getInputDeviceForAttributes(const audio_attributes_t &attr,
                                                     uid_t uid = 0,
                                                     audio_session_t session = AUDIO_SESSION_NONE,
                                                     sp<AudioPolicyMix> *mix = nullptr)
                                                     const override;

    void setStrategyDevices(const sp<ProductStrategy>& strategy,
                            const DeviceVector& devices) override;

    DeviceVector getDevicesForProductStrategy(product_strategy_t strategy) const override;

private:
    template<typename T>
    status_t loadWithFallback(const T& configSource);

    status_t setDefaultDevice(audio_devices_t device);

    void filterOutputDevicesForStrategy(legacy_strategy strategy,
                                            DeviceVector& availableOutputDevices,
                                            const SwAudioOutputCollection &outputs) const;

    product_strategy_t remapStrategyFromContext(product_strategy_t strategy,
                                            const SwAudioOutputCollection &outputs) const;

    DeviceVector getDevicesForStrategyInt(legacy_strategy strategy,
                                          DeviceVector availableOutputDevices,
                                          const SwAudioOutputCollection &outputs) const;

    sp<DeviceDescriptor> getDeviceForInputSource(audio_source_t inputSource) const;

    product_strategy_t getProductStrategyFromLegacy(legacy_strategy legacyStrategy) const;
    audio_devices_t getPreferredDeviceTypeForLegacyStrategy(
        const DeviceVector& availableOutputDevices, legacy_strategy legacyStrategy) const;
    DeviceVector getPreferredAvailableDevicesForInputSource(
            const DeviceVector& availableInputDevices, audio_source_t inputSource) const;
    DeviceVector getDisabledDevicesForInputSource(
            const DeviceVector& availableInputDevices, audio_source_t inputSource) const;

    std::map<product_strategy_t, legacy_strategy> mLegacyStrategyMap;
};
} // namespace audio_policy
} // namespace android
