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
#include <AudioPolicyManagerInterface.h>
#include <AudioPolicyPluginInterface.h>
#include "Collection.h"

namespace android {
class AudioPolicyManagerObserver;

namespace audio_policy {

class ParameterManagerWrapper;
class VolumeProfile;

class Engine : public EngineBase, AudioPolicyPluginInterface
{
public:
    Engine();
    virtual ~Engine();

    template <class RequestedInterface>
    RequestedInterface *queryInterface();

    ///
    /// from EngineBase
    ///
    android::status_t initCheck() override;

    audio_devices_t getDeviceForInputSource(audio_source_t inputSource) const override
    {
        return getPropertyForKey<audio_devices_t, audio_source_t>(inputSource);
    }

    audio_devices_t getDeviceForStrategy(routing_strategy stategy) const override;

    routing_strategy getStrategyForStream(audio_stream_type_t stream) override
    {
        return getPropertyForKey<routing_strategy, audio_stream_type_t>(stream);
    }

    routing_strategy getStrategyForUsage(audio_usage_t usage) override;

    status_t setPhoneState(audio_mode_t mode) override;

    audio_mode_t getPhoneState() const override;

    status_t setForceUse(audio_policy_force_use_t usage, audio_policy_forced_cfg_t config) override;

    audio_policy_forced_cfg_t getForceUse(audio_policy_force_use_t usage) const override;

    android::status_t setDeviceConnectionState(const sp<DeviceDescriptor> devDesc,
                                               audio_policy_dev_state_t state) override;

    DeviceVector getOutputDevicesForAttributes(const audio_attributes_t &attr,
                                               const sp<DeviceDescriptor> &preferedDevice = nullptr,
                                               bool fromCache = false) const override;

    DeviceVector getOutputDevicesForStream(audio_stream_type_t stream,
                                           bool fromCache = false) const override;

    sp<DeviceDescriptor> getInputDeviceForAttributes(
            const audio_attributes_t &attr, AudioMix **mix = nullptr) const override;

    void updateDeviceSelectionCache() override;

    ///
    /// from AudioPolicyPluginInterface
    ///
    status_t addStrategy(const std::string &name, routing_strategy strategy) override
    {
        return add<routing_strategy>(name, strategy);
    }
    status_t addStream(const std::string &name, audio_stream_type_t stream) override
    {
        return add<audio_stream_type_t>(name, stream);
    }
    status_t addUsage(const std::string &name, audio_usage_t usage) override
    {
        return add<audio_usage_t>(name, usage);
    }
    status_t addInputSource(const std::string &name, audio_source_t source) override
    {
        return add<audio_source_t>(name, source);
    }
    bool setDeviceForStrategy(const routing_strategy &strategy, audio_devices_t devices) override
    {
        return setPropertyForKey<audio_devices_t, routing_strategy>(devices, strategy);
    }
    bool setStrategyForStream(const audio_stream_type_t &stream,
                              routing_strategy strategy) override
    {
        return setPropertyForKey<routing_strategy, audio_stream_type_t>(strategy, stream);
    }
    bool setVolumeProfileForStream(const audio_stream_type_t &stream,
                                   const audio_stream_type_t &volumeProfile) override;

    bool setStrategyForUsage(const audio_usage_t &usage, routing_strategy strategy) override
    {
        return setPropertyForKey<routing_strategy, audio_usage_t>(strategy, usage);
    }
    bool setDeviceForInputSource(const audio_source_t &inputSource, audio_devices_t device) override
    {
        return setPropertyForKey<audio_devices_t, audio_source_t>(device, inputSource);
    }
    void setDeviceAddressForProductStrategy(product_strategy_t strategy,
                                                    const std::string &address) override;

    bool setDeviceTypesForProductStrategy(product_strategy_t strategy,
                                                  audio_devices_t devices) override;

    product_strategy_t getProductStrategyByName(const std::string &name) override
    {
        return EngineBase::getProductStrategyByName(name);
    }

private:
    /* Copy facilities are put private to disable copy. */
    Engine(const Engine &object);
    Engine &operator=(const Engine &object);

    StrategyCollection mStrategyCollection; /**< Strategies indexed by their enum id. */
    StreamCollection mStreamCollection; /**< Streams indexed by their enum id.  */
    UsageCollection mUsageCollection; /**< Usages indexed by their enum id. */
    InputSourceCollection mInputSourceCollection; /**< Input sources indexed by their enum id. */

    template <typename Key>
    status_t add(const std::string &name, const Key &key);

    template <typename Key>
    Element<Key> *getFromCollection(const Key &key) const;

    template <typename Key>
    const Collection<Key> &getCollection() const;

    template <typename Key>
    Collection<Key> &getCollection();

    template <typename Property, typename Key>
    Property getPropertyForKey(Key key) const;

    template <typename Property, typename Key>
    bool setPropertyForKey(const Property &property, const Key &key);

    status_t loadAudioPolicyEngineConfig();

    DeviceVector getDevicesForProductStrategy(product_strategy_t strategy) const;

    /**
     * Policy Parameter Manager hidden through a wrapper.
     */
    ParameterManagerWrapper *mPolicyParameterMgr;

    DeviceStrategyMap mDevicesForStrategies;
};

} // namespace audio_policy

} // namespace android

