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
#include <EngineInterface.h>
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
    virtual ~Engine() = default;

    template <class RequestedInterface>
    RequestedInterface *queryInterface();

    ///
    /// from EngineInterface
    ///
    status_t loadFromHalConfigWithFallback(
            const media::audio::common::AudioHalEngineConfig& config) override;

    status_t loadFromXmlConfigWithFallback(const std::string& xmlFilePath = "") override;

    ///
    /// from EngineBase
    ///
    status_t initCheck() override;

    status_t setPhoneState(audio_mode_t mode) override;

    audio_mode_t getPhoneState() const override;

    status_t setForceUse(audio_policy_force_use_t usage, audio_policy_forced_cfg_t config) override;

    audio_policy_forced_cfg_t getForceUse(audio_policy_force_use_t usage) const override;

    status_t setDeviceConnectionState(const sp<DeviceDescriptor> devDesc,
                                      audio_policy_dev_state_t state) override;

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

    status_t setDevicesRoleForStrategy(product_strategy_t strategy, device_role_t role,
                                       const AudioDeviceTypeAddrVector &devices) override;

    status_t removeDevicesRoleForStrategy(product_strategy_t strategy, device_role_t role,
                const AudioDeviceTypeAddrVector &devices) override;
    status_t clearDevicesRoleForStrategy(product_strategy_t strategy, device_role_t role) override;

    ///
    /// from AudioPolicyPluginInterface
    ///
    status_t addStream(const std::string &name, audio_stream_type_t stream) override
    {
        return add<audio_stream_type_t>(name, stream);
    }
    status_t addInputSource(const std::string &name, audio_source_t source) override
    {
        return add<audio_source_t>(name, source);
    }
    bool setVolumeProfileForStream(const audio_stream_type_t &stream,
                                   const audio_stream_type_t &volumeProfile) override;

    bool setDeviceForInputSource(const audio_source_t &inputSource, uint64_t device) override;

    void setDeviceAddressForProductStrategy(product_strategy_t strategy,
                                                    const std::string &address) override;

    bool setDeviceTypesForProductStrategy(product_strategy_t strategy, uint64_t devices) override;

    product_strategy_t getProductStrategyByName(const std::string &name) override
    {
        return EngineBase::getProductStrategyByName(name);
    }

private:
    android::status_t disableDevicesForStrategy(product_strategy_t strategy,
            const DeviceVector &devicesToDisable);
    void enableDevicesForStrategy(product_strategy_t strategy, const DeviceVector &devicesToEnable);
    android::status_t setOutputDevicesConnectionState(const DeviceVector &devices,
                                                      audio_policy_dev_state_t state);

    /* Copy facilities are put private to disable copy. */
    Engine(const Engine &object);
    Engine &operator=(const Engine &object);

    StreamCollection mStreamCollection; /**< Streams indexed by their enum id.  */
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

    status_t loadAudioPolicyEngineConfig(const std::string& xmlFilePath);

    DeviceVector getCachedDevices(product_strategy_t ps) const;

    ///
    /// from EngineBase
    ///
    DeviceVector getDevicesForProductStrategy(product_strategy_t strategy) const override;

    /**
     * Policy Parameter Manager hidden through a wrapper.
     */
    ParameterManagerWrapper *mPolicyParameterMgr;
};

} // namespace audio_policy

} // namespace android
