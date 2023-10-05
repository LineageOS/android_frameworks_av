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

#pragma once

#include <functional>

#include <android/media/audio/common/AudioHalEngineConfig.h>
#include <EngineConfig.h>
#include <EngineInterface.h>
#include <ProductStrategy.h>
#include <VolumeGroup.h>
#include <LastRemovableMediaDevices.h>

namespace android {
namespace audio_policy {

class EngineBase : public EngineInterface
{
public:
    ///
    /// from EngineInterface
    ///
    android::status_t initCheck() override;

    void setObserver(AudioPolicyManagerObserver *observer) override;

    status_t setPhoneState(audio_mode_t mode) override;

    audio_mode_t getPhoneState() const override { return mPhoneState; }

    status_t setForceUse(audio_policy_force_use_t usage, audio_policy_forced_cfg_t config) override
    {
        mForceUse[usage] = config;
        return NO_ERROR;
    }

    audio_policy_forced_cfg_t getForceUse(audio_policy_force_use_t usage) const override
    {
        return mForceUse[usage];
    }
    android::status_t setDeviceConnectionState(const sp<DeviceDescriptor> /*devDesc*/,
                                               audio_policy_dev_state_t /*state*/) override;

    product_strategy_t getProductStrategyForAttributes(
            const audio_attributes_t &attr, bool fallbackOnDefault = true) const override;

    audio_stream_type_t getStreamTypeForAttributes(const audio_attributes_t &attr) const override;

    audio_attributes_t getAttributesForStreamType(audio_stream_type_t stream) const override;

    StreamTypeVector getStreamTypesForProductStrategy(product_strategy_t ps) const override;

    AttributesVector getAllAttributesForProductStrategy(product_strategy_t ps) const override;

    StrategyVector getOrderedProductStrategies() const override;

    status_t listAudioProductStrategies(AudioProductStrategyVector &strategies) const override;

    VolumeCurves *getVolumeCurvesForAttributes(const audio_attributes_t &attr) const override;

    VolumeCurves *getVolumeCurvesForStreamType(audio_stream_type_t stream) const override;

    IVolumeCurves *getVolumeCurvesForVolumeGroup(volume_group_t group) const override
    {
       return mVolumeGroups.find(group) != end(mVolumeGroups) ?
                   mVolumeGroups.at(group)->getVolumeCurves() : nullptr;
    }

    VolumeGroupVector getVolumeGroups() const override;

    volume_group_t getVolumeGroupForAttributes(
            const audio_attributes_t &attr, bool fallbackOnDefault = true) const override;

    volume_group_t getVolumeGroupForStreamType(
            audio_stream_type_t stream, bool fallbackOnDefault = true) const override;

    status_t listAudioVolumeGroups(AudioVolumeGroupVector &groups) const override;

    /**
     * Get the list of currently connected removable device types ordered from most recently
     * connected to least recently connected.
     * @param group the device group to consider: wired, a2dp... If none, consider all groups.
     * @param excludedDevices list of device types to ignore
     * @return a potentially empty ordered list of connected removable devices.
     */
    std::vector<audio_devices_t> getLastRemovableMediaDevices(
            device_out_group_t group = GROUP_NONE,
            std::vector<audio_devices_t> excludedDevices = {}) const {
        return mLastRemovableMediaDevices.getLastRemovableMediaDevices(group, excludedDevices);
    }

    void dump(String8 *dst) const override;

    status_t setDevicesRoleForStrategy(product_strategy_t strategy, device_role_t role,
            const AudioDeviceTypeAddrVector &devices) override;

    status_t removeDevicesRoleForStrategy(product_strategy_t strategy, device_role_t role,
            const AudioDeviceTypeAddrVector &devices) override;

    status_t clearDevicesRoleForStrategy(product_strategy_t strategy, device_role_t role) override;

    status_t getDevicesForRoleAndStrategy(product_strategy_t strategy, device_role_t role,
            AudioDeviceTypeAddrVector &devices) const override;

    engineConfig::ParsingResult loadAudioPolicyEngineConfig(
            const media::audio::common::AudioHalEngineConfig& aidlConfig);

    engineConfig::ParsingResult loadAudioPolicyEngineConfig(const std::string& xmlFilePath = "");

    const ProductStrategyMap &getProductStrategies() const { return mProductStrategies; }

    ProductStrategyMap &getProductStrategies() { return mProductStrategies; }

    product_strategy_t getProductStrategyForStream(audio_stream_type_t stream) const;

    product_strategy_t getProductStrategyByName(const std::string &name) const;

    AudioPolicyManagerObserver *getApmObserver() const { return mApmObserver; }

    inline bool isInCall() const
    {
        return is_state_in_call(getPhoneState());
    }

    VolumeSource toVolumeSource(audio_stream_type_t stream) const
    {
        return static_cast<VolumeSource>(getVolumeGroupForStreamType(stream));
    }

    status_t switchVolumeCurve(audio_stream_type_t streamSrc, audio_stream_type_t streamDst);

    status_t restoreOriginVolumeCurve(audio_stream_type_t stream);

    status_t setDevicesRoleForCapturePreset(audio_source_t audioSource, device_role_t role,
            const AudioDeviceTypeAddrVector &devices) override;

    status_t addDevicesRoleForCapturePreset(audio_source_t audioSource, device_role_t role,
            const AudioDeviceTypeAddrVector &devices) override;

    /**
     * Remove devices role for capture preset. When `forceMatched` is true, the devices to be
     * removed must all show as role for the capture preset. Otherwise, only devices that has shown
     * as role for the capture preset will be remove.
     */
    status_t doRemoveDevicesRoleForCapturePreset(audio_source_t audioSource,
            device_role_t role, const AudioDeviceTypeAddrVector& devices,
            bool forceMatched=true);

    status_t removeDevicesRoleForCapturePreset(audio_source_t audioSource,
            device_role_t role, const AudioDeviceTypeAddrVector& devices) override;

    status_t clearDevicesRoleForCapturePreset(audio_source_t audioSource,
            device_role_t role) override;

    status_t getDevicesForRoleAndCapturePreset(audio_source_t audioSource,
            device_role_t role, AudioDeviceTypeAddrVector &devices) const override;

    DeviceVector getActiveMediaDevices(const DeviceVector& availableDevices) const override;

    void initializeDeviceSelectionCache() override;

    void updateDeviceSelectionCache() override;

protected:
    DeviceVector getPreferredAvailableDevicesForProductStrategy(
        const DeviceVector& availableOutputDevices, product_strategy_t strategy) const;
    DeviceVector getDisabledDevicesForProductStrategy(
        const DeviceVector& availableOutputDevices, product_strategy_t strategy) const;

private:
    engineConfig::ParsingResult processParsingResult(engineConfig::ParsingResult&& rawResult);

    /**
     * Get media devices as the given role
     *
     * @param role the audio devices role
     * @param availableDevices all available devices
     * @param devices the DeviceVector to store devices as the given role
     * @return NO_ERROR if all devices associated to the given role are present in available devices
     *         NAME_NO_FOUND if there is no strategy for media or there are no devices associate to
     *         the given role
     *         NOT_ENOUGH_DATA if not all devices as given role are present in available devices
     */
    status_t getMediaDevicesForRole(device_role_t role, const DeviceVector& availableDevices,
            DeviceVector& devices) const;

    void dumpCapturePresetDevicesRoleMap(String8 *dst, int spaces) const;

    AudioPolicyManagerObserver *mApmObserver = nullptr;

    ProductStrategyMap mProductStrategies;
    ProductStrategyDevicesRoleMap mProductStrategyDeviceRoleMap;
    CapturePresetDevicesRoleMap mCapturePresetDevicesRoleMap;
    VolumeGroupMap mVolumeGroups;
    LastRemovableMediaDevices mLastRemovableMediaDevices;
    audio_mode_t mPhoneState = AUDIO_MODE_NORMAL;  /**< current phone state. */

    /** current forced use configuration. */
    audio_policy_forced_cfg_t mForceUse[AUDIO_POLICY_FORCE_USE_CNT] = {};

protected:
    /**
     * Set the device information for a given strategy.
     *
     * @param strategy the strategy to set devices information
     * @param devices the devices selected for the strategy
     */
    virtual void setStrategyDevices(const sp<ProductStrategy>& /*strategy*/,
                                    const DeviceVector& /*devices*/) {
        // In EngineBase, do nothing. It is up to the actual engine to decide if it is needed to
        // set devices information for the given strategy.
    }

    /**
     * Get devices that will be used for the given product strategy.
     *
     * @param strategy the strategy to query
     */
    virtual DeviceVector getDevicesForProductStrategy(product_strategy_t strategy) const = 0;

    DeviceStrategyMap mDevicesForStrategies;
};

} // namespace audio_policy
} // namespace android
