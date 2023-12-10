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

#include <string>
#include <utility>

#include <AudioPolicyManagerObserver.h>
#include <android/media/audio/common/AudioHalEngineConfig.h>
#include <media/AudioProductStrategy.h>
#include <media/AudioVolumeGroup.h>
#include <IVolumeCurves.h>
#include <policy.h>
#include <Volume.h>
#include <HwModule.h>
#include <DeviceDescriptor.h>
#include <system/audio.h>
#include <system/audio_policy.h>
#include <utils/Errors.h>
#include <utils/Vector.h>

namespace android {

using DeviceStrategyMap = std::map<product_strategy_t, DeviceVector>;
using StrategyVector = std::vector<product_strategy_t>;
using VolumeGroupVector = std::vector<volume_group_t>;
using CapturePresetDevicesRoleMap =
        std::map<std::pair<audio_source_t, device_role_t>, AudioDeviceTypeAddrVector>;

/**
 * This interface is dedicated to the policy manager that a Policy Engine shall implement.
 */
class EngineInterface
{
public:
    /**
     * Loads the engine configuration from AIDL configuration data.
     * If loading failed, tries to fall back to some default configuration. If fallback
     * is impossible, returns an error.
     */
    virtual status_t loadFromHalConfigWithFallback(
            const media::audio::common::AudioHalEngineConfig& config) = 0;

    /**
     * Loads the engine configuration from the specified or the default config file.
     * If loading failed, tries to fall back to some default configuration. If fallback
     * is impossible, returns an error.
     */
    virtual status_t loadFromXmlConfigWithFallback(const std::string& xmlFilePath = "") = 0;

    /**
     * Checks if the engine was correctly initialized.
     *
     * @return NO_ERROR if initialization has been done correctly, error code otherwise..
     */
    virtual status_t initCheck() = 0;

    /**
     * Sets the Manager observer that allows the engine to retrieve information on collection
     * of devices, streams, HwModules, ...
     *
     * @param[in] observer handle on the manager.
     */
    virtual void setObserver(AudioPolicyManagerObserver *observer) = 0;

    /**
     * Set the Telephony Mode.
     *
     * @param[in] mode: Android Phone state (normal, ringtone, csv, in communication)
     *
     * @return NO_ERROR if Telephony Mode set correctly, error code otherwise.
     */
    virtual status_t setPhoneState(audio_mode_t mode) = 0;

    /**
     * Get the telephony Mode
     *
     * @return the current telephony mode
     */
    virtual audio_mode_t getPhoneState() const = 0;

    /**
     * Set Force Use config for a given usage.
     *
     * @param[in] usage for which a configuration shall be forced.
     * @param[in] config wished to be forced for the given usage.
     *
     * @return NO_ERROR if the Force Use config was set correctly, error code otherwise (e.g. config
     * not allowed a given usage...)
     */
    virtual status_t setForceUse(audio_policy_force_use_t usage,
                                 audio_policy_forced_cfg_t config) = 0;

    /**
     * Get Force Use config for a given usage.
     *
     * @param[in] usage for which a configuration shall be forced.
     *
     * @return config wished to be forced for the given usage.
     */
    virtual audio_policy_forced_cfg_t getForceUse(audio_policy_force_use_t usage) const = 0;

    /**
     * Set the connection state of device(s).
     *
     * @param[in] devDesc for which the state has changed.
     * @param[in] state of availability of this(these) device(s).
     *
     * @return NO_ERROR if devices criterion updated correctly, error code otherwise.
     */
    virtual status_t setDeviceConnectionState(const android::sp<android::DeviceDescriptor> devDesc,
                                              audio_policy_dev_state_t state) = 0;

    /**
     * Get the strategy selected for a given audio attributes.
     *
     * @param[in] audio attributes to get the selected @product_strategy_t followed by.
     * @param fallbackOnDefault if true, will return the fallback strategy if the attributes
     * are not explicitly assigned to a given strategy.
     * @return @product_strategy_t to be followed.
     */
    virtual product_strategy_t getProductStrategyForAttributes(
            const audio_attributes_t &attr, bool fallbackOnDefault = true) const = 0;

    /**
     * @brief getOutputDevicesForAttributes retrieves the devices to be used for given
     * audio attributes.
     * @param attributes of the output requesting Device(s) selection
     * @param preferedDevice valid reference if a prefered device is requested, nullptr otherwise.
     * @param fromCache if true, the device is returned from internal cache,
     *                  otherwise it is determined by current state (device connected,phone state,
     *                  force use, a2dp output...)
     * @return vector of selected device descriptors.
     *         Appropriate device for streams handled by the specified audio attributes according
     *         to current phone state, forced states, connected devices...
     *         if fromCache is true, the device is returned from internal cache,
     *         otherwise it is determined by current state (device connected,phone state, force use,
     *         a2dp output...)
     * This allows to:
     *      1 speed up process when the state is stable (when starting or stopping an output)
     *      2 access to either current device selection (fromCache == true) or
     *      "future" device selection (fromCache == false) when called from a context
     *      where conditions are changing (setDeviceConnectionState(), setPhoneState()...) AND
     *      before manager updates its outputs.
     */
    virtual DeviceVector getOutputDevicesForAttributes(
            const audio_attributes_t &attributes,
            const sp<DeviceDescriptor> &preferedDevice = nullptr,
            bool fromCache = false) const = 0;

    /**
     * @brief getOutputDevicesForStream Legacy function retrieving devices from a stream type.
     * @param stream type of the output requesting Device(s) selection
     * @param fromCache if true, the device is returned from internal cache,
     *                  otherwise it is determined by current state (device connected,phone state,
     *                  force use, a2dp output...)
     * @return appropriate device for streams handled by the specified audio attributes according
     *         to current phone state, forced states, connected devices...
     *         if fromCache is true, the device is returned from internal cache,
     *         otherwise it is determined by current state (device connected,phone state, force use,
     *         a2dp output...)
     * This allows to:
     *      1 speed up process when the state is stable (when starting or stopping an output)
     *      2 access to either current device selection (fromCache == true) or
     *      "future" device selection (fromCache == false) when called from a context
     *      where conditions are changing (setDeviceConnectionState(), setPhoneState()...) AND
     *      before manager updates its outputs.
     */
    virtual DeviceVector getOutputDevicesForStream(audio_stream_type_t stream,
                                                   bool fromCache = false) const = 0;

    /**
     * Get the input device selected for given audio attributes.
     *
     * @param[in] attr audio attributes to consider
     * @param[out] mix to be used if a mix has been installed for the given audio attributes.
     * @return selected input device for the audio attributes, may be null if error.
     */
    virtual sp<DeviceDescriptor> getInputDeviceForAttributes(
            const audio_attributes_t &attr,
            uid_t uid = 0,
            audio_session_t session = AUDIO_SESSION_NONE,
            sp<AudioPolicyMix> *mix = nullptr) const = 0;

    /**
     * Get the legacy stream type for a given audio attributes.
     *
     * @param[in] audio attributes to get the associated audio_stream_type_t.
     *
     * @return audio_stream_type_t associated to the attributes.
     */
    virtual audio_stream_type_t getStreamTypeForAttributes(
            const audio_attributes_t &attr) const = 0;

    /**
     * @brief getAttributesForStream get the audio attributes from legacy stream type
     * Attributes returned might only be used to check upon routing decision, not volume decisions.
     * @param stream to consider
     * @return audio attributes matching the legacy stream type
     */
    virtual audio_attributes_t getAttributesForStreamType(audio_stream_type_t stream) const = 0;

    /**
     * @brief getStreamTypesForProductStrategy retrieves the list of legacy stream type following
     * the given product strategy
     * @param ps product strategy to consider
     * @return associated legacy Stream Types vector of the given product strategy
     */
    virtual StreamTypeVector getStreamTypesForProductStrategy(product_strategy_t ps) const = 0;

    /**
     * @brief getAllAttributesForProductStrategy retrieves all the attributes following the given
     * product strategy. Any attributes that "matches" with this one will follow the product
     * strategy.
     * "matching" means the usage shall match if reference attributes has a defined usage, AND
     * content type shall match if reference attributes has a defined content type AND
     * flags shall match if reference attributes has defined flags AND
     * tags shall match if reference attributes has defined tags.
     * @param ps product strategy to consider
     * @return vector of product strategy ids, empty if unknown strategy.
     */
    virtual AttributesVector getAllAttributesForProductStrategy(product_strategy_t ps) const = 0;

    /**
     * @brief getOrderedAudioProductStrategies
     * @return priority ordered product strategies to help the AudioPolicyManager evaluating the
     * device selection per output according to the prioritized strategies.
     */
    virtual StrategyVector getOrderedProductStrategies() const = 0;

    /**
     * @brief updateDeviceSelectionCache. Device selection for AudioAttribute / Streams is cached
     * in the engine in order to speed up process when the audio system is stable.
     * When a device is connected, the android mode is changed, engine is notified and can update
     * the cache.
     * When starting / stopping an output with a stream that can affect notification, the engine
     * needs to update the cache upon this function call.
     */
    virtual void updateDeviceSelectionCache() = 0;

    /**
     * @brief listAudioProductStrategies. Introspection API to retrieve a collection of
     * AudioProductStrategyVector that allows to build AudioAttributes according to a
     * product_strategy which is just an index. It has also a human readable name to help the
     * Car/Oem/AudioManager identiying the use case.
     * @param strategies collection.
     * @return OK if the list has been retrieved, error code otherwise
     */
    virtual status_t listAudioProductStrategies(AudioProductStrategyVector &strategies) const = 0;

    /**
     * @brief getVolumeCurvesForAttributes retrieves the Volume Curves interface for the
     *        requested Audio Attributes.
     * @param attr to be considered
     * @return IVolumeCurves interface pointer if found, nullptr otherwise
     */
    virtual IVolumeCurves *getVolumeCurvesForAttributes(const audio_attributes_t &attr) const = 0;

    /**
     * @brief getVolumeCurvesForStreamType retrieves the Volume Curves interface for the stream
     * @param stream to be considered
     * @return IVolumeCurves interface pointer if found, nullptr otherwise
     */
    virtual IVolumeCurves *getVolumeCurvesForStreamType(audio_stream_type_t stream) const = 0;

    /**
     * @brief getVolumeCurvesForVolumeGroup retrieves the Volume Curves interface for volume group
     * @param group to be considered
     * @return IVolumeCurves interface pointer if found, nullptr otherwise
     */
    virtual IVolumeCurves *getVolumeCurvesForVolumeGroup(volume_group_t group) const = 0;

    /**
     * @brief getVolumeGroups retrieves the collection of volume groups.
     * @return vector of volume groups
     */
    virtual VolumeGroupVector getVolumeGroups() const = 0;

    /**
     * @brief getVolumeGroupForAttributes gets the appropriate volume group to be used for a given
     * Audio Attributes.
     * @param attr to be considered
     * @param fallbackOnDefault if true, will return the fallback volume group if the attributes
     * are not associated to any volume group.
     * @return volume group associated to the given audio attributes, default group if none
     * applicable, VOLUME_GROUP_NONE if no default group defined.
     */
    virtual volume_group_t getVolumeGroupForAttributes(
            const audio_attributes_t &attr, bool fallbackOnDefault = true) const = 0;

    /**
     * @brief getVolumeGroupForStreamType gets the appropriate volume group to be used for a given
     * legacy stream type
     * @param stream type to be considered
     * @param fallbackOnDefault if true, will return the fallback volume group if the stream type
     * is not associated to any volume group.
     * @return volume group associated to the given stream type, default group if none applicable,
     * VOLUME_GROUP_NONE if no default group defined.
     */
    virtual volume_group_t getVolumeGroupForStreamType(
            audio_stream_type_t stream, bool fallbackOnDefault = true) const = 0;

    /**
     * @brief listAudioVolumeGroups introspection API to get the Audio Volume Groups, aka
     * former stream aliases in Audio Service, defining volume curves attached to one or more
     * Audio Attributes.
     * @param groups
     * @return NO_ERROR if the volume groups were retrieved successfully, error code otherwise
     */
    virtual status_t listAudioVolumeGroups(AudioVolumeGroupVector &groups) const = 0;

    /**
     * @brief setDevicesRoleForStrategy sets devices role for a strategy when available. To remove
     * devices role, removeDevicesRoleForStrategy must be called. When devices role is set
     * successfully, previously set devices for the same role and strategy will be removed.
     * @param strategy the audio strategy whose routing will be affected
     * @param role the role of the devices for the strategy. All device roles are defined at
     *             system/media/audio/include/system/audio_policy.h. DEVICE_ROLE_NONE is invalid
     *             for setting.
     * @param devices the audio devices to be set
     * @return BAD_VALUE if the strategy or role is invalid,
     *     or NO_ERROR if the role of the devices for strategy was set
     */
    virtual status_t setDevicesRoleForStrategy(product_strategy_t strategy, device_role_t role,
            const AudioDeviceTypeAddrVector &devices) = 0;

    /**
     * @brief removeDevicesRoleForStrategy removes the role of device(s) previously set
     * for the given strategy
     * @param strategy the audio strategy whose routing will be affected
     * @param role the role of the devices for strategy
     * @param devices the audio devices to be removed
     * @return BAD_VALUE if the strategy or role is invalid,
     *     or NO_ERROR if the devices for this role was removed
     */
    virtual status_t removeDevicesRoleForStrategy(product_strategy_t strategy, device_role_t role,
            const AudioDeviceTypeAddrVector &devices) = 0;

    /**
     * @brief clearDevicesRoleForStrategy removes the role of all devices previously set
     * for the given strategy
     * @param strategy the audio strategy whose routing will be affected
     * @param role the role of the devices for strategy
     * @return BAD_VALUE if the strategy or role is invalid,
     *     or NO_ERROR if the devices for this role was removed
     */
    virtual status_t clearDevicesRoleForStrategy(product_strategy_t strategy,
            device_role_t role) = 0;

    /**
     * @brief getDevicesForRoleAndStrategy queries which devices have the specified role for the
     * specified strategy
     * @param strategy the strategy to query
     * @param role the role of the devices to query
     * @param devices returns list of devices with matching role for the specified strategy.
     *                DEVICE_ROLE_NONE is invalid as input.
     * @return BAD_VALUE if the strategy or role is invalid,
     *     or NAME_NOT_FOUND if no device for the role and strategy was set
     *     or NO_ERROR if the devices parameter contains a list of devices
     */
    virtual status_t getDevicesForRoleAndStrategy(product_strategy_t strategy, device_role_t role,
            AudioDeviceTypeAddrVector &devices) const = 0;

    /**
     * @brief setDevicesRoleForCapturePreset sets devices role for a capture preset when available.
     * To remove devices role, removeDevicesRoleForCapturePreset must be called. Calling
     * clearDevicesRoleForCapturePreset will remove all devices as role. When devices role is set
     * successfully, previously set devices for the same role and capture preset will be removed.
     * @param audioSource the audio capture preset whose routing will be affected
     * @param role the role of the devices for the capture preset. All device roles are defined at
     *             system/media/audio/include/system/audio_policy.h. DEVICE_ROLE_NONE is invalid
     *             for setting.
     * @param devices the audio devices to be set
     * @return BAD_VALUE if the capture preset or role is invalid,
     *     or NO_ERROR if the role of the devices for capture preset was set
     */
    virtual status_t setDevicesRoleForCapturePreset(audio_source_t audioSource, device_role_t role,
            const AudioDeviceTypeAddrVector &devices) = 0;

    /**
     * @brief addDevicesRoleForCapturePreset adds devices role for a capture preset when available.
     * To remove devices role, removeDevicesRoleForCapturePreset must be called. Calling
     * clearDevicesRoleForCapturePreset will remove all devices as role.
     * @param audioSource the audio capture preset whose routing will be affected
     * @param role the role of the devices for the capture preset. All device roles are defined at
     *             system/media/audio/include/system/audio_policy.h. DEVICE_ROLE_NONE is invalid
     *             for setting.
     * @param devices the audio devices to be added
     * @return BAD_VALUE if the capture preset or role is invalid,
     *     or NO_ERROR if the role of the devices for capture preset was added
     */
    virtual status_t addDevicesRoleForCapturePreset(audio_source_t audioSource, device_role_t role,
            const AudioDeviceTypeAddrVector &devices) = 0;

    /**
     * @brief removeDevicesRoleForCapturePreset removes the role of device(s) previously set
     * for the given capture preset
     * @param audioSource the audio capture preset whose routing will be affected
     * @param role the role of the devices for the capture preset
     * @param devices the devices to be removed
     * @return BAD_VALUE if 1) the capture preset is invalid, 2) role is invalid or 3) the list of
     *     devices to be removed are not all present as role for a capture preset
     *     or NO_ERROR if the devices for this role was removed
     */
    virtual status_t removeDevicesRoleForCapturePreset(audio_source_t audioSource,
            device_role_t role, const AudioDeviceTypeAddrVector& devices) = 0;

    /**
     * @brief clearDevicesRoleForCapturePreset removes the role of all device(s) previously set
     * for the given capture preset
     * @param audioSource the audio capture preset whose routing will be affected
     * @param role the role of the devices for the capture preset
     * @return BAD_VALUE if the capture preset or role is invalid,
     *     or NO_ERROR if the devices for this role was removed
     */
    virtual status_t clearDevicesRoleForCapturePreset(audio_source_t audioSource,
            device_role_t role);

    /**
     * @brief getDevicesForRoleAndCapturePreset queries which devices have the specified role for
     * the specified capture preset
     * @param audioSource the capture preset to query
     * @param role the role of the devices to query
     * @param devices returns list of devices with matching role for the specified capture preset.
     *                DEVICE_ROLE_NONE is invalid as input.
     * @return BAD_VALUE if the capture preset or role is invalid,
     *     or NAME_NOT_FOUND if no device for the role and capture preset was set
     *     or NO_ERROR if the devices parameter contains a list of devices
     */
    virtual status_t getDevicesForRoleAndCapturePreset(audio_source_t audioSource,
            device_role_t role, AudioDeviceTypeAddrVector &devices) const = 0;

    /**
     * @brief getActiveMediaDevices returns which devices will most likely to be used for media
     * @param availableDevices all available devices
     * @return collection of active devices
     */
    virtual DeviceVector getActiveMediaDevices(const DeviceVector& availableDevices) const = 0;

    /**
     * @brief initializeDeviceSelectionCache. Device selection for AudioAttribute / Streams is
     * cached in the engine in order to speed up process when the audio system is stable. When the
     * audio system is initializing, not all audio devices information will be available. In that
     * case, calling this function can allow the engine to initialize the device selection cache
     * with default values.
     * This must only be called when audio policy manager is initializing.
     */
    virtual void initializeDeviceSelectionCache() = 0;

    virtual void dump(String8 *dst) const = 0;

protected:
    virtual ~EngineInterface() {}
};

__attribute__((visibility("default")))
extern "C" EngineInterface* createEngineInstance();

__attribute__((visibility("default")))
extern "C" void destroyEngineInstance(EngineInterface *engine);

} // namespace android
