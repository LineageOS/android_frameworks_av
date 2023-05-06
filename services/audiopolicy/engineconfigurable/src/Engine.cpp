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

#define LOG_TAG "APM::AudioPolicyEngine"
//#define LOG_NDEBUG 0

//#define VERY_VERBOSE_LOGGING
#ifdef VERY_VERBOSE_LOGGING
#define ALOGVV ALOGV
#else
#define ALOGVV(a...) do { } while(0)
#endif

#include "Engine.h"
#include "Stream.h"
#include "InputSource.h"

#include <EngineConfig.h>
#include <policy.h>
#include <AudioIODescriptorInterface.h>
#include <ParameterManagerWrapper.h>
#include <media/AudioContainers.h>

#include <media/TypeConverter.h>

#include <cinttypes>

using std::string;
using std::map;

namespace android {
namespace audio_policy {

template <>
StreamCollection &Engine::getCollection<audio_stream_type_t>()
{
    return mStreamCollection;
}
template <>
InputSourceCollection &Engine::getCollection<audio_source_t>()
{
    return mInputSourceCollection;
}

template <>
const StreamCollection &Engine::getCollection<audio_stream_type_t>() const
{
    return mStreamCollection;
}
template <>
const InputSourceCollection &Engine::getCollection<audio_source_t>() const
{
    return mInputSourceCollection;
}

Engine::Engine() : mPolicyParameterMgr(new ParameterManagerWrapper())
{
}

status_t Engine::loadFromHalConfigWithFallback(
        const media::audio::common::AudioHalEngineConfig& config __unused) {
    // b/242678729. Need to implement for the configurable engine.
    return INVALID_OPERATION;
}

status_t Engine::loadFromXmlConfigWithFallback(const std::string& xmlFilePath)
{
    status_t loadResult = loadAudioPolicyEngineConfig(xmlFilePath);
    if (loadResult < 0) {
        ALOGE("Policy Engine configuration is invalid.");
    }
    return loadResult;
}

status_t Engine::initCheck()
{
    std::string error;
    if (mPolicyParameterMgr == nullptr || mPolicyParameterMgr->start(error) != NO_ERROR) {
        ALOGE("%s: could not start Policy PFW: %s", __FUNCTION__, error.c_str());
        return NO_INIT;
    }
    return EngineBase::initCheck();
}

template <typename Key>
Element<Key> *Engine::getFromCollection(const Key &key) const
{
    const Collection<Key> &collection = getCollection<Key>();
    return collection.get(key);
}

template <typename Key>
status_t Engine::add(const std::string &name, const Key &key)
{
    Collection<Key> &collection = getCollection<Key>();
    return collection.add(name, key);
}

template <typename Property, typename Key>
Property Engine::getPropertyForKey(Key key) const
{
    Element<Key> *element = getFromCollection<Key>(key);
    if (element == NULL) {
        ALOGE("%s: Element not found within collection", __FUNCTION__);
        return static_cast<Property>(0);
    }
    return element->template get<Property>();
}

bool Engine::setVolumeProfileForStream(const audio_stream_type_t &stream,
                                       const audio_stream_type_t &profile)
{
    if (setPropertyForKey<audio_stream_type_t, audio_stream_type_t>(stream, profile)) {
        switchVolumeCurve(profile, stream);
        return true;
    }
    return false;
}

template <typename Property, typename Key>
bool Engine::setPropertyForKey(const Property &property, const Key &key)
{
    Element<Key> *element = getFromCollection<Key>(key);
    if (element == NULL) {
        ALOGE("%s: Element not found within collection", __FUNCTION__);
        return false;
    }
    return element->template set<Property>(property) == NO_ERROR;
}

status_t Engine::setPhoneState(audio_mode_t mode)
{
    status_t status = mPolicyParameterMgr->setPhoneState(mode);
    if (status != NO_ERROR) {
        return status;
    }
    return EngineBase::setPhoneState(mode);
}

audio_mode_t Engine::getPhoneState() const
{
    return mPolicyParameterMgr->getPhoneState();
}

status_t Engine::setForceUse(audio_policy_force_use_t usage,
                                      audio_policy_forced_cfg_t config)
{
    status_t status = mPolicyParameterMgr->setForceUse(usage, config);
    if (status != NO_ERROR) {
        return status;
    }
    return EngineBase::setForceUse(usage, config);
}

audio_policy_forced_cfg_t Engine::getForceUse(audio_policy_force_use_t usage) const
{
    return mPolicyParameterMgr->getForceUse(usage);
}

status_t Engine::setOutputDevicesConnectionState(const DeviceVector &devices,
                                                 audio_policy_dev_state_t state)
{
    for (const auto &device : devices) {
        mPolicyParameterMgr->setDeviceConnectionState(device->type(), device->address(), state);
    }
    DeviceVector availableOutputDevices = getApmObserver()->getAvailableOutputDevices();
    if (state == AUDIO_POLICY_DEVICE_STATE_UNAVAILABLE) {
        availableOutputDevices.remove(devices);
    } else {
        availableOutputDevices.add(devices);
    }
    return mPolicyParameterMgr->setAvailableOutputDevices(availableOutputDevices.types());
}

status_t Engine::setDeviceConnectionState(const sp<DeviceDescriptor> device,
                                          audio_policy_dev_state_t state)
{
    mPolicyParameterMgr->setDeviceConnectionState(device->type(), device->address(), state);
    if (audio_is_output_device(device->type())) {
        return mPolicyParameterMgr->setAvailableOutputDevices(
                    getApmObserver()->getAvailableOutputDevices().types());
    } else if (audio_is_input_device(device->type())) {
        return mPolicyParameterMgr->setAvailableInputDevices(
                    getApmObserver()->getAvailableInputDevices().types());
    }
    return EngineBase::setDeviceConnectionState(device, state);
}

status_t Engine::loadAudioPolicyEngineConfig(const std::string& xmlFilePath)
{
    auto result = EngineBase::loadAudioPolicyEngineConfig(xmlFilePath);

    // Custom XML Parsing
    auto loadCriteria= [this](const auto& configCriteria, const auto& configCriterionTypes) {
        for (auto& criterion : configCriteria) {
            engineConfig::CriterionType criterionType;
            for (auto &configCriterionType : configCriterionTypes) {
                if (configCriterionType.name == criterion.typeName) {
                    criterionType = configCriterionType;
                    break;
                }
            }
            ALOG_ASSERT(not criterionType.name.empty(), "Invalid criterion type for %s",
                        criterion.name.c_str());
            mPolicyParameterMgr->addCriterion(criterion.name, criterionType.isInclusive,
                                              criterionType.valuePairs,
                                              criterion.defaultLiteralValue);
        }
    };

    loadCriteria(result.parsedConfig->criteria, result.parsedConfig->criterionTypes);
    return result.nbSkippedElement == 0? NO_ERROR : BAD_VALUE;
}

status_t Engine::setDevicesRoleForStrategy(product_strategy_t strategy, device_role_t role,
                                           const AudioDeviceTypeAddrVector &devices)
{
    DeviceVector availableOutputDevices = getApmObserver()->getAvailableOutputDevices();
    DeviceVector prevDisabledDevices =
            getDisabledDevicesForProductStrategy(availableOutputDevices, strategy);
    status_t status = EngineBase::setDevicesRoleForStrategy(strategy, role, devices);
    if (status != NO_ERROR) {
        return status;
    }
    DeviceVector newDisabledDevices =
            getDisabledDevicesForProductStrategy(availableOutputDevices, strategy);
    if (role == DEVICE_ROLE_PREFERRED) {
        DeviceVector reenabledDevices = prevDisabledDevices;
        reenabledDevices.remove(newDisabledDevices);
        if (reenabledDevices.empty()) {
            ALOGD("%s DEVICE_ROLE_PREFERRED empty renabled devices", __func__);
            return status;
        }
        // some devices were moved from disabled to preferred, need to force a resync for these
        enableDevicesForStrategy(strategy, prevDisabledDevices);
    }
    if (newDisabledDevices.empty()) {
        return status;
    }
    return disableDevicesForStrategy(strategy, newDisabledDevices);
}

status_t Engine::removeDevicesRoleForStrategy(product_strategy_t strategy, device_role_t role,
        const AudioDeviceTypeAddrVector &devices)
{
    const auto productStrategies = getProductStrategies();
    if (productStrategies.find(strategy) == end(productStrategies)) {
        ALOGE("%s invalid %d", __func__, strategy);
        return BAD_VALUE;
    }
    DeviceVector availableOutputDevices = getApmObserver()->getAvailableOutputDevices();
    DeviceVector prevDisabledDevices =
            getDisabledDevicesForProductStrategy(availableOutputDevices, strategy);
    status_t status = EngineBase::removeDevicesRoleForStrategy(strategy, role, devices);
    if (status != NO_ERROR || role == DEVICE_ROLE_PREFERRED) {
        return status;
    }
    // Removing ROLE_DISABLED for given devices, need to force a resync for these
    enableDevicesForStrategy(strategy, prevDisabledDevices);

    DeviceVector remainingDisabledDevices = getDisabledDevicesForProductStrategy(
            availableOutputDevices, strategy);
    if (remainingDisabledDevices.empty()) {
        return status;
    }
    return disableDevicesForStrategy(strategy, remainingDisabledDevices);
}

status_t Engine::clearDevicesRoleForStrategy(product_strategy_t strategy, device_role_t role)
{
    const auto productStrategies = getProductStrategies();
    if (productStrategies.find(strategy) == end(productStrategies)) {
        ALOGE("%s invalid %d", __func__, strategy);
        return BAD_VALUE;
    }
    DeviceVector availableOutputDevices = getApmObserver()->getAvailableOutputDevices();
    DeviceVector prevDisabledDevices =
            getDisabledDevicesForProductStrategy(availableOutputDevices, strategy);
    status_t status = EngineBase::clearDevicesRoleForStrategy(strategy, role);
    if (status != NO_ERROR || role == DEVICE_ROLE_PREFERRED || prevDisabledDevices.empty()) {
        return status;
    }
    // Disabled devices were removed, need to force a resync for these
    enableDevicesForStrategy(strategy, prevDisabledDevices);
    return NO_ERROR;
}

void Engine::enableDevicesForStrategy(product_strategy_t strategy __unused,
        const DeviceVector &devicesToEnable) {
    // devices were (re)enabled, need to force a resync for these
    setOutputDevicesConnectionState(devicesToEnable, AUDIO_POLICY_DEVICE_STATE_UNAVAILABLE);
    setOutputDevicesConnectionState(devicesToEnable, AUDIO_POLICY_DEVICE_STATE_AVAILABLE);
}

status_t Engine::disableDevicesForStrategy(product_strategy_t strategy,
        const DeviceVector &devicesToDisable) {
    // Filter out disabled devices for this strategy.
    // However, to update the output device decision, availability criterion shall be updated,
    // which may impact other strategies. So, as a WA, reconsider now and later to prevent from
    // altering decision for other strategies;
    setOutputDevicesConnectionState(devicesToDisable, AUDIO_POLICY_DEVICE_STATE_UNAVAILABLE);

    DeviceTypeSet deviceTypes = getProductStrategies().getDeviceTypesForProductStrategy(strategy);
    const std::string address(getProductStrategies().getDeviceAddressForProductStrategy(strategy));

    setOutputDevicesConnectionState(devicesToDisable, AUDIO_POLICY_DEVICE_STATE_AVAILABLE);

    // Force reapply devices for given strategy
    getProductStrategies().at(strategy)->setDeviceTypes(deviceTypes);
    setDeviceAddressForProductStrategy(strategy, address);
    return NO_ERROR;
}

DeviceVector Engine::getDevicesForProductStrategy(product_strategy_t ps) const
{
    DeviceVector selectedDevices = {};
    DeviceVector disabledDevices = {};
    const auto productStrategies = getProductStrategies();
    if (productStrategies.find(ps) == productStrategies.end()) {
        ALOGE("%s: Trying to get device on invalid strategy %d", __FUNCTION__, ps);
        return selectedDevices;
    }
    DeviceVector availableOutputDevices = getApmObserver()->getAvailableOutputDevices();
    const SwAudioOutputCollection &outputs = getApmObserver()->getOutputs();
    DeviceTypeSet availableOutputDevicesTypes = availableOutputDevices.types();

    // check if this strategy has a preferred device that is available,
    // if yes, give priority to it.
    DeviceVector preferredAvailableDevVec =
            getPreferredAvailableDevicesForProductStrategy(availableOutputDevices, ps);
    if (!preferredAvailableDevVec.isEmpty()) {
        return preferredAvailableDevVec;
    }

    /** This is the only case handled programmatically because the PFW is unable to know the
     * activity of streams.
     *
     * -While media is playing on a remote device, use the the sonification behavior.
     * Note that we test this usecase before testing if media is playing because
     * the isStreamActive() method only informs about the activity of a stream, not
     * if it's for local playback. Note also that we use the same delay between both tests
     *
     * -When media is not playing anymore, fall back on the sonification behavior
     */
    DeviceTypeSet deviceTypes;
    product_strategy_t psOrFallback = ps;
    if (ps == getProductStrategyForStream(AUDIO_STREAM_NOTIFICATION) &&
            !is_state_in_call(getPhoneState()) &&
            !outputs.isActiveRemotely(toVolumeSource(AUDIO_STREAM_MUSIC),
                                      SONIFICATION_RESPECTFUL_AFTER_MUSIC_DELAY) &&
            outputs.isActive(toVolumeSource(AUDIO_STREAM_MUSIC),
                             SONIFICATION_RESPECTFUL_AFTER_MUSIC_DELAY)) {
        psOrFallback = getProductStrategyForStream(AUDIO_STREAM_MUSIC);
    } else if (ps == getProductStrategyForStream(AUDIO_STREAM_ACCESSIBILITY) &&
        (outputs.isActive(toVolumeSource(AUDIO_STREAM_RING)) ||
         outputs.isActive(toVolumeSource(AUDIO_STREAM_ALARM)))) {
            // do not route accessibility prompts to a digital output currently configured with a
            // compressed format as they would likely not be mixed and dropped.
            // Device For Sonification conf file has HDMI, SPDIF and HDMI ARC unreacheable.
        psOrFallback = getProductStrategyForStream(AUDIO_STREAM_RING);
    }
    disabledDevices = getDisabledDevicesForProductStrategy(availableOutputDevices, psOrFallback);
    deviceTypes = productStrategies.getDeviceTypesForProductStrategy(psOrFallback);
    // In case a fallback is decided on other strategy, prevent from selecting this device if
    // disabled for current strategy.
    availableOutputDevices.remove(disabledDevices);

    if (deviceTypes.empty() ||
            Intersection(deviceTypes, availableOutputDevicesTypes).empty()) {
        auto defaultDevice = getApmObserver()->getDefaultOutputDevice();
        ALOG_ASSERT(defaultDevice != nullptr, "no valid default device defined");
        selectedDevices = DeviceVector(defaultDevice);
    } else if (/*device_distinguishes_on_address(*deviceTypes.begin())*/ isSingleDeviceType(
            deviceTypes, AUDIO_DEVICE_OUT_BUS)) {
        // We do expect only one device for these types of devices
        // Criterion device address garantee this one is available
        // If this criterion is not wished, need to ensure this device is available
        const String8 address(productStrategies.getDeviceAddressForProductStrategy(ps).c_str());
        ALOGV("%s:device %s %s %d",
                __FUNCTION__, dumpDeviceTypes(deviceTypes).c_str(), address.c_str(), ps);
        auto busDevice = availableOutputDevices.getDevice(
                *deviceTypes.begin(), address, AUDIO_FORMAT_DEFAULT);
        if (busDevice == nullptr) {
            ALOGE("%s:unavailable device %s %s, fallback on default", __func__,
                  dumpDeviceTypes(deviceTypes).c_str(), address.c_str());
            auto defaultDevice = getApmObserver()->getDefaultOutputDevice();
            ALOG_ASSERT(defaultDevice != nullptr, "Default Output Device NOT available");
            selectedDevices = DeviceVector(defaultDevice);
        } else {
            selectedDevices = DeviceVector(busDevice);
        }
    } else {
        ALOGV("%s:device %s %d", __FUNCTION__, dumpDeviceTypes(deviceTypes).c_str(), ps);
        selectedDevices = availableOutputDevices.getDevicesFromTypes(deviceTypes);
    }
    return selectedDevices;
}

DeviceVector Engine::getOutputDevicesForAttributes(const audio_attributes_t &attributes,
                                                   const sp<DeviceDescriptor> &preferredDevice,
                                                   bool fromCache) const
{
    // First check for explict routing device
    if (preferredDevice != nullptr) {
        ALOGV("%s explicit Routing on device %s", __func__, preferredDevice->toString().c_str());
        return DeviceVector(preferredDevice);
    }
    product_strategy_t strategy = getProductStrategyForAttributes(attributes);
    const DeviceVector availableOutputDevices = getApmObserver()->getAvailableOutputDevices();
    const SwAudioOutputCollection &outputs = getApmObserver()->getOutputs();
    //
    // @TODO: what is the priority of explicit routing? Shall it be considered first as it used to
    // be by APM?
    //
    // Honor explicit routing requests only if all active clients have a preferred route in which
    // case the last active client route is used
    sp<DeviceDescriptor> device = findPreferredDevice(outputs, strategy, availableOutputDevices);
    if (device != nullptr) {
        return DeviceVector(device);
    }
    return fromCache? getCachedDevices(strategy) : getDevicesForProductStrategy(strategy);
}

DeviceVector Engine::getCachedDevices(product_strategy_t ps) const
{
    return mDevicesForStrategies.find(ps) != mDevicesForStrategies.end() ?
                mDevicesForStrategies.at(ps) : DeviceVector{};
}

DeviceVector Engine::getOutputDevicesForStream(audio_stream_type_t stream, bool fromCache) const
{
    auto attributes = EngineBase::getAttributesForStreamType(stream);
    return getOutputDevicesForAttributes(attributes, nullptr, fromCache);
}

sp<DeviceDescriptor> Engine::getInputDeviceForAttributes(const audio_attributes_t &attr,
                                                         uid_t uid,
                                                         audio_session_t session,
                                                         sp<AudioPolicyMix> *mix) const
{
    const auto &policyMixes = getApmObserver()->getAudioPolicyMixCollection();
    const auto availableInputDevices = getApmObserver()->getAvailableInputDevices();
    const auto &inputs = getApmObserver()->getInputs();
    std::string address;
    //
    // Explicit Routing ??? what is the priority of explicit routing? Shall it be considered
    // first as it used to be by APM?
    //
    // Honor explicit routing requests only if all active clients have a preferred route in which
    // case the last active client route is used
    sp<DeviceDescriptor> device =
            findPreferredDevice(inputs, attr.source, availableInputDevices);
    if (device != nullptr) {
        return device;
    }

    device = policyMixes.getDeviceAndMixForInputSource(attr,
                                                       availableInputDevices,
                                                       uid,
                                                       session,
                                                       mix);
    if (device != nullptr) {
        return device;
    }

    audio_devices_t deviceType = getPropertyForKey<audio_devices_t, audio_source_t>(attr.source);

    if (audio_is_remote_submix_device(deviceType)) {
        address = "0";
        std::size_t pos;
        std::string tags { attr.tags };
        if ((pos = tags.find("addr=")) != std::string::npos) {
            address = tags.substr(pos + std::strlen("addr="));
        }
    }
    return availableInputDevices.getDevice(deviceType, String8(address.c_str()), AUDIO_FORMAT_DEFAULT);
}

void Engine::setDeviceAddressForProductStrategy(product_strategy_t strategy,
                                                const std::string &address)
{
    if (getProductStrategies().find(strategy) == getProductStrategies().end()) {
        ALOGE("%s: Trying to set address %s on invalid strategy %d", __FUNCTION__, address.c_str(),
              strategy);
        return;
    }
    getProductStrategies().at(strategy)->setDeviceAddress(address);
}

bool Engine::setDeviceTypesForProductStrategy(product_strategy_t strategy, uint64_t devices)
{
    if (getProductStrategies().find(strategy) == getProductStrategies().end()) {
        ALOGE("%s: set device %" PRId64 " on invalid strategy %d", __FUNCTION__, devices, strategy);
        return false;
    }
    // Here device matches the criterion value, need to rebuitd android device types;
    DeviceTypeSet types =
            mPolicyParameterMgr->convertDeviceCriterionValueToDeviceTypes(devices, true /*isOut*/);
    getProductStrategies().at(strategy)->setDeviceTypes(types);
    return true;
}

bool Engine::setDeviceForInputSource(const audio_source_t &inputSource, uint64_t device)
{
    DeviceTypeSet types = mPolicyParameterMgr->convertDeviceCriterionValueToDeviceTypes(
                device, false /*isOut*/);
    ALOG_ASSERT(types.size() <= 1, "one input device expected at most");
    audio_devices_t deviceType = types.empty() ? AUDIO_DEVICE_IN_DEFAULT : *types.begin();
    return setPropertyForKey<audio_devices_t, audio_source_t>(deviceType, inputSource);
}

template <>
EngineInterface *Engine::queryInterface()
{
    return this;
}

template <>
AudioPolicyPluginInterface *Engine::queryInterface()
{
    return this;
}

} // namespace audio_policy
} // namespace android
