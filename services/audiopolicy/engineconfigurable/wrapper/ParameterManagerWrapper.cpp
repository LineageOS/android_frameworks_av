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

#define LOG_TAG "APM::AudioPolicyEngine/PFWWrapper"
//#define LOG_NDEBUG 0

#include "ParameterManagerWrapper.h"
#include <ParameterMgrPlatformConnector.h>
#include <SelectionCriterionTypeInterface.h>
#include <SelectionCriterionInterface.h>
#include <media/convert.h>
#include <algorithm>
#include <cutils/bitops.h>
#include <cutils/config_utils.h>
#include <cutils/misc.h>
#include <fstream>
#include <limits>
#include <sstream>
#include <string>
#include <vector>
#include <stdint.h>
#include <cinttypes>
#include <cmath>
#include <utils/Log.h>

using std::string;
using std::map;
using std::vector;

/// PFW related definitions
// Logger
class ParameterMgrPlatformConnectorLogger : public CParameterMgrPlatformConnector::ILogger
{
public:
    ParameterMgrPlatformConnectorLogger() {}

    virtual void info(const string &log)
    {
        ALOGV("policy-parameter-manager: %s", log.c_str());
    }
    virtual void warning(const string &log)
    {
        ALOGW("policy-parameter-manager: %s", log.c_str());
    }
};

namespace android {

using utilities::convertTo;

namespace audio_policy {

const char *const ParameterManagerWrapper::mPolicyPfwDefaultConfFileName =
    "/etc/parameter-framework/ParameterFrameworkConfigurationPolicy.xml";
const char *const ParameterManagerWrapper::mPolicyPfwVendorConfFileName =
    "/vendor/etc/parameter-framework/ParameterFrameworkConfigurationPolicy.xml";

static const char *const gInputDeviceCriterionName = "AvailableInputDevices";
static const char *const gOutputDeviceCriterionName = "AvailableOutputDevices";
static const char *const gPhoneStateCriterionName = "TelephonyMode";
static const char *const gOutputDeviceAddressCriterionName = "AvailableOutputDevicesAddresses";
static const char *const gInputDeviceAddressCriterionName = "AvailableInputDevicesAddresses";

/**
 * Order MUST be align with defintiion of audio_policy_force_use_t within audio_policy.h
 */
static const char *const gForceUseCriterionTag[AUDIO_POLICY_FORCE_USE_CNT] =
{
    [AUDIO_POLICY_FORCE_FOR_COMMUNICATION] =        "ForceUseForCommunication",
    [AUDIO_POLICY_FORCE_FOR_MEDIA] =                "ForceUseForMedia",
    [AUDIO_POLICY_FORCE_FOR_RECORD] =               "ForceUseForRecord",
    [AUDIO_POLICY_FORCE_FOR_DOCK] =                 "ForceUseForDock",
    [AUDIO_POLICY_FORCE_FOR_SYSTEM] =               "ForceUseForSystem",
    [AUDIO_POLICY_FORCE_FOR_HDMI_SYSTEM_AUDIO] =    "ForceUseForHdmiSystemAudio",
    [AUDIO_POLICY_FORCE_FOR_ENCODED_SURROUND] =     "ForceUseForEncodedSurround",
    [AUDIO_POLICY_FORCE_FOR_VIBRATE_RINGING] =      "ForceUseForVibrateRinging"
};

template <>
struct ParameterManagerWrapper::parameterManagerElementSupported<ISelectionCriterionInterface> {};
template <>
struct ParameterManagerWrapper::parameterManagerElementSupported<ISelectionCriterionTypeInterface> {};

ParameterManagerWrapper::ParameterManagerWrapper(bool enableSchemaVerification,
                                                 const std::string &schemaUri)
    : mPfwConnectorLogger(new ParameterMgrPlatformConnectorLogger)
{
    // Connector
    if (access(mPolicyPfwVendorConfFileName, R_OK) == 0) {
        mPfwConnector = new CParameterMgrPlatformConnector(mPolicyPfwVendorConfFileName);
    } else {
        mPfwConnector = new CParameterMgrPlatformConnector(mPolicyPfwDefaultConfFileName);
    }

    // Logger
    mPfwConnector->setLogger(mPfwConnectorLogger);

    // Schema validation
    std::string error;
    bool ret = mPfwConnector->setValidateSchemasOnStart(enableSchemaVerification, error);
    ALOGE_IF(!ret, "Failed to activate schema validation: %s", error.c_str());
    if (enableSchemaVerification && ret && !schemaUri.empty()) {
        ALOGE("Schema verification activated with schema URI: %s", schemaUri.c_str());
        mPfwConnector->setSchemaUri(schemaUri);
    }
}

status_t ParameterManagerWrapper::addCriterion(const std::string &name, bool isInclusive,
                                               ValuePairs pairs, const std::string &defaultValue)
{
    ALOG_ASSERT(not isStarted(), "Cannot add a criterion if PFW is already started");
    auto criterionType = mPfwConnector->createSelectionCriterionType(isInclusive);

    for (auto pair : pairs) {
        std::string error;
        ALOGV("%s: Adding pair %" PRIu64", %s for criterionType %s", __func__, std::get<0>(pair),
              std::get<2>(pair).c_str(), name.c_str());
        criterionType->addValuePair(std::get<0>(pair), std::get<2>(pair), error);

        if (name == gOutputDeviceCriterionName) {
            ALOGV("%s: Adding mOutputDeviceToCriterionTypeMap %d %" PRIu64" for criterionType %s",
                  __func__, std::get<1>(pair), std::get<0>(pair), name.c_str());
            audio_devices_t androidType = static_cast<audio_devices_t>(std::get<1>(pair));
            mOutputDeviceToCriterionTypeMap[androidType] = std::get<0>(pair);
        }
        if (name == gInputDeviceCriterionName) {
            ALOGV("%s: Adding mInputDeviceToCriterionTypeMap %d %" PRIu64" for criterionType %s",
                  __func__, std::get<1>(pair), std::get<0>(pair), name.c_str());
            audio_devices_t androidType = static_cast<audio_devices_t>(std::get<1>(pair));
            mInputDeviceToCriterionTypeMap[androidType] = std::get<0>(pair);
        }
    }
    ALOG_ASSERT(mPolicyCriteria.find(name) == mPolicyCriteria.end(),
                "%s: Criterion %s already added", __FUNCTION__, name.c_str());

    auto criterion = mPfwConnector->createSelectionCriterion(name, criterionType);
    mPolicyCriteria[name] = criterion;

    if (not defaultValue.empty()) {
        uint64_t numericalValue = 0;
        if (not criterionType->getNumericalValue(defaultValue.c_str(), numericalValue)) {
            ALOGE("%s; trying to apply invalid default literal value (%s)", __FUNCTION__,
                  defaultValue.c_str());
        }
        criterion->setCriterionState(numericalValue);
    }
    return NO_ERROR;
}

ParameterManagerWrapper::~ParameterManagerWrapper()
{
    // Unset logger
    mPfwConnector->setLogger(NULL);
    // Remove logger
    delete mPfwConnectorLogger;
    // Remove connector
    delete mPfwConnector;
}

status_t ParameterManagerWrapper::start(std::string &error)
{
    ALOGD("%s: in", __FUNCTION__);
    /// Start PFW
    if (!mPfwConnector->start(error)) {
        ALOGE("%s: Policy PFW start error: %s", __FUNCTION__, error.c_str());
        return NO_INIT;
    }
    ALOGD("%s: Policy PFW successfully started!", __FUNCTION__);
    return NO_ERROR;
}

template <typename T>
T *ParameterManagerWrapper::getElement(const string &name, std::map<string, T *> &elementsMap)
{
    parameterManagerElementSupported<T>();
    typename std::map<string, T *>::iterator it = elementsMap.find(name);
    ALOG_ASSERT(it != elementsMap.end(), "Element %s not found", name.c_str());
    return it != elementsMap.end() ? it->second : NULL;
}

template <typename T>
const T *ParameterManagerWrapper::getElement(const string &name, const std::map<string, T *> &elementsMap) const
{
    parameterManagerElementSupported<T>();
    typename std::map<string, T *>::const_iterator it = elementsMap.find(name);
    ALOG_ASSERT(it != elementsMap.end(), "Element %s not found", name.c_str());
    return it != elementsMap.end() ? it->second : NULL;
}

bool ParameterManagerWrapper::isStarted()
{
    return mPfwConnector && mPfwConnector->isStarted();
}

status_t ParameterManagerWrapper::setPhoneState(audio_mode_t mode)
{
    ISelectionCriterionInterface *criterion =
            getElement<ISelectionCriterionInterface>(gPhoneStateCriterionName, mPolicyCriteria);
    if (criterion == NULL) {
        ALOGE("%s: no criterion found for %s", __FUNCTION__, gPhoneStateCriterionName);
        return BAD_VALUE;
    }
    if (!isValueValidForCriterion(criterion, static_cast<int>(mode))) {
        return BAD_VALUE;
    }
    criterion->setCriterionState((int)(mode));
    applyPlatformConfiguration();
    return NO_ERROR;
}

audio_mode_t ParameterManagerWrapper::getPhoneState() const
{
    const ISelectionCriterionInterface *criterion =
            getElement<ISelectionCriterionInterface>(gPhoneStateCriterionName, mPolicyCriteria);
    if (criterion == NULL) {
        ALOGE("%s: no criterion found for %s", __FUNCTION__, gPhoneStateCriterionName);
        return AUDIO_MODE_NORMAL;
    }
    return static_cast<audio_mode_t>(criterion->getCriterionState());
}

status_t ParameterManagerWrapper::setForceUse(audio_policy_force_use_t usage,
                                              audio_policy_forced_cfg_t config)
{
    // @todo: return an error on a unsupported value
    if (usage > AUDIO_POLICY_FORCE_USE_CNT) {
        return BAD_VALUE;
    }

    ISelectionCriterionInterface *criterion =
            getElement<ISelectionCriterionInterface>(gForceUseCriterionTag[usage], mPolicyCriteria);
    if (criterion == NULL) {
        ALOGE("%s: no criterion found for %s", __FUNCTION__, gForceUseCriterionTag[usage]);
        return BAD_VALUE;
    }
    if (!isValueValidForCriterion(criterion, static_cast<int>(config))) {
        return BAD_VALUE;
    }
    criterion->setCriterionState((int)config);
    applyPlatformConfiguration();
    return NO_ERROR;
}

audio_policy_forced_cfg_t ParameterManagerWrapper::getForceUse(audio_policy_force_use_t usage) const
{
    // @todo: return an error on a unsupported value
    if (usage > AUDIO_POLICY_FORCE_USE_CNT) {
        return AUDIO_POLICY_FORCE_NONE;
    }
    const ISelectionCriterionInterface *criterion =
            getElement<ISelectionCriterionInterface>(gForceUseCriterionTag[usage], mPolicyCriteria);
    if (criterion == NULL) {
        ALOGE("%s: no criterion found for %s", __FUNCTION__, gForceUseCriterionTag[usage]);
        return AUDIO_POLICY_FORCE_NONE;
    }
    return static_cast<audio_policy_forced_cfg_t>(criterion->getCriterionState());
}

bool ParameterManagerWrapper::isValueValidForCriterion(ISelectionCriterionInterface *criterion,
                                                       int valueToCheck)
{
    const ISelectionCriterionTypeInterface *interface = criterion->getCriterionType();
    string literalValue;
    return interface->getLiteralValue(valueToCheck, literalValue);
}

status_t ParameterManagerWrapper::setDeviceConnectionState(
        audio_devices_t type, const std::string &address, audio_policy_dev_state_t state)
{
    std::string criterionName = audio_is_output_device(type) ?
                gOutputDeviceAddressCriterionName : gInputDeviceAddressCriterionName;

    ALOGV("%s: device with address %s %s", __FUNCTION__, address.c_str(),
          state != AUDIO_POLICY_DEVICE_STATE_AVAILABLE? "disconnected" : "connected");
    ISelectionCriterionInterface *criterion =
            getElement<ISelectionCriterionInterface>(criterionName, mPolicyCriteria);

    if (criterion == NULL) {
        ALOGE("%s: no criterion found for %s", __FUNCTION__, criterionName.c_str());
        return DEAD_OBJECT;
    }

    auto criterionType = criterion->getCriterionType();
    uint64_t deviceAddressId;
    if (not criterionType->getNumericalValue(address.c_str(), deviceAddressId)) {
        ALOGW("%s: unknown device address reported (%s) for criterion %s", __FUNCTION__,
              address.c_str(), criterionName.c_str());
        return BAD_TYPE;
    }
    int currentValueMask = criterion->getCriterionState();
    if (state == AUDIO_POLICY_DEVICE_STATE_AVAILABLE) {
        currentValueMask |= deviceAddressId;
    }
    else {
        currentValueMask &= ~deviceAddressId;
    }
    criterion->setCriterionState(currentValueMask);
    return NO_ERROR;
}

status_t ParameterManagerWrapper::setAvailableInputDevices(const DeviceTypeSet &types)
{
    ISelectionCriterionInterface *criterion =
            getElement<ISelectionCriterionInterface>(gInputDeviceCriterionName, mPolicyCriteria);
    if (criterion == NULL) {
        ALOGE("%s: no criterion found for %s", __func__, gInputDeviceCriterionName);
        return DEAD_OBJECT;
    }
    criterion->setCriterionState(convertDeviceTypesToCriterionValue(types));
    applyPlatformConfiguration();
    return NO_ERROR;
}

status_t ParameterManagerWrapper::setAvailableOutputDevices(const DeviceTypeSet &types)
{
    ISelectionCriterionInterface *criterion =
            getElement<ISelectionCriterionInterface>(gOutputDeviceCriterionName, mPolicyCriteria);
    if (criterion == NULL) {
        ALOGE("%s: no criterion found for %s", __func__, gOutputDeviceCriterionName);
        return DEAD_OBJECT;
    }
    criterion->setCriterionState(convertDeviceTypesToCriterionValue(types));
    applyPlatformConfiguration();
    return NO_ERROR;
}

void ParameterManagerWrapper::applyPlatformConfiguration()
{
    mPfwConnector->applyConfigurations();
}

uint64_t ParameterManagerWrapper::convertDeviceTypeToCriterionValue(audio_devices_t type) const {
    bool isOut = audio_is_output_devices(type);
    uint32_t typeMask = isOut ? type : (type & ~AUDIO_DEVICE_BIT_IN);

    const auto &adapters = isOut ? mOutputDeviceToCriterionTypeMap : mInputDeviceToCriterionTypeMap;
    // Only multibit devices need adaptation.
    if (popcount(typeMask) > 1) {
        const auto &adapter = adapters.find(type);
        if (adapter != adapters.end()) {
            ALOGV("%s: multibit device %d converted to criterion %" PRIu64, __func__, type,
                  adapter->second);
            return adapter->second;
        }
        ALOGE("%s: failed to find map for multibit device %d", __func__, type);
        return 0;
    }
    return typeMask;
}

uint64_t ParameterManagerWrapper::convertDeviceTypesToCriterionValue(
        const DeviceTypeSet &types) const {
    uint64_t criterionValue = 0;
    for (const auto &type : types) {
        criterionValue += convertDeviceTypeToCriterionValue(type);
    }
    return criterionValue;
}

DeviceTypeSet ParameterManagerWrapper::convertDeviceCriterionValueToDeviceTypes(
        uint64_t criterionValue, bool isOut) const {
    DeviceTypeSet deviceTypes;
    const auto &adapters = isOut ? mOutputDeviceToCriterionTypeMap : mInputDeviceToCriterionTypeMap;
    for (const auto &adapter : adapters) {
        if ((adapter.second & criterionValue) == adapter.second) {
            deviceTypes.insert(adapter.first);
        }
    }
    return deviceTypes;
}

} // namespace audio_policy
} // namespace android
