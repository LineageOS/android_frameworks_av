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
#include <ParameterMgrFullConnector.h>
#include <ParameterMgrPlatformConnector.h>
#include <SelectionCriterionTypeInterface.h>
#include <SelectionCriterionInterface.h>
#include <media/convert.h>
#include <algorithm>
#include <cutils/bitops.h>
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

#ifdef ENABLE_CAP_AIDL_HYBRID_MODE
// Legacy XML from vendor partition used when disabling AIDL CAP configuration (HIDL or Hybrid)
const char *const ParameterManagerWrapper::mVendorPolicyPfwConfFileName =
    "/vendor/etc/parameter-framework/ParameterFrameworkConfigurationPolicy.xml";
#endif
const char *const ParameterManagerWrapper::mPolicyPfwConfFileName =
    "/etc/parameter-framework/ParameterFrameworkConfigurationCap.xml";

template <>
struct ParameterManagerWrapper::parameterManagerElementSupported<ISelectionCriterionInterface> {};
template <>
struct ParameterManagerWrapper::parameterManagerElementSupported<ISelectionCriterionTypeInterface> {};

ParameterManagerWrapper::ParameterManagerWrapper(bool useLegacyConfigurationFile,
        bool enableSchemaVerification, const std::string &schemaUri)
    : mPfwConnectorLogger(new ParameterMgrPlatformConnectorLogger)
{
    std::string policyPfwConfFileName;
#ifdef ENABLE_CAP_AIDL_HYBRID_MODE
    // Connector
    if (useLegacyConfigurationFile && access(mVendorPolicyPfwConfFileName, R_OK) == 0) {
        policyPfwConfFileName = mVendorPolicyPfwConfFileName;
    }
#endif
    if (!useLegacyConfigurationFile && access(mPolicyPfwConfFileName, R_OK) == 0) {
        policyPfwConfFileName = mPolicyPfwConfFileName;
    }
    if (policyPfwConfFileName.empty()) {
        // bailing out
        ALOGE("%s: failed to find Cap config file, cannot init Cap.", __func__);
        return;
    }
    mPfwConnector = new CParameterMgrFullConnector(policyPfwConfFileName);
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
    if (mPfwConnector == nullptr) {
        ALOGE("%s: failed, Cap not initialized", __func__);
        return NO_INIT;
    }
    ALOG_ASSERT(not isStarted(), "%s failed since PFW is already started", __func__);
    auto criterionType = mPfwConnector->createSelectionCriterionType(isInclusive);

    for (auto pair : pairs) {
        std::string error;
        ALOGV("%s: Adding pair %" PRIu64", %s for criterionType %s", __func__, std::get<0>(pair),
              std::get<2>(pair).c_str(), name.c_str());
        criterionType->addValuePair(std::get<0>(pair), std::get<2>(pair), error);

        if (name == capEngineConfig::gOutputDeviceCriterionName) {
            ALOGV("%s: Adding mOutputDeviceToCriterionTypeMap 0x%X %" PRIu64" for criterionType %s",
                  __func__, std::get<1>(pair), std::get<0>(pair), name.c_str());
            audio_devices_t androidType = static_cast<audio_devices_t>(std::get<1>(pair));
            mOutputDeviceToCriterionTypeMap[androidType] = std::get<0>(pair);
        }
        if (name == capEngineConfig::gInputDeviceCriterionName) {
            ALOGV("%s: Adding mInputDeviceToCriterionTypeMap 0x%X %" PRIu64" for criterionType %s",
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
    if (mPfwConnector != nullptr) {
        mPfwConnector->setLogger(NULL);
    }
    // Remove logger
    delete mPfwConnectorLogger;
    // Remove connector
    delete mPfwConnector;
}

status_t ParameterManagerWrapper::start(std::string &error)
{
    ALOGD("%s: in", __FUNCTION__);
    /// Start PFW
    if (mPfwConnector == nullptr || !mPfwConnector->start(error)) {
        ALOGE("%s: Policy PFW failed (error:  %s)", __func__,
              mPfwConnector == nullptr ? "invalid connector" : error.c_str());
        return NO_INIT;
    }
    ALOGD("%s: Policy PFW succeeded!", __FUNCTION__);
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

bool ParameterManagerWrapper::isStarted() const
{
    return mPfwConnector && mPfwConnector->isStarted();
}

status_t ParameterManagerWrapper::setPhoneState(audio_mode_t mode)
{
    if (!isStarted()) {
        ALOGE("%s: failed, Cap not initialized", __func__);
        return NO_INIT;
    }
    ISelectionCriterionInterface *criterion = getElement<ISelectionCriterionInterface>(
            capEngineConfig::gPhoneStateCriterionName, mPolicyCriteria);
    if (criterion == NULL) {
        ALOGW("%s: no criterion found for %s", __FUNCTION__,
              capEngineConfig::gPhoneStateCriterionName);
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
    if (!isStarted()) {
        ALOGE("%s: failed, Cap not initialized", __func__);
        return AUDIO_MODE_NORMAL;
    }
    const ISelectionCriterionInterface *criterion = getElement<ISelectionCriterionInterface>(
            capEngineConfig::gPhoneStateCriterionName, mPolicyCriteria);
    if (criterion == NULL) {
        ALOGD("%s: no criterion found for %s", __func__, capEngineConfig::gPhoneStateCriterionName);
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
    if (!isStarted()) {
        ALOGE("%s: failed, Cap not initialized", __func__);
        return NO_INIT;
    }
    ISelectionCriterionInterface *criterion = getElement<ISelectionCriterionInterface>(
            capEngineConfig::gForceUseCriterionTag[usage], mPolicyCriteria);
    if (criterion == NULL) {
        ALOGW("%s: no criterion found for %s", __func__,
              capEngineConfig::gForceUseCriterionTag[usage]);
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
    if (!isStarted()) {
        ALOGE("%s: failed, Cap not initialized", __func__);
        return AUDIO_POLICY_FORCE_NONE;
    }
    const ISelectionCriterionInterface *criterion = getElement<ISelectionCriterionInterface>(
            capEngineConfig::gForceUseCriterionTag[usage], mPolicyCriteria);
    if (criterion == NULL) {
        ALOGD("%s: no criterion found for %s", __func__,
              capEngineConfig::gForceUseCriterionTag[usage]);
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
    if (!isStarted()) {
        ALOGE("%s: failed, Cap not initialized", __func__);
        return NO_INIT;
    }
    std::string criterionName = audio_is_output_device(type) ?
            capEngineConfig::gOutputDeviceAddressCriterionName :
            capEngineConfig::gInputDeviceAddressCriterionName;
    ALOGV("%s: device with address %s %s", __FUNCTION__, address.c_str(),
          state != AUDIO_POLICY_DEVICE_STATE_AVAILABLE? "disconnected" : "connected");
    ISelectionCriterionInterface *criterion =
            getElement<ISelectionCriterionInterface>(criterionName, mPolicyCriteria);

    if (criterion == NULL) {
        ALOGW("%s: no criterion found for %s", __func__, criterionName.c_str());
        return DEAD_OBJECT;
    }

    auto criterionType = criterion->getCriterionType();
    uint64_t deviceAddressId;
    if (not criterionType->getNumericalValue(address.c_str(), deviceAddressId)) {
        ALOGW("%s: unknown device address reported (%s) for criterion %s", __func__,
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

status_t ParameterManagerWrapper::setAvailableInputDevices(const DeviceTypeSet &types) {
    if (!isStarted()) {
        ALOGE("%s: failed, Cap not initialized", __func__);
        return NO_INIT;
    }
    ISelectionCriterionInterface *criterion = getElement<ISelectionCriterionInterface>(
            capEngineConfig::gInputDeviceCriterionName, mPolicyCriteria);
    if (criterion == NULL) {
        ALOGE("%s: no criterion found for %s", __func__,
              capEngineConfig::gInputDeviceCriterionName);
        return DEAD_OBJECT;
    }
    criterion->setCriterionState(convertDeviceTypesToCriterionValue(types));
    applyPlatformConfiguration();
    return NO_ERROR;
}

status_t ParameterManagerWrapper::setAvailableOutputDevices(const DeviceTypeSet &types) {
    if (!isStarted()) {
        ALOGE("%s: failed, Cap not initialized", __func__);
        return NO_INIT;
    }
    ISelectionCriterionInterface *criterion = getElement<ISelectionCriterionInterface>(
            capEngineConfig::gOutputDeviceCriterionName, mPolicyCriteria);
    if (criterion == NULL) {
        ALOGE("%s: no criterion found for %s", __func__,
              capEngineConfig::gOutputDeviceCriterionName);
        return DEAD_OBJECT;
    }
    criterion->setCriterionState(convertDeviceTypesToCriterionValue(types));
    applyPlatformConfiguration();
    return NO_ERROR;
}

void ParameterManagerWrapper::applyPlatformConfiguration()
{
    if (!isStarted()) {
        ALOGE("%s: failed, Cap not initialized", __func__);
        return;
    }
    mPfwConnector->applyConfigurations();
}

uint64_t ParameterManagerWrapper::convertDeviceTypeToCriterionValue(audio_devices_t type) const {
    bool isOut = audio_is_output_devices(type);
    const auto &adapters = isOut ? mOutputDeviceToCriterionTypeMap : mInputDeviceToCriterionTypeMap;
    const auto &adapter = adapters.find(type);
    if (adapter != adapters.end()) {
        ALOGV("%s: multibit device %d converted to criterion %" PRIu64, __func__, type,
              adapter->second);
        return adapter->second;
    }
    ALOGE("%s: failed to find map for multibit device %d", __func__, type);
    return 0;
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

void ParameterManagerWrapper::createDomain(const std::string &domain)
{
    if (!isStarted()) {
        ALOGE("%s: failed, Cap not initialized", __func__);
        return;
    }
    std::string error;
    bool ret = mPfwConnector->createDomain(domain, error);
    if (!ret) {
        ALOGD("%s: failed for %s (error=%s)", __func__, domain.c_str(),
        error.c_str());
    }
}

void ParameterManagerWrapper::addConfigurableElementToDomain(const std::string &domain,
        const std::string &elementPath)
{
    if (!isStarted()) {
        ALOGE("%s: failed, Cap not initialized", __func__);
        return;
    }
    std::string error;
    bool ret = mPfwConnector->addConfigurableElementToDomain(domain, elementPath, error);
    ALOGE_IF(!ret, "%s: failed for %s for domain %s (error=%s)",
              __func__, elementPath.c_str(), domain.c_str(), error.c_str());
}

void ParameterManagerWrapper::createConfiguration(const std::string &domain,
        const std::string &configurationName)
{
    if (!isStarted()) {
        ALOGE("%s: failed, Cap not initialized", __func__);
        return;
    }
    std::string error;
    bool ret = mPfwConnector->createConfiguration(domain, configurationName, error);
    ALOGE_IF(!ret, "%s: failed for %s for domain %s (error=%s)",
              __func__, configurationName.c_str(), domain.c_str(), error.c_str());
}

void ParameterManagerWrapper::setApplicationRule(
        const std::string &domain, const std::string &configurationName, const std::string &rule)
{
    if (!isStarted()) {
        ALOGE("%s: failed, Cap not initialized", __func__);
        return;
    }
    std::string error;
    bool ret = mPfwConnector->setApplicationRule(domain, configurationName, rule, error);
    ALOGE_IF(!ret, "%s: failed for %s for domain %s and configuration %s (error=%s)",
              __func__, rule.c_str(), domain.c_str(), configurationName.c_str(), error.c_str());
}

void ParameterManagerWrapper::accessConfigurationValue(const std::string &domain,
        const std::string &configurationName, const std::string &elementPath,
        std::string &value)
{
    if (!isStarted()) {
        ALOGE("%s: failed, Cap not initialized", __func__);
        return;
    }
    std::string error;
    bool ret = mPfwConnector->accessConfigurationValue(domain, configurationName, elementPath,
            value, /*set=*/ true, error);
    ALOGE_IF(!ret, "%s: failed to set value %s for parameter %s on domain %s and configuration %s "
          "(error=%s)", __func__, value.c_str(), elementPath.c_str(),  domain.c_str(),
          configurationName.c_str(), error.c_str());
}

status_t ParameterManagerWrapper::setConfiguration(
        const android::capEngineConfig::ParsingResult& capSettings)
{
    if (!isStarted()) {
        return NO_INIT;
    }
    std::string error;
    if (!mPfwConnector->setTuningMode(/* bOn= */ true, error)) {
        ALOGD("%s: failed (error=%s)", __func__, error.c_str());
        return DEAD_OBJECT;
    }
    for (auto &domain: capSettings.parsedConfig->capConfigurableDomains) {
        createDomain(domain.name);
        for (const auto &configurableElementValue : domain.settings[0].configurableElementValues) {
            addConfigurableElementToDomain(domain.name,
                    configurableElementValue.configurableElement.path);
        }
        for (const auto &configuration : domain.configurations) {
            createConfiguration(domain.name, configuration.name);
            setApplicationRule(domain.name, configuration.name, configuration.rule);
        }
        for (const auto &setting : domain.settings) {
            for (const auto &configurableElementValue : setting.configurableElementValues) {
                std::string value = configurableElementValue.value;
                accessConfigurationValue(domain.name, setting.configurationName,
                        configurableElementValue.configurableElement.path, value);
            }

        }
    }
    mPfwConnector->setTuningMode(/* bOn= */ false, error);
    return OK;
}

} // namespace audio_policy
} // namespace android
