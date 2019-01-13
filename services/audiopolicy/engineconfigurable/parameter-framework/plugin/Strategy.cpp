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

#include "Strategy.h"
#include "PolicyMappingKeys.h"
#include "PolicySubsystem.h"
#include <RoutingStrategy.h>

using std::string;
using android::routing_strategy;

namespace detail {

constexpr std::pair<routing_strategy, const char*> routingStrategyMap[] = {
    {android::STRATEGY_MEDIA, "STRATEGY_MEDIA"},
    {android::STRATEGY_PHONE, "STRATEGY_PHONE"},
    {android::STRATEGY_SONIFICATION, "STRATEGY_SONIFICATION"},
    {android::STRATEGY_SONIFICATION_RESPECTFUL, "STRATEGY_SONIFICATION_RESPECTFUL"},
    {android::STRATEGY_DTMF, "STRATEGY_DTMF"},
    {android::STRATEGY_ENFORCED_AUDIBLE, "STRATEGY_ENFORCED_AUDIBLE"},
    {android::STRATEGY_TRANSMITTED_THROUGH_SPEAKER, "STRATEGY_TRANSMITTED_THROUGH_SPEAKER"},
    {android::STRATEGY_ACCESSIBILITY, "STRATEGY_ACCESSIBILITY"},
    {android::STRATEGY_REROUTING, "STRATEGY_REROUTING"},
};

bool fromString(const char *literalName, routing_strategy &type)
{
    for (auto& pair : routingStrategyMap) {
        if (strcmp(pair.second, literalName) == 0) {
            type = pair.first;
            return true;
        }
    }
    return false;
}

}

Strategy::Strategy(const string &mappingValue,
                   CInstanceConfigurableElement *instanceConfigurableElement,
                   const CMappingContext &context,
                   core::log::Logger& logger)
    : CFormattedSubsystemObject(instanceConfigurableElement,
                                logger,
                                mappingValue,
                                MappingKeyAmend1,
                                (MappingKeyAmendEnd - MappingKeyAmend1 + 1),
                                context),
      mPolicySubsystem(static_cast<const PolicySubsystem *>(
                           instanceConfigurableElement->getBelongingSubsystem())),
      mPolicyPluginInterface(mPolicySubsystem->getPolicyPluginInterface())
{
    std::string name(context.getItem(MappingKeyName));
    if (not detail::fromString(name.c_str(), mId)) {
        LOG_ALWAYS_FATAL("Invalid Strategy %s, invalid XML structure file", name.c_str());
    }
    // Declares the strategy to audio policy engine
    mPolicyPluginInterface->addStrategy(instanceConfigurableElement->getName(), mId);
}

bool Strategy::sendToHW(string & /*error*/)
{
    uint32_t applicableOutputDevice;
    blackboardRead(&applicableOutputDevice, sizeof(applicableOutputDevice));
    return mPolicyPluginInterface->setDeviceForStrategy(mId, applicableOutputDevice);
}
