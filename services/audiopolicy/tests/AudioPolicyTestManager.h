/*
 * Copyright (C) 2017 The Android Open Source Project
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

#include "managerdefault/AudioPolicyManager.h"

namespace android {

class AudioPolicyTestManager : public AudioPolicyManager {
  public:
    explicit AudioPolicyTestManager(AudioPolicyClientInterface *clientInterface)
            : AudioPolicyTestManager(AudioPolicyConfig::createDefault(), clientInterface) {}
    AudioPolicyTestManager(const sp<const AudioPolicyConfig>& config,
            AudioPolicyClientInterface *clientInterface)
            : AudioPolicyManager(config,
                    loadApmEngineLibraryAndCreateEngine(config->getEngineLibraryNameSuffix()),
                    clientInterface) {}
    using AudioPolicyManager::getConfig;
    using AudioPolicyManager::initialize;
    using AudioPolicyManager::getOutputs;
    using AudioPolicyManager::getInputs;
    using AudioPolicyManager::getAvailableOutputDevices;
    using AudioPolicyManager::getAvailableInputDevices;
    using AudioPolicyManager::setSurroundFormatEnabled;
    using AudioPolicyManager::releaseMsdOutputPatches;
    using AudioPolicyManager::setMsdOutputPatches;
    using AudioPolicyManager::getAudioPatches;
    using AudioPolicyManager::getDirectPlaybackSupport;
    using AudioPolicyManager::getDirectProfilesForAttributes;
    using AudioPolicyManager::setDeviceConnectionState;
    using AudioPolicyManager::deviceToAudioPort;
    using AudioPolicyManager::handleDeviceConfigChange;
    uint32_t getAudioPortGeneration() const { return mAudioPortGeneration; }
};

}  // namespace android
