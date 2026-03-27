/*
 * Copyright (C) 2019 The Android Open Source Project
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

#define LOG_TAG "AudioPolicy_Boot_Test"

#include <string>
#include <unordered_set>

#include <gtest/gtest.h>

#include <AudioPolicyConfig.h>
#include <media/AudioSystem.h>
#include <media/TypeConverter.h>
#include <system/audio.h>
#include <utils/Log.h>

#include "AudioPolicyManagerTestClient.h"
#include "AudioPolicyTestManager.h"

using namespace android;

TEST(AudioHealthTest, AttachedDeviceFound) {
    unsigned int generation;
    std::vector<audio_port_v7> audioPorts;
    ASSERT_EQ(NO_ERROR, AudioSystem::listAudioPorts(
            AUDIO_PORT_ROLE_NONE, AUDIO_PORT_TYPE_DEVICE, audioPorts, &generation));

    std::unordered_set<audio_devices_t> attachedDevices;
    for (const auto& port : audioPorts) {
        attachedDevices.insert(port.ext.device.type);
    }

    auto config = AudioPolicyConfig::loadFromApmXmlConfigWithFallback();
    ASSERT_NE(AudioPolicyConfig::kDefaultConfigSource, config->getSource());

    for (const auto& desc : config->getInputDevices()) {
        if (attachedDevices.find(desc->type()) == attachedDevices.end()) {
            std::string deviceType;
            (void)DeviceConverter::toString(desc->type(), deviceType);
            ADD_FAILURE() << "Input device \"" << deviceType << "\" not found";
        }
    }
    for (const auto& desc : config->getOutputDevices()) {
        if (attachedDevices.find(desc->type()) == attachedDevices.end()) {
            std::string deviceType;
            (void)DeviceConverter::toString(desc->type(), deviceType);
            ADD_FAILURE() << "Output device \"" << deviceType << "\" not found";
        }
    }
}

TEST(AudioHealthTest, ConnectSupportedDevice) {
    auto config = AudioPolicyConfig::loadFromApmXmlConfigWithFallback();
    ASSERT_NE(AudioPolicyConfig::kDefaultConfigSource, config->getSource());
    AudioPolicyManagerTestClient client;
    AudioPolicyTestManager manager(config, &client);

    DeviceVector devices;
    for (const auto& hwModule : config->getHwModules()) {
        for (const auto& profile : hwModule->getOutputProfiles()) {
            devices.merge(profile->getSupportedDevices());
        }
        for (const auto& profile : hwModule->getInputProfiles()) {
            devices.merge(profile->getSupportedDevices());
        }
    }
    for (const auto& device : devices) {
        if (!audio_is_bluetooth_out_sco_device(device->type()) &&
            !audio_is_bluetooth_in_sco_device(device->type())) {
            // There are two reasons to only test connecting BT devices.
            // 1) It is easier to construct a fake address.
            // 2) This test will be run in presubmit. In that case, it makes sense to make the test
            //    processing time short.
            continue;
        }
        std::string address = "11:22:33:44:55:66";
        media::AudioPortFw aidlPort;
        ASSERT_EQ(OK, manager.deviceToAudioPort(device->type(), address.c_str(), "" /*name*/,
                                                 &aidlPort));
        ASSERT_EQ(AUDIO_POLICY_DEVICE_STATE_UNAVAILABLE,
                AudioSystem::getDeviceConnectionState(device->type(), address.c_str()));
        ASSERT_EQ(NO_ERROR, AudioSystem::setDeviceConnectionState(
                AUDIO_POLICY_DEVICE_STATE_AVAILABLE, aidlPort.hal, AUDIO_FORMAT_DEFAULT, false));
        ASSERT_EQ(AUDIO_POLICY_DEVICE_STATE_AVAILABLE,
                AudioSystem::getDeviceConnectionState(device->type(), address.c_str()));
        ASSERT_EQ(NO_ERROR, AudioSystem::setDeviceConnectionState(
                AUDIO_POLICY_DEVICE_STATE_UNAVAILABLE, aidlPort.hal, AUDIO_FORMAT_DEFAULT, false));
        ASSERT_EQ(AUDIO_POLICY_DEVICE_STATE_UNAVAILABLE,
                AudioSystem::getDeviceConnectionState(device->type(), address.c_str()));
    }
}
