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

#include <unordered_set>

#include <gtest/gtest.h>

#include <media/AudioSystem.h>
#include <system/audio.h>
#include <utils/Log.h>

#include "AudioPolicyManagerTestClient.h"
#include "AudioPolicyTestManager.h"

using namespace android;

TEST(AudioHealthTest, AttachedDeviceFound) {
    unsigned int numPorts;
    unsigned int generation1;
    unsigned int generation;
    struct audio_port *audioPorts = NULL;
    int attempts = 10;
    do {
        if (attempts-- < 0) {
            free(audioPorts);
            GTEST_FAIL() << "Query audio ports time out";
        }
        numPorts = 0;
        ASSERT_EQ(NO_ERROR, AudioSystem::listAudioPorts(
                AUDIO_PORT_ROLE_NONE, AUDIO_PORT_TYPE_DEVICE, &numPorts, NULL, &generation1));
        if (numPorts == 0) {
            free(audioPorts);
            GTEST_FAIL() << "Number of audio ports should not be zero";
        }

        audioPorts = (struct audio_port *)realloc(audioPorts, numPorts * sizeof(struct audio_port));
        status_t status = AudioSystem::listAudioPorts(
                AUDIO_PORT_ROLE_NONE, AUDIO_PORT_TYPE_DEVICE, &numPorts, audioPorts, &generation);
        if (status != NO_ERROR) {
            free(audioPorts);
            GTEST_FAIL() << "Query audio ports failed";
        }
    } while (generation1 != generation);
    std::unordered_set<audio_devices_t> attachedDevices;
    for (int i = 0 ; i < numPorts; i++) {
        attachedDevices.insert(audioPorts[i].ext.device.type);
    }
    free(audioPorts);

    AudioPolicyManagerTestClient client;
    AudioPolicyTestManager manager(&client);
    manager.loadConfig();
    ASSERT_NE("AudioPolicyConfig::setDefault", manager.getConfig().getSource());

    for (auto desc : manager.getConfig().getInputDevices()) {
        ASSERT_NE(attachedDevices.end(), attachedDevices.find(desc->type()));
    }
    for (auto desc : manager.getConfig().getOutputDevices()) {
        ASSERT_NE(attachedDevices.end(), attachedDevices.find(desc->type()));
    }
}
