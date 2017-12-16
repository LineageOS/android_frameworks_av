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

#include <gtest/gtest.h>

#include "AudioPolicyTestClient.h"
#include "AudioPolicyTestManager.h"

using namespace android;

TEST(AudioPolicyManager, InitFailure) {
    AudioPolicyTestClient client;
    AudioPolicyTestManager manager(&client);
    manager.getConfig().setDefault();
    // Since the default client fails to open anything,
    // APM should indicate that the initialization didn't succeed.
    ASSERT_EQ(NO_INIT, manager.initialize());
    ASSERT_EQ(NO_INIT, manager.initCheck());
}


// A client that provides correct module and IO handles for inputs and outputs.
class AudioPolicyTestClientWithModulesIoHandles : public AudioPolicyTestClient {
  public:
    audio_module_handle_t loadHwModule(const char* /*name*/) override {
        return mNextModule++;
    }
    status_t openOutput(audio_module_handle_t module,
                        audio_io_handle_t* output,
                        audio_config_t* /*config*/,
                        audio_devices_t* /*devices*/,
                        const String8& /*address*/,
                        uint32_t* /*latencyMs*/,
                        audio_output_flags_t /*flags*/) override {
        if (module >= mNextModule) {
            ALOGE("%s: Module handle %d has not been allocated yet (next is %d)",
                    __func__, module, mNextModule);
            return BAD_VALUE;
        }
        *output = mNextIoHandle++;
        return NO_ERROR;
    }
    status_t openInput(audio_module_handle_t module,
                       audio_io_handle_t* input,
                       audio_config_t* /*config*/,
                       audio_devices_t* /*device*/,
                       const String8& /*address*/,
                       audio_source_t /*source*/,
                       audio_input_flags_t /*flags*/) override {
        if (module >= mNextModule) {
            ALOGE("%s: Module handle %d has not been allocated yet (next is %d)",
                    __func__, module, mNextModule);
            return BAD_VALUE;
        }
        *input = mNextIoHandle++;
        return NO_ERROR;
    }
  private:
    audio_module_handle_t mNextModule = AUDIO_MODULE_HANDLE_NONE + 1;
    audio_io_handle_t mNextIoHandle = AUDIO_IO_HANDLE_NONE + 1;
};

TEST(AudioPolicyManager, InitSuccess) {
    AudioPolicyTestClientWithModulesIoHandles client;
    AudioPolicyTestManager manager(&client);
    manager.getConfig().setDefault();
    ASSERT_EQ(NO_ERROR, manager.initialize());
    ASSERT_EQ(NO_ERROR, manager.initCheck());
}
