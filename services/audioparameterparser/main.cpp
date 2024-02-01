/*
 * Copyright (C) 2024 The Android Open Source Project
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

#define LOG_TAG "Audio_ParameterParser"
#include <android-base/logging.h>
#include <android/binder_manager.h>
#include <android/binder_process.h>

#include "ParameterParser.h"

using vendor::audio::parserservice::ParameterParser;

int main() {
    // This is a debug implementation, always enable debug logging.
    android::base::SetMinimumLogSeverity(::android::base::DEBUG);

    auto parser = ndk::SharedRefBase::make<ParameterParser>();
    const std::string parserFqn =
            std::string().append(ParameterParser::descriptor).append("/default");
    binder_status_t status =
            AServiceManager_addService(parser->asBinder().get(), parserFqn.c_str());
    if (status != STATUS_OK) {
        LOG(ERROR) << "failed to register service for \"" << parserFqn << "\"";
    }

    ABinderProcess_joinThreadPool();
    return EXIT_FAILURE;  // should not reach
}
