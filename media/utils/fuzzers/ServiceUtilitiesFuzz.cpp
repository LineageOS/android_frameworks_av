/*
 * Copyright 2020 The Android Open Source Project
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

#include <fcntl.h>

#include <functional>
#include  <type_traits>

#include <android/content/AttributionSourceState.h>
#include "fuzzer/FuzzedDataProvider.h"
#include "mediautils/ServiceUtilities.h"

static constexpr int kMaxStringLen = 256;

using android::content::AttributionSourceState;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    FuzzedDataProvider data_provider(data, size);
    int32_t uid = data_provider.ConsumeIntegral<int32_t>();
    int32_t pid = data_provider.ConsumeIntegral<int32_t>();
    audio_source_t source = static_cast<audio_source_t>(data_provider
        .ConsumeIntegral<std::underlying_type_t<audio_source_t>>());
    uint32_t deviceId = data_provider.ConsumeIntegral<uint32_t>();

    std::string packageNameStr = data_provider.ConsumeRandomLengthString(kMaxStringLen);
    std::string msgStr = data_provider.ConsumeRandomLengthString(kMaxStringLen);
    android::String16 msgStr16(packageNameStr.c_str());
    AttributionSourceState attributionSource;
    attributionSource.packageName = packageNameStr;
    attributionSource.uid = uid;
    attributionSource.pid = pid;
    attributionSource.token = android::sp<android::BBinder>::make();

    // There is not state here, and order is not significant,
    // so we can simply call all of the target functions
    android::isServiceUid(uid);
    android::isAudioServerUid(uid);
    android::isAudioServerOrSystemServerUid(uid);
    android::isAudioServerOrMediaServerUid(uid);
    android::recordingAllowed(attributionSource);
    android::recordingAllowed(attributionSource, deviceId, source);
    android::startRecording(attributionSource, deviceId, msgStr16, source);
    android::finishRecording(attributionSource, deviceId, source);
    android::captureAudioOutputAllowed(attributionSource);
    android::modifyPhoneStateAllowed(attributionSource);
    android::bypassInterruptionPolicyAllowed(attributionSource);
    android::modifyAudioRoutingAllowed();
    android::modifyDefaultAudioEffectsAllowed();
    android::dumpAllowed();
    return 0;
}
