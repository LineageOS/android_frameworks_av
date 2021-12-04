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

#define LOG_TAG "APM::AudioCollections"
//#define LOG_NDEBUG 0

#include <android-base/stringprintf.h>

#include "AudioCollections.h"
#include "AudioRoute.h"
#include "HwModule.h"
#include "PolicyAudioPort.h"

namespace android {

sp<PolicyAudioPort> findByTagName(const PolicyAudioPortVector& policyAudioPortVector,
                                  const std::string &tagName)
{
    for (const auto& port : policyAudioPortVector) {
        if (port->getTagName() == tagName) {
            return port;
        }
    }
    return nullptr;
}

void dumpAudioRouteVector(const AudioRouteVector& audioRouteVector, String8 *dst, int spaces)
{
    if (audioRouteVector.isEmpty()) {
        return;
    }
    dst->appendFormat("%*s- Audio Routes (%zu):\n", spaces - 2, "", audioRouteVector.size());
    for (size_t i = 0; i < audioRouteVector.size(); i++) {
        const std::string prefix = base::StringPrintf("%*s %zu. ", spaces, "", i + 1);
        dst->append(prefix.c_str());
        audioRouteVector.itemAt(i)->dump(dst, prefix.size());
    }
}

} // namespace android
