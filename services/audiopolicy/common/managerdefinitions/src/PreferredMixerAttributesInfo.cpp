/*
 * Copyright (C) 2022 The Android Open Source Project
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

#include "PreferredMixerAttributesInfo.h"

namespace android {

void PreferredMixerAttributesInfo::dump(String8 *dst) {
    dst->appendFormat("device port ID: %d; owner uid: %d; profile name: %s; flags: %#x; "
                      "sample rate: %u; channel mask: %#x; format: %#x; mixer behavior: %d; "
                      "active clients count: %d\n",
                      mDevicePortId, mUid, mProfile->getName().c_str(), mOutputFlags,
                      mMixerAttributes.config.sample_rate, mMixerAttributes.config.channel_mask,
                      mMixerAttributes.config.format, mMixerAttributes.mixer_behavior,
                      mActiveClientsCount);
}

} // namespace android