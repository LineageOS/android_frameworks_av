/*
 * Copyright (C) 2016 The Android Open Source Project
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

#define LOG_TAG "EffectsFactoryHalHidl"
//#define LOG_NDEBUG 0

#include "EffectHalHidl.h"
#include "EffectsFactoryHalHidl.h"

using ::android::hardware::Return;

using namespace ::android::hardware::audio::effect;

namespace android {

// static
sp<EffectsFactoryHalInterface> EffectsFactoryHalInterface::create() {
    if (V2_0::IEffectsFactory::getService() != nullptr) {
        return new EffectsFactoryHalHidl();
    }
    return nullptr;
}

// static
bool EffectsFactoryHalInterface::isNullUuid(const effect_uuid_t *pEffectUuid) {
    return memcmp(pEffectUuid, EFFECT_UUID_NULL, sizeof(effect_uuid_t)) == 0;
}

} // namespace android
