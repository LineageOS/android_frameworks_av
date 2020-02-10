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

#include <media/audiohal/EffectsFactoryHalInterface.h>
#include <media/audiohal/FactoryHalHidl.h>

namespace android {

// static
sp<EffectsFactoryHalInterface> EffectsFactoryHalInterface::create() {
    return createPreferredImpl<EffectsFactoryHalInterface>(
            "android.hardware.audio.effect", "IEffectsFactory");
}

// static
bool EffectsFactoryHalInterface::isNullUuid(const effect_uuid_t *pEffectUuid) {
    return memcmp(pEffectUuid, EFFECT_UUID_NULL, sizeof(effect_uuid_t)) == 0;
}

} // namespace android
