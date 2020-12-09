/*
 * Copyright (C) 2020 The Android Open Source Project
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

#ifndef ANDROID_AUDIO_SANITIZER_H_
#define ANDROID_AUDIO_SANITIZER_H_

#include <system/audio.h>
#include <system/audio_effect.h>
#include <utils/Errors.h>
#include <utils/Log.h>

namespace android {

class AudioSanitizer {
public:
    static status_t sanitizeAudioAttributes(
            audio_attributes_t *attr, const char *bugNumber = nullptr);

    static status_t sanitizeEffectDescriptor(
            effect_descriptor_t *desc, const char *bugNumber = nullptr);

    static status_t sanitizeAudioPortConfig(
            struct audio_port_config *config, const char *bugNumber = nullptr);

    static status_t sanitizeAudioPort(
            struct audio_port *port, const char *bugNumber = nullptr);

    static status_t sanitizeAudioPatch(
            struct audio_patch *patch, const char *bugNumber = nullptr);
};

}; // namespace android

#endif  /*ANDROID_AUDIO_SANITIZER_H_*/
