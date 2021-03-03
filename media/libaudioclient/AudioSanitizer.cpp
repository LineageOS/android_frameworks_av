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

#include <media/AudioSanitizer.h>

namespace android {

    /** returns true if string overflow was prevented by zero termination */
template <size_t size>
bool preventStringOverflow(char (&s)[size]) {
    if (strnlen(s, size) < size) return false;
    s[size - 1] = '\0';
    return true;
}

status_t safetyNetLog(status_t status, const char *bugNumber) {
    if (status != NO_ERROR && bugNumber != nullptr) {
        android_errorWriteLog(0x534e4554, bugNumber); // SafetyNet logging
    }
    return status;
}

status_t AudioSanitizer::sanitizeAudioAttributes(
        audio_attributes_t *attr, const char *bugNumber)
{
    status_t status = NO_ERROR;
    const size_t tagsMaxSize = AUDIO_ATTRIBUTES_TAGS_MAX_SIZE;
    if (strnlen(attr->tags, tagsMaxSize) >= tagsMaxSize) {
        status = BAD_VALUE;
    }
    attr->tags[tagsMaxSize - 1] = '\0';
    return safetyNetLog(status, bugNumber);
}

/** returns BAD_VALUE if sanitization was required. */
status_t AudioSanitizer::sanitizeEffectDescriptor(
        effect_descriptor_t *desc, const char *bugNumber)
{
    status_t status = NO_ERROR;
    if (preventStringOverflow(desc->name)
        | /* always */ preventStringOverflow(desc->implementor)) {
        status = BAD_VALUE;
    }
    return safetyNetLog(status, bugNumber);
}

/** returns BAD_VALUE if sanitization was required. */
status_t AudioSanitizer::sanitizeAudioPortConfig(
        struct audio_port_config *config, const char *bugNumber)
{
    status_t status = NO_ERROR;
    if (config->type == AUDIO_PORT_TYPE_DEVICE &&
        preventStringOverflow(config->ext.device.address)) {
        status = BAD_VALUE;
    }
    return safetyNetLog(status, bugNumber);
}

/** returns BAD_VALUE if sanitization was required. */
status_t AudioSanitizer::sanitizeAudioPort(
        struct audio_port *port, const char *bugNumber)
{
    status_t status = NO_ERROR;
    if (preventStringOverflow(port->name)) {
        status = BAD_VALUE;
    }
    if (sanitizeAudioPortConfig(&port->active_config) != NO_ERROR) {
        status = BAD_VALUE;
    }
    if (port->type == AUDIO_PORT_TYPE_DEVICE &&
        preventStringOverflow(port->ext.device.address)) {
        status = BAD_VALUE;
    }
    return safetyNetLog(status, bugNumber);
}

/** returns BAD_VALUE if sanitization was required. */
status_t AudioSanitizer::sanitizeAudioPatch(
        struct audio_patch *patch, const char *bugNumber)
{
    status_t status = NO_ERROR;
    if (patch->num_sources > AUDIO_PATCH_PORTS_MAX) {
        patch->num_sources = AUDIO_PATCH_PORTS_MAX;
        status = BAD_VALUE;
    }
    if (patch->num_sinks > AUDIO_PATCH_PORTS_MAX) {
        patch->num_sinks = AUDIO_PATCH_PORTS_MAX;
        status = BAD_VALUE;
    }
    for (size_t i = 0; i < patch->num_sources; i++) {
        if (sanitizeAudioPortConfig(&patch->sources[i]) != NO_ERROR) {
            status = BAD_VALUE;
        }
    }
    for (size_t i = 0; i < patch->num_sinks; i++) {
        if (sanitizeAudioPortConfig(&patch->sinks[i]) != NO_ERROR) {
            status = BAD_VALUE;
        }
    }
    return safetyNetLog(status, bugNumber);
}

}; // namespace android
