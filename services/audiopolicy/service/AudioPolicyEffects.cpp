/*
 * Copyright (C) 2014 The Android Open Source Project
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

#define LOG_TAG "AudioPolicyEffects"
//#define LOG_NDEBUG 0

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <memory>
#include <cutils/misc.h>
#include <media/AudioEffect.h>
#include <media/EffectsConfig.h>
#include <mediautils/ServiceUtilities.h>
#include <system/audio.h>
#include <system/audio_effects/audio_effects_conf.h>
#include <utils/Vector.h>
#include <utils/SortedVector.h>
#include <cutils/config_utils.h>
#include <binder/IPCThreadState.h>
#include "AudioPolicyEffects.h"

namespace android {

using content::AttributionSourceState;

// ----------------------------------------------------------------------------
// AudioPolicyEffects Implementation
// ----------------------------------------------------------------------------

AudioPolicyEffects::AudioPolicyEffects(const sp<EffectsFactoryHalInterface>& effectsFactoryHal) {
    // Note: clang thread-safety permits the ctor to call guarded _l methods without
    // acquiring the associated mutex capability as standard practice is to assume
    // single threaded construction and destruction.

    // load xml config with effectsFactoryHal
    status_t loadResult = loadAudioEffectConfig_ll(effectsFactoryHal);
    if (loadResult < 0) {
        ALOGW("Failed to query effect configuration, fallback to load .conf");
        // load automatic audio effect modules
        if (access(AUDIO_EFFECT_VENDOR_CONFIG_FILE, R_OK) == 0) {
            loadAudioEffectConfigLegacy_l(AUDIO_EFFECT_VENDOR_CONFIG_FILE);
        } else if (access(AUDIO_EFFECT_DEFAULT_CONFIG_FILE, R_OK) == 0) {
            loadAudioEffectConfigLegacy_l(AUDIO_EFFECT_DEFAULT_CONFIG_FILE);
        }
    } else if (loadResult > 0) {
        ALOGE("Effect config is partially invalid, skipped %d elements", loadResult);
    }
}

status_t AudioPolicyEffects::addInputEffects(audio_io_handle_t input,
                             audio_source_t inputSource,
                             audio_session_t audioSession)
{
    status_t status = NO_ERROR;

    // create audio pre processors according to input source
    audio_source_t aliasSource = (inputSource == AUDIO_SOURCE_HOTWORD) ?
                                    AUDIO_SOURCE_VOICE_RECOGNITION : inputSource;

    audio_utils::lock_guard _l(mMutex);
    auto sourceIt = mInputSources.find(aliasSource);
    if (sourceIt == mInputSources.end()) {
        ALOGV("addInputEffects(): no processing needs to be attached to this source");
        return status;
    }
    std::shared_ptr<EffectVector>& sessionDesc = mInputSessions[audioSession];
    if (sessionDesc == nullptr) {
        sessionDesc = std::make_shared<EffectVector>(audioSession);
    }
    sessionDesc->mRefCount++;

    ALOGV("addInputEffects(): input: %d, refCount: %d", input, sessionDesc->mRefCount);
    if (sessionDesc->mRefCount == 1) {
        int64_t token = IPCThreadState::self()->clearCallingIdentity();
        const std::shared_ptr<EffectDescVector>& effects = sourceIt->second;
        for (const std::shared_ptr<EffectDesc>& effect : *effects) {
            AttributionSourceState attributionSource;
            attributionSource.packageName = "android";
            attributionSource.token = sp<BBinder>::make();
            auto fx = sp<AudioEffect>::make(attributionSource);
            fx->set(nullptr /*type */, &effect->mUuid, -1 /* priority */, nullptr /* callback */,
                    audioSession, input);
            status_t status = fx->initCheck();
            if (status != NO_ERROR && status != ALREADY_EXISTS) {
                ALOGW("addInputEffects(): failed to create Fx %s on source %d",
                      effect->mName.c_str(), (int32_t)aliasSource);
                // fx goes out of scope and strong ref on AudioEffect is released
                continue;
            }
            for (size_t j = 0; j < effect->mParams.size(); j++) {
                // const_cast here due to API.
                fx->setParameter(const_cast<effect_param_t*>(effect->mParams[j].get()));
            }
            ALOGV("addInputEffects(): added Fx %s on source: %d",
                  effect->mName.c_str(), (int32_t)aliasSource);
            sessionDesc->mEffects.push_back(std::move(fx));
        }
        sessionDesc->setProcessorEnabled(true);
        IPCThreadState::self()->restoreCallingIdentity(token);
    }
    return status;
}


status_t AudioPolicyEffects::releaseInputEffects(audio_io_handle_t input,
                                                 audio_session_t audioSession)
{
    status_t status = NO_ERROR;

    audio_utils::lock_guard _l(mMutex);
    auto it = mInputSessions.find(audioSession);
    if (it == mInputSessions.end()) {
        return status;
    }
    std::shared_ptr<EffectVector> sessionDesc = it->second;
    sessionDesc->mRefCount--;
    ALOGV("releaseInputEffects(): input: %d, refCount: %d", input, sessionDesc->mRefCount);
    if (sessionDesc->mRefCount == 0) {
        sessionDesc->setProcessorEnabled(false);
        mInputSessions.erase(it);
        ALOGV("releaseInputEffects(): all effects released");
    }
    return status;
}

status_t AudioPolicyEffects::queryDefaultInputEffects(audio_session_t audioSession,
                                                      effect_descriptor_t *descriptors,
                                                      uint32_t *count)
{
    status_t status = NO_ERROR;

    audio_utils::lock_guard _l(mMutex);
    auto it = mInputSessions.find(audioSession);
    if (it == mInputSessions.end()) {
        *count = 0;
        return BAD_VALUE;
    }
    const std::vector<sp<AudioEffect>>& effects = it->second->mEffects;
    const size_t copysize = std::min(effects.size(), (size_t)*count);
    for (size_t i = 0; i < copysize; i++) {
        descriptors[i] = effects[i]->descriptor();
    }
    if (effects.size() > *count) {
        status = NO_MEMORY;
    }
    *count = effects.size();
    return status;
}


status_t AudioPolicyEffects::queryDefaultOutputSessionEffects(audio_session_t audioSession,
                         effect_descriptor_t *descriptors,
                         uint32_t *count)
{
    status_t status = NO_ERROR;

    audio_utils::lock_guard _l(mMutex);
    auto it = mOutputSessions.find(audioSession);
    if (it == mOutputSessions.end()) {
        *count = 0;
        return BAD_VALUE;
    }
    const std::vector<sp<AudioEffect>>& effects = it->second->mEffects;
    const size_t copysize = std::min(effects.size(), (size_t)*count);
    for (size_t i = 0; i < copysize; i++) {
        descriptors[i] = effects[i]->descriptor();
    }
    if (effects.size() > *count) {
        status = NO_MEMORY;
    }
    *count = effects.size();
    return status;
}


status_t AudioPolicyEffects::addOutputSessionEffects(audio_io_handle_t output,
                         audio_stream_type_t stream,
                         audio_session_t audioSession)
{
    status_t status = NO_ERROR;

    audio_utils::lock_guard _l(mMutex);
    // create audio processors according to stream
    // FIXME: should we have specific post processing settings for internal streams?
    // default to media for now.
    if (stream >= AUDIO_STREAM_PUBLIC_CNT) {
        stream = AUDIO_STREAM_MUSIC;
    }
    auto it = mOutputStreams.find(stream);
    if (it == mOutputStreams.end()) {
        ALOGV("addOutputSessionEffects(): no output processing needed for this stream");
        return NO_ERROR;
    }

    std::shared_ptr<EffectVector>& procDesc = mOutputSessions[audioSession];
    if (procDesc == nullptr) {
        procDesc = std::make_shared<EffectVector>(audioSession);
    }
    procDesc->mRefCount++;

    ALOGV("addOutputSessionEffects(): session: %d, refCount: %d",
          audioSession, procDesc->mRefCount);
    if (procDesc->mRefCount == 1) {
        // make sure effects are associated to audio server even if we are executing a binder call
        int64_t token = IPCThreadState::self()->clearCallingIdentity();
        const std::shared_ptr<EffectDescVector>& effects = it->second;
        for (const std::shared_ptr<EffectDesc>& effect : *effects) {
            AttributionSourceState attributionSource;
            attributionSource.packageName = "android";
            attributionSource.token = sp<BBinder>::make();
            auto fx = sp<AudioEffect>::make(attributionSource);
            fx->set(nullptr /* type */, &effect->mUuid, 0 /* priority */, nullptr /* callback */,
                    audioSession, output);
            status_t status = fx->initCheck();
            if (status != NO_ERROR && status != ALREADY_EXISTS) {
                ALOGE("addOutputSessionEffects(): failed to create Fx  %s on session %d",
                      effect->mName.c_str(), audioSession);
                // fx goes out of scope and strong ref on AudioEffect is released
                continue;
            }
            ALOGV("addOutputSessionEffects(): added Fx %s on session: %d for stream: %d",
                  effect->mName.c_str(), audioSession, (int32_t)stream);
            procDesc->mEffects.push_back(std::move(fx));
        }

        procDesc->setProcessorEnabled(true);
        IPCThreadState::self()->restoreCallingIdentity(token);
    }
    return status;
}

status_t AudioPolicyEffects::releaseOutputSessionEffects(audio_io_handle_t output,
                         audio_stream_type_t stream,
                         audio_session_t audioSession)
{
    (void) output; // argument not used for now
    (void) stream; // argument not used for now

    audio_utils::lock_guard _l(mMutex);
    auto it = mOutputSessions.find(audioSession);
    if (it == mOutputSessions.end()) {
        ALOGV("releaseOutputSessionEffects: no output processing was attached to this stream");
        return NO_ERROR;
    }

    std::shared_ptr<EffectVector> procDesc = it->second;
    procDesc->mRefCount--;
    ALOGV("releaseOutputSessionEffects(): session: %d, refCount: %d",
          audioSession, procDesc->mRefCount);
    if (procDesc->mRefCount == 0) {
        procDesc->setProcessorEnabled(false);
        procDesc->mEffects.clear();
        mOutputSessions.erase(it);
        ALOGV("releaseOutputSessionEffects(): output processing released from session: %d",
              audioSession);
    }
    return NO_ERROR;
}

status_t AudioPolicyEffects::addSourceDefaultEffect(const effect_uuid_t *type,
                                                    const String16& opPackageName,
                                                    const effect_uuid_t *uuid,
                                                    int32_t priority,
                                                    audio_source_t source,
                                                    audio_unique_id_t* id)
{
    if (uuid == NULL || type == NULL) {
        ALOGE("addSourceDefaultEffect(): Null uuid or type uuid pointer");
        return BAD_VALUE;
    }

    // HOTWORD, FM_TUNER and ECHO_REFERENCE are special case sources > MAX.
    if (source < AUDIO_SOURCE_DEFAULT ||
            (source > AUDIO_SOURCE_MAX &&
             source != AUDIO_SOURCE_HOTWORD &&
             source != AUDIO_SOURCE_FM_TUNER &&
             source != AUDIO_SOURCE_ECHO_REFERENCE &&
             source != AUDIO_SOURCE_ULTRASOUND)) {
        ALOGE("addSourceDefaultEffect(): Unsupported source type %d", source);
        return BAD_VALUE;
    }

    // Check that |uuid| or |type| corresponds to an effect on the system.
    effect_descriptor_t descriptor = {};
    status_t res = AudioEffect::getEffectDescriptor(
            uuid, type, EFFECT_FLAG_TYPE_PRE_PROC, &descriptor);
    if (res != OK) {
        ALOGE("addSourceDefaultEffect(): Failed to find effect descriptor matching uuid/type.");
        return res;
    }

    // Only pre-processing effects can be added dynamically as source defaults.
    if ((descriptor.flags & EFFECT_FLAG_TYPE_MASK) != EFFECT_FLAG_TYPE_PRE_PROC) {
        ALOGE("addSourceDefaultEffect(): Desired effect cannot be attached "
              "as a source default effect.");
        return BAD_VALUE;
    }

    audio_utils::lock_guard _l(mMutex);

    // Find the EffectDescVector for the given source type, or create a new one if necessary.
    std::shared_ptr<EffectDescVector>& desc = mInputSources[source];
    if (desc == nullptr) {
        desc = std::make_shared<EffectDescVector>();
    }

    // Create a new effect and add it to the vector.
    res = AudioEffect::newEffectUniqueId(id);
    if (res != OK) {
        ALOGE("addSourceDefaultEffect(): failed to get new unique id.");
        return res;
    }
    std::shared_ptr<EffectDesc> effect = std::make_shared<EffectDesc>(
            descriptor.name, descriptor.type, opPackageName, descriptor.uuid, priority, *id);
    desc->push_back(std::move(effect));
    // TODO(b/71813697): Support setting params as well.

    // TODO(b/71814300): Retroactively attach to any existing sources of the given type.
    // This requires tracking the source type of each session id in addition to what is
    // already being tracked.

    return NO_ERROR;
}

status_t AudioPolicyEffects::addStreamDefaultEffect(const effect_uuid_t *type,
                                                    const String16& opPackageName,
                                                    const effect_uuid_t *uuid,
                                                    int32_t priority,
                                                    audio_usage_t usage,
                                                    audio_unique_id_t* id)
{
    if (uuid == NULL || type == NULL) {
        ALOGE("addStreamDefaultEffect(): Null uuid or type uuid pointer");
        return BAD_VALUE;
    }
    audio_stream_type_t stream = AudioSystem::attributesToStreamType(attributes_initializer(usage));

    if (stream < AUDIO_STREAM_MIN || stream >= AUDIO_STREAM_PUBLIC_CNT) {
        ALOGE("addStreamDefaultEffect(): Unsupported stream type %d", stream);
        return BAD_VALUE;
    }

    // Check that |uuid| or |type| corresponds to an effect on the system.
    effect_descriptor_t descriptor = {};
    status_t res = AudioEffect::getEffectDescriptor(
            uuid, type, EFFECT_FLAG_TYPE_INSERT, &descriptor);
    if (res != OK) {
        ALOGE("addStreamDefaultEffect(): Failed to find effect descriptor matching uuid/type.");
        return res;
    }

    // Only insert effects can be added dynamically as stream defaults.
    if ((descriptor.flags & EFFECT_FLAG_TYPE_MASK) != EFFECT_FLAG_TYPE_INSERT) {
        ALOGE("addStreamDefaultEffect(): Desired effect cannot be attached "
              "as a stream default effect.");
        return BAD_VALUE;
    }

    audio_utils::lock_guard _l(mMutex);

    // Find the EffectDescVector for the given stream type, or create a new one if necessary.
    std::shared_ptr<EffectDescVector>& desc = mOutputStreams[stream];
    if (desc == nullptr) {
        // No effects for this stream type yet.
        desc = std::make_shared<EffectDescVector>();
    }

    // Create a new effect and add it to the vector.
    res = AudioEffect::newEffectUniqueId(id);
    if (res != OK) {
        ALOGE("addStreamDefaultEffect(): failed to get new unique id.");
        return res;
    }
    std::shared_ptr<EffectDesc> effect = std::make_shared<EffectDesc>(
            descriptor.name, descriptor.type, opPackageName, descriptor.uuid, priority, *id);
    desc->push_back(std::move(effect));
    // TODO(b/71813697): Support setting params as well.

    // TODO(b/71814300): Retroactively attach to any existing streams of the given type.
    // This requires tracking the stream type of each session id in addition to what is
    // already being tracked.

    return NO_ERROR;
}

status_t AudioPolicyEffects::removeSourceDefaultEffect(audio_unique_id_t id)
{
    if (id == AUDIO_UNIQUE_ID_ALLOCATE) {
        // ALLOCATE is not a unique identifier, but rather a reserved value indicating
        // a real id has not been assigned. For default effects, this value is only used
        // by system-owned defaults from the loaded config, which cannot be removed.
        return BAD_VALUE;
    }

    audio_utils::lock_guard _l(mMutex);

    // Check each source type.
    for (auto& [source, descVector] : mInputSources) {
        // Check each effect for each source.
        for (auto desc = descVector->begin(); desc != descVector->end(); ++desc) {
            if ((*desc)->mId == id) {
                // Found it!
                // TODO(b/71814300): Remove from any sources the effect was attached to.
                descVector->erase(desc);
                // Handles are unique; there can only be one match, so return early.
                return NO_ERROR;
            }
        }
    }

    // Effect wasn't found, so it's been trivially removed successfully.
    return NO_ERROR;
}

status_t AudioPolicyEffects::removeStreamDefaultEffect(audio_unique_id_t id)
{
    if (id == AUDIO_UNIQUE_ID_ALLOCATE) {
        // ALLOCATE is not a unique identifier, but rather a reserved value indicating
        // a real id has not been assigned. For default effects, this value is only used
        // by system-owned defaults from the loaded config, which cannot be removed.
        return BAD_VALUE;
    }

    audio_utils::lock_guard _l(mMutex);

    // Check each stream type.
    for (auto& [stream, descVector] : mOutputStreams) {
        // Check each effect for each stream.
        for (auto desc = descVector->begin(); desc != descVector->end(); ++desc) {
            if ((*desc)->mId == id) {
                // Found it!
                // TODO(b/71814300): Remove from any streams the effect was attached to.
                descVector->erase(desc);
                // Handles are unique; there can only be one match, so return early.
                return NO_ERROR;
            }
        }
    }

    // Effect wasn't found, so it's been trivially removed successfully.
    return NO_ERROR;
}

void AudioPolicyEffects::EffectVector::setProcessorEnabled(bool enabled)
{
    for (const auto& effect : mEffects) {
        effect->setEnabled(enabled);
    }
}


// ----------------------------------------------------------------------------
// Audio processing configuration
// ----------------------------------------------------------------------------

// we keep to const char* instead of std::string_view as comparison is believed faster.
constexpr const char* kInputSourceNames[AUDIO_SOURCE_CNT - 1] = {
    MIC_SRC_TAG,
    VOICE_UL_SRC_TAG,
    VOICE_DL_SRC_TAG,
    VOICE_CALL_SRC_TAG,
    CAMCORDER_SRC_TAG,
    VOICE_REC_SRC_TAG,
    VOICE_COMM_SRC_TAG,
    REMOTE_SUBMIX_SRC_TAG,
    UNPROCESSED_SRC_TAG,
    VOICE_PERFORMANCE_SRC_TAG
};

// returns the audio_source_t enum corresponding to the input source name or
// AUDIO_SOURCE_CNT is no match found
/*static*/ audio_source_t AudioPolicyEffects::inputSourceNameToEnum(const char *name)
{
    int i;
    for (i = AUDIO_SOURCE_MIC; i < AUDIO_SOURCE_CNT; i++) {
        if (strcmp(name, kInputSourceNames[i - AUDIO_SOURCE_MIC]) == 0) {
            ALOGV("inputSourceNameToEnum found source %s %d", name, i);
            break;
        }
    }
    return (audio_source_t)i;
}

// +1 as enum starts from -1
constexpr const char* kStreamNames[AUDIO_STREAM_PUBLIC_CNT + 1] = {
    AUDIO_STREAM_DEFAULT_TAG,
    AUDIO_STREAM_VOICE_CALL_TAG,
    AUDIO_STREAM_SYSTEM_TAG,
    AUDIO_STREAM_RING_TAG,
    AUDIO_STREAM_MUSIC_TAG,
    AUDIO_STREAM_ALARM_TAG,
    AUDIO_STREAM_NOTIFICATION_TAG,
    AUDIO_STREAM_BLUETOOTH_SCO_TAG,
    AUDIO_STREAM_ENFORCED_AUDIBLE_TAG,
    AUDIO_STREAM_DTMF_TAG,
    AUDIO_STREAM_TTS_TAG,
    AUDIO_STREAM_ASSISTANT_TAG
};

// returns the audio_stream_t enum corresponding to the output stream name or
// AUDIO_STREAM_PUBLIC_CNT is no match found
/* static */
audio_stream_type_t AudioPolicyEffects::streamNameToEnum(const char *name)
{
    int i;
    for (i = AUDIO_STREAM_DEFAULT; i < AUDIO_STREAM_PUBLIC_CNT; i++) {
        if (strcmp(name, kStreamNames[i - AUDIO_STREAM_DEFAULT]) == 0) {
            ALOGV("streamNameToEnum found stream %s %d", name, i);
            break;
        }
    }
    return (audio_stream_type_t)i;
}

// ----------------------------------------------------------------------------
// Audio Effect Config parser
// ----------------------------------------------------------------------------

/* static */
size_t AudioPolicyEffects::growParamSize(char **param,
                                         size_t size,
                                         size_t *curSize,
                                         size_t *totSize)
{
    // *curSize is at least sizeof(effect_param_t) + 2 * sizeof(int)
    size_t pos = ((*curSize - 1 ) / size + 1) * size;

    if (pos + size > *totSize) {
        while (pos + size > *totSize) {
            *totSize += ((*totSize + 7) / 8) * 4;
        }
        char *newParam = (char *)realloc(*param, *totSize);
        if (newParam == NULL) {
            ALOGE("%s realloc error for size %zu", __func__, *totSize);
            return 0;
        }
        *param = newParam;
    }
    *curSize = pos + size;
    return pos;
}

/* static */
size_t AudioPolicyEffects::readParamValue(cnode *node,
                                          char **param,
                                          size_t *curSize,
                                          size_t *totSize)
{
    size_t len = 0;
    size_t pos;

    if (strncmp(node->name, SHORT_TAG, sizeof(SHORT_TAG) + 1) == 0) {
        pos = growParamSize(param, sizeof(short), curSize, totSize);
        if (pos == 0) {
            goto exit;
        }
        *(short *)(*param + pos) = (short)atoi(node->value);
        ALOGV("readParamValue() reading short %d", *(short *)(*param + pos));
        len = sizeof(short);
    } else if (strncmp(node->name, INT_TAG, sizeof(INT_TAG) + 1) == 0) {
        pos = growParamSize(param, sizeof(int), curSize, totSize);
        if (pos == 0) {
            goto exit;
        }
        *(int *)(*param + pos) = atoi(node->value);
        ALOGV("readParamValue() reading int %d", *(int *)(*param + pos));
        len = sizeof(int);
    } else if (strncmp(node->name, FLOAT_TAG, sizeof(FLOAT_TAG) + 1) == 0) {
        pos = growParamSize(param, sizeof(float), curSize, totSize);
        if (pos == 0) {
            goto exit;
        }
        *(float *)(*param + pos) = (float)atof(node->value);
        ALOGV("readParamValue() reading float %f",*(float *)(*param + pos));
        len = sizeof(float);
    } else if (strncmp(node->name, BOOL_TAG, sizeof(BOOL_TAG) + 1) == 0) {
        pos = growParamSize(param, sizeof(bool), curSize, totSize);
        if (pos == 0) {
            goto exit;
        }
        if (strncmp(node->value, "true", strlen("true") + 1) == 0) {
            *(bool *)(*param + pos) = true;
        } else {
            *(bool *)(*param + pos) = false;
        }
        ALOGV("readParamValue() reading bool %s",
              *(bool *)(*param + pos) ? "true" : "false");
        len = sizeof(bool);
    } else if (strncmp(node->name, STRING_TAG, sizeof(STRING_TAG) + 1) == 0) {
        len = strnlen(node->value, EFFECT_STRING_LEN_MAX);
        if (*curSize + len + 1 > *totSize) {
            *totSize = *curSize + len + 1;
            char *newParam = (char *)realloc(*param, *totSize);
            if (newParam == NULL) {
                len = 0;
                ALOGE("%s realloc error for string len %zu", __func__, *totSize);
                goto exit;
            }
            *param = newParam;
        }
        strncpy(*param + *curSize, node->value, len);
        *curSize += len;
        (*param)[*curSize] = '\0';
        ALOGV("readParamValue() reading string %s", *param + *curSize - len);
    } else {
        ALOGW("readParamValue() unknown param type %s", node->name);
    }
exit:
    return len;
}

/* static */
std::shared_ptr<const effect_param_t> AudioPolicyEffects::loadEffectParameter(cnode* root)
{
    cnode *param;
    cnode *value;
    size_t curSize = sizeof(effect_param_t);
    size_t totSize = sizeof(effect_param_t) + 2 * sizeof(int);
    effect_param_t *fx_param = (effect_param_t *)malloc(totSize);

    if (fx_param == NULL) {
        ALOGE("%s malloc error for effect structure of size %zu",
              __func__, totSize);
        return NULL;
    }

    param = config_find(root, PARAM_TAG);
    value = config_find(root, VALUE_TAG);
    if (param == NULL && value == NULL) {
        // try to parse simple parameter form {int int}
        param = root->first_child;
        if (param != NULL) {
            // Note: that a pair of random strings is read as 0 0
            int *ptr = (int *)fx_param->data;
#if LOG_NDEBUG == 0
            int *ptr2 = (int *)((char *)param + sizeof(effect_param_t));
            ALOGV("loadEffectParameter() ptr %p ptr2 %p", ptr, ptr2);
#endif
            *ptr++ = atoi(param->name);
            *ptr = atoi(param->value);
            fx_param->psize = sizeof(int);
            fx_param->vsize = sizeof(int);
            return {fx_param, free};
        }
    }
    if (param == NULL || value == NULL) {
        ALOGW("loadEffectParameter() invalid parameter description %s",
              root->name);
        goto error;
    }

    fx_param->psize = 0;
    param = param->first_child;
    while (param) {
        ALOGV("loadEffectParameter() reading param of type %s", param->name);
        size_t size =
                readParamValue(param, (char **)&fx_param, &curSize, &totSize);
        if (size == 0) {
            goto error;
        }
        fx_param->psize += size;
        param = param->next;
    }

    // align start of value field on 32 bit boundary
    curSize = ((curSize - 1 ) / sizeof(int) + 1) * sizeof(int);

    fx_param->vsize = 0;
    value = value->first_child;
    while (value) {
        ALOGV("loadEffectParameter() reading value of type %s", value->name);
        size_t size =
                readParamValue(value, (char **)&fx_param, &curSize, &totSize);
        if (size == 0) {
            goto error;
        }
        fx_param->vsize += size;
        value = value->next;
    }

    return {fx_param, free};

error:
    free(fx_param);
    return NULL;
}

/* static */
void AudioPolicyEffects::loadEffectParameters(
        cnode* root, std::vector<std::shared_ptr<const effect_param_t>>& params)
{
    cnode *node = root->first_child;
    while (node) {
        ALOGV("loadEffectParameters() loading param %s", node->name);
        const auto param = loadEffectParameter(node);
        if (param != nullptr) {
            params.push_back(param);
        }
        node = node->next;
    }
}

/* static */
std::shared_ptr<AudioPolicyEffects::EffectDescVector> AudioPolicyEffects::loadEffectConfig(
        cnode* root, const EffectDescVector& effects)
{
    cnode *node = root->first_child;
    if (node == NULL) {
        ALOGW("loadInputSource() empty element %s", root->name);
        return NULL;
    }
    auto desc = std::make_shared<EffectDescVector>();
    while (node) {
        size_t i;

        for (i = 0; i < effects.size(); i++) {
            if (effects[i]->mName == node->name) {
                ALOGV("loadEffectConfig() found effect %s in list", node->name);
                break;
            }
        }
        if (i == effects.size()) {
            ALOGV("loadEffectConfig() effect %s not in list", node->name);
            node = node->next;
            continue;
        }
        auto effect = std::make_shared<EffectDesc>(*effects[i]);   // deep copy
        loadEffectParameters(node, effect->mParams);
        ALOGV("loadEffectConfig() adding effect %s uuid %08x",
              effect->mName.c_str(), effect->mUuid.timeLow);
        desc->push_back(std::move(effect));
        node = node->next;
    }
    if (desc->empty()) {
        ALOGW("loadEffectConfig() no valid effects found in config %s", root->name);
        return nullptr;
    }
    return desc;
}

status_t AudioPolicyEffects::loadInputEffectConfigurations_l(cnode* root,
        const EffectDescVector& effects)
{
    cnode *node = config_find(root, PREPROCESSING_TAG);
    if (node == NULL) {
        return -ENOENT;
    }
    node = node->first_child;
    while (node) {
        audio_source_t source = inputSourceNameToEnum(node->name);
        if (source == AUDIO_SOURCE_CNT) {
            ALOGW("%s() invalid input source %s", __func__, node->name);
            node = node->next;
            continue;
        }
        ALOGV("%s() loading input source %s", __func__, node->name);
        auto desc = loadEffectConfig(node, effects);
        if (desc == NULL) {
            node = node->next;
            continue;
        }
        mInputSources[source] = std::move(desc);
        node = node->next;
    }
    return NO_ERROR;
}

status_t AudioPolicyEffects::loadStreamEffectConfigurations_l(cnode* root,
        const EffectDescVector& effects)
{
    cnode *node = config_find(root, OUTPUT_SESSION_PROCESSING_TAG);
    if (node == NULL) {
        return -ENOENT;
    }
    node = node->first_child;
    while (node) {
        audio_stream_type_t stream = streamNameToEnum(node->name);
        if (stream == AUDIO_STREAM_PUBLIC_CNT) {
            ALOGW("%s() invalid output stream %s", __func__, node->name);
            node = node->next;
            continue;
        }
        ALOGV("%s() loading output stream %s", __func__, node->name);
        std::shared_ptr<EffectDescVector> desc = loadEffectConfig(node, effects);
        if (desc == NULL) {
            node = node->next;
            continue;
        }
        mOutputStreams[stream] = std::move(desc);
        node = node->next;
    }
    return NO_ERROR;
}

/* static */
std::shared_ptr<AudioPolicyEffects::EffectDesc> AudioPolicyEffects::loadEffect(cnode* root)
{
    cnode *node = config_find(root, UUID_TAG);
    if (node == NULL) {
        return NULL;
    }
    effect_uuid_t uuid;
    if (AudioEffect::stringToGuid(node->value, &uuid) != NO_ERROR) {
        ALOGW("loadEffect() invalid uuid %s", node->value);
        return NULL;
    }
    return std::make_shared<EffectDesc>(root->name, uuid);
}

/* static */
android::AudioPolicyEffects::EffectDescVector AudioPolicyEffects::loadEffects(cnode *root)
{
    EffectDescVector effects;
    cnode *node = config_find(root, EFFECTS_TAG);
    if (node == NULL) {
        ALOGW("%s() Cannot find %s configuration", __func__, EFFECTS_TAG);
        return effects;
    }
    node = node->first_child;
    while (node) {
        ALOGV("loadEffects() loading effect %s", node->name);
        auto effect = loadEffect(node);
        if (effect == NULL) {
            node = node->next;
            continue;
        }
        effects.push_back(std::move(effect));
        node = node->next;
    }
    return effects;
}

status_t AudioPolicyEffects::loadAudioEffectConfig_ll(
        const sp<EffectsFactoryHalInterface>& effectsFactoryHal) {
    if (!effectsFactoryHal) {
        ALOGE("%s Null EffectsFactoryHalInterface", __func__);
        return UNEXPECTED_NULL;
    }

    const auto skippedElements = VALUE_OR_RETURN_STATUS(effectsFactoryHal->getSkippedElements());
    const auto processings = effectsFactoryHal->getProcessings();
    if (!processings) {
        ALOGE("%s Null processings with %zu skipped elements", __func__, skippedElements);
        return UNEXPECTED_NULL;
    }

    auto loadProcessingChain = [](auto& processingChain, auto& streams) {
        for (auto& stream : processingChain) {
            auto effectDescs = std::make_shared<EffectDescVector>();
            for (auto& effect : stream.effects) {
                effectDescs->push_back(
                        std::make_shared<EffectDesc>(effect->name, effect->uuid));
            }
            streams[stream.type] = std::move(effectDescs);
        }
    };

    auto loadDeviceProcessingChain = [](auto& processingChain, auto& devicesEffects) {
        for (auto& deviceProcess : processingChain) {
            auto effectDescs = std::make_unique<EffectDescVector>();
            for (auto& effect : deviceProcess.effects) {
                effectDescs->push_back(
                        std::make_shared<EffectDesc>(effect->name, effect->uuid));
            }
            auto devEffects = std::make_unique<DeviceEffects>(
                        std::move(effectDescs), deviceProcess.type, deviceProcess.address);
            devicesEffects.emplace(deviceProcess.address, std::move(devEffects));
        }
    };

    // access to mInputSources and mOutputStreams requires mMutex;
    loadProcessingChain(processings->preprocess, mInputSources);
    loadProcessingChain(processings->postprocess, mOutputStreams);

    // access to mDeviceEffects requires mDeviceEffectsMutex
    loadDeviceProcessingChain(processings->deviceprocess, mDeviceEffects);

    return skippedElements;
}

status_t AudioPolicyEffects::loadAudioEffectConfigLegacy_l(const char *path)
{
    cnode *root;
    char *data;

    data = (char *)load_file(path, NULL);
    if (data == NULL) {
        return -ENODEV;
    }
    root = config_node("", "");
    config_load(root, data);

    const EffectDescVector effects = loadEffects(root);

    // requires mMutex
    loadInputEffectConfigurations_l(root, effects);
    loadStreamEffectConfigurations_l(root, effects);
    config_free(root);
    free(root);
    free(data);

    return NO_ERROR;
}

void AudioPolicyEffects::initDefaultDeviceEffects()
{
    std::lock_guard _l(mDeviceEffectsMutex);
    for (const auto& deviceEffectsIter : mDeviceEffects) {
        const auto& deviceEffects =  deviceEffectsIter.second;
        for (const auto& effectDesc : *deviceEffects->mEffectDescriptors) {
            AttributionSourceState attributionSource;
            attributionSource.packageName = "android";
            attributionSource.token = sp<BBinder>::make();
            sp<AudioEffect> fx = sp<AudioEffect>::make(attributionSource);
            fx->set(EFFECT_UUID_NULL, &effectDesc->mUuid, 0 /* priority */, nullptr /* callback */,
                    AUDIO_SESSION_DEVICE, AUDIO_IO_HANDLE_NONE,
                    AudioDeviceTypeAddr{deviceEffects->getDeviceType(),
                                        deviceEffects->getDeviceAddress()});
            status_t status = fx->initCheck();
            if (status != NO_ERROR && status != ALREADY_EXISTS) {
                ALOGE("%s(): failed to create Fx %s on port type=%d address=%s", __func__,
                      effectDesc->mName.c_str(), deviceEffects->getDeviceType(),
                      deviceEffects->getDeviceAddress().c_str());
                // fx goes out of scope and strong ref on AudioEffect is released
                continue;
            }
            fx->setEnabled(true);
            ALOGV("%s(): create Fx %s added on port type=%d address=%s", __func__,
                  effectDesc->mName.c_str(), deviceEffects->getDeviceType(),
                  deviceEffects->getDeviceAddress().c_str());
            deviceEffects->mEffects.push_back(std::move(fx));
        }
    }
}

} // namespace android
