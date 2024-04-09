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

#define LOG_TAG "APM::EffectDescriptor"
//#define LOG_NDEBUG 0

#include <android-base/stringprintf.h>

#include "AudioInputDescriptor.h"
#include "EffectDescriptor.h"
#include <utils/String8.h>

#include <AudioPolicyInterface.h>
#include "AudioPolicyMix.h"
#include "HwModule.h"

namespace android {

void EffectDescriptor::dump(String8 *dst, int spaces) const
{
    dst->appendFormat("Effect ID: %d; Attached to I/O handle: %d; Session: %d;\n",
            mId, mIo, mSession);
    dst->appendFormat("%*sMusic Effect? %s; \"%s\"; %s; %s\n", spaces, "",
            isMusicEffect()? "yes" : "no", mDesc.name,
            mEnabled ? "Enabled" : "Disabled", mSuspended ? "Suspended" : "Active");
}

EffectDescriptorCollection::EffectDescriptorCollection() :
    mTotalEffectsCpuLoad(0),
    mTotalEffectsMemory(0),
    mTotalEffectsMemoryMaxUsed(0)
{

}

status_t EffectDescriptorCollection::registerEffect(const effect_descriptor_t *desc,
                                                    audio_io_handle_t io,
                                                    int session,
                                                    int id, bool isMusicEffect)
{
    if (getEffect(id) != nullptr) {
        ALOGW("%s effect %s already registered", __FUNCTION__, desc->name);
        return INVALID_OPERATION;
    }

    if (mTotalEffectsMemory + desc->memoryUsage > getMaxEffectsMemory()) {
        ALOGW("registerEffect() memory limit exceeded for Fx %s, Memory %d KB",
                desc->name, desc->memoryUsage);
        return INVALID_OPERATION;
    }
    mTotalEffectsMemory += desc->memoryUsage;
    if (mTotalEffectsMemory > mTotalEffectsMemoryMaxUsed) {
        mTotalEffectsMemoryMaxUsed = mTotalEffectsMemory;
    }
    ALOGV("registerEffect() effect %s, io %d, session %d id %d",
            desc->name, io, session, id);
    ALOGV("registerEffect() memory %d, total memory %d", desc->memoryUsage, mTotalEffectsMemory);

    sp<EffectDescriptor> effectDesc =
        new EffectDescriptor(desc, isMusicEffect, id, io, (audio_session_t)session);
    add(id, effectDesc);

    return NO_ERROR;
}

sp<EffectDescriptor> EffectDescriptorCollection::getEffect(int id) const
{
    ssize_t index = indexOfKey(id);
    if (index < 0) {
        return nullptr;
    }
    return valueAt(index);
}

status_t EffectDescriptorCollection::unregisterEffect(int id)
{
    sp<EffectDescriptor> effectDesc = getEffect(id);
    if (effectDesc == nullptr) {
        ALOGW("%s unknown effect ID %d", __FUNCTION__, id);
        return INVALID_OPERATION;
    }

    if (mTotalEffectsMemory < effectDesc->mDesc.memoryUsage) {
        ALOGW("unregisterEffect() memory %d too big for total %d",
                effectDesc->mDesc.memoryUsage, mTotalEffectsMemory);
        effectDesc->mDesc.memoryUsage = mTotalEffectsMemory;
    }
    mTotalEffectsMemory -= effectDesc->mDesc.memoryUsage;
    ALOGV("unregisterEffect() effect %s, ID %d, memory %d total memory %d",
            effectDesc->mDesc.name, id, effectDesc->mDesc.memoryUsage, mTotalEffectsMemory);

    removeItem(id);

    return NO_ERROR;
}

status_t EffectDescriptorCollection::setEffectEnabled(int id, bool enabled)
{
    ssize_t index = indexOfKey(id);
    if (index < 0) {
        ALOGW("unregisterEffect() unknown effect ID %d", id);
        return INVALID_OPERATION;
    }

    return setEffectEnabled(valueAt(index), enabled);
}

bool EffectDescriptorCollection::isEffectEnabled(int id) const
{
    ssize_t index = indexOfKey(id);
    if (index < 0) {
        return false;
    }
    return valueAt(index)->mEnabled;
}

status_t EffectDescriptorCollection::setEffectEnabled(const sp<EffectDescriptor> &effectDesc,
                                                      bool enabled)
{
    if (enabled == effectDesc->mEnabled) {
        ALOGV("setEffectEnabled(%s) effect already %s",
             enabled?"true":"false", enabled?"enabled":"disabled");
        return INVALID_OPERATION;
    }

    if (enabled) {
        if (mTotalEffectsCpuLoad + effectDesc->mDesc.cpuLoad > getMaxEffectsCpuLoad()) {
            ALOGW("setEffectEnabled(true) CPU Load limit exceeded for Fx %s, CPU %f MIPS",
                 effectDesc->mDesc.name, (float)effectDesc->mDesc.cpuLoad/10);
            return INVALID_OPERATION;
        }
        mTotalEffectsCpuLoad += effectDesc->mDesc.cpuLoad;
        ALOGV("setEffectEnabled(true) total CPU %d", mTotalEffectsCpuLoad);
    } else {
        if (mTotalEffectsCpuLoad < effectDesc->mDesc.cpuLoad) {
            ALOGW("setEffectEnabled(false) CPU load %d too high for total %d",
                    effectDesc->mDesc.cpuLoad, mTotalEffectsCpuLoad);
            effectDesc->mDesc.cpuLoad = mTotalEffectsCpuLoad;
        }
        mTotalEffectsCpuLoad -= effectDesc->mDesc.cpuLoad;
        ALOGV("setEffectEnabled(false) total CPU %d", mTotalEffectsCpuLoad);
    }
    effectDesc->mEnabled = enabled;
    return NO_ERROR;
}

bool EffectDescriptorCollection::isNonOffloadableEffectEnabled() const
{
    for (size_t i = 0; i < size(); i++) {
        sp<EffectDescriptor> effectDesc = valueAt(i);
        if (effectDesc->mEnabled && (effectDesc->isMusicEffect()) &&
                ((effectDesc->mDesc.flags & EFFECT_FLAG_OFFLOAD_SUPPORTED) == 0)) {
            ALOGV("isNonOffloadableEffectEnabled() non offloadable effect %s enabled on session %d",
                  effectDesc->mDesc.name, effectDesc->mSession);
            return true;
        }
    }
    return false;
}

uint32_t EffectDescriptorCollection::getMaxEffectsCpuLoad() const
{
    return MAX_EFFECTS_CPU_LOAD;
}

uint32_t EffectDescriptorCollection::getMaxEffectsMemory() const
{
    return MAX_EFFECTS_MEMORY;
}

void EffectDescriptorCollection::moveEffects(audio_session_t sessionId, audio_io_handle_t srcIo,
                                             audio_io_handle_t dstIo,
                                             AudioPolicyClientInterface *clientInterface)
{
    ALOGV("%s session %d srcIo %d dstIo %d", __func__, sessionId, srcIo, dstIo);
    for (size_t i = 0; i < size(); i++) {
        sp<EffectDescriptor> effect = valueAt(i);
        if (effect->mSession == sessionId && effect->mIo == srcIo) {
            effect->mIo = dstIo;
            // Backup enable state before any updatePolicyState call
            effect->mIsOrphan = (dstIo == AUDIO_IO_HANDLE_NONE);
        }
    }
    clientInterface->moveEffects(sessionId, srcIo, dstIo);
}

void EffectDescriptorCollection::moveEffects(const std::vector<int>& ids, audio_io_handle_t dstIo)
{
    ALOGV("%s num effects %zu, first ID %d, dstIo %d",
        __func__, ids.size(), ids.size() ? ids[0] : 0, dstIo);
    for (size_t i = 0; i < size(); i++) {
        sp<EffectDescriptor> effect = valueAt(i);
        if (std::find(begin(ids), end(ids), effect->mId) != end(ids)) {
            effect->mIo = dstIo;
            effect->mIsOrphan = (dstIo == AUDIO_IO_HANDLE_NONE);
        }
    }
}

bool EffectDescriptorCollection::hasOrphansForSession(audio_session_t sessionId) const
{
    for (size_t i = 0; i < size(); ++i) {
        sp<EffectDescriptor> effect = valueAt(i);
        if (effect->mSession == sessionId && effect->mIsOrphan) {
            return true;
        }
    }
    return false;
}

bool EffectDescriptorCollection::hasOrphanEffectsForSessionAndType(
        audio_session_t sessionId, const effect_uuid_t* effectType) const {
    if (effectType == nullptr) {
        return hasOrphansForSession(sessionId);
    }

    for (size_t i = 0; i < size(); ++i) {
        sp<EffectDescriptor> effect = valueAt(i);
        if (effect->mIsOrphan && effect->mSession == sessionId &&
            memcmp(&effect->mDesc.type, effectType, sizeof(effect_uuid_t)) == 0) {
            return true;
        }
    }
    return false;
}

EffectDescriptorCollection EffectDescriptorCollection::getOrphanEffectsForSession(
        audio_session_t sessionId) const
{
    EffectDescriptorCollection effects;
    for (size_t i = 0; i < size(); i++) {
        sp<EffectDescriptor> effect = valueAt(i);
        if (effect->mSession == sessionId && effect->mIsOrphan) {
            effects.add(keyAt(i), effect);
        }
    }
    return effects;
}

audio_io_handle_t EffectDescriptorCollection::getIoForSession(audio_session_t sessionId,
                                                              const effect_uuid_t *effectType) const
{
    for (size_t i = 0; i < size(); ++i) {
        sp<EffectDescriptor> effect = valueAt(i);
        if (effect->mSession == sessionId && (effectType == nullptr ||
                memcmp(&effect->mDesc.type, effectType, sizeof(effect_uuid_t)) == 0)) {
            return effect->mIo;
        }
    }
    return AUDIO_IO_HANDLE_NONE;
}

void EffectDescriptorCollection::moveEffectsForIo(audio_session_t session,
        audio_io_handle_t dstIo, const AudioInputCollection *inputs,
        AudioPolicyClientInterface *clientInterface)
{
    // No src io: try to find from effect session the src Io to move from
    audio_io_handle_t srcIo = getIoForSession(session);
    if (hasOrphansForSession(session) || (srcIo != AUDIO_IO_HANDLE_NONE && srcIo != dstIo)) {
        moveEffects(session, srcIo, dstIo, inputs, clientInterface);
    }
}

void EffectDescriptorCollection::moveEffects(audio_session_t session,
        audio_io_handle_t srcIo, audio_io_handle_t dstIo, const AudioInputCollection *inputs,
        AudioPolicyClientInterface *clientInterface)
{
    if ((srcIo != AUDIO_IO_HANDLE_NONE && srcIo == dstIo)
            || (srcIo == AUDIO_IO_HANDLE_NONE && !hasOrphansForSession(session))) {
        return;
    }
    // Either we may find orphan effects for given session or effects for this session might have
    // been assigned first to another input (it may happen when an input is released or recreated
    // after client sets its preferred device)
    EffectDescriptorCollection effectsToMove;
    if (srcIo == AUDIO_IO_HANDLE_NONE) {
        ALOGV("%s: restoring effects for session %d from orphan park to io=%d", __func__,
                session, dstIo);
        effectsToMove = getOrphanEffectsForSession(session);
    } else {
        ALOGV("%s: moving effects for session %d from io=%d to io=%d", __func__, session, srcIo,
              dstIo);
        if (const sp<AudioInputDescriptor>& previousInputDesc = inputs->valueFor(srcIo)) {
            effectsToMove = getEffectsForIo(srcIo);
            for (size_t i = 0; i < effectsToMove.size(); ++i) {
                const sp<EffectDescriptor>& effect = effectsToMove.valueAt(i);
                effect->mEnabledWhenMoved = effect->mEnabled;
                previousInputDesc->trackEffectEnabled(effect, false);
            }
        } else {
            ALOGW("%s: no effect descriptor for srcIo %d", __func__, srcIo);
        }
    }
    moveEffects(session, srcIo, dstIo, clientInterface);

    if (dstIo != AUDIO_IO_HANDLE_NONE) {
        if (const sp<AudioInputDescriptor>& inputDesc = inputs->valueFor(dstIo)) {
            for (size_t i = 0; i < effectsToMove.size(); ++i) {
                const sp<EffectDescriptor>& effect = effectsToMove.valueAt(i);
                inputDesc->trackEffectEnabled(effect, effect->mEnabledWhenMoved);
            }
        } else {
            ALOGW("%s: no effect descriptor for dstIo %d", __func__, dstIo);
        }
    }
}

void EffectDescriptorCollection::putOrphanEffectsForIo(audio_io_handle_t srcIo)
{
    for (size_t i = 0; i < size(); i++) {
        sp<EffectDescriptor> effect = valueAt(i);
        if (effect->mIo == srcIo) {
            effect->mIo = AUDIO_IO_HANDLE_NONE;
            effect->mIsOrphan = true;
        }
    }
}

void EffectDescriptorCollection::putOrphanEffects(audio_session_t session,
        audio_io_handle_t srcIo, const AudioInputCollection *inputs,
        AudioPolicyClientInterface *clientInterface)
{
    if (getIoForSession(session) != srcIo) {
       // Effect session not held by this client io handle
       return;
    }
    ALOGV("%s: park effects for session %d and io=%d to orphans", __func__, session, srcIo);
    moveEffects(session, srcIo, AUDIO_IO_HANDLE_NONE, inputs, clientInterface);
}

EffectDescriptorCollection EffectDescriptorCollection::getEffectsForIo(audio_io_handle_t io) const
{
    EffectDescriptorCollection effects;
    for (size_t i = 0; i < size(); i++) {
        if (valueAt(i)->mIo == io) {
            effects.add(keyAt(i), valueAt(i));
        }
    }
    return effects;
}

void EffectDescriptorCollection::dump(String8 *dst, int spaces, bool verbose) const
{
    if (verbose) {
        dst->appendFormat(
            "\n%*sTotal Effects CPU: %f MIPS, "
            "Total Effects memory: %d KB, Max memory used: %d KB\n",
            spaces, "",
            (float) mTotalEffectsCpuLoad / 10,
            mTotalEffectsMemory,
            mTotalEffectsMemoryMaxUsed);
    }
    if (size() > 0) {
        if (spaces > 1) spaces -= 2;
        dst->appendFormat("%*s- Effects (%zu):\n", spaces, "", size());
        for (size_t i = 0; i < size(); i++) {
            const std::string prefix = base::StringPrintf("%*s %zu. ", spaces, "", i + 1);
            dst->appendFormat("%s", prefix.c_str());
            valueAt(i)->dump(dst, prefix.size());
        }
    }
}

}; //namespace android
