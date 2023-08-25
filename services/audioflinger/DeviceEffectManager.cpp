/*
**
** Copyright 2019, The Android Open Source Project
**
** Licensed under the Apache License, Version 2.0 (the "License");
** you may not use this file except in compliance with the License.
** You may obtain a copy of the License at
**
**     http://www.apache.org/licenses/LICENSE-2.0
**
** Unless required by applicable law or agreed to in writing, software
** distributed under the License is distributed on an "AS IS" BASIS,
** WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
** See the License for the specific language governing permissions and
** limitations under the License.
*/


#define LOG_TAG "AudioFlinger::DeviceEffectManager"
//#define LOG_NDEBUG 0

#include <utils/Log.h>
#include <audio_utils/primitives.h>

#include "AudioFlinger.h"
#include "EffectConfiguration.h"
#include <media/audiohal/EffectsFactoryHalInterface.h>

// ----------------------------------------------------------------------------


namespace android {

using detail::AudioHalVersionInfo;
using media::IEffectClient;

void AudioFlinger::DeviceEffectManager::onCreateAudioPatch(audio_patch_handle_t handle,
        const PatchPanel::Patch& patch) {
    ALOGV("%s handle %d mHalHandle %d device sink %08x",
            __func__, handle, patch.mHalHandle,
            patch.mAudioPatch.num_sinks > 0 ? patch.mAudioPatch.sinks[0].ext.device.type : 0);
    Mutex::Autolock _l(mLock);
    for (auto& effect : mDeviceEffects) {
        status_t status = effect.second->onCreatePatch(handle, patch);
        ALOGV("%s Effect onCreatePatch status %d", __func__, status);
        ALOGW_IF(status == BAD_VALUE, "%s onCreatePatch error %d", __func__, status);
    }
}

void AudioFlinger::DeviceEffectManager::onReleaseAudioPatch(audio_patch_handle_t handle) {
    ALOGV("%s", __func__);
    Mutex::Autolock _l(mLock);
    for (auto& effect : mDeviceEffects) {
        effect.second->onReleasePatch(handle);
    }
}

// DeviceEffectManager::createEffect_l() must be called with AudioFlinger::mLock held
sp<AudioFlinger::EffectHandle> AudioFlinger::DeviceEffectManager::createEffect_l(
        effect_descriptor_t *descriptor,
        const AudioDeviceTypeAddr& device,
        const sp<AudioFlinger::Client>& client,
        const sp<IEffectClient>& effectClient,
        const std::map<audio_patch_handle_t, PatchPanel::Patch>& patches,
        int *enabled,
        status_t *status,
        bool probe,
        bool notifyFramesProcessed) {
    sp<DeviceEffectProxy> effect;
    sp<EffectHandle> handle;
    status_t lStatus;

    lStatus = checkEffectCompatibility(descriptor);
    if (probe || lStatus != NO_ERROR) {
       *status = lStatus;
       return handle;
    }

    {
        Mutex::Autolock _l(mLock);
        auto iter = mDeviceEffects.find(device);
        if (iter != mDeviceEffects.end()) {
            effect = iter->second;
        } else {
            effect = new DeviceEffectProxy(device, mMyCallback,
                    descriptor, mAudioFlinger.nextUniqueId(AUDIO_UNIQUE_ID_USE_EFFECT),
                    notifyFramesProcessed);
        }
        // create effect handle and connect it to effect module
        handle = new EffectHandle(effect, client, effectClient, 0 /*priority*/,
                                  notifyFramesProcessed);
        lStatus = handle->initCheck();
        if (lStatus == NO_ERROR) {
            lStatus = effect->addHandle(handle.get());
            if (lStatus == NO_ERROR) {
                lStatus = effect->init(patches);
                if (lStatus == NAME_NOT_FOUND) {
                    lStatus = NO_ERROR;
                }
                if (lStatus == NO_ERROR || lStatus == ALREADY_EXISTS) {
                    mDeviceEffects.emplace(device, effect);
                }
            }
        }
    }
    if (enabled != nullptr) {
        *enabled = (int)effect->isEnabled();
    }
    *status = lStatus;
    return handle;
}

status_t AudioFlinger::DeviceEffectManager::checkEffectCompatibility(
        const effect_descriptor_t *desc) {
    const sp<EffectsFactoryHalInterface> effectsFactory =
            audioflinger::EffectConfiguration::getEffectsFactoryHal();
    if (effectsFactory == nullptr) {
        return BAD_VALUE;
    }

    static const AudioHalVersionInfo sMinDeviceEffectHalVersion =
            AudioHalVersionInfo(AudioHalVersionInfo::Type::HIDL, 6, 0);
    static const AudioHalVersionInfo halVersion =
            audioflinger::EffectConfiguration::getAudioHalVersionInfo();

    // We can trust AIDL generated AudioHalVersionInfo comparison operator (based on std::tie) as
    // long as the type, major and minor sequence doesn't change in the definition.
    if (((desc->flags & EFFECT_FLAG_TYPE_MASK) != EFFECT_FLAG_TYPE_PRE_PROC
            && (desc->flags & EFFECT_FLAG_TYPE_MASK) != EFFECT_FLAG_TYPE_POST_PROC)
            || halVersion < sMinDeviceEffectHalVersion) {
        ALOGW("%s() non pre/post processing device effect %s or incompatible API version %s",
                __func__, desc->name, halVersion.toString().c_str());
        return BAD_VALUE;
    }

    return NO_ERROR;
}

status_t AudioFlinger::DeviceEffectManager::createEffectHal(
        const effect_uuid_t *pEffectUuid, int32_t sessionId, int32_t deviceId,
        sp<EffectHalInterface> *effect) {
    status_t status = NO_INIT;
    const sp<EffectsFactoryHalInterface> effectsFactory =
            audioflinger::EffectConfiguration::getEffectsFactoryHal();
    if (effectsFactory != 0) {
        status = effectsFactory->createEffect(
                pEffectUuid, sessionId, AUDIO_IO_HANDLE_NONE, deviceId, effect);
    }
    return status;
}

void AudioFlinger::DeviceEffectManager::dump(int fd)
NO_THREAD_SAFETY_ANALYSIS  // conditional try lock
{
    const bool locked = dumpTryLock(mLock);
    if (!locked) {
        String8 result("DeviceEffectManager may be deadlocked\n");
        write(fd, result.c_str(), result.size());
    }

    String8 heading("\nDevice Effects:\n");
    write(fd, heading.c_str(), heading.size());
    for (const auto& iter : mDeviceEffects) {
        String8 outStr;
        outStr.appendFormat("%*sEffect for device %s address %s:\n", 2, "",
                ::android::toString(iter.first.mType).c_str(), iter.first.getAddress());
        write(fd, outStr.c_str(), outStr.size());
        iter.second->dump(fd, 4);
    }

    if (locked) {
        mLock.unlock();
    }
}


size_t AudioFlinger::DeviceEffectManager::removeEffect(const sp<DeviceEffectProxy>& effect)
{
    Mutex::Autolock _l(mLock);
    mDeviceEffects.erase(effect->device());
    return mDeviceEffects.size();
}

bool AudioFlinger::DeviceEffectManagerCallback::disconnectEffectHandle(
        EffectHandle *handle, bool unpinIfLast) {
    sp<EffectBase> effectBase = handle->effect().promote();
    if (effectBase == nullptr) {
        return false;
    }

    sp<DeviceEffectProxy> effect = effectBase->asDeviceEffectProxy();
    if (effect == nullptr) {
        return false;
    }
    // restore suspended effects if the disconnected handle was enabled and the last one.
    bool remove = (effect->removeHandle(handle) == 0) && (!effect->isPinned() || unpinIfLast);
    if (remove) {
        mManager.removeEffect(effect);
        if (handle->enabled()) {
            effectBase->checkSuspendOnEffectEnabled(false, false /*threadLocked*/);
        }
    }
    return true;
}

} // namespace android
