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
#include <media/audiohal/EffectsFactoryHalInterface.h>

// ----------------------------------------------------------------------------


namespace android {

void AudioFlinger::DeviceEffectManager::createAudioPatch(audio_patch_handle_t handle,
        const PatchPanel::Patch& patch) {
    ALOGV("%s handle %d mHalHandle %d num sinks %d device sink %08x",
            __func__, handle, patch.mHalHandle,
            patch.mAudioPatch.num_sinks,
            patch.mAudioPatch.num_sinks > 0 ? patch.mAudioPatch.sinks[0].ext.device.type : 0);

    mCommandThread->createAudioPatchCommand(handle, patch);
}

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

void AudioFlinger::DeviceEffectManager::releaseAudioPatch(audio_patch_handle_t handle) {
    ALOGV("%s", __func__);
    mCommandThread->releaseAudioPatchCommand(handle);
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
        bool probe) {
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
                    descriptor, mAudioFlinger.nextUniqueId(AUDIO_UNIQUE_ID_USE_EFFECT));
        }
        // create effect handle and connect it to effect module
        handle = new EffectHandle(effect, client, effectClient, 0 /*priority*/);
        lStatus = handle->initCheck();
        if (lStatus == NO_ERROR) {
            lStatus = effect->addHandle(handle.get());
            if (lStatus == NO_ERROR) {
                effect->init(patches);
                mDeviceEffects.emplace(device, effect);
            }
        }
    }
    if (enabled != NULL) {
        *enabled = (int)effect->isEnabled();
    }
    *status = lStatus;
    return handle;
}

status_t AudioFlinger::DeviceEffectManager::checkEffectCompatibility(
        const effect_descriptor_t *desc) {

    if ((desc->flags & EFFECT_FLAG_TYPE_MASK) != EFFECT_FLAG_TYPE_PRE_PROC
        && (desc->flags & EFFECT_FLAG_TYPE_MASK) != EFFECT_FLAG_TYPE_POST_PROC) {
        ALOGW("%s() non pre/post processing device effect %s", __func__, desc->name);
        return BAD_VALUE;
    }

    return NO_ERROR;
}

status_t AudioFlinger::DeviceEffectManager::createEffectHal(
        const effect_uuid_t *pEffectUuid, int32_t sessionId, int32_t deviceId,
        sp<EffectHalInterface> *effect) {
    status_t status = NO_INIT;
    sp<EffectsFactoryHalInterface> effectsFactory = mAudioFlinger.getEffectsFactory();
    if (effectsFactory != 0) {
        status = effectsFactory->createEffect(
                pEffectUuid, sessionId, AUDIO_IO_HANDLE_NONE, deviceId, effect);
    }
    return status;
}

void AudioFlinger::DeviceEffectManager::dump(int fd) {
    const bool locked = dumpTryLock(mLock);
    if (!locked) {
        String8 result("DeviceEffectManager may be deadlocked\n");
        write(fd, result.string(), result.size());
    }

    String8 heading("\nDevice Effects:\n");
    write(fd, heading.string(), heading.size());
    for (const auto& iter : mDeviceEffects) {
        String8 outStr;
        outStr.appendFormat("%*sEffect for device %s address %s:\n", 2, "",
                ::android::toString(iter.first.mType).c_str(), iter.first.getAddress());
        write(fd, outStr.string(), outStr.size());
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

// -----------  DeviceEffectManager::CommandThread implementation ----------


AudioFlinger::DeviceEffectManager::CommandThread::~CommandThread()
{
    Mutex::Autolock _l(mLock);
    mCommands.clear();
}

void AudioFlinger::DeviceEffectManager::CommandThread::onFirstRef()
{
    run("DeviceEffectManage_CommandThread", ANDROID_PRIORITY_AUDIO);
}

bool AudioFlinger::DeviceEffectManager::CommandThread::threadLoop()
{
    mLock.lock();
    while (!exitPending())
    {
        while (!mCommands.empty() && !exitPending()) {
            sp<Command> command = mCommands.front();
            mCommands.pop_front();
            mLock.unlock();

            switch (command->mCommand) {
            case CREATE_AUDIO_PATCH: {
                CreateAudioPatchData *data = (CreateAudioPatchData *)command->mData.get();
                ALOGV("CommandThread() processing create audio patch handle %d", data->mHandle);
                mManager.onCreateAudioPatch(data->mHandle, data->mPatch);
                } break;
            case RELEASE_AUDIO_PATCH: {
                ReleaseAudioPatchData *data = (ReleaseAudioPatchData *)command->mData.get();
                ALOGV("CommandThread() processing release audio patch handle %d", data->mHandle);
                mManager.onReleaseAudioPatch(data->mHandle);
                } break;
            default:
                ALOGW("CommandThread() unknown command %d", command->mCommand);
            }
            mLock.lock();
        }

        // At this stage we have either an empty command queue or the first command in the queue
        // has a finite delay. So unless we are exiting it is safe to wait.
        if (!exitPending()) {
            ALOGV("CommandThread() going to sleep");
            mWaitWorkCV.wait(mLock);
        }
    }
    mLock.unlock();
    return false;
}

void AudioFlinger::DeviceEffectManager::CommandThread::sendCommand(sp<Command> command) {
    Mutex::Autolock _l(mLock);
    mCommands.push_back(command);
    mWaitWorkCV.signal();
}

void AudioFlinger::DeviceEffectManager::CommandThread::createAudioPatchCommand(
        audio_patch_handle_t handle, const PatchPanel::Patch& patch)
{
    sp<Command> command = new Command(CREATE_AUDIO_PATCH, new CreateAudioPatchData(handle, patch));
    ALOGV("CommandThread() adding create patch handle %d mHalHandle %d.", handle, patch.mHalHandle);
    sendCommand(command);
}

void AudioFlinger::DeviceEffectManager::CommandThread::releaseAudioPatchCommand(
        audio_patch_handle_t handle)
{
    sp<Command> command = new Command(RELEASE_AUDIO_PATCH, new ReleaseAudioPatchData(handle));
    ALOGV("CommandThread() adding release patch");
    sendCommand(command);
}

void AudioFlinger::DeviceEffectManager::CommandThread::exit()
{
    ALOGV("CommandThread::exit");
    {
        AutoMutex _l(mLock);
        requestExit();
        mWaitWorkCV.signal();
    }
    // Note that we can call it from the thread loop if all other references have been released
    // but it will safely return WOULD_BLOCK in this case
    requestExitAndWait();
}

} // namespace android
