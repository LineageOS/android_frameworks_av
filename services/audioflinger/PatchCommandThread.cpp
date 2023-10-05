/*
**
** Copyright 2022, The Android Open Source Project
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

#define LOG_TAG "AudioFlinger::PatchCommandThread"
//#define LOG_NDEBUG 0

#include "AudioFlinger.h"

namespace android {

constexpr char kPatchCommandThreadName[] = "AudioFlinger_PatchCommandThread";

AudioFlinger::PatchCommandThread::~PatchCommandThread() {
    exit();

    std::lock_guard _l(mLock);
    mCommands.clear();
}

void AudioFlinger::PatchCommandThread::onFirstRef() {
    run(kPatchCommandThreadName, ANDROID_PRIORITY_AUDIO);
}

void AudioFlinger::PatchCommandThread::addListener(const sp<PatchCommandListener>& listener) {
    ALOGV("%s add listener %p", __func__, static_cast<void*>(listener.get()));
    std::lock_guard _l(mListenerLock);
    mListeners.emplace_back(listener);
}

void AudioFlinger::PatchCommandThread::createAudioPatch(audio_patch_handle_t handle,
        const PatchPanel::Patch& patch) {
    ALOGV("%s handle %d mHalHandle %d num sinks %d device sink %08x",
            __func__, handle, patch.mHalHandle,
            patch.mAudioPatch.num_sinks,
            patch.mAudioPatch.num_sinks > 0 ? patch.mAudioPatch.sinks[0].ext.device.type : 0);

    createAudioPatchCommand(handle, patch);
}

void AudioFlinger::PatchCommandThread::releaseAudioPatch(audio_patch_handle_t handle) {
    ALOGV("%s", __func__);
    releaseAudioPatchCommand(handle);
}

bool AudioFlinger::PatchCommandThread::threadLoop()
NO_THREAD_SAFETY_ANALYSIS  // bug in clang compiler.
{
    std::unique_lock _l(mLock);

    while (!exitPending()) {
        while (!mCommands.empty() && !exitPending()) {
            const sp<Command> command = mCommands.front();
            mCommands.pop_front();
            _l.unlock();

            std::vector<wp<PatchCommandListener>> listenersCopy;
            {
                std::lock_guard _ll(mListenerLock);
                listenersCopy = mListeners;
            }

            switch (command->mCommand) {
                case CREATE_AUDIO_PATCH: {
                    const auto data = (CreateAudioPatchData*) command->mData.get();
                    ALOGV("%s processing create audio patch handle %d",
                          __func__,
                          data->mHandle);

                    for (const auto& listener : listenersCopy) {
                        auto spListener = listener.promote();
                        if (spListener) {
                            spListener->onCreateAudioPatch(data->mHandle, data->mPatch);
                        }
                    }
                }
                    break;
                case RELEASE_AUDIO_PATCH: {
                    const auto data = (ReleaseAudioPatchData*) command->mData.get();
                    ALOGV("%s processing release audio patch handle %d",
                          __func__,
                          data->mHandle);

                    for (const auto& listener : listenersCopy) {
                        auto spListener = listener.promote();
                        if (spListener) {
                            spListener->onReleaseAudioPatch(data->mHandle);
                        }
                    }
                }
                    break;
                default:
                    ALOGW("%s unknown command %d", __func__, command->mCommand);
                    break;
            }
            _l.lock();
        }

        // At this stage we have either an empty command queue or the first command in the queue
        // has a finite delay. So unless we are exiting it is safe to wait.
        if (!exitPending()) {
            ALOGV("%s going to sleep", __func__);
            mWaitWorkCV.wait(_l);
        }
    }
    return false;
}

void AudioFlinger::PatchCommandThread::sendCommand(const sp<Command>& command) {
    std::lock_guard _l(mLock);
    mCommands.emplace_back(command);
    mWaitWorkCV.notify_one();
}

void AudioFlinger::PatchCommandThread::createAudioPatchCommand(
        audio_patch_handle_t handle, const PatchPanel::Patch& patch) {
    auto command = sp<Command>::make(CREATE_AUDIO_PATCH,
                                     new CreateAudioPatchData(handle, patch));
    ALOGV("%s adding create patch handle %d mHalHandle %d.",
          __func__,
          handle,
          patch.mHalHandle);
    sendCommand(command);
}

void AudioFlinger::PatchCommandThread::releaseAudioPatchCommand(audio_patch_handle_t handle) {
    sp<Command> command =
        sp<Command>::make(RELEASE_AUDIO_PATCH, new ReleaseAudioPatchData(handle));
    ALOGV("%s adding release patch", __func__);
    sendCommand(command);
}

void AudioFlinger::PatchCommandThread::exit() {
    ALOGV("%s", __func__);
    {
        std::lock_guard _l(mLock);
        requestExit();
        mWaitWorkCV.notify_one();
    }
    // Note that we can call it from the thread loop if all other references have been released
    // but it will safely return WOULD_BLOCK in this case
    requestExitAndWait();
}

}  // namespace android
