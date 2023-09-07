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

#pragma once

#include "IAfPatchPanel.h"

#include <utils/RefBase.h>  // avoid transitive dependency
#include <utils/Thread.h>  // avoid transitive dependency

#include <deque>
#include <mutex>  // avoid transitive dependency

namespace android {

class Command;

// Thread to execute create and release patch commands asynchronously. This is needed because
// IAfPatchPanel::createAudioPatch and releaseAudioPatch are executed from audio policy service
// with mutex locked and effect management requires to call back into audio policy service
class PatchCommandThread : public Thread {
public:

    enum {
        CREATE_AUDIO_PATCH,
        RELEASE_AUDIO_PATCH,
        UPDATE_AUDIO_PATCH,
    };

    class PatchCommandListener : public virtual RefBase {
    public:
        virtual void onCreateAudioPatch(audio_patch_handle_t handle,
                                        const IAfPatchPanel::Patch& patch) = 0;
        virtual void onReleaseAudioPatch(audio_patch_handle_t handle) = 0;
        virtual void onUpdateAudioPatch(audio_patch_handle_t oldHandle,
                                        audio_patch_handle_t newHandle,
                                        const IAfPatchPanel::Patch& patch) = 0;
    };

    PatchCommandThread() : Thread(false /* canCallJava */) {}
    ~PatchCommandThread() override;

    void addListener(const sp<PatchCommandListener>& listener)
            EXCLUDES_PatchCommandThread_ListenerMutex;

    void createAudioPatch(audio_patch_handle_t handle, const IAfPatchPanel::Patch& patch)
            EXCLUDES_PatchCommandThread_Mutex;
    void releaseAudioPatch(audio_patch_handle_t handle) EXCLUDES_PatchCommandThread_Mutex;
    void updateAudioPatch(audio_patch_handle_t oldHandle, audio_patch_handle_t newHandle,
            const IAfPatchPanel::Patch& patch) EXCLUDES_PatchCommandThread_Mutex;

    // Thread virtuals
    void onFirstRef() override;
    bool threadLoop() override;

    void exit();

    void createAudioPatchCommand(audio_patch_handle_t handle,
            const IAfPatchPanel::Patch& patch) EXCLUDES_PatchCommandThread_Mutex;
    void releaseAudioPatchCommand(audio_patch_handle_t handle) EXCLUDES_PatchCommandThread_Mutex;
    void updateAudioPatchCommand(audio_patch_handle_t oldHandle, audio_patch_handle_t newHandle,
            const IAfPatchPanel::Patch& patch) EXCLUDES_PatchCommandThread_Mutex;

private:
    class CommandData;

    // Command type received from the PatchPanel
    class Command: public RefBase {
    public:
        Command() = default;
        Command(int command, const sp<CommandData>& data)
            : mCommand(command), mData(data) {}

        const int mCommand = -1;
        const sp<CommandData> mData;
    };

    class CommandData: public RefBase {};

    class CreateAudioPatchData : public CommandData {
    public:
        CreateAudioPatchData(audio_patch_handle_t handle, const IAfPatchPanel::Patch& patch)
            :   mHandle(handle), mPatch(patch) {}

        const audio_patch_handle_t mHandle;
        const IAfPatchPanel::Patch mPatch;
    };

    class ReleaseAudioPatchData : public CommandData {
    public:
        explicit ReleaseAudioPatchData(audio_patch_handle_t handle)
            :   mHandle(handle) {}

        audio_patch_handle_t mHandle;
    };

    class UpdateAudioPatchData : public CommandData {
    public:
        UpdateAudioPatchData(audio_patch_handle_t oldHandle,
                             audio_patch_handle_t newHandle,
                             const IAfPatchPanel::Patch& patch)
            :   mOldHandle(oldHandle), mNewHandle(newHandle), mPatch(patch) {}

        const audio_patch_handle_t mOldHandle;
        const audio_patch_handle_t mNewHandle;
        const IAfPatchPanel::Patch mPatch;
    };

    void sendCommand(const sp<Command>& command) EXCLUDES_PatchCommandThread_Mutex;

    audio_utils::mutex& mutex() const RETURN_CAPABILITY(audio_utils::PatchCommandThread_Mutex) {
        return mMutex;
    }
    audio_utils::mutex& listenerMutex() const
            RETURN_CAPABILITY(audio_utils::PatchCommandThread_ListenerMutex) {
        return mListenerMutex;
    }

    mutable audio_utils::mutex mMutex;
    audio_utils::condition_variable mWaitWorkCV;
    std::deque<sp<Command>> mCommands GUARDED_BY(mutex()); // list of pending commands

    mutable audio_utils::mutex mListenerMutex;
    std::vector<wp<PatchCommandListener>> mListeners GUARDED_BY(listenerMutex());
};

}  // namespace android
