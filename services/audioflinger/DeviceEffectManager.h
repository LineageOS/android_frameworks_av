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

#ifndef INCLUDING_FROM_AUDIOFLINGER_H
    #error This header file should only be included from AudioFlinger.h
#endif

// DeviceEffectManager is concealed within AudioFlinger, their lifetimes are the same.
class DeviceEffectManager {
public:
    explicit DeviceEffectManager(AudioFlinger* audioFlinger)
        : mCommandThread(new CommandThread(*this)), mAudioFlinger(*audioFlinger),
        mMyCallback(new DeviceEffectManagerCallback(this)) {}

            ~DeviceEffectManager() {
                mCommandThread->exit();
            }

    sp<EffectHandle> createEffect_l(effect_descriptor_t *descriptor,
                const AudioDeviceTypeAddr& device,
                const sp<AudioFlinger::Client>& client,
                const sp<IEffectClient>& effectClient,
                const std::map<audio_patch_handle_t, PatchPanel::Patch>& patches,
                int *enabled,
                status_t *status,
                bool probe);
    void createAudioPatch(audio_patch_handle_t handle, const PatchPanel::Patch& patch);
    void releaseAudioPatch(audio_patch_handle_t handle);

    size_t removeEffect(const sp<DeviceEffectProxy>& effect);
    status_t createEffectHal(const effect_uuid_t *pEffectUuid,
           int32_t sessionId, int32_t deviceId,
           sp<EffectHalInterface> *effect);
    status_t addEffectToHal(audio_port_handle_t deviceId, audio_module_handle_t hwModuleId,
            sp<EffectHalInterface> effect) {
        return mAudioFlinger.addEffectToHal(deviceId, hwModuleId, effect);
    };
    status_t removeEffectFromHal(audio_port_handle_t deviceId, audio_module_handle_t hwModuleId,
            sp<EffectHalInterface> effect) {
        return mAudioFlinger.removeEffectFromHal(deviceId, hwModuleId, effect);
    };

    AudioFlinger& audioFlinger() const { return mAudioFlinger; }

    void dump(int fd);

private:

    // Thread to execute create and release patch commands asynchronously. This is needed because
    // PatchPanel::createAudioPatch and releaseAudioPatch are executed from audio policy service
    // with mutex locked and effect management requires to call back into audio policy service
    class Command;
    class CommandThread : public Thread {
    public:

        enum {
            CREATE_AUDIO_PATCH,
            RELEASE_AUDIO_PATCH,
        };

        CommandThread(DeviceEffectManager& manager)
            : Thread(false), mManager(manager) {}
        ~CommandThread() override;

        // Thread virtuals
        void onFirstRef() override;
        bool threadLoop() override;

                void exit();

                void createAudioPatchCommand(audio_patch_handle_t handle,
                        const PatchPanel::Patch& patch);
                void releaseAudioPatchCommand(audio_patch_handle_t handle);

    private:
        class CommandData;

        // descriptor for requested tone playback event
        class Command: public RefBase {
        public:
            Command() = default;
            Command(int command, sp<CommandData> data)
                : mCommand(command), mData(data) {}

            int mCommand = -1;
            sp<CommandData> mData;
        };

        class CommandData: public RefBase {
        public:
            virtual ~CommandData() = default;
        };

        class CreateAudioPatchData : public CommandData {
        public:
            CreateAudioPatchData(audio_patch_handle_t handle, const PatchPanel::Patch& patch)
                :   mHandle(handle), mPatch(patch) {}

            audio_patch_handle_t mHandle;
            const PatchPanel::Patch mPatch;
        };

        class ReleaseAudioPatchData : public CommandData {
        public:
            ReleaseAudioPatchData(audio_patch_handle_t handle)
                :   mHandle(handle) {}

            audio_patch_handle_t mHandle;
        };

        void sendCommand(sp<Command> command);

        Mutex   mLock;
        Condition mWaitWorkCV;
        std::deque <sp<Command>> mCommands; // list of pending commands
        DeviceEffectManager& mManager;
    };

    void onCreateAudioPatch(audio_patch_handle_t handle, const PatchPanel::Patch& patch);
    void onReleaseAudioPatch(audio_patch_handle_t handle);

    status_t checkEffectCompatibility(const effect_descriptor_t *desc);

    Mutex mLock;
    sp<CommandThread> mCommandThread;
    AudioFlinger &mAudioFlinger;
    const sp<DeviceEffectManagerCallback> mMyCallback;
    std::map<AudioDeviceTypeAddr, sp<DeviceEffectProxy>> mDeviceEffects;
};

class DeviceEffectManagerCallback :  public EffectCallbackInterface {
public:
            DeviceEffectManagerCallback(DeviceEffectManager *manager)
                : mManager(*manager) {}

    status_t createEffectHal(const effect_uuid_t *pEffectUuid,
           int32_t sessionId, int32_t deviceId,
           sp<EffectHalInterface> *effect) override {
                return mManager.createEffectHal(pEffectUuid, sessionId, deviceId, effect);
            }
    status_t allocateHalBuffer(size_t size __unused,
            sp<EffectBufferHalInterface>* buffer __unused) override { return NO_ERROR; }
    bool updateOrphanEffectChains(const sp<EffectBase>& effect __unused) override { return false; }

    audio_io_handle_t io() const override  { return AUDIO_IO_HANDLE_NONE; }
    bool isOutput() const override { return false; }
    bool isOffload() const override { return false; }
    bool isOffloadOrDirect() const override { return false; }
    bool isOffloadOrMmap() const override { return false; }

    uint32_t  sampleRate() const override { return 0; }
    audio_channel_mask_t channelMask() const override { return AUDIO_CHANNEL_NONE; }
    uint32_t channelCount() const override { return 0; }
    size_t    frameCount() const override  { return 0; }
    uint32_t  latency() const override  { return 0; }

    status_t addEffectToHal(sp<EffectHalInterface> effect __unused) override {
        return NO_ERROR;
    }
    status_t removeEffectFromHal(sp<EffectHalInterface> effect __unused) override {
        return NO_ERROR;
    }

    bool disconnectEffectHandle(EffectHandle *handle, bool unpinIfLast) override;
    void setVolumeForOutput(float left __unused, float right __unused) const override {}

    // check if effects should be suspended or restored when a given effect is enable or disabled
    void checkSuspendOnEffectEnabled(const sp<EffectBase>& effect __unused,
                          bool enabled __unused, bool threadLocked __unused) override {}
    void resetVolume() override {}
    uint32_t strategy() const override  { return 0; }
    int32_t activeTrackCnt() const override { return 0; }
    void onEffectEnable(const sp<EffectBase>& effect __unused) override {}
    void onEffectDisable(const sp<EffectBase>& effect __unused) override {}

    wp<EffectChain> chain() const override { return nullptr; }

    int newEffectId() { return mManager.audioFlinger().nextUniqueId(AUDIO_UNIQUE_ID_USE_EFFECT); }

    status_t addEffectToHal(audio_port_handle_t deviceId,
            audio_module_handle_t hwModuleId, sp<EffectHalInterface> effect) {
        return mManager.addEffectToHal(deviceId, hwModuleId, effect);
    }
    status_t removeEffectFromHal(audio_port_handle_t deviceId,
            audio_module_handle_t hwModuleId, sp<EffectHalInterface> effect) {
        return mManager.removeEffectFromHal(deviceId, hwModuleId, effect);
    }
private:
    DeviceEffectManager& mManager;
};
