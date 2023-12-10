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
class DeviceEffectManager : public PatchCommandThread::PatchCommandListener {
public:
    explicit DeviceEffectManager(AudioFlinger& audioFlinger)
        : mAudioFlinger(audioFlinger),
          mMyCallback(new DeviceEffectManagerCallback(*this)) {}

    void onFirstRef() override {
        mAudioFlinger.mPatchCommandThread->addListener(this);
    }

    sp<EffectHandle> createEffect_l(effect_descriptor_t *descriptor,
                const AudioDeviceTypeAddr& device,
                const sp<AudioFlinger::Client>& client,
                const sp<media::IEffectClient>& effectClient,
                const std::map<audio_patch_handle_t, PatchPanel::Patch>& patches,
                int *enabled,
                status_t *status,
                bool probe,
                bool notifyFramesProcessed);

    size_t removeEffect(const sp<DeviceEffectProxy>& effect);
    status_t createEffectHal(const effect_uuid_t *pEffectUuid,
           int32_t sessionId, int32_t deviceId,
           sp<EffectHalInterface> *effect);
    status_t addEffectToHal(const struct audio_port_config *device,
            const sp<EffectHalInterface>& effect) {
        return mAudioFlinger.addEffectToHal(device, effect);
    };
    status_t removeEffectFromHal(const struct audio_port_config *device,
            const sp<EffectHalInterface>& effect) {
        return mAudioFlinger.removeEffectFromHal(device, effect);
    };

    AudioFlinger& audioFlinger() const { return mAudioFlinger; }

    void dump(int fd);

    // PatchCommandThread::PatchCommandListener implementation

    void onCreateAudioPatch(audio_patch_handle_t handle,
                            const PatchPanel::Patch& patch) override;
    void onReleaseAudioPatch(audio_patch_handle_t handle) override;

private:
    status_t checkEffectCompatibility(const effect_descriptor_t *desc);

    Mutex mLock;
    AudioFlinger &mAudioFlinger;
    const sp<DeviceEffectManagerCallback> mMyCallback;
    std::map<AudioDeviceTypeAddr, sp<DeviceEffectProxy>> mDeviceEffects;
};

class DeviceEffectManagerCallback : public EffectCallbackInterface {
public:
    explicit DeviceEffectManagerCallback(DeviceEffectManager& manager)
        : mManager(manager) {}

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
    bool isSpatializer() const override { return false; }

    uint32_t  sampleRate() const override { return 0; }
    audio_channel_mask_t inChannelMask(int id __unused) const override {
        return AUDIO_CHANNEL_NONE;
    }
    uint32_t inChannelCount(int id __unused) const override { return 0; }
    audio_channel_mask_t outChannelMask() const override { return AUDIO_CHANNEL_NONE; }
    uint32_t outChannelCount() const override { return 0; }

    audio_channel_mask_t hapticChannelMask() const override { return AUDIO_CHANNEL_NONE; }
    size_t    frameCount() const override  { return 0; }
    uint32_t  latency() const override  { return 0; }

    status_t addEffectToHal(const sp<EffectHalInterface>& /* effect */) override {
        return NO_ERROR;
    }
    status_t removeEffectFromHal(const sp<EffectHalInterface>& /* effect */) override {
        return NO_ERROR;
    }

    bool disconnectEffectHandle(EffectHandle *handle, bool unpinIfLast) override;
    void setVolumeForOutput(float left __unused, float right __unused) const override {}

    // check if effects should be suspended or restored when a given effect is enable or disabled
    void checkSuspendOnEffectEnabled(const sp<EffectBase>& effect __unused,
                          bool enabled __unused, bool threadLocked __unused) override {}
    void resetVolume() override {}
    product_strategy_t strategy() const override  { return static_cast<product_strategy_t>(0); }
    int32_t activeTrackCnt() const override { return 0; }
    void onEffectEnable(const sp<EffectBase>& effect __unused) override {}
    void onEffectDisable(const sp<EffectBase>& effect __unused) override {}

    wp<EffectChain> chain() const override { return nullptr; }

    bool isAudioPolicyReady() const override {
        return mManager.audioFlinger().isAudioPolicyReady();
    }

    int newEffectId() { return mManager.audioFlinger().nextUniqueId(AUDIO_UNIQUE_ID_USE_EFFECT); }

    status_t addEffectToHal(const struct audio_port_config *device,
            const sp<EffectHalInterface>& effect) {
        return mManager.addEffectToHal(device, effect);
    }
    status_t removeEffectFromHal(const struct audio_port_config *device,
            const sp<EffectHalInterface>& effect) {
        return mManager.removeEffectFromHal(device, effect);
    }
private:
    DeviceEffectManager& mManager;
};
