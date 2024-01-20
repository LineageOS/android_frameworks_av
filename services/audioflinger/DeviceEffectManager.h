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

#pragma once

#include "IAfEffect.h"
#include "PatchCommandThread.h"

namespace android {

class IAfDeviceEffectManagerCallback : public virtual RefBase {
public:
    virtual bool isAudioPolicyReady() const = 0;
    virtual audio_unique_id_t nextUniqueId(audio_unique_id_use_t use) = 0;
    virtual const sp<PatchCommandThread>& getPatchCommandThread() = 0;
    virtual status_t addEffectToHal(
            const struct audio_port_config* device, const sp<EffectHalInterface>& effect)
            EXCLUDES_AudioFlinger_HardwareMutex = 0;
    virtual status_t removeEffectFromHal(
            const struct audio_port_config* device, const sp<EffectHalInterface>& effect)
            EXCLUDES_AudioFlinger_HardwareMutex= 0;
};

class DeviceEffectManagerCallback;

// DeviceEffectManager is concealed within AudioFlinger, their lifetimes are the same.
class DeviceEffectManager : public PatchCommandThread::PatchCommandListener {
public:
    explicit DeviceEffectManager(
            const sp<IAfDeviceEffectManagerCallback>& afDeviceEffectManagerCallback);

    void onFirstRef() override;

    sp<IAfEffectHandle> createEffect_l(effect_descriptor_t *descriptor,
                const AudioDeviceTypeAddr& device,
                const sp<Client>& client,
                const sp<media::IEffectClient>& effectClient,
                const std::map<audio_patch_handle_t, IAfPatchPanel::Patch>& patches,
                int *enabled,
                status_t *status,
                bool probe,
                bool notifyFramesProcessed) REQUIRES(audio_utils::AudioFlinger_Mutex);

    size_t removeEffect(const sp<IAfDeviceEffectProxy>& effect);
    static status_t createEffectHal(const effect_uuid_t *pEffectUuid,
           int32_t sessionId, int32_t deviceId,
           sp<EffectHalInterface> *effect);
    status_t addEffectToHal(const struct audio_port_config *device,
            const sp<EffectHalInterface>& effect);
    status_t removeEffectFromHal(const struct audio_port_config *device,
            const sp<EffectHalInterface>& effect);

    const auto& afDeviceEffectManagerCallback() const { return mAfDeviceEffectManagerCallback; }

    void dump(int fd);

    // PatchCommandThread::PatchCommandListener implementation

    void onCreateAudioPatch(audio_patch_handle_t handle,
            const IAfPatchPanel::Patch& patch) final
            EXCLUDES_DeviceEffectManager_Mutex;
    void onReleaseAudioPatch(audio_patch_handle_t handle) final
            EXCLUDES_DeviceEffectManager_Mutex;
    void onUpdateAudioPatch(audio_patch_handle_t oldHandle,
            audio_patch_handle_t newHandle, const IAfPatchPanel::Patch& patch) final
            EXCLUDES_DeviceEffectManager_Mutex;

private:
    static status_t checkEffectCompatibility(const effect_descriptor_t *desc);

    audio_utils::mutex& mutex() const RETURN_CAPABILITY(audio_utils::DeviceEffectManager_Mutex) {
       return mMutex;
   }
    mutable audio_utils::mutex mMutex{audio_utils::MutexOrder::kDeviceEffectManager_Mutex};
    const sp<IAfDeviceEffectManagerCallback> mAfDeviceEffectManagerCallback;
    const sp<DeviceEffectManagerCallback> mMyCallback;
    std::map<AudioDeviceTypeAddr, std::vector<sp<IAfDeviceEffectProxy>>>
            mDeviceEffects GUARDED_BY(mutex());
};

class DeviceEffectManagerCallback : public EffectCallbackInterface {
public:
    explicit DeviceEffectManagerCallback(DeviceEffectManager& manager)
        : mManager(manager) {}

    status_t createEffectHal(const effect_uuid_t *pEffectUuid,
            int32_t sessionId, int32_t deviceId, sp<EffectHalInterface> *effect) final {
                return mManager.createEffectHal(pEffectUuid, sessionId, deviceId, effect);
            }
    status_t allocateHalBuffer(size_t size __unused,
            sp<EffectBufferHalInterface>* buffer __unused) final { return NO_ERROR; }
    bool updateOrphanEffectChains(const sp<IAfEffectBase>& effect __unused) final {
        return false;
    }

    audio_io_handle_t io() const final { return AUDIO_IO_HANDLE_NONE; }
    bool isOutput() const final { return false; }
    bool isOffload() const final { return false; }
    bool isOffloadOrDirect() const final { return false; }
    bool isOffloadOrMmap() const final { return false; }
    bool isSpatializer() const final { return false; }

    uint32_t sampleRate() const final { return 0; }
    audio_channel_mask_t inChannelMask(int id __unused) const final {
        return AUDIO_CHANNEL_NONE;
    }
    uint32_t inChannelCount(int id __unused) const final { return 0; }
    audio_channel_mask_t outChannelMask() const final { return AUDIO_CHANNEL_NONE; }
    uint32_t outChannelCount() const final { return 0; }

    audio_channel_mask_t hapticChannelMask() const final { return AUDIO_CHANNEL_NONE; }
    size_t frameCount() const final { return 0; }
    uint32_t latency() const final { return 0; }

    status_t addEffectToHal(const sp<EffectHalInterface>& /* effect */) final {
        return NO_ERROR;
    }
    status_t removeEffectFromHal(const sp<EffectHalInterface>& /* effect */) final {
        return NO_ERROR;
    }

    bool disconnectEffectHandle(IAfEffectHandle *handle, bool unpinIfLast) final;
    void setVolumeForOutput(float left __unused, float right __unused) const final {}

    // check if effects should be suspended or restored when a given effect is enable or disabled
    void checkSuspendOnEffectEnabled(const sp<IAfEffectBase>& effect __unused,
                          bool enabled __unused, bool threadLocked __unused) final {}
    void resetVolume_l() final REQUIRES(audio_utils::EffectChain_Mutex) {}
    product_strategy_t strategy() const final { return static_cast<product_strategy_t>(0); }
    int32_t activeTrackCnt() const final { return 0; }
    void onEffectEnable(const sp<IAfEffectBase>& effect __unused) final {}
    void onEffectDisable(const sp<IAfEffectBase>& effect __unused) final {}

    wp<IAfEffectChain> chain() const final { return nullptr; }

    bool isAudioPolicyReady() const final;

    int newEffectId() const;

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

}  // namespace android
