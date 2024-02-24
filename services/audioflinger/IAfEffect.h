/*
 * Copyright (C) 2023 The Android Open Source Project
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

#pragma once

#include "IAfPatchPanel.h"  // full class Patch definition needed

#include <android/media/AudioVibratorInfo.h>
#include <android/media/BnEffect.h>
#include <android/media/BnEffectClient.h>
#include <audio_utils/mutex.h>
#include <media/AudioCommonTypes.h>  // product_strategy_t
#include <media/AudioDeviceTypeAddr.h>
#include <media/audiohal/EffectHalInterface.h>
#include <utils/RefBase.h>
#include <vibrator/ExternalVibration.h>

namespace android {

class Client;
class DeviceEffectManagerCallback;

class IAfDeviceEffectProxy;
class IAfEffectBase;
class IAfEffectChain;
class IAfEffectHandle;
class IAfEffectModule;
class IAfThreadBase;

// Interface implemented by the EffectModule parent or owner (e.g an EffectChain) to abstract
// interactions between the EffectModule and the reset of the audio framework.
class EffectCallbackInterface : public RefBase {
public:
    // Trivial methods usually implemented with help from ThreadBase
    virtual audio_io_handle_t io() const = 0;
    virtual bool isOutput() const = 0;
    virtual bool isOffload() const = 0;
    virtual bool isOffloadOrDirect() const = 0;
    virtual bool isOffloadOrMmap() const = 0;
    virtual bool isSpatializer() const = 0;
    virtual uint32_t sampleRate() const = 0;
    virtual audio_channel_mask_t inChannelMask(int id) const = 0;
    virtual uint32_t inChannelCount(int id) const = 0;
    virtual audio_channel_mask_t outChannelMask() const = 0;
    virtual uint32_t outChannelCount() const = 0;
    virtual audio_channel_mask_t hapticChannelMask() const = 0;
    virtual size_t frameCount() const = 0;

    // Non trivial methods usually implemented with help from ThreadBase:
    // pay attention to mutex locking order
    virtual uint32_t latency() const { return 0; }
    virtual status_t addEffectToHal(const sp<EffectHalInterface>& effect) = 0;
    virtual status_t removeEffectFromHal(const sp<EffectHalInterface>& effect) = 0;
    virtual void setVolumeForOutput(float left, float right) const = 0;
    virtual bool disconnectEffectHandle(IAfEffectHandle *handle, bool unpinIfLast) = 0;
    virtual void checkSuspendOnEffectEnabled(
            const sp<IAfEffectBase>& effect, bool enabled, bool threadLocked) = 0;
    virtual void onEffectEnable(const sp<IAfEffectBase>& effect) = 0;
    virtual void onEffectDisable(const sp<IAfEffectBase>& effect) = 0;

    // Methods usually implemented with help from AudioFlinger: pay attention to mutex locking order
    virtual status_t createEffectHal(const effect_uuid_t *pEffectUuid,
            int32_t sessionId, int32_t deviceId, sp<EffectHalInterface> *effect) = 0;
    virtual status_t allocateHalBuffer(size_t size, sp<EffectBufferHalInterface>* buffer) = 0;
    virtual bool updateOrphanEffectChains(const sp<IAfEffectBase>& effect) = 0;

    // Methods usually implemented with help from EffectChain: pay attention to mutex locking order
    virtual product_strategy_t strategy() const = 0;
    virtual int32_t activeTrackCnt() const = 0;
    virtual void resetVolume_l() REQUIRES(audio_utils::EffectChain_Mutex) = 0;
    virtual wp<IAfEffectChain> chain() const = 0;
    virtual bool isAudioPolicyReady() const = 0;
};

class IAfEffectBase : public virtual RefBase {
    friend class EffectChain;
    friend class EffectHandle;

public:
    enum effect_state {
        IDLE,
        RESTART,
        STARTING,
        ACTIVE,
        STOPPING,
        STOPPED,
        DESTROYED
    };
    virtual int id() const = 0;
    virtual effect_state state() const = 0;
    virtual audio_session_t sessionId() const = 0;
    virtual const effect_descriptor_t& desc() const = 0;
    virtual bool isOffloadable() const = 0;
    virtual bool isImplementationSoftware() const = 0;
    virtual bool isProcessImplemented() const = 0;
    virtual bool isVolumeControl() const REQUIRES(audio_utils::EffectChain_Mutex) = 0;
    virtual bool isVolumeMonitor() const = 0;
    virtual bool isEnabled() const = 0;
    virtual bool isPinned() const = 0;
    virtual void unPin() = 0;
    virtual status_t updatePolicyState() EXCLUDES_EffectBase_Mutex = 0;
    virtual bool purgeHandles() EXCLUDES_EffectBase_Mutex = 0;
    virtual void checkSuspendOnEffectEnabled(bool enabled, bool threadLocked) = 0;

    // mCallback is atomic so this can be lock-free.
    virtual void setCallback(const sp<EffectCallbackInterface>& callback) = 0;
    virtual sp<EffectCallbackInterface> getCallback() const = 0;

    virtual status_t addHandle(IAfEffectHandle* handle) EXCLUDES_EffectBase_Mutex = 0;
    virtual ssize_t removeHandle(IAfEffectHandle* handle) EXCLUDES_EffectBase_Mutex = 0;

    virtual sp<IAfEffectModule> asEffectModule() = 0;
    virtual sp<IAfDeviceEffectProxy> asDeviceEffectProxy() = 0;

    virtual status_t command(int32_t cmdCode, const std::vector<uint8_t>& cmdData,
                             int32_t maxReplySize, std::vector<uint8_t>* reply)
            EXCLUDES(audio_utils::EffectBase_Mutex) = 0;

    virtual void dump(int fd, const Vector<String16>& args) const = 0;

private:
    virtual status_t setEnabled(bool enabled, bool fromHandle) EXCLUDES_EffectBase_Mutex = 0;
    virtual status_t setEnabled_l(bool enabled) REQUIRES(audio_utils::EffectBase_Mutex) = 0;
    virtual void setSuspended(bool suspended) EXCLUDES_EffectBase_Mutex = 0;
    virtual bool suspended() const EXCLUDES_EffectBase_Mutex = 0;

    virtual ssize_t disconnectHandle(IAfEffectHandle* handle,
                                     bool unpinIfLast) EXCLUDES_EffectBase_Mutex = 0;
    virtual ssize_t removeHandle_l(IAfEffectHandle* handle)
            REQUIRES(audio_utils::EffectBase_Mutex) = 0;
    virtual IAfEffectHandle* controlHandle_l() REQUIRES(audio_utils::EffectBase_Mutex) = 0;

    virtual audio_utils::mutex& mutex() const
            RETURN_CAPABILITY(android::audio_utils::EffectBase_Mutex) = 0;
};

class IAfEffectModule : public virtual IAfEffectBase {
    friend class DeviceEffectProxy;
    friend class EffectChain;

public:
    static sp<IAfEffectModule> create(
            const sp<EffectCallbackInterface>& callabck,
            effect_descriptor_t *desc,
            int id,
            audio_session_t sessionId,
            bool pinned,
            audio_port_handle_t deviceId);

    virtual int16_t *inBuffer() const = 0;
    virtual status_t setDevices(const AudioDeviceTypeAddrVector &devices) = 0;
    virtual status_t setInputDevice(const AudioDeviceTypeAddr &device) = 0;
    virtual status_t setVolume(uint32_t *left, uint32_t *right, bool controller) = 0;
    virtual status_t setOffloaded_l(bool offloaded, audio_io_handle_t io) = 0;
    virtual bool isOffloaded_l() const = 0;

    virtual status_t setAudioSource(audio_source_t source) = 0;
    virtual status_t setMode(audio_mode_t mode) = 0;

    virtual status_t start_l() = 0;
    virtual status_t getConfigs_l(audio_config_base_t* inputCfg, audio_config_base_t* outputCfg,
                                  bool* isOutput) const
            REQUIRES(audio_utils::EffectHandle_Mutex) EXCLUDES_EffectBase_Mutex = 0;

    static bool isHapticGenerator(const effect_uuid_t* type);
    virtual bool isHapticGenerator() const = 0;
    static bool isSpatializer(const effect_uuid_t* type);
    virtual bool isSpatializer() const = 0;

    virtual status_t setHapticScale_l(int id, os::HapticScale hapticScale)
            REQUIRES(audio_utils::ThreadBase_Mutex) EXCLUDES_EffectBase_Mutex = 0;
    virtual status_t setVibratorInfo_l(const media::AudioVibratorInfo& vibratorInfo)
            REQUIRES(audio_utils::ThreadBase_Mutex) EXCLUDES_EffectBase_Mutex = 0;
    virtual status_t sendMetadata_ll(const std::vector<playback_track_metadata_v7_t>& metadata)
            REQUIRES(audio_utils::ThreadBase_Mutex,
                     audio_utils::EffectChain_Mutex) EXCLUDES_EffectBase_Mutex = 0;

private:
    virtual void process() = 0;
    virtual bool updateState_l()
            REQUIRES(audio_utils::EffectChain_Mutex) EXCLUDES_EffectBase_Mutex = 0;
    virtual void reset_l() REQUIRES(audio_utils::EffectChain_Mutex) = 0;
    virtual status_t configure_l() REQUIRES(audio_utils::EffectChain_Mutex) = 0;
    virtual status_t init_l()
            REQUIRES(audio_utils::EffectChain_Mutex) EXCLUDES_EffectBase_Mutex = 0;
    virtual uint32_t status() const = 0;
    virtual bool isProcessEnabled() const = 0;
    virtual bool isOffloadedOrDirect_l() const REQUIRES(audio_utils::EffectChain_Mutex) = 0;
    virtual bool isVolumeControlEnabled_l() const REQUIRES(audio_utils::EffectChain_Mutex) = 0;

    virtual void setInBuffer(const sp<EffectBufferHalInterface>& buffer) = 0;
    virtual void setOutBuffer(const sp<EffectBufferHalInterface>& buffer) = 0;
    virtual int16_t *outBuffer() const = 0;

    // Updates the access mode if it is out of date.  May issue a new effect configure.
    virtual void updateAccessMode_l() = 0;

    virtual status_t stop_l() = 0;
    virtual void addEffectToHal_l() = 0;
    virtual void release_l() = 0;
};

class IAfEffectChain : public RefBase {
    // Most of these methods are accessed from AudioFlinger::Thread
public:
    static sp<IAfEffectChain> create(
            const sp<IAfThreadBase>& thread,
            audio_session_t sessionId);

    // special key used for an entry in mSuspendedEffects keyed vector
    // corresponding to a suspend all request.
    static constexpr int kKeyForSuspendAll = 0;

    // minimum duration during which we force calling effect process when last track on
    // a session is stopped or removed to allow effect tail to be rendered
    static constexpr int kProcessTailDurationMs = 1000;

    virtual void process_l() REQUIRES(audio_utils::EffectChain_Mutex) = 0;

    virtual audio_utils::mutex& mutex() const RETURN_CAPABILITY(audio_utils::EffectChain_Mutex) = 0;

    virtual status_t createEffect_l(sp<IAfEffectModule>& effect, effect_descriptor_t* desc, int id,
                                    audio_session_t sessionId, bool pinned)
            REQUIRES(audio_utils::ThreadBase_Mutex) EXCLUDES_EffectChain_Mutex = 0;

    virtual status_t addEffect_l(const sp<IAfEffectModule>& handle)
            REQUIRES(audio_utils::ThreadBase_Mutex) EXCLUDES_EffectChain_Mutex = 0;
    virtual status_t addEffect_ll(const sp<IAfEffectModule>& handle)
            REQUIRES(audio_utils::ThreadBase_Mutex, audio_utils::EffectChain_Mutex) = 0;
    virtual size_t removeEffect_l(const sp<IAfEffectModule>& handle,
                                  bool release = false) EXCLUDES_EffectChain_Mutex = 0;

    virtual audio_session_t sessionId() const = 0;
    virtual void setSessionId(audio_session_t sessionId) = 0;

    virtual sp<IAfEffectModule> getEffectFromDesc_l(effect_descriptor_t* descriptor) const
            REQUIRES(audio_utils::ThreadBase_Mutex) = 0;
    virtual sp<IAfEffectModule> getEffectFromId_l(int id) const
            REQUIRES(audio_utils::ThreadBase_Mutex) = 0;
    virtual sp<IAfEffectModule> getEffectFromType_l(const effect_uuid_t* type) const
            REQUIRES(audio_utils::ThreadBase_Mutex) = 0;
    virtual std::vector<int> getEffectIds_l() const = 0;
    virtual bool setVolume(uint32_t* left, uint32_t* right,
                           bool force = false) EXCLUDES_EffectChain_Mutex = 0;
    virtual void resetVolume_l() REQUIRES(audio_utils::EffectChain_Mutex) = 0;
    virtual void setDevices_l(const AudioDeviceTypeAddrVector& devices)
            REQUIRES(audio_utils::ThreadBase_Mutex) = 0;
    virtual void setInputDevice_l(const AudioDeviceTypeAddr& device)
            REQUIRES(audio_utils::ThreadBase_Mutex) = 0;
    virtual void setMode_l(audio_mode_t mode) REQUIRES(audio_utils::ThreadBase_Mutex) = 0;
    virtual void setAudioSource_l(audio_source_t source)
            REQUIRES(audio_utils::ThreadBase_Mutex) = 0;

    virtual void setInBuffer(const sp<EffectBufferHalInterface>& buffer) = 0;
    virtual float *inBuffer() const = 0;
    virtual void setOutBuffer(const sp<EffectBufferHalInterface>& buffer) = 0;
    virtual float *outBuffer() const = 0;

    virtual void incTrackCnt() = 0;
    virtual void decTrackCnt() = 0;
    virtual int32_t trackCnt() const = 0;

    virtual void incActiveTrackCnt() = 0;
    virtual void decActiveTrackCnt() = 0;
    virtual int32_t activeTrackCnt() const = 0;

    virtual product_strategy_t strategy() const = 0;
    virtual void setStrategy(product_strategy_t strategy) = 0;

    // suspend or restore effects of the specified type. The number of suspend requests is counted
    // and restore occurs once all suspend requests are cancelled.
    virtual void setEffectSuspended_l(const effect_uuid_t* type, bool suspend) = 0;
    // suspend all eligible effects
    virtual void setEffectSuspendedAll_l(bool suspend) = 0;
    // check if effects should be suspended or restored when a given effect is enable or disabled
    virtual void checkSuspendOnEffectEnabled_l(const sp<IAfEffectModule>& effect, bool enabled)
            REQUIRES(audio_utils::ThreadBase_Mutex) REQUIRES(audio_utils::ThreadBase_Mutex) = 0;

    virtual void clearInputBuffer() EXCLUDES_EffectChain_Mutex = 0;

    // At least one non offloadable effect in the chain is enabled
    virtual bool isNonOffloadableEnabled() const EXCLUDES_EffectChain_Mutex = 0;
    virtual bool isNonOffloadableEnabled_l() const REQUIRES(audio_utils::EffectChain_Mutex) = 0;

    virtual void syncHalEffectsState_l()
            REQUIRES(audio_utils::ThreadBase_Mutex) EXCLUDES_EffectChain_Mutex = 0;

    // flags is an ORed set of audio_output_flags_t which is updated on return.
    virtual void checkOutputFlagCompatibility(audio_output_flags_t *flags) const = 0;

    // flags is an ORed set of audio_input_flags_t which is updated on return.
    virtual void checkInputFlagCompatibility(audio_input_flags_t *flags) const = 0;

    // Is this EffectChain compatible with the RAW audio flag.
    virtual bool isRawCompatible() const = 0;

    // Is this EffectChain compatible with the FAST audio flag.
    virtual bool isFastCompatible() const = 0;

    // Is this EffectChain compatible with the bit-perfect audio flag.
    virtual bool isBitPerfectCompatible() const = 0;

    // isCompatibleWithThread_l() must be called with thread->mLock held
    virtual bool isCompatibleWithThread_l(const sp<IAfThreadBase>& thread) const
            REQUIRES(audio_utils::ThreadBase_Mutex) EXCLUDES_EffectChain_Mutex = 0;

    virtual bool containsHapticGeneratingEffect_l() = 0;

    virtual void setHapticScale_l(int id, os::HapticScale hapticScale)
            REQUIRES(audio_utils::ThreadBase_Mutex) EXCLUDES_EffectChain_Mutex = 0;

    virtual sp<EffectCallbackInterface> effectCallback() const = 0;

    virtual wp<IAfThreadBase> thread() const = 0;
    virtual void setThread(const sp<IAfThreadBase>& thread) EXCLUDES_EffectChain_Mutex = 0;

    virtual bool isFirstEffect(int id) const = 0;

    virtual size_t numberOfEffects() const = 0;
    virtual sp<IAfEffectModule> getEffectModule(size_t index) const = 0;

    // sendMetadata_l() must be called with thread->mLock held
    virtual void sendMetadata_l(const std::vector<playback_track_metadata_v7_t>& allMetadata,
        const std::optional<const std::vector<playback_track_metadata_v7_t>> spatializedMetadata);

    virtual void dump(int fd, const Vector<String16>& args) const = 0;
};

class IAfEffectHandle : public virtual RefBase {
    friend class EffectBase;
    friend class EffectChain;
    friend class EffectModule;

public:
    static sp<IAfEffectHandle> create(
            const sp<IAfEffectBase>& effect,
            const sp<Client>& client,
            const sp<media::IEffectClient>& effectClient,
            int32_t priority, bool notifyFramesProcessed);

    virtual status_t initCheck() const = 0;
    virtual bool enabled() const = 0;
    virtual int id() const = 0;
    virtual wp<IAfEffectBase> effect() const = 0;
    virtual sp<android::media::IEffect> asIEffect() = 0;
    virtual const sp<Client>& client() const = 0;

private:
    virtual void setControl(bool hasControl, bool signal, bool enabled) = 0;
    virtual bool hasControl() const = 0;
    virtual void setEnabled(bool enabled) = 0;
    virtual bool disconnected() const = 0;
    virtual int priority() const = 0;

    virtual void commandExecuted(uint32_t cmdCode,
            const std::vector<uint8_t>& cmdData,
            const std::vector<uint8_t>& replyData) = 0;
    virtual void framesProcessed(int32_t frames) const = 0;

    virtual void dumpToBuffer(char* buffer, size_t size) const = 0;
};

class IAfDeviceEffectProxy : public virtual IAfEffectBase {
public:
    static sp<IAfDeviceEffectProxy> create(const AudioDeviceTypeAddr& device,
                const sp<DeviceEffectManagerCallback>& callback,
                effect_descriptor_t *desc, int id, bool notifyFramesProcessed);

    virtual status_t init_l(const std::map<audio_patch_handle_t, IAfPatchPanel::Patch>& patches)
            REQUIRES(audio_utils::DeviceEffectManager_Mutex) EXCLUDES_EffectBase_Mutex = 0;
    virtual const AudioDeviceTypeAddr& device() const = 0;

    virtual status_t onCreatePatch(
            audio_patch_handle_t patchHandle,
            const IAfPatchPanel::Patch& patch) = 0;
    virtual status_t onUpdatePatch(audio_patch_handle_t oldPatchHandle,
            audio_patch_handle_t newPatchHandle,
            const IAfPatchPanel::Patch& patch) = 0;
    virtual void onReleasePatch(audio_patch_handle_t patchHandle) = 0;

    virtual void dump2(int fd, int spaces) const = 0; // TODO(b/291319101) naming?

private:
    // used by DeviceEffectProxy
    virtual bool isOutput() const = 0;
    virtual uint32_t sampleRate() const = 0;
    virtual audio_channel_mask_t channelMask() const = 0;
    virtual uint32_t channelCount() const = 0;

    virtual size_t removeEffect(const sp<IAfEffectModule>& effect) = 0;
    virtual status_t addEffectToHal(const sp<EffectHalInterface>& effect) = 0;
    virtual status_t removeEffectFromHal(const sp<EffectHalInterface>& effect) = 0;
};

}  // namespace android
