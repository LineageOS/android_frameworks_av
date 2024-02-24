/*
**
** Copyright 2012, The Android Open Source Project
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

#include "DeviceEffectManager.h"
#include "IAfEffect.h"

#include <android-base/macros.h>  // DISALLOW_COPY_AND_ASSIGN
#include <mediautils/Synchronization.h>
#include <private/media/AudioEffectShared.h>

#include <map>  // avoid transitive dependency

namespace android {

//--- Audio Effect Management

// EffectBase(EffectModule) and EffectChain classes both have their own mutex to protect
// state changes or resource modifications. Always respect the following order
// if multiple mutexes must be acquired to avoid cross deadlock:
// AudioFlinger -> ThreadBase -> EffectChain -> EffectBase(EffectModule)
// AudioHandle -> ThreadBase -> EffectChain -> EffectBase(EffectModule)

// NOTE: When implementing the EffectCallbackInterface, in an EffectChain or other, it is important
// to pay attention to this locking order as some callback methods can be called from a state where
// EffectModule and/or EffectChain mutexes are held.

// In addition, methods that lock the AudioPolicyService mutex (getOutputForEffect(),
// startOutput(), getInputForAttr(), releaseInput()...) should never be called with AudioFlinger or
// Threadbase mutex locked to avoid cross deadlock with other clients calling AudioPolicyService
// methods that in turn call AudioFlinger thus locking the same mutexes in the reverse order.


// The EffectBase class contains common properties, state and behavior for and EffectModule or
// other derived classes managing an audio effect instance within the effect framework.
// It also contains the class mutex (see comment on locking order above).
class EffectBase : public virtual IAfEffectBase {
public:
    EffectBase(const sp<EffectCallbackInterface>& callback,
               effect_descriptor_t *desc,
               int id,
               audio_session_t sessionId,
               bool pinned);

    int id() const final { return mId; }
    effect_state state() const final {
        return mState;
    }
    audio_session_t sessionId() const final {
        return mSessionId;
    }
    const effect_descriptor_t& desc() const final { return mDescriptor; }
    bool isOffloadable() const final
                        { return (mDescriptor.flags & EFFECT_FLAG_OFFLOAD_SUPPORTED) != 0; }
    bool isImplementationSoftware() const final
                        { return (mDescriptor.flags & EFFECT_FLAG_HW_ACC_MASK) == 0; }
    bool isProcessImplemented() const final
                        { return (mDescriptor.flags & EFFECT_FLAG_NO_PROCESS) == 0; }
    bool isVolumeControl() const
                        { return (mDescriptor.flags & EFFECT_FLAG_VOLUME_MASK)
                            == EFFECT_FLAG_VOLUME_CTRL; }
    bool isVolumeMonitor() const final
                        { return (mDescriptor.flags & EFFECT_FLAG_VOLUME_MASK)
                            == EFFECT_FLAG_VOLUME_MONITOR; }

    status_t setEnabled(bool enabled, bool fromHandle) override EXCLUDES_EffectBase_Mutex;
    status_t setEnabled_l(bool enabled) final REQUIRES(audio_utils::EffectBase_Mutex);
    bool isEnabled() const final;
    void setSuspended(bool suspended) final EXCLUDES_EffectBase_Mutex;
    bool suspended() const final EXCLUDES_EffectBase_Mutex;

    status_t command(int32_t __unused,
                             const std::vector<uint8_t>& __unused,
                             int32_t __unused,
                             std::vector<uint8_t>* __unused) override {
        return NO_ERROR;
    }

    // mCallback is atomic so this can be lock-free.
    void setCallback(const sp<EffectCallbackInterface>& callback) final {
        mCallback = callback;
    }
    sp<EffectCallbackInterface> getCallback() const final {
        return mCallback.load();
    }

    status_t addHandle(IAfEffectHandle* handle) final EXCLUDES_EffectBase_Mutex;
    ssize_t disconnectHandle(IAfEffectHandle* handle,
                             bool unpinIfLast) final EXCLUDES_EffectBase_Mutex;
    ssize_t removeHandle(IAfEffectHandle* handle) final EXCLUDES_EffectBase_Mutex;
    ssize_t removeHandle_l(IAfEffectHandle* handle) final REQUIRES(audio_utils::EffectBase_Mutex);
    IAfEffectHandle* controlHandle_l() final REQUIRES(audio_utils::EffectBase_Mutex);
    bool purgeHandles() final EXCLUDES_EffectBase_Mutex;

    void checkSuspendOnEffectEnabled(bool enabled, bool threadLocked) final;

    bool isPinned() const final { return mPinned; }
    void unPin() final { mPinned = false; }

    audio_utils::mutex& mutex() const final
            RETURN_CAPABILITY(android::audio_utils::EffectBase_Mutex) {
        return mMutex;
    }

    status_t updatePolicyState() final EXCLUDES_EffectBase_Mutex;

    sp<IAfEffectModule> asEffectModule() override { return nullptr; }
    sp<IAfDeviceEffectProxy> asDeviceEffectProxy() override { return nullptr; }

    void dump(int fd, const Vector<String16>& args) const override;

protected:
    bool isInternal_l() const REQUIRES(audio_utils::EffectBase_Mutex) {
        for (auto handle : mHandles) {
            if (handle->client() != nullptr) {
                return false;
            }
        }
        return true;
    }

    bool             mPinned = false;

    DISALLOW_COPY_AND_ASSIGN(EffectBase);

    // mutex for process, commands and handles list protection
    mutable audio_utils::mutex mMutex{audio_utils::MutexOrder::kEffectBase_Mutex};
    mediautils::atomic_sp<EffectCallbackInterface> mCallback; // parent effect chain
    const int                 mId;        // this instance unique ID
    const audio_session_t     mSessionId; // audio session ID
    const effect_descriptor_t mDescriptor;// effect descriptor received from effect engine
    effect_state              mState = IDLE; // current activation state
    // effect is suspended: temporarily disabled by framework
    bool                      mSuspended = false;

    Vector<IAfEffectHandle *> mHandles;  // list of client handles
                // First handle in mHandles has highest priority and controls the effect module

    // Audio policy effect state management
    // Mutex protecting transactions with audio policy manager as mutex() cannot
    // be held to avoid cross deadlocks with audio policy mutex
    audio_utils::mutex& policyMutex() const
            RETURN_CAPABILITY(android::audio_utils::EffectBase_PolicyMutex) {
        return mPolicyMutex;
    }
    mutable audio_utils::mutex mPolicyMutex{audio_utils::MutexOrder::kEffectBase_PolicyMutex};
    // Effect is registered in APM or not
    bool                      mPolicyRegistered = false;
    // Effect enabled state communicated to APM. Enabled state corresponds to
    // state requested by the EffectHandle with control
    bool                      mPolicyEnabled = false;
};

// The EffectModule class is a wrapper object controlling the effect engine implementation
// in the effect library. It prevents concurrent calls to process() and command() functions
// from different client threads. It keeps a list of EffectHandle objects corresponding
// to all client applications using this effect and notifies applications of effect state,
// control or parameter changes. It manages the activation state machine to send appropriate
// reset, enable, disable commands to effect engine and provide volume
// ramping when effects are activated/deactivated.
// When controlling an auxiliary effect, the EffectModule also provides an input buffer used by
// the attached track(s) to accumulate their auxiliary channel.
class EffectModule : public IAfEffectModule, public EffectBase {
public:
    EffectModule(const sp<EffectCallbackInterface>& callabck,
                    effect_descriptor_t *desc,
                    int id,
                    audio_session_t sessionId,
                    bool pinned,
                    audio_port_handle_t deviceId) REQUIRES(audio_utils::EffectChain_Mutex);
    ~EffectModule() override REQUIRES(audio_utils::EffectChain_Mutex);

    void process() final EXCLUDES_EffectBase_Mutex;
    bool updateState_l() final REQUIRES(audio_utils::EffectChain_Mutex) EXCLUDES_EffectBase_Mutex;
    status_t command(int32_t cmdCode, const std::vector<uint8_t>& cmdData, int32_t maxReplySize,
                     std::vector<uint8_t>* reply) final EXCLUDES_EffectBase_Mutex;

    void reset_l() final REQUIRES(audio_utils::EffectBase_Mutex);
    status_t configure_l() final REQUIRES(audio_utils::EffectChain_Mutex);
    status_t init_l() final REQUIRES(audio_utils::EffectChain_Mutex) EXCLUDES_EffectBase_Mutex;
    uint32_t status() const final {
        return mStatus;
    }
    bool isProcessEnabled() const final;
    bool isOffloadedOrDirect_l() const final REQUIRES(audio_utils::EffectChain_Mutex);
    bool isVolumeControlEnabled_l() const final REQUIRES(audio_utils::EffectChain_Mutex);
    void setInBuffer(const sp<EffectBufferHalInterface>& buffer) final;
    int16_t *inBuffer() const final {
        return mInBuffer != 0 ? reinterpret_cast<int16_t*>(mInBuffer->ptr()) : NULL;
    }
    void setOutBuffer(const sp<EffectBufferHalInterface>& buffer) final;
    int16_t *outBuffer() const final {
        return mOutBuffer != 0 ? reinterpret_cast<int16_t*>(mOutBuffer->ptr()) : NULL;
    }
    // Updates the access mode if it is out of date.  May issue a new effect configure.
    void updateAccessMode_l() final REQUIRES(audio_utils::EffectChain_Mutex) {
        if (requiredEffectBufferAccessMode() != mConfig.outputCfg.accessMode) {
            configure_l();
        }
    }
    status_t setDevices(const AudioDeviceTypeAddrVector& devices) final EXCLUDES_EffectBase_Mutex;
    status_t setInputDevice(const AudioDeviceTypeAddr& device) final EXCLUDES_EffectBase_Mutex;
    status_t setVolume(uint32_t *left, uint32_t *right, bool controller) final;
    status_t setMode(audio_mode_t mode) final EXCLUDES_EffectBase_Mutex;
    status_t setAudioSource(audio_source_t source) final EXCLUDES_EffectBase_Mutex;
    status_t start_l() final REQUIRES(audio_utils::EffectChain_Mutex) EXCLUDES_EffectBase_Mutex;
    status_t stop_l() final REQUIRES(audio_utils::EffectChain_Mutex) EXCLUDES_EffectBase_Mutex;

    status_t setOffloaded_l(bool offloaded, audio_io_handle_t io) final
            REQUIRES(audio_utils::EffectChain_Mutex) EXCLUDES_EffectBase_Mutex;
    bool isOffloaded_l() const final
            REQUIRES(audio_utils::EffectChain_Mutex) EXCLUDES_EffectBase_Mutex;
    void addEffectToHal_l() final REQUIRES(audio_utils::EffectChain_Mutex);
    void release_l() final REQUIRES(audio_utils::EffectChain_Mutex);

    sp<IAfEffectModule> asEffectModule() final { return this; }

    bool isHapticGenerator() const final;
    bool isSpatializer() const final;

    status_t setHapticScale_l(int id, os::HapticScale hapticScale) final
            REQUIRES(audio_utils::ThreadBase_Mutex) EXCLUDES_EffectBase_Mutex;
    status_t setVibratorInfo_l(const media::AudioVibratorInfo& vibratorInfo) final
            REQUIRES(audio_utils::ThreadBase_Mutex) EXCLUDES_EffectBase_Mutex;
    status_t sendMetadata_ll(const std::vector<playback_track_metadata_v7_t>& metadata) final
            REQUIRES(audio_utils::ThreadBase_Mutex,
                     audio_utils::EffectChain_Mutex) EXCLUDES_EffectBase_Mutex;

    status_t getConfigs_l(audio_config_base_t* inputCfg, audio_config_base_t* outputCfg,
                          bool* isOutput) const final
            REQUIRES(audio_utils::EffectHandle_Mutex) EXCLUDES_EffectBase_Mutex;

    void dump(int fd, const Vector<String16>& args) const final;

private:

    // Maximum time allocated to effect engines to complete the turn off sequence
    static const uint32_t MAX_DISABLE_TIME_MS = 10000;

    DISALLOW_COPY_AND_ASSIGN(EffectModule);

    status_t start_ll() REQUIRES(audio_utils::EffectChain_Mutex, audio_utils::EffectBase_Mutex);
    status_t stop_ll() REQUIRES(audio_utils::EffectChain_Mutex, audio_utils::EffectBase_Mutex);
    status_t removeEffectFromHal_l() REQUIRES(audio_utils::EffectChain_Mutex);
    status_t sendSetAudioDevicesCommand(const AudioDeviceTypeAddrVector &devices, uint32_t cmdCode);
    effect_buffer_access_e requiredEffectBufferAccessMode() const {
        return mConfig.inputCfg.buffer.raw == mConfig.outputCfg.buffer.raw
                ? EFFECT_BUFFER_ACCESS_WRITE : EFFECT_BUFFER_ACCESS_ACCUMULATE;
    }

    status_t setVolumeInternal(uint32_t *left, uint32_t *right, bool controller);


    effect_config_t     mConfig;    // input and output audio configuration
    sp<EffectHalInterface> mEffectInterface; // Effect module HAL
    sp<EffectBufferHalInterface> mInBuffer;  // Buffers for interacting with HAL
    sp<EffectBufferHalInterface> mOutBuffer;
    status_t            mStatus;    // initialization status
                // First handle in mHandles has highest priority and controls the effect module
    uint32_t mMaxDisableWaitCnt;    // maximum grace period before forcing an effect off after
                                    // sending disable command.
    uint32_t mDisableWaitCnt;       // current process() calls count during disable period.
    bool     mOffloaded;            // effect is currently offloaded to the audio DSP
    // effect has been added to this HAL input stream
    audio_io_handle_t mCurrentHalStream = AUDIO_IO_HANDLE_NONE;
    bool     mIsOutput;             // direction of the AF thread

    bool    mSupportsFloat;         // effect supports float processing
    sp<EffectBufferHalInterface> mInConversionBuffer;  // Buffers for HAL conversion if needed.
    sp<EffectBufferHalInterface> mOutConversionBuffer;
    uint32_t mInChannelCountRequested;
    uint32_t mOutChannelCountRequested;

    template <typename MUTEX>
    class AutoLockReentrant {
    public:
        AutoLockReentrant(MUTEX& mutex, pid_t allowedTid)
            : mMutex(gettid() == allowedTid ? nullptr : &mutex)
        {
            if (mMutex != nullptr) mMutex->lock();
        }
        ~AutoLockReentrant() {
            if (mMutex != nullptr) mMutex->unlock();
        }
    private:
        MUTEX * const mMutex;
    };

    static constexpr pid_t INVALID_PID = (pid_t)-1;
    // this tid is allowed to call setVolume() without acquiring the mutex.
    pid_t mSetVolumeReentrantTid = INVALID_PID;
};

// The EffectHandle class implements the IEffect interface. It provides resources
// to receive parameter updates, keeps track of effect control
// ownership and state and has a pointer to the EffectModule object it is controlling.
// There is one EffectHandle object for each application controlling (or using)
// an effect module.
// The EffectHandle is obtained by calling AudioFlinger::createEffect().
class EffectHandle: public IAfEffectHandle, public android::media::BnEffect {
public:

    EffectHandle(const sp<IAfEffectBase>& effect,
            const sp<Client>& client,
            const sp<media::IEffectClient>& effectClient,
            int32_t priority, bool notifyFramesProcessed);
    ~EffectHandle() override;
    status_t onTransact(
            uint32_t code, const Parcel& data, Parcel* reply, uint32_t flags) final;
    status_t initCheck() const final;

    // IEffect
    android::binder::Status enable(int32_t* _aidl_return) final;
    android::binder::Status disable(int32_t* _aidl_return) final;
    android::binder::Status command(int32_t cmdCode,
                                    const std::vector<uint8_t>& cmdData,
                                    int32_t maxResponseSize,
                                    std::vector<uint8_t>* response,
                                    int32_t* _aidl_return) final;
    android::binder::Status disconnect() final;
    android::binder::Status getCblk(media::SharedFileRegion* _aidl_return) final;
    android::binder::Status getConfig(media::EffectConfig* _config,
                                      int32_t* _aidl_return) final;

    const sp<Client>& client() const final { return mClient; }

    sp<android::media::IEffect> asIEffect() final {
        return sp<android::media::IEffect>::fromExisting(this);
    }

private:
    void disconnect(bool unpinIfLast);

    // Give or take control of effect module
    // - hasControl: true if control is given, false if removed
    // - signal: true client app should be signaled of change, false otherwise
    // - enabled: state of the effect when control is passed
    void setControl(bool hasControl, bool signal, bool enabled) final;
    void commandExecuted(uint32_t cmdCode,
                         const std::vector<uint8_t>& cmdData,
                         const std::vector<uint8_t>& replyData) final;
    bool enabled() const final { return mEnabled; }
    void setEnabled(bool enabled) final;
    void framesProcessed(int32_t frames) const final;

public:
    // Getters
    wp<IAfEffectBase> effect() const final { return mEffect; }
    int id() const final {
        sp<IAfEffectBase> effect = mEffect.promote();
        if (effect == 0) {
            return 0;
        }
        return effect->id();
    }
private:
    int priority() const final { return mPriority; }
    bool hasControl() const final { return mHasControl; }
    bool disconnected() const final { return mDisconnected; }

    void dumpToBuffer(char* buffer, size_t size) const final;


private:
    DISALLOW_COPY_AND_ASSIGN(EffectHandle);

    audio_utils::mutex& mutex() const RETURN_CAPABILITY(android::audio_utils::EffectHandle_Mutex) {
        return mMutex;
    }
    // protects IEffect method calls
    mutable audio_utils::mutex mMutex{audio_utils::MutexOrder::kEffectHandle_Mutex};
    const wp<IAfEffectBase> mEffect;               // pointer to controlled EffectModule
    const sp<media::IEffectClient> mEffectClient;  // callback interface for client notifications
    /*const*/ sp<Client> mClient;            // client for shared memory allocation, see
                                             //   disconnect()
    sp<IMemory> mCblkMemory;                 // shared memory for control block
    effect_param_cblk_t* mCblk;              // control block for deferred parameter setting via
                                             // shared memory
    uint8_t* mBuffer;                        // pointer to parameter area in shared memory
    int mPriority;                           // client application priority to control the effect
    bool mHasControl;                        // true if this handle is controlling the effect
    bool mEnabled;                           // cached enable state: needed when the effect is
                                             // restored after being suspended
    bool mDisconnected;                      // Set to true by disconnect()
    const bool mNotifyFramesProcessed;       // true if the client callback event
                                             // EVENT_FRAMES_PROCESSED must be generated
};

// the EffectChain class represents a group of effects associated to one audio session.
// There can be any number of EffectChain objects per output mixer thread (PlaybackThread).
// The EffectChain with session ID AUDIO_SESSION_OUTPUT_MIX contains global effects applied
// to the output mix.
// Effects in this chain can be insert or auxiliary. Effects in other chains (attached to
// tracks) are insert only. The EffectChain maintains an ordered list of effect module, the
// order corresponding in the effect process order. When attached to a track (session ID !=
// AUDIO_SESSION_OUTPUT_MIX),
// it also provide it's own input buffer used by the track as accumulation buffer.
class EffectChain : public IAfEffectChain {
public:
    EffectChain(const sp<IAfThreadBase>& thread, audio_session_t sessionId);

    void process_l() final REQUIRES(audio_utils::EffectChain_Mutex);

    audio_utils::mutex& mutex() const final RETURN_CAPABILITY(audio_utils::EffectChain_Mutex) {
        return mMutex;
    }

    status_t createEffect_l(sp<IAfEffectModule>& effect, effect_descriptor_t* desc, int id,
                            audio_session_t sessionId, bool pinned) final
            REQUIRES(audio_utils::ThreadBase_Mutex) EXCLUDES_EffectChain_Mutex;
    status_t addEffect_l(const sp<IAfEffectModule>& handle) final
            REQUIRES(audio_utils::ThreadBase_Mutex) EXCLUDES_EffectChain_Mutex;
    status_t addEffect_ll(const sp<IAfEffectModule>& handle) final
            REQUIRES(audio_utils::ThreadBase_Mutex, audio_utils::EffectChain_Mutex);
    size_t removeEffect_l(const sp<IAfEffectModule>& handle, bool release = false) final
            REQUIRES(audio_utils::ThreadBase_Mutex) EXCLUDES_EffectChain_Mutex;

    audio_session_t sessionId() const final { return mSessionId; }
    void setSessionId(audio_session_t sessionId) final { mSessionId = sessionId; }

    sp<IAfEffectModule> getEffectFromDesc_l(effect_descriptor_t* descriptor) const final
            REQUIRES(audio_utils::ThreadBase_Mutex);
    sp<IAfEffectModule> getEffectFromId_l(int id) const final
            REQUIRES(audio_utils::ThreadBase_Mutex);
    sp<IAfEffectModule> getEffectFromType_l(const effect_uuid_t* type) const final
            REQUIRES(audio_utils::ThreadBase_Mutex);
    std::vector<int> getEffectIds_l() const final REQUIRES(audio_utils::ThreadBase_Mutex);
    // FIXME use float to improve the dynamic range

    bool setVolume(uint32_t* left, uint32_t* right,
                   bool force = false) final EXCLUDES_EffectChain_Mutex;
    void resetVolume_l() final REQUIRES(audio_utils::EffectChain_Mutex);
    void setDevices_l(const AudioDeviceTypeAddrVector& devices) final
            REQUIRES(audio_utils::ThreadBase_Mutex);
    void setInputDevice_l(const AudioDeviceTypeAddr& device) final
            REQUIRES(audio_utils::ThreadBase_Mutex);
    void setMode_l(audio_mode_t mode) final REQUIRES(audio_utils::ThreadBase_Mutex);
    void setAudioSource_l(audio_source_t source) final REQUIRES(audio_utils::ThreadBase_Mutex);

    void setInBuffer(const sp<EffectBufferHalInterface>& buffer) final {
        mInBuffer = buffer;
    }
    float *inBuffer() const final {
        return mInBuffer != 0 ? reinterpret_cast<float*>(mInBuffer->ptr()) : NULL;
    }
    void setOutBuffer(const sp<EffectBufferHalInterface>& buffer) final {
        mOutBuffer = buffer;
    }
    float *outBuffer() const final {
        return mOutBuffer != 0 ? reinterpret_cast<float*>(mOutBuffer->ptr()) : NULL;
    }
    void incTrackCnt() final { android_atomic_inc(&mTrackCnt); }
    void decTrackCnt() final { android_atomic_dec(&mTrackCnt); }
    int32_t trackCnt() const final { return android_atomic_acquire_load(&mTrackCnt); }

    void incActiveTrackCnt() final { android_atomic_inc(&mActiveTrackCnt);
                               mTailBufferCount = mMaxTailBuffers; }
    void decActiveTrackCnt() final { android_atomic_dec(&mActiveTrackCnt); }
    int32_t activeTrackCnt() const final {
        return android_atomic_acquire_load(&mActiveTrackCnt);
    }

    product_strategy_t strategy() const final { return mStrategy; }
    void setStrategy(product_strategy_t strategy) final
            { mStrategy = strategy; }

    // suspend or restore effects of the specified type. The number of suspend requests is counted
    // and restore occurs once all suspend requests are cancelled.
    void setEffectSuspended_l(const effect_uuid_t* type, bool suspend) final
            REQUIRES(audio_utils::ThreadBase_Mutex);
    // suspend all eligible effects
    void setEffectSuspendedAll_l(bool suspend) final REQUIRES(audio_utils::ThreadBase_Mutex);
    // check if effects should be suspended or restored when a given effect is enable or disabled
    void checkSuspendOnEffectEnabled_l(const sp<IAfEffectModule>& effect, bool enabled) final
            REQUIRES(audio_utils::ThreadBase_Mutex);

    void clearInputBuffer() final EXCLUDES_EffectChain_Mutex;

    // At least one non offloadable effect in the chain is enabled
    bool isNonOffloadableEnabled() const final EXCLUDES_EffectChain_Mutex;
    bool isNonOffloadableEnabled_l() const final REQUIRES(audio_utils::EffectChain_Mutex);

    void syncHalEffectsState_l()
            REQUIRES(audio_utils::ThreadBase_Mutex) EXCLUDES_EffectChain_Mutex final;

    // flags is an ORed set of audio_output_flags_t which is updated on return.
    void checkOutputFlagCompatibility(audio_output_flags_t *flags) const final;

    // flags is an ORed set of audio_input_flags_t which is updated on return.
    void checkInputFlagCompatibility(audio_input_flags_t *flags) const final;

    // Is this EffectChain compatible with the RAW audio flag.
    bool isRawCompatible() const final;

    // Is this EffectChain compatible with the FAST audio flag.
    bool isFastCompatible() const final;

    // Is this EffectChain compatible with the bit-perfect audio flag.
    bool isBitPerfectCompatible() const final;

    // isCompatibleWithThread_l() must be called with thread->mutex() held
    bool isCompatibleWithThread_l(const sp<IAfThreadBase>& thread) const final
            REQUIRES(audio_utils::ThreadBase_Mutex) EXCLUDES_EffectChain_Mutex;

    // Requires either IAfThreadBase::mutex() or EffectChain::mutex() held
    bool containsHapticGeneratingEffect_l() final;

    void setHapticScale_l(int id, os::HapticScale hapticScale) final
            REQUIRES(audio_utils::ThreadBase_Mutex) EXCLUDES_EffectChain_Mutex;

    sp<EffectCallbackInterface> effectCallback() const final { return mEffectCallback; }

    wp<IAfThreadBase> thread() const final { return mEffectCallback->thread(); }

    bool isFirstEffect(int id) const final {
        return !mEffects.isEmpty() && id == mEffects[0]->id();
    }

    void dump(int fd, const Vector<String16>& args) const final;

    size_t numberOfEffects() const final { return mEffects.size(); }

    sp<IAfEffectModule> getEffectModule(size_t index) const final {
        return mEffects[index];
    }

    void sendMetadata_l(const std::vector<playback_track_metadata_v7_t>& allMetadata,
        const std::optional<const std::vector<playback_track_metadata_v7_t>> spatializedMetadata)
            final REQUIRES(audio_utils::ThreadBase_Mutex);

    void setThread(const sp<IAfThreadBase>& thread) final EXCLUDES_EffectChain_Mutex;

  private:
    bool setVolume_l(uint32_t* left, uint32_t* right, bool force = false)
            REQUIRES(audio_utils::EffectChain_Mutex);

    // For transaction consistency, please consider holding the EffectChain lock before
    // calling the EffectChain::EffectCallback methods, excepting
    // createEffectHal and allocateHalBuffer.
    //
    // This prevents migration of the EffectChain to another PlaybackThread
    // for the purposes of the EffectCallback.
    class EffectCallback :  public EffectCallbackInterface {
    public:
        // Note: ctors taking a weak pointer to their owner must not promote it
        // during construction (but may keep a reference for later promotion).
        EffectCallback(const wp<EffectChain>& owner,
                const sp<IAfThreadBase>& thread)  // we take a sp<> but store a wp<>.
            : mChain(owner)
            , mThread(thread) {
            mThreadType = thread->type();
            mAfThreadCallback = thread->afThreadCallback();
        }

        status_t createEffectHal(const effect_uuid_t *pEffectUuid,
               int32_t sessionId, int32_t deviceId, sp<EffectHalInterface> *effect) override;
        status_t allocateHalBuffer(size_t size, sp<EffectBufferHalInterface>* buffer) override;
        bool updateOrphanEffectChains(const sp<IAfEffectBase>& effect) override;

        audio_io_handle_t io() const override;
        bool isOutput() const override;
        bool isOffload() const override;
        bool isOffloadOrDirect() const override;
        bool isOffloadOrMmap() const override;
        bool isSpatializer() const override;

        uint32_t sampleRate() const override;
        audio_channel_mask_t inChannelMask(int id) const override;
        uint32_t inChannelCount(int id) const override;
        audio_channel_mask_t outChannelMask() const override;
        uint32_t outChannelCount() const override;
        audio_channel_mask_t hapticChannelMask() const override;
        size_t frameCount() const override;
        uint32_t latency() const override;

        status_t addEffectToHal(const sp<EffectHalInterface>& effect) override;
        status_t removeEffectFromHal(const sp<EffectHalInterface>& effect) override;
        bool disconnectEffectHandle(IAfEffectHandle *handle, bool unpinIfLast) override;
        void setVolumeForOutput(float left, float right) const override;

        // check if effects should be suspended/restored when a given effect is enable/disabled
        void checkSuspendOnEffectEnabled(const sp<IAfEffectBase>& effect, bool enabled,
                                         bool threadLocked) override;
        void resetVolume_l() override
                REQUIRES(audio_utils::ThreadBase_Mutex, audio_utils::EffectChain_Mutex);
        product_strategy_t strategy() const override;
        int32_t activeTrackCnt() const override;
        void onEffectEnable(const sp<IAfEffectBase>& effect) override;
        void onEffectDisable(const sp<IAfEffectBase>& effect) override;

        wp<IAfEffectChain> chain() const final { return mChain; }

        bool isAudioPolicyReady() const final {
            return mAfThreadCallback->isAudioPolicyReady();
        }

        wp<IAfThreadBase> thread() const { return mThread.load(); }

        void setThread(const sp<IAfThreadBase>& thread) {
            mThread = thread;
            mThreadType = thread->type();
            mAfThreadCallback = thread->afThreadCallback();
        }

    private:
        const wp<IAfEffectChain> mChain;
        mediautils::atomic_wp<IAfThreadBase> mThread;
        sp<IAfThreadCallback> mAfThreadCallback;
        IAfThreadBase::type_t mThreadType;
    };

    DISALLOW_COPY_AND_ASSIGN(EffectChain);

    class SuspendedEffectDesc : public RefBase {
    public:
        SuspendedEffectDesc() : mRefCount(0) {}

        int mRefCount;   // > 0 when suspended
        effect_uuid_t mType;
        wp<IAfEffectModule> mEffect;
    };

    // get a list of effect modules to suspend when an effect of the type
    // passed is enabled.
    void getSuspendEligibleEffects_l(Vector<sp<IAfEffectModule>>& effects)
            REQUIRES(audio_utils::ThreadBase_Mutex);

    // get an effect module if it is currently enable
    sp<IAfEffectModule> getEffectIfEnabled_l(const effect_uuid_t* type)
            REQUIRES(audio_utils::ThreadBase_Mutex);
    // true if the effect whose descriptor is passed can be suspended
    // OEMs can modify the rules implemented in this method to exclude specific effect
    // types or implementations from the suspend/restore mechanism.
    bool isEffectEligibleForSuspend_l(const effect_descriptor_t& desc)
            REQUIRES(audio_utils::ThreadBase_Mutex);

    static bool isEffectEligibleForBtNrecSuspend_l(const effect_uuid_t* type)
            REQUIRES(audio_utils::ThreadBase_Mutex);

    void clearInputBuffer_l() REQUIRES(audio_utils::EffectChain_Mutex);

    // true if any effect module within the chain has volume control
    bool hasVolumeControlEnabled_l() const REQUIRES(audio_utils::EffectChain_Mutex);

    void setVolumeForOutput_l(uint32_t left, uint32_t right)
            REQUIRES(audio_utils::EffectChain_Mutex);

    ssize_t getInsertIndex_ll(const effect_descriptor_t& desc)
            REQUIRES(audio_utils::ThreadBase_Mutex, audio_utils::EffectChain_Mutex);

    std::optional<size_t> findVolumeControl_l(size_t from, size_t to) const
            REQUIRES(audio_utils::EffectChain_Mutex);

    // mutex protecting effect list
    mutable audio_utils::mutex mMutex{audio_utils::MutexOrder::kEffectChain_Mutex};
             Vector<sp<IAfEffectModule>> mEffects; // list of effect modules
             audio_session_t mSessionId; // audio session ID
             sp<EffectBufferHalInterface> mInBuffer;  // chain input buffer
             sp<EffectBufferHalInterface> mOutBuffer; // chain output buffer

    // 'volatile' here means these are accessed with atomic operations instead of mutex
    volatile int32_t mActiveTrackCnt;    // number of active tracks connected
    volatile int32_t mTrackCnt;          // number of tracks connected

             int32_t mTailBufferCount;   // current effect tail buffer count
             int32_t mMaxTailBuffers;    // maximum effect tail buffers
             uint32_t mLeftVolume;       // previous volume on left channel
             uint32_t mRightVolume;      // previous volume on right channel
             uint32_t mNewLeftVolume;       // new volume on left channel
             uint32_t mNewRightVolume;      // new volume on right channel
             product_strategy_t mStrategy; // strategy for this effect chain
             // mSuspendedEffects lists all effects currently suspended in the chain.
             // Use effect type UUID timelow field as key. There is no real risk of identical
             // timeLow fields among effect type UUIDs.
             // Updated by setEffectSuspended_l() and setEffectSuspendedAll_l() only.
             KeyedVector< int, sp<SuspendedEffectDesc> > mSuspendedEffects;

             const sp<EffectCallback> mEffectCallback;

             wp<IAfEffectModule> mVolumeControlEffect;
};

class DeviceEffectProxy : public IAfDeviceEffectProxy, public EffectBase {
public:
    DeviceEffectProxy(const AudioDeviceTypeAddr& device,
            const sp<DeviceEffectManagerCallback>& callback,
                effect_descriptor_t *desc, int id, bool notifyFramesProcessed)
            : EffectBase(callback, desc, id, AUDIO_SESSION_DEVICE, false),
                mDevice(device), mManagerCallback(callback),
                mMyCallback(new ProxyCallback(wp<DeviceEffectProxy>(this), callback)),
                mNotifyFramesProcessed(notifyFramesProcessed) {}

    status_t setEnabled(bool enabled, bool fromHandle) final;
    sp<IAfDeviceEffectProxy> asDeviceEffectProxy() final { return this; }

    status_t init_l(const std::map<audio_patch_handle_t, IAfPatchPanel::Patch>& patches) final
            REQUIRES(audio_utils::DeviceEffectManager_Mutex) EXCLUDES_EffectBase_Mutex;

    status_t onCreatePatch(audio_patch_handle_t patchHandle,
                           const IAfPatchPanel::Patch& patch) final;

    status_t onUpdatePatch(audio_patch_handle_t oldPatchHandle, audio_patch_handle_t newPatchHandle,
           const IAfPatchPanel::Patch& patch) final;

    void onReleasePatch(audio_patch_handle_t patchHandle) final;

    size_t removeEffect(const sp<IAfEffectModule>& effect) final;

    status_t addEffectToHal(const sp<EffectHalInterface>& effect) final;
    status_t removeEffectFromHal(const sp<EffectHalInterface>& effect) final;

    const AudioDeviceTypeAddr& device() const final { return mDevice; };
    bool isOutput() const final;
    uint32_t sampleRate() const final;
    audio_channel_mask_t channelMask() const final;
    uint32_t channelCount() const final;

    status_t command(int32_t cmdCode, const std::vector<uint8_t>& cmdData, int32_t maxReplySize,
                     std::vector<uint8_t>* reply) final EXCLUDES_DeviceEffectProxy_ProxyMutex;

    void dump2(int fd, int spaces) const final;

private:

    class ProxyCallback :  public EffectCallbackInterface {
    public:
        // Note: ctors taking a weak pointer to their owner must not promote it
        // during construction (but may keep a reference for later promotion).
        ProxyCallback(const wp<DeviceEffectProxy>& owner,
                const sp<DeviceEffectManagerCallback>& callback)
            : mProxy(owner), mManagerCallback(callback) {}

        status_t createEffectHal(const effect_uuid_t *pEffectUuid,
               int32_t sessionId, int32_t deviceId, sp<EffectHalInterface> *effect) override;
        status_t allocateHalBuffer(size_t size __unused,
                sp<EffectBufferHalInterface>* buffer __unused) override { return NO_ERROR; }
        bool updateOrphanEffectChains(const sp<IAfEffectBase>& effect __unused) override {
                    return false;
        }

        audio_io_handle_t io() const override { return AUDIO_IO_HANDLE_NONE; }
        bool isOutput() const override;
        bool isOffload() const override { return false; }
        bool isOffloadOrDirect() const override { return false; }
        bool isOffloadOrMmap() const override { return false; }
        bool isSpatializer() const override { return false; }

        uint32_t sampleRate() const override;
        audio_channel_mask_t inChannelMask(int id) const override;
        uint32_t inChannelCount(int id) const override;
        audio_channel_mask_t outChannelMask() const override;
        uint32_t outChannelCount() const override;
        audio_channel_mask_t hapticChannelMask() const override { return AUDIO_CHANNEL_NONE; }
        size_t frameCount() const override  { return 0; }
        uint32_t latency() const override  { return 0; }

        status_t addEffectToHal(const sp<EffectHalInterface>& effect) override;
        status_t removeEffectFromHal(const sp<EffectHalInterface>& effect) override;

        bool disconnectEffectHandle(IAfEffectHandle *handle, bool unpinIfLast) override;
        void setVolumeForOutput(float left __unused, float right __unused) const override {}

        void checkSuspendOnEffectEnabled(const sp<IAfEffectBase>& effect __unused,
                              bool enabled __unused, bool threadLocked __unused) override {}
        void resetVolume_l() override REQUIRES(audio_utils::EffectChain_Mutex) {}
        product_strategy_t strategy() const override  { return static_cast<product_strategy_t>(0); }
        int32_t activeTrackCnt() const override { return 0; }
        void onEffectEnable(const sp<IAfEffectBase>& effect __unused) override;
        void onEffectDisable(const sp<IAfEffectBase>& effect __unused) override;

        wp<IAfEffectChain> chain() const override { return nullptr; }

        bool isAudioPolicyReady() const override {
            return mManagerCallback->isAudioPolicyReady();
        }

        int newEffectId();

    private:
        const wp<DeviceEffectProxy> mProxy;
        const sp<DeviceEffectManagerCallback> mManagerCallback;
    };

    status_t checkPort(const IAfPatchPanel::Patch& patch,
            const struct audio_port_config* port, sp<IAfEffectHandle>* handle);

    const AudioDeviceTypeAddr mDevice;
    const sp<DeviceEffectManagerCallback> mManagerCallback;
    const sp<ProxyCallback> mMyCallback;

    audio_utils::mutex& proxyMutex() const
            RETURN_CAPABILITY(android::audio_utils::DeviceEffectProxy_ProxyMutex) {
        return mProxyMutex;
    }
    mutable audio_utils::mutex mProxyMutex{
            audio_utils::MutexOrder::kDeviceEffectProxy_ProxyMutex};
    std::map<audio_patch_handle_t, sp<IAfEffectHandle>> mEffectHandles; // protected by mProxyMutex
    sp<IAfEffectModule> mHalEffect; // protected by mProxyMutex
    struct audio_port_config mDevicePort = { .id = AUDIO_PORT_HANDLE_NONE };
    const bool mNotifyFramesProcessed;
};

} // namespace android
