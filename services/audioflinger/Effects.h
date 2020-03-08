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

#ifndef INCLUDING_FROM_AUDIOFLINGER_H
    #error This header file should only be included from AudioFlinger.h
#endif

//--- Audio Effect Management

// Interface implemented by the EffectModule parent or owner (e.g an EffectChain) to abstract
// interactions between the EffectModule and the reset of the audio framework.
class EffectCallbackInterface : public RefBase {
public:
            ~EffectCallbackInterface() override = default;

    // Trivial methods usually implemented with help from ThreadBase
    virtual audio_io_handle_t io() const = 0;
    virtual bool isOutput() const = 0;
    virtual bool isOffload() const = 0;
    virtual bool isOffloadOrDirect() const = 0;
    virtual bool isOffloadOrMmap() const = 0;
    virtual uint32_t sampleRate() const = 0;
    virtual audio_channel_mask_t channelMask() const = 0;
    virtual uint32_t channelCount() const = 0;
    virtual size_t frameCount() const = 0;

    // Non trivial methods usually implemented with help from ThreadBase:
    //   pay attention to mutex locking order
    virtual uint32_t latency() const { return 0; }
    virtual status_t addEffectToHal(sp<EffectHalInterface> effect) = 0;
    virtual status_t removeEffectFromHal(sp<EffectHalInterface> effect) = 0;
    virtual void setVolumeForOutput(float left, float right) const = 0;
    virtual bool disconnectEffectHandle(EffectHandle *handle, bool unpinIfLast) = 0;
    virtual void checkSuspendOnEffectEnabled(const sp<EffectBase>& effect,
                                             bool enabled,
                                             bool threadLocked) = 0;
    virtual void onEffectEnable(const sp<EffectBase>& effect) = 0;
    virtual void onEffectDisable(const sp<EffectBase>& effect) = 0;

    // Methods usually implemented with help from AudioFlinger: pay attention to mutex locking order
    virtual status_t createEffectHal(const effect_uuid_t *pEffectUuid,
                    int32_t sessionId, int32_t deviceId, sp<EffectHalInterface> *effect) = 0;
    virtual status_t allocateHalBuffer(size_t size, sp<EffectBufferHalInterface>* buffer) = 0;
    virtual bool updateOrphanEffectChains(const sp<EffectBase>& effect) = 0;

    // Methods usually implemented with help from EffectChain: pay attention to mutex locking order
    virtual uint32_t strategy() const = 0;
    virtual int32_t activeTrackCnt() const = 0;
    virtual void resetVolume() = 0;

    virtual wp<EffectChain> chain() const = 0;
};

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
class EffectBase : public RefBase {
public:
    EffectBase(const sp<EffectCallbackInterface>& callback,
               effect_descriptor_t *desc,
               int id,
               audio_session_t sessionId,
               bool pinned);

    ~EffectBase() override = default;

    enum effect_state {
        IDLE,
        RESTART,
        STARTING,
        ACTIVE,
        STOPPING,
        STOPPED,
        DESTROYED
    };

    int id() const { return mId; }
    effect_state state() const {
        return mState;
    }
    audio_session_t sessionId() const {
        return mSessionId;
    }
    const effect_descriptor_t& desc() const { return mDescriptor; }
    bool             isOffloadable() const
                        { return (mDescriptor.flags & EFFECT_FLAG_OFFLOAD_SUPPORTED) != 0; }
    bool             isImplementationSoftware() const
                        { return (mDescriptor.flags & EFFECT_FLAG_HW_ACC_MASK) == 0; }
    bool             isProcessImplemented() const
                        { return (mDescriptor.flags & EFFECT_FLAG_NO_PROCESS) == 0; }
    bool             isVolumeControl() const
                        { return (mDescriptor.flags & EFFECT_FLAG_VOLUME_MASK)
                            == EFFECT_FLAG_VOLUME_CTRL; }
    bool             isVolumeMonitor() const
                        { return (mDescriptor.flags & EFFECT_FLAG_VOLUME_MASK)
                            == EFFECT_FLAG_VOLUME_MONITOR; }

    virtual status_t setEnabled(bool enabled, bool fromHandle);
    status_t    setEnabled_l(bool enabled);
    bool isEnabled() const;

    void             setSuspended(bool suspended);
    bool             suspended() const;

    virtual status_t command(uint32_t cmdCode __unused,
                 uint32_t cmdSize __unused,
                 void *pCmdData __unused,
                 uint32_t *replySize __unused,
                 void *pReplyData __unused) { return NO_ERROR; };

    void setCallback(const sp<EffectCallbackInterface>& callback) { mCallback = callback; }
    sp<EffectCallbackInterface>&     callback() { return mCallback; }

    status_t addHandle(EffectHandle *handle);
    ssize_t disconnectHandle(EffectHandle *handle, bool unpinIfLast);
    ssize_t removeHandle(EffectHandle *handle);
    virtual ssize_t removeHandle_l(EffectHandle *handle);
    EffectHandle* controlHandle_l();
    bool purgeHandles();

    void             checkSuspendOnEffectEnabled(bool enabled, bool threadLocked);

    bool             isPinned() const { return mPinned; }
    void             unPin() { mPinned = false; }

    void             lock() { mLock.lock(); }
    void             unlock() { mLock.unlock(); }

    status_t         updatePolicyState();

    virtual          sp<EffectModule> asEffectModule() { return nullptr; }
    virtual          sp<DeviceEffectProxy> asDeviceEffectProxy() { return nullptr; }

    void             dump(int fd, const Vector<String16>& args);

private:
    friend class AudioFlinger;      // for mHandles
    bool             mPinned = false;

    DISALLOW_COPY_AND_ASSIGN(EffectBase);

mutable Mutex                 mLock;      // mutex for process, commands and handles list protection
    sp<EffectCallbackInterface> mCallback; // parent effect chain
    const int                 mId;        // this instance unique ID
    const audio_session_t     mSessionId; // audio session ID
    const effect_descriptor_t mDescriptor;// effect descriptor received from effect engine
    effect_state              mState = IDLE; // current activation state
    // effect is suspended: temporarily disabled by framework
    bool                      mSuspended = false;

    Vector<EffectHandle *>    mHandles;   // list of client handles
                // First handle in mHandles has highest priority and controls the effect module

    // Audio policy effect state management
    // Mutex protecting transactions with audio policy manager as mLock cannot
    // be held to avoid cross deadlocks with audio policy mutex
    Mutex                     mPolicyLock;
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
class EffectModule : public EffectBase {
public:
    EffectModule(const sp<EffectCallbackInterface>& callabck,
                    effect_descriptor_t *desc,
                    int id,
                    audio_session_t sessionId,
                    bool pinned,
                    audio_port_handle_t deviceId);
    virtual ~EffectModule();

    void process();
    bool updateState();
    status_t command(uint32_t cmdCode,
                     uint32_t cmdSize,
                     void *pCmdData,
                     uint32_t *replySize,
                     void *pReplyData) override;

    void reset_l();
    status_t configure();
    status_t init();

    uint32_t status() {
        return mStatus;
    }

    bool isProcessEnabled() const;
    bool isOffloadedOrDirect() const;
    bool isVolumeControlEnabled() const;

    void        setInBuffer(const sp<EffectBufferHalInterface>& buffer);
    int16_t     *inBuffer() const {
        return mInBuffer != 0 ? reinterpret_cast<int16_t*>(mInBuffer->ptr()) : NULL;
    }
    void        setOutBuffer(const sp<EffectBufferHalInterface>& buffer);
    int16_t     *outBuffer() const {
        return mOutBuffer != 0 ? reinterpret_cast<int16_t*>(mOutBuffer->ptr()) : NULL;
    }

    ssize_t removeHandle_l(EffectHandle *handle) override;

    status_t         setDevices(const AudioDeviceTypeAddrVector &devices);
    status_t         setInputDevice(const AudioDeviceTypeAddr &device);
    status_t         setVolume(uint32_t *left, uint32_t *right, bool controller);
    status_t         setMode(audio_mode_t mode);
    status_t         setAudioSource(audio_source_t source);
    status_t         start();
    status_t         stop();

    status_t         setOffloaded(bool offloaded, audio_io_handle_t io);
    bool             isOffloaded() const;
    void             addEffectToHal_l();
    void             release_l();

    sp<EffectModule> asEffectModule() override { return this; }

    void             dump(int fd, const Vector<String16>& args);

private:
    friend class AudioFlinger;      // for mHandles

    // Maximum time allocated to effect engines to complete the turn off sequence
    static const uint32_t MAX_DISABLE_TIME_MS = 10000;

    DISALLOW_COPY_AND_ASSIGN(EffectModule);

    status_t start_l();
    status_t stop_l();
    status_t removeEffectFromHal_l();
    status_t sendSetAudioDevicesCommand(const AudioDeviceTypeAddrVector &devices, uint32_t cmdCode);

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

#ifdef FLOAT_EFFECT_CHAIN
    bool    mSupportsFloat;         // effect supports float processing
    sp<EffectBufferHalInterface> mInConversionBuffer;  // Buffers for HAL conversion if needed.
    sp<EffectBufferHalInterface> mOutConversionBuffer;
    uint32_t mInChannelCountRequested;
    uint32_t mOutChannelCountRequested;
#endif

    class AutoLockReentrant {
    public:
        AutoLockReentrant(Mutex& mutex, pid_t allowedTid)
            : mMutex(gettid() == allowedTid ? nullptr : &mutex)
        {
            if (mMutex != nullptr) mMutex->lock();
        }
        ~AutoLockReentrant() {
            if (mMutex != nullptr) mMutex->unlock();
        }
    private:
        Mutex * const mMutex;
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
class EffectHandle: public android::BnEffect {
public:

    EffectHandle(const sp<EffectBase>& effect,
            const sp<AudioFlinger::Client>& client,
            const sp<IEffectClient>& effectClient,
            int32_t priority);
    virtual ~EffectHandle();
    virtual status_t initCheck();

    // IEffect
    virtual status_t enable();
    virtual status_t disable();
    virtual status_t command(uint32_t cmdCode,
                             uint32_t cmdSize,
                             void *pCmdData,
                             uint32_t *replySize,
                             void *pReplyData);
    virtual void disconnect();
private:
            void disconnect(bool unpinIfLast);
public:
    virtual sp<IMemory> getCblk() const { return mCblkMemory; }
    virtual status_t onTransact(uint32_t code, const Parcel& data,
            Parcel* reply, uint32_t flags);


    // Give or take control of effect module
    // - hasControl: true if control is given, false if removed
    // - signal: true client app should be signaled of change, false otherwise
    // - enabled: state of the effect when control is passed
    void setControl(bool hasControl, bool signal, bool enabled);
    void commandExecuted(uint32_t cmdCode,
                         uint32_t cmdSize,
                         void *pCmdData,
                         uint32_t replySize,
                         void *pReplyData);
    void setEnabled(bool enabled);
    bool enabled() const { return mEnabled; }

    // Getters
    wp<EffectBase> effect() const { return mEffect; }
    int id() const {
        sp<EffectBase> effect = mEffect.promote();
        if (effect == 0) {
            return 0;
        }
        return effect->id();
    }
    int priority() const { return mPriority; }
    bool hasControl() const { return mHasControl; }
    bool disconnected() const { return mDisconnected; }

    void dumpToBuffer(char* buffer, size_t size);

private:
    friend class AudioFlinger;          // for mEffect, mHasControl, mEnabled
    DISALLOW_COPY_AND_ASSIGN(EffectHandle);

    Mutex mLock;                        // protects IEffect method calls
    wp<EffectBase> mEffect;           // pointer to controlled EffectModule
    sp<IEffectClient> mEffectClient;    // callback interface for client notifications
    /*const*/ sp<Client> mClient;       // client for shared memory allocation, see disconnect()
    sp<IMemory>         mCblkMemory;    // shared memory for control block
    effect_param_cblk_t* mCblk;         // control block for deferred parameter setting via
                                        // shared memory
    uint8_t*            mBuffer;        // pointer to parameter area in shared memory
    int mPriority;                      // client application priority to control the effect
    bool mHasControl;                   // true if this handle is controlling the effect
    bool mEnabled;                      // cached enable state: needed when the effect is
                                        // restored after being suspended
    bool mDisconnected;                 // Set to true by disconnect()
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
class EffectChain : public RefBase {
public:
    EffectChain(const wp<ThreadBase>& wThread, audio_session_t sessionId);
    virtual ~EffectChain();

    // special key used for an entry in mSuspendedEffects keyed vector
    // corresponding to a suspend all request.
    static const int        kKeyForSuspendAll = 0;

    // minimum duration during which we force calling effect process when last track on
    // a session is stopped or removed to allow effect tail to be rendered
    static const int        kProcessTailDurationMs = 1000;

    void process_l();

    void lock() {
        mLock.lock();
    }
    void unlock() {
        mLock.unlock();
    }

    status_t createEffect_l(sp<EffectModule>& effect,
                            effect_descriptor_t *desc,
                            int id,
                            audio_session_t sessionId,
                            bool pinned);
    status_t addEffect_l(const sp<EffectModule>& handle);
    status_t addEffect_ll(const sp<EffectModule>& handle);
    size_t removeEffect_l(const sp<EffectModule>& handle, bool release = false);

    audio_session_t sessionId() const { return mSessionId; }
    void setSessionId(audio_session_t sessionId) { mSessionId = sessionId; }

    sp<EffectModule> getEffectFromDesc_l(effect_descriptor_t *descriptor);
    sp<EffectModule> getEffectFromId_l(int id);
    sp<EffectModule> getEffectFromType_l(const effect_uuid_t *type);
    std::vector<int> getEffectIds();
    // FIXME use float to improve the dynamic range
    bool setVolume_l(uint32_t *left, uint32_t *right, bool force = false);
    void resetVolume_l();
    void setDevices_l(const AudioDeviceTypeAddrVector &devices);
    void setInputDevice_l(const AudioDeviceTypeAddr &device);
    void setMode_l(audio_mode_t mode);
    void setAudioSource_l(audio_source_t source);

    void setInBuffer(const sp<EffectBufferHalInterface>& buffer) {
        mInBuffer = buffer;
    }
    effect_buffer_t *inBuffer() const {
        return mInBuffer != 0 ? reinterpret_cast<effect_buffer_t*>(mInBuffer->ptr()) : NULL;
    }
    void setOutBuffer(const sp<EffectBufferHalInterface>& buffer) {
        mOutBuffer = buffer;
    }
    effect_buffer_t *outBuffer() const {
        return mOutBuffer != 0 ? reinterpret_cast<effect_buffer_t*>(mOutBuffer->ptr()) : NULL;
    }

    void incTrackCnt() { android_atomic_inc(&mTrackCnt); }
    void decTrackCnt() { android_atomic_dec(&mTrackCnt); }
    int32_t trackCnt() const { return android_atomic_acquire_load(&mTrackCnt); }

    void incActiveTrackCnt() { android_atomic_inc(&mActiveTrackCnt);
                               mTailBufferCount = mMaxTailBuffers; }
    void decActiveTrackCnt() { android_atomic_dec(&mActiveTrackCnt); }
    int32_t activeTrackCnt() const { return android_atomic_acquire_load(&mActiveTrackCnt); }

    uint32_t strategy() const { return mStrategy; }
    void setStrategy(uint32_t strategy)
            { mStrategy = strategy; }

    // suspend or restore effects of the specified type. The number of suspend requests is counted
    // and restore occurs once all suspend requests are cancelled.
    void setEffectSuspended_l(const effect_uuid_t *type,
                              bool suspend);
    // suspend all eligible effects
    void setEffectSuspendedAll_l(bool suspend);
    // check if effects should be suspended or restored when a given effect is enable or disabled
    void checkSuspendOnEffectEnabled(const sp<EffectModule>& effect, bool enabled);

    void clearInputBuffer();

    // At least one non offloadable effect in the chain is enabled
    bool isNonOffloadableEnabled();
    bool isNonOffloadableEnabled_l();

    void syncHalEffectsState();

    // flags is an ORed set of audio_output_flags_t which is updated on return.
    void checkOutputFlagCompatibility(audio_output_flags_t *flags) const;

    // flags is an ORed set of audio_input_flags_t which is updated on return.
    void checkInputFlagCompatibility(audio_input_flags_t *flags) const;

    // Is this EffectChain compatible with the RAW audio flag.
    bool isRawCompatible() const;

    // Is this EffectChain compatible with the FAST audio flag.
    bool isFastCompatible() const;

    // isCompatibleWithThread_l() must be called with thread->mLock held
    bool isCompatibleWithThread_l(const sp<ThreadBase>& thread) const;

    sp<EffectCallbackInterface> effectCallback() const { return mEffectCallback; }
    wp<ThreadBase> thread() const { return mEffectCallback->thread(); }

    void dump(int fd, const Vector<String16>& args);

private:

    class EffectCallback :  public EffectCallbackInterface {
    public:
        // Note: ctors taking a weak pointer to their owner must not promote it
        // during construction (but may keep a reference for later promotion).
        EffectCallback(const wp<EffectChain>& owner,
                       const wp<ThreadBase>& thread)
            : mChain(owner) {
            setThread(thread);
        }

        status_t createEffectHal(const effect_uuid_t *pEffectUuid,
               int32_t sessionId, int32_t deviceId, sp<EffectHalInterface> *effect) override;
        status_t allocateHalBuffer(size_t size, sp<EffectBufferHalInterface>* buffer) override;
        bool updateOrphanEffectChains(const sp<EffectBase>& effect) override;

        audio_io_handle_t io() const override;
        bool isOutput() const override;
        bool isOffload() const override;
        bool isOffloadOrDirect() const override;
        bool isOffloadOrMmap() const override;

        uint32_t sampleRate() const override;
        audio_channel_mask_t channelMask() const override;
        uint32_t channelCount() const override;
        size_t frameCount() const override;
        uint32_t latency() const override;

        status_t addEffectToHal(sp<EffectHalInterface> effect) override;
        status_t removeEffectFromHal(sp<EffectHalInterface> effect) override;
        bool disconnectEffectHandle(EffectHandle *handle, bool unpinIfLast) override;
        void setVolumeForOutput(float left, float right) const override;

        // check if effects should be suspended/restored when a given effect is enable/disabled
        void checkSuspendOnEffectEnabled(const sp<EffectBase>& effect,
                              bool enabled, bool threadLocked) override;
        void resetVolume() override;
        uint32_t strategy() const override;
        int32_t activeTrackCnt() const override;
        void onEffectEnable(const sp<EffectBase>& effect) override;
        void onEffectDisable(const sp<EffectBase>& effect) override;

        wp<EffectChain> chain() const override { return mChain; }

        wp<ThreadBase> thread() { return mThread; }

        void setThread(const wp<ThreadBase>& thread) {
            mThread = thread;
            sp<ThreadBase> p = thread.promote();
            mAudioFlinger = p ? p->mAudioFlinger : nullptr;
        }

    private:
        wp<EffectChain> mChain;
        wp<ThreadBase> mThread;
        wp<AudioFlinger> mAudioFlinger;
    };

    friend class AudioFlinger;  // for mThread, mEffects
    DISALLOW_COPY_AND_ASSIGN(EffectChain);

    class SuspendedEffectDesc : public RefBase {
    public:
        SuspendedEffectDesc() : mRefCount(0) {}

        int mRefCount;   // > 0 when suspended
        effect_uuid_t mType;
        wp<EffectModule> mEffect;
    };

    // get a list of effect modules to suspend when an effect of the type
    // passed is enabled.
    void                       getSuspendEligibleEffects(Vector< sp<EffectModule> > &effects);

    // get an effect module if it is currently enable
    sp<EffectModule> getEffectIfEnabled(const effect_uuid_t *type);
    // true if the effect whose descriptor is passed can be suspended
    // OEMs can modify the rules implemented in this method to exclude specific effect
    // types or implementations from the suspend/restore mechanism.
    bool isEffectEligibleForSuspend(const effect_descriptor_t& desc);

    static bool isEffectEligibleForBtNrecSuspend(const effect_uuid_t *type);

    void clearInputBuffer_l();

    void setThread(const sp<ThreadBase>& thread);

    // true if any effect module within the chain has volume control
    bool hasVolumeControlEnabled_l() const;

    void setVolumeForOutput_l(uint32_t left, uint32_t right);

    mutable  Mutex mLock;        // mutex protecting effect list
             Vector< sp<EffectModule> > mEffects; // list of effect modules
             audio_session_t mSessionId; // audio session ID
             sp<EffectBufferHalInterface> mInBuffer;  // chain input buffer
             sp<EffectBufferHalInterface> mOutBuffer; // chain output buffer

    // 'volatile' here means these are accessed with atomic operations instead of mutex
    volatile int32_t mActiveTrackCnt;    // number of active tracks connected
    volatile int32_t mTrackCnt;          // number of tracks connected

             int32_t mTailBufferCount;   // current effect tail buffer count
             int32_t mMaxTailBuffers;    // maximum effect tail buffers
             int mVolumeCtrlIdx;         // index of insert effect having control over volume
             uint32_t mLeftVolume;       // previous volume on left channel
             uint32_t mRightVolume;      // previous volume on right channel
             uint32_t mNewLeftVolume;       // new volume on left channel
             uint32_t mNewRightVolume;      // new volume on right channel
             uint32_t mStrategy; // strategy for this effect chain
             // mSuspendedEffects lists all effects currently suspended in the chain.
             // Use effect type UUID timelow field as key. There is no real risk of identical
             // timeLow fields among effect type UUIDs.
             // Updated by setEffectSuspended_l() and setEffectSuspendedAll_l() only.
             KeyedVector< int, sp<SuspendedEffectDesc> > mSuspendedEffects;

             const sp<EffectCallback> mEffectCallback;
};

class DeviceEffectProxy : public EffectBase {
public:
        DeviceEffectProxy (const AudioDeviceTypeAddr& device,
                const sp<DeviceEffectManagerCallback>& callback,
                effect_descriptor_t *desc, int id)
            : EffectBase(callback, desc, id, AUDIO_SESSION_DEVICE, false),
                mDevice(device), mManagerCallback(callback),
                mMyCallback(new ProxyCallback(wp<DeviceEffectProxy>(this),
                                              callback)) {}

    status_t setEnabled(bool enabled, bool fromHandle) override;
    sp<DeviceEffectProxy> asDeviceEffectProxy() override { return this; }

    status_t init(const std::map<audio_patch_handle_t, PatchPanel::Patch>& patches);
    status_t onCreatePatch(audio_patch_handle_t patchHandle, const PatchPanel::Patch& patch);
    void onReleasePatch(audio_patch_handle_t patchHandle);

    size_t removeEffect(const sp<EffectModule>& effect);

    status_t addEffectToHal(sp<EffectHalInterface> effect);
    status_t removeEffectFromHal(sp<EffectHalInterface> effect);

    const AudioDeviceTypeAddr& device() { return mDevice; };
    bool isOutput() const;
    uint32_t sampleRate() const;
    audio_channel_mask_t channelMask() const;
    uint32_t channelCount() const;

    void dump(int fd, int spaces);

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
        bool updateOrphanEffectChains(const sp<EffectBase>& effect __unused) override {
                    return false;
        }

        audio_io_handle_t io() const override { return AUDIO_IO_HANDLE_NONE; }
        bool isOutput() const override;
        bool isOffload() const override { return false; }
        bool isOffloadOrDirect() const override { return false; }
        bool isOffloadOrMmap() const override { return false; }

        uint32_t sampleRate() const override;
        audio_channel_mask_t channelMask() const override;
        uint32_t channelCount() const override;
        size_t frameCount() const override  { return 0; }
        uint32_t latency() const override  { return 0; }

        status_t addEffectToHal(sp<EffectHalInterface> effect) override;
        status_t removeEffectFromHal(sp<EffectHalInterface> effect) override;

        bool disconnectEffectHandle(EffectHandle *handle, bool unpinIfLast) override;
        void setVolumeForOutput(float left __unused, float right __unused) const override {}

        void checkSuspendOnEffectEnabled(const sp<EffectBase>& effect __unused,
                              bool enabled __unused, bool threadLocked __unused) override {}
        void resetVolume() override {}
        uint32_t strategy() const override  { return 0; }
        int32_t activeTrackCnt() const override { return 0; }
        void onEffectEnable(const sp<EffectBase>& effect __unused) override {}
        void onEffectDisable(const sp<EffectBase>& effect __unused) override {}

        wp<EffectChain> chain() const override { return nullptr; }

        int newEffectId();

    private:
        const wp<DeviceEffectProxy> mProxy;
        const sp<DeviceEffectManagerCallback> mManagerCallback;
    };

    status_t checkPort(const PatchPanel::Patch& patch, const struct audio_port_config *port,
            sp<EffectHandle> *handle);

    const AudioDeviceTypeAddr mDevice;
    const sp<DeviceEffectManagerCallback> mManagerCallback;
    const sp<ProxyCallback> mMyCallback;

    Mutex mProxyLock;
    std::map<audio_patch_handle_t, sp<EffectHandle>> mEffectHandles; // protected by mProxyLock
    sp<EffectModule> mHalEffect; // protected by mProxyLock
    struct audio_port_config mDevicePort = { .id = AUDIO_PORT_HANDLE_NONE };
};
