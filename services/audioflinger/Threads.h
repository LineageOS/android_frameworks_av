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

// ADD_BATTERY_DATA AUDIO_WATCHDOG FAST_THREAD_STATISTICS STATE_QUEUE_DUMP TEE_SINK
#include "Configuration.h"
#include "IAfThread.h"
#include "IAfTrack.h"

#include <android-base/macros.h>  // DISALLOW_COPY_AND_ASSIGN
#include <android/os/IPowerManager.h>
#include <afutils/AudioWatchdog.h>
#include <afutils/NBAIO_Tee.h>
#include <audio_utils/Balance.h>
#include <audio_utils/SimpleLog.h>
#include <datapath/ThreadMetrics.h>
#include <fastpath/FastCapture.h>
#include <fastpath/FastMixer.h>
#include <mediautils/Synchronization.h>
#include <mediautils/ThreadSnapshot.h>
#include <timing/MonotonicFrameCounter.h>
#include <utils/Log.h>

namespace android {

class AsyncCallbackThread;

class ThreadBase : public virtual IAfThreadBase, public Thread {
public:
    static const char *threadTypeToString(type_t type);

    // ThreadBase_ThreadLoop is a virtual mutex (always nullptr) that
    // guards methods and variables that ONLY run and are accessed
    // on the single threaded threadLoop().
    //
    // As access is by a single thread, the variables are thread safe.
    static audio_utils::mutex* ThreadBase_ThreadLoop;

    IAfThreadCallback* afThreadCallback() const final { return mAfThreadCallback.get(); }

    ThreadBase(const sp<IAfThreadCallback>& afThreadCallback, audio_io_handle_t id,
               type_t type, bool systemReady, bool isOut);
    ~ThreadBase() override;

    status_t readyToRun() final;
    void clearPowerManager() final EXCLUDES_ThreadBase_Mutex;

    // base for record and playback
    enum {
        CFG_EVENT_IO,
        CFG_EVENT_PRIO,
        CFG_EVENT_SET_PARAMETER,
        CFG_EVENT_CREATE_AUDIO_PATCH,
        CFG_EVENT_RELEASE_AUDIO_PATCH,
        CFG_EVENT_UPDATE_OUT_DEVICE,
        CFG_EVENT_RESIZE_BUFFER,
        CFG_EVENT_CHECK_OUTPUT_STAGE_EFFECTS,
        CFG_EVENT_HAL_LATENCY_MODES_CHANGED,
    };

    class ConfigEventData: public RefBase {
    public:
        virtual  void dump(char *buffer, size_t size) = 0;
    protected:
        ConfigEventData() = default;
    };

    // Config event sequence by client if status needed (e.g binder thread calling setParameters()):
    //  1. create SetParameterConfigEvent. This sets mWaitStatus in config event
    //  2. Lock mutex()
    //  3. Call sendConfigEvent_l(): Append to mConfigEvents and mWaitWorkCV.signal
    //  4. sendConfigEvent_l() reads status from event->mStatus;
    //  5. sendConfigEvent_l() returns status
    //  6. Unlock
    //
    // Parameter sequence by server: threadLoop calling processConfigEvents_l():
    // 1. Lock mutex()
    // 2. If there is an entry in mConfigEvents proceed ...
    // 3. Read first entry in mConfigEvents
    // 4. Remove first entry from mConfigEvents
    // 5. Process
    // 6. Set event->mStatus
    // 7. event->mCondition.notify_one()
    // 8. Unlock

    class ConfigEvent: public RefBase {
    public:
        void dump(char *buffer, size_t size) {
            snprintf(buffer, size, "Event type: %d\n", mType);
            if (mData != nullptr) {
                snprintf(buffer, size, "Data:\n");
                mData->dump(buffer, size);
            }
        }

        audio_utils::mutex& mutex() const RETURN_CAPABILITY(audio_utils::ConfigEvent_Mutex) {
            return mMutex;
        }
        const int mType; // event type e.g. CFG_EVENT_IO
        // mutex associated with mCondition
        mutable audio_utils::mutex mMutex{audio_utils::MutexOrder::kConfigEvent_Mutex};
        audio_utils::condition_variable mCondition; // condition for status return

        // NO_THREAD_SAFETY_ANALYSIS Can we add GUARDED_BY?
        status_t mStatus; // status communicated to sender

        bool mWaitStatus GUARDED_BY(mutex()); // true if sender is waiting for status
        // true if must wait for system ready to enter event queue
        bool mRequiresSystemReady GUARDED_BY(mutex());

        // NO_THREAD_SAFETY_ANALYSIS Can we add GUARDED_BY?
        sp<ConfigEventData> mData; // event specific parameter data

    protected:
        explicit ConfigEvent(int type, bool requiresSystemReady = false) :
            mType(type), mStatus(NO_ERROR), mWaitStatus(false),
            mRequiresSystemReady(requiresSystemReady), mData(NULL) {}
    };

    class IoConfigEventData : public ConfigEventData {
    public:
        IoConfigEventData(audio_io_config_event_t event, pid_t pid,
                          audio_port_handle_t portId) :
            mEvent(event), mPid(pid), mPortId(portId) {}

        virtual  void dump(char *buffer, size_t size) {
            snprintf(buffer, size, "- IO event: event %d\n", mEvent);
        }

        const audio_io_config_event_t mEvent;
        const pid_t                 mPid;
        const audio_port_handle_t   mPortId;
    };

    class IoConfigEvent : public ConfigEvent {
    public:
        IoConfigEvent(audio_io_config_event_t event, pid_t pid, audio_port_handle_t portId) :
            ConfigEvent(CFG_EVENT_IO) {
            mData = new IoConfigEventData(event, pid, portId);
        }
    };

    class PrioConfigEventData : public ConfigEventData {
    public:
        PrioConfigEventData(pid_t pid, pid_t tid, int32_t prio, bool forApp) :
            mPid(pid), mTid(tid), mPrio(prio), mForApp(forApp) {}

        virtual  void dump(char *buffer, size_t size) {
            snprintf(buffer, size, "- Prio event: pid %d, tid %d, prio %d, for app? %d\n",
                    mPid, mTid, mPrio, mForApp);
        }

        const pid_t mPid;
        const pid_t mTid;
        const int32_t mPrio;
        const bool mForApp;
    };

    class PrioConfigEvent : public ConfigEvent {
    public:
        PrioConfigEvent(pid_t pid, pid_t tid, int32_t prio, bool forApp) :
            ConfigEvent(CFG_EVENT_PRIO, true) {
            mData = new PrioConfigEventData(pid, tid, prio, forApp);
        }
    };

    class SetParameterConfigEventData : public ConfigEventData {
    public:
        explicit SetParameterConfigEventData(const String8& keyValuePairs) :
            mKeyValuePairs(keyValuePairs) {}

        virtual  void dump(char *buffer, size_t size) {
            snprintf(buffer, size, "- KeyValue: %s\n", mKeyValuePairs.c_str());
        }

        const String8 mKeyValuePairs;
    };

    class SetParameterConfigEvent : public ConfigEvent {
    public:
        explicit SetParameterConfigEvent(const String8& keyValuePairs) :
            ConfigEvent(CFG_EVENT_SET_PARAMETER) {
            mData = new SetParameterConfigEventData(keyValuePairs);
            mWaitStatus = true;
        }
    };

    class CreateAudioPatchConfigEventData : public ConfigEventData {
    public:
        CreateAudioPatchConfigEventData(const struct audio_patch patch,
                                        audio_patch_handle_t handle) :
            mPatch(patch), mHandle(handle) {}

        virtual  void dump(char *buffer, size_t size) {
            snprintf(buffer, size, "- Patch handle: %u\n", mHandle);
        }

        const struct audio_patch mPatch;
        audio_patch_handle_t mHandle;  // cannot be const
    };

    class CreateAudioPatchConfigEvent : public ConfigEvent {
    public:
        CreateAudioPatchConfigEvent(const struct audio_patch patch,
                                    audio_patch_handle_t handle) :
            ConfigEvent(CFG_EVENT_CREATE_AUDIO_PATCH) {
            mData = new CreateAudioPatchConfigEventData(patch, handle);
            mWaitStatus = true;
        }
    };

    class ReleaseAudioPatchConfigEventData : public ConfigEventData {
    public:
        explicit ReleaseAudioPatchConfigEventData(const audio_patch_handle_t handle) :
            mHandle(handle) {}

        virtual  void dump(char *buffer, size_t size) {
            snprintf(buffer, size, "- Patch handle: %u\n", mHandle);
        }

        const audio_patch_handle_t mHandle;
    };

    class ReleaseAudioPatchConfigEvent : public ConfigEvent {
    public:
        explicit ReleaseAudioPatchConfigEvent(const audio_patch_handle_t handle) :
            ConfigEvent(CFG_EVENT_RELEASE_AUDIO_PATCH) {
            mData = new ReleaseAudioPatchConfigEventData(handle);
            mWaitStatus = true;
        }
    };

    class UpdateOutDevicesConfigEventData : public ConfigEventData {
    public:
        explicit UpdateOutDevicesConfigEventData(const DeviceDescriptorBaseVector& outDevices) :
            mOutDevices(outDevices) {}

        virtual void dump(char *buffer, size_t size) {
            snprintf(buffer, size, "- Devices: %s", android::toString(mOutDevices).c_str());
        }

        const DeviceDescriptorBaseVector mOutDevices;
    };

    class UpdateOutDevicesConfigEvent : public ConfigEvent {
    public:
        explicit UpdateOutDevicesConfigEvent(const DeviceDescriptorBaseVector& outDevices) :
            ConfigEvent(CFG_EVENT_UPDATE_OUT_DEVICE) {
            mData = new UpdateOutDevicesConfigEventData(outDevices);
        }
    };

    class ResizeBufferConfigEventData : public ConfigEventData {
    public:
        explicit ResizeBufferConfigEventData(int32_t maxSharedAudioHistoryMs) :
            mMaxSharedAudioHistoryMs(maxSharedAudioHistoryMs) {}

        virtual void dump(char *buffer, size_t size) {
            snprintf(buffer, size, "- mMaxSharedAudioHistoryMs: %d", mMaxSharedAudioHistoryMs);
        }

        const int32_t mMaxSharedAudioHistoryMs;
    };

    class ResizeBufferConfigEvent : public ConfigEvent {
    public:
        explicit ResizeBufferConfigEvent(int32_t maxSharedAudioHistoryMs) :
            ConfigEvent(CFG_EVENT_RESIZE_BUFFER) {
            mData = new ResizeBufferConfigEventData(maxSharedAudioHistoryMs);
        }
    };

    class CheckOutputStageEffectsEvent : public ConfigEvent {
    public:
        CheckOutputStageEffectsEvent() :
            ConfigEvent(CFG_EVENT_CHECK_OUTPUT_STAGE_EFFECTS) {
        }
    };

    class HalLatencyModesChangedEvent : public ConfigEvent {
    public:
        HalLatencyModesChangedEvent() :
            ConfigEvent(CFG_EVENT_HAL_LATENCY_MODES_CHANGED) {
        }
    };


    class PMDeathRecipient : public IBinder::DeathRecipient {
    public:
        explicit    PMDeathRecipient(const wp<ThreadBase>& thread) : mThread(thread) {}

        // IBinder::DeathRecipient
        void binderDied(const wp<IBinder>& who) final;

    private:
        DISALLOW_COPY_AND_ASSIGN(PMDeathRecipient);

        const wp<ThreadBase> mThread;
    };

    type_t type() const final { return mType; }
    bool isDuplicating() const final { return (mType == DUPLICATING); }
    audio_io_handle_t id() const final { return mId;}

    uint32_t sampleRate() const final { return mSampleRate; }
    audio_channel_mask_t channelMask() const final { return mChannelMask; }
    audio_channel_mask_t mixerChannelMask() const override { return mChannelMask; }
    audio_format_t format() const final { return mHALFormat; }
    uint32_t channelCount() const final { return mChannelCount; }
    audio_channel_mask_t hapticChannelMask() const override { return AUDIO_CHANNEL_NONE; }
    uint32_t hapticChannelCount() const override { return 0; }
    uint32_t latency_l() const override { return 0; }  // NO_THREAD_SAFETY_ANALYSIS
    void setVolumeForOutput_l(float /* left */, float /* right */) const override
            REQUIRES(mutex()) {}

                // Return's the HAL's frame count i.e. fast mixer buffer size.
    size_t frameCountHAL() const final { return mFrameCount; }
    size_t frameSize() const final { return mFrameSize; }

    // Should be "virtual status_t requestExitAndWait()" and override same
    // method in Thread, but Thread::requestExitAndWait() is not yet virtual.
    void exit() final EXCLUDES_ThreadBase_Mutex;
    status_t setParameters(const String8& keyValuePairs) final EXCLUDES_ThreadBase_Mutex;

                // sendConfigEvent_l() must be called with ThreadBase::mutex() held
                // Can temporarily release the lock if waiting for a reply from
                // processConfigEvents_l().
    status_t sendConfigEvent_l(sp<ConfigEvent>& event) REQUIRES(mutex());
    void sendIoConfigEvent(audio_io_config_event_t event, pid_t pid = 0,
            audio_port_handle_t portId = AUDIO_PORT_HANDLE_NONE) final EXCLUDES_ThreadBase_Mutex;
    void sendIoConfigEvent_l(audio_io_config_event_t event, pid_t pid = 0,
            audio_port_handle_t portId = AUDIO_PORT_HANDLE_NONE) final REQUIRES(mutex());
    void sendPrioConfigEvent(pid_t pid, pid_t tid, int32_t prio, bool forApp) final
            EXCLUDES_ThreadBase_Mutex;
    void sendPrioConfigEvent_l(pid_t pid, pid_t tid, int32_t prio, bool forApp) final
            REQUIRES(mutex());
    status_t sendSetParameterConfigEvent_l(const String8& keyValuePair) final REQUIRES(mutex());
    status_t sendCreateAudioPatchConfigEvent(const struct audio_patch* patch,
            audio_patch_handle_t* handle) final EXCLUDES_ThreadBase_Mutex;
    status_t sendReleaseAudioPatchConfigEvent(audio_patch_handle_t handle) final
            EXCLUDES_ThreadBase_Mutex;
    status_t sendUpdateOutDeviceConfigEvent(
            const DeviceDescriptorBaseVector& outDevices) final EXCLUDES_ThreadBase_Mutex;
    void sendResizeBufferConfigEvent_l(int32_t maxSharedAudioHistoryMs) final REQUIRES(mutex());
    void sendCheckOutputStageEffectsEvent() final EXCLUDES_ThreadBase_Mutex;
    void sendCheckOutputStageEffectsEvent_l() final REQUIRES(mutex());
    void sendHalLatencyModesChangedEvent_l() final REQUIRES(mutex());

    void processConfigEvents_l() final REQUIRES(mutex());
    void setCheckOutputStageEffects() override {}
    void updateOutDevices(const DeviceDescriptorBaseVector& outDevices) override;
    void toAudioPortConfig(struct audio_port_config* config) override;
    void resizeInputBuffer_l(int32_t maxSharedAudioHistoryMs) override REQUIRES(mutex());

    // see note at declaration of mStandby, mOutDevice and mInDevice
    bool inStandby() const override { return mStandby; }
    const DeviceTypeSet outDeviceTypes_l() const final REQUIRES(mutex()) {
        return getAudioDeviceTypes(mOutDeviceTypeAddrs);
    }
    audio_devices_t inDeviceType_l() const final REQUIRES(mutex()) {
        return mInDeviceTypeAddr.mType;
    }
    DeviceTypeSet getDeviceTypes_l() const final REQUIRES(mutex()) {
        return isOutput() ? outDeviceTypes_l() : DeviceTypeSet({inDeviceType_l()});
    }

    const AudioDeviceTypeAddrVector& outDeviceTypeAddrs() const final {
        return mOutDeviceTypeAddrs;
    }
    const AudioDeviceTypeAddr& inDeviceTypeAddr() const final {
        return mInDeviceTypeAddr;
    }

    bool isOutput() const final { return mIsOut; }

    bool isOffloadOrMmap() const final {
        switch (mType) {
        case OFFLOAD:
        case MMAP_PLAYBACK:
        case MMAP_CAPTURE:
            return true;
        default:
            return false;
        }
    }

    sp<IAfEffectHandle> createEffect_l(
                                    const sp<Client>& client,
                                    const sp<media::IEffectClient>& effectClient,
                                    int32_t priority,
                                    audio_session_t sessionId,
                                    effect_descriptor_t *desc,
                                    int *enabled,
                                    status_t *status /*non-NULL*/,
                                    bool pinned,
                                    bool probe,
                                    bool notifyFramesProcessed) final
            REQUIRES(audio_utils::AudioFlinger_Mutex);

                // return values for hasAudioSession (bit field)
                enum effect_state {
                    EFFECT_SESSION = 0x1,   // the audio session corresponds to at least one
                                            // effect
                    TRACK_SESSION = 0x2,    // the audio session corresponds to at least one
                                            // track
                    FAST_SESSION = 0x4,     // the audio session corresponds to at least one
                                            // fast track
                    SPATIALIZED_SESSION = 0x8, // the audio session corresponds to at least one
                                               // spatialized track
                    BIT_PERFECT_SESSION = 0x10 // the audio session corresponds to at least one
                                               // bit-perfect track
                };

    // get effect chain corresponding to session Id.
    sp<IAfEffectChain> getEffectChain(audio_session_t sessionId) const final;
    // same as getEffectChain() but must be called with ThreadBase mutex locked
    sp<IAfEffectChain> getEffectChain_l(audio_session_t sessionId) const final REQUIRES(mutex());
    std::vector<int> getEffectIds_l(audio_session_t sessionId) const final REQUIRES(mutex());

                // lock all effect chains Mutexes. Must be called before releasing the
                // ThreadBase mutex before processing the mixer and effects. This guarantees the
                // integrity of the chains during the process.
                // Also sets the parameter 'effectChains' to current value of mEffectChains.
    void lockEffectChains_l(Vector<sp<IAfEffectChain>>& effectChains) final REQUIRES(mutex());
                // unlock effect chains after process
    void unlockEffectChains(const Vector<sp<IAfEffectChain>>& effectChains) final;
                // get a copy of mEffectChains vector
    Vector<sp<IAfEffectChain>> getEffectChains_l() const final REQUIRES(mutex()) {
        return mEffectChains;
    }
                // set audio mode to all effect chains
    void setMode(audio_mode_t mode) final;
                // get effect module with corresponding ID on specified audio session
    sp<IAfEffectModule> getEffect(audio_session_t sessionId, int effectId) const final;
    sp<IAfEffectModule> getEffect_l(audio_session_t sessionId, int effectId) const final
            REQUIRES(mutex());
                // add and effect module. Also creates the effect chain is none exists for
                // the effects audio session. Only called in a context of moving an effect
                // from one thread to another
    status_t addEffect_ll(const sp<IAfEffectModule>& effect) final
            REQUIRES(audio_utils::AudioFlinger_Mutex, mutex());
                // remove and effect module. Also removes the effect chain is this was the last
                // effect
    void removeEffect_l(const sp<IAfEffectModule>& effect, bool release = false) final
            REQUIRES(mutex());
                // disconnect an effect handle from module and destroy module if last handle
    void disconnectEffectHandle(IAfEffectHandle* handle, bool unpinIfLast) final;
                // detach all tracks connected to an auxiliary effect
    void detachAuxEffect_l(int /* effectId */) override REQUIRES(mutex()) {}
    // TODO(b/291317898) - remove hasAudioSession_l below.
    uint32_t hasAudioSession_l(audio_session_t sessionId) const override REQUIRES(mutex()) = 0;
    uint32_t hasAudioSession(audio_session_t sessionId) const final EXCLUDES_ThreadBase_Mutex {
        audio_utils::lock_guard _l(mutex());
        return hasAudioSession_l(sessionId);
    }

                template <typename T>
    uint32_t hasAudioSession_l(audio_session_t sessionId, const T& tracks) const
            REQUIRES(mutex()) {
                    uint32_t result = 0;
                    if (getEffectChain_l(sessionId) != 0) {
                        result = EFFECT_SESSION;
                    }
                    for (size_t i = 0; i < tracks.size(); ++i) {
                        const sp<IAfTrackBase>& track = tracks[i];
                        if (sessionId == track->sessionId()
                                && !track->isInvalid()       // not yet removed from tracks.
                                && !track->isTerminated()) {
                            result |= TRACK_SESSION;
                            if (track->isFastTrack()) {
                                result |= FAST_SESSION;  // caution, only represents first track.
                            }
                            if (track->isSpatialized()) {
                                result |= SPATIALIZED_SESSION;  // caution, only first track.
                            }
                            if (track->isBitPerfect()) {
                                result |= BIT_PERFECT_SESSION;
                            }
                            break;
                        }
                    }
                    return result;
                }

                // the value returned by default implementation is not important as the
                // strategy is only meaningful for PlaybackThread which implements this method
    product_strategy_t getStrategyForSession_l(
            audio_session_t /* sessionId */) const override REQUIRES(mutex()){
        return static_cast<product_strategy_t>(0);
    }

                // check if some effects must be suspended/restored when an effect is enabled
                // or disabled
    void checkSuspendOnEffectEnabled(bool enabled,
                                                 audio_session_t sessionId,
                                                 bool threadLocked) final;


                // Return a reference to a per-thread heap which can be used to allocate IMemory
                // objects that will be read-only to client processes, read/write to mediaserver,
                // and shared by all client processes of the thread.
                // The heap is per-thread rather than common across all threads, because
                // clients can't be trusted not to modify the offset of the IMemory they receive.
                // If a thread does not have such a heap, this method returns 0.
    sp<MemoryDealer> readOnlyHeap() const override { return nullptr; }

    sp<IMemory> pipeMemory() const override { return nullptr; }

    void systemReady() final EXCLUDES_ThreadBase_Mutex;

    void broadcast_l() final REQUIRES(mutex());

    bool isTimestampCorrectionEnabled_l() const override REQUIRES(mutex()) { return false; }

    bool isMsdDevice() const final { return mIsMsdDevice; }

    void dump(int fd, const Vector<String16>& args) override;

                // deliver stats to mediametrics.
    void sendStatistics(bool force) final
            REQUIRES(ThreadBase_ThreadLoop) EXCLUDES_ThreadBase_Mutex;

    audio_utils::mutex& mutex() const final RETURN_CAPABILITY(audio_utils::ThreadBase_Mutex) {
        return mMutex;
    }
    mutable audio_utils::mutex mMutex{audio_utils::MutexOrder::kThreadBase_Mutex};

    void onEffectEnable(const sp<IAfEffectModule>& effect) final EXCLUDES_ThreadBase_Mutex;
    void onEffectDisable() final EXCLUDES_ThreadBase_Mutex;

                // invalidateTracksForAudioSession_l must be called with holding mutex().
    void invalidateTracksForAudioSession_l(audio_session_t /* sessionId */) const override
            REQUIRES(mutex()) {}
                // Invalidate all the tracks with the given audio session.
    void invalidateTracksForAudioSession(audio_session_t sessionId) const final
            EXCLUDES_ThreadBase_Mutex {
        audio_utils::lock_guard _l(mutex());
                    invalidateTracksForAudioSession_l(sessionId);
                }

                template <typename T>
    void invalidateTracksForAudioSession_l(audio_session_t sessionId,
            const T& tracks) const REQUIRES(mutex()) {
                    for (size_t i = 0; i < tracks.size(); ++i) {
                        const sp<IAfTrackBase>& track = tracks[i];
                        if (sessionId == track->sessionId()) {
                            track->invalidate();
                        }
                    }
                }

    void startMelComputation_l(const sp<audio_utils::MelProcessor>& processor) override
            REQUIRES(audio_utils::AudioFlinger_Mutex);
    void stopMelComputation_l() override
            REQUIRES(audio_utils::AudioFlinger_Mutex);

protected:

                // entry describing an effect being suspended in mSuspendedSessions keyed vector
                class SuspendedSessionDesc : public RefBase {
                public:
                    SuspendedSessionDesc() : mRefCount(0) {}

                    int mRefCount;          // number of active suspend requests
                    effect_uuid_t mType;    // effect type UUID
                };

    void acquireWakeLock() EXCLUDES_ThreadBase_Mutex;
    virtual void acquireWakeLock_l() REQUIRES(mutex());
    void releaseWakeLock() EXCLUDES_ThreadBase_Mutex;
    void releaseWakeLock_l() REQUIRES(mutex());
    void updateWakeLockUids_l(const SortedVector<uid_t> &uids) REQUIRES(mutex());
    void getPowerManager_l() REQUIRES(mutex());
                // suspend or restore effects of the specified type (or all if type is NULL)
                // on a given session. The number of suspend requests is counted and restore
                // occurs when all suspend requests are cancelled.
    void setEffectSuspended_l(const effect_uuid_t *type,
                                          bool suspend,
            audio_session_t sessionId) final REQUIRES(mutex());
                // updated mSuspendedSessions when an effect is suspended or restored
    void updateSuspendedSessions_l(const effect_uuid_t *type,
                                                      bool suspend,
            audio_session_t sessionId) REQUIRES(mutex());
                // check if some effects must be suspended when an effect chain is added
    void checkSuspendOnAddEffectChain_l(const sp<IAfEffectChain>& chain) REQUIRES(mutex());

                // sends the metadata of the active tracks to the HAL
                struct MetadataUpdate {
                    std::vector<playback_track_metadata_v7_t> playbackMetadataUpdate;
                    std::vector<record_track_metadata_v7_t>   recordMetadataUpdate;
                };
    // NO_THREAD_SAFETY_ANALYSIS, updateMetadata_l() should include ThreadBase_ThreadLoop
    // but MmapThread::start() -> exitStandby_l() -> updateMetadata_l() prevents this.
    virtual MetadataUpdate updateMetadata_l() REQUIRES(mutex()) = 0;

                String16 getWakeLockTag();

    virtual void preExit() EXCLUDES_ThreadBase_Mutex {}
    virtual void setMasterMono_l(bool mono __unused) REQUIRES(mutex()) {}
    virtual     bool        requireMonoBlend() { return false; }

                            // called within the threadLoop to obtain timestamp from the HAL.
    virtual status_t threadloop_getHalTimestamp_l(
            ExtendedTimestamp *timestamp __unused) const
            REQUIRES(mutex(), ThreadBase_ThreadLoop) {
                                return INVALID_OPERATION;
                            }
public:
// TODO(b/291317898) organize with publics
                product_strategy_t getStrategyForStream(audio_stream_type_t stream) const;
protected:

    virtual void onHalLatencyModesChanged_l() REQUIRES(mutex()) {}

    virtual void dumpInternals_l(int fd __unused, const Vector<String16>& args __unused)
            REQUIRES(mutex()) {}
    virtual void dumpTracks_l(int fd __unused, const Vector<String16>& args __unused)
            REQUIRES(mutex()) {}

                const type_t            mType;

                // Used by parameters, config events, addTrack_l, exit
                audio_utils::condition_variable mWaitWorkCV;

                const sp<IAfThreadCallback>  mAfThreadCallback;
                ThreadMetrics           mThreadMetrics;
                const bool              mIsOut;

                // updated by PlaybackThread::readOutputParameters_l() or
                // RecordThread::readInputParameters_l()
                uint32_t                mSampleRate;
                size_t                  mFrameCount;       // output HAL, direct output, record
                audio_channel_mask_t    mChannelMask;
                uint32_t                mChannelCount;
                size_t                  mFrameSize;
                // not HAL frame size, this is for output sink (to pipe to fast mixer)
                audio_format_t          mFormat;           // Source format for Recording and
                                                           // Sink format for Playback.
                                                           // Sink format may be different than
                                                           // HAL format if Fastmixer is used.
                audio_format_t          mHALFormat;
                size_t                  mBufferSize;       // HAL buffer size for read() or write()

     // output device types and addresses
    AudioDeviceTypeAddrVector mOutDeviceTypeAddrs GUARDED_BY(mutex());
    AudioDeviceTypeAddr mInDeviceTypeAddr GUARDED_BY(mutex());   // input device type and address
    Vector<sp<ConfigEvent>> mConfigEvents GUARDED_BY(mutex());

    // events awaiting system ready
    Vector<sp<ConfigEvent>> mPendingConfigEvents GUARDED_BY(mutex());

                // These fields are written and read by thread itself without lock or barrier,
                // and read by other threads without lock or barrier via standby(), outDeviceTypes()
                // and inDeviceType().
                // Because of the absence of a lock or barrier, any other thread that reads
                // these fields must use the information in isolation, or be prepared to deal
                // with possibility that it might be inconsistent with other information.
                bool                    mStandby;     // Whether thread is currently in standby.

    // NO_THREAD_SAFETY_ANALYSIS - mPatch and mAudioSource should be guarded by mutex().
                struct audio_patch      mPatch;
                audio_source_t          mAudioSource;

                const audio_io_handle_t mId;
    Vector<sp<IAfEffectChain>> mEffectChains GUARDED_BY(mutex());

                static const int        kThreadNameLength = 16; // prctl(PR_SET_NAME) limit
                char                    mThreadName[kThreadNameLength]; // guaranteed NUL-terminated
    sp<os::IPowerManager> mPowerManager GUARDED_BY(mutex());
    sp<IBinder> mWakeLockToken GUARDED_BY(mutex());
                const sp<PMDeathRecipient> mDeathRecipient;
                // list of suspended effects per session and per type. The first (outer) vector is
                // keyed by session ID, the second (inner) by type UUID timeLow field
                // Updated by updateSuspendedSessions_l() only.
                KeyedVector< audio_session_t, KeyedVector< int, sp<SuspendedSessionDesc> > >
                                        mSuspendedSessions;
                // TODO: add comment and adjust size as needed
                static const size_t     kLogSize = 4 * 1024;
                sp<NBLog::Writer>       mNBLogWriter;
                bool                    mSystemReady;

    // NO_THREAD_SAFETY_ANALYSIS - mTimestamp and mTimestampVerifier should be
    // accessed under mutex for the RecordThread.
    ExtendedTimestamp mTimestamp;
    TimestampVerifier<int64_t /* frame count */, int64_t /* time ns */> mTimestampVerifier;
                // DIRECT and OFFLOAD threads should reset frame count to zero on stop/flush
                // TODO: add confirmation checks:
                // 1) DIRECT threads and linear PCM format really resets to 0?
                // 2) Is frame count really valid if not linear pcm?
                // 3) Are all 64 bits of position returned, not just lowest 32 bits?
                // Timestamp corrected device should be a single device.

    audio_devices_t mTimestampCorrectedDevice = AUDIO_DEVICE_NONE;  // CONST set in ctor

                // ThreadLoop statistics per iteration.
    std::atomic<int64_t> mLastIoBeginNs = -1;  // set in threadLoop, read by dump()
    int64_t mLastIoEndNs GUARDED_BY(ThreadBase_ThreadLoop) = -1;

                // ThreadSnapshot is thread-safe (internally locked)
                mediautils::ThreadSnapshot mThreadSnapshot;

    audio_utils::Statistics<double> mIoJitterMs GUARDED_BY(mutex()) {0.995 /* alpha */};
    audio_utils::Statistics<double> mProcessTimeMs GUARDED_BY(mutex()) {0.995 /* alpha */};

    // NO_THREAD_SAFETY_ANALYSIS  GUARDED_BY(mutex())
                audio_utils::Statistics<double> mLatencyMs{0.995 /* alpha */};
                audio_utils::Statistics<double> mMonopipePipeDepthStats{0.999 /* alpha */};

                // Save the last count when we delivered statistics to mediametrics.
                int64_t                 mLastRecordedTimestampVerifierN = 0;
                int64_t                 mLastRecordedTimeNs = 0;  // BOOTTIME to include suspend.

                bool                    mIsMsdDevice = false;
                // A condition that must be evaluated by the thread loop has changed and
                // we must not wait for async write callback in the thread loop before evaluating it
                bool                    mSignalPending;

#ifdef TEE_SINK
                NBAIO_Tee               mTee;
#endif
                // ActiveTracks is a sorted vector of track type T representing the
                // active tracks of threadLoop() to be considered by the locked prepare portion.
                // ActiveTracks should be accessed with the ThreadBase lock held.
                //
                // During processing and I/O, the threadLoop does not hold the lock;
                // hence it does not directly use ActiveTracks.  Care should be taken
                // to hold local strong references or defer removal of tracks
                // if the threadLoop may still be accessing those tracks due to mix, etc.
                //
                // This class updates power information appropriately.
                //

                template <typename T>
                class ActiveTracks {
                public:
                    explicit ActiveTracks(SimpleLog *localLog = nullptr)
                        : mActiveTracksGeneration(0)
                        , mLastActiveTracksGeneration(0)
                        , mLocalLog(localLog)
                    { }

                    ~ActiveTracks() {
                        ALOGW_IF(!mActiveTracks.isEmpty(),
                                "ActiveTracks should be empty in destructor");
                    }
                    // returns the last track added (even though it may have been
                    // subsequently removed from ActiveTracks).
                    //
                    // Used for DirectOutputThread to ensure a flush is called when transitioning
                    // to a new track (even though it may be on the same session).
                    // Used for OffloadThread to ensure that volume and mixer state is
                    // taken from the latest track added.
                    //
                    // The latest track is saved with a weak pointer to prevent keeping an
                    // otherwise useless track alive. Thus the function will return nullptr
                    // if the latest track has subsequently been removed and destroyed.
                    sp<T> getLatest() {
                        return mLatestActiveTrack.promote();
                    }

                    // SortedVector methods
                    ssize_t         add(const sp<T> &track);
                    ssize_t         remove(const sp<T> &track);
                    size_t          size() const {
                        return mActiveTracks.size();
                    }
                    bool            isEmpty() const {
                        return mActiveTracks.isEmpty();
                    }
                    ssize_t indexOf(const sp<T>& item) const {
                        return mActiveTracks.indexOf(item);
                    }
                    sp<T>           operator[](size_t index) const {
                        return mActiveTracks[index];
                    }
                    typename SortedVector<sp<T>>::iterator begin() {
                        return mActiveTracks.begin();
                    }
                    typename SortedVector<sp<T>>::iterator end() {
                        return mActiveTracks.end();
                    }

                    // Due to Binder recursion optimization, clear() and updatePowerState()
                    // cannot be called from a Binder thread because they may call back into
                    // the original calling process (system server) for BatteryNotifier
                    // (which requires a Java environment that may not be present).
                    // Hence, call clear() and updatePowerState() only from the
                    // ThreadBase thread.
                    void            clear();
                    // periodically called in the threadLoop() to update power state uids.
                    void updatePowerState_l(const sp<ThreadBase>& thread, bool force = false)
                            REQUIRES(audio_utils::ThreadBase_Mutex);

                    /** @return true if one or move active tracks was added or removed since the
                     *          last time this function was called or the vector was created.
                     *          true if volume of one of active tracks was changed.
                     */
                    bool            readAndClearHasChanged();

                    /** Force updating track metadata to audio HAL stream next time
                     * readAndClearHasChanged() is called.
                     */
                    void            setHasChanged() { mHasChanged = true; }

                private:
                    void            logTrack(const char *funcName, const sp<T> &track) const;

                    SortedVector<uid_t> getWakeLockUids() {
                        SortedVector<uid_t> wakeLockUids;
                        for (const sp<T> &track : mActiveTracks) {
                            wakeLockUids.add(track->uid());
                        }
                        return wakeLockUids; // moved by underlying SharedBuffer
                    }

                    SortedVector<sp<T>> mActiveTracks;
                    int                 mActiveTracksGeneration;
                    int                 mLastActiveTracksGeneration;
                    wp<T>               mLatestActiveTrack; // latest track added to ActiveTracks
                    SimpleLog * const   mLocalLog;
                    // If the vector has changed since last call to readAndClearHasChanged
                    bool                mHasChanged = false;
                };

                SimpleLog mLocalLog;  // locked internally

private:
    void dumpBase_l(int fd, const Vector<String16>& args) REQUIRES(mutex());
    void dumpEffectChains_l(int fd, const Vector<String16>& args) REQUIRES(mutex());
};

// --- PlaybackThread ---
class PlaybackThread : public ThreadBase, public virtual IAfPlaybackThread,
                       public StreamOutHalInterfaceCallback,
                       public virtual VolumeInterface, public StreamOutHalInterfaceEventCallback {
public:
    sp<IAfPlaybackThread> asIAfPlaybackThread() final {
        return sp<IAfPlaybackThread>::fromExisting(this);
    }

    // retry count before removing active track in case of underrun on offloaded thread:
    // we need to make sure that AudioTrack client has enough time to send large buffers
    //FIXME may be more appropriate if expressed in time units. Need to revise how underrun is
    // handled for offloaded tracks
    static const int8_t kMaxTrackRetriesOffload = 20;
    static const int8_t kMaxTrackStartupRetriesOffload = 100;
    static constexpr uint32_t kMaxTracksPerUid = 40;
    static constexpr size_t kMaxTracks = 256;

    // Maximum delay (in nanoseconds) for upcoming buffers in suspend mode, otherwise
    // if delay is greater, the estimated time for timeLoopNextNs is reset.
    // This allows for catch-up to be done for small delays, while resetting the estimate
    // for initial conditions or large delays.
    static const nsecs_t kMaxNextBufferDelayNs = 100000000;

    PlaybackThread(const sp<IAfThreadCallback>& afThreadCallback, AudioStreamOut* output,
                   audio_io_handle_t id, type_t type, bool systemReady,
                   audio_config_base_t *mixerConfig = nullptr);
    ~PlaybackThread() override;

    // Thread virtuals
    bool threadLoop() final REQUIRES(ThreadBase_ThreadLoop) EXCLUDES_ThreadBase_Mutex;

    // RefBase
    void onFirstRef() override;

    status_t checkEffectCompatibility_l(
            const effect_descriptor_t* desc, audio_session_t sessionId) final REQUIRES(mutex());

    void addOutputTrack_l(const sp<IAfTrack>& track) final REQUIRES(mutex()) {
        mTracks.add(track);
    }

    status_t setAppVolume(const String8& packageName, const float value) final;
    status_t setAppMute(const String8& packageName, const bool muted) final;
    void listAppVolumes(std::set<media::AppVolume> &container) final;

protected:
    // Code snippets that were lifted up out of threadLoop()
    virtual void threadLoop_mix() REQUIRES(ThreadBase_ThreadLoop) = 0;
    virtual void threadLoop_sleepTime() REQUIRES(ThreadBase_ThreadLoop) = 0;
    virtual ssize_t threadLoop_write() REQUIRES(ThreadBase_ThreadLoop);
    virtual void threadLoop_drain() REQUIRES(ThreadBase_ThreadLoop);
    virtual void threadLoop_standby() REQUIRES(ThreadBase_ThreadLoop);
    virtual void threadLoop_exit() REQUIRES(ThreadBase_ThreadLoop);
    virtual void threadLoop_removeTracks(const Vector<sp<IAfTrack>>& tracksToRemove)
            REQUIRES(ThreadBase_ThreadLoop);

                // prepareTracks_l reads and writes mActiveTracks, and returns
                // the pending set of tracks to remove via Vector 'tracksToRemove'.  The caller
                // is responsible for clearing or destroying this Vector later on, when it
                // is safe to do so. That will drop the final ref count and destroy the tracks.
    virtual mixer_state prepareTracks_l(Vector<sp<IAfTrack>>* tracksToRemove)
            REQUIRES(mutex(), ThreadBase_ThreadLoop) = 0;

    void removeTracks_l(const Vector<sp<IAfTrack>>& tracksToRemove) REQUIRES(mutex());
    status_t handleVoipVolume_l(float *volume) REQUIRES(mutex());

    // StreamOutHalInterfaceCallback implementation
    virtual     void        onWriteReady();
    virtual     void        onDrainReady();
    virtual     void        onError();

public: // AsyncCallbackThread
                void        resetWriteBlocked(uint32_t sequence);
                void        resetDraining(uint32_t sequence);
protected:

    virtual     bool        waitingAsyncCallback();
    virtual bool waitingAsyncCallback_l() REQUIRES(mutex());
    virtual bool shouldStandby_l() REQUIRES(mutex(), ThreadBase_ThreadLoop);
    virtual void onAddNewTrack_l() REQUIRES(mutex());
public:  // AsyncCallbackThread
                void        onAsyncError(); // error reported by AsyncCallbackThread
protected:
    // StreamHalInterfaceCodecFormatCallback implementation
                void        onCodecFormatChanged(
            const std::basic_string<uint8_t>& metadataBs) final;

    // ThreadBase virtuals
    void preExit() final EXCLUDES_ThreadBase_Mutex;

    virtual     bool        keepWakeLock() const { return true; }
    virtual void acquireWakeLock_l() REQUIRES(mutex()) {
                                ThreadBase::acquireWakeLock_l();
        mActiveTracks.updatePowerState_l(this, true /* force */);
                            }

    virtual void checkOutputStageEffects()
            REQUIRES(ThreadBase_ThreadLoop) EXCLUDES_ThreadBase_Mutex {}
    virtual     void        setHalLatencyMode_l() {}


    void dumpInternals_l(int fd, const Vector<String16>& args) override REQUIRES(mutex());
    void dumpTracks_l(int fd, const Vector<String16>& args) final REQUIRES(mutex());

public:

    status_t initCheck() const final { return mOutput == nullptr ? NO_INIT : NO_ERROR; }

                // return estimated latency in milliseconds, as reported by HAL
    uint32_t latency() const final;
                // same, but lock must already be held
    uint32_t latency_l() const final /* REQUIRES(mutex()) */;  // NO_THREAD_SAFETY_ANALYSIS

                // VolumeInterface
    void setMasterVolume(float value) final;
    void setMasterBalance(float balance) override EXCLUDES_ThreadBase_Mutex;
    void setMasterMute(bool muted) final;
    void setStreamVolume(audio_stream_type_t stream, float value) final EXCLUDES_ThreadBase_Mutex;
    void setStreamMute(audio_stream_type_t stream, bool muted) final EXCLUDES_ThreadBase_Mutex;
    float streamVolume(audio_stream_type_t stream) const final EXCLUDES_ThreadBase_Mutex;
    void setVolumeForOutput_l(float left, float right) const final;

    sp<IAfTrack> createTrack_l(
                                const sp<Client>& client,
                                audio_stream_type_t streamType,
                                const audio_attributes_t& attr,
                                uint32_t *sampleRate,
                                audio_format_t format,
                                audio_channel_mask_t channelMask,
                                size_t *pFrameCount,
                                size_t *pNotificationFrameCount,
                                uint32_t notificationsPerBuffer,
                                float speed,
                                const sp<IMemory>& sharedBuffer,
                                audio_session_t sessionId,
                                audio_output_flags_t *flags,
                                pid_t creatorPid,
                                const AttributionSourceState& attributionSource,
                                pid_t tid,
                                status_t *status /*non-NULL*/,
                                audio_port_handle_t portId,
                                const sp<media::IAudioTrackCallback>& callback,
                                bool isSpatialized,
                                bool isBitPerfect,
                                audio_output_flags_t* afTrackFlags) final
            REQUIRES(audio_utils::AudioFlinger_Mutex);

    bool isTrackActive(const sp<IAfTrack>& track) const final {
        return mActiveTracks.indexOf(track) >= 0;
    }

    AudioStreamOut* getOutput_l() const final REQUIRES(mutex()) { return mOutput; }
    AudioStreamOut* getOutput() const final EXCLUDES_ThreadBase_Mutex;
    AudioStreamOut* clearOutput() final EXCLUDES_ThreadBase_Mutex;

    // NO_THREAD_SAFETY_ANALYSIS -- probably needs a lock.
    sp<StreamHalInterface> stream() const final;

    // suspend(), restore(), and isSuspended() are implemented atomically.
    void suspend() final { ++mSuspended; }
    void restore() final {
        // if restore() is done without suspend(), get back into
        // range so that the next suspend() will operate correctly
        while (true) {
            int32_t suspended = mSuspended;
            if (suspended <= 0) {
                ALOGW("%s: invalid mSuspended %d <= 0", __func__, suspended);
                return;
            }
            const int32_t desired = suspended - 1;
            if (mSuspended.compare_exchange_weak(suspended, desired)) return;
        }
    }
    bool isSuspended() const final { return mSuspended > 0; }

    String8 getParameters(const String8& keys) EXCLUDES_ThreadBase_Mutex;

    // Hold either the AudioFlinger::mutex or the ThreadBase::mutex
    void ioConfigChanged_l(audio_io_config_event_t event, pid_t pid = 0,
            audio_port_handle_t portId = AUDIO_PORT_HANDLE_NONE) final;
    status_t getRenderPosition(uint32_t* halFrames, uint32_t* dspFrames) const final
            EXCLUDES_ThreadBase_Mutex;
                // Consider also removing and passing an explicit mMainBuffer initialization
                // parameter to AF::IAfTrack::Track().
    float* sinkBuffer() const final {
                    return reinterpret_cast<float *>(mSinkBuffer); };

    void detachAuxEffect_l(int effectId) final REQUIRES(mutex());

    status_t attachAuxEffect(const sp<IAfTrack>& track, int EffectId) final
            EXCLUDES_ThreadBase_Mutex;
    status_t attachAuxEffect_l(const sp<IAfTrack>& track, int EffectId) final REQUIRES(mutex());

    status_t addEffectChain_l(const sp<IAfEffectChain>& chain) final REQUIRES(mutex());
    size_t removeEffectChain_l(const sp<IAfEffectChain>& chain) final REQUIRES(mutex());
    uint32_t hasAudioSession_l(audio_session_t sessionId) const final REQUIRES(mutex()) {
                            return ThreadBase::hasAudioSession_l(sessionId, mTracks);
                        }
    product_strategy_t getStrategyForSession_l(audio_session_t sessionId) const final
            REQUIRES(mutex());


    status_t setSyncEvent(const sp<audioflinger::SyncEvent>& event) final
            EXCLUDES_ThreadBase_Mutex;
    // could be static.
    bool isValidSyncEvent(const sp<audioflinger::SyncEvent>& event) const final;

    // Does this require the AudioFlinger mutex as well?
    bool invalidateTracks_l(audio_stream_type_t streamType) final
            REQUIRES(mutex());
    bool invalidateTracks_l(std::set<audio_port_handle_t>& portIds) final
            REQUIRES(mutex());
    void invalidateTracks(audio_stream_type_t streamType) override;
                // Invalidate tracks by a set of port ids. The port id will be removed from
                // the given set if the corresponding track is found and invalidated.
    void invalidateTracks(std::set<audio_port_handle_t>& portIds) override
            EXCLUDES_ThreadBase_Mutex;

    size_t frameCount() const final { return mNormalFrameCount; }

    audio_channel_mask_t mixerChannelMask() const final {
                    return mMixerChannelMask;
                }

    status_t getTimestamp_l(AudioTimestamp& timestamp) final
            REQUIRES(mutex(), ThreadBase_ThreadLoop);

    void addPatchTrack(const sp<IAfPatchTrack>& track) final EXCLUDES_ThreadBase_Mutex;
    void deletePatchTrack(const sp<IAfPatchTrack>& track) final EXCLUDES_ThreadBase_Mutex;

    // NO_THREAD_SAFETY_ANALYSIS - fix this to use atomics.
    void toAudioPortConfig(struct audio_port_config* config) final;

                // Return the asynchronous signal wait time.
    int64_t computeWaitTimeNs_l() const override REQUIRES(mutex()) { return INT64_MAX; }
                // returns true if the track is allowed to be added to the thread.
    bool isTrackAllowed_l(
                                    audio_channel_mask_t channelMask __unused,
                                    audio_format_t format __unused,
                                    audio_session_t sessionId __unused,
            uid_t uid) const override REQUIRES(mutex()) {
                                return trackCountForUid_l(uid) < PlaybackThread::kMaxTracksPerUid
                                       && mTracks.size() < PlaybackThread::kMaxTracks;
                            }

    bool isTimestampCorrectionEnabled_l() const final REQUIRES(mutex()) {
        return audio_is_output_devices(mTimestampCorrectedDevice)
                && outDeviceTypes_l().count(mTimestampCorrectedDevice) != 0;
                            }

    // NO_THREAD_SAFETY_ANALYSIS - fix this to be atomic.
    bool isStreamInitialized() const final {
                                return !(mOutput == nullptr || mOutput->stream == nullptr);
                            }

    audio_channel_mask_t hapticChannelMask() const final {
                                         return mHapticChannelMask;
                                     }

    uint32_t hapticChannelCount() const final {
        return mHapticChannelCount;
    }

    bool supportsHapticPlayback() const final {
                    return (mHapticChannelMask & AUDIO_CHANNEL_HAPTIC_ALL) != AUDIO_CHANNEL_NONE;
                }

    void setDownStreamPatch(const struct audio_patch* patch) final EXCLUDES_ThreadBase_Mutex {
        audio_utils::lock_guard _l(mutex());
                    mDownStreamPatch = *patch;
                }

    IAfTrack* getTrackById_l(audio_port_handle_t trackId) final REQUIRES(mutex());

    bool hasMixer() const final {
                    return mType == MIXER || mType == DUPLICATING || mType == SPATIALIZER;
                }

    status_t setRequestedLatencyMode(
            audio_latency_mode_t /* mode */) override { return INVALID_OPERATION; }

    status_t getSupportedLatencyModes(
            std::vector<audio_latency_mode_t>* /* modes */) override {
                    return INVALID_OPERATION;
                }

    status_t setBluetoothVariableLatencyEnabled(bool /* enabled */) override{
                    return INVALID_OPERATION;
                }

    void startMelComputation_l(const sp<audio_utils::MelProcessor>& processor) override
            REQUIRES(audio_utils::AudioFlinger_Mutex);
    void stopMelComputation_l() override
            REQUIRES(audio_utils::AudioFlinger_Mutex);

    void setStandby() final EXCLUDES_ThreadBase_Mutex {
        audio_utils::lock_guard _l(mutex());
                    setStandby_l();
                }

    void setStandby_l() final REQUIRES(mutex()) {
                    mStandby = true;
                    mHalStarted = false;
                    mKernelPositionOnStandby =
                        mTimestamp.mPosition[ExtendedTimestamp::LOCATION_KERNEL];
                }

    bool waitForHalStart() final EXCLUDES_ThreadBase_Mutex {
                    audio_utils::unique_lock _l(mutex());
                    static const nsecs_t kWaitHalTimeoutNs = seconds(2);
                    nsecs_t endWaitTimetNs = systemTime() + kWaitHalTimeoutNs;
                    while (!mHalStarted) {
                        nsecs_t timeNs = systemTime();
                        if (timeNs >= endWaitTimetNs) {
                            break;
                        }
                        nsecs_t waitTimeLeftNs = endWaitTimetNs - timeNs;
                        mWaitHalStartCV.wait_for(_l, std::chrono::nanoseconds(waitTimeLeftNs));
                    }
                    return mHalStarted;
                }
protected:
    // updated by readOutputParameters_l()
    size_t                          mNormalFrameCount;  // normal mixer and effects

    // throttle the thread processing
    bool mThreadThrottle GUARDED_BY(ThreadBase_ThreadLoop);

    // throttle time for MIXER threads - atomic as read by dump()
    std::atomic<uint32_t> mThreadThrottleTimeMs;

    // notify once per throttling
    uint32_t mThreadThrottleEndMs GUARDED_BY(ThreadBase_ThreadLoop);

    // half the buffer size in milliseconds
    uint32_t mHalfBufferMs GUARDED_BY(ThreadBase_ThreadLoop);

    void*                           mSinkBuffer;         // frame size aligned sink buffer

    // TODO:
    // Rearrange the buffer info into a struct/class with
    // clear, copy, construction, destruction methods.
    //
    // mSinkBuffer also has associated with it:
    //
    // mSinkBufferSize: Sink Buffer Size
    // mFormat: Sink Buffer Format

    // Mixer Buffer (mMixerBuffer*)
    //
    // In the case of floating point or multichannel data, which is not in the
    // sink format, it is required to accumulate in a higher precision or greater channel count
    // buffer before downmixing or data conversion to the sink buffer.

    // Set to "true" to enable the Mixer Buffer otherwise mixer output goes to sink buffer.
    bool mMixerBufferEnabled GUARDED_BY(ThreadBase_ThreadLoop);

    // Storage, 32 byte aligned (may make this alignment a requirement later).
    // Due to constraints on mNormalFrameCount, the buffer size is a multiple of 16 frames.
    void* mMixerBuffer GUARDED_BY(ThreadBase_ThreadLoop);

    // Size of mMixerBuffer in bytes: mNormalFrameCount * #channels * sampsize.
    size_t mMixerBufferSize GUARDED_BY(ThreadBase_ThreadLoop);

    // The audio format of mMixerBuffer. Set to AUDIO_FORMAT_PCM_(FLOAT|16_BIT) only.
    audio_format_t mMixerBufferFormat GUARDED_BY(ThreadBase_ThreadLoop);

    // An internal flag set to true by MixerThread::prepareTracks_l()
    // when mMixerBuffer contains valid data after mixing.
    bool mMixerBufferValid GUARDED_BY(ThreadBase_ThreadLoop);

    // Effects Buffer (mEffectsBuffer*)
    //
    // In the case of effects data, which is not in the sink format,
    // it is required to accumulate in a different buffer before data conversion
    // to the sink buffer.

    // Set to "true" to enable the Effects Buffer otherwise effects output goes to sink buffer.
    bool mEffectBufferEnabled;
    // NO_THREAD_SAFETY_ANALYSIS: Spatializer access this in addEffectChain_l()

    // Storage, 32 byte aligned (may make this alignment a requirement later).
    // Due to constraints on mNormalFrameCount, the buffer size is a multiple of 16 frames.
    void* mEffectBuffer;
    // NO_THREAD_SAFETY_ANALYSIS: Spatializer access this in addEffectChain_l()

    // Size of mEffectsBuffer in bytes: mNormalFrameCount * #channels * sampsize.
    size_t mEffectBufferSize;
    // NO_THREAD_SAFETY_ANALYSIS: Spatializer access this in addEffectChain_l()

    // The audio format of mEffectsBuffer. Set to AUDIO_FORMAT_PCM_16_BIT only.
    // NO_THREAD_SAFETY_ANALYSIS: Spatializer access this in addEffectChain_l()
    audio_format_t mEffectBufferFormat;

    // An internal flag set to true by MixerThread::prepareTracks_l()
    // when mEffectsBuffer contains valid data after mixing.
    //
    // When this is set, all mixer data is routed into the effects buffer
    // for any processing (including output processing).
    bool mEffectBufferValid GUARDED_BY(ThreadBase_ThreadLoop);

    // Set to "true" to enable when data has already copied to sink
    bool mHasDataCopiedToSinkBuffer GUARDED_BY(ThreadBase_ThreadLoop) = false;

    // Frame size aligned buffer used as input and output to all post processing effects
    // except the Spatializer in a SPATIALIZER thread. Non spatialized tracks are mixed into
    // this buffer so that post processing effects can be applied.
    void* mPostSpatializerBuffer GUARDED_BY(mutex()) = nullptr;

    // Size of mPostSpatializerBuffer in bytes
    size_t mPostSpatializerBufferSize GUARDED_BY(mutex());

    // suspend count, > 0 means suspended.  While suspended, the thread continues to pull from
    // tracks and mix, but doesn't write to HAL.  A2DP and SCO HAL implementations can't handle
    // concurrent use of both of them, so Audio Policy Service suspends one of the threads to
    // workaround that restriction.
    // 'volatile' means accessed via atomic operations and no lock.
    std::atomic<int32_t> mSuspended;

    int64_t                         mBytesWritten;
    std::atomic<int64_t> mFramesWritten;  // not reset on standby
    int64_t                         mLastFramesWritten = -1; // track changes in timestamp
                                                             // server frames written.
    int64_t                         mSuspendedFrames; // not reset on standby

    // mHapticChannelMask and mHapticChannelCount will only be valid when the thread support
    // haptic playback.
    audio_channel_mask_t            mHapticChannelMask = AUDIO_CHANNEL_NONE;
    uint32_t                        mHapticChannelCount = 0;

    audio_channel_mask_t            mMixerChannelMask = AUDIO_CHANNEL_NONE;

    // mMasterMute is in both PlaybackThread and in AudioFlinger.  When a
    // PlaybackThread needs to find out if master-muted, it checks it's local
    // copy rather than the one in AudioFlinger.  This optimization saves a lock.
    bool mMasterMute GUARDED_BY(mutex());
    void setMasterMute_l(bool muted) REQUIRES(mutex()) { mMasterMute = muted; }

                auto discontinuityForStandbyOrFlush() const { // call on threadLoop or with lock.
                    return ((mType == DIRECT && !audio_is_linear_pcm(mFormat))
                                    || mType == OFFLOAD)
                            ? mTimestampVerifier.DISCONTINUITY_MODE_ZERO
                            : mTimestampVerifier.DISCONTINUITY_MODE_CONTINUOUS;
                }

    ActiveTracks<IAfTrack> mActiveTracks;

    // Time to sleep between cycles when:
    virtual uint32_t        activeSleepTimeUs() const;      // mixer state MIXER_TRACKS_ENABLED
    virtual uint32_t        idleSleepTimeUs() const = 0;    // mixer state MIXER_IDLE
    virtual uint32_t        suspendSleepTimeUs() const = 0; // audio policy manager suspended us
    // No sleep when mixer state == MIXER_TRACKS_READY; relies on audio HAL stream->write()
    // No sleep in standby mode; waits on a condition

    // Code snippets that are temporarily lifted up out of threadLoop() until the merge

    // consider unification with MMapThread
    virtual void checkSilentMode_l() final REQUIRES(mutex());

    // Non-trivial for DUPLICATING only
    virtual void saveOutputTracks() REQUIRES(ThreadBase_ThreadLoop) {}
    virtual void clearOutputTracks() REQUIRES(ThreadBase_ThreadLoop) {}

    // Cache various calculated values, at threadLoop() entry and after a parameter change
    virtual void cacheParameters_l() REQUIRES(mutex(), ThreadBase_ThreadLoop);
                void        setCheckOutputStageEffects() override {
                                mCheckOutputStageEffects.store(true);
                            }

    virtual uint32_t correctLatency_l(uint32_t latency) const REQUIRES(mutex());

    virtual     status_t    createAudioPatch_l(const struct audio_patch *patch,
            audio_patch_handle_t *handle) REQUIRES(mutex());
    virtual status_t releaseAudioPatch_l(const audio_patch_handle_t handle)
            REQUIRES(mutex());

    // NO_THREAD_SAFETY_ANALYSIS - fix this to use atomics
    bool usesHwAvSync() const final { return mType == DIRECT && mOutput != nullptr
                                    && mHwSupportsPause
                                    && (mOutput->flags & AUDIO_OUTPUT_FLAG_HW_AV_SYNC); }

                uint32_t    trackCountForUid_l(uid_t uid) const;

                void        invalidateTracksForAudioSession_l(
            audio_session_t sessionId) const override REQUIRES(mutex()) {
                                ThreadBase::invalidateTracksForAudioSession_l(sessionId, mTracks);
                            }

    DISALLOW_COPY_AND_ASSIGN(PlaybackThread);

    status_t addTrack_l(const sp<IAfTrack>& track) final REQUIRES(mutex());
    bool destroyTrack_l(const sp<IAfTrack>& track) final REQUIRES(mutex());

    void removeTrack_l(const sp<IAfTrack>& track) REQUIRES(mutex());

    void readOutputParameters_l() REQUIRES(mutex());
    MetadataUpdate updateMetadata_l() final REQUIRES(mutex());
    virtual void sendMetadataToBackend_l(const StreamOutHalInterface::SourceMetadata& metadata)
            REQUIRES(mutex()) ;

    void collectTimestamps_l() REQUIRES(mutex(), ThreadBase_ThreadLoop);

    // The Tracks class manages tracks added and removed from the Thread.
    template <typename T>
    class Tracks {
    public:
        explicit Tracks(bool saveDeletedTrackIds) :
            mSaveDeletedTrackIds(saveDeletedTrackIds) { }

        // SortedVector methods
        ssize_t         add(const sp<T> &track) {
            const ssize_t index = mTracks.add(track);
            LOG_ALWAYS_FATAL_IF(index < 0, "cannot add track");
            return index;
        }
        ssize_t         remove(const sp<T> &track);
        size_t          size() const {
            return mTracks.size();
        }
        bool            isEmpty() const {
            return mTracks.isEmpty();
        }
        ssize_t         indexOf(const sp<T> &item) {
            return mTracks.indexOf(item);
        }
        sp<T>           operator[](size_t index) const {
            return mTracks[index];
        }
        typename SortedVector<sp<T>>::iterator begin() {
            return mTracks.begin();
        }
        typename SortedVector<sp<T>>::iterator end() {
            return mTracks.end();
        }

        size_t          processDeletedTrackIds(const std::function<void(int)>& f) {
            for (const int trackId : mDeletedTrackIds) {
                f(trackId);
            }
            return mDeletedTrackIds.size();
        }

        void            clearDeletedTrackIds() { mDeletedTrackIds.clear(); }

    private:
        // Tracks pending deletion for MIXER type threads
        const bool mSaveDeletedTrackIds; // true to enable tracking
        std::set<int> mDeletedTrackIds;

        SortedVector<sp<T>> mTracks; // wrapped SortedVector.
    };

    Tracks<IAfTrack>                   mTracks;

    stream_type_t                   mStreamTypes[AUDIO_STREAM_CNT];

    AudioStreamOut                  *mOutput;

    float                           mMasterVolume;
    std::atomic<float>              mMasterBalance{};
    audio_utils::Balance            mBalance;
    int                             mNumWrites;
    int                             mNumDelayedWrites;
    bool                            mInWrite;

    // FIXME rename these former local variables of threadLoop to standard "m" names
    nsecs_t                         mStandbyTimeNs;
    size_t                          mSinkBufferSize;

    // cached copies of activeSleepTimeUs() and idleSleepTimeUs() made by cacheParameters_l()
    uint32_t                        mActiveSleepTimeUs;
    uint32_t                        mIdleSleepTimeUs;

    uint32_t                        mSleepTimeUs;

    // mixer status returned by prepareTracks_l()
    mixer_state mMixerStatus GUARDED_BY(ThreadBase_ThreadLoop); // current cycle
                                                  // previous cycle when in prepareTracks_l()
    mixer_state mMixerStatusIgnoringFastTracks GUARDED_BY(ThreadBase_ThreadLoop);
                                                  // FIXME or a separate ready state per track

    // FIXME move these declarations into the specific sub-class that needs them
    // MIXER only
    uint32_t sleepTimeShift GUARDED_BY(ThreadBase_ThreadLoop);

    // same as AudioFlinger::mStandbyTimeInNsecs except for DIRECT which uses a shorter value
    nsecs_t mStandbyDelayNs;  // GUARDED_BY(mutex());

    // MIXER only
    nsecs_t                         maxPeriod;

    // DUPLICATING only
    uint32_t                        writeFrames;

    size_t mBytesRemaining GUARDED_BY(ThreadBase_ThreadLoop);
    size_t mCurrentWriteLength GUARDED_BY(ThreadBase_ThreadLoop);
    bool                            mUseAsyncWrite;
    // mWriteAckSequence contains current write sequence on bits 31-1. The write sequence is
    // incremented each time a write(), a flush() or a standby() occurs.
    // Bit 0 is set when a write blocks and indicates a callback is expected.
    // Bit 0 is reset by the async callback thread calling resetWriteBlocked(). Out of sequence
    // callbacks are ignored.
    uint32_t                        mWriteAckSequence;
    // mDrainSequence contains current drain sequence on bits 31-1. The drain sequence is
    // incremented each time a drain is requested or a flush() or standby() occurs.
    // Bit 0 is set when the drain() command is called at the HAL and indicates a callback is
    // expected.
    // Bit 0 is reset by the async callback thread calling resetDraining(). Out of sequence
    // callbacks are ignored.
    uint32_t                        mDrainSequence;

    sp<AsyncCallbackThread>         mCallbackThread;

    audio_utils::mutex& audioTrackCbMutex() const { return mAudioTrackCbMutex; }
    mutable audio_utils::mutex mAudioTrackCbMutex{
            audio_utils::MutexOrder::kPlaybackThread_AudioTrackCbMutex};
    // Record of IAudioTrackCallback
    std::map<sp<IAfTrack>, sp<media::IAudioTrackCallback>> mAudioTrackCallbacks;

    // The HAL output sink is treated as non-blocking, but current implementation is blocking
    sp<NBAIO_Sink>          mOutputSink;
    // If a fast mixer is present, the blocking pipe sink, otherwise clear
    sp<NBAIO_Sink>          mPipeSink;
    // The current sink for the normal mixer to write it's (sub)mix, mOutputSink or mPipeSink
    sp<NBAIO_Sink>          mNormalSink;

    uint32_t                mScreenState;   // cached copy of gScreenState
    // TODO: add comment and adjust size as needed
    static const size_t     kFastMixerLogSize = 8 * 1024;
    sp<NBLog::Writer>       mFastMixerNBLogWriter;

    // Downstream patch latency, available if mDownstreamLatencyStatMs.getN() > 0.
    audio_utils::Statistics<double> mDownstreamLatencyStatMs{0.999};

    // output stream start detection based on render position returned by the kernel
    // condition signalled when the output stream has started
    audio_utils::condition_variable mWaitHalStartCV;
    // true when the output stream render position has moved, reset to false in standby
    bool                     mHalStarted = false;
    // last kernel render position saved when entering standby
    int64_t                  mKernelPositionOnStandby = 0;

public:
    FastTrackUnderruns getFastTrackUnderruns(size_t /* fastIndex */) const override
        { return {}; }
    const std::atomic<int64_t>& framesWritten() const final { return mFramesWritten; }

protected:
                // accessed by both binder threads and within threadLoop(), lock on mutex needed
     uint32_t& fastTrackAvailMask_l() final REQUIRES(mutex()) { return mFastTrackAvailMask; }
     uint32_t mFastTrackAvailMask;  // bit i set if fast track [i] is available
                bool        mHwSupportsPause;
                bool        mHwPaused;
                bool        mFlushPending;
                // volumes last sent to audio HAL with stream->setVolume()
                float mLeftVolFloat;
                float mRightVolFloat;

                // audio patch used by the downstream software patch.
                // Only used if ThreadBase::mIsMsdDevice is true.
                struct audio_patch mDownStreamPatch;

                std::atomic_bool mCheckOutputStageEffects{};


                // Provides periodic checking for timestamp advancement for underrun detection.
                class IsTimestampAdvancing {
                public:
                    // The timestamp will not be checked any faster than the specified time.
                    explicit IsTimestampAdvancing(nsecs_t minimumTimeBetweenChecksNs)
                        :   mMinimumTimeBetweenChecksNs(minimumTimeBetweenChecksNs)
                    {
                        clear();
                    }
                    // Check if the presentation position has advanced in the last periodic time.
                    bool check(AudioStreamOut * output);
                    // Clear the internal state when the playback state changes for the output
                    // stream.
                    void clear();
                private:
                    // The minimum time between timestamp checks.
                    const nsecs_t mMinimumTimeBetweenChecksNs;
                    // Add differential check on the timestamps to see if there is a change in the
                    // timestamp frame position between the last call to check.
                    uint64_t mPreviousPosition;
                    // The time at which the last check occurred, to ensure we don't check too
                    // frequently, giving the Audio HAL enough time to update its timestamps.
                    nsecs_t mPreviousNs;
                    // The valued is latched so we don't check timestamps too frequently.
                    bool mLatchedValue;
                };
                IsTimestampAdvancing mIsTimestampAdvancing;

    virtual     void flushHw_l() {
                    mIsTimestampAdvancing.clear();
                }
};

class MixerThread : public PlaybackThread,
                    public StreamOutHalInterfaceLatencyModeCallback  {
public:
    MixerThread(const sp<IAfThreadCallback>& afThreadCallback,
                AudioStreamOut* output,
                audio_io_handle_t id,
                bool systemReady,
                type_t type = MIXER,
                audio_config_base_t *mixerConfig = nullptr);
    ~MixerThread() override;

    // RefBase
    void onFirstRef() override;

                // StreamOutHalInterfaceLatencyModeCallback
                void        onRecommendedLatencyModeChanged(
            std::vector<audio_latency_mode_t> modes) final;

    // Thread virtuals

    bool checkForNewParameter_l(const String8& keyValuePair, status_t& status) final
            REQUIRES(mutex());

    bool isTrackAllowed_l(
                                    audio_channel_mask_t channelMask, audio_format_t format,
            audio_session_t sessionId, uid_t uid) const final REQUIRES(mutex());
protected:
    mixer_state prepareTracks_l(Vector<sp<IAfTrack>>* tracksToRemove) override
            REQUIRES(mutex(), ThreadBase_ThreadLoop);
    uint32_t idleSleepTimeUs() const final;
    uint32_t suspendSleepTimeUs() const final;
    void cacheParameters_l() override REQUIRES(mutex(), ThreadBase_ThreadLoop);

    void acquireWakeLock_l() final REQUIRES(mutex()) {
        PlaybackThread::acquireWakeLock_l();
        if (hasFastMixer()) {
            mFastMixer->setBoottimeOffset(
                    mTimestamp.mTimebaseOffset[ExtendedTimestamp::TIMEBASE_BOOTTIME]);
        }
    }

    void dumpInternals_l(int fd, const Vector<String16>& args) override REQUIRES(mutex());

    // threadLoop snippets
    ssize_t threadLoop_write() override REQUIRES(ThreadBase_ThreadLoop);
    void threadLoop_standby() override REQUIRES(ThreadBase_ThreadLoop);
    void threadLoop_mix() override REQUIRES(ThreadBase_ThreadLoop);
    void threadLoop_sleepTime() override REQUIRES(ThreadBase_ThreadLoop);
    uint32_t correctLatency_l(uint32_t latency) const final REQUIRES(mutex());

    status_t createAudioPatch_l(
            const struct audio_patch* patch, audio_patch_handle_t* handle)
            final REQUIRES(mutex());
    status_t releaseAudioPatch_l(const audio_patch_handle_t handle) final REQUIRES(mutex());

                AudioMixer* mAudioMixer;    // normal mixer

            // Support low latency mode by default as unless explicitly indicated by the audio HAL
            // we assume the audio path is compatible with the head tracking latency requirements
            std::vector<audio_latency_mode_t> mSupportedLatencyModes = {AUDIO_LATENCY_MODE_LOW};
            // default to invalid value to force first update to the audio HAL
            audio_latency_mode_t mSetLatencyMode =
                    (audio_latency_mode_t)AUDIO_LATENCY_MODE_INVALID;

            // Bluetooth Variable latency control logic is enabled or disabled for this thread
            std::atomic_bool mBluetoothLatencyModesEnabled;

private:
                // one-time initialization, no locks required
                sp<FastMixer>     mFastMixer;     // non-0 if there is also a fast mixer
                sp<AudioWatchdog> mAudioWatchdog; // non-0 if there is an audio watchdog thread

                // contents are not guaranteed to be consistent, no locks required
                FastMixerDumpState mFastMixerDumpState;
#ifdef STATE_QUEUE_DUMP
                StateQueueObserverDump mStateQueueObserverDump;
                StateQueueMutatorDump  mStateQueueMutatorDump;
#endif
                AudioWatchdogDump mAudioWatchdogDump;

                // accessible only within the threadLoop(), no locks required
                //          mFastMixer->sq()    // for mutating and pushing state
    int32_t mFastMixerFutex GUARDED_BY(ThreadBase_ThreadLoop);  // for cold idle

                std::atomic_bool mMasterMono;
public:
    virtual     bool        hasFastMixer() const { return mFastMixer != 0; }
    virtual     FastTrackUnderruns getFastTrackUnderruns(size_t fastIndex) const {
                              ALOG_ASSERT(fastIndex < FastMixerState::sMaxFastTracks);
                              return mFastMixerDumpState.mTracks[fastIndex].mUnderruns;
                            }

    status_t threadloop_getHalTimestamp_l(
            ExtendedTimestamp *timestamp) const override
            REQUIRES(mutex(), ThreadBase_ThreadLoop) {
                                if (mNormalSink.get() != nullptr) {
                                    return mNormalSink->getTimestamp(*timestamp);
                                }
                                return INVALID_OPERATION;
                            }

                status_t    getSupportedLatencyModes(
                                    std::vector<audio_latency_mode_t>* modes) override;

                status_t    setBluetoothVariableLatencyEnabled(bool enabled) override;

protected:
    virtual     void       setMasterMono_l(bool mono) {
                               mMasterMono.store(mono);
                               if (mFastMixer != nullptr) { /* hasFastMixer() */
                                   mFastMixer->setMasterMono(mMasterMono);
                               }
                           }
                // the FastMixer performs mono blend if it exists.
                // Blending with limiter is not idempotent,
                // and blending without limiter is idempotent but inefficient to do twice.
    virtual     bool       requireMonoBlend() { return mMasterMono.load() && !hasFastMixer(); }

    void setMasterBalance(float balance) override EXCLUDES_ThreadBase_Mutex {
                               mMasterBalance.store(balance);
                               if (hasFastMixer()) {
                                   mFastMixer->setMasterBalance(balance);
                               }
                           }

    void updateHalSupportedLatencyModes_l() REQUIRES(mutex());
    void onHalLatencyModesChanged_l() override REQUIRES(mutex());
    void setHalLatencyMode_l() override REQUIRES(mutex());
};

class DirectOutputThread : public PlaybackThread, public virtual IAfDirectOutputThread {
public:

    sp<IAfDirectOutputThread> asIAfDirectOutputThread() final {
        return sp<IAfDirectOutputThread>::fromExisting(this);
    }

    DirectOutputThread(const sp<IAfThreadCallback>& afThreadCallback, AudioStreamOut* output,
                       audio_io_handle_t id, bool systemReady,
                       const audio_offload_info_t& offloadInfo)
        : DirectOutputThread(afThreadCallback, output, id, DIRECT, systemReady, offloadInfo) { }

    ~DirectOutputThread() override;

    status_t selectPresentation(int presentationId, int programId) final;

    // Thread virtuals

    virtual     bool        checkForNewParameter_l(const String8& keyValuePair,
            status_t& status) REQUIRES(mutex());

    void flushHw_l() override REQUIRES(mutex(), ThreadBase_ThreadLoop);

    void setMasterBalance(float balance) override EXCLUDES_ThreadBase_Mutex;

protected:
    virtual     uint32_t    activeSleepTimeUs() const;
    virtual     uint32_t    idleSleepTimeUs() const;
    virtual     uint32_t    suspendSleepTimeUs() const;
    virtual void cacheParameters_l() REQUIRES(mutex(), ThreadBase_ThreadLoop);

    void dumpInternals_l(int fd, const Vector<String16>& args) override REQUIRES(mutex());

    // threadLoop snippets
    virtual mixer_state prepareTracks_l(Vector<sp<IAfTrack>>* tracksToRemove)
            REQUIRES(mutex(), ThreadBase_ThreadLoop);
    virtual void threadLoop_mix() REQUIRES(ThreadBase_ThreadLoop);
    virtual void threadLoop_sleepTime() REQUIRES(ThreadBase_ThreadLoop);
    virtual void threadLoop_exit() REQUIRES(ThreadBase_ThreadLoop);
    virtual bool shouldStandby_l() REQUIRES(mutex());

    virtual void onAddNewTrack_l() REQUIRES(mutex());

    const       audio_offload_info_t mOffloadInfo;

    audioflinger::MonotonicFrameCounter mMonotonicFrameCounter;  // for VolumeShaper
    bool mVolumeShaperActive = false;

    DirectOutputThread(const sp<IAfThreadCallback>& afThreadCallback, AudioStreamOut* output,
                       audio_io_handle_t id, ThreadBase::type_t type, bool systemReady,
                       const audio_offload_info_t& offloadInfo);
    void processVolume_l(IAfTrack *track, bool lastTrack) REQUIRES(mutex());
    bool isTunerStream() const { return (mOffloadInfo.content_id > 0); }

    // prepareTracks_l() tells threadLoop_mix() the name of the single active track
    sp<IAfTrack>               mActiveTrack;

    wp<IAfTrack>               mPreviousTrack;         // used to detect track switch

    // This must be initialized for initial condition of mMasterBalance = 0 (disabled).
    float                   mMasterBalanceLeft = 1.f;
    float                   mMasterBalanceRight = 1.f;

public:
    virtual     bool        hasFastMixer() const { return false; }

    virtual int64_t computeWaitTimeNs_l() const override REQUIRES(mutex());

    status_t    threadloop_getHalTimestamp_l(ExtendedTimestamp *timestamp) const override {
                    // For DIRECT and OFFLOAD threads, query the output sink directly.
                    if (mOutput != nullptr) {
                        uint64_t uposition64;
                        struct timespec time;
                        if (mOutput->getPresentationPosition(
                                &uposition64, &time) == OK) {
                            timestamp->mPosition[ExtendedTimestamp::LOCATION_KERNEL]
                                    = (int64_t)uposition64;
                            timestamp->mTimeNs[ExtendedTimestamp::LOCATION_KERNEL]
                                    = audio_utils_ns_from_timespec(&time);
                            return NO_ERROR;
                        }
                    }
                    return INVALID_OPERATION;
                }
};

class OffloadThread : public DirectOutputThread {
public:

    OffloadThread(const sp<IAfThreadCallback>& afThreadCallback, AudioStreamOut* output,
                  audio_io_handle_t id, bool systemReady,
                  const audio_offload_info_t& offloadInfo);
    virtual                 ~OffloadThread() {};
    void flushHw_l() final REQUIRES(mutex(), ThreadBase_ThreadLoop);

protected:
    // threadLoop snippets
    mixer_state prepareTracks_l(Vector<sp<IAfTrack>>* tracksToRemove) final
            REQUIRES(mutex(), ThreadBase_ThreadLoop);
    void threadLoop_exit() final REQUIRES(ThreadBase_ThreadLoop);

    bool waitingAsyncCallback() final;
    bool waitingAsyncCallback_l() final REQUIRES(mutex());
    void invalidateTracks(audio_stream_type_t streamType) final EXCLUDES_ThreadBase_Mutex;
    void invalidateTracks(std::set<audio_port_handle_t>& portIds) final EXCLUDES_ThreadBase_Mutex;

    bool keepWakeLock() const final { return (mKeepWakeLock || (mDrainSequence & 1)); }

private:
    size_t      mPausedWriteLength;     // length in bytes of write interrupted by pause
    size_t      mPausedBytesRemaining;  // bytes still waiting in mixbuffer after resume
    bool        mKeepWakeLock;          // keep wake lock while waiting for write callback
};

class AsyncCallbackThread : public Thread {
public:
    explicit AsyncCallbackThread(const wp<PlaybackThread>& playbackThread);

    // Thread virtuals
    bool threadLoop() final;

    // RefBase
    void onFirstRef() final;

            void        exit();
            void        setWriteBlocked(uint32_t sequence);
            void        resetWriteBlocked();
            void        setDraining(uint32_t sequence);
            void        resetDraining();
            void        setAsyncError();

private:
    const wp<PlaybackThread>   mPlaybackThread;
    // mWriteAckSequence corresponds to the last write sequence passed by the offload thread via
    // setWriteBlocked(). The sequence is shifted one bit to the left and the lsb is used
    // to indicate that the callback has been received via resetWriteBlocked()
    uint32_t                   mWriteAckSequence;
    // mDrainSequence corresponds to the last drain sequence passed by the offload thread via
    // setDraining(). The sequence is shifted one bit to the left and the lsb is used
    // to indicate that the callback has been received via resetDraining()
    uint32_t                   mDrainSequence;
    audio_utils::condition_variable mWaitWorkCV;
    mutable audio_utils::mutex mMutex{audio_utils::MutexOrder::kAsyncCallbackThread_Mutex};
    bool                       mAsyncError;

    audio_utils::mutex& mutex() const RETURN_CAPABILITY(audio_utils::AsyncCallbackThread_Mutex) {
        return mMutex;
    }
};

class DuplicatingThread : public MixerThread, public IAfDuplicatingThread {
public:
    DuplicatingThread(const sp<IAfThreadCallback>& afThreadCallback,
            IAfPlaybackThread* mainThread,
                      audio_io_handle_t id, bool systemReady);
    ~DuplicatingThread() override;

    sp<IAfDuplicatingThread> asIAfDuplicatingThread() final {
        return sp<IAfDuplicatingThread>::fromExisting(this);
    }

    // Thread virtuals
    void addOutputTrack(IAfPlaybackThread* thread) final EXCLUDES_ThreadBase_Mutex;
    void removeOutputTrack(IAfPlaybackThread* thread) final EXCLUDES_ThreadBase_Mutex;
    uint32_t waitTimeMs() const final { return mWaitTimeMs; }

                void        sendMetadataToBackend_l(
            const StreamOutHalInterface::SourceMetadata& metadata) final REQUIRES(mutex());
protected:
    virtual     uint32_t    activeSleepTimeUs() const;
    void dumpInternals_l(int fd, const Vector<String16>& args) final REQUIRES(mutex());

private:
    bool outputsReady() REQUIRES(ThreadBase_ThreadLoop);
protected:
    // threadLoop snippets
    void threadLoop_mix() final REQUIRES(ThreadBase_ThreadLoop);
    void threadLoop_sleepTime() final REQUIRES(ThreadBase_ThreadLoop);
    ssize_t threadLoop_write() final REQUIRES(ThreadBase_ThreadLoop);
    void threadLoop_standby() final REQUIRES(ThreadBase_ThreadLoop);
    void threadLoop_exit() final REQUIRES(ThreadBase_ThreadLoop);
    void cacheParameters_l() final REQUIRES(mutex(), ThreadBase_ThreadLoop);

private:
    // called from threadLoop, addOutputTrack, removeOutputTrack
    void updateWaitTime_l() REQUIRES(mutex());
protected:
    void saveOutputTracks() final REQUIRES(mutex(), ThreadBase_ThreadLoop);
    void clearOutputTracks() final REQUIRES(mutex(), ThreadBase_ThreadLoop);
private:

                uint32_t    mWaitTimeMs;
    // NO_THREAD_SAFETY_ANALYSIS  GUARDED_BY(ThreadBase_ThreadLoop)
    SortedVector <sp<IAfOutputTrack>> outputTracks;
    SortedVector <sp<IAfOutputTrack>> mOutputTracks GUARDED_BY(mutex());
public:
    virtual     bool        hasFastMixer() const { return false; }
                status_t    threadloop_getHalTimestamp_l(
            ExtendedTimestamp *timestamp) const override REQUIRES(mutex()) {
        if (mOutputTracks.size() > 0) {
            // forward the first OutputTrack's kernel information for timestamp.
            const ExtendedTimestamp trackTimestamp =
                    mOutputTracks[0]->getClientProxyTimestamp();
            if (trackTimestamp.mTimeNs[ExtendedTimestamp::LOCATION_KERNEL] > 0) {
                timestamp->mTimeNs[ExtendedTimestamp::LOCATION_KERNEL] =
                        trackTimestamp.mTimeNs[ExtendedTimestamp::LOCATION_KERNEL];
                timestamp->mPosition[ExtendedTimestamp::LOCATION_KERNEL] =
                        trackTimestamp.mPosition[ExtendedTimestamp::LOCATION_KERNEL];
                return OK;  // discard server timestamp - that's ignored.
            }
        }
        return INVALID_OPERATION;
    }
};

class SpatializerThread : public MixerThread {
public:
    SpatializerThread(const sp<IAfThreadCallback>& afThreadCallback,
                           AudioStreamOut* output,
                           audio_io_handle_t id,
                           bool systemReady,
                           audio_config_base_t *mixerConfig);

    bool hasFastMixer() const final { return false; }

    status_t setRequestedLatencyMode(audio_latency_mode_t mode) final EXCLUDES_ThreadBase_Mutex;

protected:
    void checkOutputStageEffects() final
            REQUIRES(ThreadBase_ThreadLoop) EXCLUDES_ThreadBase_Mutex;
    void setHalLatencyMode_l() final REQUIRES(mutex());

    void threadLoop_exit() final REQUIRES(ThreadBase_ThreadLoop);

private:
            // Do not request a specific mode by default
            audio_latency_mode_t mRequestedLatencyMode = AUDIO_LATENCY_MODE_FREE;

            sp<IAfEffectHandle> mFinalDownMixer;
};

// record thread
class RecordThread : public IAfRecordThread, public ThreadBase
{
    friend class ResamplerBufferProvider;
public:
    sp<IAfRecordThread> asIAfRecordThread() final {
        return sp<IAfRecordThread>::fromExisting(this);
    }

            RecordThread(const sp<IAfThreadCallback>& afThreadCallback,
                    AudioStreamIn *input,
                    audio_io_handle_t id,
                    bool systemReady
                    );
    ~RecordThread() override;

    // no addTrack_l ?
    void destroyTrack_l(const sp<IAfRecordTrack>& track) final REQUIRES(mutex());
    void removeTrack_l(const sp<IAfRecordTrack>& track) final REQUIRES(mutex());

    // Thread virtuals
    bool threadLoop() final REQUIRES(ThreadBase_ThreadLoop) EXCLUDES_ThreadBase_Mutex;
    void preExit() final EXCLUDES_ThreadBase_Mutex;

    // RefBase
    void onFirstRef() final EXCLUDES_ThreadBase_Mutex;

    status_t initCheck() const final { return mInput == nullptr ? NO_INIT : NO_ERROR; }

    sp<MemoryDealer> readOnlyHeap() const final { return mReadOnlyHeap; }

    sp<IMemory> pipeMemory() const final { return mPipeMemory; }

    sp<IAfRecordTrack> createRecordTrack_l(
                    const sp<Client>& client,
                    const audio_attributes_t& attr,
                    uint32_t *pSampleRate,
                    audio_format_t format,
                    audio_channel_mask_t channelMask,
                    size_t *pFrameCount,
                    audio_session_t sessionId,
                    size_t *pNotificationFrameCount,
                    pid_t creatorPid,
                    const AttributionSourceState& attributionSource,
                    audio_input_flags_t *flags,
                    pid_t tid,
                    status_t *status /*non-NULL*/,
                    audio_port_handle_t portId,
                    int32_t maxSharedAudioHistoryMs) final
            REQUIRES(audio_utils::AudioFlinger_Mutex) EXCLUDES_ThreadBase_Mutex;

            status_t start(IAfRecordTrack* recordTrack,
                              AudioSystem::sync_event_t event,
            audio_session_t triggerSession) final EXCLUDES_ThreadBase_Mutex;

            // ask the thread to stop the specified track, and
            // return true if the caller should then do it's part of the stopping process
    bool stop(IAfRecordTrack* recordTrack) final EXCLUDES_ThreadBase_Mutex;
    AudioStreamIn* getInput() const final { return mInput; }
    AudioStreamIn* clearInput() final;

            // TODO(b/291317898) Unify with IAfThreadBase
            virtual sp<StreamHalInterface> stream() const;


    virtual bool checkForNewParameter_l(const String8& keyValuePair,
                                               status_t& status) REQUIRES(mutex());
    virtual void cacheParameters_l() REQUIRES(mutex(), ThreadBase_ThreadLoop) {}
    virtual String8 getParameters(const String8& keys) EXCLUDES_ThreadBase_Mutex;

    // Hold either the AudioFlinger::mutex or the ThreadBase::mutex
    void ioConfigChanged_l(audio_io_config_event_t event, pid_t pid = 0,
            audio_port_handle_t portId = AUDIO_PORT_HANDLE_NONE) final;
    virtual status_t    createAudioPatch_l(const struct audio_patch *patch,
            audio_patch_handle_t *handle) REQUIRES(mutex());
    virtual status_t releaseAudioPatch_l(const audio_patch_handle_t handle) REQUIRES(mutex());
    void updateOutDevices(const DeviceDescriptorBaseVector& outDevices) override
            EXCLUDES_ThreadBase_Mutex;
    void resizeInputBuffer_l(int32_t maxSharedAudioHistoryMs) override REQUIRES(mutex());

    void addPatchTrack(const sp<IAfPatchRecord>& record) final EXCLUDES_ThreadBase_Mutex;
    void deletePatchTrack(const sp<IAfPatchRecord>& record) final EXCLUDES_ThreadBase_Mutex;

    void readInputParameters_l() REQUIRES(mutex());
    uint32_t getInputFramesLost() const final EXCLUDES_ThreadBase_Mutex;

    virtual status_t addEffectChain_l(const sp<IAfEffectChain>& chain) REQUIRES(mutex());
    virtual size_t removeEffectChain_l(const sp<IAfEffectChain>& chain) REQUIRES(mutex());
    uint32_t hasAudioSession_l(audio_session_t sessionId) const override REQUIRES(mutex()) {
                         return ThreadBase::hasAudioSession_l(sessionId, mTracks);
                     }

            // Return the set of unique session IDs across all tracks.
            // The keys are the session IDs, and the associated values are meaningless.
            // FIXME replace by Set [and implement Bag/Multiset for other uses].
            KeyedVector<audio_session_t, bool> sessionIds() const;

    status_t setSyncEvent(const sp<audioflinger::SyncEvent>& event) override
            EXCLUDES_ThreadBase_Mutex;
            bool     isValidSyncEvent(const sp<audioflinger::SyncEvent>& event) const override;

    static void syncStartEventCallback(const wp<audioflinger::SyncEvent>& event);

    virtual size_t      frameCount() const { return mFrameCount; }
    bool hasFastCapture() const final { return mFastCapture != 0; }
    virtual void        toAudioPortConfig(struct audio_port_config *config);

    virtual status_t checkEffectCompatibility_l(const effect_descriptor_t *desc,
            audio_session_t sessionId) REQUIRES(mutex());

    virtual void acquireWakeLock_l() REQUIRES(mutex()) {
                            ThreadBase::acquireWakeLock_l();
        mActiveTracks.updatePowerState_l(this, true /* force */);
                        }

    void checkBtNrec() final EXCLUDES_ThreadBase_Mutex;

            // Sets the UID records silence
    void setRecordSilenced(audio_port_handle_t portId, bool silenced) final
            EXCLUDES_ThreadBase_Mutex;

    status_t getActiveMicrophones(
            std::vector<media::MicrophoneInfoFw>* activeMicrophones) const final
            EXCLUDES_ThreadBase_Mutex;
    status_t setPreferredMicrophoneDirection(audio_microphone_direction_t direction) final
            EXCLUDES_ThreadBase_Mutex;
    status_t setPreferredMicrophoneFieldDimension(float zoom) final EXCLUDES_ThreadBase_Mutex;

    MetadataUpdate updateMetadata_l() override REQUIRES(mutex());

    bool fastTrackAvailable() const final { return mFastTrackAvail; }
    void setFastTrackAvailable(bool available) final { mFastTrackAvail = available; }

    bool isTimestampCorrectionEnabled_l() const override REQUIRES(mutex()) {
                            // checks popcount for exactly one device.
                            // Is currently disabled. Before enabling,
                            // verify compressed record timestamps.
                            return audio_is_input_device(mTimestampCorrectedDevice)
                && inDeviceType_l() == mTimestampCorrectedDevice;
                        }

    status_t shareAudioHistory(const std::string& sharedAudioPackageName,
                                          audio_session_t sharedSessionId = AUDIO_SESSION_NONE,
            int64_t sharedAudioStartMs = -1) final EXCLUDES_ThreadBase_Mutex;
            status_t    shareAudioHistory_l(const std::string& sharedAudioPackageName,
                                          audio_session_t sharedSessionId = AUDIO_SESSION_NONE,
            int64_t sharedAudioStartMs = -1) REQUIRES(mutex());
    void resetAudioHistory_l() final REQUIRES(mutex());

    bool isStreamInitialized() const final {
                            return !(mInput == nullptr || mInput->stream == nullptr);
                        }

protected:
    void dumpInternals_l(int fd, const Vector<String16>& args) override REQUIRES(mutex());
    void dumpTracks_l(int fd, const Vector<String16>& args) override REQUIRES(mutex());

private:
            // Enter standby if not already in standby, and set mStandby flag
            void    standbyIfNotAlreadyInStandby();

            // Call the HAL standby method unconditionally, and don't change mStandby flag
            void    inputStandBy();

    void checkBtNrec_l() REQUIRES(mutex());

    int32_t getOldestFront_l() REQUIRES(mutex());
    void updateFronts_l(int32_t offset) REQUIRES(mutex());

            AudioStreamIn                       *mInput;
            Source                              *mSource;
            SortedVector <sp<IAfRecordTrack>>    mTracks;
            // mActiveTracks has dual roles:  it indicates the current active track(s), and
            // is used together with mStartStopCV to indicate start()/stop() progress
            ActiveTracks<IAfRecordTrack>           mActiveTracks;

            audio_utils::condition_variable mStartStopCV;

            // resampler converts input at HAL Hz to output at AudioRecord client Hz
            void                               *mRsmpInBuffer;  // size = mRsmpInFramesOA
            size_t                              mRsmpInFrames;  // size of resampler input in frames
            size_t                              mRsmpInFramesP2;// size rounded up to a power-of-2
            size_t                              mRsmpInFramesOA;// mRsmpInFramesP2 + over-allocation

            // rolling index that is never cleared
            int32_t                             mRsmpInRear;    // last filled frame + 1

            // For dumpsys
            const sp<MemoryDealer>              mReadOnlyHeap;

            // one-time initialization, no locks required
            sp<FastCapture>                     mFastCapture;   // non-0 if there is also
                                                                // a fast capture

            // FIXME audio watchdog thread

            // contents are not guaranteed to be consistent, no locks required
            FastCaptureDumpState                mFastCaptureDumpState;
#ifdef STATE_QUEUE_DUMP
            // FIXME StateQueue observer and mutator dump fields
#endif
            // FIXME audio watchdog dump

            // accessible only within the threadLoop(), no locks required
            //          mFastCapture->sq()      // for mutating and pushing state
            int32_t     mFastCaptureFutex;      // for cold idle

            // The HAL input source is treated as non-blocking,
            // but current implementation is blocking
            sp<NBAIO_Source>                    mInputSource;
            // The source for the normal capture thread to read from: mInputSource or mPipeSource
            sp<NBAIO_Source>                    mNormalSource;
            // If a fast capture is present, the non-blocking pipe sink written to by fast capture,
            // otherwise clear
            sp<NBAIO_Sink>                      mPipeSink;
            // If a fast capture is present, the non-blocking pipe source read by normal thread,
            // otherwise clear
            sp<NBAIO_Source>                    mPipeSource;
            // Depth of pipe from fast capture to normal thread and fast clients, always power of 2
            size_t                              mPipeFramesP2;
            // If a fast capture is present, the Pipe as IMemory, otherwise clear
            sp<IMemory>                         mPipeMemory;

            // TODO: add comment and adjust size as needed
            static const size_t                 kFastCaptureLogSize = 4 * 1024;
            sp<NBLog::Writer>                   mFastCaptureNBLogWriter;

            bool                                mFastTrackAvail;    // true if fast track available
            // common state to all record threads
            std::atomic_bool                    mBtNrecSuspended;

            int64_t                             mFramesRead = 0;    // continuous running counter.

            DeviceDescriptorBaseVector          mOutDevices;

            int32_t                             mMaxSharedAudioHistoryMs = 0;
            std::string                         mSharedAudioPackageName = {};
            int32_t                             mSharedAudioStartFrames = -1;
            audio_session_t                     mSharedAudioSessionId = AUDIO_SESSION_NONE;
};

class MmapThread : public ThreadBase, public virtual IAfMmapThread
{
 public:
    MmapThread(const sp<IAfThreadCallback>& afThreadCallback, audio_io_handle_t id,
               AudioHwDevice *hwDev, const sp<StreamHalInterface>& stream, bool systemReady,
               bool isOut);

    void configure(const audio_attributes_t* attr,
                                      audio_stream_type_t streamType,
                                      audio_session_t sessionId,
                                      const sp<MmapStreamCallback>& callback,
                                      audio_port_handle_t deviceId,
            audio_port_handle_t portId) override EXCLUDES_ThreadBase_Mutex {
        audio_utils::lock_guard l(mutex());
        configure_l(attr, streamType, sessionId, callback, deviceId, portId);
    }

    void configure_l(const audio_attributes_t* attr,
            audio_stream_type_t streamType,
            audio_session_t sessionId,
            const sp<MmapStreamCallback>& callback,
            audio_port_handle_t deviceId,
            audio_port_handle_t portId) REQUIRES(mutex());

    void disconnect() final EXCLUDES_ThreadBase_Mutex;

    // MmapStreamInterface for adapter.
    status_t createMmapBuffer(int32_t minSizeFrames, struct audio_mmap_buffer_info* info) final
            EXCLUDES_ThreadBase_Mutex;
    status_t getMmapPosition(struct audio_mmap_position* position) const override
            EXCLUDES_ThreadBase_Mutex;
    status_t start(const AudioClient& client,
                   const audio_attributes_t *attr,
            audio_port_handle_t* handle) final EXCLUDES_ThreadBase_Mutex;
    status_t stop(audio_port_handle_t handle) final EXCLUDES_ThreadBase_Mutex;
    status_t standby() final EXCLUDES_ThreadBase_Mutex;
    status_t getExternalPosition(uint64_t* position, int64_t* timeNanos) const
            EXCLUDES_ThreadBase_Mutex = 0;
    status_t reportData(const void* buffer, size_t frameCount) override EXCLUDES_ThreadBase_Mutex;

    // RefBase
    void onFirstRef() final;

    // Thread virtuals
    bool threadLoop() final REQUIRES(ThreadBase_ThreadLoop) EXCLUDES_ThreadBase_Mutex;

    // Not in ThreadBase
    virtual void threadLoop_exit() final REQUIRES(ThreadBase_ThreadLoop);
    virtual void threadLoop_standby() final REQUIRES(ThreadBase_ThreadLoop);
    virtual bool shouldStandby_l() final REQUIRES(mutex()){ return false; }
    virtual status_t exitStandby_l() REQUIRES(mutex());

    status_t initCheck() const final { return mHalStream == nullptr ? NO_INIT : NO_ERROR; }
    size_t frameCount() const final { return mFrameCount; }
    bool checkForNewParameter_l(const String8& keyValuePair, status_t& status)
            final REQUIRES(mutex());
    String8 getParameters(const String8& keys) final EXCLUDES_ThreadBase_Mutex;
    void ioConfigChanged_l(audio_io_config_event_t event, pid_t pid = 0,
            audio_port_handle_t portId = AUDIO_PORT_HANDLE_NONE) final
            /* holds either AF::mutex or TB::mutex */;
    void readHalParameters_l() REQUIRES(mutex());
    void cacheParameters_l() final REQUIRES(mutex(), ThreadBase_ThreadLoop) {}
    status_t createAudioPatch_l(
            const struct audio_patch* patch, audio_patch_handle_t* handle) final
            REQUIRES(mutex());
    status_t releaseAudioPatch_l(const audio_patch_handle_t handle) final
            REQUIRES(mutex());
    // NO_THREAD_SAFETY_ANALYSIS
    void toAudioPortConfig(struct audio_port_config* config) override;

    sp<StreamHalInterface> stream() const final { return mHalStream; }
    status_t addEffectChain_l(const sp<IAfEffectChain>& chain) final REQUIRES(mutex());
    size_t removeEffectChain_l(const sp<IAfEffectChain>& chain) final REQUIRES(mutex());
    status_t checkEffectCompatibility_l(
            const effect_descriptor_t *desc, audio_session_t sessionId) final REQUIRES(mutex());

    uint32_t hasAudioSession_l(audio_session_t sessionId) const override REQUIRES(mutex()) {
                                // Note: using mActiveTracks as no mTracks here.
                                return ThreadBase::hasAudioSession_l(sessionId, mActiveTracks);
                            }
    status_t setSyncEvent(const sp<audioflinger::SyncEvent>& event) final;
    bool isValidSyncEvent(const sp<audioflinger::SyncEvent>& event) const final;

    virtual void checkSilentMode_l() REQUIRES(mutex()) {} // cannot be const (RecordThread)
    virtual void processVolume_l() REQUIRES(mutex()) {}
    void checkInvalidTracks_l() REQUIRES(mutex());

    // Not in ThreadBase
    virtual audio_stream_type_t streamType_l() const REQUIRES(mutex()) {
        return AUDIO_STREAM_DEFAULT;
    }
    virtual void invalidateTracks(audio_stream_type_t /* streamType */)
            EXCLUDES_ThreadBase_Mutex {}
    void invalidateTracks(std::set<audio_port_handle_t>& /* portIds */) override
            EXCLUDES_ThreadBase_Mutex {}

                // Sets the UID records silence
    void setRecordSilenced(
            audio_port_handle_t /* portId */, bool /* silenced */) override
            EXCLUDES_ThreadBase_Mutex {}

    bool isStreamInitialized() const override { return false; }

    void setClientSilencedState_l(audio_port_handle_t portId, bool silenced) REQUIRES(mutex()) {
                                mClientSilencedStates[portId] = silenced;
                            }

    size_t eraseClientSilencedState_l(audio_port_handle_t portId) REQUIRES(mutex()) {
                                return mClientSilencedStates.erase(portId);
                            }

    bool isClientSilenced_l(audio_port_handle_t portId) const REQUIRES(mutex()) {
                                const auto it = mClientSilencedStates.find(portId);
                                return it != mClientSilencedStates.end() ? it->second : false;
                            }

    void setClientSilencedIfExists_l(audio_port_handle_t portId, bool silenced)
            REQUIRES(mutex()) {
                                const auto it = mClientSilencedStates.find(portId);
                                if (it != mClientSilencedStates.end()) {
                                    it->second = silenced;
                                }
                            }

 protected:
    void dumpInternals_l(int fd, const Vector<String16>& args) override REQUIRES(mutex());
    void dumpTracks_l(int fd, const Vector<String16>& args) final REQUIRES(mutex());

                /**
                 * @brief mDeviceId  current device port unique identifier
                 */
    audio_port_handle_t mDeviceId GUARDED_BY(mutex()) = AUDIO_PORT_HANDLE_NONE;

    audio_attributes_t mAttr GUARDED_BY(mutex());
    audio_session_t mSessionId GUARDED_BY(mutex());
    audio_port_handle_t mPortId GUARDED_BY(mutex());

    wp<MmapStreamCallback> mCallback GUARDED_BY(mutex());
    sp<StreamHalInterface> mHalStream; // NO_THREAD_SAFETY_ANALYSIS
    sp<DeviceHalInterface> mHalDevice GUARDED_BY(mutex());
    AudioHwDevice* const mAudioHwDev GUARDED_BY(mutex());
    ActiveTracks<IAfMmapTrack> mActiveTracks GUARDED_BY(mutex());
    float mHalVolFloat GUARDED_BY(mutex());
    std::map<audio_port_handle_t, bool> mClientSilencedStates GUARDED_BY(mutex());

    int32_t mNoCallbackWarningCount GUARDED_BY(mutex());
    static constexpr int32_t kMaxNoCallbackWarnings = 5;
};

class MmapPlaybackThread : public MmapThread, public IAfMmapPlaybackThread,
        public virtual VolumeInterface {
public:
    MmapPlaybackThread(const sp<IAfThreadCallback>& afThreadCallback, audio_io_handle_t id,
                       AudioHwDevice *hwDev, AudioStreamOut *output, bool systemReady);

    sp<IAfMmapPlaybackThread> asIAfMmapPlaybackThread() final {
        return sp<IAfMmapPlaybackThread>::fromExisting(this);
    }

    void configure(const audio_attributes_t* attr,
                                      audio_stream_type_t streamType,
                                      audio_session_t sessionId,
                                      const sp<MmapStreamCallback>& callback,
                                      audio_port_handle_t deviceId,
            audio_port_handle_t portId) final EXCLUDES_ThreadBase_Mutex;

    AudioStreamOut* clearOutput() final EXCLUDES_ThreadBase_Mutex;

                // VolumeInterface
    void setMasterVolume(float value) final;
    // Needs implementation?
    void setMasterBalance(float /* value */) final EXCLUDES_ThreadBase_Mutex {}
    void setMasterMute(bool muted) final EXCLUDES_ThreadBase_Mutex;
    void setStreamVolume(audio_stream_type_t stream, float value) final EXCLUDES_ThreadBase_Mutex;
    void setStreamMute(audio_stream_type_t stream, bool muted) final EXCLUDES_ThreadBase_Mutex;
    float streamVolume(audio_stream_type_t stream) const final EXCLUDES_ThreadBase_Mutex;

    void setMasterMute_l(bool muted) REQUIRES(mutex()) { mMasterMute = muted; }

    void invalidateTracks(audio_stream_type_t streamType) final EXCLUDES_ThreadBase_Mutex;
    void invalidateTracks(std::set<audio_port_handle_t>& portIds) final EXCLUDES_ThreadBase_Mutex;

    audio_stream_type_t streamType_l() const final REQUIRES(mutex()) {
        return mStreamType;
    }
    void checkSilentMode_l() final REQUIRES(mutex());
    void processVolume_l() final REQUIRES(mutex());

    MetadataUpdate updateMetadata_l() final REQUIRES(mutex());

    void toAudioPortConfig(struct audio_port_config* config) final;

    status_t getExternalPosition(uint64_t* position, int64_t* timeNanos) const final;

    bool isStreamInitialized() const final {
                                return !(mOutput == nullptr || mOutput->stream == nullptr);
                            }

    status_t reportData(const void* buffer, size_t frameCount) final;

    void startMelComputation_l(const sp<audio_utils::MelProcessor>& processor) final
            REQUIRES(audio_utils::AudioFlinger_Mutex);
    void stopMelComputation_l() final
            REQUIRES(audio_utils::AudioFlinger_Mutex);

protected:
    void dumpInternals_l(int fd, const Vector<String16>& args) final REQUIRES(mutex());
    float streamVolume_l() const REQUIRES(mutex()) {
                    return mStreamTypes[mStreamType].volume;
                }
    bool streamMuted_l() const REQUIRES(mutex()) {
                    return mStreamTypes[mStreamType].mute;
                }

    stream_type_t mStreamTypes[AUDIO_STREAM_CNT] GUARDED_BY(mutex());
    audio_stream_type_t mStreamType GUARDED_BY(mutex());
    float mMasterVolume GUARDED_BY(mutex());
    bool mMasterMute GUARDED_BY(mutex());
    AudioStreamOut* mOutput;  // NO_THREAD_SAFETY_ANALYSIS

    mediautils::atomic_sp<audio_utils::MelProcessor> mMelProcessor;  // locked internally
};

class MmapCaptureThread : public MmapThread, public IAfMmapCaptureThread
{
public:
    MmapCaptureThread(const sp<IAfThreadCallback>& afThreadCallback, audio_io_handle_t id,
                      AudioHwDevice *hwDev, AudioStreamIn *input, bool systemReady);

    sp<IAfMmapCaptureThread> asIAfMmapCaptureThread() final {
        return sp<IAfMmapCaptureThread>::fromExisting(this);
    }

    AudioStreamIn* clearInput() final EXCLUDES_ThreadBase_Mutex;

    status_t exitStandby_l() REQUIRES(mutex()) final;

    MetadataUpdate updateMetadata_l() final REQUIRES(mutex());
    void processVolume_l() final REQUIRES(mutex());
    void setRecordSilenced(audio_port_handle_t portId, bool silenced) final
            EXCLUDES_ThreadBase_Mutex;

    void toAudioPortConfig(struct audio_port_config* config) final;

    status_t getExternalPosition(uint64_t* position, int64_t* timeNanos) const final;

    bool isStreamInitialized() const final {
                                   return !(mInput == nullptr || mInput->stream == nullptr);
                               }

protected:

    AudioStreamIn* mInput;  // NO_THREAD_SAFETY_ANALYSIS
};

class BitPerfectThread : public MixerThread {
public:
    BitPerfectThread(const sp<IAfThreadCallback>& afThreadCallback, AudioStreamOut *output,
                     audio_io_handle_t id, bool systemReady);

protected:
    mixer_state prepareTracks_l(Vector<sp<IAfTrack>>* tracksToRemove) final
            REQUIRES(mutex(), ThreadBase_ThreadLoop);
    void threadLoop_mix() final REQUIRES(ThreadBase_ThreadLoop);

private:
    // These variables are only accessed on the threadLoop; hence need no mutex.
    bool mIsBitPerfect GUARDED_BY(ThreadBase_ThreadLoop) = false;
    float mVolumeLeft GUARDED_BY(ThreadBase_ThreadLoop) = 0.f;
    float mVolumeRight GUARDED_BY(ThreadBase_ThreadLoop) = 0.f;
};

} // namespace android
