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

#include <android/media/IAudioTrackCallback.h>
#include <android/media/IEffectClient.h>
#include <audiomanager/IAudioManager.h>
#include <audio_utils/mutex.h>
#include <audio_utils/MelProcessor.h>
#include <binder/MemoryDealer.h>
#include <datapath/AudioStreamIn.h>
#include <datapath/AudioStreamOut.h>
#include <datapath/VolumeInterface.h>
#include <fastpath/FastMixerDumpState.h>
#include <media/DeviceDescriptorBase.h>
#include <media/MmapStreamInterface.h>
#include <media/audiohal/StreamHalInterface.h>
#include <media/nblog/NBLog.h>
#include <timing/SyncEvent.h>
#include <utils/RefBase.h>
#include <vibrator/ExternalVibration.h>

#include <optional>

namespace android {

class IAfDirectOutputThread;
class IAfDuplicatingThread;
class IAfMmapCaptureThread;
class IAfMmapPlaybackThread;
class IAfPlaybackThread;
class IAfRecordThread;

class IAfEffectChain;
class IAfEffectHandle;
class IAfEffectModule;
class IAfPatchPanel;
class IAfPatchRecord;
class IAfPatchTrack;
class IAfRecordTrack;
class IAfTrack;
class IAfTrackBase;
class Client;
class MelReporter;

// Used internally for Threads.cpp and AudioFlinger.cpp
struct stream_type_t {
    float volume = 1.f;
    bool mute = false;
};

// Note this is exposed through IAfThreadBase::afThreadCallback()
// and hence may be used by the Effect / Track framework.
class IAfThreadCallback : public virtual RefBase {
public:
    virtual audio_utils::mutex& mutex() const
            RETURN_CAPABILITY(audio_utils::AudioFlinger_Mutex) = 0;
    virtual bool isNonOffloadableGlobalEffectEnabled_l() const
            REQUIRES(mutex()) = 0;  // Tracks
    virtual audio_unique_id_t nextUniqueId(audio_unique_id_use_t use) = 0;
    virtual bool btNrecIsOff() const = 0;
    virtual float masterVolume_l() const
            REQUIRES(mutex()) = 0;
    virtual bool masterMute_l() const
            REQUIRES(mutex()) = 0;
    virtual float getMasterBalance_l() const
            REQUIRES(mutex()) = 0;
    virtual bool streamMute_l(audio_stream_type_t stream) const
            REQUIRES(mutex()) = 0;
    virtual audio_mode_t getMode() const = 0;
    virtual bool isLowRamDevice() const = 0;
    virtual bool isAudioPolicyReady() const = 0;  // Effects
    virtual uint32_t getScreenState() const = 0;
    virtual std::optional<media::AudioVibratorInfo> getDefaultVibratorInfo_l() const
            REQUIRES(mutex()) = 0;
    virtual const sp<IAfPatchPanel>& getPatchPanel() const = 0;
    virtual const sp<MelReporter>& getMelReporter() const = 0;
    virtual const sp<EffectsFactoryHalInterface>& getEffectsFactoryHal() const = 0;
    virtual sp<IAudioManager> getOrCreateAudioManager() = 0;  // Tracks

    virtual bool updateOrphanEffectChains(const sp<IAfEffectModule>& effect)
            EXCLUDES_AudioFlinger_Mutex = 0;
    virtual status_t moveEffectChain_ll(audio_session_t sessionId,
            IAfPlaybackThread* srcThread, IAfPlaybackThread* dstThread)
            REQUIRES(mutex(), audio_utils::ThreadBase_Mutex) = 0;

    virtual void requestLogMerge() = 0;
    virtual sp<NBLog::Writer> newWriter_l(size_t size, const char *name)
            REQUIRES(mutex()) = 0;
    virtual void unregisterWriter(const sp<NBLog::Writer>& writer) = 0;

    virtual sp<audioflinger::SyncEvent> createSyncEvent(AudioSystem::sync_event_t type,
            audio_session_t triggerSession,
            audio_session_t listenerSession,
            const audioflinger::SyncEventCallback& callBack,
            const wp<IAfTrackBase>& cookie)
            EXCLUDES_AudioFlinger_Mutex = 0;

    virtual void ioConfigChanged(audio_io_config_event_t event,
            const sp<AudioIoDescriptor>& ioDesc,
            pid_t pid = 0) EXCLUDES_AudioFlinger_ClientMutex = 0;
    virtual void onNonOffloadableGlobalEffectEnable() EXCLUDES_AudioFlinger_Mutex = 0;
    virtual void onSupportedLatencyModesChanged(
            audio_io_handle_t output, const std::vector<audio_latency_mode_t>& modes)
            EXCLUDES_AudioFlinger_ClientMutex = 0;
};

class IAfThreadBase : public virtual RefBase {
public:
    enum type_t {
        MIXER,          // Thread class is MixerThread
        DIRECT,         // Thread class is DirectOutputThread
        DUPLICATING,    // Thread class is DuplicatingThread
        RECORD,         // Thread class is RecordThread
        OFFLOAD,        // Thread class is OffloadThread
        MMAP_PLAYBACK,  // Thread class for MMAP playback stream
        MMAP_CAPTURE,   // Thread class for MMAP capture stream
        SPATIALIZER,    //
        BIT_PERFECT,    // Thread class for BitPerfectThread
        // When adding a value, also update IAfThreadBase::threadTypeToString()
    };

    static const char* threadTypeToString(type_t type);
    static std::string formatToString(audio_format_t format);  // compliant for MediaMetrics
    static bool isValidPcmSinkChannelMask(audio_channel_mask_t channelMask);
    static bool isValidPcmSinkFormat(audio_format_t format);

    virtual status_t readyToRun() = 0;
    virtual void clearPowerManager() = 0;
    virtual status_t initCheck() const = 0;
    virtual type_t type() const = 0;
    virtual bool isDuplicating() const = 0;
    virtual audio_io_handle_t id() const = 0;
    virtual uint32_t sampleRate() const = 0;
    virtual audio_channel_mask_t channelMask() const = 0;
    virtual audio_channel_mask_t mixerChannelMask() const = 0;
    virtual audio_format_t format() const = 0;
    virtual uint32_t channelCount() const = 0;

    // Called by AudioFlinger::frameCount(audio_io_handle_t output) and effects,
    // and returns the [normal mix] buffer's frame count.
    virtual size_t frameCount() const = 0;
    virtual audio_channel_mask_t hapticChannelMask() const = 0;
    virtual uint32_t hapticChannelCount() const = 0;
    virtual uint32_t latency_l() const = 0;
    virtual void setVolumeForOutput_l(float left, float right) const = 0;

    // Return's the HAL's frame count i.e. fast mixer buffer size.
    virtual size_t frameCountHAL() const = 0;
    virtual size_t frameSize() const = 0;
    // Should be "virtual status_t requestExitAndWait()" and override same
    // method in Thread, but Thread::requestExitAndWait() is not yet virtual.
    virtual void exit() = 0;
    virtual bool checkForNewParameter_l(const String8& keyValuePair, status_t& status) = 0;
    virtual status_t setParameters(const String8& keyValuePairs) = 0;
    virtual String8 getParameters(const String8& keys) = 0;
    virtual void ioConfigChanged(
            audio_io_config_event_t event, pid_t pid = 0,
            audio_port_handle_t portId = AUDIO_PORT_HANDLE_NONE) = 0;

    // sendConfigEvent_l() must be called with ThreadBase::mLock held
    // Can temporarily release the lock if waiting for a reply from
    // processConfigEvents_l().
    // status_t sendConfigEvent_l(sp<ConfigEvent>& event);
    virtual void sendIoConfigEvent(
            audio_io_config_event_t event, pid_t pid = 0,
            audio_port_handle_t portId = AUDIO_PORT_HANDLE_NONE) = 0;
    virtual void sendIoConfigEvent_l(
            audio_io_config_event_t event, pid_t pid = 0,
            audio_port_handle_t portId = AUDIO_PORT_HANDLE_NONE) = 0;
    virtual void sendPrioConfigEvent(pid_t pid, pid_t tid, int32_t prio, bool forApp) = 0;
    virtual void sendPrioConfigEvent_l(pid_t pid, pid_t tid, int32_t prio, bool forApp) = 0;
    virtual status_t sendSetParameterConfigEvent_l(const String8& keyValuePair) = 0;
    virtual status_t sendCreateAudioPatchConfigEvent(
            const struct audio_patch* patch, audio_patch_handle_t* handle) = 0;
    virtual status_t sendReleaseAudioPatchConfigEvent(audio_patch_handle_t handle) = 0;
    virtual status_t sendUpdateOutDeviceConfigEvent(
            const DeviceDescriptorBaseVector& outDevices) = 0;
    virtual void sendResizeBufferConfigEvent_l(int32_t maxSharedAudioHistoryMs) = 0;
    virtual void sendCheckOutputStageEffectsEvent() = 0;
    virtual void sendCheckOutputStageEffectsEvent_l() = 0;
    virtual void sendHalLatencyModesChangedEvent_l() = 0;

    virtual void processConfigEvents_l() = 0;
    virtual void setCheckOutputStageEffects() = 0;
    virtual void cacheParameters_l() = 0;
    virtual status_t createAudioPatch_l(
            const struct audio_patch* patch, audio_patch_handle_t* handle) = 0;
    virtual status_t releaseAudioPatch_l(const audio_patch_handle_t handle) = 0;
    virtual void updateOutDevices(const DeviceDescriptorBaseVector& outDevices) = 0;
    virtual void toAudioPortConfig(struct audio_port_config* config) = 0;
    virtual void resizeInputBuffer_l(int32_t maxSharedAudioHistoryMs) = 0;

    // see note at declaration of mStandby, mOutDevice and mInDevice
    virtual bool inStandby() const = 0;
    virtual const DeviceTypeSet outDeviceTypes() const = 0;
    virtual audio_devices_t inDeviceType() const = 0;
    virtual DeviceTypeSet getDeviceTypes() const = 0;
    virtual const AudioDeviceTypeAddrVector& outDeviceTypeAddrs() const = 0;
    virtual const AudioDeviceTypeAddr& inDeviceTypeAddr() const = 0;
    virtual bool isOutput() const = 0;
    virtual bool isOffloadOrMmap() const = 0;
    virtual sp<StreamHalInterface> stream() const = 0;
    virtual sp<IAfEffectHandle> createEffect_l(
            const sp<Client>& client,
            const sp<media::IEffectClient>& effectClient,
            int32_t priority,
            audio_session_t sessionId,
            effect_descriptor_t* desc,
            int* enabled,
            status_t* status /*non-NULL*/,
            bool pinned,
            bool probe,
            bool notifyFramesProcessed)
            REQUIRES(audio_utils::AudioFlinger_Mutex) = 0;

    // return values for hasAudioSession (bit field)
    enum effect_state {
        EFFECT_SESSION = 0x1,       // the audio session corresponds to at least one
                                    // effect
        TRACK_SESSION = 0x2,        // the audio session corresponds to at least one
                                    // track
        FAST_SESSION = 0x4,         // the audio session corresponds to at least one
                                    // fast track
        SPATIALIZED_SESSION = 0x8,  // the audio session corresponds to at least one
                                    // spatialized track
        BIT_PERFECT_SESSION = 0x10  // the audio session corresponds to at least one
                                    // bit-perfect track
    };

    // get effect chain corresponding to session Id.
    virtual sp<IAfEffectChain> getEffectChain(audio_session_t sessionId) const = 0;
    // same as getEffectChain() but must be called with ThreadBase mutex locked
    virtual sp<IAfEffectChain> getEffectChain_l(audio_session_t sessionId) const = 0;
    virtual std::vector<int> getEffectIds_l(audio_session_t sessionId) const = 0;
    // add an effect chain to the chain list (mEffectChains)
    virtual status_t addEffectChain_l(const sp<IAfEffectChain>& chain) = 0;
    // remove an effect chain from the chain list (mEffectChains)
    virtual size_t removeEffectChain_l(const sp<IAfEffectChain>& chain) = 0;
    // lock all effect chains Mutexes. Must be called before releasing the
    // ThreadBase mutex before processing the mixer and effects. This guarantees the
    // integrity of the chains during the process.
    // Also sets the parameter 'effectChains' to current value of mEffectChains.
    virtual void lockEffectChains_l(Vector<sp<IAfEffectChain>>& effectChains) = 0;
    // unlock effect chains after process
    virtual void unlockEffectChains(const Vector<sp<IAfEffectChain>>& effectChains) = 0;
    // get a copy of mEffectChains vector
    virtual Vector<sp<IAfEffectChain>> getEffectChains_l() const = 0;
    // set audio mode to all effect chains
    virtual void setMode(audio_mode_t mode) = 0;
    // get effect module with corresponding ID on specified audio session
    virtual sp<IAfEffectModule> getEffect(audio_session_t sessionId, int effectId) const = 0;
    virtual sp<IAfEffectModule> getEffect_l(audio_session_t sessionId, int effectId) const = 0;
    // add and effect module. Also creates the effect chain is none exists for
    // the effects audio session. Only called in a context of moving an effect
    // from one thread to another
    virtual status_t addEffect_ll(const sp<IAfEffectModule>& effect)
            REQUIRES(audio_utils::AudioFlinger_Mutex, mutex()) = 0;
    // remove and effect module. Also removes the effect chain is this was the last
    // effect
    virtual void removeEffect_l(const sp<IAfEffectModule>& effect, bool release = false) = 0;
    // disconnect an effect handle from module and destroy module if last handle
    virtual void disconnectEffectHandle(IAfEffectHandle* handle, bool unpinIfLast) = 0;
    // detach all tracks connected to an auxiliary effect
    virtual void detachAuxEffect_l(int effectId) = 0;
    // returns a combination of:
    // - EFFECT_SESSION if effects on this audio session exist in one chain
    // - TRACK_SESSION if tracks on this audio session exist
    // - FAST_SESSION if fast tracks on this audio session exist
    // - SPATIALIZED_SESSION if spatialized tracks on this audio session exist
    virtual uint32_t hasAudioSession_l(audio_session_t sessionId) const = 0;
    virtual uint32_t hasAudioSession(audio_session_t sessionId) const = 0;

    // the value returned by default implementation is not important as the
    // strategy is only meaningful for PlaybackThread which implements this method
    virtual product_strategy_t getStrategyForSession_l(audio_session_t sessionId) const = 0;

    // check if some effects must be suspended/restored when an effect is enabled
    // or disabled
    virtual void checkSuspendOnEffectEnabled(
            bool enabled, audio_session_t sessionId, bool threadLocked) = 0;

    virtual status_t setSyncEvent(const sp<audioflinger::SyncEvent>& event) = 0;
    virtual bool isValidSyncEvent(const sp<audioflinger::SyncEvent>& event) const = 0;

    // Return a reference to a per-thread heap which can be used to allocate IMemory
    // objects that will be read-only to client processes, read/write to mediaserver,
    // and shared by all client processes of the thread.
    // The heap is per-thread rather than common across all threads, because
    // clients can't be trusted not to modify the offset of the IMemory they receive.
    // If a thread does not have such a heap, this method returns 0.
    virtual sp<MemoryDealer> readOnlyHeap() const = 0;

    virtual sp<IMemory> pipeMemory() const = 0;

    virtual void systemReady() = 0;

    // checkEffectCompatibility_l() must be called with ThreadBase::mLock held
    virtual status_t checkEffectCompatibility_l(
            const effect_descriptor_t* desc, audio_session_t sessionId) = 0;

    virtual void broadcast_l() = 0;

    virtual bool isTimestampCorrectionEnabled() const = 0;

    virtual bool isMsdDevice() const = 0;

    virtual void dump(int fd, const Vector<String16>& args) = 0;

    // deliver stats to mediametrics.
    virtual void sendStatistics(bool force) = 0;

    virtual audio_utils::mutex& mutex() const
            RETURN_CAPABILITY(audio_utils::ThreadBase_Mutex) = 0;

    virtual void onEffectEnable(const sp<IAfEffectModule>& effect) = 0;
    virtual void onEffectDisable() = 0;

    // invalidateTracksForAudioSession_l must be called with holding mLock.
    virtual void invalidateTracksForAudioSession_l(audio_session_t sessionId) const = 0;
    // Invalidate all the tracks with the given audio session.
    virtual void invalidateTracksForAudioSession(audio_session_t sessionId) const = 0;

    virtual bool isStreamInitialized() const = 0;
    virtual void startMelComputation_l(const sp<audio_utils::MelProcessor>& processor)
            REQUIRES(audio_utils::AudioFlinger_Mutex) = 0;
    virtual void stopMelComputation_l()
            REQUIRES(audio_utils::AudioFlinger_Mutex) = 0;

    virtual product_strategy_t getStrategyForStream(audio_stream_type_t stream) const = 0;

    virtual void setEffectSuspended_l(
            const effect_uuid_t* type, bool suspend, audio_session_t sessionId) = 0;

    // Dynamic cast to derived interface
    virtual sp<IAfDirectOutputThread> asIAfDirectOutputThread() { return nullptr; }
    virtual sp<IAfDuplicatingThread> asIAfDuplicatingThread() { return nullptr; }
    virtual sp<IAfPlaybackThread> asIAfPlaybackThread() { return nullptr; }
    virtual sp<IAfRecordThread> asIAfRecordThread() { return nullptr; }
    virtual IAfThreadCallback* afThreadCallback() const = 0;
};

class IAfPlaybackThread : public virtual IAfThreadBase, public virtual VolumeInterface {
public:
    static sp<IAfPlaybackThread> createBitPerfectThread(
            const sp<IAfThreadCallback>& afThreadCallback, AudioStreamOut* output,
            audio_io_handle_t id, bool systemReady);

    static sp<IAfPlaybackThread> createDirectOutputThread(
            const sp<IAfThreadCallback>& afThreadCallback, AudioStreamOut* output,
            audio_io_handle_t id, bool systemReady, const audio_offload_info_t& offloadInfo);

    static sp<IAfPlaybackThread> createMixerThread(
            const sp<IAfThreadCallback>& afThreadCallback, AudioStreamOut* output,
            audio_io_handle_t id, bool systemReady, type_t type = MIXER,
            audio_config_base_t* mixerConfig = nullptr);

    static sp<IAfPlaybackThread> createOffloadThread(
            const sp<IAfThreadCallback>& afThreadCallback, AudioStreamOut* output,
            audio_io_handle_t id, bool systemReady, const audio_offload_info_t& offloadInfo);

    static sp<IAfPlaybackThread> createSpatializerThread(
            const sp<IAfThreadCallback>& afThreadCallback, AudioStreamOut* output,
            audio_io_handle_t id, bool systemReady, audio_config_base_t* mixerConfig);

    static constexpr int8_t kMaxTrackStopRetriesOffload = 2;

    enum mixer_state {
        MIXER_IDLE,            // no active tracks
        MIXER_TRACKS_ENABLED,  // at least one active track, but no track has any data ready
        MIXER_TRACKS_READY,    // at least one active track, and at least one track has data
        MIXER_DRAIN_TRACK,     // drain currently playing track
        MIXER_DRAIN_ALL,       // fully drain the hardware
        // standby mode does not have an enum value
        // suspend by audio policy manager is orthogonal to mixer state
    };

    // return estimated latency in milliseconds, as reported by HAL
    virtual uint32_t latency() const = 0;  // should be in IAfThreadBase?

    virtual uint32_t& fastTrackAvailMask_l() = 0;

    virtual sp<IAfTrack> createTrack_l(
            const sp<Client>& client,
            audio_stream_type_t streamType,
            const audio_attributes_t& attr,
            uint32_t* sampleRate,
            audio_format_t format,
            audio_channel_mask_t channelMask,
            size_t* pFrameCount,
            size_t* pNotificationFrameCount,
            uint32_t notificationsPerBuffer,
            float speed,
            const sp<IMemory>& sharedBuffer,
            audio_session_t sessionId,
            audio_output_flags_t* flags,
            pid_t creatorPid,
            const AttributionSourceState& attributionSource,
            pid_t tid,
            status_t* status /*non-NULL*/,
            audio_port_handle_t portId,
            const sp<media::IAudioTrackCallback>& callback,
            bool isSpatialized,
            bool isBitPerfect)
            REQUIRES(audio_utils::AudioFlinger_Mutex) = 0;

    virtual status_t addTrack_l(const sp<IAfTrack>& track) = 0;
    virtual bool destroyTrack_l(const sp<IAfTrack>& track) = 0;
    virtual bool isTrackActive(const sp<IAfTrack>& track) const = 0;
    virtual void addOutputTrack_l(const sp<IAfTrack>& track) = 0;

    virtual AudioStreamOut* getOutput_l() const = 0;
    virtual AudioStreamOut* getOutput() const = 0;
    virtual AudioStreamOut* clearOutput() = 0;

    // a very large number of suspend() will eventually wraparound, but unlikely
    virtual void suspend() = 0;
    virtual void restore() = 0;
    virtual bool isSuspended() const = 0;
    virtual status_t getRenderPosition(uint32_t* halFrames, uint32_t* dspFrames) const = 0;
    // Consider also removing and passing an explicit mMainBuffer initialization
    // parameter to AF::IAfTrack::Track().
    virtual float* sinkBuffer() const = 0;

    virtual status_t attachAuxEffect(const sp<IAfTrack>& track, int EffectId) = 0;
    virtual status_t attachAuxEffect_l(const sp<IAfTrack>& track, int EffectId) = 0;

    // called with AudioFlinger lock held
    virtual bool invalidateTracks_l(audio_stream_type_t streamType) = 0;
    virtual bool invalidateTracks_l(std::set<audio_port_handle_t>& portIds) = 0;
    virtual void invalidateTracks(audio_stream_type_t streamType) = 0;
    // Invalidate tracks by a set of port ids. The port id will be removed from
    // the given set if the corresponding track is found and invalidated.
    virtual void invalidateTracks(std::set<audio_port_handle_t>& portIds) = 0;

    virtual status_t getTimestamp_l(AudioTimestamp& timestamp) = 0;
    virtual void addPatchTrack(const sp<IAfPatchTrack>& track) = 0;
    virtual void deletePatchTrack(const sp<IAfPatchTrack>& track) = 0;

    // Return the asynchronous signal wait time.
    virtual int64_t computeWaitTimeNs_l() const = 0;
    // returns true if the track is allowed to be added to the thread.
    virtual bool isTrackAllowed_l(
            audio_channel_mask_t channelMask, audio_format_t format, audio_session_t sessionId,
            uid_t uid) const = 0;

    virtual bool supportsHapticPlayback() const = 0;

    virtual void setDownStreamPatch(const struct audio_patch* patch) = 0;

    virtual IAfTrack* getTrackById_l(audio_port_handle_t trackId) = 0;

    virtual bool hasMixer() const = 0;

    virtual status_t setRequestedLatencyMode(audio_latency_mode_t mode) = 0;

    virtual status_t getSupportedLatencyModes(std::vector<audio_latency_mode_t>* modes) = 0;

    virtual status_t setBluetoothVariableLatencyEnabled(bool enabled) = 0;

    virtual void setStandby() = 0;
    virtual void setStandby_l() = 0;
    virtual bool waitForHalStart() = 0;

    virtual bool hasFastMixer() const = 0;
    virtual FastTrackUnderruns getFastTrackUnderruns(size_t fastIndex) const = 0;
    virtual const std::atomic<int64_t>& framesWritten() const = 0;

    virtual bool usesHwAvSync() const = 0;
};

class IAfDirectOutputThread : public virtual IAfPlaybackThread {
public:
    virtual status_t selectPresentation(int presentationId, int programId) = 0;
};

class IAfDuplicatingThread : public virtual IAfPlaybackThread {
public:
    static sp<IAfDuplicatingThread> create(
            const sp<IAfThreadCallback>& afThreadCallback, IAfPlaybackThread* mainThread,
            audio_io_handle_t id, bool systemReady);

    virtual void addOutputTrack(IAfPlaybackThread* thread) = 0;
    virtual uint32_t waitTimeMs() const = 0;
    virtual void removeOutputTrack(IAfPlaybackThread* thread) = 0;
};

class IAfRecordThread : public virtual IAfThreadBase {
public:
    static sp<IAfRecordThread> create(
            const sp<IAfThreadCallback>& afThreadCallback, AudioStreamIn* input,
            audio_io_handle_t id, bool systemReady);

    virtual sp<IAfRecordTrack> createRecordTrack_l(
            const sp<Client>& client,
            const audio_attributes_t& attr,
            uint32_t* pSampleRate,
            audio_format_t format,
            audio_channel_mask_t channelMask,
            size_t* pFrameCount,
            audio_session_t sessionId,
            size_t* pNotificationFrameCount,
            pid_t creatorPid,
            const AttributionSourceState& attributionSource,
            audio_input_flags_t* flags,
            pid_t tid,
            status_t* status /*non-NULL*/,
            audio_port_handle_t portId,
            int32_t maxSharedAudioHistoryMs)
            REQUIRES(audio_utils::AudioFlinger_Mutex) = 0;
    virtual void destroyTrack_l(const sp<IAfRecordTrack>& track) = 0;
    virtual void removeTrack_l(const sp<IAfRecordTrack>& track) = 0;

    virtual status_t start(
            IAfRecordTrack* recordTrack, AudioSystem::sync_event_t event,
            audio_session_t triggerSession) = 0;

    // ask the thread to stop the specified track, and
    // return true if the caller should then do it's part of the stopping process
    virtual bool stop(IAfRecordTrack* recordTrack) = 0;

    virtual AudioStreamIn* getInput() const = 0;
    virtual AudioStreamIn* clearInput() = 0;

    virtual status_t getActiveMicrophones(
            std::vector<media::MicrophoneInfoFw>* activeMicrophones) const = 0;
    virtual status_t setPreferredMicrophoneDirection(audio_microphone_direction_t direction) = 0;
    virtual status_t setPreferredMicrophoneFieldDimension(float zoom) = 0;

    virtual void addPatchTrack(const sp<IAfPatchRecord>& record) = 0;
    virtual void deletePatchTrack(const sp<IAfPatchRecord>& record) = 0;
    virtual bool fastTrackAvailable() const = 0;
    virtual void setFastTrackAvailable(bool available) = 0;

    virtual void setRecordSilenced(audio_port_handle_t portId, bool silenced) = 0;
    virtual bool hasFastCapture() const = 0;

    virtual void checkBtNrec() = 0;
    virtual uint32_t getInputFramesLost() const = 0;

    virtual status_t shareAudioHistory(
            const std::string& sharedAudioPackageName,
            audio_session_t sharedSessionId = AUDIO_SESSION_NONE,
            int64_t sharedAudioStartMs = -1) = 0;
    virtual void resetAudioHistory_l() = 0;
};

class IAfMmapThread : public virtual IAfThreadBase {
public:
    // createIAudioTrackAdapter() is a static constructor which creates an
    // MmapStreamInterface AIDL interface adapter from the MmapThread object that
    // may be passed back to the client.
    //
    // Only one AIDL MmapStreamInterface interface adapter should be created per MmapThread.
    static sp<MmapStreamInterface> createMmapStreamInterfaceAdapter(
            const sp<IAfMmapThread>& mmapThread);

    virtual void configure(
            const audio_attributes_t* attr,
            audio_stream_type_t streamType,
            audio_session_t sessionId,
            const sp<MmapStreamCallback>& callback,
            audio_port_handle_t deviceId,
            audio_port_handle_t portId) = 0;
    virtual void disconnect() = 0;

    // MmapStreamInterface handling (see adapter)
    virtual status_t createMmapBuffer(
            int32_t minSizeFrames, struct audio_mmap_buffer_info* info) = 0;
    virtual status_t getMmapPosition(struct audio_mmap_position* position) const = 0;
    virtual status_t start(
            const AudioClient& client, const audio_attributes_t* attr,
            audio_port_handle_t* handle) = 0;
    virtual status_t stop(audio_port_handle_t handle) = 0;
    virtual status_t standby() = 0;
    virtual status_t getExternalPosition(uint64_t* position, int64_t* timeNanos) const = 0;
    virtual status_t reportData(const void* buffer, size_t frameCount) = 0;

    // TODO(b/291317898)  move to IAfThreadBase?
    virtual void invalidateTracks(std::set<audio_port_handle_t>& portIds) = 0;

    // Sets the UID records silence - TODO(b/291317898)  move to IAfMmapCaptureThread
    virtual void setRecordSilenced(audio_port_handle_t portId, bool silenced) = 0;

    virtual sp<IAfMmapPlaybackThread> asIAfMmapPlaybackThread() { return nullptr; }
    virtual sp<IAfMmapCaptureThread> asIAfMmapCaptureThread() { return nullptr; }
};

class IAfMmapPlaybackThread : public virtual IAfMmapThread, public virtual VolumeInterface {
public:
    static sp<IAfMmapPlaybackThread> create(
            const sp<IAfThreadCallback>& afThreadCallback, audio_io_handle_t id,
            AudioHwDevice* hwDev, AudioStreamOut* output, bool systemReady);

    virtual AudioStreamOut* clearOutput() = 0;
};

class IAfMmapCaptureThread : public virtual IAfMmapThread {
public:
    static sp<IAfMmapCaptureThread> create(
            const sp<IAfThreadCallback>& afThreadCallback, audio_io_handle_t id,
            AudioHwDevice* hwDev, AudioStreamIn* input, bool systemReady);

    virtual AudioStreamIn* clearInput() = 0;
};

}  // namespace android
