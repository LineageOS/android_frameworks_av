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

#include <android/media/BnAudioRecord.h>
#include <android/media/BnAudioTrack.h>
#include <audiomanager/IAudioManager.h>
#include <binder/IMemory.h>
#include <fastpath/FastMixerDumpState.h>
#include <media/AudioSystem.h>
#include <media/VolumeShaper.h>
#include <private/media/AudioTrackShared.h>
#include <timing/SyncEvent.h>
#include <timing/SynchronizedRecordState.h>
#include <utils/RefBase.h>
#include <vibrator/ExternalVibration.h>

#include <vector>

namespace android {

class Client;
class ResamplerBufferProvider;
struct Source;

class IAfDuplicatingThread;
class IAfPatchRecord;
class IAfPatchTrack;
class IAfPlaybackThread;
class IAfRecordThread;
class IAfThreadBase;

struct TeePatch {
    sp<IAfPatchRecord> patchRecord;
    sp<IAfPatchTrack> patchTrack;
};

using TeePatches = std::vector<TeePatch>;

// Common interface to all Playback and Record tracks.
class IAfTrackBase : public virtual RefBase {
public:
    enum track_state : int32_t {
        IDLE,
        FLUSHED,  // for PlaybackTracks only
        STOPPED,
        // next 2 states are currently used for fast tracks
        // and offloaded tracks only
        STOPPING_1,  // waiting for first underrun
        STOPPING_2,  // waiting for presentation complete
        RESUMING,    // for PlaybackTracks only
        ACTIVE,
        PAUSING,
        PAUSED,
        STARTING_1,  // for RecordTrack only
        STARTING_2,  // for RecordTrack only
    };

    // where to allocate the data buffer
    enum alloc_type {
        ALLOC_CBLK,      // allocate immediately after control block
        ALLOC_READONLY,  // allocate from a separate read-only heap per thread
        ALLOC_PIPE,      // do not allocate; use the pipe buffer
        ALLOC_LOCAL,     // allocate a local buffer
        ALLOC_NONE,      // do not allocate:use the buffer passed to TrackBase constructor
    };

    enum track_type {
        TYPE_DEFAULT,
        TYPE_OUTPUT,
        TYPE_PATCH,
    };

    virtual status_t initCheck() const = 0;
    virtual status_t start(
            AudioSystem::sync_event_t event = AudioSystem::SYNC_EVENT_NONE,
            audio_session_t triggerSession = AUDIO_SESSION_NONE) = 0;
    virtual void stop() = 0;
    virtual sp<IMemory> getCblk() const = 0;
    virtual audio_track_cblk_t* cblk() const = 0;
    virtual audio_session_t sessionId() const = 0;
    virtual uid_t uid() const = 0;
    virtual pid_t creatorPid() const = 0;
    virtual uint32_t sampleRate() const = 0;
    virtual size_t frameSize() const = 0;
    virtual audio_port_handle_t portId() const = 0;
    virtual status_t setSyncEvent(const sp<audioflinger::SyncEvent>& event) = 0;
    virtual track_state state() const = 0;
    virtual void setState(track_state state) = 0;
    virtual sp<IMemory> getBuffers() const = 0;
    virtual void* buffer() const = 0;
    virtual size_t bufferSize() const = 0;
    virtual bool isFastTrack() const = 0;
    virtual bool isDirect() const = 0;
    virtual bool isOutputTrack() const = 0;
    virtual bool isPatchTrack() const = 0;
    virtual bool isExternalTrack() const = 0;

    virtual void invalidate() = 0;
    virtual bool isInvalid() const = 0;

    virtual void terminate() = 0;
    virtual bool isTerminated() const = 0;

    virtual audio_attributes_t attributes() const = 0;
    virtual bool isSpatialized() const = 0;
    virtual bool isBitPerfect() const = 0;

    // not currently implemented in TrackBase, but overridden.
    virtual void destroy() {};  // MmapTrack doesn't implement.
    virtual void appendDumpHeader(String8& result) const = 0;
    virtual void appendDump(String8& result, bool active) const = 0;

    // Dup with AudioBufferProvider interface
    virtual status_t getNextBuffer(AudioBufferProvider::Buffer* buffer) = 0;
    virtual void releaseBuffer(AudioBufferProvider::Buffer* buffer) = 0;

    // Added for RecordTrack and OutputTrack
    virtual wp<IAfThreadBase> thread() const = 0;
    virtual const sp<ServerProxy>& serverProxy() const = 0;

    // TEE_SINK
    virtual void dumpTee(int fd __unused, const std::string& reason __unused) const {};

    /** returns the buffer contents size converted to time in milliseconds
     * for PCM Playback or Record streaming tracks. The return value is zero for
     * PCM static tracks and not defined for non-PCM tracks.
     *
     * This may be called without the thread lock.
     */
    virtual double bufferLatencyMs() const = 0;

    /** returns whether the track supports server latency computation.
     * This is set in the constructor and constant throughout the track lifetime.
     */
    virtual bool isServerLatencySupported() const = 0;

    /** computes the server latency for PCM Playback or Record track
     * to the device sink/source.  This is the time for the next frame in the track buffer
     * written or read from the server thread to the device source or sink.
     *
     * This may be called without the thread lock, but latencyMs and fromTrack
     * may be not be synchronized. For example PatchPanel may not obtain the
     * thread lock before calling.
     *
     * \param latencyMs on success is set to the latency in milliseconds of the
     *        next frame written/read by the server thread to/from the track buffer
     *        from the device source/sink.
     * \param fromTrack on success is set to true if latency was computed directly
     *        from the track timestamp; otherwise set to false if latency was
     *        estimated from the server timestamp.
     *        fromTrack may be nullptr or omitted if not required.
     *
     * \returns OK or INVALID_OPERATION on failure.
     */
    virtual status_t getServerLatencyMs(double* latencyMs, bool* fromTrack = nullptr) const = 0;

    /** computes the total client latency for PCM Playback or Record tracks
     * for the next client app access to the device sink/source; i.e. the
     * server latency plus the buffer latency.
     *
     * This may be called without the thread lock, but latencyMs and fromTrack
     * may be not be synchronized. For example PatchPanel may not obtain the
     * thread lock before calling.
     *
     * \param latencyMs on success is set to the latency in milliseconds of the
     *        next frame written/read by the client app to/from the track buffer
     *        from the device sink/source.
     * \param fromTrack on success is set to true if latency was computed directly
     *        from the track timestamp; otherwise set to false if latency was
     *        estimated from the server timestamp.
     *        fromTrack may be nullptr or omitted if not required.
     *
     * \returns OK or INVALID_OPERATION on failure.
     */
    virtual status_t getTrackLatencyMs(double* latencyMs, bool* fromTrack = nullptr) const = 0;

    // TODO: Consider making this external.
    struct FrameTime {
        int64_t frames;
        int64_t timeNs;
    };

    // KernelFrameTime is updated per "mix" period even for non-pcm tracks.
    virtual void getKernelFrameTime(FrameTime* ft) const = 0;

    virtual audio_format_t format() const = 0;
    virtual int id() const = 0;

    virtual const char* getTrackStateAsString() const = 0;

    // Called by the PlaybackThread to indicate that the track is becoming active
    // and a new interval should start with a given device list.
    virtual void logBeginInterval(const std::string& devices) = 0;

    // Called by the PlaybackThread to indicate the track is no longer active.
    virtual void logEndInterval() = 0;

    // Called to tally underrun frames in playback.
    virtual void tallyUnderrunFrames(size_t frames) = 0;

    virtual audio_channel_mask_t channelMask() const = 0;

    /** @return true if the track has changed (metadata or volume) since
     *          the last time this function was called,
     *          true if this function was never called since the track creation,
     *          false otherwise.
     *  Thread safe.
     */
    virtual bool readAndClearHasChanged() = 0;

    /** Set that a metadata has changed and needs to be notified to backend. Thread safe. */
    virtual void setMetadataHasChanged() = 0;

    /**
     * Called when a track moves to active state to record its contribution to battery usage.
     * Track state transitions should eventually be handled within the track class.
     */
    virtual void beginBatteryAttribution() = 0;

    /**
     * Called when a track moves out of the active state to record its contribution
     * to battery usage.
     */
    virtual void endBatteryAttribution() = 0;

    /**
     * For RecordTrack
     * TODO(b/291317964) either use this or add asRecordTrack or asTrack etc.
     */
    virtual void handleSyncStartEvent(const sp<audioflinger::SyncEvent>& event __unused){};

    // For Thread use, fast tracks and offloaded tracks only
    // TODO(b/291317964) rearrange to IAfTrack.
    virtual bool isStopped() const = 0;
    virtual bool isStopping() const = 0;
    virtual bool isStopping_1() const = 0;
    virtual bool isStopping_2() const = 0;
};

// Common interface for Playback tracks.
class IAfTrack : public virtual IAfTrackBase {
public:
    // FillingStatus is used for suppressing volume ramp at begin of playing
    enum FillingStatus { FS_INVALID, FS_FILLING, FS_FILLED, FS_ACTIVE };

    // createIAudioTrackAdapter() is a static constructor which creates an
    // IAudioTrack AIDL interface adapter from the Track object that
    // may be passed back to the client (if needed).
    //
    // Only one AIDL IAudioTrack interface adapter should be created per Track.
    static sp<media::IAudioTrack> createIAudioTrackAdapter(const sp<IAfTrack>& track);

    static sp<IAfTrack> create(
            IAfPlaybackThread* thread,
            const sp<Client>& client,
            audio_stream_type_t streamType,
            const audio_attributes_t& attr,
            uint32_t sampleRate,
            audio_format_t format,
            audio_channel_mask_t channelMask,
            size_t frameCount,
            void* buffer,
            size_t bufferSize,
            const sp<IMemory>& sharedBuffer,
            audio_session_t sessionId,
            pid_t creatorPid,
            const AttributionSourceState& attributionSource,
            audio_output_flags_t flags,
            track_type type,
            audio_port_handle_t portId = AUDIO_PORT_HANDLE_NONE,
            /** default behaviour is to start when there are as many frames
              * ready as possible (aka. Buffer is full). */
            size_t frameCountToBeReady = SIZE_MAX,
            float speed = 1.0f,
            bool isSpatialized = false,
            bool isBitPerfect = false);

    virtual void pause() = 0;
    virtual void flush() = 0;
    virtual audio_stream_type_t streamType() const = 0;
    virtual bool isOffloaded() const = 0;
    virtual bool isOffloadedOrDirect() const = 0;
    virtual bool isStatic() const = 0;
    virtual status_t setParameters(const String8& keyValuePairs) = 0;
    virtual status_t selectPresentation(int presentationId, int programId) = 0;
    virtual status_t attachAuxEffect(int EffectId) = 0;
    virtual void setAuxBuffer(int EffectId, int32_t* buffer) = 0;
    virtual int32_t* auxBuffer() const = 0;
    virtual void setMainBuffer(float* buffer) = 0;
    virtual float* mainBuffer() const = 0;
    virtual int auxEffectId() const = 0;
    virtual status_t getTimestamp(AudioTimestamp& timestamp) = 0;
    virtual void signal() = 0;
    virtual status_t getDualMonoMode(audio_dual_mono_mode_t* mode) const = 0;
    virtual status_t setDualMonoMode(audio_dual_mono_mode_t mode) = 0;
    virtual status_t getAudioDescriptionMixLevel(float* leveldB) const = 0;
    virtual status_t setAudioDescriptionMixLevel(float leveldB) = 0;
    virtual status_t getPlaybackRateParameters(audio_playback_rate_t* playbackRate) const = 0;
    virtual status_t setPlaybackRateParameters(const audio_playback_rate_t& playbackRate) = 0;

    // implement FastMixerState::VolumeProvider interface
    virtual gain_minifloat_packed_t getVolumeLR() const = 0;

    // implement volume handling.
    virtual media::VolumeShaper::Status applyVolumeShaper(
            const sp<media::VolumeShaper::Configuration>& configuration,
            const sp<media::VolumeShaper::Operation>& operation) = 0;
    virtual sp<media::VolumeShaper::State> getVolumeShaperState(int id) const = 0;
    virtual sp<media::VolumeHandler> getVolumeHandler() const = 0;
    /** Set the computed normalized final volume of the track.
     * !masterMute * masterVolume * streamVolume * averageLRVolume */
    virtual void setFinalVolume(float volumeLeft, float volumeRight) = 0;
    virtual float getFinalVolume() const = 0;
    virtual void getFinalVolume(float* left, float* right) const = 0;

    using SourceMetadatas = std::vector<playback_track_metadata_v7_t>;
    using MetadataInserter = std::back_insert_iterator<SourceMetadatas>;
    /** Copy the track metadata in the provided iterator. Thread safe. */
    virtual void copyMetadataTo(MetadataInserter& backInserter) const = 0;

    /** Return haptic playback of the track is enabled or not, used in mixer. */
    virtual bool getHapticPlaybackEnabled() const = 0;
    /** Set haptic playback of the track is enabled or not, should be
     * set after query or get callback from vibrator service */
    virtual void setHapticPlaybackEnabled(bool hapticPlaybackEnabled) = 0;
    /** Return at what intensity to play haptics, used in mixer. */
    virtual os::HapticScale getHapticIntensity() const = 0;
    /** Return the maximum amplitude allowed for haptics data, used in mixer. */
    virtual float getHapticMaxAmplitude() const = 0;
    /** Set intensity of haptic playback, should be set after querying vibrator service. */
    virtual void setHapticIntensity(os::HapticScale hapticIntensity) = 0;
    /** Set maximum amplitude allowed for haptic data, should be set after querying
     *  vibrator service.
     */
    virtual void setHapticMaxAmplitude(float maxAmplitude) = 0;
    virtual sp<os::ExternalVibration> getExternalVibration() const = 0;

    // This function should be called with holding thread lock.
    virtual void updateTeePatches_l() = 0;

    // Argument teePatchesToUpdate is by value, use std::move to optimize.
    virtual void setTeePatchesToUpdate_l(TeePatches teePatchesToUpdate) = 0;

    static bool checkServerLatencySupported(audio_format_t format, audio_output_flags_t flags) {
        return audio_is_linear_pcm(format) && (flags & AUDIO_OUTPUT_FLAG_HW_AV_SYNC) == 0;
    }

    virtual audio_output_flags_t getOutputFlags() const = 0;
    virtual float getSpeed() const = 0;

    /**
     * Updates the mute state and notifies the audio service. Call this only when holding player
     * thread lock.
     */
    virtual void processMuteEvent_l(
            const sp<IAudioManager>& audioManager, mute_state_t muteState) = 0;

    virtual void triggerEvents(AudioSystem::sync_event_t type) = 0;

    virtual void disable() = 0;
    virtual int& fastIndex() = 0;
    virtual bool isPlaybackRestricted() const = 0;

    // Used by thread only

    virtual bool isPausing() const = 0;
    virtual bool isPaused() const = 0;
    virtual bool isResuming() const = 0;
    virtual bool isReady() const = 0;
    virtual void setPaused() = 0;
    virtual void reset() = 0;
    virtual bool isFlushPending() const = 0;
    virtual void flushAck() = 0;
    virtual bool isResumePending() const = 0;
    virtual void resumeAck() = 0;
    // For direct or offloaded tracks ensure that the pause state is acknowledged
    // by the playback thread in case of an immediate flush.
    virtual bool isPausePending() const = 0;
    virtual void pauseAck() = 0;
    virtual void updateTrackFrameInfo(
            int64_t trackFramesReleased, int64_t sinkFramesWritten, uint32_t halSampleRate,
            const ExtendedTimestamp& timeStamp) = 0;
    virtual sp<IMemory> sharedBuffer() const = 0;

    // Dup with ExtendedAudioBufferProvider
    virtual size_t framesReady() const = 0;

    // presentationComplete checked by frames. (Mixed Tracks).
    // framesWritten is cumulative, never reset, and is shared all tracks
    // audioHalFrames is derived from output latency
    virtual bool presentationComplete(int64_t framesWritten, size_t audioHalFrames) = 0;

    // presentationComplete checked by time. (Direct Tracks).
    virtual bool presentationComplete(uint32_t latencyMs) = 0;

    virtual void resetPresentationComplete() = 0;

    virtual bool hasVolumeController() const = 0;
    virtual void setHasVolumeController(bool hasVolumeController) = 0;
    virtual const sp<AudioTrackServerProxy>& audioTrackServerProxy() const = 0;
    virtual void setCachedVolume(float volume) = 0;
    virtual void setResetDone(bool resetDone) = 0;

    virtual ExtendedAudioBufferProvider* asExtendedAudioBufferProvider() = 0;
    virtual VolumeProvider* asVolumeProvider() = 0;

    // TODO(b/291317964) split into getter/setter
    virtual FillingStatus& fillingStatus() = 0;
    virtual int8_t& retryCount() = 0;
    virtual FastTrackUnderruns& fastTrackUnderruns() = 0;
};

// playback track, used by DuplicatingThread
class IAfOutputTrack : public virtual IAfTrack {
public:
    static sp<IAfOutputTrack> create(
            IAfPlaybackThread* playbackThread,
            IAfDuplicatingThread* sourceThread, uint32_t sampleRate,
            audio_format_t format, audio_channel_mask_t channelMask, size_t frameCount,
            const AttributionSourceState& attributionSource);

    virtual ssize_t write(void* data, uint32_t frames) = 0;
    virtual bool bufferQueueEmpty() const = 0;
    virtual bool isActive() const = 0;

    /** Set the metadatas of the upstream tracks. Thread safe. */
    virtual void setMetadatas(const SourceMetadatas& metadatas) = 0;
    /** returns client timestamp to the upstream duplicating thread. */
    virtual ExtendedTimestamp getClientProxyTimestamp() const = 0;
};

class IAfMmapTrack : public virtual IAfTrackBase {
public:
    static sp<IAfMmapTrack> create(IAfThreadBase* thread,
            const audio_attributes_t& attr,
            uint32_t sampleRate,
            audio_format_t format,
            audio_channel_mask_t channelMask,
            audio_session_t sessionId,
            bool isOut,
            const android::content::AttributionSourceState& attributionSource,
            pid_t creatorPid,
            audio_port_handle_t portId = AUDIO_PORT_HANDLE_NONE);

    // protected by MMapThread::mLock
    virtual void setSilenced_l(bool silenced) = 0;
    // protected by MMapThread::mLock
    virtual bool isSilenced_l() const = 0;
    // protected by MMapThread::mLock
    virtual bool getAndSetSilencedNotified_l() = 0;

    /**
     * Updates the mute state and notifies the audio service. Call this only when holding player
     * thread lock.
     */
    virtual void processMuteEvent_l(  // see IAfTrack
            const sp<IAudioManager>& audioManager, mute_state_t muteState) = 0;
};

class RecordBufferConverter;

class IAfRecordTrack : public virtual IAfTrackBase {
public:
    // createIAudioRecordAdapter() is a static constructor which creates an
    // IAudioRecord AIDL interface adapter from the RecordTrack object that
    // may be passed back to the client (if needed).
    //
    // Only one AIDL IAudioRecord interface adapter should be created per RecordTrack.
    static sp<media::IAudioRecord> createIAudioRecordAdapter(const sp<IAfRecordTrack>& recordTrack);

    static sp<IAfRecordTrack> create(IAfRecordThread* thread,
            const sp<Client>& client,
            const audio_attributes_t& attr,
            uint32_t sampleRate,
            audio_format_t format,
            audio_channel_mask_t channelMask,
            size_t frameCount,
            void* buffer,
            size_t bufferSize,
            audio_session_t sessionId,
            pid_t creatorPid,
            const AttributionSourceState& attributionSource,
            audio_input_flags_t flags,
            track_type type,
            audio_port_handle_t portId = AUDIO_PORT_HANDLE_NONE,
            int32_t startFrames = -1);

    // clear the buffer overflow flag
    virtual void clearOverflow() = 0;
    // set the buffer overflow flag and return previous value
    virtual bool setOverflow() = 0;

    // TODO(b/291317964) handleSyncStartEvent in IAfTrackBase should move here.
    virtual void clearSyncStartEvent() = 0;
    virtual void updateTrackFrameInfo(
            int64_t trackFramesReleased, int64_t sourceFramesRead, uint32_t halSampleRate,
            const ExtendedTimestamp& timestamp) = 0;

    virtual void setSilenced(bool silenced) = 0;
    virtual bool isSilenced() const = 0;
    virtual status_t getActiveMicrophones(
            std::vector<media::MicrophoneInfoFw>* activeMicrophones) const = 0;

    virtual status_t setPreferredMicrophoneDirection(audio_microphone_direction_t direction) = 0;
    virtual status_t setPreferredMicrophoneFieldDimension(float zoom) = 0;
    virtual status_t shareAudioHistory(
            const std::string& sharedAudioPackageName, int64_t sharedAudioStartMs) = 0;
    virtual int32_t startFrames() const = 0;

    static bool checkServerLatencySupported(audio_format_t format, audio_input_flags_t flags) {
        return audio_is_linear_pcm(format) && (flags & AUDIO_INPUT_FLAG_HW_AV_SYNC) == 0;
    }

    using SinkMetadatas = std::vector<record_track_metadata_v7_t>;
    using MetadataInserter = std::back_insert_iterator<SinkMetadatas>;
    virtual void copyMetadataTo(MetadataInserter& backInserter) const = 0; // see IAfTrack

    // private to Threads
    virtual AudioBufferProvider::Buffer& sinkBuffer() = 0;
    virtual audioflinger::SynchronizedRecordState& synchronizedRecordState() = 0;
    virtual RecordBufferConverter* recordBufferConverter() const = 0;
    virtual ResamplerBufferProvider* resamplerBufferProvider() const = 0;
};

// PatchProxyBufferProvider interface is implemented by PatchTrack and PatchRecord.
// it provides buffer access methods that map those of a ClientProxy (see AudioTrackShared.h)
class PatchProxyBufferProvider {
public:
    virtual ~PatchProxyBufferProvider() = default;
    virtual bool producesBufferOnDemand() const = 0;
    virtual status_t obtainBuffer(
            Proxy::Buffer* buffer, const struct timespec* requested = nullptr) = 0;
    virtual void releaseBuffer(Proxy::Buffer* buffer) = 0;
};

class IAfPatchTrackBase : public virtual RefBase {
public:
    using Timeout = std::optional<std::chrono::nanoseconds>;

    virtual void setPeerTimeout(std::chrono::nanoseconds timeout) = 0;
    virtual void setPeerProxy(const sp<IAfPatchTrackBase>& proxy, bool holdReference) = 0;
    virtual void clearPeerProxy() = 0;
    virtual PatchProxyBufferProvider* asPatchProxyBufferProvider() = 0;
};

class IAfPatchTrack : public virtual IAfTrack, public virtual IAfPatchTrackBase {
public:
    static sp<IAfPatchTrack> create(
            IAfPlaybackThread* playbackThread,
            audio_stream_type_t streamType,
            uint32_t sampleRate,
            audio_channel_mask_t channelMask,
            audio_format_t format,
            size_t frameCount,
            void *buffer,
            size_t bufferSize,
            audio_output_flags_t flags,
            const Timeout& timeout = {},
            size_t frameCountToBeReady = 1 /** Default behaviour is to start
                                             *  as soon as possible to have
                                             *  the lowest possible latency
                                             *  even if it might glitch. */);
};

class IAfPatchRecord : public virtual IAfRecordTrack, public virtual IAfPatchTrackBase {
public:
    static sp<IAfPatchRecord> create(
            IAfRecordThread* recordThread,
            uint32_t sampleRate,
            audio_channel_mask_t channelMask,
            audio_format_t format,
            size_t frameCount,
            void* buffer,
            size_t bufferSize,
            audio_input_flags_t flags,
            const Timeout& timeout = {},
            audio_source_t source = AUDIO_SOURCE_DEFAULT);

    static sp<IAfPatchRecord> createPassThru(
            IAfRecordThread* recordThread,
            uint32_t sampleRate,
            audio_channel_mask_t channelMask,
            audio_format_t format,
            size_t frameCount,
            audio_input_flags_t flags,
            audio_source_t source = AUDIO_SOURCE_DEFAULT);

    virtual Source* getSource() = 0;
    virtual size_t writeFrames(const void* src, size_t frameCount, size_t frameSize) = 0;
};

}  // namespace android
