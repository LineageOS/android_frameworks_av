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

#include "TrackBase.h"

#include <android/os/BnExternalVibrationController.h>
#include <audio_utils/LinearMap.h>
#include <binder/AppOpsManager.h>

namespace android {

// Checks and monitors OP_PLAY_AUDIO
class OpPlayAudioMonitor : public RefBase {
    friend class sp<OpPlayAudioMonitor>;
public:
    ~OpPlayAudioMonitor() override;
    bool hasOpPlayAudio() const;

    static sp<OpPlayAudioMonitor> createIfNeeded(
            IAfThreadBase* thread,
            const AttributionSourceState& attributionSource,
            const audio_attributes_t& attr, int id,
            audio_stream_type_t streamType);

private:
    OpPlayAudioMonitor(IAfThreadBase* thread,
                       const AttributionSourceState& attributionSource,
                       audio_usage_t usage, int id, uid_t uid);
    void onFirstRef() override;
    static void getPackagesForUid(uid_t uid, Vector<String16>& packages);

    AppOpsManager mAppOpsManager;

    class PlayAudioOpCallback : public BnAppOpsCallback {
    public:
        explicit PlayAudioOpCallback(const wp<OpPlayAudioMonitor>& monitor);
        void opChanged(int32_t op, const String16& packageName) override;

    private:
        const wp<OpPlayAudioMonitor> mMonitor;
    };

    sp<PlayAudioOpCallback> mOpCallback;
    // called by PlayAudioOpCallback when OP_PLAY_AUDIO is updated in AppOp callback
    void checkPlayAudioForUsage(bool doBroadcast);

    wp<IAfThreadBase> mThread;
    std::atomic_bool mHasOpPlayAudio;
    const AttributionSourceState mAttributionSource;
    const int32_t mUsage; // on purpose not audio_usage_t because always checked in appOps as int32_t
    const int mId; // for logging purposes only
    const uid_t mUid;
    const String16 mPackageName;
};

// playback track
class Track : public TrackBase, public virtual IAfTrack, public VolumeProvider {
public:
    Track(IAfPlaybackThread* thread,
                                const sp<Client>& client,
                                audio_stream_type_t streamType,
                                const audio_attributes_t& attr,
                                uint32_t sampleRate,
                                audio_format_t format,
                                audio_channel_mask_t channelMask,
                                size_t frameCount,
                                void *buffer,
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
    ~Track() override;
    status_t initCheck() const final;
    void appendDumpHeader(String8& result) const final;
    void appendDump(String8& result, bool active) const final;
    status_t start(AudioSystem::sync_event_t event = AudioSystem::SYNC_EVENT_NONE,
            audio_session_t triggerSession = AUDIO_SESSION_NONE) override;
    void stop() override;
    void pause() final;
    void flush() final;
    void destroy() final;
    uint32_t sampleRate() const final;
    audio_stream_type_t streamType() const final {
                return mStreamType;
            }
    bool isOffloaded() const final
                                { return (mFlags & AUDIO_OUTPUT_FLAG_COMPRESS_OFFLOAD) != 0; }
    bool isDirect() const final
                                { return (mFlags & AUDIO_OUTPUT_FLAG_DIRECT) != 0; }
    bool isOffloadedOrDirect() const final { return (mFlags
                            & (AUDIO_OUTPUT_FLAG_COMPRESS_OFFLOAD
                                    | AUDIO_OUTPUT_FLAG_DIRECT)) != 0; }
    bool isStatic() const final { return  mSharedBuffer.get() != nullptr; }

    status_t setParameters(const String8& keyValuePairs) final;
    status_t selectPresentation(int presentationId, int programId) final;
    status_t attachAuxEffect(int EffectId) final;
    void setAuxBuffer(int EffectId, int32_t* buffer) final;
    int32_t* auxBuffer() const final { return mAuxBuffer; }
    void setMainBuffer(float* buffer) final { mMainBuffer = buffer; }
    float* mainBuffer() const final { return mMainBuffer; }
    int auxEffectId() const final { return mAuxEffectId; }
    status_t getTimestamp(AudioTimestamp& timestamp) final;
    void signal() final;
    status_t getDualMonoMode(audio_dual_mono_mode_t* mode) const final;
    status_t setDualMonoMode(audio_dual_mono_mode_t mode) final;
    status_t getAudioDescriptionMixLevel(float* leveldB) const final;
    status_t setAudioDescriptionMixLevel(float leveldB) final;
    status_t getPlaybackRateParameters(audio_playback_rate_t* playbackRate) const final;
    status_t setPlaybackRateParameters(const audio_playback_rate_t& playbackRate) final;

    // implement FastMixerState::VolumeProvider interface
    gain_minifloat_packed_t getVolumeLR() const final;

    status_t setSyncEvent(const sp<audioflinger::SyncEvent>& event) final;
    bool isFastTrack() const final { return (mFlags & AUDIO_OUTPUT_FLAG_FAST) != 0; }
    double bufferLatencyMs() const final {
                            return isStatic() ? 0. : TrackBase::bufferLatencyMs();
                        }

    // implement volume handling.
    media::VolumeShaper::Status applyVolumeShaper(
                                const sp<media::VolumeShaper::Configuration>& configuration,
                                const sp<media::VolumeShaper::Operation>& operation);
    sp<media::VolumeShaper::State> getVolumeShaperState(int id) const final;
    sp<media::VolumeHandler> getVolumeHandler() const final{ return mVolumeHandler; }
    /** Set the computed normalized final volume of the track.
     * !masterMute * masterVolume * streamVolume * averageLRVolume */
    void setFinalVolume(float volumeLeft, float volumeRight) final;
    float getFinalVolume() const final { return mFinalVolume; }
    void getFinalVolume(float* left, float* right) const final {
                            *left = mFinalVolumeLeft;
                            *right = mFinalVolumeRight;
    }

    using SourceMetadatas = std::vector<playback_track_metadata_v7_t>;
    using MetadataInserter = std::back_insert_iterator<SourceMetadatas>;
    /** Copy the track metadata in the provided iterator. Thread safe. */
    void copyMetadataTo(MetadataInserter& backInserter) const override;


            /** Return haptic playback of the track is enabled or not, used in mixer. */
    bool getHapticPlaybackEnabled() const final { return mHapticPlaybackEnabled; }
            /** Set haptic playback of the track is enabled or not, should be
             *  set after query or get callback from vibrator service */
    void setHapticPlaybackEnabled(bool hapticPlaybackEnabled) final {
                mHapticPlaybackEnabled = hapticPlaybackEnabled;
            }
            /** Return at what intensity to play haptics, used in mixer. */
    os::HapticScale getHapticIntensity() const final { return mHapticIntensity; }
            /** Return the maximum amplitude allowed for haptics data, used in mixer. */
    float getHapticMaxAmplitude() const final { return mHapticMaxAmplitude; }
            /** Set intensity of haptic playback, should be set after querying vibrator service. */
    void setHapticIntensity(os::HapticScale hapticIntensity) final {
                if (os::isValidHapticScale(hapticIntensity)) {
                    mHapticIntensity = hapticIntensity;
                    setHapticPlaybackEnabled(mHapticIntensity != os::HapticScale::MUTE);
                }
            }
            /** Set maximum amplitude allowed for haptic data, should be set after querying
             *  vibrator service.
             */
    void setHapticMaxAmplitude(float maxAmplitude) final {
                mHapticMaxAmplitude = maxAmplitude;
            }
    sp<os::ExternalVibration> getExternalVibration() const final { return mExternalVibration; }

            // This function should be called with holding thread lock.
    void updateTeePatches_l() final;
    void setTeePatchesToUpdate_l(TeePatches teePatchesToUpdate) final;

    void tallyUnderrunFrames(size_t frames) final {
       if (isOut()) { // we expect this from output tracks only
           mAudioTrackServerProxy->tallyUnderrunFrames(frames);
           // Fetch absolute numbers from AudioTrackShared as it counts
           // contiguous underruns as a one -- we want a consistent number.
           // TODO: isolate this counting into a class.
           mTrackMetrics.logUnderruns(mAudioTrackServerProxy->getUnderrunCount(),
                   mAudioTrackServerProxy->getUnderrunFrames());
       }
    }

    audio_output_flags_t getOutputFlags() const final { return mFlags; }
    float getSpeed() const final { return mSpeed; }
    bool isSpatialized() const final { return mIsSpatialized; }
    bool isBitPerfect() const final { return mIsBitPerfect; }

    /**
     * Updates the mute state and notifies the audio service. Call this only when holding player
     * thread lock.
     */
    void processMuteEvent_l(const sp<IAudioManager>& audioManager, mute_state_t muteState) final;

protected:

    DISALLOW_COPY_AND_ASSIGN(Track);

    // AudioBufferProvider interface
    status_t getNextBuffer(AudioBufferProvider::Buffer* buffer) override;
    void releaseBuffer(AudioBufferProvider::Buffer* buffer) override;

    // ExtendedAudioBufferProvider interface
    size_t framesReady() const override;
    int64_t framesReleased() const override;
    void onTimestamp(const ExtendedTimestamp &timestamp) override;

    // Used by thread
    bool isPausing() const final { return mState == PAUSING; }
    bool isPaused() const final { return mState == PAUSED; }
    bool isResuming() const final { return mState == RESUMING; }
    bool isReady() const final;
    void setPaused() final { mState = PAUSED; }
    void reset() final;
    bool isFlushPending() const final { return mFlushHwPending; }
    void flushAck() final;
    bool isResumePending() const final;
    void resumeAck() final;
    // For direct or offloaded tracks ensure that the pause state is acknowledged
    // by the playback thread in case of an immediate flush.
    bool isPausePending() const final { return mPauseHwPending; }
    void pauseAck() final;
    void updateTrackFrameInfo(int64_t trackFramesReleased, int64_t sinkFramesWritten,
            uint32_t halSampleRate, const ExtendedTimestamp& timeStamp) final;

    sp<IMemory> sharedBuffer() const final { return mSharedBuffer; }

    // presentationComplete checked by frames. (Mixed Tracks).
    // framesWritten is cumulative, never reset, and is shared all tracks
    // audioHalFrames is derived from output latency
    bool presentationComplete(int64_t framesWritten, size_t audioHalFrames) final;

    // presentationComplete checked by time. (Direct Tracks).
    bool presentationComplete(uint32_t latencyMs) final;

    void resetPresentationComplete() final {
        mPresentationCompleteFrames = 0;
        mPresentationCompleteTimeNs = 0;
    }

    // notifyPresentationComplete is called when presentationComplete() detects
    // that the track is finished stopping.
    void notifyPresentationComplete();

    void signalClientFlag(int32_t flag);

    void triggerEvents(AudioSystem::sync_event_t type) final;
    void invalidate() final;
    void disable() final;
    int& fastIndex() final { return mFastIndex; }
    bool isPlaybackRestricted() const final {
        // The monitor is only created for tracks that can be silenced.
        return mOpPlayAudioMonitor ? !mOpPlayAudioMonitor->hasOpPlayAudio() : false; }

    const sp<AudioTrackServerProxy>& audioTrackServerProxy() const final {
        return mAudioTrackServerProxy;
    }
    bool hasVolumeController() const final { return mHasVolumeController; }
    void setHasVolumeController(bool hasVolumeController) final {
        mHasVolumeController = hasVolumeController;
    }
    void setCachedVolume(float volume) final {
        mCachedVolume = volume;
    }
    void setResetDone(bool resetDone) final {
        mResetDone = resetDone;
    }
    ExtendedAudioBufferProvider* asExtendedAudioBufferProvider() final {
        return this;
    }
    VolumeProvider* asVolumeProvider() final {
        return this;
    }

    FillingStatus& fillingStatus() final { return mFillingStatus; }
    int8_t& retryCount() final { return mRetryCount; }
    FastTrackUnderruns& fastTrackUnderruns() final { return mObservedUnderruns; }

protected:
    mutable FillingStatus mFillingStatus;
    int8_t              mRetryCount;

    // see comment at ~Track for why this can't be const
    sp<IMemory>         mSharedBuffer;

    bool                mResetDone;
    const audio_stream_type_t mStreamType;
    float     *mMainBuffer;

    int32_t             *mAuxBuffer;
    int                 mAuxEffectId;
    bool                mHasVolumeController;

    // access these three variables only when holding thread lock.
    LinearMap<int64_t> mFrameMap;           // track frame to server frame mapping

    ExtendedTimestamp  mSinkTimestamp;

    sp<media::VolumeHandler>  mVolumeHandler; // handles multiple VolumeShaper configs and operations

    sp<OpPlayAudioMonitor>  mOpPlayAudioMonitor;

    bool                mHapticPlaybackEnabled = false; // indicates haptic playback enabled or not
    // intensity to play haptic data
    os::HapticScale mHapticIntensity = os::HapticScale::MUTE;
    // max amplitude allowed for haptic data
    float mHapticMaxAmplitude = NAN;
    class AudioVibrationController : public os::BnExternalVibrationController {
    public:
        explicit AudioVibrationController(Track* track) : mTrack(track) {}
        binder::Status mute(/*out*/ bool *ret) override;
        binder::Status unmute(/*out*/ bool *ret) override;
    private:
        Track* const mTrack;
        bool setMute(bool muted);
    };
    sp<AudioVibrationController> mAudioVibrationController;
    sp<os::ExternalVibration>    mExternalVibration;

    audio_dual_mono_mode_t mDualMonoMode = AUDIO_DUAL_MONO_MODE_OFF;
    float               mAudioDescriptionMixLevel = -std::numeric_limits<float>::infinity();
    audio_playback_rate_t  mPlaybackRateParameters = AUDIO_PLAYBACK_RATE_INITIALIZER;

private:
    void                interceptBuffer(const AudioBufferProvider::Buffer& buffer);
    // Must hold thread lock to access tee patches
    template <class F>
    void                forEachTeePatchTrack_l(F f) {
        for (auto& tp : mTeePatches) { f(tp.patchTrack); }
    };

    size_t              mPresentationCompleteFrames = 0; // (Used for Mixed tracks)
                                    // The number of frames written to the
                                    // audio HAL when this track is considered fully rendered.
                                    // Zero means not monitoring.
    int64_t             mPresentationCompleteTimeNs = 0; // (Used for Direct tracks)
                                    // The time when this track is considered fully rendered.
                                    // Zero means not monitoring.

    // The following fields are only for fast tracks, and should be in a subclass
    int                 mFastIndex; // index within FastMixerState::mFastTracks[];
                                    // either mFastIndex == -1 if not isFastTrack()
                                    // or 0 < mFastIndex < FastMixerState::kMaxFast because
                                    // index 0 is reserved for normal mixer's submix;
                                    // index is allocated statically at track creation time
                                    // but the slot is only used if track is active
    FastTrackUnderruns  mObservedUnderruns; // Most recently observed value of
                                    // mFastMixerDumpState.mTracks[mFastIndex].mUnderruns
    volatile float      mCachedVolume;  // combined master volume and stream type volume;
                                        // 'volatile' means accessed without lock or
                                        // barrier, but is read/written atomically
    float               mFinalVolume; // combine master volume, stream type volume and track volume
    float               mFinalVolumeLeft; // combine master volume, stream type volume and track
                                          // volume
    float               mFinalVolumeRight; // combine master volume, stream type volume and track
                                           // volume
    sp<AudioTrackServerProxy>  mAudioTrackServerProxy;
    bool                mResumeToStopping; // track was paused in stopping state.
    bool                mFlushHwPending; // track requests for thread flush
    bool                mPauseHwPending = false; // direct/offload track request for thread pause
    audio_output_flags_t mFlags;
    TeePatches mTeePatches;
    std::optional<TeePatches> mTeePatchesToUpdate;
    const float         mSpeed;
    const bool          mIsSpatialized;
    const bool          mIsBitPerfect;

    // TODO: replace PersistableBundle with own struct
    // access these two variables only when holding player thread lock.
    std::unique_ptr<os::PersistableBundle> mMuteEventExtras;
    mute_state_t        mMuteState;
};  // end of Track


// playback track, used by DuplicatingThread
class OutputTrack : public Track, public IAfOutputTrack {
public:

    class Buffer : public AudioBufferProvider::Buffer {
    public:
        void *mBuffer;
    };

    OutputTrack(IAfPlaybackThread* thread,
            IAfDuplicatingThread* sourceThread,
                                uint32_t sampleRate,
                                audio_format_t format,
                                audio_channel_mask_t channelMask,
                                size_t frameCount,
                                const AttributionSourceState& attributionSource);
    ~OutputTrack() override;

    status_t start(AudioSystem::sync_event_t event =
                                    AudioSystem::SYNC_EVENT_NONE,
                             audio_session_t triggerSession = AUDIO_SESSION_NONE) final;
    void stop() final;
    ssize_t write(void* data, uint32_t frames) final;
    bool bufferQueueEmpty() const final { return mBufferQueue.size() == 0; }
    bool isActive() const final { return mActive; }

    void copyMetadataTo(MetadataInserter& backInserter) const final;
    /** Set the metadatas of the upstream tracks. Thread safe. */
    void setMetadatas(const SourceMetadatas& metadatas) final;
    /** returns client timestamp to the upstream duplicating thread. */
    ExtendedTimestamp getClientProxyTimestamp() const final {
                            // server - kernel difference is not true latency when drained
                            // i.e. mServerProxy->isDrained().
                            ExtendedTimestamp timestamp;
                            (void) mClientProxy->getTimestamp(&timestamp);
                            // On success, the timestamp LOCATION_SERVER and LOCATION_KERNEL
                            // entries will be properly filled. If getTimestamp()
                            // is unsuccessful, then a default initialized timestamp
                            // (with mTimeNs[] filled with -1's) is returned.
                            return timestamp;
                        }
private:
    status_t            obtainBuffer(AudioBufferProvider::Buffer* buffer,
                                     uint32_t waitTimeMs);
    void                queueBuffer(Buffer& inBuffer);
    void                clearBufferQueue();

    void                restartIfDisabled();

    // Maximum number of pending buffers allocated by OutputTrack::write()
    static const uint8_t kMaxOverFlowBuffers = 10;

    Vector < Buffer* >          mBufferQueue;
    AudioBufferProvider::Buffer mOutBuffer;
    bool                        mActive;
    IAfDuplicatingThread* const mSourceThread; // for waitTimeMs() in write()
    sp<AudioTrackClientProxy>   mClientProxy;

    /** Attributes of the source tracks.
     *
     * This member must be accessed with mTrackMetadatasMutex taken.
     * There is one writer (duplicating thread) and one reader (downstream mixer).
     *
     * That means that the duplicating thread can block the downstream mixer
     * thread and vice versa for the time of the copy.
     * If this becomes an issue, the metadata could be stored in an atomic raw pointer,
     * and a exchange with nullptr and delete can be used.
     * Alternatively a read-copy-update might be implemented.
     */
    SourceMetadatas mTrackMetadatas;
    /** Protects mTrackMetadatas against concurrent access. */
    mutable std::mutex mTrackMetadatasMutex;
};  // end of OutputTrack

// playback track, used by PatchPanel
class PatchTrack : public Track, public PatchTrackBase, public IAfPatchTrack {
public:
    PatchTrack(IAfPlaybackThread* playbackThread,
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
    ~PatchTrack() override;

    size_t framesReady() const final;

    status_t start(AudioSystem::sync_event_t event =
                                    AudioSystem::SYNC_EVENT_NONE,
                             audio_session_t triggerSession = AUDIO_SESSION_NONE) final;

    // AudioBufferProvider interface
    status_t getNextBuffer(AudioBufferProvider::Buffer* buffer) final;
    void releaseBuffer(AudioBufferProvider::Buffer* buffer) final;

    // PatchProxyBufferProvider interface
    status_t obtainBuffer(Proxy::Buffer* buffer, const struct timespec* timeOut = nullptr) final;
    void releaseBuffer(Proxy::Buffer* buffer) final;

private:
            void restartIfDisabled();
};  // end of PatchTrack

} // namespace android
