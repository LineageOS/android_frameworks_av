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

#include "Configuration.h"  // TEE_SINK
#include "IAfTrack.h"

#include <afutils/NBAIO_Tee.h>
#include <android-base/macros.h>  // DISALLOW_COPY_AND_ASSIGN
#include <datapath/TrackMetrics.h>
#include <mediautils/BatteryNotifier.h>

#include <atomic>    // avoid transitive dependency
#include <list>      // avoid transitive dependency
#include <optional>  // avoid transitive dependency

namespace android {

// base for record and playback
class TrackBase : public ExtendedAudioBufferProvider, public virtual IAfTrackBase {
public:
    TrackBase(IAfThreadBase* thread,
                                const sp<Client>& client,
                                const audio_attributes_t& mAttr,
                                uint32_t sampleRate,
                                audio_format_t format,
                                audio_channel_mask_t channelMask,
                                size_t frameCount,
                                void *buffer,
                                size_t bufferSize,
                                audio_session_t sessionId,
                                pid_t creatorPid,
                                uid_t uid,
                                bool isOut,
                                const alloc_type alloc = ALLOC_CBLK,
                                track_type type = TYPE_DEFAULT,
                                audio_port_handle_t portId = AUDIO_PORT_HANDLE_NONE,
                                std::string metricsId = {});
    ~TrackBase() override;
    status_t initCheck() const override;
    sp<IMemory> getCblk() const final { return mCblkMemory; }
    audio_track_cblk_t* cblk() const final { return mCblk; }
    audio_session_t sessionId() const final { return mSessionId; }
    uid_t uid() const final { return mUid; }
    pid_t creatorPid() const final { return mCreatorPid; }
    audio_port_handle_t portId() const final { return mPortId; }
    status_t setSyncEvent(const sp<audioflinger::SyncEvent>& event) override;
    track_state state() const final { return mState; }
    void setState(track_state state) final { mState = state; }
    sp<IMemory> getBuffers() const final { return mBufferMemory; }
    void* buffer() const final { return mBuffer; }
    size_t bufferSize() const final { return mBufferSize; }

    bool isOutputTrack() const final { return (mType == TYPE_OUTPUT); }
    bool isPatchTrack() const final { return (mType == TYPE_PATCH); }
    bool isExternalTrack() const final { return !isOutputTrack() && !isPatchTrack(); }
    void invalidate() override {
                            if (mIsInvalid) return;
                            mTrackMetrics.logInvalidate();
                            mIsInvalid = true;
                        }
    bool isInvalid() const final { return mIsInvalid; }
    void terminate() final { mTerminated = true; }
    bool isTerminated() const final { return mTerminated; }
    audio_attributes_t attributes() const final { return mAttr; }
    bool isSpatialized() const override { return false; }
    bool isBitPerfect() const override { return false; }

    wp<IAfThreadBase> thread() const final { return mThread; }

    const sp<ServerProxy>& serverProxy() const final { return mServerProxy; }

#ifdef TEE_SINK
    void dumpTee(int fd, const std::string &reason) const final {
        mTee.dump(fd, reason);
    }
#endif
    /** returns the buffer contents size converted to time in milliseconds
     * for PCM Playback or Record streaming tracks. The return value is zero for
     * PCM static tracks and not defined for non-PCM tracks.
     *
     * This may be called without the thread lock.
     */
    double bufferLatencyMs() const override {
                            return mServerProxy->framesReadySafe() * 1000. / sampleRate();
                        }

    /** returns whether the track supports server latency computation.
     * This is set in the constructor and constant throughout the track lifetime.
     */
    bool isServerLatencySupported() const final { return mServerLatencySupported; }

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
    status_t getServerLatencyMs(double* latencyMs, bool* fromTrack = nullptr) const final {
                            if (!isServerLatencySupported()) {
                                return INVALID_OPERATION;
                            }

                            // if no thread lock is acquired, these atomics are not
                            // synchronized with each other, considered a benign race.

                            const double serverLatencyMs = mServerLatencyMs.load();
                            if (serverLatencyMs == 0.) {
                                return INVALID_OPERATION;
                            }
                            if (fromTrack != nullptr) {
                                *fromTrack = mServerLatencyFromTrack.load();
                            }
                            *latencyMs = serverLatencyMs;
                            return OK;
                        }

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
    status_t getTrackLatencyMs(double* latencyMs, bool* fromTrack = nullptr) const {
                            double serverLatencyMs;
                            status_t status = getServerLatencyMs(&serverLatencyMs, fromTrack);
                            if (status == OK) {
                                *latencyMs = serverLatencyMs + bufferLatencyMs();
                            }
                            return status;
                        }

    // KernelFrameTime is updated per "mix" period even for non-pcm tracks.
    void getKernelFrameTime(FrameTime* ft) const final {
                           *ft = mKernelFrameTime.load();
                        }

    audio_format_t format() const final { return mFormat; }
    int id() const final { return mId; }

    const char* getTrackStateAsString() const final {
        if (isTerminated()) {
            return "TERMINATED";
        }
        switch (mState) {
        case IDLE:
            return "IDLE";
        case STOPPING_1: // for Fast and Offload
            return "STOPPING_1";
        case STOPPING_2: // for Fast and Offload
            return "STOPPING_2";
        case STOPPED:
            return "STOPPED";
        case RESUMING:
            return "RESUMING";
        case ACTIVE:
            return "ACTIVE";
        case PAUSING:
            return "PAUSING";
        case PAUSED:
            return "PAUSED";
        case FLUSHED:
            return "FLUSHED";
        case STARTING_1: // for RecordTrack
            return "STARTING_1";
        case STARTING_2: // for RecordTrack
            return "STARTING_2";
        default:
            return "UNKNOWN";
        }
    }

    // Called by the PlaybackThread to indicate that the track is becoming active
    // and a new interval should start with a given device list.
    void logBeginInterval(const std::string& devices) final {
        mTrackMetrics.logBeginInterval(devices);
    }

    // Called by the PlaybackThread to indicate the track is no longer active.
    void logEndInterval() final {
        mTrackMetrics.logEndInterval();
    }

    // Called to tally underrun frames in playback.
    void tallyUnderrunFrames(size_t /* frames */) override {}

    audio_channel_mask_t channelMask() const final { return mChannelMask; }

    /** @return true if the track has changed (metadata or volume) since
     *          the last time this function was called,
     *          true if this function was never called since the track creation,
     *          false otherwise.
     *  Thread safe.
     */
    bool readAndClearHasChanged() final { return !mChangeNotified.test_and_set(); }

    /** Set that a metadata has changed and needs to be notified to backend. Thread safe. */
    void setMetadataHasChanged() final { mChangeNotified.clear(); }

    /**
     * Called when a track moves to active state to record its contribution to battery usage.
     * Track state transitions should eventually be handled within the track class.
     */
    void beginBatteryAttribution() final {
        mBatteryStatsHolder.emplace(uid());
    }

    /**
     * Called when a track moves out of the active state to record its contribution
     * to battery usage.
     */
    void endBatteryAttribution() final {
        mBatteryStatsHolder.reset();
    }

protected:
    DISALLOW_COPY_AND_ASSIGN(TrackBase);

    void releaseCblk() {
        if (mCblk != nullptr) {
            mState.clear();
            mCblk->~audio_track_cblk_t();   // destroy our shared-structure.
            if (mClient == 0) {
                free(mCblk);
            }
            mCblk = nullptr;
        }
    }

    // AudioBufferProvider interface
    // status_t getNextBuffer(AudioBufferProvider::Buffer* buffer) override;
    void releaseBuffer(AudioBufferProvider::Buffer* buffer) override;

    // ExtendedAudioBufferProvider interface is only needed for Track,
    // but putting it in TrackBase avoids the complexity of virtual inheritance
    size_t framesReady() const override { return SIZE_MAX; } // MmapTrack doesn't implement.

    uint32_t channelCount() const { return mChannelCount; }

    size_t frameSize() const final { return mFrameSize; }

    uint32_t sampleRate() const override { return mSampleRate; }

    bool isStopped() const final {
        return (mState == STOPPED || mState == FLUSHED);
    }

    // for fast tracks and offloaded tracks only
    bool isStopping() const final {
        return mState == STOPPING_1 || mState == STOPPING_2;
    }
    bool isStopping_1() const final {
        return mState == STOPPING_1;
    }
    bool isStopping_2() const final {
        return mState == STOPPING_2;
    }

    // Upper case characters are final states.
    // Lower case characters are transitory.
    const char *getTrackStateAsCodedString() const {
        if (isTerminated()) {
            return "T ";
        }
        switch (mState) {
        case IDLE:
            return "I ";
        case STOPPING_1: // for Fast and Offload
            return "s1";
        case STOPPING_2: // for Fast and Offload
            return "s2";
        case STOPPED:
            return "S ";
        case RESUMING:
            return "r ";
        case ACTIVE:
            return "A ";
        case PAUSING:
            return "p ";
        case PAUSED:
            return "P ";
        case FLUSHED:
            return "F ";
        case STARTING_1: // for RecordTrack
            return "r1";
        case STARTING_2: // for RecordTrack
            return "r2";
        default:
            return "? ";
        }
    }

    bool isOut() const { return mIsOut; }
                                    // true for Track, false for RecordTrack,
                                    // this could be a track type if needed later

    const wp<IAfThreadBase> mThread;
    const alloc_type     mAllocType;
    /*const*/ sp<Client> mClient;   // see explanation at ~TrackBase() why not const
    sp<IMemory>         mCblkMemory;
    audio_track_cblk_t* mCblk;
    sp<IMemory>         mBufferMemory;  // currently non-0 for fast RecordTrack only
    void*               mBuffer;    // start of track buffer, typically in shared memory
                                    // except for OutputTrack when it is in local memory
    size_t              mBufferSize; // size of mBuffer in bytes
    // we don't really need a lock for these
    MirroredVariable<track_state>  mState;
    const audio_attributes_t mAttr;
    const uint32_t      mSampleRate;    // initial sample rate only; for tracks which
                        // support dynamic rates, the current value is in control block
    const audio_format_t mFormat;
    const audio_channel_mask_t mChannelMask;
    const uint32_t      mChannelCount;
    const size_t        mFrameSize; // AudioFlinger's view of frame size in shared memory,
                                    // where for AudioTrack (but not AudioRecord),
                                    // 8-bit PCM samples are stored as 16-bit
    const size_t        mFrameCount;// size of track buffer given at createTrack() or
                                    // createRecord(), and then adjusted as needed

    const audio_session_t mSessionId;
    uid_t               mUid;
    std::list<sp<audioflinger::SyncEvent>> mSyncEvents;
    const bool          mIsOut;
    sp<ServerProxy>     mServerProxy;
    const int           mId;
#ifdef TEE_SINK
    NBAIO_Tee           mTee;
#endif
    bool                mTerminated;
    track_type          mType;      // must be one of TYPE_DEFAULT, TYPE_OUTPUT, TYPE_PATCH ...
    audio_io_handle_t   mThreadIoHandle; // I/O handle of the thread the track is attached to
    audio_port_handle_t mPortId; // unique ID for this track used by audio policy
    bool                mIsInvalid; // non-resettable latch, set by invalidate()

    // It typically takes 5 threadloop mix iterations for latency to stabilize.
    // However, this can be 12+ iterations for BT.
    // To be sure, we wait for latency to dip (it usually increases at the start)
    // to assess stability and then log to MediaMetrics.
    // Rapid start / pause calls may cause inaccurate numbers.
    static inline constexpr int32_t LOG_START_COUNTDOWN = 12;
    int32_t             mLogStartCountdown = 0; // Mixer period countdown
    int64_t             mLogStartTimeNs = 0;    // Monotonic time at start()
    int64_t             mLogStartFrames = 0;    // Timestamp frames at start()
    double              mLogLatencyMs = 0.;     // Track the last log latency

    bool                mLogForceVolumeUpdate = true; // force volume update to TrackMetrics.

    TrackMetrics        mTrackMetrics;

    bool                mServerLatencySupported = false;
    std::atomic<bool>   mServerLatencyFromTrack{}; // latency from track or server timestamp.
    std::atomic<double> mServerLatencyMs{};        // last latency pushed from server thread.
    std::atomic<FrameTime> mKernelFrameTime{};     // last frame time on kernel side.
    const pid_t         mCreatorPid;  // can be different from mclient->pid() for instance
                                      // when created by NuPlayer on behalf of a client

    // If the last track change was notified to the client with readAndClearHasChanged
    std::atomic_flag    mChangeNotified = ATOMIC_FLAG_INIT;
    // RAII object for battery stats book-keeping
    std::optional<mediautils::BatteryStatsAudioHandle> mBatteryStatsHolder;
};

class PatchTrackBase : public PatchProxyBufferProvider, public virtual IAfPatchTrackBase
{
public:
                        PatchTrackBase(const sp<ClientProxy>& proxy,
                                       IAfThreadBase* thread,
                                       const Timeout& timeout);
            void setPeerTimeout(std::chrono::nanoseconds timeout) final;
            void setPeerProxy(const sp<IAfPatchTrackBase>& proxy, bool holdReference) final {
                if (proxy) {
                    mPeerReferenceHold = holdReference ? proxy : nullptr;
                    mPeerProxy = proxy->asPatchProxyBufferProvider();
                } else {
                    clearPeerProxy();
                }
            }
            void clearPeerProxy() final {
                            mPeerReferenceHold.clear();
                            mPeerProxy = nullptr;
                        }

            PatchProxyBufferProvider* asPatchProxyBufferProvider() final { return this; }

            bool        producesBufferOnDemand() const override { return false; }

protected:
    const sp<ClientProxy>       mProxy;
    sp<RefBase>                 mPeerReferenceHold;   // keeps mPeerProxy alive during access.
    PatchProxyBufferProvider*   mPeerProxy = nullptr;
    struct timespec             mPeerTimeout{};
};

} // namespace android
