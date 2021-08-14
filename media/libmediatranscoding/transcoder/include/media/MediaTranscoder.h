/*
 * Copyright (C) 2020 The Android Open Source Project
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

#ifndef ANDROID_MEDIA_TRANSCODER_H
#define ANDROID_MEDIA_TRANSCODER_H

#include <android/binder_auto_utils.h>
#include <media/MediaSampleWriter.h>
#include <media/MediaTrackTranscoderCallback.h>
#include <media/NdkMediaCodecPlatform.h>
#include <media/NdkMediaError.h>
#include <media/NdkMediaFormat.h>
#include <utils/Mutex.h>

#include <atomic>
#include <memory>
#include <mutex>
#include <unordered_set>

namespace android {

class MediaSampleReader;

class MediaTranscoder : public std::enable_shared_from_this<MediaTranscoder>,
                        public MediaTrackTranscoderCallback,
                        public MediaSampleWriter::CallbackInterface {
public:
    /** Callbacks from transcoder to client. */
    class CallbackInterface {
    public:
        /** Transcoder finished successfully. */
        virtual void onFinished(const MediaTranscoder* transcoder) = 0;

        /** Transcoder encountered an unrecoverable error. */
        virtual void onError(const MediaTranscoder* transcoder, media_status_t error) = 0;

        /** Transcoder progress update reported in percent from 0 to 100. */
        virtual void onProgressUpdate(const MediaTranscoder* transcoder, int32_t progress) = 0;

        /** Transcoder heart-beat signal. */
        virtual void onHeartBeat(const MediaTranscoder* transcoder) = 0;

        /**
         * Transcoder lost codec resources and paused operations. The client can resume transcoding
         * again when resources are available by either:
         *   1) Calling resume on the same MediaTranscoder instance.
         *   2) Creating a new MediaTranscoding instance with the paused state and then calling
         *      resume.
         */
        virtual void onCodecResourceLost(
                const MediaTranscoder* transcoder,
                const std::shared_ptr<ndk::ScopedAParcel>& pausedState) = 0;

        virtual ~CallbackInterface() = default;
    };

    /**
     * Creates a new MediaTranscoder instance. If the supplied paused state is valid, the transcoder
     * will be initialized with the paused state and be ready to be resumed right away. It is not
     * possible to change any configurations on a paused transcoder.
     */
    static std::shared_ptr<MediaTranscoder> create(
            const std::shared_ptr<CallbackInterface>& callbacks, int64_t heartBeatIntervalUs = -1,
            pid_t pid = AMEDIACODEC_CALLING_PID, uid_t uid = AMEDIACODEC_CALLING_UID,
            const std::shared_ptr<ndk::ScopedAParcel>& pausedState = nullptr);

    /** Configures source from path fd. */
    media_status_t configureSource(int fd);

    /** Gets the media formats of all tracks in the file. */
    std::vector<std::shared_ptr<AMediaFormat>> getTrackFormats() const;

    /**
     * Configures transcoding of a track. Tracks that are not configured will not present in the
     * final transcoded file, i.e. tracks will be dropped by default. Passing nullptr for
     * trackFormat means the track will be copied unchanged ("passthrough") to the destination.
     * Track configurations must be done after the source has been configured.
     * Note: trackFormat is not modified but cannot be const.
     */
    media_status_t configureTrackFormat(size_t trackIndex, AMediaFormat* trackFormat);

    /** Configures destination from fd. */
    media_status_t configureDestination(int fd);

    /** Starts transcoding. No configurations can be made once the transcoder has started. */
    media_status_t start();

    /**
     * Pauses transcoding and finalizes the partial transcoded file to disk. Pause is a synchronous
     * operation and will wait until all internal components are done. Once this method returns it
     * is safe to release the transcoder instance. No callback will be called if the transcoder was
     * paused successfully. But if the transcoding finishes or encountered an error during pause,
     * the corresponding callback will be called.
     */
    media_status_t pause(std::shared_ptr<ndk::ScopedAParcel>* pausedState);

    /** Resumes a paused transcoding. */
    media_status_t resume();

    /**
     * Cancels the transcoding. Once canceled the transcoding can not be restarted. Client
     * will be responsible for cleaning up the abandoned file. Cancel is a synchronous operation and
     * will wait until all internal components are done. Once this method returns it is safe to
     * release the transcoder instance. Normally no callback will be called when the transcoder is
     * cancelled. But if the transcoding finishes or encountered an error during cancel, the
     * corresponding callback will be called.
     */
    media_status_t cancel();

    virtual ~MediaTranscoder() = default;

private:
    MediaTranscoder(const std::shared_ptr<CallbackInterface>& callbacks,
                    int64_t heartBeatIntervalUs, pid_t pid, uid_t uid);

    // MediaTrackTranscoderCallback
    virtual void onTrackFormatAvailable(const MediaTrackTranscoder* transcoder) override;
    virtual void onTrackFinished(const MediaTrackTranscoder* transcoder) override;
    virtual void onTrackStopped(const MediaTrackTranscoder* transcoder) override;
    virtual void onTrackError(const MediaTrackTranscoder* transcoder,
                              media_status_t status) override;
    // ~MediaTrackTranscoderCallback

    // MediaSampleWriter::CallbackInterface
    virtual void onFinished(const MediaSampleWriter* writer, media_status_t status) override;
    virtual void onStopped(const MediaSampleWriter* writer) override;
    virtual void onProgressUpdate(const MediaSampleWriter* writer, int32_t progress) override;
    virtual void onHeartBeat(const MediaSampleWriter* writer) override;
    // ~MediaSampleWriter::CallbackInterface

    void onThreadFinished(const void* thread, media_status_t threadStatus, bool threadStopped);
    media_status_t requestStop(bool stopOnSync);
    void waitForThreads();

    std::shared_ptr<CallbackInterface> mCallbacks;
    std::shared_ptr<MediaSampleReader> mSampleReader;
    std::shared_ptr<MediaSampleWriter> mSampleWriter;
    std::vector<std::shared_ptr<AMediaFormat>> mSourceTrackFormats;
    std::vector<std::shared_ptr<MediaTrackTranscoder>> mTrackTranscoders;
    std::mutex mTracksAddedMutex;
    std::unordered_set<const MediaTrackTranscoder*> mTracksAdded GUARDED_BY(mTracksAddedMutex);
    int64_t mHeartBeatIntervalUs;
    pid_t mPid;
    uid_t mUid;

    enum ThreadState {
        PENDING = 0,  // Not yet started.
        RUNNING,      // Currently running.
        DONE,         // Done running (can be finished, stopped or error).
    };
    std::mutex mThreadStateMutex;
    std::condition_variable mThreadsDoneSignal;
    std::unordered_map<const void*, ThreadState> mThreadStates GUARDED_BY(mThreadStateMutex);
    media_status_t mTranscoderStatus GUARDED_BY(mThreadStateMutex) = AMEDIA_OK;
    bool mTranscoderStopped GUARDED_BY(mThreadStateMutex) = false;
    bool mThreadsDone GUARDED_BY(mThreadStateMutex) = false;
    bool mCallbackSent GUARDED_BY(mThreadStateMutex) = false;
    bool mSampleWriterStopped GUARDED_BY(mThreadStateMutex) = false;

    std::atomic_bool mCancelled = false;
};

}  // namespace android
#endif  // ANDROID_MEDIA_TRANSCODER_H
