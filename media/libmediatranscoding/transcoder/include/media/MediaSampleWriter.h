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

#ifndef ANDROID_MEDIA_SAMPLE_WRITER_H
#define ANDROID_MEDIA_SAMPLE_WRITER_H

#include <media/MediaSample.h>
#include <media/NdkMediaCodec.h>
#include <media/NdkMediaError.h>
#include <media/NdkMediaFormat.h>
#include <utils/Mutex.h>

#include <condition_variable>
#include <functional>
#include <memory>
#include <mutex>
#include <queue>
#include <thread>
#include <unordered_map>

namespace android {

/**
 * Muxer interface used by MediaSampleWriter.
 * Methods in this interface are guaranteed to be called sequentially by MediaSampleWriter.
 */
class MediaSampleWriterMuxerInterface {
public:
    /**
     * Adds a new track to the muxer.
     * @param trackFormat Format of the new track.
     * @return A non-negative track index on success, or a negative number on failure.
     */
    virtual ssize_t addTrack(AMediaFormat* trackFormat) = 0;

    /** Starts the muxer. */
    virtual media_status_t start() = 0;
    /**
     * Writes sample data to a previously added track.
     * @param trackIndex Index of the track the sample data belongs to.
     * @param data The sample data.
     * @param info The sample information.
     * @return The number of bytes written.
     */
    virtual media_status_t writeSampleData(size_t trackIndex, const uint8_t* data,
                                           const AMediaCodecBufferInfo* info) = 0;

    /** Stops the muxer. */
    virtual media_status_t stop() = 0;
    virtual ~MediaSampleWriterMuxerInterface() = default;
};

/**
 * MediaSampleWriter is a wrapper around a muxer. The sample writer puts samples on a queue that
 * is serviced by an internal thread to minimize blocking time for clients. MediaSampleWriter also
 * provides progress reporting. The default muxer interface implementation is based
 * directly on AMediaMuxer.
 */
class MediaSampleWriter : public std::enable_shared_from_this<MediaSampleWriter> {
public:
    /** Function prototype for delivering media samples to the writer. */
    using MediaSampleConsumerFunction =
            std::function<void(const std::shared_ptr<MediaSample>& sample)>;

    /** Callback interface. */
    class CallbackInterface {
    public:
        /**
         * Sample writer finished. The finished callback is only called after the sample writer has
         * been successfully started.
         */
        virtual void onFinished(const MediaSampleWriter* writer, media_status_t status) = 0;

        /** Sample writer was stopped before it was finished. */
        virtual void onStopped(const MediaSampleWriter* writer) = 0;

        /** Sample writer progress update in percent. */
        virtual void onProgressUpdate(const MediaSampleWriter* writer, int32_t progress) = 0;

        /** Sample writer heart-beat signal. */
        virtual void onHeartBeat(const MediaSampleWriter* writer) = 0;

        virtual ~CallbackInterface() = default;
    };

    static std::shared_ptr<MediaSampleWriter> Create();

    /**
     * Initializes the sample writer with its default muxer implementation. MediaSampleWriter needs
     * to be initialized before tracks are added and can only be initialized once.
     * @param fd An open file descriptor to write to. The caller is responsible for closing this
     *        file descriptor and it is safe to do so once this method returns.
     * @param callbacks Client callback object that gets called by the sample writer.
     * @param heartBeatIntervalUs Interval (in microsecond) at which the sample writer should send a
     *        heart-beat to onProgressUpdate() to indicate it's making progress. Value <=0 indicates
     *        that the heartbeat is not required.
     * @return True if the writer was successfully initialized.
     */
    bool init(int fd, const std::weak_ptr<CallbackInterface>& callbacks /* nonnull */,
              int64_t heartBeatIntervalUs = -1);

    /**
     * Initializes the sample writer with a custom muxer interface implementation.
     * @param muxer The custom muxer interface implementation.
     * @param @param callbacks Client callback object that gets called by the sample writer.
     * @param heartBeatIntervalUs Interval (in microsecond) at which the sample writer should send a
     *        heart-beat to onProgressUpdate() to indicate it's making progress.
     * @return True if the writer was successfully initialized.
     */
    bool init(const std::shared_ptr<MediaSampleWriterMuxerInterface>& muxer /* nonnull */,
              const std::weak_ptr<CallbackInterface>& callbacks /* nonnull */,
              int64_t heartBeatIntervalUs = -1);

    /**
     * Adds a new track to the sample writer. Tracks must be added after the sample writer has been
     * initialized and before it is started.
     * @param trackFormat The format of the track to add.
     * @return A sample consumer to add samples to if the track was successfully added, or nullptr
     * if the track could not be added.
     */
    MediaSampleConsumerFunction addTrack(
            const std::shared_ptr<AMediaFormat>& trackFormat /* nonnull */);

    /**
     * Starts the sample writer. The sample writer will start processing samples and writing them to
     * its muxer on an internal thread. MediaSampleWriter can only be started once.
     * @return True if the sample writer was successfully started.
     */
    bool start();

    /**
     * Stops the sample writer. If the sample writer is not yet finished, its operation will be
     * aborted and the onStopped callback will fire. If the sample writer has already finished and
     * the onFinished callback has fired the writer has already automatically stopped and there is
     * no need to call stop manually. Once the sample writer has been stopped it cannot be
     * restarted. This method is asynchronous and will not wait for the sample writer to stop before
     * returning.
     */
    void stop();

    /** Destructor. */
    ~MediaSampleWriter();

private:
    struct TrackRecord {
        TrackRecord(int64_t durationUs)
              : mDurationUs(durationUs),
                mFirstSampleTimeUs(0),
                mPrevSampleTimeUs(INT64_MIN),
                mFirstSampleTimeSet(false),
                mReachedEos(false){};

        TrackRecord() : TrackRecord(0){};

        int64_t mDurationUs;
        int64_t mFirstSampleTimeUs;
        int64_t mPrevSampleTimeUs;
        bool mFirstSampleTimeSet;
        bool mReachedEos;
    };

    // Track index and sample.
    using SampleEntry = std::pair<size_t, std::shared_ptr<MediaSample>>;

    struct SampleComparator {
        // Return true if lhs should come after rhs in the sample queue.
        bool operator()(const SampleEntry& lhs, const SampleEntry& rhs) {
            const bool lhsEos = lhs.second->info.flags & SAMPLE_FLAG_END_OF_STREAM;
            const bool rhsEos = rhs.second->info.flags & SAMPLE_FLAG_END_OF_STREAM;

            if (lhsEos && !rhsEos) {
                return true;
            } else if (!lhsEos && rhsEos) {
                return false;
            } else if (lhsEos && rhsEos) {
                return lhs.first > rhs.first;
            }

            return lhs.second->info.presentationTimeUs > rhs.second->info.presentationTimeUs;
        }
    };

    std::weak_ptr<CallbackInterface> mCallbacks;
    std::shared_ptr<MediaSampleWriterMuxerInterface> mMuxer;
    int64_t mHeartBeatIntervalUs;

    std::mutex mMutex;  // Protects sample queue and state.
    std::condition_variable mSampleSignal;
    std::unordered_map<size_t, TrackRecord> mTracks;
    std::priority_queue<SampleEntry, std::vector<SampleEntry>, SampleComparator> mSampleQueue
            GUARDED_BY(mMutex);

    enum : int {
        UNINITIALIZED,
        INITIALIZED,
        STARTED,
        STOPPED,
    } mState GUARDED_BY(mMutex);

    MediaSampleWriter() : mState(UNINITIALIZED){};
    void addSampleToTrack(size_t trackIndex, const std::shared_ptr<MediaSample>& sample);
    media_status_t writeSamples(bool* wasStopped);
    media_status_t runWriterLoop(bool* wasStopped);
};

}  // namespace android
#endif  // ANDROID_MEDIA_SAMPLE_WRITER_H
