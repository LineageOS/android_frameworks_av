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

#include <media/MediaSampleQueue.h>
#include <media/NdkMediaCodec.h>
#include <media/NdkMediaError.h>
#include <media/NdkMediaFormat.h>
#include <utils/Mutex.h>

#include <functional>
#include <memory>
#include <mutex>
#include <set>
#include <thread>

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
 * MediaSampleWriter writes samples to a muxer while keeping its input sources synchronized. Each
 * source track have its own MediaSampleQueue from which samples are dequeued by the sample writer
 * and written to the muxer. The sample writer always prioritizes dequeueing samples from the source
 * track that is farthest behind by comparing sample timestamps. If the slowest track does not have
 * any samples pending the writer moves on to the next track but never allows tracks to diverge more
 * than a configurable duration of time. The default muxer interface implementation is based
 * directly on AMediaMuxer.
 */
class MediaSampleWriter {
public:
    /** The default maximum track divergence in microseconds. */
    static constexpr uint32_t kDefaultMaxTrackDivergenceUs = 1 * 1000 * 1000;  // 1 second.

    /** Callback interface. */
    class CallbackInterface {
    public:
        /**
         * Sample writer finished. The finished callback is only called after the sample writer has
         * been successfully started.
         */
        virtual void onFinished(const MediaSampleWriter* writer, media_status_t status) = 0;

        /** Sample writer progress update in percent. */
        virtual void onProgressUpdate(const MediaSampleWriter* writer, int32_t progress) = 0;

        virtual ~CallbackInterface() = default;
    };

    /**
     * Constructor with custom maximum track divergence.
     * @param maxTrackDivergenceUs The maximum track divergence in microseconds.
     */
    MediaSampleWriter(uint32_t maxTrackDivergenceUs)
          : mMaxTrackDivergenceUs(maxTrackDivergenceUs), mMuxer(nullptr), mState(UNINITIALIZED){};

    /** Constructor using the default maximum track divergence. */
    MediaSampleWriter() : MediaSampleWriter(kDefaultMaxTrackDivergenceUs){};

    /** Destructor. */
    ~MediaSampleWriter();

    /**
     * Initializes the sample writer with its default muxer implementation. MediaSampleWriter needs
     * to be initialized before tracks are added and can only be initialized once.
     * @param fd An open file descriptor to write to. The caller is responsible for closing this
     *        file descriptor and it is safe to do so once this method returns.
     * @param callbacks Client callback object that gets called by the sample writer.
     * @return True if the writer was successfully initialized.
     */
    bool init(int fd, const std::weak_ptr<CallbackInterface>& callbacks /* nonnull */);

    /**
     * Initializes the sample writer with a custom muxer interface implementation.
     * @param muxer The custom muxer interface implementation.
     * @param @param callbacks Client callback object that gets called by the sample writer.
     * @return True if the writer was successfully initialized.
     */
    bool init(const std::shared_ptr<MediaSampleWriterMuxerInterface>& muxer /* nonnull */,
              const std::weak_ptr<CallbackInterface>& callbacks /* nonnull */);

    /**
     * Adds a new track to the sample writer. Tracks must be added after the sample writer has been
     * initialized and before it is started.
     * @param sampleQueue The MediaSampleQueue to pull samples from.
     * @param trackFormat The format of the track to add.
     * @return True if the track was successfully added.
     */
    bool addTrack(const std::shared_ptr<MediaSampleQueue>& sampleQueue /* nonnull */,
                  const std::shared_ptr<AMediaFormat>& trackFormat /* nonnull */);

    /**
     * Starts the sample writer. The sample writer will start processing samples and writing them to
     * its muxer on an internal thread. MediaSampleWriter can only be started once.
     * @return True if the sample writer was successfully started.
     */
    bool start();

    /**
     * Stops the sample writer. If the sample writer is not yet finished its operation will be
     * aborted and an error value will be returned to the client in the callback supplied to
     * {@link #start}. If the sample writer has already finished and the client callback has fired
     * the writer has already automatically stopped and there is no need to call stop manually. Once
     * the sample writer has been stopped it cannot be restarted.
     * @return True if the sample writer was successfully stopped on this call. False if the sample
     *         writer was already stopped or was never started.
     */
    bool stop();

private:
    struct TrackRecord {
        TrackRecord(const std::shared_ptr<MediaSampleQueue>& sampleQueue, size_t trackIndex,
                    int64_t durationUs)
              : mSampleQueue(sampleQueue),
                mTrackIndex(trackIndex),
                mDurationUs(durationUs),
                mFirstSampleTimeUs(0),
                mPrevSampleTimeUs(INT64_MIN),
                mFirstSampleTimeSet(false),
                mReachedEos(false) {}

        std::shared_ptr<MediaSampleQueue> mSampleQueue;
        const size_t mTrackIndex;
        int64_t mDurationUs;
        int64_t mFirstSampleTimeUs;
        int64_t mPrevSampleTimeUs;
        bool mFirstSampleTimeSet;
        bool mReachedEos;

        struct compare {
            bool operator()(const TrackRecord* lhs, const TrackRecord* rhs) const {
                return lhs->mPrevSampleTimeUs < rhs->mPrevSampleTimeUs;
            }
        };
    };

    const uint32_t mMaxTrackDivergenceUs;
    std::weak_ptr<CallbackInterface> mCallbacks;
    std::shared_ptr<MediaSampleWriterMuxerInterface> mMuxer;
    std::vector<std::unique_ptr<TrackRecord>> mAllTracks;
    std::multiset<TrackRecord*, TrackRecord::compare> mSortedTracks;
    std::thread mThread;

    std::mutex mStateMutex;
    enum : int {
        UNINITIALIZED,
        INITIALIZED,
        STARTED,
        STOPPED,
    } mState GUARDED_BY(mStateMutex);

    media_status_t writeSamples();
    media_status_t runWriterLoop();
    std::multiset<TrackRecord*>::iterator getNextOutputTrack();
};

}  // namespace android
#endif  // ANDROID_MEDIA_SAMPLE_WRITER_H
