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

#ifndef ANDROID_MEDIA_TRACK_TRANSCODER_H
#define ANDROID_MEDIA_TRACK_TRANSCODER_H

#include <media/MediaSampleQueue.h>
#include <media/MediaSampleReader.h>
#include <media/MediaSampleWriter.h>
#include <media/NdkMediaError.h>
#include <media/NdkMediaFormat.h>
#include <utils/Mutex.h>

#include <functional>
#include <memory>
#include <mutex>
#include <thread>

namespace android {

class MediaTrackTranscoderCallback;

/**
 * Base class for all track transcoders. MediaTrackTranscoder operates asynchronously on an internal
 * thread and communicates through a MediaTrackTranscoderCallback instance. Transcoded samples are
 * enqueued on the MediaTrackTranscoder's output queue. Samples need to be dequeued from the output
 * queue or the transcoder will run out of buffers and stall. Once the consumer is done with a
 * transcoded sample it is the consumer's responsibility to as soon as possible release all
 * references to that sample in order to return the buffer to the transcoder. MediaTrackTranscoder
 * is an abstract class and instances are created through one of the concrete subclasses.
 *
 * The base class MediaTrackTranscoder is responsible for thread and state management and guarantees
 * that operations {configure, start, stop} are sent to the derived class in correct order.
 * MediaTrackTranscoder is also responsible for delivering callback notifications once the
 * transcoder has been successfully started.
 */
class MediaTrackTranscoder {
public:
    /**
     * Configures the track transcoder with an input MediaSampleReader and a destination format.
     * A track transcoder have to be configured before it is started.
     * @param mediaSampleReader The MediaSampleReader to read input samples from.
     * @param trackIndex The index of the track to transcode in mediaSampleReader.
     * @param destinationFormat The destination format.
     * @return AMEDIA_OK if the track transcoder was successfully configured.
     */
    media_status_t configure(const std::shared_ptr<MediaSampleReader>& mediaSampleReader,
                             int trackIndex,
                             const std::shared_ptr<AMediaFormat>& destinationFormat);

    /**
     * Starts the track transcoder. After the track transcoder is successfully started it will run
     * until a callback signals that transcoding has ended. Start should only be called once.
     * @return True if the track transcoder started, or false if it had already been started.
     */
    bool start();

    /**
     * Stops the track transcoder. Once the transcoding has been stopped it cannot be restarted
     * again. It is safe to call stop multiple times. Stop is an asynchronous operation. Once the
     * track transcoder has stopped the onTrackStopped callback will get called, unless the
     * transcoding finished or encountered an error before it could be stopped in which case the
     * callbacks corresponding to those events will be called instead.
     * @param stopOnSyncSample Request the transcoder to stop after emitting a sync sample.
     */
    void stop(bool stopOnSyncSample = false);

    /**
     * Set the sample consumer function. The MediaTrackTranscoder will deliver transcoded samples to
     * this function. If the MediaTrackTranscoder is started before a consumer is set the transcoder
     * will buffer a limited number of samples internally before stalling. Once a consumer has been
     * set the internally buffered samples will be delivered to the consumer.
     * @param sampleConsumer The sample consumer function.
     */
    void setSampleConsumer(const MediaSampleWriter::MediaSampleConsumerFunction& sampleConsumer);

    /**
      * Retrieves the track transcoder's final output format. The output is available after the
      * track transcoder has been successfully configured.
      * @return The track output format.
      */
    virtual std::shared_ptr<AMediaFormat> getOutputFormat() const = 0;

    virtual ~MediaTrackTranscoder() = default;

protected:
    MediaTrackTranscoder(const std::weak_ptr<MediaTrackTranscoderCallback>& transcoderCallback)
          : mTranscoderCallback(transcoderCallback){};

    // Called by subclasses when the actual track format becomes available.
    void notifyTrackFormatAvailable();

    // Called by subclasses when a transcoded sample is available. Samples must not hold a strong
    // reference to the track transcoder in order to avoid retain cycles through the track
    // transcoder's sample queue.
    void onOutputSampleAvailable(const std::shared_ptr<MediaSample>& sample);

    // configureDestinationFormat needs to be implemented by subclasses, and gets called on an
    // external thread before start.
    virtual media_status_t configureDestinationFormat(
            const std::shared_ptr<AMediaFormat>& destinationFormat) = 0;

    // runTranscodeLoop needs to be implemented by subclasses, and gets called on
    // MediaTrackTranscoder's internal thread when the track transcoder is started.
    virtual media_status_t runTranscodeLoop(bool* stopped) = 0;

    // abortTranscodeLoop needs to be implemented by subclasses, and should request transcoding to
    // be aborted as soon as possible. It should be safe to call abortTranscodeLoop multiple times.
    virtual void abortTranscodeLoop() = 0;

    std::shared_ptr<MediaSampleReader> mMediaSampleReader;
    int mTrackIndex;
    std::shared_ptr<AMediaFormat> mSourceFormat;

    enum StopRequest {
        NONE,
        STOP_NOW,
        STOP_ON_SYNC,
    };
    std::atomic<StopRequest> mStopRequest = NONE;

private:
    std::mutex mSampleMutex;
    // SampleQueue for buffering output samples before a sample consumer has been set.
    MediaSampleQueue mSampleQueue GUARDED_BY(mSampleMutex);
    MediaSampleWriter::MediaSampleConsumerFunction mSampleConsumer GUARDED_BY(mSampleMutex);
    const std::weak_ptr<MediaTrackTranscoderCallback> mTranscoderCallback;
    std::mutex mStateMutex;
    enum {
        UNINITIALIZED,
        CONFIGURED,
        STARTED,
        STOPPED,
    } mState GUARDED_BY(mStateMutex) = UNINITIALIZED;
};

}  // namespace android
#endif  // ANDROID_MEDIA_TRACK_TRANSCODER_H
