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
#include <media/NdkMediaError.h>
#include <media/NdkMediaFormat.h>
#include <utils/Mutex.h>

#include <functional>
#include <memory>
#include <thread>

namespace android {

class MediaTrackTranscoder;

/** Callback interface for MediaTrackTranscoder. */
class MediaTrackTranscoderCallback {
public:
    /**
     * Called when the MediaTrackTranscoder instance have finished transcoding all media samples
     * successfully.
     * @param transcoder The MediaTrackTranscoder that finished the transcoding.
     */
    virtual void onTrackFinished(MediaTrackTranscoder* transcoder);

    /**
     * Called when the MediaTrackTranscoder instance encountered an error it could not recover from.
     * @param transcoder The MediaTrackTranscoder that encountered the error.
     * @param status The non-zero error code describing the encountered error.
     */
    virtual void onTrackError(MediaTrackTranscoder* transcoder, media_status_t status);

protected:
    virtual ~MediaTrackTranscoderCallback() = default;
};

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
     * Starts the track transcoder. Once started the track transcoder have to be stopped by calling
     * {@link #stop}, even after completing successfully. Start should only be called once.
     * @return True if the track transcoder started, or false if it had already been started.
     */
    bool start();

    /**
     * Stops the track transcoder. Once the transcoding has been stopped it cannot be restarted
     * again. It is safe to call stop multiple times.
     * @return True if the track transcoder stopped, or false if it was already stopped.
     */
    bool stop();

    /** Sample output queue. */
    MediaSampleQueue mOutputQueue = {};

protected:
    MediaTrackTranscoder(const std::weak_ptr<MediaTrackTranscoderCallback>& transcoderCallback)
          : mTranscoderCallback(transcoderCallback){};
    virtual ~MediaTrackTranscoder() = default;

    // configureDestinationFormat needs to be implemented by subclasses, and gets called on an
    // external thread before start.
    virtual media_status_t configureDestinationFormat(
            const std::shared_ptr<AMediaFormat>& destinationFormat) = 0;

    // runTranscodeLoop needs to be implemented by subclasses, and gets called on
    // MediaTrackTranscoder's internal thread when the track transcoder is started.
    virtual media_status_t runTranscodeLoop() = 0;

    // abortTranscodeLoop needs to be implemented by subclasses, and should request transcoding to
    // be aborted as soon as possible. It should be safe to call abortTranscodeLoop multiple times.
    virtual void abortTranscodeLoop() = 0;

    std::shared_ptr<MediaSampleReader> mMediaSampleReader;
    int mTrackIndex;
    std::shared_ptr<AMediaFormat> mSourceFormat;

private:
    const std::weak_ptr<MediaTrackTranscoderCallback> mTranscoderCallback;
    std::mutex mStateMutex;
    std::thread mTranscodingThread GUARDED_BY(mStateMutex);
    enum {
        UNINITIALIZED,
        CONFIGURED,
        STARTED,
        STOPPED,
    } mState GUARDED_BY(mStateMutex) = UNINITIALIZED;
};

}  // namespace android
#endif  // ANDROID_MEDIA_TRACK_TRANSCODER_H
