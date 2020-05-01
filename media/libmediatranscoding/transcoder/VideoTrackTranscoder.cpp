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

// #define LOG_NDEBUG 0
#define LOG_TAG "VideoTrackTranscoder"

#include <android-base/logging.h>
#include <media/VideoTrackTranscoder.h>

namespace android {

// Check that the codec sample flags have the expected NDK meaning.
static_assert(SAMPLE_FLAG_CODEC_CONFIG == AMEDIACODEC_BUFFER_FLAG_CODEC_CONFIG,
              "Sample flag mismatch: CODEC_CONFIG");
static_assert(SAMPLE_FLAG_END_OF_STREAM == AMEDIACODEC_BUFFER_FLAG_END_OF_STREAM,
              "Sample flag mismatch: END_OF_STREAM");
static_assert(SAMPLE_FLAG_PARTIAL_FRAME == AMEDIACODEC_BUFFER_FLAG_PARTIAL_FRAME,
              "Sample flag mismatch: PARTIAL_FRAME");

template <typename T>
void VideoTrackTranscoder::BlockingQueue<T>::push(T const& value, bool front) {
    {
        std::unique_lock<std::mutex> lock(mMutex);
        if (front) {
            mQueue.push_front(value);
        } else {
            mQueue.push_back(value);
        }
    }
    mCondition.notify_one();
}

template <typename T>
T VideoTrackTranscoder::BlockingQueue<T>::pop() {
    std::unique_lock<std::mutex> lock(mMutex);
    while (mQueue.empty()) {
        mCondition.wait(lock);
    }
    T value = mQueue.front();
    mQueue.pop_front();
    return value;
}

// Dispatch responses to codec callbacks onto the message queue.
struct AsyncCodecCallbackDispatch {
    static void onAsyncInputAvailable(AMediaCodec* codec, void* userdata, int32_t index) {
        VideoTrackTranscoder* transcoder = static_cast<VideoTrackTranscoder*>(userdata);
        if (codec == transcoder->mDecoder) {
            transcoder->mCodecMessageQueue.push(
                    [transcoder, index] { transcoder->enqueueInputSample(index); });
        }
    }

    static void onAsyncOutputAvailable(AMediaCodec* codec, void* userdata, int32_t index,
                                       AMediaCodecBufferInfo* bufferInfoPtr) {
        VideoTrackTranscoder* transcoder = static_cast<VideoTrackTranscoder*>(userdata);
        AMediaCodecBufferInfo bufferInfo = *bufferInfoPtr;
        transcoder->mCodecMessageQueue.push([transcoder, index, codec, bufferInfo] {
            if (codec == transcoder->mDecoder) {
                transcoder->transferBuffer(index, bufferInfo);
            } else if (codec == transcoder->mEncoder) {
                transcoder->dequeueOutputSample(index, bufferInfo);
            }
        });
    }

    static void onAsyncFormatChanged(AMediaCodec* codec, void* userdata, AMediaFormat* format) {
        VideoTrackTranscoder* transcoder = static_cast<VideoTrackTranscoder*>(userdata);
        const char* kCodecName = (codec == transcoder->mDecoder ? "Decoder" : "Encoder");
        LOG(DEBUG) << kCodecName << " format changed: " << AMediaFormat_toString(format);
    }

    static void onAsyncError(AMediaCodec* codec, void* userdata, media_status_t error,
                             int32_t actionCode, const char* detail) {
        LOG(ERROR) << "Error from codec " << codec << ", userdata " << userdata << ", error "
                   << error << ", action " << actionCode << ", detail " << detail;
        VideoTrackTranscoder* transcoder = static_cast<VideoTrackTranscoder*>(userdata);
        transcoder->mCodecMessageQueue.push(
                [transcoder, error] {
                    transcoder->mStatus = error;
                    transcoder->mStopRequested = true;
                },
                true);
    }
};

VideoTrackTranscoder::~VideoTrackTranscoder() {
    if (mDecoder != nullptr) {
        AMediaCodec_delete(mDecoder);
    }

    if (mEncoder != nullptr) {
        AMediaCodec_delete(mEncoder);
    }

    if (mSurface != nullptr) {
        ANativeWindow_release(mSurface);
    }
}

// Creates and configures the codecs.
media_status_t VideoTrackTranscoder::configureDestinationFormat(
        const std::shared_ptr<AMediaFormat>& destinationFormat) {
    media_status_t status = AMEDIA_OK;

    if (destinationFormat == nullptr) {
        LOG(ERROR) << "Destination format is null";
        return AMEDIA_ERROR_INVALID_PARAMETER;
    }

    mDestinationFormat = destinationFormat;

    // Create and configure the encoder.
    const char* destinationMime = nullptr;
    bool ok = AMediaFormat_getString(mDestinationFormat.get(), AMEDIAFORMAT_KEY_MIME,
                                     &destinationMime);
    if (!ok) {
        LOG(ERROR) << "Destination MIME type is required for transcoding.";
        return AMEDIA_ERROR_INVALID_PARAMETER;
    }

    mEncoder = AMediaCodec_createEncoderByType(destinationMime);
    if (mEncoder == nullptr) {
        LOG(ERROR) << "Unable to create encoder for type " << destinationMime;
        return AMEDIA_ERROR_UNSUPPORTED;
    }

    status = AMediaCodec_configure(mEncoder, mDestinationFormat.get(), NULL /* surface */,
                                   NULL /* crypto */, AMEDIACODEC_CONFIGURE_FLAG_ENCODE);
    if (status != AMEDIA_OK) {
        LOG(ERROR) << "Unable to configure video encoder: " << status;
        return status;
    }

    status = AMediaCodec_createInputSurface(mEncoder, &mSurface);
    if (status != AMEDIA_OK) {
        LOG(ERROR) << "Unable to create an encoder input surface: %d" << status;
        return status;
    }

    // Create and configure the decoder.
    const char* sourceMime = nullptr;
    ok = AMediaFormat_getString(mSourceFormat.get(), AMEDIAFORMAT_KEY_MIME, &sourceMime);
    if (!ok) {
        LOG(ERROR) << "Source MIME type is required for transcoding.";
        return AMEDIA_ERROR_INVALID_PARAMETER;
    }

    mDecoder = AMediaCodec_createDecoderByType(sourceMime);
    if (mDecoder == nullptr) {
        LOG(ERROR) << "Unable to create decoder for type " << sourceMime;
        return AMEDIA_ERROR_UNSUPPORTED;
    }

    status = AMediaCodec_configure(mDecoder, mSourceFormat.get(), mSurface, NULL /* crypto */,
                                   0 /* flags */);
    if (status != AMEDIA_OK) {
        LOG(ERROR) << "Unable to configure video decoder: " << status;
        return status;
    }

    // Configure codecs to run in async mode.
    AMediaCodecOnAsyncNotifyCallback asyncCodecCallbacks = {
            .onAsyncInputAvailable = AsyncCodecCallbackDispatch::onAsyncInputAvailable,
            .onAsyncOutputAvailable = AsyncCodecCallbackDispatch::onAsyncOutputAvailable,
            .onAsyncFormatChanged = AsyncCodecCallbackDispatch::onAsyncFormatChanged,
            .onAsyncError = AsyncCodecCallbackDispatch::onAsyncError};

    status = AMediaCodec_setAsyncNotifyCallback(mDecoder, asyncCodecCallbacks, this);
    if (status != AMEDIA_OK) {
        LOG(ERROR) << "Unable to set decoder to async mode: " << status;
        return status;
    }

    status = AMediaCodec_setAsyncNotifyCallback(mEncoder, asyncCodecCallbacks, this);
    if (status != AMEDIA_OK) {
        LOG(ERROR) << "Unable to set encoder to async mode: " << status;
        return status;
    }

    return AMEDIA_OK;
}

void VideoTrackTranscoder::enqueueInputSample(int32_t bufferIndex) {
    media_status_t status = AMEDIA_OK;

    if (mEOSFromSource) {
        return;
    }

    status = mMediaSampleReader->getSampleInfoForTrack(mTrackIndex, &mSampleInfo);
    if (status != AMEDIA_OK && status != AMEDIA_ERROR_END_OF_STREAM) {
        LOG(ERROR) << "Error getting next sample info: " << status;
        mStatus = status;
        return;
    }
    const bool endOfStream = (status == AMEDIA_ERROR_END_OF_STREAM);

    if (!endOfStream) {
        size_t bufferSize = 0;
        uint8_t* sourceBuffer = AMediaCodec_getInputBuffer(mDecoder, bufferIndex, &bufferSize);
        if (sourceBuffer == nullptr) {
            LOG(ERROR) << "Decoder returned a NULL input buffer.";
            mStatus = AMEDIA_ERROR_UNKNOWN;
            return;
        } else if (bufferSize < mSampleInfo.size) {
            LOG(ERROR) << "Decoder returned an input buffer that is smaller than the sample.";
            mStatus = AMEDIA_ERROR_UNKNOWN;
            return;
        }

        status = mMediaSampleReader->readSampleDataForTrack(mTrackIndex, sourceBuffer,
                                                            mSampleInfo.size);
        if (status != AMEDIA_OK) {
            LOG(ERROR) << "Unable to read next sample data. Aborting transcode.";
            mStatus = status;
            return;
        }

        mMediaSampleReader->advanceTrack(mTrackIndex);
    } else {
        LOG(DEBUG) << "EOS from source.";
        mEOSFromSource = true;
    }

    status = AMediaCodec_queueInputBuffer(mDecoder, bufferIndex, 0, mSampleInfo.size,
                                          mSampleInfo.presentationTimeUs, mSampleInfo.flags);
    if (status != AMEDIA_OK) {
        LOG(ERROR) << "Unable to queue input buffer for decode: " << status;
        mStatus = status;
        return;
    }
}

void VideoTrackTranscoder::transferBuffer(int32_t bufferIndex, AMediaCodecBufferInfo bufferInfo) {
    if (bufferIndex >= 0) {
        bool needsRender = bufferInfo.size > 0;
        AMediaCodec_releaseOutputBuffer(mDecoder, bufferIndex, needsRender);
    }

    if (bufferInfo.flags & AMEDIACODEC_BUFFER_FLAG_END_OF_STREAM) {
        LOG(DEBUG) << "EOS from decoder.";
        media_status_t status = AMediaCodec_signalEndOfInputStream(mEncoder);
        if (status != AMEDIA_OK) {
            LOG(ERROR) << "SignalEOS on encoder returned error: " << status;
            mStatus = status;
        }
    }
}

void VideoTrackTranscoder::dequeueOutputSample(int32_t bufferIndex,
                                               AMediaCodecBufferInfo bufferInfo) {
    if (bufferIndex >= 0) {
        size_t sampleSize = 0;
        uint8_t* buffer = AMediaCodec_getOutputBuffer(mEncoder, bufferIndex, &sampleSize);

        std::shared_ptr<MediaSample> sample = MediaSample::createWithReleaseCallback(
                buffer, bufferInfo.offset, bufferIndex,
                std::bind(&VideoTrackTranscoder::releaseOutputSample, this, std::placeholders::_1));
        sample->info.size = bufferInfo.size;
        sample->info.flags = bufferInfo.flags;
        sample->info.presentationTimeUs = bufferInfo.presentationTimeUs;

        const bool aborted = mOutputQueue.enqueue(sample);
        if (aborted) {
            LOG(ERROR) << "Output sample queue was aborted. Stopping transcode.";
            mStatus = AMEDIA_ERROR_IO;  // TODO: Define custom error codes?
            return;
        }
    } else if (bufferIndex == AMEDIACODEC_INFO_OUTPUT_FORMAT_CHANGED) {
        AMediaFormat* newFormat = AMediaCodec_getOutputFormat(mEncoder);
        LOG(DEBUG) << "Encoder output format changed: " << AMediaFormat_toString(newFormat);
    }

    if (bufferInfo.flags & AMEDIACODEC_BUFFER_FLAG_END_OF_STREAM) {
        LOG(DEBUG) << "EOS from encoder.";
        mEOSFromEncoder = true;
    }
}

void VideoTrackTranscoder::releaseOutputSample(MediaSample* sample) {
    AMediaCodec_releaseOutputBuffer(mEncoder, sample->bufferId, false /* render */);
}

media_status_t VideoTrackTranscoder::runTranscodeLoop() {
    media_status_t status = AMEDIA_OK;

    status = AMediaCodec_start(mDecoder);
    if (status != AMEDIA_OK) {
        LOG(ERROR) << "Unable to start video decoder: " << status;
        return status;
    }

    status = AMediaCodec_start(mEncoder);
    if (status != AMEDIA_OK) {
        LOG(ERROR) << "Unable to start video encoder: " << status;
        AMediaCodec_stop(mDecoder);
        return status;
    }

    // Process codec events until EOS is reached, transcoding is stopped or an error occurs.
    while (!mStopRequested && !mEOSFromEncoder && mStatus == AMEDIA_OK) {
        std::function<void()> message = mCodecMessageQueue.pop();
        message();
    }

    // Return error if transcoding was stopped before it finished.
    if (mStopRequested && !mEOSFromEncoder && mStatus == AMEDIA_OK) {
        mStatus = AMEDIA_ERROR_UNKNOWN;  // TODO: Define custom error codes?
    }

    AMediaCodec_stop(mDecoder);
    AMediaCodec_stop(mEncoder);
    return mStatus;
}

void VideoTrackTranscoder::abortTranscodeLoop() {
    // Push abort message to the front of the codec event queue.
    mCodecMessageQueue.push([this] { mStopRequested = true; }, true /* front */);
}

}  // namespace android
