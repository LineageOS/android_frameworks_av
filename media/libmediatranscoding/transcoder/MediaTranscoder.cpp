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
#define LOG_TAG "MediaTranscoder"

#include <android-base/logging.h>
#include <fcntl.h>
#include <media/MediaSampleReaderNDK.h>
#include <media/MediaSampleWriter.h>
#include <media/MediaTranscoder.h>
#include <media/PassthroughTrackTranscoder.h>
#include <media/VideoTrackTranscoder.h>
#include <unistd.h>

namespace android {

#define DEFINE_FORMAT_VALUE_COPY_FUNC(_type, _typeName)                                  \
    static void copy##_typeName(const char* key, AMediaFormat* to, AMediaFormat* from) { \
        _type value;                                                                     \
        if (AMediaFormat_get##_typeName(from, key, &value)) {                            \
            AMediaFormat_set##_typeName(to, key, value);                                 \
        }                                                                                \
    }

DEFINE_FORMAT_VALUE_COPY_FUNC(const char*, String);
DEFINE_FORMAT_VALUE_COPY_FUNC(int64_t, Int64);
DEFINE_FORMAT_VALUE_COPY_FUNC(int32_t, Int32);

static AMediaFormat* mergeMediaFormats(AMediaFormat* base, AMediaFormat* overlay) {
    if (base == nullptr || overlay == nullptr) {
        LOG(ERROR) << "Cannot merge null formats";
        return nullptr;
    }

    AMediaFormat* format = AMediaFormat_new();
    if (AMediaFormat_copy(format, base) != AMEDIA_OK) {
        AMediaFormat_delete(format);
        return nullptr;
    }

    // Note: AMediaFormat does not expose a function for appending values from another format or for
    // iterating over all values and keys in a format. Instead we define a static list of known keys
    // along with their value types and copy the ones that are present. A better solution would be
    // to either implement required functions in NDK or to parse the overlay format's string
    // representation and copy all existing keys.
    static const struct {
        const char* key;
        void (*copyValue)(const char* key, AMediaFormat* to, AMediaFormat* from);
    } kSupportedConfigs[] = {
            {AMEDIAFORMAT_KEY_MIME, copyString},
            {AMEDIAFORMAT_KEY_DURATION, copyInt64},
            {AMEDIAFORMAT_KEY_WIDTH, copyInt32},
            {AMEDIAFORMAT_KEY_HEIGHT, copyInt32},
            {AMEDIAFORMAT_KEY_BIT_RATE, copyInt32},
            {AMEDIAFORMAT_KEY_PROFILE, copyInt32},
            {AMEDIAFORMAT_KEY_LEVEL, copyInt32},
            {AMEDIAFORMAT_KEY_COLOR_FORMAT, copyInt32},
            {AMEDIAFORMAT_KEY_COLOR_RANGE, copyInt32},
            {AMEDIAFORMAT_KEY_COLOR_STANDARD, copyInt32},
            {AMEDIAFORMAT_KEY_COLOR_TRANSFER, copyInt32},
            {AMEDIAFORMAT_KEY_FRAME_RATE, copyInt32},
            {AMEDIAFORMAT_KEY_I_FRAME_INTERVAL, copyInt32},
    };

    for (int i = 0; i < (sizeof(kSupportedConfigs) / sizeof(kSupportedConfigs[0])); ++i) {
        kSupportedConfigs[i].copyValue(kSupportedConfigs[i].key, format, overlay);
    }

    return format;
}

void MediaTranscoder::sendCallback(media_status_t status) {
    bool expected = false;
    if (mCallbackSent.compare_exchange_strong(expected, true)) {
        if (status == AMEDIA_OK) {
            mCallbacks->onFinished(this);
        } else {
            mCallbacks->onError(this, status);
        }

        // Transcoding is done and the callback to the client has been sent, so tear down the
        // pipeline but do it asynchronously to avoid deadlocks. If an error occurred, client
        // should clean up the file.
        std::thread asyncCancelThread{[self = shared_from_this()] { self->cancel(); }};
        asyncCancelThread.detach();
    }
}

void MediaTranscoder::onTrackFinished(const MediaTrackTranscoder* transcoder) {
    LOG(DEBUG) << "TrackTranscoder " << transcoder << " finished";
}

void MediaTranscoder::onTrackError(const MediaTrackTranscoder* transcoder, media_status_t status) {
    LOG(DEBUG) << "TrackTranscoder " << transcoder << " returned error " << status;
    sendCallback(status);
}

void MediaTranscoder::onSampleWriterFinished(media_status_t status) {
    LOG((status != AMEDIA_OK) ? ERROR : DEBUG) << "Sample writer finished with status " << status;
    sendCallback(status);
}

MediaTranscoder::MediaTranscoder(const std::shared_ptr<CallbackInterface>& callbacks)
      : mCallbacks(callbacks) {}

std::shared_ptr<MediaTranscoder> MediaTranscoder::create(
        const std::shared_ptr<CallbackInterface>& callbacks,
        const std::shared_ptr<Parcel>& pausedState) {
    if (pausedState != nullptr) {
        LOG(ERROR) << "Initializing from paused state is currently not supported.";
        return nullptr;
    } else if (callbacks == nullptr) {
        LOG(ERROR) << "Callbacks cannot be null";
        return nullptr;
    }

    return std::shared_ptr<MediaTranscoder>(new MediaTranscoder(callbacks));
}

media_status_t MediaTranscoder::configureSource(int fd) {
    if (fd < 0) {
        LOG(ERROR) << "Invalid source fd: " << fd;
        return AMEDIA_ERROR_INVALID_PARAMETER;
    }

    const size_t fileSize = lseek(fd, 0, SEEK_END);
    lseek(fd, 0, SEEK_SET);

    mSampleReader = MediaSampleReaderNDK::createFromFd(fd, 0 /* offset */, fileSize);

    if (mSampleReader == nullptr) {
        LOG(ERROR) << "Unable to parse source fd: " << fd;
        return AMEDIA_ERROR_UNSUPPORTED;
    }

    const size_t trackCount = mSampleReader->getTrackCount();
    for (size_t trackIndex = 0; trackIndex < trackCount; ++trackIndex) {
        AMediaFormat* trackFormat = mSampleReader->getTrackFormat(static_cast<int>(trackIndex));
        if (trackFormat == nullptr) {
            LOG(ERROR) << "Track #" << trackIndex << " has no format";
            return AMEDIA_ERROR_MALFORMED;
        }

        mSourceTrackFormats.emplace_back(trackFormat, &AMediaFormat_delete);
    }

    return AMEDIA_OK;
}

std::vector<std::shared_ptr<AMediaFormat>> MediaTranscoder::getTrackFormats() const {
    // Return a deep copy of the formats to avoid the caller modifying our internal formats.
    std::vector<std::shared_ptr<AMediaFormat>> trackFormats;
    for (const std::shared_ptr<AMediaFormat>& sourceFormat : mSourceTrackFormats) {
        AMediaFormat* copy = AMediaFormat_new();
        AMediaFormat_copy(copy, sourceFormat.get());
        trackFormats.emplace_back(copy, &AMediaFormat_delete);
    }
    return trackFormats;
}

media_status_t MediaTranscoder::configureTrackFormat(size_t trackIndex, AMediaFormat* trackFormat) {
    if (mSampleReader == nullptr) {
        LOG(ERROR) << "Source must be configured before tracks";
        return AMEDIA_ERROR_INVALID_OPERATION;
    } else if (trackIndex >= mSourceTrackFormats.size()) {
        LOG(ERROR) << "Track index " << trackIndex
                   << " is out of bounds. Track count: " << mSourceTrackFormats.size();
        return AMEDIA_ERROR_INVALID_PARAMETER;
    }

    std::unique_ptr<MediaTrackTranscoder> transcoder = nullptr;
    std::shared_ptr<AMediaFormat> format = nullptr;

    if (trackFormat == nullptr) {
        transcoder = std::make_unique<PassthroughTrackTranscoder>(shared_from_this());
    } else {
        const char* srcMime = nullptr;
        if (!AMediaFormat_getString(mSourceTrackFormats[trackIndex].get(), AMEDIAFORMAT_KEY_MIME,
                                    &srcMime)) {
            LOG(ERROR) << "Source track #" << trackIndex << " has no mime type";
            return AMEDIA_ERROR_MALFORMED;
        }

        if (strncmp(srcMime, "video/", 6) != 0) {
            LOG(ERROR) << "Only video tracks are supported for transcoding. Unable to configure "
                          "track #"
                       << trackIndex << " with mime " << srcMime;
            return AMEDIA_ERROR_UNSUPPORTED;
        }

        const char* dstMime = nullptr;
        if (AMediaFormat_getString(trackFormat, AMEDIAFORMAT_KEY_MIME, &dstMime)) {
            if (strncmp(dstMime, "video/", 6) != 0) {
                LOG(ERROR) << "Unable to convert media types for track #" << trackIndex << ", from "
                           << srcMime << " to " << dstMime;
                return AMEDIA_ERROR_UNSUPPORTED;
            }
        }

        transcoder = std::make_unique<VideoTrackTranscoder>(shared_from_this());

        AMediaFormat* mergedFormat =
                mergeMediaFormats(mSourceTrackFormats[trackIndex].get(), trackFormat);
        if (mergedFormat == nullptr) {
            LOG(ERROR) << "Unable to merge source and destination formats";
            return AMEDIA_ERROR_UNKNOWN;
        }

        format = std::shared_ptr<AMediaFormat>(mergedFormat, &AMediaFormat_delete);
    }

    media_status_t status = transcoder->configure(mSampleReader, trackIndex, format);
    if (status != AMEDIA_OK) {
        LOG(ERROR) << "Configure track transcoder for track #" << trackIndex << " returned error "
                   << status;
        return status;
    }

    mTrackTranscoders.emplace_back(std::move(transcoder));
    return AMEDIA_OK;
}

media_status_t MediaTranscoder::configureDestination(int fd) {
    if (fd < 0) {
        LOG(ERROR) << "Invalid destination fd: " << fd;
        return AMEDIA_ERROR_INVALID_PARAMETER;
    }

    if (mSampleWriter != nullptr) {
        LOG(ERROR) << "Destination is already configured.";
        return AMEDIA_ERROR_INVALID_OPERATION;
    }

    mSampleWriter = std::make_unique<MediaSampleWriter>();
    const bool initOk = mSampleWriter->init(
            fd, std::bind(&MediaTranscoder::onSampleWriterFinished, this, std::placeholders::_1));

    if (!initOk) {
        LOG(ERROR) << "Unable to initialize sample writer with destination fd: " << fd;
        mSampleWriter.reset();
        return AMEDIA_ERROR_UNKNOWN;
    }

    return AMEDIA_OK;
}

media_status_t MediaTranscoder::start() {
    if (mTrackTranscoders.size() < 1) {
        LOG(ERROR) << "Unable to start, no tracks are configured.";
        return AMEDIA_ERROR_INVALID_OPERATION;
    } else if (mSampleWriter == nullptr) {
        LOG(ERROR) << "Unable to start, destination is not configured";
        return AMEDIA_ERROR_INVALID_OPERATION;
    }

    // Add tracks to the writer.
    for (auto& transcoder : mTrackTranscoders) {
        const bool ok = mSampleWriter->addTrack(transcoder->getOutputQueue(),
                                                transcoder->getOutputFormat());
        if (!ok) {
            LOG(ERROR) << "Unable to add track to sample writer.";
            return AMEDIA_ERROR_UNKNOWN;
        }
    }

    bool started = mSampleWriter->start();
    if (!started) {
        LOG(ERROR) << "Unable to start sample writer.";
        return AMEDIA_ERROR_UNKNOWN;
    }

    // Start transcoders
    for (auto& transcoder : mTrackTranscoders) {
        started = transcoder->start();
        if (!started) {
            LOG(ERROR) << "Unable to start track transcoder.";
            cancel();
            return AMEDIA_ERROR_UNKNOWN;
        }
    }
    return AMEDIA_OK;
}

media_status_t MediaTranscoder::pause(std::shared_ptr<const Parcelable>* pausedState) {
    (void)pausedState;
    LOG(ERROR) << "Pause is not currently supported";
    return AMEDIA_ERROR_UNSUPPORTED;
}

media_status_t MediaTranscoder::resume() {
    LOG(ERROR) << "Resume is not currently supported";
    return AMEDIA_ERROR_UNSUPPORTED;
}

media_status_t MediaTranscoder::cancel() {
    bool expected = false;
    if (!mCancelled.compare_exchange_strong(expected, true)) {
        // Already cancelled.
        return AMEDIA_OK;
    }

    mSampleWriter->stop();
    for (auto& transcoder : mTrackTranscoders) {
        transcoder->stop();
    }

    return AMEDIA_OK;
}

}  // namespace android
