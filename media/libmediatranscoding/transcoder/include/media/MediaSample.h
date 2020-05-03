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

#ifndef ANDROID_MEDIA_SAMPLE_H
#define ANDROID_MEDIA_SAMPLE_H

#include <cstdint>
#include <functional>
#include <memory>

namespace android {

/**
 * Media sample flags.
 * These flags purposely match the media NDK's buffer and extractor flags with one exception. The
 * NDK extractor's flag for encrypted samples (AMEDIAEXTRACTOR_SAMPLE_FLAG_ENCRYPTED) is equal to 2,
 * i.e. the same as SAMPLE_FLAG_CODEC_CONFIG below and NDK's AMEDIACODEC_BUFFER_FLAG_CODEC_CONFIG.
 * Sample producers based on the NDK's extractor is responsible for catching those values.
 * Note that currently the media transcoder does not support encrypted samples.
 */
enum : uint32_t {
    SAMPLE_FLAG_SYNC_SAMPLE = 1,
    SAMPLE_FLAG_CODEC_CONFIG = 2,
    SAMPLE_FLAG_END_OF_STREAM = 4,
    SAMPLE_FLAG_PARTIAL_FRAME = 8,
};

/**
 * MediaSampleInfo is an object that carries information about a compressed media sample without
 * holding any sample data.
 */
struct MediaSampleInfo {
    /** The sample's presentation timestamp in microseconds. */
    int64_t presentationTimeUs = 0;

    /** The size of the compressed sample data in bytes. */
    size_t size = 0;

    /** Sample flags. */
    uint32_t flags = 0;
};

/**
 * MediaSample holds a compressed media sample in memory.
 */
struct MediaSample {
    /**
     * Callback to notify that a media sample is about to be released, giving the creator a chance
     * to reclaim the data buffer backing the sample. Once this callback returns, the media sample
     * instance *will* be released so it cannot be used outside of the callback. To enable the
     * callback, create the media sample with {@link #createWithReleaseCallback}.
     * @param sample The sample to be released.
     */
    using OnSampleReleasedCallback = std::function<void(MediaSample* sample)>;

    /**
     * Creates a new media sample instance with a registered release callback. The release callback
     * will get called right before the media sample is released giving the creator a chance to
     * reclaim the buffer.
     * @param buffer Byte buffer containing the sample's compressed data.
     * @param dataOffset Offset, in bytes, to the sample's compressed data inside the buffer.
     * @param bufferId Buffer identifier that can be used to identify the buffer on release.
     * @param releaseCallback The sample release callback.
     * @return A new media sample instance.
     */
    static std::shared_ptr<MediaSample> createWithReleaseCallback(
            uint8_t* buffer, size_t dataOffset, uint32_t bufferId,
            OnSampleReleasedCallback releaseCallback) {
        MediaSample* sample = new MediaSample(buffer, dataOffset, bufferId, releaseCallback);
        return std::shared_ptr<MediaSample>(
                sample, std::bind(&MediaSample::releaseSample, std::placeholders::_1));
    }

    /**
     * Byte buffer containing the sample's compressed data. The media sample instance does not take
     * ownership of the buffer and will not automatically release the memory, but the caller can
     * register a release callback by creating the media sample with
     * {@link #createWithReleaseCallback}.
     */
    const uint8_t* buffer = nullptr;

    /** Offset, in bytes, to the sample's compressed data inside the buffer. */
    size_t dataOffset = 0;

    /**
     * Buffer identifier. This identifier is likely only meaningful to the sample data producer and
     * can be used for reclaiming the buffer once a consumer is done processing it.
     */
    uint32_t bufferId = 0xBAADF00D;

    /** Media sample information. */
    MediaSampleInfo info;

private:
    MediaSample(uint8_t* buffer, size_t dataOffset, uint32_t bufferId,
                OnSampleReleasedCallback releaseCallback)
          : buffer(buffer),
            dataOffset(dataOffset),
            bufferId(bufferId),
            mReleaseCallback(releaseCallback){};

    static void releaseSample(MediaSample* sample) {
        if (sample->mReleaseCallback != nullptr) {
            sample->mReleaseCallback(sample);
        }
        delete sample;
    }

    // Do not allow copying to prevent dangling pointers in the copied object after the original is
    // released.
    MediaSample(const MediaSample&) = delete;
    MediaSample& operator=(const MediaSample&) = delete;

    const OnSampleReleasedCallback mReleaseCallback = nullptr;
};

}  // namespace android
#endif  // ANDROID_MEDIA_SAMPLE_H
