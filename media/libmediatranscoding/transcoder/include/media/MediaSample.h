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

// Check that the sample flags have the expected NDK meaning.
namespace {
#include <media/NdkMediaCodec.h>
#include <media/NdkMediaExtractor.h>

static_assert(SAMPLE_FLAG_SYNC_SAMPLE == AMEDIAEXTRACTOR_SAMPLE_FLAG_SYNC,
              "Sample flag mismatch: SYNC_SAMPLE");
static_assert(SAMPLE_FLAG_CODEC_CONFIG == AMEDIACODEC_BUFFER_FLAG_CODEC_CONFIG,
              "Sample flag mismatch: CODEC_CONFIG");
static_assert(SAMPLE_FLAG_END_OF_STREAM == AMEDIACODEC_BUFFER_FLAG_END_OF_STREAM,
              "Sample flag mismatch: END_OF_STREAM");
static_assert(SAMPLE_FLAG_PARTIAL_FRAME == AMEDIACODEC_BUFFER_FLAG_PARTIAL_FRAME,
              "Sample flag mismatch: PARTIAL_FRAME");
}  // anonymous namespace

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
     * Byte buffer containing the sample's compressed data.
     * The memory backing this buffer is not managed by the MediaSample object so a separate
     * mechanism to release a buffer is needed between a producer and a consumer.
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
};

}  // namespace android
#endif  // ANDROID_MEDIA_SAMPLE_H
