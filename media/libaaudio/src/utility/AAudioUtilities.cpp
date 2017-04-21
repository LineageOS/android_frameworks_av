/*
 * Copyright 2016 The Android Open Source Project
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

#define LOG_TAG "AAudio"
//#define LOG_NDEBUG 0
#include <utils/Log.h>

#include <stdint.h>
#include <sys/types.h>
#include <utils/Errors.h>

#include "aaudio/AAudio.h"
#include "AAudioUtilities.h"

using namespace android;

int32_t AAudioConvert_formatToSizeInBytes(aaudio_audio_format_t format) {
    int32_t size = AAUDIO_ERROR_ILLEGAL_ARGUMENT;
    switch (format) {
        case AAUDIO_FORMAT_PCM_I16:
            size = sizeof(int16_t);
            break;
        case AAUDIO_FORMAT_PCM_FLOAT:
            size = sizeof(float);
            break;
        default:
            break;
    }
    return size;
}

// TODO This similar to a function in audio_utils. Consider using that instead.
void AAudioConvert_floatToPcm16(const float *source, int32_t numSamples, int16_t *destination) {
    for (int i = 0; i < numSamples; i++) {
        float fval = source[i];
        fval += 1.0; // to avoid discontinuity at 0.0 caused by truncation
        fval *= 32768.0f;
        int32_t sample = (int32_t) fval;
        // clip to 16-bit range
        if (sample < 0) sample = 0;
        else if (sample > 0x0FFFF) sample = 0x0FFFF;
        sample -= 32768; // center at zero
        destination[i] = (int16_t) sample;
    }
}

void AAudioConvert_pcm16ToFloat(const int16_t *source, int32_t numSamples, float *destination) {
    for (int i = 0; i < numSamples; i++) {
        destination[i] = source[i] * (1.0f / 32768.0f);
    }
}

status_t AAudioConvert_aaudioToAndroidStatus(aaudio_result_t result) {
    // This covers the case for AAUDIO_OK and for positive results.
    if (result >= 0) {
        return result;
    }
    status_t status;
    switch (result) {
    case AAUDIO_ERROR_DISCONNECTED:
    case AAUDIO_ERROR_INVALID_HANDLE:
        status = DEAD_OBJECT;
        break;
    case AAUDIO_ERROR_INVALID_STATE:
        status = INVALID_OPERATION;
        break;
    case AAUDIO_ERROR_UNEXPECTED_VALUE: // TODO redundant?
    case AAUDIO_ERROR_INVALID_RATE:
    case AAUDIO_ERROR_INVALID_FORMAT:
    case AAUDIO_ERROR_ILLEGAL_ARGUMENT:
        status = BAD_VALUE;
        break;
    case AAUDIO_ERROR_WOULD_BLOCK:
        status = WOULD_BLOCK;
        break;
    // TODO add more result codes
    default:
        status = UNKNOWN_ERROR;
        break;
    }
    return status;
}

aaudio_result_t AAudioConvert_androidToAAudioResult(status_t status) {
    // This covers the case for OK and for positive result.
    if (status >= 0) {
        return status;
    }
    aaudio_result_t result;
    switch (status) {
    case BAD_TYPE:
        result = AAUDIO_ERROR_INVALID_HANDLE;
        break;
    case DEAD_OBJECT:
        result = AAUDIO_ERROR_NO_SERVICE;
        break;
    case INVALID_OPERATION:
        result = AAUDIO_ERROR_INVALID_STATE;
        break;
    case BAD_VALUE:
        result = AAUDIO_ERROR_UNEXPECTED_VALUE;
        break;
    case WOULD_BLOCK:
        result = AAUDIO_ERROR_WOULD_BLOCK;
        break;
    // TODO add more status codes
    default:
        result = AAUDIO_ERROR_INTERNAL;
        break;
    }
    return result;
}

audio_format_t AAudioConvert_aaudioToAndroidDataFormat(aaudio_audio_format_t aaudioFormat) {
    audio_format_t androidFormat;
    switch (aaudioFormat) {
    case AAUDIO_FORMAT_PCM_I16:
        androidFormat = AUDIO_FORMAT_PCM_16_BIT;
        break;
    case AAUDIO_FORMAT_PCM_FLOAT:
        androidFormat = AUDIO_FORMAT_PCM_FLOAT;
        break;
    default:
        androidFormat = AUDIO_FORMAT_DEFAULT;
        ALOGE("AAudioConvert_aaudioToAndroidDataFormat 0x%08X unrecognized", aaudioFormat);
        break;
    }
    return androidFormat;
}

aaudio_audio_format_t AAudioConvert_androidToAAudioDataFormat(audio_format_t androidFormat) {
    aaudio_audio_format_t aaudioFormat = AAUDIO_FORMAT_INVALID;
    switch (androidFormat) {
    case AUDIO_FORMAT_PCM_16_BIT:
        aaudioFormat = AAUDIO_FORMAT_PCM_I16;
        break;
    case AUDIO_FORMAT_PCM_FLOAT:
        aaudioFormat = AAUDIO_FORMAT_PCM_FLOAT;
        break;
    default:
        aaudioFormat = AAUDIO_FORMAT_INVALID;
        ALOGE("AAudioConvert_androidToAAudioDataFormat 0x%08X unrecognized", androidFormat);
        break;
    }
    return aaudioFormat;
}

int32_t AAudioConvert_framesToBytes(int32_t numFrames,
                                            int32_t bytesPerFrame,
                                            int32_t *sizeInBytes) {
    // TODO implement more elegantly
    const int32_t maxChannels = 256; // ridiculously large
    const int32_t maxBytesPerFrame = maxChannels * sizeof(float);
    // Prevent overflow by limiting multiplicands.
    if (bytesPerFrame > maxBytesPerFrame || numFrames > (0x3FFFFFFF / maxBytesPerFrame)) {
        ALOGE("size overflow, numFrames = %d, frameSize = %zd", numFrames, bytesPerFrame);
        return AAUDIO_ERROR_OUT_OF_RANGE;
    }
    *sizeInBytes = numFrames * bytesPerFrame;
    return AAUDIO_OK;
}
