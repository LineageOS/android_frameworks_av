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

#define LOG_TAG "OboeAudio"
//#define LOG_NDEBUG 0
#include <utils/Log.h>

#include <stdint.h>
#include <sys/types.h>
#include <utils/Errors.h>

#include "oboe/OboeDefinitions.h"
#include "OboeUtilities.h"

using namespace android;

oboe_size_bytes_t OboeConvert_formatToSizeInBytes(oboe_audio_format_t format) {
    oboe_datatype_t dataType = OBOE_AUDIO_FORMAT_DATA_TYPE(format);
    oboe_size_bytes_t size;
    switch (dataType) {
        case OBOE_AUDIO_DATATYPE_UINT8:
            size = sizeof(uint8_t);
            break;
        case OBOE_AUDIO_DATATYPE_INT16:
            size = sizeof(int16_t);
            break;
        case OBOE_AUDIO_DATATYPE_INT32:
        case OBOE_AUDIO_DATATYPE_INT824:
            size = sizeof(int32_t);
            break;
        case OBOE_AUDIO_DATATYPE_FLOAT32:
            size = sizeof(float);
            break;
        default:
            size = OBOE_ERROR_ILLEGAL_ARGUMENT;
            break;
    }
    return size;
}

// TODO This similar to a function in audio_utils. Consider using that instead.
void OboeConvert_floatToPcm16(const float *source, int32_t numSamples, int16_t *destination) {
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

void OboeConvert_pcm16ToFloat(const float *source, int32_t numSamples, int16_t *destination) {
    for (int i = 0; i < numSamples; i++) {
        destination[i] = source[i] * (1.0f / 32768.0f);
    }
}

oboe_result_t OboeConvert_androidToOboeError(status_t error) {
    if (error >= 0) {
        return error;
    }
    oboe_result_t result;
    switch (error) {
    case OK:
        result = OBOE_OK;
        break;
    case INVALID_OPERATION:
        result = OBOE_ERROR_INVALID_STATE;
        break;
    case BAD_VALUE:
        result = OBOE_ERROR_UNEXPECTED_VALUE;
        break;
    case WOULD_BLOCK:
        result = OBOE_ERROR_WOULD_BLOCK;
        break;
    // TODO add more error codes
    default:
        result = OBOE_ERROR_INTERNAL;
        break;
    }
    return result;
}

audio_format_t OboeConvert_oboeToAndroidDataFormat(oboe_audio_format_t oboeFormat) {
    audio_format_t androidFormat;
    switch (oboeFormat) {
    case OBOE_AUDIO_FORMAT_PCM16:
        androidFormat = AUDIO_FORMAT_PCM_16_BIT;
        break;
    case OBOE_AUDIO_FORMAT_PCM_FLOAT:
        androidFormat = AUDIO_FORMAT_PCM_FLOAT;
        break;
    case OBOE_AUDIO_FORMAT_PCM824:
        androidFormat = AUDIO_FORMAT_PCM_8_24_BIT;
        break;
    case OBOE_AUDIO_FORMAT_PCM32:
        androidFormat = AUDIO_FORMAT_PCM_32_BIT;
        break;
    default:
        androidFormat = AUDIO_FORMAT_DEFAULT;
        ALOGE("OboeConvert_oboeToAndroidDataFormat 0x%08X unrecognized", oboeFormat);
        break;
    }
    return androidFormat;
}

oboe_audio_format_t OboeConvert_androidToOboeDataFormat(audio_format_t androidFormat) {
    oboe_audio_format_t oboeFormat = OBOE_AUDIO_FORMAT_INVALID;
    switch (androidFormat) {
    case AUDIO_FORMAT_PCM_16_BIT:
        oboeFormat = OBOE_AUDIO_FORMAT_PCM16;
        break;
    case AUDIO_FORMAT_PCM_FLOAT:
        oboeFormat = OBOE_AUDIO_FORMAT_PCM_FLOAT;
        break;
    case AUDIO_FORMAT_PCM_32_BIT:
        oboeFormat = OBOE_AUDIO_FORMAT_PCM32;
        break;
    case AUDIO_FORMAT_PCM_8_24_BIT:
        oboeFormat = OBOE_AUDIO_FORMAT_PCM824;
        break;
    default:
        oboeFormat = OBOE_AUDIO_FORMAT_INVALID;
        ALOGE("OboeConvert_androidToOboeDataFormat 0x%08X unrecognized", androidFormat);
        break;
    }
    return oboeFormat;
}

oboe_size_bytes_t OboeConvert_framesToBytes(oboe_size_frames_t numFrames,
                                            oboe_size_bytes_t bytesPerFrame,
                                            oboe_size_bytes_t *sizeInBytes) {
    // TODO implement more elegantly
    const int32_t maxChannels = 256; // ridiculously large
    const oboe_size_frames_t maxBytesPerFrame = maxChannels * sizeof(float);
    // Prevent overflow by limiting multiplicands.
    if (bytesPerFrame > maxBytesPerFrame || numFrames > (0x3FFFFFFF / maxBytesPerFrame)) {
        ALOGE("size overflow, numFrames = %d, frameSize = %zd", numFrames, bytesPerFrame);
        return OBOE_ERROR_OUT_OF_RANGE;
    }
    *sizeInBytes = numFrames * bytesPerFrame;
    return OBOE_OK;
}
