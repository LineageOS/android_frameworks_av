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

#ifndef UTILITY_AAUDIO_UTILITIES_H
#define UTILITY_AAUDIO_UTILITIES_H

#include <stdint.h>
#include <sys/types.h>

#include <utils/Errors.h>
#include <hardware/audio.h>

#include "aaudio/AAudio.h"

/**
 * Convert an AAudio result into the closest matching Android status.
 */
android::status_t AAudioConvert_aaudioToAndroidStatus(aaudio_result_t result);

/**
 * Convert an Android status into the closest matching AAudio result.
 */
aaudio_result_t AAudioConvert_androidToAAudioResult(android::status_t status);

void AAudioConvert_floatToPcm16(const float *source, int32_t numSamples, int16_t *destination);

void AAudioConvert_pcm16ToFloat(const int16_t *source, int32_t numSamples, float *destination);

/**
 * Calculate the number of bytes and prevent numeric overflow.
 * @param numFrames frame count
 * @param bytesPerFrame size of a frame in bytes
 * @param sizeInBytes total size in bytes
 * @return AAUDIO_OK or negative error, eg. AAUDIO_ERROR_OUT_OF_RANGE
 */
int32_t AAudioConvert_framesToBytes(int32_t numFrames,
                                            int32_t bytesPerFrame,
                                            int32_t *sizeInBytes);

audio_format_t AAudioConvert_aaudioToAndroidDataFormat(aaudio_audio_format_t aaudio_format);

aaudio_audio_format_t AAudioConvert_androidToAAudioDataFormat(audio_format_t format);

/**
 * @return the size of a sample of the given format in bytes or AAUDIO_ERROR_ILLEGAL_ARGUMENT
 */
int32_t AAudioConvert_formatToSizeInBytes(aaudio_audio_format_t format);

#endif //UTILITY_AAUDIO_UTILITIES_H
