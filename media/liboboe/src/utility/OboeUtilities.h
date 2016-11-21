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

#ifndef UTILITY_OBOEUTILITIES_H
#define UTILITY_OBOEUTILITIES_H

#include <stdint.h>
#include <sys/types.h>

#include <utils/Errors.h>
#include <hardware/audio.h>

#include "oboe/OboeDefinitions.h"

oboe_result_t OboeConvert_androidToOboeError(android::status_t error);

void OboeConvert_floatToPcm16(const float *source, int32_t numSamples, int16_t *destination);

void OboeConvert_pcm16ToFloat(const int16_t *source, int32_t numSamples, float *destination);

/**
 * Calculate the number of bytes and prevent numeric overflow.
 * @param numFrames frame count
 * @param bytesPerFrame size of a frame in bytes
 * @param sizeInBytes total size in bytes
 * @return OBOE_OK or negative error, eg. OBOE_ERROR_OUT_OF_RANGE
 */
oboe_size_bytes_t OboeConvert_framesToBytes(oboe_size_frames_t numFrames,
                                            oboe_size_bytes_t bytesPerFrame,
                                            oboe_size_bytes_t *sizeInBytes);

audio_format_t OboeConvert_oboeToAndroidDataFormat(oboe_audio_format_t oboe_format);

oboe_audio_format_t OboeConvert_androidToOboeDataFormat(audio_format_t format);

/**
 * @return the size of a sample of the given format in bytes or OBOE_ERROR_ILLEGAL_ARGUMENT
 */
oboe_size_bytes_t OboeConvert_formatToSizeInBytes(oboe_audio_format_t format);

#endif //UTILITY_OBOEUTILITIES_H
