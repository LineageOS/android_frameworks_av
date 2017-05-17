/*
 * Copyright 2015 The Android Open Source Project
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

#include <new>
#include <stdint.h>

#include <aaudio/AAudio.h>

#include "binding/AAudioBinderClient.h"
#include "client/AudioStreamInternal.h"
#include "core/AudioStream.h"
#include "core/AudioStreamBuilder.h"
#include "legacy/AudioStreamRecord.h"
#include "legacy/AudioStreamTrack.h"

using namespace aaudio;

/*
 * AudioStreamBuilder
 */
AudioStreamBuilder::AudioStreamBuilder() {
}

AudioStreamBuilder::~AudioStreamBuilder() {
}

static aaudio_result_t builder_createStream(aaudio_direction_t direction,
                                         aaudio_sharing_mode_t sharingMode,
                                         bool tryMMap,
                                         AudioStream **audioStreamPtr) {
    *audioStreamPtr = nullptr;
    aaudio_result_t result = AAUDIO_OK;

    switch (direction) {

        case AAUDIO_DIRECTION_INPUT:
            if (sharingMode == AAUDIO_SHARING_MODE_SHARED) {
                *audioStreamPtr = new AudioStreamRecord();
            } else {
                ALOGE("AudioStreamBuilder(): bad sharing mode = %d for input", sharingMode);
                result = AAUDIO_ERROR_ILLEGAL_ARGUMENT;
            }
            break;

        case AAUDIO_DIRECTION_OUTPUT:
            if (tryMMap) {
                *audioStreamPtr = new AudioStreamInternal(AAudioBinderClient::getInstance(), false);
            } else {
                *audioStreamPtr = new AudioStreamTrack();
            }
            break;

        default:
            ALOGE("AudioStreamBuilder(): bad direction = %d", direction);
            result = AAUDIO_ERROR_ILLEGAL_ARGUMENT;
    }
    return result;
}

// Try to open using MMAP path if that is enabled.
// Fall back to Legacy path is MMAP not available.
aaudio_result_t AudioStreamBuilder::build(AudioStream** streamPtr) {
    AudioStream *audioStream = nullptr;
    *streamPtr = nullptr;

    int32_t mmapEnabled = AAudioProperty_getMMapEnabled();
    int32_t mmapExclusiveEnabled = AAudioProperty_getMMapExclusiveEnabled();
    ALOGD("AudioStreamBuilder(): mmapEnabled = %d, mmapExclusiveEnabled = %d",
          mmapEnabled, mmapExclusiveEnabled);

    aaudio_sharing_mode_t sharingMode = getSharingMode();
    if ((sharingMode == AAUDIO_SHARING_MODE_EXCLUSIVE)
        && (mmapExclusiveEnabled == AAUDIO_USE_NEVER)) {
        ALOGW("AudioStreamBuilder(): EXCLUSIVE sharing mode not supported. Use SHARED.");
        sharingMode = AAUDIO_SHARING_MODE_SHARED;
        setSharingMode(sharingMode);
    }

    bool allowMMap = mmapEnabled != AAUDIO_USE_NEVER;
    bool allowLegacy = mmapEnabled != AAUDIO_USE_ALWAYS;

    aaudio_result_t result = builder_createStream(getDirection(), sharingMode,
                                                  allowMMap, &audioStream);
    if (result == AAUDIO_OK) {
        // Open the stream using the parameters from the builder.
        result = audioStream->open(*this);
        if (result == AAUDIO_OK) {
            *streamPtr = audioStream;
        } else {
            bool isMMap = audioStream->isMMap();
            delete audioStream;
            audioStream = nullptr;

            if (isMMap && allowLegacy) {
                ALOGD("AudioStreamBuilder.build() MMAP stream did not open so try Legacy path");
                // If MMAP stream failed to open then TRY using a legacy stream.
                result = builder_createStream(getDirection(), sharingMode,
                                              false, &audioStream);
                if (result == AAUDIO_OK) {
                    result = audioStream->open(*this);
                    if (result == AAUDIO_OK) {
                        *streamPtr = audioStream;
                    } else {
                        delete audioStream;
                    }
                }
            }
        }
    }

    ALOGD("AudioStreamBuilder(): returned %d", result);
    return result;
}
