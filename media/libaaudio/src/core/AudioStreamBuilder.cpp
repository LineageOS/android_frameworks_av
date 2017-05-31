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
#include <aaudio/AAudioTesting.h>

#include "binding/AAudioBinderClient.h"
#include "client/AudioStreamInternalCapture.h"
#include "client/AudioStreamInternalPlay.h"
#include "core/AudioStream.h"
#include "core/AudioStreamBuilder.h"
#include "legacy/AudioStreamRecord.h"
#include "legacy/AudioStreamTrack.h"

using namespace aaudio;

#define AAUDIO_MMAP_POLICY_DEFAULT             AAUDIO_POLICY_NEVER
#define AAUDIO_MMAP_EXCLUSIVE_POLICY_DEFAULT   AAUDIO_POLICY_NEVER

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
            if (tryMMap) {
                *audioStreamPtr = new AudioStreamInternalCapture(AAudioBinderClient::getInstance(),
                                                                 false);
            } else {
                *audioStreamPtr = new AudioStreamRecord();
            }
            break;

        case AAUDIO_DIRECTION_OUTPUT:
            if (tryMMap) {
                *audioStreamPtr = new AudioStreamInternalPlay(AAudioBinderClient::getInstance(),
                                                              false);
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

// Try to open using MMAP path if that is allowed.
// Fall back to Legacy path if MMAP not available.
// Exact behavior is controlled by MMapPolicy.
aaudio_result_t AudioStreamBuilder::build(AudioStream** streamPtr) {
    AudioStream *audioStream = nullptr;
    *streamPtr = nullptr;

    // The API setting is the highest priority.
    aaudio_policy_t mmapPolicy = AAudio_getMMapPolicy();
    // If not specified then get from a system property.
    if (mmapPolicy == AAUDIO_UNSPECIFIED) {
        mmapPolicy = AAudioProperty_getMMapPolicy();
    }
    // If still not specified then use the default.
    if (mmapPolicy == AAUDIO_UNSPECIFIED) {
        mmapPolicy = AAUDIO_MMAP_POLICY_DEFAULT;
    }

    int32_t mapExclusivePolicy = AAudioProperty_getMMapExclusivePolicy();
    if (mapExclusivePolicy == AAUDIO_UNSPECIFIED) {
        mapExclusivePolicy = AAUDIO_MMAP_EXCLUSIVE_POLICY_DEFAULT;
    }
    ALOGD("AudioStreamBuilder(): mmapPolicy = %d, mapExclusivePolicy = %d",
          mmapPolicy, mapExclusivePolicy);

    aaudio_sharing_mode_t sharingMode = getSharingMode();
    if ((sharingMode == AAUDIO_SHARING_MODE_EXCLUSIVE)
        && (mapExclusivePolicy == AAUDIO_POLICY_NEVER)) {
        ALOGW("AudioStreamBuilder(): EXCLUSIVE sharing mode not supported. Use SHARED.");
        sharingMode = AAUDIO_SHARING_MODE_SHARED;
        setSharingMode(sharingMode);
    }

    bool allowMMap = mmapPolicy != AAUDIO_POLICY_NEVER;
    bool allowLegacy = mmapPolicy != AAUDIO_POLICY_ALWAYS;

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

    return result;
}
