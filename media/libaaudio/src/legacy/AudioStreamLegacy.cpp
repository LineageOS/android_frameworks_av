/*
 * Copyright 2017 The Android Open Source Project
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

#define LOG_TAG "AudioStreamLegacy"
//#define LOG_NDEBUG 0
#include <utils/Log.h>

#include <stdint.h>
#include <utils/String16.h>
#include <media/AudioTrack.h>
#include <aaudio/AAudio.h>

#include "core/AudioStream.h"
#include "legacy/AudioStreamLegacy.h"

using namespace android;
using namespace aaudio;

AudioStreamLegacy::AudioStreamLegacy()
        : AudioStream(), mDeviceCallback(new StreamDeviceCallback(this)) {
}

AudioStreamLegacy::~AudioStreamLegacy() {
}

// Called from AudioTrack.cpp or AudioRecord.cpp
static void AudioStreamLegacy_callback(int event, void* userData, void *info) {
    AudioStreamLegacy *streamLegacy = (AudioStreamLegacy *) userData;
    streamLegacy->processCallback(event, info);
}

aaudio_legacy_callback_t AudioStreamLegacy::getLegacyCallback() {
    return AudioStreamLegacy_callback;
}

// Implement FixedBlockProcessor
int32_t AudioStreamLegacy::onProcessFixedBlock(uint8_t *buffer, int32_t numBytes) {
    int32_t frameCount = numBytes / getBytesPerFrame();
    // Call using the AAudio callback interface.
    AAudioStream_dataCallback appCallback = getDataCallbackProc();
    return (*appCallback)(
            (AAudioStream *) this,
            getDataCallbackUserData(),
            buffer,
            frameCount);
}

void AudioStreamLegacy::processCallbackCommon(aaudio_callback_operation_t opcode, void *info) {
    aaudio_data_callback_result_t callbackResult;

    if (!mCallbackEnabled.load()) {
        return;
    }

    switch (opcode) {
        case AAUDIO_CALLBACK_OPERATION_PROCESS_DATA: {
            if (getState() != AAUDIO_STREAM_STATE_DISCONNECTED) {
                // Note that this code assumes an AudioTrack::Buffer is the same as
                // AudioRecord::Buffer
                // TODO define our own AudioBuffer and pass it from the subclasses.
                AudioTrack::Buffer *audioBuffer = static_cast<AudioTrack::Buffer *>(info);
                if (audioBuffer->frameCount == 0) return;

                // If the caller specified an exact size then use a block size adapter.
                if (mBlockAdapter != nullptr) {
                    int32_t byteCount = audioBuffer->frameCount * getBytesPerFrame();
                    callbackResult = mBlockAdapter->processVariableBlock(
                            (uint8_t *) audioBuffer->raw, byteCount);
                } else {
                    // Call using the AAudio callback interface.
                    callbackResult = (*getDataCallbackProc())(
                            (AAudioStream *) this,
                            getDataCallbackUserData(),
                            audioBuffer->raw,
                            audioBuffer->frameCount
                            );
                }
                if (callbackResult == AAUDIO_CALLBACK_RESULT_CONTINUE) {
                    audioBuffer->size = audioBuffer->frameCount * getBytesPerFrame();
                    incrementClientFrameCounter(audioBuffer->frameCount);
                } else {
                    audioBuffer->size = 0;
                }
                break;
            }
        }
        /// FALL THROUGH

            // Stream got rerouted so we disconnect.
        case AAUDIO_CALLBACK_OPERATION_DISCONNECTED: {
            setState(AAUDIO_STREAM_STATE_DISCONNECTED);
            ALOGD("processCallbackCommon() stream disconnected");
            if (getErrorCallbackProc() != nullptr) {
                (*getErrorCallbackProc())(
                        (AAudioStream *) this,
                        getErrorCallbackUserData(),
                        AAUDIO_ERROR_DISCONNECTED
                        );
            }
            mCallbackEnabled.store(false);
        }
            break;

        default:
            break;
    }
}

aaudio_result_t AudioStreamLegacy::getBestTimestamp(clockid_t clockId,
                                                   int64_t *framePosition,
                                                   int64_t *timeNanoseconds,
                                                   ExtendedTimestamp *extendedTimestamp) {
    int timebase;
    switch (clockId) {
        case CLOCK_BOOTTIME:
            timebase = ExtendedTimestamp::TIMEBASE_BOOTTIME;
            break;
        case CLOCK_MONOTONIC:
            timebase = ExtendedTimestamp::TIMEBASE_MONOTONIC;
            break;
        default:
            ALOGE("getTimestamp() - Unrecognized clock type %d", (int) clockId);
            return AAUDIO_ERROR_ILLEGAL_ARGUMENT;
            break;
    }
    status_t status = extendedTimestamp->getBestTimestamp(framePosition, timeNanoseconds, timebase);
    return AAudioConvert_androidToAAudioResult(status);
}

void AudioStreamLegacy::onAudioDeviceUpdate(audio_port_handle_t deviceId)
{
    ALOGD("onAudioDeviceUpdate() deviceId %d", (int)deviceId);
    if (getDeviceId() != AAUDIO_UNSPECIFIED && getDeviceId() != deviceId &&
            getState() != AAUDIO_STREAM_STATE_DISCONNECTED) {
        setState(AAUDIO_STREAM_STATE_DISCONNECTED);
        // if we have a data callback and the stream is active, send the error callback from
        // data callback thread when it sees the DISCONNECTED state
        if (!isDataCallbackActive() && getErrorCallbackProc() != nullptr) {
            (*getErrorCallbackProc())(
                    (AAudioStream *) this,
                    getErrorCallbackUserData(),
                    AAUDIO_ERROR_DISCONNECTED
                    );
        }
    }
    setDeviceId(deviceId);
}
