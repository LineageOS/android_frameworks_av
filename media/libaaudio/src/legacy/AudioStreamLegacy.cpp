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

#include "AudioStreamLegacy.h"

// go/keep-sorted start
#include <aaudio/AAudio.h>
#include <android_media_audio.h>
#include <audio_utils/primitives.h>
#include <core/AudioStream.h>
#include <media/AudioTimestamp.h>
#include <media/AudioTrack.h>
#include <utility/AudioGlobal.h>
#include <utils/Log.h>
#include <utils/String16.h>
// go/keep-sorted end

#include <stdint.h>

using namespace android;
using namespace aaudio;

AudioStreamLegacy::AudioStreamLegacy()
        : AudioStream() {
}


int32_t AudioStreamLegacy::callDataCallbackFrames(uint8_t *buffer, int32_t numFrames) {
    void *finalAudioData = buffer;
    if (getDirection() == AAUDIO_DIRECTION_INPUT) {
        finalAudioData = (void *) maybeConvertDeviceData(buffer, numFrames);
    }

    // Call using the AAudio callback interface.
    int32_t callbackResult = maybeCallDataCallback(finalAudioData, numFrames);

    if (callbackResult >= 0) {
        if (getDirection() == AAUDIO_DIRECTION_OUTPUT) {
            // Increment after because we are going to write the data to the device.
            incrementFramesWritten(callbackResult);
        } else {
            incrementFramesRead(callbackResult);
        }
    }
    return callbackResult;
}

// Implement FixedBlockProcessor
int32_t AudioStreamLegacy::onProcessFixedBlock(uint8_t *buffer, int32_t numBytes) {
    int32_t numFrames = numBytes / mBlockAdapterBytesPerFrame;
    return callDataCallbackFrames(buffer, numFrames) * mBlockAdapterBytesPerFrame;
}


void AudioStreamLegacy::onNewIAudioTrack() {
    ALOGD("%s stream disconnected", __func__);
    forceDisconnect();
    mCallbackEnabled.store(false);
}

size_t AudioStreamLegacy::onMoreData(const android::AudioTrack::Buffer& buffer) {
    // This illegal size can be used to tell AudioRecord or AudioTrack to stop calling us.
    // This takes advantage of them killing the stream when they see a size out of range.
    // That is an undocumented behavior.
    // TODO add to API in AudioRecord and AudioTrack
    // TODO(b/216175830) cleanup size re-computation
    const size_t SIZE_STOP_CALLBACKS = SIZE_MAX;
    aaudio_data_callback_result_t callbackResult = AAUDIO_CALLBACK_RESULT_CONTINUE;
    (void) checkForDisconnectRequest(true);

    // Note that this code assumes an AudioTrack::Buffer is the same as
    // AudioRecord::Buffer
    // TODO define our own AudioBuffer and pass it from the subclasses.
    size_t written = buffer.size();
    if (isDisconnected()) {
        ALOGW("%s() data, stream disconnected", __func__);
        // This will kill the stream and prevent it from being restarted.
        // That is OK because the stream is disconnected.
        written = SIZE_STOP_CALLBACKS;
    } else if (!mCallbackEnabled.load()) {
        ALOGW("%s() no data because callback disabled, set size=0", __func__);
        // Do NOT use SIZE_STOP_CALLBACKS here because that will kill the stream and
        // prevent it from being restarted. This can occur because of a race condition
        // caused by Legacy callbacks running after the track is "stopped".
        written = 0;
    } else {
        if (buffer.getFrameCount() == 0) {
            ALOGW("%s() data, frameCount is zero", __func__);
            return written;
        }

        // If the caller specified an exact size then use a block size adapter.
        if (mBlockAdapter != nullptr) {
            int32_t byteCount = buffer.getFrameCount() * getBytesPerDeviceFrame();
            std::tie(callbackResult, written) = mBlockAdapter->processVariableBlock(
                    buffer.data(), byteCount);
        } else {
            // Call using the AAudio callback interface.
            const int32_t framesProcessed = callDataCallbackFrames(
                    buffer.data(), buffer.getFrameCount());
            if (framesProcessed < 0) {
                written = 0;
                callbackResult = AAUDIO_CALLBACK_RESULT_STOP;
            } else {
                written = framesProcessed * getBytesPerDeviceFrame();
                callbackResult = AAUDIO_CALLBACK_RESULT_CONTINUE;
            }
        }

        if (callbackResult == AAUDIO_CALLBACK_RESULT_STOP) {
            ALOGD("%s() callback requested to stop", __func__);
            if (shouldStopStream()) {
                // If the callback result is STOP, stop the stream if it should be stopped.
                // Currently, the framework will not call stop if the client is doing offload
                // playback and waiting for stream end. The client will already be STOPPING
                // state when waiting for stream end.
                systemStopInternal();
                // Disable the callback just in case the system keeps trying to call us.
                mCallbackEnabled.store(false);
            }
        }

        if (processCommands() != AAUDIO_OK) {
            forceDisconnect();
            mCallbackEnabled.store(false);
        }
    }
    return written;
}

// TODO (b/216175830) this method is duplicated in order to ease refactoring which will
// reconsolidate.
size_t AudioStreamLegacy::onMoreData(const android::AudioRecord::Buffer& buffer) {
    // This illegal size can be used to tell AudioRecord or AudioTrack to stop calling us.
    // This takes advantage of them killing the stream when they see a size out of range.
    // That is an undocumented behavior.
    // TODO add to API in AudioRecord and AudioTrack
    const size_t SIZE_STOP_CALLBACKS = SIZE_MAX;
    aaudio_data_callback_result_t callbackResult = AAUDIO_CALLBACK_RESULT_CONTINUE;
    (void) checkForDisconnectRequest(true);

    // Note that this code assumes an AudioTrack::Buffer is the same as
    // AudioRecord::Buffer
    // TODO define our own AudioBuffer and pass it from the subclasses.
    size_t written = buffer.size();
    if (isDisconnected()) {
        ALOGW("%s() data, stream disconnected", __func__);
        // This will kill the stream and prevent it from being restarted.
        // That is OK because the stream is disconnected.
        written = SIZE_STOP_CALLBACKS;
    } else if (!mCallbackEnabled.load()) {
        ALOGW("%s() no data because callback disabled, set size=0", __func__);
        // Do NOT use SIZE_STOP_CALLBACKS here because that will kill the stream and
        // prevent it from being restarted. This can occur because of a race condition
        // caused by Legacy callbacks running after the track is "stopped".
        written = 0;
    } else {
        if (buffer.getFrameCount() == 0) {
            ALOGW("%s() data, frameCount is zero", __func__);
            return written;
        }

        // If the caller specified an exact size then use a block size adapter.
        if (mBlockAdapter != nullptr) {
            int32_t byteCount = buffer.getFrameCount() * getBytesPerDeviceFrame();
            std::tie(callbackResult, written) = mBlockAdapter->processVariableBlock(
                    buffer.data(), byteCount);
        } else {
            // Call using the AAudio callback interface.
            const int framesProcessed = callDataCallbackFrames(
                    buffer.data(), buffer.getFrameCount());
            if (framesProcessed < 0) {
                written = 0;
                callbackResult = AAUDIO_CALLBACK_RESULT_STOP;
            } else {
                written = framesProcessed * getBytesPerDeviceFrame();
                callbackResult = AAUDIO_CALLBACK_RESULT_CONTINUE;
            }
        }
        if (callbackResult == AAUDIO_CALLBACK_RESULT_STOP) {
            ALOGD("%s() callback requested to stop", __func__);
            // Always stop the recording case if callback result is not CONTINUE.
            systemStopInternal();
            // Disable the callback just in case the system keeps trying to call us.
            mCallbackEnabled.store(false);
        }

        if (processCommands() != AAUDIO_OK) {
            forceDisconnect();
            mCallbackEnabled.store(false);
        }
    }
    return written;
}

aaudio_result_t AudioStreamLegacy::checkForDisconnectRequest(bool errorCallbackEnabled) {
    if (mRequestDisconnect.isRequested()) {
        ALOGD("checkForDisconnectRequest() mRequestDisconnect acknowledged");
        forceDisconnect(errorCallbackEnabled);
        mRequestDisconnect.acknowledge();
        mCallbackEnabled.store(false);
        return AAUDIO_ERROR_DISCONNECTED;
    } else {
        return AAUDIO_OK;
    }
}

void AudioStreamLegacy::forceDisconnect(bool errorCallbackEnabled) {
    // There is no need to disconnect if already in these states.
    if (!isDisconnected()
            && getState() != AAUDIO_STREAM_STATE_CLOSING
            && getState() != AAUDIO_STREAM_STATE_CLOSED
            ) {
        setDisconnected();
        if (errorCallbackEnabled) {
            maybeCallErrorCallback(AAUDIO_ERROR_DISCONNECTED);
        }
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
    ExtendedTimestamp::Location location = ExtendedTimestamp::Location::LOCATION_INVALID;
    int64_t localPosition;
    status_t status = extendedTimestamp->getBestTimestamp(&localPosition, timeNanoseconds,
                                                          timebase, &location);
    if (status == OK) {
        // use MonotonicCounter to prevent retrograde motion.
        mTimestampPosition.update32((int32_t) localPosition);
        *framePosition = mTimestampPosition.get();
    }

//    ALOGD("getBestTimestamp() fposition: server = %6lld, kernel = %6lld, location = %d",
//          (long long) extendedTimestamp->mPosition[ExtendedTimestamp::Location::LOCATION_SERVER],
//          (long long) extendedTimestamp->mPosition[ExtendedTimestamp::Location::LOCATION_KERNEL],
//          (int)location);
    return AAudioConvert_androidToAAudioResult(status);
}

void AudioStreamLegacy::onAudioDeviceUpdate(audio_io_handle_t /* audioIo */,
            const android::DeviceIdVector& deviceIds) {
    // Check for empty deviceIds. Callbacks for duplicating threads returns empty devices.
    if (deviceIds.empty()) {
        ALOGW("%s(empty deviceIds", __func__);
        return;
    }
    android::DeviceIdVector oldDeviceIds = getDeviceIds();
    // Device routing is a common source of errors and DISCONNECTS.
    // Please leave this log in place. If there is a bug then this might
    // get called after the stream has been deleted so log before we
    // touch the stream object.
    ALOGD("%s() devices %s => %s",
            __func__, android::toString(oldDeviceIds).c_str(),
            android::toString(deviceIds).c_str());
    if (android::areDeviceIdsEqual(oldDeviceIds, deviceIds)) {
        ALOGD("%s, ignore device update as it is the same as the old one", __func__);
        return;
    }
    if (!android_media_audio_partial_flush_for_pcm_offload()
            && !oldDeviceIds.empty()
            && !android::areDeviceIdsEqual(oldDeviceIds, deviceIds)
            && !isDisconnected()
            ) {
        // Note that isDataCallbackActive() is affected by state so call it before DISCONNECTING.
        // If we have a data callback and the stream is active, then ask the data callback
        // to DISCONNECT and call the error callback.
        if (isDataCallbackActive()) {
            ALOGD("%s() request DISCONNECT in data callback, devices %s => %s",
                    __func__, android::toString(oldDeviceIds).c_str(),
                    android::toString(deviceIds).c_str());
            // If the stream is stopped before the data callback has a chance to handle the
            // request then the requestStop_l() and requestPause() methods will handle it after
            // the callback has stopped.
            mRequestDisconnect.request();
        } else {
            ALOGD("%s() DISCONNECT the stream now, devices %s => %s",
                    __func__, android::toString(oldDeviceIds).c_str(),
                    android::toString(deviceIds).c_str());
            forceDisconnect();
        }
    }
    setDeviceIds(deviceIds);
    if (!isDisconnected() && getState() != AAUDIO_STREAM_STATE_CLOSING &&
        getState() != AAUDIO_STREAM_STATE_CLOSED) {
        maybeSignalRoutingChangedCallback();
    }
}
