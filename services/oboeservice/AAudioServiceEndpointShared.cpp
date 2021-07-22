/*
 * Copyright (C) 2017 The Android Open Source Project
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


#define LOG_TAG "AAudioServiceEndpointShared"
//#define LOG_NDEBUG 0
#include <utils/Log.h>

#include <iomanip>
#include <iostream>
#include <sstream>

#include "binding/AAudioServiceMessage.h"
#include "client/AudioStreamInternal.h"
#include "client/AudioStreamInternalPlay.h"
#include "core/AudioStreamBuilder.h"

#include "AAudioServiceEndpointShared.h"
#include "AAudioServiceStreamShared.h"
#include "AAudioServiceStreamMMAP.h"
#include "AAudioMixer.h"
#include "AAudioService.h"

using namespace android;
using namespace aaudio;

// This is the maximum size in frames. The effective size can be tuned smaller at runtime.
#define DEFAULT_BUFFER_CAPACITY   (48 * 8)

AAudioServiceEndpointShared::AAudioServiceEndpointShared(AudioStreamInternal *streamInternal)
    : mStreamInternal(streamInternal) {}

std::string AAudioServiceEndpointShared::dump() const {
    std::stringstream result;

    result << "  SHARED: sharing exclusive stream with handle = 0x"
           << std::setfill('0') << std::setw(8)
           << std::hex << mStreamInternal->getServiceHandle()
           << std::dec << std::setfill(' ');
    result << ", XRuns = " << mStreamInternal->getXRunCount();
    result << "\n";
    result << "    Running Stream Count: " << mRunningStreamCount << "\n";

    result << AAudioServiceEndpoint::dump();
    return result.str();
}

// Share an AudioStreamInternal.
aaudio_result_t AAudioServiceEndpointShared::open(const aaudio::AAudioStreamRequest &request) {
    aaudio_result_t result = AAUDIO_OK;
    const AAudioStreamConfiguration &configuration = request.getConstantConfiguration();

    copyFrom(configuration);
    mRequestedDeviceId = configuration.getDeviceId();

    AudioStreamBuilder builder;
    builder.copyFrom(configuration);

    builder.setSharingMode(AAUDIO_SHARING_MODE_EXCLUSIVE);
    // Don't fall back to SHARED because that would cause recursion.
    builder.setSharingModeMatchRequired(true);

    builder.setBufferCapacity(DEFAULT_BUFFER_CAPACITY);

    result = mStreamInternal->open(builder);

    setSampleRate(mStreamInternal->getSampleRate());
    setChannelMask(mStreamInternal->getChannelMask());
    setDeviceId(mStreamInternal->getDeviceId());
    setSessionId(mStreamInternal->getSessionId());
    setFormat(AUDIO_FORMAT_PCM_FLOAT); // force for mixer
    mFramesPerBurst = mStreamInternal->getFramesPerBurst();

    return result;
}

void AAudioServiceEndpointShared::close() {
    stopSharingThread();
    getStreamInternal()->safeReleaseClose();
}

// Glue between C and C++ callbacks.
static void *aaudio_endpoint_thread_proc(void *arg) {
    assert(arg != nullptr);
    ALOGD("%s() called", __func__);

    // Prevent the stream from being deleted while being used.
    // This is just for extra safety. It is probably not needed because
    // this callback should be joined before the stream is closed.
    AAudioServiceEndpointShared *endpointPtr =
        static_cast<AAudioServiceEndpointShared *>(arg);
    android::sp<AAudioServiceEndpointShared> endpoint(endpointPtr);
    // Balance the incStrong() in startSharingThread_l().
    endpoint->decStrong(nullptr);

    void *result = endpoint->callbackLoop();
    // Close now so that the HW resource is freed and we can open a new device.
    if (!endpoint->isConnected()) {
        ALOGD("%s() call safeReleaseCloseFromCallback()", __func__);
        // Release and close under a lock with no check for callback collisions.
        endpoint->getStreamInternal()->safeReleaseCloseInternal();
    }

    return result;
}

aaudio_result_t aaudio::AAudioServiceEndpointShared::startSharingThread_l() {
    // Launch the callback loop thread.
    int64_t periodNanos = getStreamInternal()->getFramesPerBurst()
                          * AAUDIO_NANOS_PER_SECOND
                          / getSampleRate();
    mCallbackEnabled.store(true);
    // Prevent this object from getting deleted before the thread has a chance to create
    // its strong pointer. Assume the thread will call decStrong().
    this->incStrong(nullptr);
    aaudio_result_t result = getStreamInternal()->createThread(periodNanos,
                                                               aaudio_endpoint_thread_proc,
                                                               this);
    if (result != AAUDIO_OK) {
        this->decStrong(nullptr); // Because the thread won't do it.
    }
    return result;
}

aaudio_result_t aaudio::AAudioServiceEndpointShared::stopSharingThread() {
    mCallbackEnabled.store(false);
    return getStreamInternal()->joinThread(NULL);
}

aaudio_result_t AAudioServiceEndpointShared::startStream(
        sp<AAudioServiceStreamBase> sharedStream,
        audio_port_handle_t *clientHandle)
        NO_THREAD_SAFETY_ANALYSIS {
    aaudio_result_t result = AAUDIO_OK;

    {
        std::lock_guard<std::mutex> lock(mLockStreams);
        if (++mRunningStreamCount == 1) { // atomic
            result = getStreamInternal()->systemStart();
            if (result != AAUDIO_OK) {
                --mRunningStreamCount;
            } else {
                result = startSharingThread_l();
                if (result != AAUDIO_OK) {
                    getStreamInternal()->systemStopFromApp();
                    --mRunningStreamCount;
                }
            }
        }
    }

    if (result == AAUDIO_OK) {
        const audio_attributes_t attr = getAudioAttributesFrom(sharedStream.get());
        result = getStreamInternal()->startClient(
                sharedStream->getAudioClient(), &attr, clientHandle);
        if (result != AAUDIO_OK) {
            if (--mRunningStreamCount == 0) { // atomic
                stopSharingThread();
                getStreamInternal()->systemStopFromApp();
            }
        }
    }

    return result;
}

aaudio_result_t AAudioServiceEndpointShared::stopStream(sp<AAudioServiceStreamBase> sharedStream,
                                                        audio_port_handle_t clientHandle) {
    // Ignore result.
    (void) getStreamInternal()->stopClient(clientHandle);

    if (--mRunningStreamCount == 0) { // atomic
        stopSharingThread(); // the sharing thread locks mLockStreams
        getStreamInternal()->systemStopFromApp();
    }
    return AAUDIO_OK;
}

// Get timestamp that was written by the real-time service thread, eg. mixer.
aaudio_result_t AAudioServiceEndpointShared::getFreeRunningPosition(int64_t *positionFrames,
                                                                  int64_t *timeNanos) {
    if (mAtomicEndpointTimestamp.isValid()) {
        Timestamp timestamp = mAtomicEndpointTimestamp.read();
        *positionFrames = timestamp.getPosition();
        *timeNanos = timestamp.getNanoseconds();
        return AAUDIO_OK;
    } else {
        return AAUDIO_ERROR_UNAVAILABLE;
    }
}

aaudio_result_t AAudioServiceEndpointShared::getTimestamp(int64_t *positionFrames,
                                                          int64_t *timeNanos) {
    aaudio_result_t result = mStreamInternal->getTimestamp(CLOCK_MONOTONIC, positionFrames, timeNanos);
    if (result == AAUDIO_ERROR_INVALID_STATE) {
        // getTimestamp() can return AAUDIO_ERROR_INVALID_STATE if the stream has
        // not completely started. This can cause a race condition that kills the
        // timestamp service thread.  So we reduce the error to a less serious one
        // that allows the timestamp thread to continue.
        result = AAUDIO_ERROR_UNAVAILABLE;
    }
    return result;
}
