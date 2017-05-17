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

#define LOG_TAG "AAudioService"
//#define LOG_NDEBUG 0
#include <utils/Log.h>

#include <assert.h>
#include <map>
#include <mutex>
#include <utils/Singleton.h>

#include "AAudioEndpointManager.h"
#include "AAudioServiceEndpoint.h"
#include <algorithm>
#include <mutex>
#include <vector>

#include "core/AudioStreamBuilder.h"
#include "AAudioServiceEndpoint.h"
#include "AAudioServiceStreamShared.h"

using namespace android;  // TODO just import names needed
using namespace aaudio;   // TODO just import names needed

#define MIN_TIMEOUT_NANOS        (1000 * AAUDIO_NANOS_PER_MILLISECOND)

// Wait at least this many times longer than the operation should take.
#define MIN_TIMEOUT_OPERATIONS    4

// This is the maximum size in frames. The effective size can be tuned smaller at runtime.
#define DEFAULT_BUFFER_CAPACITY   (48 * 8)

// The mStreamInternal will use a service interface that does not go through Binder.
AAudioServiceEndpoint::AAudioServiceEndpoint(AAudioService &audioService)
        : mStreamInternal(audioService, true)
        {
}

AAudioServiceEndpoint::~AAudioServiceEndpoint() {
}

// Set up an EXCLUSIVE MMAP stream that will be shared.
aaudio_result_t AAudioServiceEndpoint::open(int32_t deviceId, aaudio_direction_t direction) {
    AudioStreamBuilder builder;
    builder.setSharingMode(AAUDIO_SHARING_MODE_EXCLUSIVE);
    // Don't fall back to SHARED because that would cause recursion.
    builder.setSharingModeMatchRequired(true);
    builder.setDeviceId(deviceId);
    builder.setDirection(direction);
    builder.setBufferCapacity(DEFAULT_BUFFER_CAPACITY);

    aaudio_result_t result = mStreamInternal.open(builder);
    if (result == AAUDIO_OK) {
        mMixer.allocate(mStreamInternal.getSamplesPerFrame(), mStreamInternal.getFramesPerBurst());

        int32_t burstsPerBuffer = AAudioProperty_getMixerBursts();
        if (burstsPerBuffer == 0) {
            mLatencyTuningEnabled = true;
            burstsPerBuffer = 2;
        }
        ALOGD("AAudioServiceEndpoint(): burstsPerBuffer = %d", burstsPerBuffer);
        int32_t desiredBufferSize = burstsPerBuffer * mStreamInternal.getFramesPerBurst();
        mStreamInternal.setBufferSize(desiredBufferSize);
    }
    return result;
}

aaudio_result_t AAudioServiceEndpoint::close() {
    return mStreamInternal.close();
}

// TODO, maybe use an interface to reduce exposure
aaudio_result_t AAudioServiceEndpoint::registerStream(AAudioServiceStreamShared *sharedStream) {
    std::lock_guard<std::mutex> lock(mLockStreams);
    mRegisteredStreams.push_back(sharedStream);
    return AAUDIO_OK;
}

aaudio_result_t AAudioServiceEndpoint::unregisterStream(AAudioServiceStreamShared *sharedStream) {
    std::lock_guard<std::mutex> lock(mLockStreams);
    mRegisteredStreams.erase(std::remove(mRegisteredStreams.begin(), mRegisteredStreams.end(), sharedStream),
              mRegisteredStreams.end());
    return AAUDIO_OK;
}

aaudio_result_t AAudioServiceEndpoint::startStream(AAudioServiceStreamShared *sharedStream) {
    // TODO use real-time technique to avoid mutex, eg. atomic command FIFO
    std::lock_guard<std::mutex> lock(mLockStreams);
    mRunningStreams.push_back(sharedStream);
    if (mRunningStreams.size() == 1) {
        startMixer_l();
    }
    return AAUDIO_OK;
}

aaudio_result_t AAudioServiceEndpoint::stopStream(AAudioServiceStreamShared *sharedStream) {
    std::lock_guard<std::mutex> lock(mLockStreams);
    mRunningStreams.erase(std::remove(mRunningStreams.begin(), mRunningStreams.end(), sharedStream),
              mRunningStreams.end());
    if (mRunningStreams.size() == 0) {
        stopMixer_l();
    }
    return AAUDIO_OK;
}

static void *aaudio_mixer_thread_proc(void *context) {
    AAudioServiceEndpoint *stream = (AAudioServiceEndpoint *) context;
    if (stream != NULL) {
        return stream->callbackLoop();
    } else {
        return NULL;
    }
}

// Render audio in the application callback and then write the data to the stream.
void *AAudioServiceEndpoint::callbackLoop() {
    ALOGD("AAudioServiceEndpoint(): callbackLoop() entering");
    int32_t underflowCount = 0;

    aaudio_result_t result = mStreamInternal.requestStart();

    // result might be a frame count
    while (mCallbackEnabled.load() && mStreamInternal.isPlaying() && (result >= 0)) {
        // Mix data from each active stream.
        {
            mMixer.clear();
            std::lock_guard<std::mutex> lock(mLockStreams);
            for(AAudioServiceStreamShared *sharedStream : mRunningStreams) {
                FifoBuffer *fifo = sharedStream->getDataFifoBuffer();
                float volume = 0.5; // TODO get from system
                bool underflowed = mMixer.mix(fifo, volume);
                underflowCount += underflowed ? 1 : 0;
                // TODO log underflows in each stream
                sharedStream->markTransferTime(AudioClock::getNanoseconds());
            }
        }

        // Write audio data to stream using a blocking write.
        int64_t timeoutNanos = calculateReasonableTimeout(mStreamInternal.getFramesPerBurst());
        result = mStreamInternal.write(mMixer.getOutputBuffer(), getFramesPerBurst(), timeoutNanos);
        if (result == AAUDIO_ERROR_DISCONNECTED) {
            disconnectRegisteredStreams();
            break;
        } else if (result != getFramesPerBurst()) {
            ALOGW("AAudioServiceEndpoint(): callbackLoop() wrote %d / %d",
                  result, getFramesPerBurst());
            break;
        }
    }

    result = mStreamInternal.requestStop();

    ALOGD("AAudioServiceEndpoint(): callbackLoop() exiting, %d underflows", underflowCount);
    return NULL; // TODO review
}

aaudio_result_t AAudioServiceEndpoint::startMixer_l() {
    // Launch the callback loop thread.
    int64_t periodNanos = mStreamInternal.getFramesPerBurst()
                          * AAUDIO_NANOS_PER_SECOND
                          / getSampleRate();
    mCallbackEnabled.store(true);
    return mStreamInternal.createThread(periodNanos, aaudio_mixer_thread_proc, this);
}

aaudio_result_t AAudioServiceEndpoint::stopMixer_l() {
    mCallbackEnabled.store(false);
    return mStreamInternal.joinThread(NULL, calculateReasonableTimeout(mStreamInternal.getFramesPerBurst()));
}

// TODO Call method in AudioStreamInternal when that callback CL is merged.
int64_t AAudioServiceEndpoint::calculateReasonableTimeout(int32_t framesPerOperation) {

    // Wait for at least a second or some number of callbacks to join the thread.
    int64_t timeoutNanoseconds = (MIN_TIMEOUT_OPERATIONS * framesPerOperation * AAUDIO_NANOS_PER_SECOND)
                                 / getSampleRate();
    if (timeoutNanoseconds < MIN_TIMEOUT_NANOS) { // arbitrary number of seconds
        timeoutNanoseconds = MIN_TIMEOUT_NANOS;
    }
    return timeoutNanoseconds;
}

void AAudioServiceEndpoint::disconnectRegisteredStreams() {
    std::lock_guard<std::mutex> lock(mLockStreams);
    for(AAudioServiceStreamShared *sharedStream : mRunningStreams) {
        sharedStream->onStop();
    }
    mRunningStreams.clear();
    for(AAudioServiceStreamShared *sharedStream : mRegisteredStreams) {
        sharedStream->onDisconnect();
    }
    mRegisteredStreams.clear();
}
