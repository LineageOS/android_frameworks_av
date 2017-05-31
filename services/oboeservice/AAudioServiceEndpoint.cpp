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

// Set up an EXCLUSIVE MMAP stream that will be shared.
aaudio_result_t AAudioServiceEndpoint::open(int32_t deviceId) {
    mStreamInternal = getStreamInternal();

    AudioStreamBuilder builder;
    builder.setSharingMode(AAUDIO_SHARING_MODE_EXCLUSIVE);
    // Don't fall back to SHARED because that would cause recursion.
    builder.setSharingModeMatchRequired(true);
    builder.setDeviceId(deviceId);
    builder.setDirection(getDirection());
    builder.setBufferCapacity(DEFAULT_BUFFER_CAPACITY);

    return getStreamInternal()->open(builder);
}

aaudio_result_t AAudioServiceEndpoint::close() {
    return getStreamInternal()->close();
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
        startSharingThread_l();
    }
    return AAUDIO_OK;
}

aaudio_result_t AAudioServiceEndpoint::stopStream(AAudioServiceStreamShared *sharedStream) {
    int numRunningStreams = 0;
    {
        std::lock_guard<std::mutex> lock(mLockStreams);
        mRunningStreams.erase(
                std::remove(mRunningStreams.begin(), mRunningStreams.end(), sharedStream),
                mRunningStreams.end());
        numRunningStreams = mRunningStreams.size();
    }
    if (numRunningStreams == 0) {
        // Don't call this under a lock because the callbackLoop also uses the lock.
        stopSharingThread();
    }
    return AAUDIO_OK;
}

static void *aaudio_endpoint_thread_proc(void *context) {
    AAudioServiceEndpoint *endpoint = (AAudioServiceEndpoint *) context;
    if (endpoint != NULL) {
        return endpoint->callbackLoop();
    } else {
        return NULL;
    }
}

aaudio_result_t AAudioServiceEndpoint::startSharingThread_l() {
    // Launch the callback loop thread.
    int64_t periodNanos = getStreamInternal()->getFramesPerBurst()
                          * AAUDIO_NANOS_PER_SECOND
                          / getSampleRate();
    mCallbackEnabled.store(true);
    return getStreamInternal()->createThread(periodNanos, aaudio_endpoint_thread_proc, this);
}

aaudio_result_t AAudioServiceEndpoint::stopSharingThread() {
    mCallbackEnabled.store(false);
    aaudio_result_t result = getStreamInternal()->joinThread(NULL);
    return result;
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
