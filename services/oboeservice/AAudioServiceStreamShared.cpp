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

#define LOG_TAG "AAudioServiceStreamShared"
//#define LOG_NDEBUG 0
#include <utils/Log.h>

#include <mutex>

#include <aaudio/AAudio.h>

#include "binding/IAAudioService.h"

#include "binding/AAudioServiceMessage.h"
#include "AAudioServiceStreamBase.h"
#include "AAudioServiceStreamShared.h"
#include "AAudioEndpointManager.h"
#include "AAudioService.h"
#include "AAudioServiceEndpoint.h"

using namespace android;
using namespace aaudio;

#define MIN_BURSTS_PER_BUFFER       2
#define DEFAULT_BURSTS_PER_BUFFER   16
// This is an arbitrary range. TODO review.
#define MAX_FRAMES_PER_BUFFER       (32 * 1024)

AAudioServiceStreamShared::AAudioServiceStreamShared(AAudioService &audioService)
    : mAudioService(audioService)
    {
}

int32_t AAudioServiceStreamShared::calculateBufferCapacity(int32_t requestedCapacityFrames,
                                                           int32_t framesPerBurst) {

    if (requestedCapacityFrames > MAX_FRAMES_PER_BUFFER) {
        ALOGE("AAudioServiceStreamShared::calculateBufferCapacity() requested capacity %d > max %d",
              requestedCapacityFrames, MAX_FRAMES_PER_BUFFER);
        return AAUDIO_ERROR_OUT_OF_RANGE;
    }

    // Determine how many bursts will fit in the buffer.
    int32_t numBursts;
    if (requestedCapacityFrames == AAUDIO_UNSPECIFIED) {
        // Use fewer bursts if default is too many.
        if ((DEFAULT_BURSTS_PER_BUFFER * framesPerBurst) > MAX_FRAMES_PER_BUFFER) {
            numBursts = MAX_FRAMES_PER_BUFFER / framesPerBurst;
        } else {
            numBursts = DEFAULT_BURSTS_PER_BUFFER;
        }
    } else {
        // round up to nearest burst boundary
        numBursts = (requestedCapacityFrames + framesPerBurst - 1) / framesPerBurst;
    }

    // Clip to bare minimum.
    if (numBursts < MIN_BURSTS_PER_BUFFER) {
        numBursts = MIN_BURSTS_PER_BUFFER;
    }
    // Check for numeric overflow.
    if (numBursts > 0x8000 || framesPerBurst > 0x8000) {
        ALOGE("AAudioServiceStreamShared::calculateBufferCapacity() overflow, capacity = %d * %d",
              numBursts, framesPerBurst);
        return AAUDIO_ERROR_OUT_OF_RANGE;
    }
    int32_t capacityInFrames = numBursts * framesPerBurst;

    // Final sanity check.
    if (capacityInFrames > MAX_FRAMES_PER_BUFFER) {
        ALOGE("AAudioServiceStreamShared::calculateBufferCapacity() calc capacity %d > max %d",
              capacityInFrames, MAX_FRAMES_PER_BUFFER);
        return AAUDIO_ERROR_OUT_OF_RANGE;
    }
    ALOGD("AAudioServiceStreamShared::calculateBufferCapacity() requested %d frames, actual = %d",
          requestedCapacityFrames, capacityInFrames);
    return capacityInFrames;
}

aaudio_result_t AAudioServiceStreamShared::open(const aaudio::AAudioStreamRequest &request,
                     aaudio::AAudioStreamConfiguration &configurationOutput)  {

    sp<AAudioServiceStreamShared> keep(this);

    aaudio_result_t result = AAudioServiceStreamBase::open(request, configurationOutput);
    if (result != AAUDIO_OK) {
        ALOGE("AAudioServiceStreamBase open() returned %d", result);
        return result;
    }

    const AAudioStreamConfiguration &configurationInput = request.getConstantConfiguration();
    aaudio_direction_t direction = request.getDirection();

    AAudioEndpointManager &mEndpointManager = AAudioEndpointManager::getInstance();
    mServiceEndpoint = mEndpointManager.openEndpoint(mAudioService, configurationOutput, direction);
    if (mServiceEndpoint == nullptr) {
        ALOGE("AAudioServiceStreamShared::open() mServiceEndPoint = %p", mServiceEndpoint);
        return AAUDIO_ERROR_UNAVAILABLE;
    }

    // Is the request compatible with the shared endpoint?
    mAudioFormat = configurationInput.getFormat();
    if (mAudioFormat == AAUDIO_FORMAT_UNSPECIFIED) {
        mAudioFormat = AAUDIO_FORMAT_PCM_FLOAT;
    } else if (mAudioFormat != AAUDIO_FORMAT_PCM_FLOAT) {
        ALOGE("AAudioServiceStreamShared::open() mAudioFormat = %d, need FLOAT", mAudioFormat);
        result = AAUDIO_ERROR_INVALID_FORMAT;
        goto error;
    }

    mSampleRate = configurationInput.getSampleRate();
    if (mSampleRate == AAUDIO_UNSPECIFIED) {
        mSampleRate = mServiceEndpoint->getSampleRate();
    } else if (mSampleRate != mServiceEndpoint->getSampleRate()) {
        ALOGE("AAudioServiceStreamShared::open() mSampleRate = %d, need %d",
              mSampleRate, mServiceEndpoint->getSampleRate());
        result = AAUDIO_ERROR_INVALID_RATE;
        goto error;
    }

    mSamplesPerFrame = configurationInput.getSamplesPerFrame();
    if (mSamplesPerFrame == AAUDIO_UNSPECIFIED) {
        mSamplesPerFrame = mServiceEndpoint->getSamplesPerFrame();
    } else if (mSamplesPerFrame != mServiceEndpoint->getSamplesPerFrame()) {
        ALOGE("AAudioServiceStreamShared::open() mSamplesPerFrame = %d, need %d",
              mSamplesPerFrame, mServiceEndpoint->getSamplesPerFrame());
        result = AAUDIO_ERROR_OUT_OF_RANGE;
        goto error;
    }

    mFramesPerBurst = mServiceEndpoint->getFramesPerBurst();
    ALOGD("AAudioServiceStreamShared::open() mSampleRate = %d, mFramesPerBurst = %d",
          mSampleRate, mFramesPerBurst);

    mCapacityInFrames = calculateBufferCapacity(configurationInput.getBufferCapacity(),
                                     mFramesPerBurst);
    if (mCapacityInFrames < 0) {
        result = mCapacityInFrames; // negative error code
        mCapacityInFrames = 0;
        goto error;
    }

    // Create audio data shared memory buffer for client.
    mAudioDataQueue = new SharedRingBuffer();
    result = mAudioDataQueue->allocate(calculateBytesPerFrame(), mCapacityInFrames);
    if (result != AAUDIO_OK) {
        ALOGE("AAudioServiceStreamShared::open() could not allocate FIFO with %d frames",
              mCapacityInFrames);
        result = AAUDIO_ERROR_NO_MEMORY;
        goto error;
    }

    ALOGD("AAudioServiceStreamShared::open() actual rate = %d, channels = %d, deviceId = %d",
          mSampleRate, mSamplesPerFrame, mServiceEndpoint->getDeviceId());

    // Fill in configuration for client.
    configurationOutput.setSampleRate(mSampleRate);
    configurationOutput.setSamplesPerFrame(mSamplesPerFrame);
    configurationOutput.setFormat(mAudioFormat);
    configurationOutput.setDeviceId(mServiceEndpoint->getDeviceId());

    result = mServiceEndpoint->registerStream(keep);
    if (result != AAUDIO_OK) {
        goto error;
    }

    setState(AAUDIO_STREAM_STATE_OPEN);
    return AAUDIO_OK;

error:
    close();
    return result;
}

/**
 * Start the flow of audio data.
 *
 * An AAUDIO_SERVICE_EVENT_STARTED will be sent to the client when complete.
 */
aaudio_result_t AAudioServiceStreamShared::start()  {
    if (isRunning()) {
        return AAUDIO_OK;
    }
    AAudioServiceEndpoint *endpoint = mServiceEndpoint;
    if (endpoint == nullptr) {
        return AAUDIO_ERROR_INVALID_STATE;
    }
    // For output streams, this will add the stream to the mixer.
    aaudio_result_t result = endpoint->startStream(this);
    if (result != AAUDIO_OK) {
        ALOGE("AAudioServiceStreamShared::start() mServiceEndpoint returned %d", result);
        disconnect();
    } else {
        result = endpoint->getStreamInternal()->startClient(mMmapClient, &mClientHandle);
        if (result == AAUDIO_OK) {
            result = AAudioServiceStreamBase::start();
        }
    }
    return result;
}

/**
 * Stop the flow of data so that start() can resume without loss of data.
 *
 * An AAUDIO_SERVICE_EVENT_PAUSED will be sent to the client when complete.
*/
aaudio_result_t AAudioServiceStreamShared::pause()  {
    if (!isRunning()) {
        return AAUDIO_OK;
    }
    AAudioServiceEndpoint *endpoint = mServiceEndpoint;
    if (endpoint == nullptr) {
        return AAUDIO_ERROR_INVALID_STATE;
    }
    endpoint->getStreamInternal()->stopClient(mClientHandle);
    aaudio_result_t result = endpoint->stopStream(this);
    if (result != AAUDIO_OK) {
        ALOGE("AAudioServiceStreamShared::pause() mServiceEndpoint returned %d", result);
        disconnect(); // TODO should we return or pause Base first?
    }
    return AAudioServiceStreamBase::pause();
}

aaudio_result_t AAudioServiceStreamShared::stop()  {
    if (!isRunning()) {
        return AAUDIO_OK;
    }
    AAudioServiceEndpoint *endpoint = mServiceEndpoint;
    if (endpoint == nullptr) {
        return AAUDIO_ERROR_INVALID_STATE;
    }
    endpoint->getStreamInternal()->stopClient(mClientHandle);
    aaudio_result_t result = endpoint->stopStream(this);
    if (result != AAUDIO_OK) {
        ALOGE("AAudioServiceStreamShared::stop() mServiceEndpoint returned %d", result);
        disconnect();
    }
    return AAudioServiceStreamBase::stop();
}

/**
 *  Discard any data held by the underlying HAL or Service.
 *
 * An AAUDIO_SERVICE_EVENT_FLUSHED will be sent to the client when complete.
 */
aaudio_result_t AAudioServiceStreamShared::flush()  {
    AAudioServiceEndpoint *endpoint = mServiceEndpoint;
    if (endpoint == nullptr) {
        return AAUDIO_ERROR_INVALID_STATE;
    }
    if (mState != AAUDIO_STREAM_STATE_PAUSED) {
         ALOGE("AAudioServiceStreamShared::flush() stream not paused, state = %s",
            AAudio_convertStreamStateToText(mState));
        return AAUDIO_ERROR_INVALID_STATE;
    }
    // Data will get flushed when the client receives the FLUSHED event.
    return AAudioServiceStreamBase::flush();
}

aaudio_result_t AAudioServiceStreamShared::close()  {
    if (mState == AAUDIO_STREAM_STATE_CLOSED) {
        return AAUDIO_OK;
    }

    stop();

    AAudioServiceEndpoint *endpoint = mServiceEndpoint;
    if (endpoint == nullptr) {
        return AAUDIO_ERROR_INVALID_STATE;
    }

    endpoint->unregisterStream(this);

    AAudioEndpointManager &mEndpointManager = AAudioEndpointManager::getInstance();
    mEndpointManager.closeEndpoint(endpoint);
    mServiceEndpoint = nullptr;

    if (mAudioDataQueue != nullptr) {
        delete mAudioDataQueue;
        mAudioDataQueue = nullptr;
    }
    return AAudioServiceStreamBase::close();
}

/**
 * Get an immutable description of the data queue created by this service.
 */
aaudio_result_t AAudioServiceStreamShared::getDownDataDescription(AudioEndpointParcelable &parcelable)
{
    // Gather information on the data queue.
    mAudioDataQueue->fillParcelable(parcelable,
                                    parcelable.mDownDataQueueParcelable);
    parcelable.mDownDataQueueParcelable.setFramesPerBurst(getFramesPerBurst());
    return AAUDIO_OK;
}

void AAudioServiceStreamShared::markTransferTime(int64_t nanoseconds) {
    mMarkedPosition = mAudioDataQueue->getFifoBuffer()->getReadCounter();
    mMarkedTime = nanoseconds;
}

aaudio_result_t AAudioServiceStreamShared::getFreeRunningPosition(int64_t *positionFrames,
                                                                int64_t *timeNanos) {
    // TODO get these two numbers as an atomic pair
    *positionFrames = mMarkedPosition;
    *timeNanos = mMarkedTime;
    return AAUDIO_OK;
}
