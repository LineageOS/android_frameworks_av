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

#define MIN_BURSTS_PER_BUFFER   2
#define MAX_BURSTS_PER_BUFFER   32

AAudioServiceStreamShared::AAudioServiceStreamShared(AAudioService &audioService)
    : mAudioService(audioService)
    {
}

AAudioServiceStreamShared::~AAudioServiceStreamShared() {
    close();
}

aaudio_result_t AAudioServiceStreamShared::open(const aaudio::AAudioStreamRequest &request,
                     aaudio::AAudioStreamConfiguration &configurationOutput)  {

    aaudio_result_t result = AAudioServiceStreamBase::open(request, configurationOutput);
    if (result != AAUDIO_OK) {
        ALOGE("AAudioServiceStreamBase open returned %d", result);
        return result;
    }

    const AAudioStreamConfiguration &configurationInput = request.getConstantConfiguration();
    int32_t deviceId = configurationInput.getDeviceId();
    aaudio_direction_t direction = request.getDirection();

    AAudioEndpointManager &mEndpointManager = AAudioEndpointManager::getInstance();
    mServiceEndpoint = mEndpointManager.openEndpoint(mAudioService, deviceId, direction);
    if (mServiceEndpoint == nullptr) {
        ALOGE("AAudioServiceStreamShared::open(), mServiceEndPoint = %p", mServiceEndpoint);
        return AAUDIO_ERROR_UNAVAILABLE;
    }

    // Is the request compatible with the shared endpoint?
    mAudioFormat = configurationInput.getAudioFormat();
    if (mAudioFormat == AAUDIO_FORMAT_UNSPECIFIED) {
        mAudioFormat = AAUDIO_FORMAT_PCM_FLOAT;
    } else if (mAudioFormat != AAUDIO_FORMAT_PCM_FLOAT) {
        ALOGE("AAudioServiceStreamShared::open(), mAudioFormat = %d, need FLOAT", mAudioFormat);
        return AAUDIO_ERROR_INVALID_FORMAT;
    }

    mSampleRate = configurationInput.getSampleRate();
    if (mSampleRate == AAUDIO_FORMAT_UNSPECIFIED) {
        mSampleRate = mServiceEndpoint->getSampleRate();
    } else if (mSampleRate != mServiceEndpoint->getSampleRate()) {
        ALOGE("AAudioServiceStreamShared::open(), mAudioFormat = %d, need %d",
              mSampleRate, mServiceEndpoint->getSampleRate());
        return AAUDIO_ERROR_INVALID_RATE;
    }

    mSamplesPerFrame = configurationInput.getSamplesPerFrame();
    if (mSamplesPerFrame == AAUDIO_FORMAT_UNSPECIFIED) {
        mSamplesPerFrame = mServiceEndpoint->getSamplesPerFrame();
    } else if (mSamplesPerFrame != mServiceEndpoint->getSamplesPerFrame()) {
        ALOGE("AAudioServiceStreamShared::open(), mSamplesPerFrame = %d, need %d",
              mSamplesPerFrame, mServiceEndpoint->getSamplesPerFrame());
        return AAUDIO_ERROR_OUT_OF_RANGE;
    }

    // Determine this stream's shared memory buffer capacity.
    mFramesPerBurst = mServiceEndpoint->getFramesPerBurst();
    int32_t minCapacityFrames = configurationInput.getBufferCapacity();
    int32_t numBursts = MAX_BURSTS_PER_BUFFER;
    if (minCapacityFrames != AAUDIO_UNSPECIFIED) {
        numBursts = (minCapacityFrames + mFramesPerBurst - 1) / mFramesPerBurst;
        if (numBursts < MIN_BURSTS_PER_BUFFER) {
            numBursts = MIN_BURSTS_PER_BUFFER;
        } else if (numBursts > MAX_BURSTS_PER_BUFFER) {
            numBursts = MAX_BURSTS_PER_BUFFER;
        }
    }
    mCapacityInFrames = numBursts * mFramesPerBurst;
    ALOGD("AAudioServiceStreamShared::open(), mCapacityInFrames = %d", mCapacityInFrames);

    // Create audio data shared memory buffer for client.
    mAudioDataQueue = new SharedRingBuffer();
    mAudioDataQueue->allocate(calculateBytesPerFrame(), mCapacityInFrames);

    // Fill in configuration for client.
    configurationOutput.setSampleRate(mSampleRate);
    configurationOutput.setSamplesPerFrame(mSamplesPerFrame);
    configurationOutput.setAudioFormat(mAudioFormat);
    configurationOutput.setDeviceId(deviceId);

    mServiceEndpoint->registerStream(this);

    return AAUDIO_OK;
}

/**
 * Start the flow of audio data.
 *
 * An AAUDIO_SERVICE_EVENT_STARTED will be sent to the client when complete.
 */
aaudio_result_t AAudioServiceStreamShared::start()  {
    AAudioServiceEndpoint *endpoint = mServiceEndpoint;
    if (endpoint == nullptr) {
        return AAUDIO_ERROR_INVALID_STATE;
    }
    // For output streams, this will add the stream to the mixer.
    aaudio_result_t result = endpoint->startStream(this);
    if (result != AAUDIO_OK) {
        ALOGE("AAudioServiceStreamShared::start() mServiceEndpoint returned %d", result);
        processError();
    } else {
        result = AAudioServiceStreamBase::start();
    }
    return AAUDIO_OK;
}

/**
 * Stop the flow of data so that start() can resume without loss of data.
 *
 * An AAUDIO_SERVICE_EVENT_PAUSED will be sent to the client when complete.
*/
aaudio_result_t AAudioServiceStreamShared::pause()  {
    AAudioServiceEndpoint *endpoint = mServiceEndpoint;
    if (endpoint == nullptr) {
        return AAUDIO_ERROR_INVALID_STATE;
    }
    // Add this stream to the mixer.
    aaudio_result_t result = endpoint->stopStream(this);
    if (result != AAUDIO_OK) {
        ALOGE("AAudioServiceStreamShared::pause() mServiceEndpoint returned %d", result);
        processError();
    }
    return AAudioServiceStreamBase::pause();
}

aaudio_result_t AAudioServiceStreamShared::stop()  {
    AAudioServiceEndpoint *endpoint = mServiceEndpoint;
    if (endpoint == nullptr) {
        return AAUDIO_ERROR_INVALID_STATE;
    }
    // Add this stream to the mixer.
    aaudio_result_t result = endpoint->stopStream(this);
    if (result != AAUDIO_OK) {
        ALOGE("AAudioServiceStreamShared::stop() mServiceEndpoint returned %d", result);
        processError();
    }
    return AAudioServiceStreamBase::stop();
}

/**
 *  Discard any data held by the underlying HAL or Service.
 *
 * An AAUDIO_SERVICE_EVENT_FLUSHED will be sent to the client when complete.
 */
aaudio_result_t AAudioServiceStreamShared::flush()  {
    // TODO make sure we are paused
    // TODO actually flush the data
    return AAudioServiceStreamBase::flush() ;
}

aaudio_result_t AAudioServiceStreamShared::close()  {
    pause();
    // TODO wait for pause() to synchronize
    AAudioServiceEndpoint *endpoint = mServiceEndpoint;
    if (endpoint != nullptr) {
        endpoint->unregisterStream(this);

        AAudioEndpointManager &mEndpointManager = AAudioEndpointManager::getInstance();
        mEndpointManager.closeEndpoint(endpoint);
        mServiceEndpoint = nullptr;
    }
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

void AAudioServiceStreamShared::onStop() {
}

void AAudioServiceStreamShared::onDisconnect() {
    mServiceEndpoint->close();
    mServiceEndpoint = nullptr;
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
