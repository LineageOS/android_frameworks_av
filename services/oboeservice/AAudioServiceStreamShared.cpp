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

#include <iomanip>
#include <iostream>
#include <mutex>

#include <aaudio/AAudio.h>

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
    : AAudioServiceStreamBase(audioService)
    , mTimestampPositionOffset(0)
    , mXRunCount(0) {
}

std::string AAudioServiceStreamShared::dumpHeader() {
    std::stringstream result;
    result << AAudioServiceStreamBase::dumpHeader();
    result << "    Write#     Read#   Avail   XRuns";
    return result.str();
}

std::string AAudioServiceStreamShared::dump() const NO_THREAD_SAFETY_ANALYSIS {
    std::stringstream result;

    const bool isLocked = AAudio_tryUntilTrue(
            [this]()->bool { return audioDataQueueLock.try_lock(); } /* f */,
            50 /* times */,
            20 /* sleepMs */);
    if (!isLocked) {
        result << "AAudioServiceStreamShared may be deadlocked\n";
    }

    result << AAudioServiceStreamBase::dump();

    result << mAudioDataQueue->dump();
    result << std::setw(8) << getXRunCount();

    if (isLocked) {
        audioDataQueueLock.unlock();
    }

    return result.str();
}

int32_t AAudioServiceStreamShared::calculateBufferCapacity(int32_t requestedCapacityFrames,
                                                           int32_t framesPerBurst) {

    if (requestedCapacityFrames > MAX_FRAMES_PER_BUFFER) {
        ALOGE("calculateBufferCapacity() requested capacity %d > max %d",
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
        ALOGE("calculateBufferCapacity() overflow, capacity = %d * %d",
              numBursts, framesPerBurst);
        return AAUDIO_ERROR_OUT_OF_RANGE;
    }
    int32_t capacityInFrames = numBursts * framesPerBurst;

    // Final range check.
    if (capacityInFrames > MAX_FRAMES_PER_BUFFER) {
        ALOGE("calculateBufferCapacity() calc capacity %d > max %d",
              capacityInFrames, MAX_FRAMES_PER_BUFFER);
        return AAUDIO_ERROR_OUT_OF_RANGE;
    }
    ALOGV("calculateBufferCapacity() requested %d frames, actual = %d",
          requestedCapacityFrames, capacityInFrames);
    return capacityInFrames;
}

aaudio_result_t AAudioServiceStreamShared::open(const aaudio::AAudioStreamRequest &request)  {

    sp<AAudioServiceStreamShared> keep(this);

    if (request.getConstantConfiguration().getSharingMode() != AAUDIO_SHARING_MODE_SHARED) {
        ALOGE("%s() sharingMode mismatch %d", __func__,
              request.getConstantConfiguration().getSharingMode());
        return AAUDIO_ERROR_INTERNAL;
    }

    aaudio_result_t result = AAudioServiceStreamBase::open(request);
    if (result != AAUDIO_OK) {
        return result;
    }

    const AAudioStreamConfiguration &configurationInput = request.getConstantConfiguration();

    sp<AAudioServiceEndpoint> endpoint = mServiceEndpointWeak.promote();
    if (endpoint == nullptr) {
        result = AAUDIO_ERROR_INVALID_STATE;
        goto error;
    }

    // Is the request compatible with the shared endpoint?
    setFormat(configurationInput.getFormat());
    if (getFormat() == AUDIO_FORMAT_DEFAULT) {
        setFormat(AUDIO_FORMAT_PCM_FLOAT);
    } else if (getFormat() != AUDIO_FORMAT_PCM_FLOAT) {
        ALOGD("%s() audio_format_t mAudioFormat = %d, need FLOAT", __func__, getFormat());
        result = AAUDIO_ERROR_INVALID_FORMAT;
        goto error;
    }

    setSampleRate(configurationInput.getSampleRate());
    if (getSampleRate() == AAUDIO_UNSPECIFIED) {
        setSampleRate(endpoint->getSampleRate());
    } else if (getSampleRate() != endpoint->getSampleRate()) {
        ALOGD("%s() mSampleRate = %d, need %d",
              __func__, getSampleRate(), endpoint->getSampleRate());
        result = AAUDIO_ERROR_INVALID_RATE;
        goto error;
    }

    setChannelMask(configurationInput.getChannelMask());
    if (getChannelMask() == AAUDIO_UNSPECIFIED) {
        setChannelMask(endpoint->getChannelMask());
    } else if (getSamplesPerFrame() != endpoint->getSamplesPerFrame()) {
        ALOGD("%s() mSamplesPerFrame = %#x, need %#x",
              __func__, getSamplesPerFrame(), endpoint->getSamplesPerFrame());
        result = AAUDIO_ERROR_OUT_OF_RANGE;
        goto error;
    }

    setBufferCapacity(calculateBufferCapacity(configurationInput.getBufferCapacity(),
                                     mFramesPerBurst));
    if (getBufferCapacity() < 0) {
        result = getBufferCapacity(); // negative error code
        setBufferCapacity(0);
        goto error;
    }

    {
        std::lock_guard<std::mutex> lock(audioDataQueueLock);
        // Create audio data shared memory buffer for client.
        mAudioDataQueue = std::make_shared<SharedRingBuffer>();
        result = mAudioDataQueue->allocate(calculateBytesPerFrame(), getBufferCapacity());
        if (result != AAUDIO_OK) {
            ALOGE("%s() could not allocate FIFO with %d frames",
                  __func__, getBufferCapacity());
            result = AAUDIO_ERROR_NO_MEMORY;
            goto error;
        }
    }

    result = endpoint->registerStream(keep);
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
 * Get an immutable description of the data queue created by this service.
 */
aaudio_result_t AAudioServiceStreamShared::getAudioDataDescription(
        AudioEndpointParcelable &parcelable)
{
    std::lock_guard<std::mutex> lock(audioDataQueueLock);
    if (mAudioDataQueue == nullptr) {
        ALOGW("%s(): mUpMessageQueue null! - stream not open", __func__);
        return AAUDIO_ERROR_NULL;
    }
    // Gather information on the data queue.
    mAudioDataQueue->fillParcelable(parcelable,
                                    parcelable.mDownDataQueueParcelable);
    parcelable.mDownDataQueueParcelable.setFramesPerBurst(getFramesPerBurst());
    return AAUDIO_OK;
}

void AAudioServiceStreamShared::markTransferTime(Timestamp &timestamp) {
    mAtomicStreamTimestamp.write(timestamp);
}

// Get timestamp that was written by mixer or distributor.
aaudio_result_t AAudioServiceStreamShared::getFreeRunningPosition(int64_t *positionFrames,
                                                                  int64_t *timeNanos) {
    // TODO Get presentation timestamp from the HAL
    if (mAtomicStreamTimestamp.isValid()) {
        Timestamp timestamp = mAtomicStreamTimestamp.read();
        *positionFrames = timestamp.getPosition();
        *timeNanos = timestamp.getNanoseconds();
        return AAUDIO_OK;
    } else {
        return AAUDIO_ERROR_UNAVAILABLE;
    }
}

// Get timestamp from lower level service.
aaudio_result_t AAudioServiceStreamShared::getHardwareTimestamp(int64_t *positionFrames,
                                                                int64_t *timeNanos) {

    int64_t position = 0;
    sp<AAudioServiceEndpoint> endpoint = mServiceEndpointWeak.promote();
    if (endpoint == nullptr) {
        ALOGW("%s() has no endpoint", __func__);
        return AAUDIO_ERROR_INVALID_STATE;
    }

    aaudio_result_t result = endpoint->getTimestamp(&position, timeNanos);
    if (result == AAUDIO_OK) {
        int64_t offset = mTimestampPositionOffset.load();
        // TODO, do not go below starting value
        position -= offset; // Offset from shared MMAP stream
        ALOGV("%s() %8lld = %8lld - %8lld",
              __func__, (long long) position, (long long) (position + offset), (long long) offset);
    }
    *positionFrames = position;
    return result;
}

void AAudioServiceStreamShared::writeDataIfRoom(int64_t mmapFramesRead,
                                                const void *buffer, int32_t numFrames) {
    int64_t clientFramesWritten = 0;

    // Lock the AudioFifo to protect against close.
    std::lock_guard <std::mutex> lock(audioDataQueueLock);

    if (mAudioDataQueue != nullptr) {
        std::shared_ptr<FifoBuffer> fifo = mAudioDataQueue->getFifoBuffer();
        // Determine offset between framePosition in client's stream
        // vs the underlying MMAP stream.
        clientFramesWritten = fifo->getWriteCounter();
        // There are two indices that refer to the same frame.
        int64_t positionOffset = mmapFramesRead - clientFramesWritten;
        setTimestampPositionOffset(positionOffset);

        // Is the buffer too full to write a burst?
        if (fifo->getEmptyFramesAvailable() < getFramesPerBurst()) {
            incrementXRunCount();
        } else {
            fifo->write(buffer, numFrames);
        }
        clientFramesWritten = fifo->getWriteCounter();
    }

    if (clientFramesWritten > 0) {
        // This timestamp represents the completion of data being written into the
        // client buffer. It is sent to the client and used in the timing model
        // to decide when data will be available to read.
        Timestamp timestamp(clientFramesWritten, AudioClock::getNanoseconds());
        markTransferTime(timestamp);
    }
}
