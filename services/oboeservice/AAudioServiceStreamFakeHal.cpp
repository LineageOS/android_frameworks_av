/*
 * Copyright (C) 2016 The Android Open Source Project
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

#include <atomic>

#include "AudioClock.h"
#include "AudioEndpointParcelable.h"

#include "AAudioServiceStreamBase.h"
#include "AAudioServiceStreamFakeHal.h"

#include "FakeAudioHal.h"

using namespace android;
using namespace aaudio;

// HACK values for Marlin
#define CARD_ID              0
#define DEVICE_ID            19

/**
 * Construct the audio message queuues and message queues.
 */

AAudioServiceStreamFakeHal::AAudioServiceStreamFakeHal()
        : AAudioServiceStreamBase()
        , mStreamId(nullptr)
        , mPreviousFrameCounter(0)
        , mAAudioThread()
{
}

AAudioServiceStreamFakeHal::~AAudioServiceStreamFakeHal() {
    ALOGD("AAudioServiceStreamFakeHal::~AAudioServiceStreamFakeHal() call close()");
    close();
}

aaudio_result_t AAudioServiceStreamFakeHal::open(aaudio::AAudioStreamRequest &request,
                                       aaudio::AAudioStreamConfiguration &configurationOutput) {
    // Open stream on HAL and pass information about the ring buffer to the client.
    mmap_buffer_info mmapInfo;
    aaudio_result_t error;

    // Open HAL
    int bufferCapacity = request.getConfiguration().getBufferCapacity();
    error = fake_hal_open(CARD_ID, DEVICE_ID, bufferCapacity, &mStreamId);
    if(error < 0) {
        ALOGE("Could not open card %d, device %d", CARD_ID, DEVICE_ID);
        return error;
    }

    // Get information about the shared audio buffer.
    error = fake_hal_get_mmap_info(mStreamId, &mmapInfo);
    if (error < 0) {
        ALOGE("fake_hal_get_mmap_info returned %d", error);
        fake_hal_close(mStreamId);
        mStreamId = nullptr;
        return error;
    }
    mHalFileDescriptor = mmapInfo.fd;
    mFramesPerBurst = mmapInfo.burst_size_in_frames;
    mCapacityInFrames = mmapInfo.buffer_capacity_in_frames;
    mCapacityInBytes = mmapInfo.buffer_capacity_in_bytes;
    mSampleRate = mmapInfo.sample_rate;
    mBytesPerFrame = mmapInfo.channel_count * sizeof(int16_t); // FIXME based on data format
    ALOGD("AAudioServiceStreamFakeHal::open() mmapInfo.burst_size_in_frames = %d",
         mmapInfo.burst_size_in_frames);
    ALOGD("AAudioServiceStreamFakeHal::open() mmapInfo.buffer_capacity_in_frames = %d",
         mmapInfo.buffer_capacity_in_frames);
    ALOGD("AAudioServiceStreamFakeHal::open() mmapInfo.buffer_capacity_in_bytes = %d",
         mmapInfo.buffer_capacity_in_bytes);

    // Fill in AAudioStreamConfiguration
    configurationOutput.setSampleRate(mSampleRate);
    configurationOutput.setSamplesPerFrame(mmapInfo.channel_count);
    configurationOutput.setAudioFormat(AAUDIO_FORMAT_PCM_I16);

    return AAUDIO_OK;
}

/**
 * Get an immutable description of the in-memory queues
 * used to communicate with the underlying HAL or Service.
 */
aaudio_result_t AAudioServiceStreamFakeHal::getDescription(AudioEndpointParcelable &parcelable) {
    // Gather information on the message queue.
    mUpMessageQueue->fillParcelable(parcelable,
                                    parcelable.mUpMessageQueueParcelable);

    // Gather information on the data queue.
    // TODO refactor into a SharedRingBuffer?
    int fdIndex = parcelable.addFileDescriptor(mHalFileDescriptor, mCapacityInBytes);
    parcelable.mDownDataQueueParcelable.setupMemory(fdIndex, 0, mCapacityInBytes);
    parcelable.mDownDataQueueParcelable.setBytesPerFrame(mBytesPerFrame);
    parcelable.mDownDataQueueParcelable.setFramesPerBurst(mFramesPerBurst);
    parcelable.mDownDataQueueParcelable.setCapacityInFrames(mCapacityInFrames);
    return AAUDIO_OK;
}

/**
 * Start the flow of data.
 */
aaudio_result_t AAudioServiceStreamFakeHal::start() {
    if (mStreamId == nullptr) return AAUDIO_ERROR_NULL;
    aaudio_result_t result = fake_hal_start(mStreamId);
    sendServiceEvent(AAUDIO_SERVICE_EVENT_STARTED);
    mState = AAUDIO_STREAM_STATE_STARTED;
    if (result == AAUDIO_OK) {
        mThreadEnabled.store(true);
        result = mAAudioThread.start(this);
    }
    return result;
}

/**
 * Stop the flow of data such that start() can resume with loss of data.
 */
aaudio_result_t AAudioServiceStreamFakeHal::pause() {
    if (mStreamId == nullptr) return AAUDIO_ERROR_NULL;
    sendCurrentTimestamp();
    aaudio_result_t result = fake_hal_pause(mStreamId);
    sendServiceEvent(AAUDIO_SERVICE_EVENT_PAUSED);
    mState = AAUDIO_STREAM_STATE_PAUSED;
    mFramesRead.reset32();
    ALOGD("AAudioServiceStreamFakeHal::pause() sent AAUDIO_SERVICE_EVENT_PAUSED");
    mThreadEnabled.store(false);
    result = mAAudioThread.stop();
    return result;
}

/**
 *  Discard any data held by the underlying HAL or Service.
 */
aaudio_result_t AAudioServiceStreamFakeHal::flush() {
    if (mStreamId == nullptr) return AAUDIO_ERROR_NULL;
    // TODO how do we flush an MMAP/NOIRQ buffer? sync pointers?
    ALOGD("AAudioServiceStreamFakeHal::pause() send AAUDIO_SERVICE_EVENT_FLUSHED");
    sendServiceEvent(AAUDIO_SERVICE_EVENT_FLUSHED);
    mState = AAUDIO_STREAM_STATE_FLUSHED;
    return AAUDIO_OK;
}

aaudio_result_t AAudioServiceStreamFakeHal::close() {
    aaudio_result_t result = AAUDIO_OK;
    if (mStreamId != nullptr) {
        result = fake_hal_close(mStreamId);
        mStreamId = nullptr;
    }
    return result;
}

void AAudioServiceStreamFakeHal::sendCurrentTimestamp() {
    int frameCounter = 0;
    int error = fake_hal_get_frame_counter(mStreamId, &frameCounter);
    if (error < 0) {
        ALOGE("AAudioServiceStreamFakeHal::sendCurrentTimestamp() error %d",
                error);
    } else if (frameCounter != mPreviousFrameCounter) {
        AAudioServiceMessage command;
        command.what = AAudioServiceMessage::code::TIMESTAMP;
        mFramesRead.update32(frameCounter);
        command.timestamp.position = mFramesRead.get();
        ALOGD("AAudioServiceStreamFakeHal::sendCurrentTimestamp() HAL frames = %d, pos = %d",
                frameCounter, (int)mFramesRead.get());
        command.timestamp.timestamp = AudioClock::getNanoseconds();
        mUpMessageQueue->getFifoBuffer()->write(&command, 1);
        mPreviousFrameCounter = frameCounter;
    }
}

// implement Runnable
void AAudioServiceStreamFakeHal::run() {
    TimestampScheduler timestampScheduler;
    timestampScheduler.setBurstPeriod(mFramesPerBurst, mSampleRate);
    timestampScheduler.start(AudioClock::getNanoseconds());
    while(mThreadEnabled.load()) {
        aaudio_nanoseconds_t nextTime = timestampScheduler.nextAbsoluteTime();
        if (AudioClock::getNanoseconds() >= nextTime) {
            sendCurrentTimestamp();
        } else  {
            // Sleep until it is time to send the next timestamp.
            AudioClock::sleepUntilNanoTime(nextTime);
        }
    }
}

