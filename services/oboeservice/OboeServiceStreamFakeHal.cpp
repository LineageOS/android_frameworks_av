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

#define LOG_TAG "OboeService"
//#define LOG_NDEBUG 0
#include <utils/Log.h>

#include "AudioClock.h"
#include "AudioEndpointParcelable.h"

#include "OboeServiceStreamBase.h"
#include "OboeServiceStreamFakeHal.h"

#include "FakeAudioHal.h"

using namespace android;
using namespace oboe;

// HACK values for Marlin
#define CARD_ID              0
#define DEVICE_ID            19

/**
 * Construct the audio message queuues and message queues.
 */

OboeServiceStreamFakeHal::OboeServiceStreamFakeHal()
        : OboeServiceStreamBase()
        , mStreamId(nullptr)
        , mPreviousFrameCounter(0)
{
}

OboeServiceStreamFakeHal::~OboeServiceStreamFakeHal() {
    ALOGD("OboeServiceStreamFakeHal::~OboeServiceStreamFakeHal() call close()");
    close();
}

oboe_result_t OboeServiceStreamFakeHal::open(oboe::OboeStreamRequest &request,
                                             oboe::OboeStreamConfiguration &configuration) {
    // Open stream on HAL and pass information about the ring buffer to the client.
    mmap_buffer_info mmapInfo;
    oboe_result_t error;

    // Open HAL
    error = fake_hal_open(CARD_ID, DEVICE_ID, &mStreamId);
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
    ALOGD("OboeServiceStreamFakeHal::open() mmapInfo.burst_size_in_frames = %d",
         mmapInfo.burst_size_in_frames);
    ALOGD("OboeServiceStreamFakeHal::open() mmapInfo.buffer_capacity_in_frames = %d",
         mmapInfo.buffer_capacity_in_frames);
    ALOGD("OboeServiceStreamFakeHal::open() mmapInfo.buffer_capacity_in_bytes = %d",
         mmapInfo.buffer_capacity_in_bytes);

    // Fill in OboeStreamConfiguration
    configuration.setSampleRate(mSampleRate);
    configuration.setSamplesPerFrame(mmapInfo.channel_count);
    configuration.setAudioFormat(OBOE_AUDIO_FORMAT_PCM16);
    return OBOE_OK;
}

/**
 * Get an immutable description of the in-memory queues
 * used to communicate with the underlying HAL or Service.
 */
oboe_result_t OboeServiceStreamFakeHal::getDescription(AudioEndpointParcelable &parcelable) {
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
    return OBOE_OK;
}

/**
 * Start the flow of data.
 */
oboe_result_t OboeServiceStreamFakeHal::start() {
    if (mStreamId == nullptr) return OBOE_ERROR_NULL;
    oboe_result_t result = fake_hal_start(mStreamId);
    sendServiceEvent(OBOE_SERVICE_EVENT_STARTED);
    mState = OBOE_STREAM_STATE_STARTED;
    return result;
}

/**
 * Stop the flow of data such that start() can resume with loss of data.
 */
oboe_result_t OboeServiceStreamFakeHal::pause() {
    if (mStreamId == nullptr) return OBOE_ERROR_NULL;
    sendCurrentTimestamp();
    oboe_result_t result = fake_hal_pause(mStreamId);
    sendServiceEvent(OBOE_SERVICE_EVENT_PAUSED);
    mState = OBOE_STREAM_STATE_PAUSED;
    mFramesRead.reset32();
    ALOGD("OboeServiceStreamFakeHal::pause() sent OBOE_SERVICE_EVENT_PAUSED");
    return result;
}

/**
 *  Discard any data held by the underlying HAL or Service.
 */
oboe_result_t OboeServiceStreamFakeHal::flush() {
    if (mStreamId == nullptr) return OBOE_ERROR_NULL;
    // TODO how do we flush an MMAP/NOIRQ buffer? sync pointers?
    ALOGD("OboeServiceStreamFakeHal::pause() send OBOE_SERVICE_EVENT_FLUSHED");
    sendServiceEvent(OBOE_SERVICE_EVENT_FLUSHED);
    mState = OBOE_STREAM_STATE_FLUSHED;
    return OBOE_OK;
}

oboe_result_t OboeServiceStreamFakeHal::close() {
    oboe_result_t result = OBOE_OK;
    if (mStreamId != nullptr) {
        result = fake_hal_close(mStreamId);
        mStreamId = nullptr;
    }
    return result;
}

void OboeServiceStreamFakeHal::sendCurrentTimestamp() {
    int frameCounter = 0;
    int error = fake_hal_get_frame_counter(mStreamId, &frameCounter);
    if (error < 0) {
        ALOGE("OboeServiceStreamFakeHal::sendCurrentTimestamp() error %d",
                error);
    } else if (frameCounter != mPreviousFrameCounter) {
        OboeServiceMessage command;
        command.what = OboeServiceMessage::code::TIMESTAMP;
        mFramesRead.update32(frameCounter);
        command.timestamp.position = mFramesRead.get();
        ALOGV("OboeServiceStreamFakeHal::sendCurrentTimestamp() HAL frames = %d, pos = %d",
                frameCounter, (int)mFramesRead.get());
        command.timestamp.timestamp = AudioClock::getNanoseconds();
        mUpMessageQueue->getFifoBuffer()->write(&command, 1);
        mPreviousFrameCounter = frameCounter;
    }
}

void OboeServiceStreamFakeHal::tickle() {
    if (mStreamId != nullptr) {
        switch (mState) {
            case OBOE_STREAM_STATE_STARTING:
            case OBOE_STREAM_STATE_STARTED:
            case OBOE_STREAM_STATE_PAUSING:
            case OBOE_STREAM_STATE_STOPPING:
                sendCurrentTimestamp();
                break;
            default:
                break;
        }
    }
}

