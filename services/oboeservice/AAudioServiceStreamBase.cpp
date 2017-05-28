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

#include <mutex>

#include "binding/IAAudioService.h"
#include "binding/AAudioServiceMessage.h"
#include "utility/AudioClock.h"

#include "AAudioServiceStreamBase.h"
#include "TimestampScheduler.h"

using namespace android;  // TODO just import names needed
using namespace aaudio;   // TODO just import names needed

/**
 * Base class for streams in the service.
 * @return
 */

AAudioServiceStreamBase::AAudioServiceStreamBase()
        : mUpMessageQueue(nullptr)
        , mAAudioThread() {
}

AAudioServiceStreamBase::~AAudioServiceStreamBase() {
    close();
}

aaudio_result_t AAudioServiceStreamBase::open(const aaudio::AAudioStreamRequest &request,
                     aaudio::AAudioStreamConfiguration &configurationOutput) {
    std::lock_guard<std::mutex> lock(mLockUpMessageQueue);
    if (mUpMessageQueue != nullptr) {
        return AAUDIO_ERROR_INVALID_STATE;
    } else {
        mUpMessageQueue = new SharedRingBuffer();
        return mUpMessageQueue->allocate(sizeof(AAudioServiceMessage), QUEUE_UP_CAPACITY_COMMANDS);
    }
}

aaudio_result_t AAudioServiceStreamBase::close() {
    std::lock_guard<std::mutex> lock(mLockUpMessageQueue);
    delete mUpMessageQueue;
    mUpMessageQueue = nullptr;

    return AAUDIO_OK;
}

aaudio_result_t AAudioServiceStreamBase::start() {
    sendServiceEvent(AAUDIO_SERVICE_EVENT_STARTED);
    mState = AAUDIO_STREAM_STATE_STARTED;
    mThreadEnabled.store(true);
    return mAAudioThread.start(this);
}

aaudio_result_t AAudioServiceStreamBase::pause() {

    sendCurrentTimestamp();
    mThreadEnabled.store(false);
    aaudio_result_t result = mAAudioThread.stop();
    if (result != AAUDIO_OK) {
        processError();
        return result;
    }
    sendServiceEvent(AAUDIO_SERVICE_EVENT_PAUSED);
    mState = AAUDIO_STREAM_STATE_PAUSED;
    return result;
}

aaudio_result_t AAudioServiceStreamBase::stop() {
    // TODO wait for data to be played out
    sendCurrentTimestamp();
    mThreadEnabled.store(false);
    aaudio_result_t result = mAAudioThread.stop();
    if (result != AAUDIO_OK) {
        processError();
        return result;
    }
    sendServiceEvent(AAUDIO_SERVICE_EVENT_STOPPED);
    mState = AAUDIO_STREAM_STATE_STOPPED;
    return result;
}

aaudio_result_t AAudioServiceStreamBase::flush() {
    sendServiceEvent(AAUDIO_SERVICE_EVENT_FLUSHED);
    mState = AAUDIO_STREAM_STATE_FLUSHED;
    return AAUDIO_OK;
}

// implement Runnable, periodically send timestamps to client
void AAudioServiceStreamBase::run() {
    ALOGD("AAudioServiceStreamBase::run() entering ----------------");
    TimestampScheduler timestampScheduler;
    timestampScheduler.setBurstPeriod(mFramesPerBurst, mSampleRate);
    timestampScheduler.start(AudioClock::getNanoseconds());
    int64_t nextTime = timestampScheduler.nextAbsoluteTime();
    while(mThreadEnabled.load()) {
        if (AudioClock::getNanoseconds() >= nextTime) {
            aaudio_result_t result = sendCurrentTimestamp();
            if (result != AAUDIO_OK) {
                break;
            }
            nextTime = timestampScheduler.nextAbsoluteTime();
        } else  {
            // Sleep until it is time to send the next timestamp.
            AudioClock::sleepUntilNanoTime(nextTime);
        }
    }
    ALOGD("AAudioServiceStreamBase::run() exiting ----------------");
}

void AAudioServiceStreamBase::processError() {
    sendServiceEvent(AAUDIO_SERVICE_EVENT_DISCONNECTED);
}

aaudio_result_t AAudioServiceStreamBase::sendServiceEvent(aaudio_service_event_t event,
                                               double  dataDouble,
                                               int64_t dataLong) {
    AAudioServiceMessage command;
    command.what = AAudioServiceMessage::code::EVENT;
    command.event.event = event;
    command.event.dataDouble = dataDouble;
    command.event.dataLong = dataLong;
    return writeUpMessageQueue(&command);
}

aaudio_result_t AAudioServiceStreamBase::writeUpMessageQueue(AAudioServiceMessage *command) {
    std::lock_guard<std::mutex> lock(mLockUpMessageQueue);
    if (mUpMessageQueue == nullptr) {
        ALOGE("writeUpMessageQueue(): mUpMessageQueue null! - stream not open");
        return AAUDIO_ERROR_NULL;
    }
    int32_t count = mUpMessageQueue->getFifoBuffer()->write(command, 1);
    if (count != 1) {
        ALOGE("writeUpMessageQueue(): Queue full. Did client die?");
        return AAUDIO_ERROR_WOULD_BLOCK;
    } else {
        return AAUDIO_OK;
    }
}

aaudio_result_t AAudioServiceStreamBase::sendCurrentTimestamp() {
    AAudioServiceMessage command;
    aaudio_result_t result = getFreeRunningPosition(&command.timestamp.position,
                                                    &command.timestamp.timestamp);
    if (result == AAUDIO_OK) {
    //    ALOGD("sendCurrentTimestamp(): position = %lld, nanos = %lld",
    //          (long long) command.timestamp.position,
    //          (long long) command.timestamp.timestamp);
        command.what = AAudioServiceMessage::code::TIMESTAMP;
        result = writeUpMessageQueue(&command);
    }
    return result;
}

/**
 * Get an immutable description of the in-memory queues
 * used to communicate with the underlying HAL or Service.
 */
aaudio_result_t AAudioServiceStreamBase::getDescription(AudioEndpointParcelable &parcelable) {
    // Gather information on the message queue.
    mUpMessageQueue->fillParcelable(parcelable,
                                    parcelable.mUpMessageQueueParcelable);
    return getDownDataDescription(parcelable);
}