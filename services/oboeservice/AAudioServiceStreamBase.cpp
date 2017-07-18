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

#define LOG_TAG "AAudioServiceStreamBase"
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
    mMmapClient.clientUid = -1;
    mMmapClient.clientPid = -1;
    mMmapClient.packageName = String16("");
}

AAudioServiceStreamBase::~AAudioServiceStreamBase() {
    ALOGD("AAudioServiceStreamBase::~AAudioServiceStreamBase() destroying %p", this);
    // If the stream is deleted when OPEN or in use then audio resources will leak.
    // This would indicate an internal error. So we want to find this ASAP.
    LOG_ALWAYS_FATAL_IF(!(mState == AAUDIO_STREAM_STATE_CLOSED
                        || mState == AAUDIO_STREAM_STATE_UNINITIALIZED
                        || mState == AAUDIO_STREAM_STATE_DISCONNECTED),
                        "service stream still open, state = %d", mState);
}

std::string AAudioServiceStreamBase::dump() const {
    std::stringstream result;

    result << "      -------- handle = 0x" << std::hex << mHandle << std::dec << "\n";
    result << "      state          = " << AAudio_convertStreamStateToText(mState) << "\n";
    result << "      format         = " << mAudioFormat << "\n";
    result << "      framesPerBurst = " << mFramesPerBurst << "\n";
    result << "      channelCount   = " << mSamplesPerFrame << "\n";
    result << "      capacityFrames = " << mCapacityInFrames << "\n";
    result << "      owner uid      = " << mMmapClient.clientUid << "\n";

    return result.str();
}

aaudio_result_t AAudioServiceStreamBase::open(const aaudio::AAudioStreamRequest &request,
                     aaudio::AAudioStreamConfiguration &configurationOutput) {

    mMmapClient.clientUid = request.getUserId();
    mMmapClient.clientPid = request.getProcessId();
    mMmapClient.packageName.setTo(String16("")); // FIXME what should we do here?

    std::lock_guard<std::mutex> lock(mLockUpMessageQueue);
    if (mUpMessageQueue != nullptr) {
        return AAUDIO_ERROR_INVALID_STATE;
    } else {
        mUpMessageQueue = new SharedRingBuffer();
        return mUpMessageQueue->allocate(sizeof(AAudioServiceMessage), QUEUE_UP_CAPACITY_COMMANDS);
    }
}

aaudio_result_t AAudioServiceStreamBase::close() {
    if (mState != AAUDIO_STREAM_STATE_CLOSED) {
        stopTimestampThread();
        std::lock_guard<std::mutex> lock(mLockUpMessageQueue);
        delete mUpMessageQueue;
        mUpMessageQueue = nullptr;
        mState = AAUDIO_STREAM_STATE_CLOSED;
    }
    return AAUDIO_OK;
}

aaudio_result_t AAudioServiceStreamBase::start() {
    if (isRunning()) {
        return AAUDIO_OK;
    }
    sendServiceEvent(AAUDIO_SERVICE_EVENT_STARTED);
    mState = AAUDIO_STREAM_STATE_STARTED;
    mThreadEnabled.store(true);
    return mAAudioThread.start(this);
}

aaudio_result_t AAudioServiceStreamBase::pause() {
    aaudio_result_t result = AAUDIO_OK;
    if (!isRunning()) {
        return result;
    }
    sendCurrentTimestamp();
    mThreadEnabled.store(false);
    result = mAAudioThread.stop();
    if (result != AAUDIO_OK) {
        disconnect();
        return result;
    }
    sendServiceEvent(AAUDIO_SERVICE_EVENT_PAUSED);
    mState = AAUDIO_STREAM_STATE_PAUSED;
    return result;
}

aaudio_result_t AAudioServiceStreamBase::stop() {
    aaudio_result_t result = AAUDIO_OK;
    if (!isRunning()) {
        return result;
    }
    // TODO wait for data to be played out
    sendCurrentTimestamp(); // warning - this calls a virtual function
    result = stopTimestampThread();
    if (result != AAUDIO_OK) {
        disconnect();
        return result;
    }
    sendServiceEvent(AAUDIO_SERVICE_EVENT_STOPPED);
    mState = AAUDIO_STREAM_STATE_STOPPED;
    return result;
}

aaudio_result_t AAudioServiceStreamBase::stopTimestampThread() {
    aaudio_result_t result = AAUDIO_OK;
    // clear flag that tells thread to loop
    if (mThreadEnabled.exchange(false)) {
        result = mAAudioThread.stop();
    }
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
            // TODO Wait for a signal with a timeout so that we can stop more quickly.
            AudioClock::sleepUntilNanoTime(nextTime);
        }
    }
    ALOGD("AAudioServiceStreamBase::run() exiting ----------------");
}

void AAudioServiceStreamBase::disconnect() {
    if (mState != AAUDIO_STREAM_STATE_DISCONNECTED) {
        sendServiceEvent(AAUDIO_SERVICE_EVENT_DISCONNECTED);
        mState = AAUDIO_STREAM_STATE_DISCONNECTED;
    }
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
    } else if (result == AAUDIO_ERROR_UNAVAILABLE) {
        result = AAUDIO_OK; // just not available yet, try again later
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
