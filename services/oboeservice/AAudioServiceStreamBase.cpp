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

#include <iomanip>
#include <iostream>
#include <mutex>

#include <media/MediaMetricsItem.h>
#include <media/TypeConverter.h>
#include <mediautils/SchedulingPolicyService.h>

#include "binding/AAudioServiceMessage.h"
#include "core/AudioGlobal.h"
#include "utility/AudioClock.h"

#include "AAudioEndpointManager.h"
#include "AAudioService.h"
#include "AAudioServiceEndpoint.h"
#include "AAudioServiceStreamBase.h"

using namespace android;  // TODO just import names needed
using namespace aaudio;   // TODO just import names needed

using content::AttributionSourceState;

static const int64_t TIMEOUT_NANOS = 3LL * 1000 * 1000 * 1000;
// If the stream is idle for more than `IDLE_TIMEOUT_NANOS`, the stream will be put into standby.
static const int64_t IDLE_TIMEOUT_NANOS = 3e9;

/**
 * Base class for streams in the service.
 * @return
 */

AAudioServiceStreamBase::AAudioServiceStreamBase(AAudioService &audioService)
        : mCommandThread("AACommand")
        , mAtomicStreamTimestamp()
        , mAudioService(audioService) {
    mMmapClient.attributionSource = AttributionSourceState();
}

AAudioServiceStreamBase::~AAudioServiceStreamBase() {
    ALOGD("%s() called", __func__);

    // May not be set if open failed.
    if (mMetricsId.size() > 0) {
        mediametrics::LogItem(mMetricsId)
                .set(AMEDIAMETRICS_PROP_EVENT, AMEDIAMETRICS_PROP_EVENT_VALUE_DTOR)
                .set(AMEDIAMETRICS_PROP_STATE, AudioGlobal_convertStreamStateToText(getState()))
                .record();
    }

    // If the stream is deleted when OPEN or in use then audio resources will leak.
    // This would indicate an internal error. So we want to find this ASAP.
    LOG_ALWAYS_FATAL_IF(!(getState() == AAUDIO_STREAM_STATE_CLOSED
                        || getState() == AAUDIO_STREAM_STATE_UNINITIALIZED),
                        "service stream %p still open, state = %d",
                        this, getState());

    // Stop the command thread before destroying.
    stopCommandThread();
}

std::string AAudioServiceStreamBase::dumpHeader() {
    return {"    T   Handle   UId   Port Run State Format Burst Chan Mask     Capacity"
            " HwFormat HwChan HwRate"};
}

std::string AAudioServiceStreamBase::dump() const {
    std::stringstream result;

    result << "    0x" << std::setfill('0') << std::setw(8) << std::hex << mHandle
           << std::dec << std::setfill(' ') ;
    result << std::setw(6) << mMmapClient.attributionSource.uid;
    result << std::setw(7) << mClientHandle;
    result << std::setw(4) << (isRunning() ? "yes" : " no");
    result << std::setw(6) << getState();
    result << std::setw(7) << getFormat();
    result << std::setw(6) << mFramesPerBurst;
    result << std::setw(5) << getSamplesPerFrame();
    result << std::setw(8) << std::hex << getChannelMask() << std::dec;
    result << std::setw(9) << getBufferCapacity();
    result << std::setw(9) << getHardwareFormat();
    result << std::setw(7) << getHardwareSamplesPerFrame();
    result << std::setw(7) << getHardwareSampleRate();

    return result.str();
}

void AAudioServiceStreamBase::logOpen(aaudio_handle_t streamHandle) {
    // This is the first log sent from the AAudio Service for a stream.
    mMetricsId = std::string(AMEDIAMETRICS_KEY_PREFIX_AUDIO_STREAM)
            + std::to_string(streamHandle);

    audio_attributes_t attributes = AAudioServiceEndpoint::getAudioAttributesFrom(this);

    // Once this item is logged by the server, the client with the same PID, UID
    // can also log properties.
    mediametrics::LogItem(mMetricsId)
        .setPid(getOwnerProcessId())
        .setUid(getOwnerUserId())
        .set(AMEDIAMETRICS_PROP_ALLOWUID, (int32_t)getOwnerUserId())
        .set(AMEDIAMETRICS_PROP_EVENT, AMEDIAMETRICS_PROP_EVENT_VALUE_OPEN)
        // the following are immutable
        .set(AMEDIAMETRICS_PROP_BUFFERCAPACITYFRAMES, (int32_t)getBufferCapacity())
        .set(AMEDIAMETRICS_PROP_BURSTFRAMES, (int32_t)getFramesPerBurst())
        .set(AMEDIAMETRICS_PROP_CHANNELCOUNT, (int32_t)getSamplesPerFrame())
        .set(AMEDIAMETRICS_PROP_CONTENTTYPE, toString(attributes.content_type).c_str())
        .set(AMEDIAMETRICS_PROP_DIRECTION,
                AudioGlobal_convertDirectionToText(getDirection()))
        .set(AMEDIAMETRICS_PROP_ENCODING, toString(getFormat()).c_str())
        .set(AMEDIAMETRICS_PROP_ROUTEDDEVICEID, (int32_t)getDeviceId())
        .set(AMEDIAMETRICS_PROP_SAMPLERATE, (int32_t)getSampleRate())
        .set(AMEDIAMETRICS_PROP_SESSIONID, (int32_t)getSessionId())
        .set(AMEDIAMETRICS_PROP_SOURCE, toString(attributes.source).c_str())
        .set(AMEDIAMETRICS_PROP_USAGE, toString(attributes.usage).c_str())
        .record();
}

aaudio_result_t AAudioServiceStreamBase::open(const aaudio::AAudioStreamRequest &request) {
    AAudioEndpointManager &mEndpointManager = AAudioEndpointManager::getInstance();
    aaudio_result_t result = AAUDIO_OK;

    mMmapClient.attributionSource = request.getAttributionSource();
    // TODO b/182392769: use attribution source util
    mMmapClient.attributionSource.uid = VALUE_OR_FATAL(
        legacy2aidl_uid_t_int32_t(IPCThreadState::self()->getCallingUid()));
    mMmapClient.attributionSource.pid = VALUE_OR_FATAL(
        legacy2aidl_pid_t_int32_t(IPCThreadState::self()->getCallingPid()));

    // Limit scope of lock to avoid recursive lock in close().
    {
        std::lock_guard<std::mutex> lock(mUpMessageQueueLock);
        if (mUpMessageQueue != nullptr) {
            ALOGE("%s() called twice", __func__);
            return AAUDIO_ERROR_INVALID_STATE;
        }

        mUpMessageQueue = std::make_shared<SharedRingBuffer>();
        result = mUpMessageQueue->allocate(sizeof(AAudioServiceMessage),
                                           QUEUE_UP_CAPACITY_COMMANDS);
        if (result != AAUDIO_OK) {
            goto error;
        }

        // This is not protected by a lock because the stream cannot be
        // referenced until the service returns a handle to the client.
        // So only one thread can open a stream.
        mServiceEndpoint = mEndpointManager.openEndpoint(mAudioService,
                                                         request);
        if (mServiceEndpoint == nullptr) {
            result = AAUDIO_ERROR_UNAVAILABLE;
            goto error;
        }
        // Save a weak pointer that we will use to access the endpoint.
        mServiceEndpointWeak = mServiceEndpoint;

        mFramesPerBurst = mServiceEndpoint->getFramesPerBurst();
        copyFrom(*mServiceEndpoint);
    }

    // Make sure this object does not get deleted before the run() method
    // can protect it by making a strong pointer.
    mCommandQueue.startWaiting();
    mThreadEnabled = true;
    incStrong(nullptr); // See run() method.
    result = mCommandThread.start(this);
    if (result != AAUDIO_OK) {
        decStrong(nullptr); // run() can't do it so we have to do it here.
        goto error;
    }
    return result;

error:
    closeAndClear();
    stopCommandThread();
    return result;
}

aaudio_result_t AAudioServiceStreamBase::close() {
    aaudio_result_t result = sendCommand(CLOSE, nullptr, true /*waitForReply*/, TIMEOUT_NANOS);
    if (result == AAUDIO_ERROR_ALREADY_CLOSED) {
        // AAUDIO_ERROR_ALREADY_CLOSED is not a really error but just indicate the stream has
        // already been closed. In that case, there is no need to close the stream once more.
        ALOGD("The stream(%d) is already closed", mHandle);
        return AAUDIO_OK;
    }

    stopCommandThread();

    return result;
}

aaudio_result_t AAudioServiceStreamBase::close_l() {
    if (getState() == AAUDIO_STREAM_STATE_CLOSED) {
        return AAUDIO_ERROR_ALREADY_CLOSED;
    }

    // This will stop the stream, just in case it was not already stopped.
    stop_l();

    return closeAndClear();
}

aaudio_result_t AAudioServiceStreamBase::startDevice() {
    mClientHandle = AUDIO_PORT_HANDLE_NONE;
    sp<AAudioServiceEndpoint> endpoint = mServiceEndpointWeak.promote();
    if (endpoint == nullptr) {
        ALOGE("%s() has no endpoint", __func__);
        return AAUDIO_ERROR_INVALID_STATE;
    }
    return endpoint->startStream(this, &mClientHandle);
}

/**
 * Start the flow of audio data.
 *
 * An AAUDIO_SERVICE_EVENT_STARTED will be sent to the client when complete.
 */
aaudio_result_t AAudioServiceStreamBase::start() {
    return sendCommand(START, nullptr, true /*waitForReply*/, TIMEOUT_NANOS);
}

aaudio_result_t AAudioServiceStreamBase::start_l() {
    const int64_t beginNs = AudioClock::getNanoseconds();
    aaudio_result_t result = AAUDIO_OK;

    if (auto state = getState();
        state == AAUDIO_STREAM_STATE_CLOSED || isDisconnected_l()) {
        ALOGW("%s() already CLOSED, returns INVALID_STATE, handle = %d",
                __func__, getHandle());
        return AAUDIO_ERROR_INVALID_STATE;
    }

    if (mStandby) {
        ALOGW("%s() the stream is standby, return ERROR_STANDBY, "
              "expecting the client call exitStandby before start", __func__);
        return AAUDIO_ERROR_STANDBY;
    }

    mediametrics::Defer defer([&] {
        mediametrics::LogItem(mMetricsId)
            .set(AMEDIAMETRICS_PROP_EVENT, AMEDIAMETRICS_PROP_EVENT_VALUE_START)
            .set(AMEDIAMETRICS_PROP_EXECUTIONTIMENS, (int64_t)(AudioClock::getNanoseconds() - beginNs))
            .set(AMEDIAMETRICS_PROP_STATE, AudioGlobal_convertStreamStateToText(getState()))
            .set(AMEDIAMETRICS_PROP_STATUS, (int32_t)result)
            .record(); });

    if (isRunning()) {
        return result;
    }

    setFlowing(false);
    setSuspended(false);

    // Start with fresh presentation timestamps.
    mAtomicStreamTimestamp.clear();

    mClientHandle = AUDIO_PORT_HANDLE_NONE;
    result = startDevice();
    if (result != AAUDIO_OK) goto error;

    // This should happen at the end of the start.
    sendServiceEvent(AAUDIO_SERVICE_EVENT_STARTED, static_cast<int64_t>(mClientHandle));
    setState(AAUDIO_STREAM_STATE_STARTED);

    return result;

error:
    disconnect_l();
    return result;
}

aaudio_result_t AAudioServiceStreamBase::pause() {
    return sendCommand(PAUSE, nullptr, true /*waitForReply*/, TIMEOUT_NANOS);
}

aaudio_result_t AAudioServiceStreamBase::pause_l() {
    aaudio_result_t result = AAUDIO_OK;
    if (!isRunning()) {
        return result;
    }
    const int64_t beginNs = AudioClock::getNanoseconds();

    mediametrics::Defer defer([&] {
        mediametrics::LogItem(mMetricsId)
            .set(AMEDIAMETRICS_PROP_EVENT, AMEDIAMETRICS_PROP_EVENT_VALUE_PAUSE)
            .set(AMEDIAMETRICS_PROP_EXECUTIONTIMENS, (int64_t)(AudioClock::getNanoseconds() - beginNs))
            .set(AMEDIAMETRICS_PROP_STATE, AudioGlobal_convertStreamStateToText(getState()))
            .set(AMEDIAMETRICS_PROP_STATUS, (int32_t)result)
            .record(); });

    sp<AAudioServiceEndpoint> endpoint = mServiceEndpointWeak.promote();
    if (endpoint == nullptr) {
        ALOGE("%s() has no endpoint", __func__);
        result =  AAUDIO_ERROR_INVALID_STATE; // for MediaMetric tracking
        return result;
    }
    result = endpoint->stopStream(this, mClientHandle);
    if (result != AAUDIO_OK) {
        ALOGE("%s() mServiceEndpoint returned %d, %s", __func__, result, getTypeText());
        disconnect_l(); // TODO should we return or pause Base first?
    }

    sendServiceEvent(AAUDIO_SERVICE_EVENT_PAUSED);
    setState(AAUDIO_STREAM_STATE_PAUSED);
    return result;
}

aaudio_result_t AAudioServiceStreamBase::stop() {
    return sendCommand(STOP, nullptr, true /*waitForReply*/, TIMEOUT_NANOS);
}

aaudio_result_t AAudioServiceStreamBase::stop_l() {
    aaudio_result_t result = AAUDIO_OK;
    if (!isRunning()) {
        return result;
    }
    const int64_t beginNs = AudioClock::getNanoseconds();

    mediametrics::Defer defer([&] {
        mediametrics::LogItem(mMetricsId)
            .set(AMEDIAMETRICS_PROP_EVENT, AMEDIAMETRICS_PROP_EVENT_VALUE_STOP)
            .set(AMEDIAMETRICS_PROP_EXECUTIONTIMENS, (int64_t)(AudioClock::getNanoseconds() - beginNs))
            .set(AMEDIAMETRICS_PROP_STATE, AudioGlobal_convertStreamStateToText(getState()))
            .set(AMEDIAMETRICS_PROP_STATUS, (int32_t)result)
            .record(); });

    setState(AAUDIO_STREAM_STATE_STOPPING);

    if (result != AAUDIO_OK) {
        disconnect_l();
        return result;
    }

    sp<AAudioServiceEndpoint> endpoint = mServiceEndpointWeak.promote();
    if (endpoint == nullptr) {
        ALOGE("%s() has no endpoint", __func__);
        result =  AAUDIO_ERROR_INVALID_STATE; // for MediaMetric tracking
        return result;
    }
    // TODO wait for data to be played out
    result = endpoint->stopStream(this, mClientHandle);
    if (result != AAUDIO_OK) {
        ALOGE("%s() stopStream returned %d, %s", __func__, result, getTypeText());
        disconnect_l();
        // TODO what to do with result here?
    }

    sendServiceEvent(AAUDIO_SERVICE_EVENT_STOPPED);
    setState(AAUDIO_STREAM_STATE_STOPPED);
    return result;
}

aaudio_result_t AAudioServiceStreamBase::flush() {
    return sendCommand(FLUSH, nullptr, true /*waitForReply*/, TIMEOUT_NANOS);
}

aaudio_result_t AAudioServiceStreamBase::flush_l() {
    aaudio_result_t result = AAudio_isFlushAllowed(getState());
    if (result != AAUDIO_OK) {
        return result;
    }
    const int64_t beginNs = AudioClock::getNanoseconds();

    mediametrics::Defer defer([&] {
        mediametrics::LogItem(mMetricsId)
            .set(AMEDIAMETRICS_PROP_EVENT, AMEDIAMETRICS_PROP_EVENT_VALUE_FLUSH)
            .set(AMEDIAMETRICS_PROP_EXECUTIONTIMENS, (int64_t)(AudioClock::getNanoseconds() - beginNs))
            .set(AMEDIAMETRICS_PROP_STATE, AudioGlobal_convertStreamStateToText(getState()))
            .set(AMEDIAMETRICS_PROP_STATUS, (int32_t)result)
            .record(); });

    // Data will get flushed when the client receives the FLUSHED event.
    sendServiceEvent(AAUDIO_SERVICE_EVENT_FLUSHED);
    setState(AAUDIO_STREAM_STATE_FLUSHED);
    return AAUDIO_OK;
}

// implement Runnable, periodically send timestamps to client and process commands from queue.
__attribute__((no_sanitize("integer")))
void AAudioServiceStreamBase::run() {
    ALOGD("%s() %s entering >>>>>>>>>>>>>> COMMANDS", __func__, getTypeText());
    // Hold onto the ref counted stream until the end.
    android::sp<AAudioServiceStreamBase> holdStream(this);
    TimestampScheduler timestampScheduler;
    int64_t nextTimestampReportTime;
    int64_t nextDataReportTime;
    int64_t standbyTime = AudioClock::getNanoseconds() + IDLE_TIMEOUT_NANOS;
    // Balance the incStrong from when the thread was launched.
    holdStream->decStrong(nullptr);

    // Taking mLock while starting the thread. All the operation must be able to
    // run with holding the lock.
    std::scoped_lock<std::mutex> _l(mLock);

    int32_t loopCount = 0;
    while (mThreadEnabled.load()) {
        loopCount++;
        int64_t timeoutNanos = -1;
        if (isDisconnected_l()) {
            if (!isStandby_l()) {
                // If the stream is disconnected but not in standby mode, wait until standby time.
                timeoutNanos = standbyTime - AudioClock::getNanoseconds();
                timeoutNanos = std::max<int64_t>(0, timeoutNanos);
            } // else {
                // If the stream is disconnected and in standby mode, keep `timeoutNanos` as
                // -1 to wait forever until next command as the stream can only be closed.
            // }
        } else if (isRunning() || (isIdle_l() && !isStandby_l())) {
            timeoutNanos = (isRunning() ? std::min(nextTimestampReportTime, nextDataReportTime)
                                        : standbyTime) - AudioClock::getNanoseconds();
            timeoutNanos = std::max<int64_t>(0, timeoutNanos);
        }

        auto command = mCommandQueue.waitForCommand(timeoutNanos);
        if (!mThreadEnabled) {
            // Break the loop if the thread is disabled.
            break;
        }

        if (isRunning() && !isDisconnected_l()) {
            auto currentTimestamp = AudioClock::getNanoseconds();
            if (currentTimestamp >= nextDataReportTime) {
                reportData_l();
                nextDataReportTime = nextDataReportTime_l();
            }
            if (currentTimestamp >= nextTimestampReportTime) {
                // It is time to update timestamp.
                if (sendCurrentTimestamp_l() != AAUDIO_OK) {
                    ALOGE("Failed to send current timestamp, stop updating timestamp");
                    disconnect_l();
                }
                nextTimestampReportTime = timestampScheduler.nextAbsoluteTime();
            }
        }
        if ((isIdle_l() || isDisconnected_l()) && AudioClock::getNanoseconds() >= standbyTime) {
            aaudio_result_t result = standby_l();
            if (result != AAUDIO_OK) {
                // If standby failed because of the function is not implemented, there is no
                // need to retry. Otherwise, retry standby later.
                ALOGW("Failed to enter standby, error=%d", result);
                standbyTime = result == AAUDIO_ERROR_UNIMPLEMENTED
                        ? std::numeric_limits<int64_t>::max()
                        : AudioClock::getNanoseconds() + IDLE_TIMEOUT_NANOS;
            }
        }

        if (command != nullptr) {
            std::scoped_lock<std::mutex> _commandLock(command->lock);
            switch (command->operationCode) {
                case START:
                    command->result = start_l();
                    timestampScheduler.setBurstPeriod(mFramesPerBurst, getSampleRate());
                    timestampScheduler.start(AudioClock::getNanoseconds());
                    nextTimestampReportTime = timestampScheduler.nextAbsoluteTime();
                    nextDataReportTime = nextDataReportTime_l();
                    break;
                case PAUSE:
                    command->result = pause_l();
                    standbyTime = AudioClock::getNanoseconds() + IDLE_TIMEOUT_NANOS;
                    break;
                case STOP:
                    command->result = stop_l();
                    standbyTime = AudioClock::getNanoseconds() + IDLE_TIMEOUT_NANOS;
                    break;
                case FLUSH:
                    command->result = flush_l();
                    break;
                case CLOSE:
                    command->result = close_l();
                    break;
                case DISCONNECT:
                    disconnect_l();
                    break;
                case REGISTER_AUDIO_THREAD: {
                    auto param = (RegisterAudioThreadParam *) command->parameter.get();
                    command->result =
                            param == nullptr ? AAUDIO_ERROR_ILLEGAL_ARGUMENT
                                             : registerAudioThread_l(param->mOwnerPid,
                                                                     param->mClientThreadId,
                                                                     param->mPriority);
                }
                    break;
                case UNREGISTER_AUDIO_THREAD: {
                    auto param = (UnregisterAudioThreadParam *) command->parameter.get();
                    command->result =
                            param == nullptr ? AAUDIO_ERROR_ILLEGAL_ARGUMENT
                                             : unregisterAudioThread_l(param->mClientThreadId);
                }
                    break;
                case GET_DESCRIPTION: {
                    auto param = (GetDescriptionParam *) command->parameter.get();
                    command->result = param == nullptr ? AAUDIO_ERROR_ILLEGAL_ARGUMENT
                                                        : getDescription_l(param->mParcelable);
                }
                    break;
                case EXIT_STANDBY: {
                    auto param = (ExitStandbyParam *) command->parameter.get();
                    command->result = param == nullptr ? AAUDIO_ERROR_ILLEGAL_ARGUMENT
                                                       : exitStandby_l(param->mParcelable);
                    standbyTime = AudioClock::getNanoseconds() + IDLE_TIMEOUT_NANOS;
                } break;
                default:
                    ALOGE("Invalid command op code: %d", command->operationCode);
                    break;
            }
            if (command->isWaitingForReply) {
                command->isWaitingForReply = false;
                command->conditionVariable.notify_one();
            }
        }
    }
    ALOGD("%s() %s exiting after %d loops <<<<<<<<<<<<<< COMMANDS",
          __func__, getTypeText(), loopCount);
}

void AAudioServiceStreamBase::disconnect() {
    sendCommand(DISCONNECT);
}

void AAudioServiceStreamBase::disconnect_l() {
    if (!isDisconnected_l() && getState() != AAUDIO_STREAM_STATE_CLOSED) {

        mediametrics::LogItem(mMetricsId)
            .set(AMEDIAMETRICS_PROP_EVENT, AMEDIAMETRICS_PROP_EVENT_VALUE_DISCONNECT)
            .set(AMEDIAMETRICS_PROP_STATE, AudioGlobal_convertStreamStateToText(getState()))
            .record();

        sendServiceEvent(AAUDIO_SERVICE_EVENT_DISCONNECTED);
        setDisconnected_l(true);
    }
}

aaudio_result_t AAudioServiceStreamBase::registerAudioThread(pid_t clientThreadId, int priority) {
    const pid_t ownerPid = IPCThreadState::self()->getCallingPid(); // TODO review
    return sendCommand(REGISTER_AUDIO_THREAD,
            std::make_shared<RegisterAudioThreadParam>(ownerPid, clientThreadId, priority),
            true /*waitForReply*/,
            TIMEOUT_NANOS);
}

aaudio_result_t AAudioServiceStreamBase::registerAudioThread_l(
        pid_t ownerPid, pid_t clientThreadId, int priority) {
    aaudio_result_t result = AAUDIO_OK;
    if (getRegisteredThread() != AAudioServiceStreamBase::ILLEGAL_THREAD_ID) {
        ALOGE("AAudioService::registerAudioThread(), thread already registered");
        result = AAUDIO_ERROR_INVALID_STATE;
    } else {
        setRegisteredThread(clientThreadId);
        int err = android::requestPriority(ownerPid, clientThreadId,
                                           priority, true /* isForApp */);
        if (err != 0) {
            ALOGE("AAudioService::registerAudioThread(%d) failed, errno = %d, priority = %d",
                  clientThreadId, errno, priority);
            result = AAUDIO_ERROR_INTERNAL;
        }
    }
    return result;
}

aaudio_result_t AAudioServiceStreamBase::unregisterAudioThread(pid_t clientThreadId) {
    return sendCommand(UNREGISTER_AUDIO_THREAD,
            std::make_shared<UnregisterAudioThreadParam>(clientThreadId),
            true /*waitForReply*/,
            TIMEOUT_NANOS);
}

aaudio_result_t AAudioServiceStreamBase::unregisterAudioThread_l(pid_t clientThreadId) {
    aaudio_result_t result = AAUDIO_OK;
    if (getRegisteredThread() != clientThreadId) {
        ALOGE("%s(), wrong thread", __func__);
        result = AAUDIO_ERROR_ILLEGAL_ARGUMENT;
    } else {
        setRegisteredThread(0);
    }
    return result;
}

void AAudioServiceStreamBase::setState(aaudio_stream_state_t state) {
    // CLOSED is a final state.
    if (mState != AAUDIO_STREAM_STATE_CLOSED) {
        mState = state;
    } else {
        ALOGW_IF(mState != state, "%s(%d) when already CLOSED", __func__, state);
    }
}

aaudio_result_t AAudioServiceStreamBase::sendServiceEvent(aaudio_service_event_t event,
                                                          double  dataDouble) {
    AAudioServiceMessage command;
    command.what = AAudioServiceMessage::code::EVENT;
    command.event.event = event;
    command.event.dataDouble = dataDouble;
    return writeUpMessageQueue(&command);
}

aaudio_result_t AAudioServiceStreamBase::sendServiceEvent(aaudio_service_event_t event,
                                                          int64_t dataLong) {
    AAudioServiceMessage command;
    command.what = AAudioServiceMessage::code::EVENT;
    command.event.event = event;
    command.event.dataLong = dataLong;
    return writeUpMessageQueue(&command);
}

bool AAudioServiceStreamBase::isUpMessageQueueBusy() {
    std::lock_guard<std::mutex> lock(mUpMessageQueueLock);
    if (mUpMessageQueue == nullptr) {
        ALOGE("%s(): mUpMessageQueue null! - stream not open", __func__);
        return true;
    }
    // Is it half full or more
    return mUpMessageQueue->getFractionalFullness() >= 0.5;
}

aaudio_result_t AAudioServiceStreamBase::writeUpMessageQueue(AAudioServiceMessage *command) {
    std::lock_guard<std::mutex> lock(mUpMessageQueueLock);
    if (mUpMessageQueue == nullptr) {
        ALOGE("%s(): mUpMessageQueue null! - stream not open", __func__);
        return AAUDIO_ERROR_NULL;
    }
    int32_t count = mUpMessageQueue->getFifoBuffer()->write(command, 1);
    if (count != 1) {
        ALOGW("%s(): Queue full. Did client stop? Suspending stream. what = %u, %s",
              __func__, static_cast<unsigned>(command->what), getTypeText());
        setSuspended(true);
        return AAUDIO_ERROR_WOULD_BLOCK;
    } else {
        if (isSuspended()) {
            ALOGW("%s(): Queue no longer full. Un-suspending the stream.", __func__);
            setSuspended(false);
        }
        return AAUDIO_OK;
    }
}

aaudio_result_t AAudioServiceStreamBase::sendXRunCount(int32_t xRunCount) {
    return sendServiceEvent(AAUDIO_SERVICE_EVENT_XRUN, (int64_t) xRunCount);
}

aaudio_result_t AAudioServiceStreamBase::sendCurrentTimestamp_l() {
    AAudioServiceMessage command;
    // It is not worth filling up the queue with timestamps.
    // That can cause the stream to get suspended.
    // So just drop the timestamp if the queue is getting full.
    if (isUpMessageQueueBusy()) {
        return AAUDIO_OK;
    }

    // Send a timestamp for the clock model.
    aaudio_result_t result = getFreeRunningPosition_l(&command.timestamp.position,
                                                      &command.timestamp.timestamp);
    if (result == AAUDIO_OK) {
        ALOGV("%s() SERVICE  %8lld at %lld", __func__,
              (long long) command.timestamp.position,
              (long long) command.timestamp.timestamp);
        command.what = AAudioServiceMessage::code::TIMESTAMP_SERVICE;
        result = writeUpMessageQueue(&command);

        if (result == AAUDIO_OK) {
            // Send a hardware timestamp for presentation time.
            result = getHardwareTimestamp_l(&command.timestamp.position,
                                            &command.timestamp.timestamp);
            if (result == AAUDIO_OK) {
                ALOGV("%s() HARDWARE %8lld at %lld", __func__,
                      (long long) command.timestamp.position,
                      (long long) command.timestamp.timestamp);
                command.what = AAudioServiceMessage::code::TIMESTAMP_HARDWARE;
                result = writeUpMessageQueue(&command);
            }
        }
    }

    if (result == AAUDIO_ERROR_UNAVAILABLE) { // TODO review best error code
        result = AAUDIO_OK; // just not available yet, try again later
    }
    return result;
}

/**
 * Get an immutable description of the in-memory queues
 * used to communicate with the underlying HAL or Service.
 */
aaudio_result_t AAudioServiceStreamBase::getDescription(AudioEndpointParcelable &parcelable) {
    return sendCommand(
            GET_DESCRIPTION,
            std::make_shared<GetDescriptionParam>(&parcelable),
            true /*waitForReply*/,
            TIMEOUT_NANOS);
}

aaudio_result_t AAudioServiceStreamBase::getDescription_l(AudioEndpointParcelable* parcelable) {
    {
        std::lock_guard<std::mutex> lock(mUpMessageQueueLock);
        if (mUpMessageQueue == nullptr) {
            ALOGE("%s(): mUpMessageQueue null! - stream not open", __func__);
            return AAUDIO_ERROR_NULL;
        }
        // Gather information on the message queue.
        mUpMessageQueue->fillParcelable(parcelable,
                                        parcelable->mUpMessageQueueParcelable);
    }
    return getAudioDataDescription_l(parcelable);
}

aaudio_result_t AAudioServiceStreamBase::exitStandby(AudioEndpointParcelable *parcelable) {
    auto command = std::make_shared<AAudioCommand>(
            EXIT_STANDBY,
            std::make_shared<ExitStandbyParam>(parcelable),
            true /*waitForReply*/,
            TIMEOUT_NANOS);
    return mCommandQueue.sendCommand(command);
}

void AAudioServiceStreamBase::onVolumeChanged(float volume) {
    sendServiceEvent(AAUDIO_SERVICE_EVENT_VOLUME, volume);
}

aaudio_result_t AAudioServiceStreamBase::sendCommand(aaudio_command_opcode opCode,
                                                     std::shared_ptr<AAudioCommandParam> param,
                                                     bool waitForReply,
                                                     int64_t timeoutNanos) {
    return mCommandQueue.sendCommand(std::make_shared<AAudioCommand>(
            opCode, param, waitForReply, timeoutNanos));
}

aaudio_result_t AAudioServiceStreamBase::closeAndClear() {
    aaudio_result_t result = AAUDIO_OK;
    sp<AAudioServiceEndpoint> endpoint = mServiceEndpointWeak.promote();
    if (endpoint == nullptr) {
        result = AAUDIO_ERROR_INVALID_STATE;
    } else {
        endpoint->unregisterStream(this);
        AAudioEndpointManager &endpointManager = AAudioEndpointManager::getInstance();
        endpointManager.closeEndpoint(endpoint);

        // AAudioService::closeStream() prevents two threads from closing at the same time.
        mServiceEndpoint.clear(); // endpoint will hold the pointer after this method returns.
    }

    setState(AAUDIO_STREAM_STATE_CLOSED);

    mediametrics::LogItem(mMetricsId)
        .set(AMEDIAMETRICS_PROP_EVENT, AMEDIAMETRICS_PROP_EVENT_VALUE_CLOSE)
        .record();
    return result;
}

void AAudioServiceStreamBase::stopCommandThread() {
    bool threadEnabled = true;
    if (mThreadEnabled.compare_exchange_strong(threadEnabled, false)) {
        mCommandQueue.stopWaiting();
        mCommandThread.stop();
    }
}
