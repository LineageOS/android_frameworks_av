/*
 * Copyright 2015 The Android Open Source Project
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

#define LOG_TAG "OboeAudio"
//#define LOG_NDEBUG 0
#include <utils/Log.h>

#include <stdint.h>
#include <oboe/OboeAudio.h>

#include "AudioStreamBuilder.h"
#include "AudioStream.h"
#include "AudioClock.h"

using namespace oboe;

/*
 * AudioStream
 */
AudioStream::AudioStream() {
}

oboe_result_t AudioStream::open(const AudioStreamBuilder& builder)
{
    // TODO validate parameters.
    // Copy parameters from the Builder because the Builder may be deleted after this call.
    mSamplesPerFrame = builder.getSamplesPerFrame();
    mSampleRate = builder.getSampleRate();
    mDeviceId = builder.getDeviceId();
    mFormat = builder.getFormat();
    mSharingMode = builder.getSharingMode();
    return OBOE_OK;
}

AudioStream::~AudioStream() {
    close();
}

oboe_result_t AudioStream::waitForStateTransition(oboe_stream_state_t startingState,
                                               oboe_stream_state_t endingState,
                                               oboe_nanoseconds_t timeoutNanoseconds)
{
    oboe_stream_state_t state = getState();
    oboe_stream_state_t nextState = state;
    if (state == startingState && state != endingState) {
        oboe_result_t result = waitForStateChange(state, &nextState, timeoutNanoseconds);
        if (result != OBOE_OK) {
            return result;
        }
    }
// It's OK if the expected transition has already occurred.
// But if we reach an unexpected state then that is an error.
    if (nextState != endingState) {
        return OBOE_ERROR_UNEXPECTED_STATE;
    } else {
        return OBOE_OK;
    }
}

oboe_result_t AudioStream::waitForStateChange(oboe_stream_state_t currentState,
                                                oboe_stream_state_t *nextState,
                                                oboe_nanoseconds_t timeoutNanoseconds)
{
    // TODO replace this when similar functionality added to AudioTrack.cpp
    oboe_nanoseconds_t durationNanos = 20 * OBOE_NANOS_PER_MILLISECOND;
    oboe_stream_state_t state = getState();
    while (state == currentState && timeoutNanoseconds > 0) {
        if (durationNanos > timeoutNanoseconds) {
            durationNanos = timeoutNanoseconds;
        }
        AudioClock::sleepForNanos(durationNanos);
        timeoutNanoseconds -= durationNanos;

        oboe_result_t result = updateState();
        if (result != OBOE_OK) {
            return result;
        }

        state = getState();
    }
    if (nextState != NULL) {
        *nextState = state;
    }
    return (state == currentState) ? OBOE_ERROR_TIMEOUT : OBOE_OK;
}

oboe_result_t AudioStream::createThread(oboe_nanoseconds_t periodNanoseconds,
                                     void *(*startRoutine)(void *), void *arg)
{
    if (mHasThread) {
        return OBOE_ERROR_INVALID_STATE;
    }
    if (startRoutine == NULL) {
        return OBOE_ERROR_NULL;
    }
    int err = pthread_create(&mThread, NULL, startRoutine, arg);
    if (err != 0) {
        return OBOE_ERROR_INTERNAL;
    } else {
        mHasThread = true;
        return OBOE_OK;
    }
}

oboe_result_t AudioStream::joinThread(void **returnArg, oboe_nanoseconds_t timeoutNanoseconds)
{
    if (!mHasThread) {
        return OBOE_ERROR_INVALID_STATE;
    }
#if 0
    // TODO implement equivalent of pthread_timedjoin_np()
    struct timespec abstime;
    int err = pthread_timedjoin_np(mThread, returnArg, &abstime);
#else
    int err = pthread_join(mThread, returnArg);
#endif
    mHasThread = false;
    // TODO Just leaked a thread?
    return err ? OBOE_ERROR_INTERNAL : OBOE_OK;
}

