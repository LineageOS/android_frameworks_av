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

#define LOG_TAG "AAudio"
//#define LOG_NDEBUG 0
#include <utils/Log.h>

#include <stdint.h>
#include <aaudio/AAudioDefinitions.h>

#include "IsochronousClockModel.h"

#define MIN_LATENESS_NANOS (10 * AAUDIO_NANOS_PER_MICROSECOND)

using namespace android;
using namespace aaudio;

IsochronousClockModel::IsochronousClockModel()
        : mSampleRate(48000)
        , mFramesPerBurst(64)
        , mMaxLatenessInNanos(0)
        , mMarkerFramePosition(0)
        , mMarkerNanoTime(0)
        , mState(STATE_STOPPED)
{
}

IsochronousClockModel::~IsochronousClockModel() {
}

void IsochronousClockModel::start(aaudio_nanoseconds_t nanoTime)
{
    mMarkerNanoTime = nanoTime;
    mState = STATE_STARTING;
}

void IsochronousClockModel::stop(aaudio_nanoseconds_t nanoTime)
{
    mMarkerNanoTime = nanoTime;
    mMarkerFramePosition = convertTimeToPosition(nanoTime); // TODO should we do this?
    mState = STATE_STOPPED;
}

void IsochronousClockModel::processTimestamp(aaudio_position_frames_t framePosition,
                                             aaudio_nanoseconds_t nanoTime) {
    int64_t framesDelta = framePosition - mMarkerFramePosition;
    int64_t nanosDelta = nanoTime - mMarkerNanoTime;
    if (nanosDelta < 1000) {
        return;
    }

//    ALOGI("processTimestamp() - mMarkerFramePosition = %lld at mMarkerNanoTime %llu",
//         (long long)mMarkerFramePosition,
//         (long long)mMarkerNanoTime);
//    ALOGI("processTimestamp() - framePosition = %lld at nanoTime %llu",
//         (long long)framePosition,
//         (long long)nanoTime);

    int64_t expectedNanosDelta = convertDeltaPositionToTime(framesDelta);
//    ALOGI("processTimestamp() - expectedNanosDelta = %lld, nanosDelta = %llu",
//         (long long)expectedNanosDelta,
//         (long long)nanosDelta);

//    ALOGI("processTimestamp() - mSampleRate = %d", mSampleRate);
//    ALOGI("processTimestamp() - mState = %d", mState);
    switch (mState) {
    case STATE_STOPPED:
        break;
    case STATE_STARTING:
        mMarkerFramePosition = framePosition;
        mMarkerNanoTime = nanoTime;
        mState = STATE_SYNCING;
        break;
    case STATE_SYNCING:
        // This will handle a burst of rapid consumption in the beginning.
        if (nanosDelta < expectedNanosDelta) {
            mMarkerFramePosition = framePosition;
            mMarkerNanoTime = nanoTime;
        } else {
            ALOGI("processTimestamp() - advance to STATE_RUNNING");
            mState = STATE_RUNNING;
        }
        break;
    case STATE_RUNNING:
        if (nanosDelta < expectedNanosDelta) {
            // Earlier than expected timestamp.
            // This data is probably more accurate so use it.
            // or we may be drifting due to a slow HW clock.
            mMarkerFramePosition = framePosition;
            mMarkerNanoTime = nanoTime;
            ALOGI("processTimestamp() - STATE_RUNNING - %d < %d micros - EARLY",
                 (int) (nanosDelta / 1000), (int)(expectedNanosDelta / 1000));
        } else if (nanosDelta > (expectedNanosDelta + mMaxLatenessInNanos)) {
            // Later than expected timestamp.
            mMarkerFramePosition = framePosition;
            mMarkerNanoTime = nanoTime - mMaxLatenessInNanos;
            ALOGI("processTimestamp() - STATE_RUNNING - %d > %d + %d micros - LATE",
                 (int) (nanosDelta / 1000), (int)(expectedNanosDelta / 1000),
                 (int) (mMaxLatenessInNanos / 1000));
        }
        break;
    default:
        break;
    }
    ++mTimestampCount;
}

void IsochronousClockModel::setSampleRate(int32_t sampleRate) {
    mSampleRate = sampleRate;
    update();
}

void IsochronousClockModel::setFramesPerBurst(int32_t framesPerBurst) {
    mFramesPerBurst = framesPerBurst;
    update();
}

void IsochronousClockModel::update() {
    int64_t nanosLate = convertDeltaPositionToTime(mFramesPerBurst); // uses mSampleRate
    mMaxLatenessInNanos = (nanosLate > MIN_LATENESS_NANOS) ? nanosLate : MIN_LATENESS_NANOS;
}

aaudio_nanoseconds_t IsochronousClockModel::convertDeltaPositionToTime(
        aaudio_position_frames_t framesDelta) const {
    return (AAUDIO_NANOS_PER_SECOND * framesDelta) / mSampleRate;
}

int64_t IsochronousClockModel::convertDeltaTimeToPosition(aaudio_nanoseconds_t nanosDelta) const {
    return (mSampleRate * nanosDelta) / AAUDIO_NANOS_PER_SECOND;
}

aaudio_nanoseconds_t IsochronousClockModel::convertPositionToTime(
        aaudio_position_frames_t framePosition) const {
    if (mState == STATE_STOPPED) {
        return mMarkerNanoTime;
    }
    aaudio_position_frames_t nextBurstIndex = (framePosition + mFramesPerBurst - 1) / mFramesPerBurst;
    aaudio_position_frames_t nextBurstPosition = mFramesPerBurst * nextBurstIndex;
    aaudio_position_frames_t framesDelta = nextBurstPosition - mMarkerFramePosition;
    aaudio_nanoseconds_t nanosDelta = convertDeltaPositionToTime(framesDelta);
    aaudio_nanoseconds_t time = (aaudio_nanoseconds_t) (mMarkerNanoTime + nanosDelta);
//    ALOGI("IsochronousClockModel::convertPositionToTime: pos = %llu --> time = %llu",
//         (unsigned long long)framePosition,
//         (unsigned long long)time);
    return time;
}

aaudio_position_frames_t IsochronousClockModel::convertTimeToPosition(
        aaudio_nanoseconds_t nanoTime) const {
    if (mState == STATE_STOPPED) {
        return mMarkerFramePosition;
    }
    aaudio_nanoseconds_t nanosDelta = nanoTime - mMarkerNanoTime;
    aaudio_position_frames_t framesDelta = convertDeltaTimeToPosition(nanosDelta);
    aaudio_position_frames_t nextBurstPosition = mMarkerFramePosition + framesDelta;
    aaudio_position_frames_t nextBurstIndex = nextBurstPosition / mFramesPerBurst;
    aaudio_position_frames_t position = nextBurstIndex * mFramesPerBurst;
//    ALOGI("IsochronousClockModel::convertTimeToPosition: time = %llu --> pos = %llu",
//         (unsigned long long)nanoTime,
//         (unsigned long long)position);
//    ALOGI("IsochronousClockModel::convertTimeToPosition: framesDelta = %llu, mFramesPerBurst = %d",
//         (long long) framesDelta, mFramesPerBurst);
    return position;
}
