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

#define LOG_TAG "IsochronousClockModel"
//#define LOG_NDEBUG 0
#include <log/log.h>

#define __STDC_FORMAT_MACROS
#include <inttypes.h>
#include <stdint.h>
#include <algorithm>

#include "utility/AudioClock.h"
#include "utility/AAudioUtilities.h"
#include "IsochronousClockModel.h"

using namespace aaudio;

using namespace android::audio_utils;

#ifndef ICM_LOG_DRIFT
#define ICM_LOG_DRIFT   0
#endif // ICM_LOG_DRIFT

// To enable the timestamp histogram, enter this before opening the stream:
//    adb root
//    adb shell setprop aaudio.log_mask 1
// A histogram of the lateness of the timestamps will be cleared when the stream is started.
// It will be updated when the model is stable and receives a timestamp,
// and dumped to the log when the stream is stopped.

IsochronousClockModel::IsochronousClockModel()
        : mMarkerFramePosition(0)
        , mMarkerNanoTime(0)
        , mSampleRate(48000)
        , mFramesPerBurst(48)
        , mBurstPeriodNanos(0) // this will be updated before use
        , mMaxMeasuredLatenessNanos(0)
        , mLatenessForDriftNanos(kInitialLatenessForDriftNanos)
        , mState(STATE_STOPPED)
{
    if ((AAudioProperty_getLogMask() & AAUDIO_LOG_CLOCK_MODEL_HISTOGRAM) != 0) {
        mHistogramMicros = std::make_unique<Histogram>(kHistogramBinCount,
                kHistogramBinWidthMicros);
    }
}

void IsochronousClockModel::setPositionAndTime(int64_t framePosition, int64_t nanoTime) {
    ALOGV("setPositionAndTime, %lld, %lld", (long long) framePosition, (long long) nanoTime);
    mMarkerFramePosition = framePosition;
    mMarkerNanoTime = nanoTime;
}

void IsochronousClockModel::start(int64_t nanoTime) {
    ALOGV("start(nanos = %lld)\n", (long long) nanoTime);
    mMarkerNanoTime = nanoTime;
    mState = STATE_STARTING;
    if (mHistogramMicros) {
        mHistogramMicros->clear();
    }
}

void IsochronousClockModel::stop(int64_t nanoTime) {
    ALOGD("stop(nanos = %lld) max lateness = %d micros\n",
        (long long) nanoTime,
        (int) (mMaxMeasuredLatenessNanos / 1000));
    setPositionAndTime(convertTimeToPosition(nanoTime), nanoTime);
    // TODO should we set position?
    mState = STATE_STOPPED;
    if (mHistogramMicros) {
        dumpHistogram();
    }
}

bool IsochronousClockModel::isStarting() const {
    return mState == STATE_STARTING;
}

bool IsochronousClockModel::isRunning() const {
    return mState == STATE_RUNNING;
}

void IsochronousClockModel::processTimestamp(int64_t framePosition, int64_t nanoTime) {
    mTimestampCount++;
// Log position and time in CSV format so we can import it easily into spreadsheets.
    //ALOGD("%s() CSV, %d, %lld, %lld", __func__,
          //mTimestampCount, (long long)framePosition, (long long)nanoTime);
    int64_t framesDelta = framePosition - mMarkerFramePosition;
    int64_t nanosDelta = nanoTime - mMarkerNanoTime;
    if (nanosDelta < 1000) {
        return;
    }

//    ALOGD("processTimestamp() - mMarkerFramePosition = %lld at mMarkerNanoTime %llu",
//         (long long)mMarkerFramePosition,
//         (long long)mMarkerNanoTime);

    int64_t expectedNanosDelta = convertDeltaPositionToTime(framesDelta);
//    ALOGD("processTimestamp() - expectedNanosDelta = %lld, nanosDelta = %llu",
//         (long long)expectedNanosDelta,
//         (long long)nanosDelta);

//    ALOGD("processTimestamp() - mSampleRate = %d", mSampleRate);
//    ALOGD("processTimestamp() - mState = %d", mState);
    int64_t latenessNanos = nanosDelta - expectedNanosDelta;
    switch (mState) {
    case STATE_STOPPED:
        break;
    case STATE_STARTING:
        setPositionAndTime(framePosition, nanoTime);
        mState = STATE_SYNCING;
        break;
    case STATE_SYNCING:
        // This will handle a burst of rapid transfer at the beginning.
        if (latenessNanos < 0) {
            setPositionAndTime(framePosition, nanoTime);
        } else {
//            ALOGD("processTimestamp() - advance to STATE_RUNNING");
            mState = STATE_RUNNING;
        }
        break;
    case STATE_RUNNING:
        if (mHistogramMicros) {
            mHistogramMicros->add(latenessNanos / AAUDIO_NANOS_PER_MICROSECOND);
        }
        // Modify estimated position based on lateness.
        // This affects the "early" side of the window, which controls output glitches.
        if (latenessNanos < 0) {
            // Earlier than expected timestamp.
            // This data is probably more accurate, so use it.
            // Or we may be drifting due to a fast HW clock.
            setPositionAndTime(framePosition, nanoTime);
#if ICM_LOG_DRIFT
            int earlyDeltaMicros = (int) ((expectedNanosDelta - nanosDelta)/ 1000);
            ALOGD("%s() - STATE_RUNNING - #%d, %4d micros EARLY",
                __func__, mTimestampCount, earlyDeltaMicros);
#endif
        } else if (latenessNanos > mLatenessForDriftNanos) {
            // When we are on the late side, it may be because of preemption in the kernel,
            // or timing jitter caused by resampling in the DSP,
            // or we may be drifting due to a slow HW clock.
            // We add slight drift value just in case there is actual long term drift
            // forward caused by a slower clock.
            // If the clock is faster than the model will get pushed earlier
            // by the code in the earlier branch.
            // The two opposing forces should allow the model to track the real clock
            // over a long time.
            int64_t driftingTime = mMarkerNanoTime + expectedNanosDelta + kDriftNanos;
            setPositionAndTime(framePosition,  driftingTime);
#if ICM_LOG_DRIFT
            ALOGD("%s() - STATE_RUNNING - #%d, DRIFT, lateness = %d micros",
                  __func__,
                  mTimestampCount,
                  (int) (latenessNanos / 1000));
#endif
        }

        // Modify mMaxMeasuredLatenessNanos.
        // This affects the "late" side of the window, which controls input glitches.
        if (latenessNanos > mMaxMeasuredLatenessNanos) { // increase
#if ICM_LOG_DRIFT
            ALOGD("%s() - STATE_RUNNING - #%d, newmax %d - oldmax %d = %4d micros LATE",
                    __func__,
                    mTimestampCount,
                    (int) (latenessNanos / 1000),
                    mMaxMeasuredLatenessNanos / 1000,
                    (int) ((latenessNanos - mMaxMeasuredLatenessNanos) / 1000)
                    );
#endif
            mMaxMeasuredLatenessNanos = (int32_t) latenessNanos;
            // Calculate upper region that will trigger a drift forwards.
            mLatenessForDriftNanos = mMaxMeasuredLatenessNanos - (mMaxMeasuredLatenessNanos >> 4);
        } else { // decrease
            // If this is an outlier in lateness then mMaxMeasuredLatenessNanos can go high
            // and stay there. So we slowly reduce mMaxMeasuredLatenessNanos for better
            // long term stability. The two opposing forces will keep mMaxMeasuredLatenessNanos
            // within a reasonable range.
            mMaxMeasuredLatenessNanos -= kDriftNanos;
        }
        break;
    default:
        break;
    }
}

void IsochronousClockModel::setSampleRate(int32_t sampleRate) {
    mSampleRate = sampleRate;
    update();
}

void IsochronousClockModel::setFramesPerBurst(int32_t framesPerBurst) {
    mFramesPerBurst = framesPerBurst;
    update();
}

// Update expected lateness based on sampleRate and framesPerBurst
void IsochronousClockModel::update() {
    mBurstPeriodNanos = convertDeltaPositionToTime(mFramesPerBurst); // uses mSampleRate
}

int64_t IsochronousClockModel::convertDeltaPositionToTime(int64_t framesDelta) const {
    return (AAUDIO_NANOS_PER_SECOND * framesDelta) / mSampleRate;
}

int64_t IsochronousClockModel::convertDeltaTimeToPosition(int64_t nanosDelta) const {
    return (mSampleRate * nanosDelta) / AAUDIO_NANOS_PER_SECOND;
}

int64_t IsochronousClockModel::convertPositionToTime(int64_t framePosition) const {
    if (mState == STATE_STOPPED) {
        return mMarkerNanoTime;
    }
    int64_t nextBurstIndex = (framePosition + mFramesPerBurst - 1) / mFramesPerBurst;
    int64_t nextBurstPosition = mFramesPerBurst * nextBurstIndex;
    int64_t framesDelta = nextBurstPosition - mMarkerFramePosition;
    int64_t nanosDelta = convertDeltaPositionToTime(framesDelta);
    int64_t time = mMarkerNanoTime + nanosDelta;
//    ALOGD("convertPositionToTime: pos = %llu --> time = %llu",
//         (unsigned long long)framePosition,
//         (unsigned long long)time);
    return time;
}

int64_t IsochronousClockModel::convertTimeToPosition(int64_t nanoTime) const {
    if (mState == STATE_STOPPED) {
        return mMarkerFramePosition;
    }
    int64_t nanosDelta = nanoTime - mMarkerNanoTime;
    int64_t framesDelta = convertDeltaTimeToPosition(nanosDelta);
    int64_t nextBurstPosition = mMarkerFramePosition + framesDelta;
    int64_t nextBurstIndex = nextBurstPosition / mFramesPerBurst;
    int64_t position = nextBurstIndex * mFramesPerBurst;
//    ALOGD("convertTimeToPosition: time = %llu --> pos = %llu",
//         (unsigned long long)nanoTime,
//         (unsigned long long)position);
//    ALOGD("convertTimeToPosition: framesDelta = %llu, mFramesPerBurst = %d",
//         (long long) framesDelta, mFramesPerBurst);
    return position;
}

int32_t IsochronousClockModel::getLateTimeOffsetNanos() const {
    return mMaxMeasuredLatenessNanos + kExtraLatenessNanos;
}

int64_t IsochronousClockModel::convertPositionToLatestTime(int64_t framePosition) const {
    return convertPositionToTime(framePosition) + getLateTimeOffsetNanos();
}

int64_t IsochronousClockModel::convertLatestTimeToPosition(int64_t nanoTime) const {
    return convertTimeToPosition(nanoTime - getLateTimeOffsetNanos());
}

void IsochronousClockModel::dump() const {
    ALOGD("mMarkerFramePosition = %" PRIu64, mMarkerFramePosition);
    ALOGD("mMarkerNanoTime      = %" PRIu64, mMarkerNanoTime);
    ALOGD("mSampleRate          = %6d", mSampleRate);
    ALOGD("mFramesPerBurst      = %6d", mFramesPerBurst);
    ALOGD("mMaxMeasuredLatenessNanos = %6d", mMaxMeasuredLatenessNanos);
    ALOGD("mState               = %6d", mState);
}

void IsochronousClockModel::dumpHistogram() const {
    if (!mHistogramMicros) return;
    std::istringstream istr(mHistogramMicros->dump());
    std::string line;
    while (std::getline(istr, line)) {
        ALOGD("lateness, %s", line.c_str());
    }
}
