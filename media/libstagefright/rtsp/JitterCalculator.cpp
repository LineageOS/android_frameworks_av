/*
 * Copyright (C) 2021 The Android Open Source Project
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

#define LOG_TAG "JitterCalc"
#include <utils/Log.h>

#include "JitterCalculator.h"

#include <stdlib.h>

namespace android {

JitterCalc::JitterCalc(int32_t clockRate)
    : mClockRate(clockRate) {
    init(0, 0, 0, 0);
}

void JitterCalc::init(uint32_t rtpTime, int64_t arrivalTimeUs, int32_t base, int32_t inter) {
    mFirstTimeStamp = rtpTime;
    mLastTimeStamp = rtpTime;
    mFirstArrivalTimeUs = arrivalTimeUs;
    mLastArrivalTimeUs = arrivalTimeUs;

    mBaseJitterUs = base;
    mInterArrivalJitterUs = inter;
}

void JitterCalc::putBaseData(uint32_t rtpTime, int64_t arrivalTimeUs) {
    // A RTP time wraps around after UINT32_MAX. Overflow can present.
    uint32_t diff = 0;
    __builtin_usub_overflow(rtpTime, mFirstTimeStamp, &diff);

    // Base jitter implementation can be various
    int64_t scheduledTimeUs = ((int32_t)diff) * 1000000ll / mClockRate;
    int64_t elapsedTimeUs = arrivalTimeUs - mFirstArrivalTimeUs;
    int64_t correctionTimeUs = elapsedTimeUs - scheduledTimeUs; // additional propagation delay;
    mBaseJitterUs = (mBaseJitterUs * 15 + correctionTimeUs) / 16;
    ALOGV("BaseJitterUs : %lld \t\t correctionTimeUs : %lld",
            (long long)mBaseJitterUs, (long long)correctionTimeUs);
}

void JitterCalc::putInterArrivalData(uint32_t rtpTime, int64_t arrivalTimeUs) {
    // A RTP time wraps around after UINT32_MAX. Overflow can present.
    uint32_t diff = 0;
    __builtin_usub_overflow(rtpTime, mLastTimeStamp, &diff);

    // 6.4.1 of RFC3550 defines this interarrival jitter value.
    int64_t diffTimeStampUs = abs((int32_t)diff) * 1000000ll / mClockRate;
    int64_t diffArrivalUs = arrivalTimeUs - mLastArrivalTimeUs; // Can't be minus
    ALOGV("diffTimeStampUs %lld \t\t diffArrivalUs %lld",
            (long long)diffTimeStampUs, (long long)diffArrivalUs);

    int64_t varianceUs = diffArrivalUs - diffTimeStampUs;
    mInterArrivalJitterUs = (mInterArrivalJitterUs * 15 + abs(varianceUs)) / 16;

    mLastTimeStamp = rtpTime;
    mLastArrivalTimeUs = arrivalTimeUs;
}

int32_t JitterCalc::getBaseJitterMs() {
    return mBaseJitterUs / 1000;
}

int32_t JitterCalc::getInterArrivalJitterMs() {
    return mInterArrivalJitterUs / 1000;
}

}   // namespace android

