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
    init();
}

void JitterCalc::init() {
    mJitterValueUs = 0;
    mLastTimeStamp = 0;
    mLastArrivalTimeUs = 0;
}

void JitterCalc::putData(int64_t rtpTime, int64_t arrivalTimeUs) {
    if (mLastTimeStamp == 0) {
        mLastTimeStamp = rtpTime;
        mLastArrivalTimeUs = arrivalTimeUs;
    }

    const int64_t UINT32_MSB = 0x80000000;
    int64_t tempLastTimeStamp = mLastTimeStamp;
    // A RTP time wraps around after UINT32_MAX. We must consider this case.
    int64_t overflowMask = (mLastTimeStamp ^ rtpTime) & UINT32_MSB;
    rtpTime |= ((overflowMask & ~rtpTime) << 1);
    tempLastTimeStamp |= ((overflowMask & ~mLastTimeStamp) << 1);
    ALOGV("Raw stamp \t\t now %llx \t\t last %llx",
            (long long)rtpTime, (long long)tempLastTimeStamp);

    int64_t diffTimeStampUs = abs(rtpTime - tempLastTimeStamp) * 1000000ll / mClockRate;
    int64_t diffArrivalUs = abs(arrivalTimeUs - mLastArrivalTimeUs);
    ALOGV("diffTimeStampus %lld \t\t diffArrivalUs %lld",
            (long long)diffTimeStampUs, (long long)diffArrivalUs);

    // 6.4.1 of RFC3550 defines this interarrival jitter value.
    mJitterValueUs = (mJitterValueUs * 15 + abs(diffTimeStampUs - diffArrivalUs)) / 16;
    ALOGV("JitterUs %lld", (long long)mJitterValueUs);

    mLastTimeStamp = (uint32_t)rtpTime;
    mLastArrivalTimeUs = arrivalTimeUs;
}

uint32_t JitterCalc::getJitterMs() {
    return mJitterValueUs / 1000;
}

}   // namespace android

