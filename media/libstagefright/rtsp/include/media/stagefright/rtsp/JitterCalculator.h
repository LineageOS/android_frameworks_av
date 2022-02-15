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

#ifndef A_JITTER_CALCULATOR_H_

#define A_JITTER_CALCULATOR_H_

#include <stdint.h>
#include <utils/RefBase.h>

namespace android {

class JitterCalc : public RefBase {
private:
    // Time Stamp per Second
    const int32_t mClockRate;

    uint32_t mFirstTimeStamp;
    uint32_t mLastTimeStamp;
    int64_t mFirstArrivalTimeUs;
    int64_t mLastArrivalTimeUs;

    int32_t mBaseJitterUs;
    int32_t mInterArrivalJitterUs;

public:
    JitterCalc(int32_t clockRate);

    void init(uint32_t rtpTime, int64_t arrivalTimeUs, int32_t base, int32_t inter);
    void putInterArrivalData(uint32_t rtpTime, int64_t arrivalTime);
    void putBaseData(uint32_t rtpTime, int64_t arrivalTimeUs);
    int32_t getBaseJitterMs();
    int32_t getInterArrivalJitterMs();
};

}   // namespace android

#endif  // A_JITTER_CALCULATOR_H_
