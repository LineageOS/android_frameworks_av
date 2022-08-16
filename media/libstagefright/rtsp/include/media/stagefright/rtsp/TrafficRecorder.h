/*
 * Copyright (C) 2010 The Android Open Source Project
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

#ifndef A_TRAFFIC_RECORDER_H_

#define A_TRAFFIC_RECORDER_H_

#include <android-base/logging.h>
#include <utils/RefBase.h>

namespace android {

// Circular array to save recent amount of bytes
template <class Time, class Bytes>
class TrafficRecorder : public RefBase {
private:
    constexpr static size_t kMinNumEntries = 4;
    constexpr static size_t kMaxNumEntries = 1024;

    size_t mSize;
    size_t mSizeMask;
    Time *mTimeArray = NULL;
    Bytes *mBytesArray = NULL;
    size_t mHeadIdx;
    size_t mTailIdx;

    int mLastReadIdx;

    const Time mRecordLimit;
    Time mClock;
    Time mLastTimeOfPrint;
    Bytes mAccuBytes;

public:
    TrafficRecorder(size_t size, Time accuTimeLimit);
    virtual ~TrafficRecorder();

    void init();
    void updateClock(Time now);
    Bytes readBytesForTotal();
    Bytes readBytesForLastPeriod(Time period);
    void writeBytes(Bytes bytes);
    void printAccuBitsForLastPeriod(Time period, Time unit);
};

template <class Time, class Bytes>
TrafficRecorder<Time, Bytes>::TrafficRecorder(size_t size, Time recordLimit)
    : mRecordLimit(recordLimit) {
    if (size > kMaxNumEntries) {
        LOG(VERBOSE) << "Limiting TrafficRecorder size to " << kMaxNumEntries;
        size = kMaxNumEntries;
    } else if (size < kMinNumEntries) {
        LOG(VERBOSE) << "Limiting TrafficRecorder size to " << kMaxNumEntries;
        size = kMinNumEntries;
    }

    size_t exp = ((sizeof(size_t) == 8) ?
                  64 - __builtin_clzl(size - 1) :
                  32 - __builtin_clz(size - 1));
    mSize = (1ul << exp);         // size = 2^exp
    mSizeMask = mSize - 1;

    LOG(VERBOSE) << "TrafficRecorder Init size " << mSize;
    mTimeArray = new Time[mSize];
    mBytesArray = new Bytes[mSize];

    init();
}

template <class Time, class Bytes>
TrafficRecorder<Time, Bytes>::~TrafficRecorder() {
    delete[] mTimeArray;
    delete[] mBytesArray;
}

template <class Time, class Bytes>
void TrafficRecorder<Time, Bytes>::init() {
    mHeadIdx = 0;
    mTailIdx = mSizeMask;
    for (int i = 0 ; i < mSize ; i++) {
        mTimeArray[i] = 0;
        mBytesArray[i] = 0;
    }
    mClock = 0;
    mLastReadIdx = 0;
    mLastTimeOfPrint = 0;
    mAccuBytes = 0;
}

template <class Time, class Bytes>
void TrafficRecorder<Time, Bytes>::updateClock(Time now) {
    mClock = now;
}

template <class Time, class Bytes>
Bytes TrafficRecorder<Time, Bytes>::readBytesForTotal() {
    return mAccuBytes;
}

template <class Time, class Bytes>
Bytes TrafficRecorder<Time, Bytes>::readBytesForLastPeriod(Time period) {
    // Not enough data
    if (period > mClock)
        return 0;

    Bytes bytes = 0;
    int i = mHeadIdx;
    while (i != mTailIdx) {
        LOG(VERBOSE) << "READ " << i << " time " << mTimeArray[i]
                << " \t EndOfPeriod " << mClock - period
                << "\t\t Bytes:" << mBytesArray[i] << "\t\t Accu: " << bytes;
        if (mTimeArray[i] < mClock - period) {
            break;
        }
        bytes += mBytesArray[i];
        i = (i - 1) & mSizeMask;
    }
    mLastReadIdx = (i + 1) & mSizeMask;

    return bytes;
}

template <class Time, class Bytes>
void TrafficRecorder<Time, Bytes>::writeBytes(Bytes bytes) {
    int writeIdx;
    if (mClock == mTimeArray[mHeadIdx]) {
        writeIdx = mHeadIdx;
        mBytesArray[writeIdx] += bytes;
    } else {
        writeIdx = (mHeadIdx + 1) & mSizeMask;
        mTimeArray[writeIdx] = mClock;
        mBytesArray[writeIdx] = bytes;
    }

    LOG(VERBOSE) << "WRITE " << writeIdx << " time " << mClock;
    if (writeIdx == mTailIdx) {
        mTailIdx = (mTailIdx + 1) & mSizeMask;
    }

    mHeadIdx = writeIdx;
    mAccuBytes += bytes;
}

template <class Time, class Bytes>
void TrafficRecorder<Time, Bytes>::printAccuBitsForLastPeriod(Time period, Time unit) {
    Time timeSinceLastPrint = mClock - mLastTimeOfPrint;
    if (timeSinceLastPrint < period)
        return;

    Bytes sum = readBytesForLastPeriod(period);
    Time readPeriod = mClock - mTimeArray[mLastReadIdx];

    float numOfUnit = (float)(readPeriod) / (unit + FLT_MIN);
    ALOGD("Actual Tx period %.3f unit \t %.0f bytes (%.0f Kbits)/Unit",
          numOfUnit, sum / numOfUnit, sum * 8.f / numOfUnit / 1000.f);
    mLastTimeOfPrint = mClock;

    if (mClock - mTimeArray[mTailIdx] < mRecordLimit) {
        // Size is not enough to record bytes for mRecordLimit period
        ALOGW("Traffic recorder size is not enough. mRecordLimit %d", mRecordLimit);
    }
}

}  // namespace android

#endif  // A_TRAFFIC_RECORDER_H_
