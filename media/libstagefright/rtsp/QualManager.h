/*
 * Copyright (C) 2018 The Android Open Source Project
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

#ifndef QUAL_MANAGER_H_

#define QUAL_MANAGER_H_

namespace android {

class QualManager {
public:
    QualManager() : mMinBitrate(-1), mMaxBitrate(-1), mTargetBitrate(512000),
                    mLastTargetBitrate(-1), mLastSetBitrateTime(0),
                    mLowBitrateStartTime(0), mAutoDowngrade(false),
                    mIsNewTargetBitrate(false){};

    int32_t getTargetBitrate() {
        if (mIsNewTargetBitrate) {
            mIsNewTargetBitrate = false;
            mLastTargetBitrate = mTargetBitrate;
            return mTargetBitrate;
        } else {
            return -1;
        }
    }

    bool isNeedToDowngrade() {
        return mAutoDowngrade;
    }

    void setTargetBitrate(uint8_t fraction, int64_t nowUs) {
        if (fraction <= (256 * 2 /100)) {           // loss less than 2%
            mTargetBitrate += mBitrateStep;
        } else if (fraction > (256 * 5 / 100)) {    // loss more than 5%
            mTargetBitrate -= mBitrateStep * 4;
        }

        if (mTargetBitrate > mMaxBitrate) {
            mTargetBitrate = mMaxBitrate;
        } else if (mTargetBitrate < mMinBitrate) {
            if (mLowBitrateStartTime != 0) {
                mLowBitrateStartTime = nowUs;
            }
            mTargetBitrate = mMinBitrate;
        }

        if (mLastTargetBitrate != mTargetBitrate || nowUs - mLastSetBitrateTime > 5000000ll) {
            mIsNewTargetBitrate = true;
            mLastSetBitrateTime = nowUs;
        }
    };

    void setMinMaxBitrate(int32_t min, int32_t max) {
        mMinBitrate = min;
        mMaxBitrate = max;
        mBitrateStep = (max - min) / 8;
    };

    void setBitrateData(int32_t bitrate, int64_t now) {
        int64_t lowBitrateDuration = 0;
        if (bitrate < mMinBitrate)
        {
            if (mLowBitrateStartTime == 0) {
                mLowBitrateStartTime = now;
            } else {
                lowBitrateDuration = now - mLowBitrateStartTime;
            }
        } else {
            mLowBitrateStartTime = 0;
        }
        if (lowBitrateDuration > mPatientTime) {
            mAutoDowngrade = true;
        } else {
            mAutoDowngrade = false;
        }
    }
private:
    int32_t mMinBitrate;
    int32_t mMaxBitrate;
    int32_t mBitrateStep;

    int32_t mTargetBitrate;
    int32_t mLastTargetBitrate;

    int64_t mLastSetBitrateTime;

    const int64_t mPatientTime = 10000000ll;    // 10 sec
    int64_t mLowBitrateStartTime;

    bool mAutoDowngrade;
    bool mIsNewTargetBitrate;
};

} //namespace android

#endif  // QUAL_MANAGER_H_
