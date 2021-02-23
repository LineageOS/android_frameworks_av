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

#define LOG_TAG "QualManager"

#include <algorithm>

#include <sys/prctl.h>
#include <utils/Log.h>

#include "QualManager.h"

namespace android {

QualManager::Watcher::Watcher(int32_t timeLimit)
    : Thread(false), mWatching(false), mSwitch(false),
      mTimeLimit(timeLimit * 1000000LL)     // timeLimit ms
{
}

bool QualManager::Watcher::isExpired() const
{
    return mSwitch;
}

void QualManager::Watcher::setup() {
    AutoMutex _l(mMyLock);
    if (mWatching == false) {
        mWatching = true;
        mMyCond.signal();
    }
}

void QualManager::Watcher::release() {
    AutoMutex _l(mMyLock);
    if (mSwitch) {
        ALOGW("%s DISARMED", name);
        mSwitch = false;
    }
    if (mWatching == true) {
        ALOGW("%s DISARMED", name);
        mWatching = false;
        mMyCond.signal();
    }
}

void QualManager::Watcher::exit() {
    AutoMutex _l(mMyLock);
    // The order is important to avoid dead lock.
    Thread::requestExit();
    mMyCond.signal();
}

QualManager::Watcher::~Watcher() {
    ALOGI("%s thread dead", name);
}

bool QualManager::Watcher::threadLoop() {
    AutoMutex _l(mMyLock);
#if defined(__linux__)
    prctl(PR_GET_NAME, name, 0, 0, 0);
#endif
    while (!exitPending()) {
        ALOGW("%s Timer init", name);
        mMyCond.wait(mMyLock);                      // waits as non-watching state
        if (exitPending())
            return false;
        ALOGW("%s timer BOOM after %d msec", name, (int)(mTimeLimit / 1000000LL));
        mMyCond.waitRelative(mMyLock, mTimeLimit);  // waits as watching satte
        if (mWatching == true) {
            mSwitch = true;
            ALOGW("%s BOOM!!!!", name);
        }
        mWatching = false;
    }
    return false;
}


QualManager::QualManager()
    : mMinBitrate(-1), mMaxBitrate(-1),
      mTargetBitrate(512000), mLastTargetBitrate(-1),
      mLastSetBitrateTime(0), mIsNewTargetBitrate(false)
{
    VFPWatcher = new Watcher(3000);     //Very Few Packet Watcher
    VFPWatcher->run("VeryFewPtk");
    LBRWatcher = new Watcher(10000);    //Low Bit Rate Watcher
    LBRWatcher->run("LowBitRate");
}

QualManager::~QualManager() {
    VFPWatcher->exit();
    LBRWatcher->exit();
}

int32_t QualManager::getTargetBitrate() {
    if (mIsNewTargetBitrate) {
        mIsNewTargetBitrate = false;
        mLastTargetBitrate = clampingBitrate(mTargetBitrate);
        mTargetBitrate = mLastTargetBitrate;
        return mTargetBitrate;
    } else {
        return -1;
    }
}

bool QualManager::isNeedToDowngrade() {
    return LBRWatcher->isExpired();
}

void QualManager::setTargetBitrate(uint8_t fraction, int64_t nowUs, bool isTooLowPkts) {
    /* Too Low Packet. Maybe opponent is switching camera.
     * If this condition goes longer, we should down bitrate.
     */
    if (isTooLowPkts) {
        VFPWatcher->setup();
    } else {
        VFPWatcher->release();
    }

    if ((fraction > (256 * 5 / 100) && !isTooLowPkts) || VFPWatcher->isExpired()) {
        // loss more than 5%                          or  VFPWatcher BOOMED
        mTargetBitrate -= mBitrateStep * 3;
    } else if (fraction <= (256 * 2 /100)) {
        // loss less than 2%
        mTargetBitrate += mBitrateStep;
    }

    if (mTargetBitrate > mMaxBitrate) {
        mTargetBitrate = mMaxBitrate + mBitrateStep;
    } else if (mTargetBitrate < mMinBitrate) {
        LBRWatcher->setup();
        mTargetBitrate = mMinBitrate - mBitrateStep;
    }

    if (mLastTargetBitrate != clampingBitrate(mTargetBitrate) ||
        nowUs - mLastSetBitrateTime > 5000000ll) {
        mIsNewTargetBitrate = true;
        mLastSetBitrateTime = nowUs;
    }
}

void QualManager::setMinMaxBitrate(int32_t min, int32_t max) {
    mMinBitrate = min;
    mMaxBitrate = max;
    mBitrateStep = (max - min) / 8;
}

void QualManager::setBitrateData(int32_t bitrate, int64_t /*now*/) {
    // A bitrate that is considered packetloss also should be good.
    if (bitrate >= mMinBitrate && mTargetBitrate >= mMinBitrate) {
        LBRWatcher->release();
    } else if (bitrate < mMinBitrate){
        LBRWatcher->setup();
    }
}

int32_t QualManager::clampingBitrate(int32_t bitrate) {
    return std::min(std::max(mMinBitrate, bitrate), mMaxBitrate);
}
} // namespace android
