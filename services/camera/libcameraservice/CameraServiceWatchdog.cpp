/*
 * Copyright (C) 2022 The Android Open Source Project
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

#define LOG_TAG "CameraServiceWatchdog"

#include "CameraServiceWatchdog.h"

namespace android {

bool CameraServiceWatchdog::threadLoop()
{
    {
        AutoMutex _l(mWatchdogLock);

        while (mPause) {
            mWatchdogCondition.wait(mWatchdogLock);
        }
    }

    std::this_thread::sleep_for(std::chrono::milliseconds(mCycleLengthMs));

    {
        AutoMutex _l(mWatchdogLock);

        for (auto it = tidToCycleCounterMap.begin(); it != tidToCycleCounterMap.end(); it++) {
            uint32_t currentThreadId = it->first;

            tidToCycleCounterMap[currentThreadId]++;

            if (tidToCycleCounterMap[currentThreadId] >= mMaxCycles) {
                ALOGW("CameraServiceWatchdog triggering abort for pid: %d", getpid());
                // We use abort here so we can get a tombstone for better
                // debugging.
                abort();
            }
        }
    }

    return true;
}

void CameraServiceWatchdog::requestExit()
{
    Thread::requestExit();

    AutoMutex _l(mWatchdogLock);

    tidToCycleCounterMap.clear();

    if (mPause) {
        mPause = false;
        mWatchdogCondition.signal();
    }
}

void CameraServiceWatchdog::setEnabled(bool enable)
{
    AutoMutex _l(mEnabledLock);

    if (enable) {
        mEnabled = true;
    } else {
        mEnabled = false;
    }
}

void CameraServiceWatchdog::stop(uint32_t tid)
{
    AutoMutex _l(mWatchdogLock);

    tidToCycleCounterMap.erase(tid);

    if (tidToCycleCounterMap.empty()) {
        mPause = true;
    }
}

void CameraServiceWatchdog::start(uint32_t tid)
{
    AutoMutex _l(mWatchdogLock);

    tidToCycleCounterMap[tid] = 0;

    if (mPause) {
        mPause = false;
        mWatchdogCondition.signal();
    }
}

}   // namespace android
