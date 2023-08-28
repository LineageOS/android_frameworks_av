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
#include "android/set_abort_message.h"
#include "utils/CameraServiceProxyWrapper.h"

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

        for (auto it = mTidMap.begin(); it != mTidMap.end(); it++) {
            uint32_t currentThreadId = it->first;

            mTidMap[currentThreadId].cycles++;

            if (mTidMap[currentThreadId].cycles >= mMaxCycles) {
                std::string abortMessage = getAbortMessage(mTidMap[currentThreadId].functionName);
                android_set_abort_message(abortMessage.c_str());
                ALOGW("CameraServiceWatchdog triggering abort for pid: %d tid: %d", getpid(),
                        currentThreadId);
                mCameraServiceProxyWrapper->logClose(mCameraId, 0 /*latencyMs*/,
                        true /*deviceError*/);
                // We use abort here so we can get a tombstone for better
                // debugging.
                abort();
            }
        }
    }

    return true;
}

std::string CameraServiceWatchdog::getAbortMessage(const std::string& functionName) {
    std::string res = "CameraServiceWatchdog triggering abort during "
            + functionName;
    return res;
}

void CameraServiceWatchdog::requestExit()
{
    Thread::requestExit();

    AutoMutex _l(mWatchdogLock);

    mTidMap.clear();

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

    mTidMap.erase(tid);

    if (mTidMap.empty()) {
        mPause = true;
    }
}

void CameraServiceWatchdog::start(uint32_t tid, const char* functionName)
{
    AutoMutex _l(mWatchdogLock);

    MonitoredFunction monitoredFunction = {};
    monitoredFunction.cycles = 0;
    monitoredFunction.functionName = functionName;
    mTidMap[tid] = monitoredFunction;

    if (mPause) {
        mPause = false;
        mWatchdogCondition.signal();
    }
}

}   // namespace android
