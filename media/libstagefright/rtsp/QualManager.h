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

#include <stdint.h>
#include <utils/Thread.h>

namespace android {
class QualManager {
public:
    QualManager();
    ~QualManager();

    int32_t getTargetBitrate();
    bool isNeedToDowngrade();

    void setTargetBitrate(uint8_t fraction, int64_t nowUs, bool isTooLowPkts);
    void setMinMaxBitrate(int32_t min, int32_t max);
    void setBitrateData(int32_t bitrate, int64_t now);
private:
    class Watcher : public Thread
    {
    public:
        Watcher(int32_t timeLimit);

        void setup();
        void release();
        void exit();
        bool isExpired() const;
    private:
        virtual ~Watcher();
        virtual bool threadLoop();

        char name[32] = {0,};

        Condition mMyCond;
        Mutex mMyLock;

        bool mWatching;
        bool mSwitch;
        const nsecs_t mTimeLimit;
    };
    sp<Watcher> VFPWatcher;
    sp<Watcher> LBRWatcher;
    int32_t mMinBitrate;
    int32_t mMaxBitrate;
    int32_t mBitrateStep;

    int32_t mTargetBitrate;
    int32_t mLastTargetBitrate;
    int64_t mLastSetBitrateTime;

    bool mIsNewTargetBitrate;

    int32_t clampingBitrate(int32_t bitrate);
};
} //namespace android

#endif  // QUAL_MANAGER_H_
