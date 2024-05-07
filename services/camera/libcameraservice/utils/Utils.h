/*
 * Copyright (C) 2024 The Android Open Source Project
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

#ifndef ANDROID_SERVERS_CAMERA_UTILS_H
#define ANDROID_SERVERS_CAMERA_UTILS_H

#include <sched.h>
#include <unistd.h>

namespace android {

/**
 * As of Android V, ro.board.api_level returns the year and month of release (ex. 202404)
 * instead of release SDK version. This function maps year/month format back to release
 * SDK version.
 *
 * Returns defaultVersion if the property is not found.
 */
int getVNDKVersionFromProp(int defaultVersion);

/**
 * An instance of this class will raise the scheduling policy of a given
 * given thread to real time and keep it this way throughout the lifetime
 * of the object. The thread scheduling policy will revert back to its original
 * state after the instances is released. By default the implementation will
 * raise the priority of the current thread unless clients explicitly specify
 * another thread id.
 * Client must avoid:
 *  - Keeping an instance of this class for extended and long running operations.
 *    This is only intended for short/temporarily priority bumps that mitigate
 *    scheduling delays within critical camera paths.
 *  - Allocating instances of this class on the memory heap unless clients have
 *    complete control over the object lifetime. It is preferable to allocate
 *    instances of this class on the stack instead.
 *  - Nesting multiple instances of this class using the same default or same thread id.
 */
class RunThreadWithRealtimePriority final {
  public:
    RunThreadWithRealtimePriority(int tid = gettid());
    ~RunThreadWithRealtimePriority();

    RunThreadWithRealtimePriority(const RunThreadWithRealtimePriority&) = delete;
    RunThreadWithRealtimePriority& operator=(const RunThreadWithRealtimePriority&) = delete;

    // SCHED_FIFO priority for request submission thread in HFR mode
    static const int kRequestThreadPriority = 1;

  private:
    int mTid;
    int mPreviousPolicy;
    bool mPolicyBumped = false;
    struct sched_param mPreviousParams;
};

} // namespace android

#endif //ANDROID_SERVERS_CAMERA_UTILS_H
