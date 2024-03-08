/*
 * Copyright (C) 2023 The Android Open Source Project
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

#include "SchedulingPolicyUtils.h"

#include <errno.h>
#include <pthread.h>
#include <sched.h>

#include <private/android_filesystem_config.h>
#include <processgroup/processgroup.h>
#include <processgroup/sched_policy.h>
#include <procinfo/process.h>
#include <utils/Log.h>

namespace android {
namespace camera3 {
namespace SchedulingPolicyUtils {

int requestPriorityDirect(int pid, int tid, int prio) {
    android::procinfo::ProcessInfo processInfo;
    static const int kMinPrio = 1;
    static const int kMaxPrio = 3;

    if (!android::procinfo::GetProcessInfo(tid, &processInfo)) {
       ALOGE("%s: Error getting process info", __FUNCTION__);
       return -EPERM;
    }

    if (prio < kMinPrio || prio > kMaxPrio || processInfo.pid != pid) {
        ALOGE("%s: Invalid parameter prio=%d pid=%d procinfo.pid=%d", __FUNCTION__, prio, pid,
                processInfo.pid);
        return -EPERM;
    }

    // Set the thread group as audio system thread group in consistent with the
    // implementation in SchedulingPolicyService.java when isApp is false in
    // requestPriority method.
    if (!SetTaskProfiles(tid, {get_sched_policy_profile_name(SP_AUDIO_SYS)},
            /*use_fd_cache*/ true)) {
        ALOGE("%s:Error in  SetTaskProfiles", __FUNCTION__);
        return -EPERM;
    }

    struct sched_param param;
    param.sched_priority = prio;
    return sched_setscheduler(tid, SCHED_FIFO | SCHED_RESET_ON_FORK, &param);
}

} // namespace SchedulingPolicyUtils
} // namespace camera3
} // namespace android
