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

#pragma once

#if defined(__linux__)
#include <signal.h>
#include <sys/syscall.h>
#include <unistd.h>
#endif

namespace android::mediautils {

// The library wrapper for gettid is only available on bionic. If we don't link
// against it, we syscall directly.
inline pid_t getThreadIdWrapper() {
#if defined(__BIONIC__)
    return ::gettid();
#else
    return syscall(SYS_gettid);
#endif
}

// Send an abort signal to a (linux) thread id.
inline int abortTid(int tid) {
#if defined(__linux__)
    const pid_t pid = getpid();
    siginfo_t siginfo = {
        .si_code = SI_QUEUE,
        .si_pid = pid,
        .si_uid = getuid(),
    };
    return syscall(SYS_rt_tgsigqueueinfo, pid, tid, SIGABRT, &siginfo);
#else
  errno = ENODEV;
  return -1;
#endif
}

}
