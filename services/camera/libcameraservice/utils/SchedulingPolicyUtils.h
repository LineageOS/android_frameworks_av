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
#ifndef ANDROID_SERVICE_CAMERA_SCHEDULING_POLICY_UTILS_H
#define ANDROID_SERVICE_CAMERA_SCHEDULING_POLICY_UTILS_H

namespace android {
namespace camera3 {
namespace SchedulingPolicyUtils {

/**
 * Request elevated priority for thread tid, whose thread group leader must be pid.
 * Instead of using scheduling policy service, this method uses direct system calls.
 * The priority parameter is currently restricted from 1 to 3 matching
 * scheduling policy service implementation.
 */
int requestPriorityDirect(int pid, int tid, int prio);

} // SchedulingPolicyUtils
} // camera3
} // android

#endif
