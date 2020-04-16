/*
 * Copyright (C) 2020 The Android Open Source Project
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

#ifndef ANDROID_MEDIA_PROCESS_INFO_INTERFACE_H
#define ANDROID_MEDIA_PROCESS_INFO_INTERFACE_H

namespace android {

// Interface for the scheduler to query a process's info.
class ProcessInfoInterface {
public:
    // Determines if a process is currently running as top process.
    // TODO(chz): this should probably be replaced by a query that determines
    // which pid has the highest priority among a given set of pids. For now,
    // we assume that there is a way to determine based on a pid number whether
    // that pid is on "top", but this may not be possible in some cases, for
    // example, the client process with highest priority is actually a foreground
    // service (serving the top-app), but technically is not "top".
    virtual bool isProcessOnTop(pid_t pid) = 0;

protected:
    virtual ~ProcessInfoInterface() = default;
};

// Interface for notifying the scheduler of a change in a process's state or
// transcoding resource availability.
class ProcessInfoCallbackInterface {
public:
    // Called when a process with pid is brought to top.
    // TODO(chz): this should probably be replace by a callback when the pid
    // that was previously identified being the highest priority as in
    // ProcessInfoInterface::isProcessOnTop() has changed in priority.
    virtual void onTopProcessChanged(pid_t pid) = 0;

    // Called when resources become available for transcoding use. The scheduler
    // may use this as a signal to attempt restart transcoding activity that
    // were previously paused due to temporary resource loss.
    virtual void onResourceAvailable() = 0;

protected:
    virtual ~ProcessInfoCallbackInterface() = default;
};

}  // namespace android
#endif  // ANDROID_MEDIA_PROCESS_INFO_INTERFACE_H
