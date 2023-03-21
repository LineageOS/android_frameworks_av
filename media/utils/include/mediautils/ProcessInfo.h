/*
 * Copyright (C) 2015 The Android Open Source Project
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

#ifndef PROCESS_INFO_H_

#define PROCESS_INFO_H_

#include <mediautils/ProcessInfoInterface.h>
#include <map>
#include <mutex>
#include <utils/Condition.h>

namespace android {

struct ProcessInfo : public ProcessInfoInterface {
    ProcessInfo();

    virtual bool getPriority(int pid, int* priority);
    virtual bool isPidTrusted(int pid);
    virtual bool isPidUidTrusted(int pid, int uid);
    virtual bool overrideProcessInfo(int pid, int procState, int oomScore);
    virtual void removeProcessInfoOverride(int pid);
    bool checkProcessExistent(const std::vector<int32_t>& pids,
                              std::vector<bool>* existent) override;

protected:
    virtual ~ProcessInfo();

private:
    struct ProcessInfoOverride {
        int procState;
        int oomScore;
    };
    std::mutex mOverrideLock;
    std::map<int, ProcessInfoOverride> mOverrideMap GUARDED_BY(mOverrideLock);

    ProcessInfo(const ProcessInfo&) = delete;
    ProcessInfo& operator=(const ProcessInfo&) = delete;
};

}  // namespace android

#endif  // PROCESS_INFO_H_
