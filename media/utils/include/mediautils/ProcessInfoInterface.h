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

#ifndef PROCESS_INFO_INTERFACE_H_
#define PROCESS_INFO_INTERFACE_H_

#include <vector>
#include <utils/RefBase.h>

namespace android {

struct ProcessInfoInterface : public RefBase {
    /*
     * Gets the priority of the process (with given pid) as oom score.
     *
     * @param[in] pid pid of the process.
     * @param[out] priority of the process.
     *
     * @return true for successful return and false otherwise.
     */
    virtual bool getPriority(int pid, int* priority) = 0;
    /*
     * Check whether the given pid is trusted or not.
     *
     * @param[in] pid pid of the process.
     *
     * @return true for trusted process and false otherwise.
     */
    virtual bool isPidTrusted(int pid) = 0;
    /*
     * Check whether the given pid and uid is trusted or not.
     *
     * @param[in] pid pid of the process.
     * @param[in] uid uid of the process.
     *
     * @return true for trusted process and false otherwise.
     */
    virtual bool isPidUidTrusted(int pid, int uid) = 0;
    /*
     * Override process state and oom score of the pid.
     *
     * @param[in] pid pid of the process.
     * @param[in] procState new state of the process to override with.
     * @param[in] oomScore new oom score of the process to override with.
     *
     * @return true upon success and false otherwise.
     */
    virtual bool overrideProcessInfo(int pid, int procState, int oomScore) = 0;
    /*
     * Remove the override info of the given process.
     *
     * @param[in] pid pid of the process.
     */
    virtual void removeProcessInfoOverride(int pid) = 0;
    /*
     * Checks whether the list of processes with given pids exist or not.
     *
     * @param[in] pids List of pids for which to check whether they are Existent or not.
     * @param[out] existent boolean vector corresponds to Existent state of each pids.
     *
     * @return true for successful return and false otherwise.
     * On successful return:
     *     - existent[i] true corresponds to pids[i] still active and
     *     - existent[i] false corresponds to pids[i] already terminated (Nonexistent)
     * On unsuccessful return, the output argument existent is invalid.
     */
    virtual bool checkProcessExistent(const std::vector<int32_t>& pids,
                                      std::vector<bool>* existent) {
        // A default implementation.
        (void)pids;
        (void)existent;
        return false;
    }

protected:
    virtual ~ProcessInfoInterface() {}
};

}  // namespace android

#endif  // PROCESS_INFO_INTERFACE_H_
