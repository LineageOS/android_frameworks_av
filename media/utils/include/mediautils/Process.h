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

#include <map>
#include <string>
#include <unistd.h>

/*
 * This header contains utilities to read the linux system /proc/pid files
 *
 * The format of this is not guaranteed to be stable, so use for diagnostic purposes only.
 *
 * The linux "proc" directory documentation:
 * https://kernel.org/doc/Documentation/filesystems/proc.txt
 * https://www.kernel.org/doc/html/latest/filesystems/proc.html?highlight=proc%20pid#chapter-3-per-process-parameters
 */

namespace android::mediautils {

/**
 * Return the thread schedule information for tid.
 *
 * String will be empty if the process does not have permission to
 * access the /proc/pid tables, or if not on a Linux device.
 *
 * Linux scheduler documentation:
 * https://www.kernel.org/doc/html/latest/scheduler/index.html
 * https://man7.org/linux/man-pages/man7/sched.7.html
 *
 * Sample as follows:

AudioOut_8D (10800, #threads: 36)
-------------------------------------------------------------------
se.exec_start                                :       8132077.598026
se.vruntime                                  :        798689.872087
se.sum_exec_runtime                          :        136466.957838
se.nr_migrations                             :               132487
se.statistics.sum_sleep_runtime              :       5629794.565945
se.statistics.wait_start                     :             0.000000
se.statistics.sleep_start                    :       8195727.586392
se.statistics.block_start                    :             0.000000
se.statistics.sleep_max                      :       1995665.869808
se.statistics.block_max                      :             0.591675
se.statistics.exec_max                       :             2.477580
se.statistics.slice_max                      :             0.000000
se.statistics.wait_max                       :             8.608642
se.statistics.wait_sum                       :          4683.266835
se.statistics.wait_count                     :               300964
se.statistics.iowait_sum                     :             0.000000
se.statistics.iowait_count                   :                    0
se.statistics.nr_migrations_cold             :                    0
se.statistics.nr_failed_migrations_affine    :                  297
se.statistics.nr_failed_migrations_running   :                 1412
se.statistics.nr_failed_migrations_hot       :                   96
se.statistics.nr_forced_migrations           :                   26
se.statistics.nr_wakeups                     :               281263
se.statistics.nr_wakeups_sync                :                   84
se.statistics.nr_wakeups_migrate             :               132322
se.statistics.nr_wakeups_local               :                 2165
se.statistics.nr_wakeups_remote              :               279098
se.statistics.nr_wakeups_affine              :                    0
se.statistics.nr_wakeups_affine_attempts     :                    0
se.statistics.nr_wakeups_passive             :                    0
se.statistics.nr_wakeups_idle                :                    0
avg_atom                                     :             0.453434
avg_per_cpu                                  :             1.030040
nr_switches                                  :               300963
nr_voluntary_switches                        :               281252
nr_involuntary_switches                      :                19711
se.load.weight                               :             73477120
se.avg.load_sum                              :                   58
se.avg.runnable_sum                          :                27648
se.avg.util_sum                              :                21504
se.avg.load_avg                              :                   48
se.avg.runnable_avg                          :                    0
se.avg.util_avg                              :                    0
se.avg.last_update_time                      :        8132075824128
se.avg.util_est.ewma                         :                    8
se.avg.util_est.enqueued                     :                    1
uclamp.min                                   :                    0
uclamp.max                                   :                 1024
effective uclamp.min                         :                    0
effective uclamp.max                         :                 1024
policy                                       :                    0
prio                                         :                  101
clock-delta                                  :                  163
*/
std::string getThreadSchedAsString(pid_t tid);

/**
 * Returns map for the raw thread schedule string.
 */
std::map<std::string, double> parseThreadSchedString(const std::string& schedString);

/**
 * Returns map for /proc/pid/task/tid/sched
 */
inline std::map<std::string, double> getThreadSchedAsMap(pid_t tid) {
    return parseThreadSchedString(getThreadSchedAsString(tid));
}

// TODO: Extend to other /proc/pid file information.
//
// See "ps" command get_ps().
// https://cs.android.com/android/platform/superproject/+/master:external/toybox/toys/posix/ps.c;l=707

} // android::mediautils
