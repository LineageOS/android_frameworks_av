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

#include <mediautils/Process.h>
#include <mediautils/TidWrapper.h>

#define LOG_TAG "media_process_tests"

#include <gtest/gtest.h>
#include <utils/Log.h>

using namespace android;
using namespace android::mediautils;

// Disables false-positives from base::Split()
//
// See mismatched sanitized libraries here:
// https://github.com/google/sanitizers/wiki/AddressSanitizerContainerOverflow
extern "C" const char* __asan_default_options() {
  return "detect_container_overflow=0";
}

TEST(media_process_tests, basic) {
  const std::string schedString = getThreadSchedAsString(getThreadIdWrapper());

  (void)schedString;
  // We don't test schedString, only that we haven't crashed.
  // ASSERT_FALSE(schedString.empty());

  // schedString is not normative.  So we conjure up our own string
  const std::string fakeString = "\
AudioOut_8D (10800, #threads: 36)\n\
-------------------------------------------------------------------\n\
se.exec_start                                :       8132077.598026\n\
se.vruntime                                  :        798689.872087\n\
se.sum_exec_runtime                          :        136466.957838\n\
se.nr_migrations                             :               132487\n\
se.statistics.sum_sleep_runtime              :       5629794.565945\n\
se.statistics.wait_start                     :             0.000000\n\
se.statistics.sleep_start                    :       8195727.586392\n\
se.statistics.block_start                    :             0.000000\n\
se.statistics.sleep_max                      :       1995665.869808\n\
se.statistics.block_max                      :             0.591675\n\
se.statistics.exec_max                       :             2.477580\n\
se.statistics.slice_max                      :             0.000000\n\
se.statistics.wait_max                       :             8.608642\n\
se.statistics.wait_sum                       :          4683.266835\n\
se.statistics.wait_count                     :               300964\n\
se.statistics.iowait_sum                     :             0.000000\n\
se.statistics.iowait_count                   :                    0\n\
se.statistics.nr_migrations_cold             :                    0\n\
se.statistics.nr_failed_migrations_affine    :                  297\n\
se.statistics.nr_failed_migrations_running   :                 1412\n\
se.statistics.nr_failed_migrations_hot       :                   96\n\
se.statistics.nr_forced_migrations           :                   26\n\
se.statistics.nr_wakeups                     :               281263\n\
se.statistics.nr_wakeups_sync                :                   84\n\
se.statistics.nr_wakeups_migrate             :               132322\n\
se.statistics.nr_wakeups_local               :                 2165\n\
se.statistics.nr_wakeups_remote              :               279098\n\
se.statistics.nr_wakeups_affine              :                    0\n\
se.statistics.nr_wakeups_affine_attempts     :                    0\n\
se.statistics.nr_wakeups_passive             :                    0\n\
se.statistics.nr_wakeups_idle                :                    0\n\
avg_atom                                     :             0.453434\n\
avg_per_cpu                                  :             1.030040\n\
nr_switches                                  :               300963\n\
nr_voluntary_switches                        :               281252\n\
nr_involuntary_switches                      :                19711\n\
se.load.weight                               :             73477120\n\
se.avg.load_sum                              :                   58\n\
se.avg.runnable_sum                          :                27648\n\
se.avg.util_sum                              :                21504\n\
se.avg.load_avg                              :                   48\n\
se.avg.runnable_avg                          :                    0\n\
se.avg.util_avg                              :                    0\n\
se.avg.last_update_time                      :        8132075824128\n\
se.avg.util_est.ewma                         :                    8\n\
se.avg.util_est.enqueued                     :                    1\n\
uclamp.min                                   :                    0\n\
uclamp.max                                   :                 1024\n\
effective uclamp.min                         :                    0\n\
effective uclamp.max                         :                 1024\n\
policy                                       :                    0\n\
prio                                         :                  101\n\
clock-delta                                  :                  163";

  std::map<std::string, double> m = parseThreadSchedString(fakeString);

  auto it = m.find("clock-delta");
  ASSERT_NE(it, m.end());
  ASSERT_EQ(it->second, 163);

  it = m.find("se.avg.load_avg");
  ASSERT_NE(it, m.end());
  ASSERT_EQ(it->second, 48);
}
