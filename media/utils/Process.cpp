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

#define LOG_TAG "Process"
#include <utils/Log.h>
#include <mediautils/Process.h>

#include <android-base/file.h>
#include <android-base/strings.h>
#include <cstdlib>

namespace {

void processLine(std::string_view s, std::map<std::string, double>& m) {
    if (s.empty()) return;

    const size_t colon_pos = s.find(':');
    if (colon_pos == std::string_view::npos) return;

    const size_t space_pos = s.find(' ');
    if (space_pos == 0 || space_pos == std::string_view::npos || space_pos > colon_pos) return;
    std::string key(s.data(), s.data() + space_pos);

    const size_t value_pos = s.find_first_not_of(' ', colon_pos + 1);
    if (value_pos == std::string_view::npos) return;

    const double value = strtod(s.data() + value_pos, nullptr /* end */);
    m[std::move(key)] = value;
}

} // namespace

namespace android::mediautils {

std::string getThreadSchedAsString(pid_t tid) {
    const pid_t pid = getpid();
    const std::string path = std::string("/proc/").append(std::to_string(pid))
            .append("/task/").append(std::to_string(tid)).append("/sched");
    std::string sched;
    (void)android::base::ReadFileToString(path.c_str(), &sched);
    return sched;
}

std::map<std::string, double> parseThreadSchedString(const std::string& schedString) {
    std::map<std::string, double> m;
    if (schedString.empty()) return m;
    std::vector<std::string> stringlist = android::base::Split(schedString, "\n");

    //  OK we use values not strings... m["summary"] = stringlist[0];
    for (size_t i = 2; i < stringlist.size(); ++i) {
        processLine(stringlist[i], m);
    }
    return m;
}

} // namespace android::mediautils
