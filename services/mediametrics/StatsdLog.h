/*
 * Copyright (C) 2021 The Android Open Source Project
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

#include <audio_utils/SimpleLog.h>
#include <map>
#include <mutex>
#include <sstream>

namespace android::mediametrics {

class StatsdLog {
public:
    explicit StatsdLog(size_t lines) : mSimpleLog(lines) {}

    void log(int atom, const std::string& string) {
        {
            std::lock_guard lock(mLock);
            ++mCountMap[atom];
        }
        mSimpleLog.log("%s", string.c_str());
    }

   std::string dumpToString(const char *prefix = "", size_t logLines = 0) const {
       std::stringstream ss;

       {   // first print out the atom counts
           std::lock_guard lock(mLock);

           size_t col = 0;
           for (const auto& count : mCountMap) {
               if (col == 8) {
                   col = 0;
                   ss << "\n" << prefix;
               } else {
                   ss << " ";
               }
               ss << "[ " << count.first << " : " << count.second << " ]";
               ++col;
           }
           ss << "\n";
       }

       // then print out the log lines
       ss << mSimpleLog.dumpToString(prefix, logLines);
       return ss.str();
   }

private:
    SimpleLog mSimpleLog; // internally locked
    std::map<int /* atom */, size_t /* count */> mCountMap GUARDED_BY(mLock); // sorted
    mutable std::mutex mLock;
};

} // namespace android::mediametrics
