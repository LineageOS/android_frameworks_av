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
#include <mutex>
#include <string>

#include <android-base/thread_annotations.h>
#include <audio_utils/Statistics.h>

namespace android::mediautils {

/**
 * MethodStatistics is used to associate Binder codes
 * with a method name and execution time statistics.
 *
 * This is used to track binder transaction times for
 * AudioFlinger and AudioPolicy services.
 *
 * Here, Code is the enumeration type for the method
 * lookup.
 */
template <typename Code>
class MethodStatistics {
public:
    using FloatType = float;
    using StatsType = audio_utils::Statistics<FloatType>;

    /**
     * Method statistics.
     *
     * Initialized with the Binder transaction list for tracking AudioFlinger
     * and AudioPolicyManager execution statistics.
     */
    explicit MethodStatistics(
            const std::initializer_list<std::pair<const Code, std::string>>& methodMap = {})
        : mMethodMap{methodMap} {}

    /**
     * Adds a method event, typically execution time in ms.
     */
    void event(Code code, FloatType executeMs) {
        std::lock_guard lg(mLock);
        mStatisticsMap[code].add(executeMs);
    }

    /**
     * Returns the name for the method code.
     */
    std::string getMethodForCode(Code code) const {
        auto it = mMethodMap.find(code);
        return it == mMethodMap.end() ? std::to_string((int)code) : it->second;
    }

    /**
     * Returns the number of times the method was invoked by event().
     */
    size_t getMethodCount(Code code) const {
        std::lock_guard lg(mLock);
        auto it = mStatisticsMap.find(code);
        return it == mStatisticsMap.end() ? 0 : it->second.getN();
    }

    /**
     * Returns the statistics object for the method.
     */
    StatsType getStatistics(Code code) const {
        std::lock_guard lg(mLock);
        auto it = mStatisticsMap.find(code);
        return it == mStatisticsMap.end() ? StatsType{} : it->second;
    }

    /**
     * Dumps the current method statistics.
     */
    std::string dump() const {
        std::stringstream ss;
        std::lock_guard lg(mLock);
        for (const auto &[code, stats] : mStatisticsMap) {
            ss << int(code) << " " << getMethodForCode(code) <<
                    " n=" << stats.getN() << " " << stats.toString() << "\n";
        }
        return ss.str();
    }

private:
    const std::map<Code, std::string> mMethodMap;
    mutable std::mutex mLock;
    std::map<Code, StatsType> mStatisticsMap GUARDED_BY(mLock);
};

// Only if used, requires IBinder.h to be included at the location of invocation.
#define METHOD_STATISTICS_BINDER_CODE_NAMES(CODE_TYPE) \
    {(CODE_TYPE)IBinder::PING_TRANSACTION , "ping"}, \
    {(CODE_TYPE)IBinder::DUMP_TRANSACTION , "dump"}, \
    {(CODE_TYPE)IBinder::SHELL_COMMAND_TRANSACTION , "shellCommand"}, \
    {(CODE_TYPE)IBinder::INTERFACE_TRANSACTION , "getInterfaceDescriptor"}, \
    {(CODE_TYPE)IBinder::SYSPROPS_TRANSACTION , "SYSPROPS_TRANSACTION"}, \
    {(CODE_TYPE)IBinder::EXTENSION_TRANSACTION , "EXTENSION_TRANSACTION"}, \
    {(CODE_TYPE)IBinder::DEBUG_PID_TRANSACTION , "DEBUG_PID_TRANSACTION"}, \

} // android::mediautils
