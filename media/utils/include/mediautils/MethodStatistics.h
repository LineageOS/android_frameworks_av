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
#include <vector>

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
    template <typename C>
    void event(C&& code, FloatType executeMs) {
        std::lock_guard lg(mLock);
        auto it = mStatisticsMap.lower_bound(code);
        if (it != mStatisticsMap.end() && it->first == code) {
            it->second.add(executeMs);
        } else {
            // StatsType ctor takes an optional array of data for initialization.
            FloatType dataArray[1] = { executeMs };
            mStatisticsMap.emplace_hint(it, std::forward<C>(code), dataArray);
        }
    }

    /**
     * Returns the name for the method code.
     */
    std::string getMethodForCode(const Code& code) const {
        auto it = mMethodMap.find(code);
        return it == mMethodMap.end() ? std::to_string((int)code) : it->second;
    }

    /**
     * Returns the number of times the method was invoked by event().
     */
    size_t getMethodCount(const Code& code) const {
        std::lock_guard lg(mLock);
        auto it = mStatisticsMap.find(code);
        return it == mStatisticsMap.end() ? 0 : it->second.getN();
    }

    /**
     * Returns the statistics object for the method.
     */
    StatsType getStatistics(const Code& code) const {
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
        if constexpr (std::is_same_v<Code, std::string>) {
            for (const auto &[code, stats] : mStatisticsMap) {
                ss << code <<
                        " n=" << stats.getN() << " " << stats.toString() << "\n";
            }
        } else /* constexpr */ {
            for (const auto &[code, stats] : mStatisticsMap) {
                ss << int(code) << " " << getMethodForCode(code) <<
                        " n=" << stats.getN() << " " << stats.toString() << "\n";
            }
        }
        return ss.str();
    }

private:
    // Note: we use a transparent comparator std::less<> for heterogeneous key lookup.
    const std::map<Code, std::string, std::less<>> mMethodMap;
    mutable std::mutex mLock;
    std::map<Code, StatsType, std::less<>> mStatisticsMap GUARDED_BY(mLock);
};

// Managed Statistics support.
// Supported Modules
#define METHOD_STATISTICS_MODULE_NAME_AUDIO_HIDL "AudioHidl"

// Returns a vector of class names for the module, or a nullptr if module not found.
std::shared_ptr<std::vector<std::string>>
getStatisticsClassesForModule(std::string_view moduleName);

// Returns a statistics object for that class, or a nullptr if class not found.
std::shared_ptr<MethodStatistics<std::string>>
getStatisticsForClass(std::string_view className);

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
