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

#include "MethodStatistics.h"
#include <chrono>
#include <memory>
#include <string>
#include <utility>

namespace android::mediautils {

class ScopedStatistics {
  public:
    /**
     * ScopedStatistics is a RAII way of obtaining
     * execution time statistics for a scoped C++ block.
     *
     * It updates the MethodStatistics shared pointer parameter
     * with the methodName parameter and the duration/lifetime of the
     * ScopedStatistics object.
     *
     * Not thread-safe, but expected to run in a single execution
     * thread, and there are no user serviceable parts exposed.
     *
     * Example:
     *
     * std::shared_ptr<mediautils::MethodStatistics<std::string>> stats =
     *     std::make_shared<mediautils::MethodStatistics<std::string>>();
     *
     * // ...
     * {
     *    mediautils::ScopedStatistics scopedStatistics("MyClass:myMethod", stats);
     *
     *    // some work to be timed here - up to the end of the block.
     * }
     *
     * \param methodName the methodname to use "ClassName::methodName"
     * \param statistics a shared ptr to the MethodStatistics object to use.
     */
    ScopedStatistics(std::string methodName,
               std::shared_ptr<mediautils::MethodStatistics<std::string>> statistics)
        : mMethodName{std::move(methodName)}
        , mStatistics{std::move(statistics)}
        , mBegin{std::chrono::steady_clock::now()} {}

    // No copy constructor.
    ScopedStatistics(const ScopedStatistics& scopedStatistics) = delete;
    ScopedStatistics& operator=(const ScopedStatistics& scopedStatistics) = delete;

    ~ScopedStatistics() {
        if (mStatistics) {
            const float elapsedMs = std::chrono::duration_cast<std::chrono::nanoseconds>(
                                            std::chrono::steady_clock::now() - mBegin)
                                            .count() *
                                    1e-6; // ns to ms.
            mStatistics->event(mMethodName, elapsedMs);
        }
    }

  private:
    const std::string mMethodName;
    const std::shared_ptr<mediautils::MethodStatistics<std::string>> mStatistics;
    const std::chrono::steady_clock::time_point mBegin;
};

} // namespace android::mediautils
