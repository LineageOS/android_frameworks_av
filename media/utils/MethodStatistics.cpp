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

#include <mediautils/MethodStatistics.h>

namespace android::mediautils {

// Repository for MethodStatistics Objects

std::shared_ptr<std::vector<std::string>>
getStatisticsClassesForModule(std::string_view moduleName) {
    static const std::map<std::string, std::shared_ptr<std::vector<std::string>>,
            std::less<> /* transparent comparator */> m {
        {
            METHOD_STATISTICS_MODULE_NAME_AUDIO_HIDL,
            std::shared_ptr<std::vector<std::string>>(
                new std::vector<std::string>{
                "DeviceHalHidl",
                "EffectHalHidl",
                "StreamInHalHidl",
                "StreamOutHalHidl",
              })
        },
    };
    auto it = m.find(moduleName);
    if (it == m.end()) return {};
    return it->second;
}

static void addClassesToMap(const std::shared_ptr<std::vector<std::string>> &classNames,
        std::map<std::string, std::shared_ptr<MethodStatistics<std::string>>,
                std::less<> /* transparent comparator */> &map) {
    if (classNames) {
        for (const auto& className : *classNames) {
            map.emplace(className, std::make_shared<MethodStatistics<std::string>>());
        }
    }
}

// singleton statistics for DeviceHalHidl StreamOutHalHidl StreamInHalHidl
std::shared_ptr<MethodStatistics<std::string>>
getStatisticsForClass(std::string_view className) {
    static const std::map<std::string, std::shared_ptr<MethodStatistics<std::string>>,
            std::less<> /* transparent comparator */> m =
        // copy elided initialization of map m.
        [](){
            std::map<std::string, std::shared_ptr<MethodStatistics<std::string>>, std::less<>> m;
            addClassesToMap(
                    getStatisticsClassesForModule(METHOD_STATISTICS_MODULE_NAME_AUDIO_HIDL),
                    m);
            return m;
        }();

    auto it = m.find(className);
    if (it == m.end()) return {};
    return it->second;
}

} // android::mediautils
