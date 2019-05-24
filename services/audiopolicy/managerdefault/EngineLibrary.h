/*
 * Copyright 2019 The Android Open Source Project
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

#include <functional>
#include <memory>
#include <string>

#include <EngineInterface.h>

namespace android {

using EngineInstance = std::unique_ptr<EngineInterface, std::function<void (EngineInterface*)>>;

class EngineLibrary : public std::enable_shared_from_this<EngineLibrary> {
public:
    static std::shared_ptr<EngineLibrary> load(std::string libraryPath);
    ~EngineLibrary();

    EngineLibrary(const EngineLibrary&) = delete;
    EngineLibrary(EngineLibrary&&) = delete;
    EngineLibrary& operator=(const EngineLibrary&) = delete;
    EngineLibrary& operator=(EngineLibrary&&) = delete;

    EngineInstance createEngine();

private:
    EngineLibrary() = default;
    bool init(std::string libraryPath);
    void close();

    void *mLibraryHandle = nullptr;
    EngineInterface* (*mCreateEngineInstance)() = nullptr;
    void (*mDestroyEngineInstance)(EngineInterface*) = nullptr;
};

}  // namespace android
