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

#define LOG_TAG "APM_EngineLoader"

#include <dlfcn.h>
#include <utils/Log.h>

#include "EngineLibrary.h"

namespace android {

// static
std::shared_ptr<EngineLibrary> EngineLibrary::load(std::string libraryPath)
{
    std::shared_ptr<EngineLibrary> engLib(new EngineLibrary());
    return engLib->init(std::move(libraryPath)) ? engLib : nullptr;
}

EngineLibrary::~EngineLibrary()
{
    close();
}

bool EngineLibrary::init(std::string libraryPath)
{
    mLibraryHandle = dlopen(libraryPath.c_str(), 0);
    if (mLibraryHandle == nullptr) {
        ALOGE("Could not dlopen %s: %s", libraryPath.c_str(), dlerror());
        return false;
    }
    mCreateEngineInstance = (EngineInterface* (*)())dlsym(mLibraryHandle, "createEngineInstance");
    mDestroyEngineInstance = (void (*)(EngineInterface*))dlsym(
            mLibraryHandle, "destroyEngineInstance");
    if (mCreateEngineInstance == nullptr || mDestroyEngineInstance == nullptr) {
        ALOGE("Could not find engine interface functions in %s", libraryPath.c_str());
        close();
        return false;
    }
    ALOGD("Loaded engine from %s", libraryPath.c_str());
    return true;
}

EngineInstance EngineLibrary::createEngine()
{
    if (mCreateEngineInstance == nullptr || mDestroyEngineInstance == nullptr) {
        return EngineInstance();
    }
    return EngineInstance(mCreateEngineInstance(),
            [lib = shared_from_this(), destroy = mDestroyEngineInstance] (EngineInterface* e) {
                destroy(e);
            });
}

void EngineLibrary::close()
{
    if (mLibraryHandle != nullptr) {
        dlclose(mLibraryHandle);
    }
    mLibraryHandle = nullptr;
    mCreateEngineInstance = nullptr;
    mDestroyEngineInstance = nullptr;
}

}  // namespace android
