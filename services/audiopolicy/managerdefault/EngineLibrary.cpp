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

EngineInstance loadApmEngineLibraryAndCreateEngine(const std::string& librarySuffix,
        const std::string& configXmlFilePath)
{
    auto engLib = EngineLibrary::load(librarySuffix);
    if (!engLib) {
        ALOGE("%s: Failed to load the engine library, suffix \"%s\"",
                __func__, librarySuffix.c_str());
        return nullptr;
    }
    auto engine = engLib->createEngineUsingXmlConfig(configXmlFilePath);
    if (engine == nullptr) {
        ALOGE("%s: Failed to instantiate the APM engine", __func__);
        return nullptr;
    }
    return engine;
}

EngineInstance loadApmEngineLibraryAndCreateEngine(const std::string& librarySuffix,
        const media::audio::common::AudioHalEngineConfig& config)
{
    auto engLib = EngineLibrary::load(librarySuffix);
    if (!engLib) {
        ALOGE("%s: Failed to load the engine library, suffix \"%s\"",
                __func__, librarySuffix.c_str());
        return nullptr;
    }
    auto engine = engLib->createEngineUsingHalConfig(config);
    if (engine == nullptr) {
        ALOGE("%s: Failed to instantiate the APM engine", __func__);
        return nullptr;
    }
    return engine;
}

// static
std::shared_ptr<EngineLibrary> EngineLibrary::load(const std::string& librarySuffix)
{
    std::string libraryPath = "libaudiopolicyengine" + librarySuffix + ".so";
    std::shared_ptr<EngineLibrary> engLib(new EngineLibrary());
    return engLib->init(std::move(libraryPath)) ? engLib : nullptr;
}

EngineLibrary::~EngineLibrary()
{
    close();
}

EngineInstance EngineLibrary::createEngineUsingXmlConfig(const std::string& xmlFilePath)
{
    auto instance = createEngine();
    if (instance != nullptr) {
        if (status_t status = instance->loadFromXmlConfigWithFallback(xmlFilePath);
                status == OK) {
            return instance;
        } else {
            ALOGE("%s: loading of the engine config with XML configuration file \"%s\" failed: %d",
                    __func__, xmlFilePath.empty() ? "default" : xmlFilePath.c_str(), status);
        }
    }
    return nullptr;
}

EngineInstance EngineLibrary::createEngineUsingHalConfig(
        const media::audio::common::AudioHalEngineConfig& config)
{
    auto instance = createEngine();
    if (instance != nullptr) {
        if (status_t status = instance->loadFromHalConfigWithFallback(config); status == OK) {
            return instance;
        } else {
            ALOGE("%s: loading of the engine config with HAL configuration \"%s\" failed: %d",
                    __func__, config.toString().c_str(), status);
        }
    }
    return nullptr;
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
