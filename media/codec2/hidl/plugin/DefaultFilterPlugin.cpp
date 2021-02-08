/*
 * Copyright 2020 The Android Open Source Project
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

//#define LOG_NDEBUG 0
#define LOG_TAG "Codec2-DefaultFilterPlugin"
#include <android-base/logging.h>

#include <set>

#include <dlfcn.h>

#include <C2Config.h>
#include <C2Debug.h>
#include <C2ParamInternal.h>

#include <codec2/hidl/plugin/FilterPlugin.h>

#include <DefaultFilterPlugin.h>
#include <FilterWrapper.h>

namespace android {

DefaultFilterPlugin::DefaultFilterPlugin(const char *pluginPath)
    : mInit(NO_INIT),
      mHandle(nullptr),
      mDestroyPlugin(nullptr),
      mPlugin(nullptr) {
    mHandle = dlopen(pluginPath, RTLD_NOW | RTLD_NODELETE);
    if (!mHandle) {
        LOG(DEBUG) << "FilterPlugin: no plugin detected";
        return;
    }
    GetFilterPluginVersionFunc getVersion =
        (GetFilterPluginVersionFunc)dlsym(mHandle, "GetFilterPluginVersion");
    if (!getVersion) {
        LOG(WARNING) << "FilterPlugin: GetFilterPluginVersion undefined";
        return;
    }
    int32_t version = getVersion();
    if (version != FilterPlugin_V1::VERSION) {
        LOG(WARNING) << "FilterPlugin: unrecognized version (" << version << ")";
        return;
    }
    CreateFilterPluginFunc createPlugin =
        (CreateFilterPluginFunc)dlsym(mHandle, "CreateFilterPlugin");
    if (!createPlugin) {
        LOG(WARNING) << "FilterPlugin: CreateFilterPlugin undefined";
        return;
    }
    mDestroyPlugin =
        (DestroyFilterPluginFunc)dlsym(mHandle, "DestroyFilterPlugin");
    if (!mDestroyPlugin) {
        LOG(WARNING) << "FilterPlugin: DestroyFilterPlugin undefined";
        return;
    }
    mPlugin = (FilterPlugin_V1 *)createPlugin();
    if (!mPlugin) {
        LOG(WARNING) << "FilterPlugin: CreateFilterPlugin returned nullptr";
        return;
    }
    mStore = mPlugin->getComponentStore();
    if (!mStore) {
        LOG(WARNING) << "FilterPlugin: FilterPlugin_V1::getComponentStore returned nullptr";
        return;
    }
    mInit = OK;
}

DefaultFilterPlugin::~DefaultFilterPlugin() {
    if (mHandle) {
        if (mDestroyPlugin && mPlugin) {
            mDestroyPlugin(mPlugin);
            mPlugin = nullptr;
        }
        dlclose(mHandle);
        mHandle = nullptr;
        mDestroyPlugin = nullptr;
    }
}

bool DefaultFilterPlugin::describe(C2String name, FilterWrapper::Descriptor *desc) {
    if (mInit != OK) {
        return false;
    }
    return mPlugin->describe(name, desc);
}

bool DefaultFilterPlugin::isFilteringEnabled(const std::shared_ptr<C2ComponentInterface> &intf) {
    if (mInit != OK) {
        return false;
    }
    return mPlugin->isFilteringEnabled(intf);
}

}  // namespace android
