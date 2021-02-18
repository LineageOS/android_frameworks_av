/*
 * Copyright 2020, The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef CODEC2_HIDL_PLUGIN_DEFAULT_FILTER_PLUGIN_H

#define CODEC2_HIDL_PLUGIN_DEFAULT_FILTER_PLUGIN_H

#include <codec2/hidl/plugin/FilterPlugin.h>

#include <FilterWrapper.h>

namespace android {

class DefaultFilterPlugin : public FilterWrapper::Plugin {
public:
    explicit DefaultFilterPlugin(const char *pluginPath);

    ~DefaultFilterPlugin();

    status_t status() const override { return mInit; }

    std::shared_ptr<C2ComponentStore> getStore() override { return mStore; }
    bool describe(C2String name, FilterWrapper::Descriptor *desc) override;
    bool isFilteringEnabled(const std::shared_ptr<C2ComponentInterface> &intf) override;

private:
    status_t mInit;
    void *mHandle;
    DestroyFilterPluginFunc mDestroyPlugin;
    FilterPlugin_V1 *mPlugin;
    std::shared_ptr<C2ComponentStore> mStore;
};

}  // namespace android

#endif  // CODEC2_HIDL_PLUGIN_DEFAULT_FILTER_PLUGIN_H
