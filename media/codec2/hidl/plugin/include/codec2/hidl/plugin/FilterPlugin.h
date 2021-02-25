/*
 * Copyright 2018, The Android Open Source Project
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

#ifndef CODEC2_HIDL_PLUGIN_FILTER_PLUGIN_H

#define CODEC2_HIDL_PLUGIN_FILTER_PLUGIN_H

#include <memory>

#include <C2Component.h>

namespace android {

class FilterPlugin_V1 {
public:
    static constexpr int32_t VERSION = 1;

    virtual ~FilterPlugin_V1() = default;

    /**
     * Returns a C2ComponentStore object with which clients can create
     * filter components / interfaces.
     */
    virtual std::shared_ptr<C2ComponentStore> getComponentStore() = 0;
    struct Descriptor {
        // Parameters that client sets for filter control.
        std::initializer_list<C2Param::Type> controlParams;
        // Parameters that the component changes after filtering.
        std::initializer_list<C2Param::Type> affectedParams;
    };

    /**
     * Describe a filter component.
     *
     * @param name[in]  filter's name
     * @param desc[out] pointer to filter descriptor to be populated
     * @return  true if |name| is in the store and |desc| is populated;
     *          false if |name| is not recognized
     */
    virtual bool describe(C2String name, Descriptor *desc) = 0;

    /**
     * Returns true if a component will apply filtering after all given the
     * current configuration; false if it will be no-op.
     */
    virtual bool isFilteringEnabled(const std::shared_ptr<C2ComponentInterface> &intf) = 0;
};

}  // namespace android

extern "C" {

typedef int32_t (*GetFilterPluginVersionFunc)();
int32_t GetFilterPluginVersion();

typedef void* (*CreateFilterPluginFunc)();
void *CreateFilterPlugin();

typedef void (*DestroyFilterPluginFunc)(void *);
void DestroyFilterPlugin(void *plugin);

}  // extern "C"

#endif  // CODEC2_HIDL_PLUGIN_FILTER_PLUGIN_H
