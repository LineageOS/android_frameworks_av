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

#ifndef CODEC2_HIDL_PLUGIN_FILTER_WRAPPER_H

#define CODEC2_HIDL_PLUGIN_FILTER_WRAPPER_H

#include <map>
#include <memory>
#include <mutex>

#include <C2Component.h>
#include <C2PlatformSupport.h>

#include <codec2/hidl/plugin/FilterPlugin.h>
#include <utils/Errors.h>

namespace android {

// TODO: documentation
class FilterWrapper : public std::enable_shared_from_this<FilterWrapper> {
public:
    using Descriptor = FilterPlugin_V1::Descriptor;

    class Plugin {
    public:
        Plugin() = default;
        virtual ~Plugin() = default;
        virtual status_t status() const = 0;
        virtual std::shared_ptr<C2ComponentStore> getStore() = 0;
        virtual bool describe(C2String name, Descriptor *desc) = 0;
        virtual bool isFilteringEnabled(const std::shared_ptr<C2ComponentInterface> &intf) = 0;
        virtual c2_status_t queryParamsForPreviousComponent(
                const std::shared_ptr<C2ComponentInterface> &intf,
                std::vector<std::unique_ptr<C2Param>> *params) = 0;
        C2_DO_NOT_COPY(Plugin);
    };

    struct Component {
        const std::shared_ptr<C2Component> comp;
        const std::shared_ptr<C2ComponentInterface> intf;
        const C2Component::Traits traits;
        const Descriptor desc;
    };

private:
    explicit FilterWrapper(std::unique_ptr<Plugin> &&plugin);
public:
    static std::shared_ptr<FilterWrapper> Create(std::unique_ptr<Plugin> &&plugin) {
        return std::shared_ptr<FilterWrapper>(new FilterWrapper(std::move(plugin)));
    }
    ~FilterWrapper();

    /**
     * Returns wrapped interface, or |intf| if wrapping is not possible / needed.
     */
    std::shared_ptr<C2ComponentInterface> maybeWrapInterface(
            const std::shared_ptr<C2ComponentInterface> intf);

    /**
     * Returns wrapped component, or |comp| if wrapping is not possible / needed.
     */
    std::shared_ptr<C2Component> maybeWrapComponent(
            const std::shared_ptr<C2Component> comp);

    /**
     * Returns ture iff the filtering will apply to the buffer in current configuration.
     */
    bool isFilteringEnabled(const std::shared_ptr<C2ComponentInterface> &intf);

    /**
     * Create a C2BlockPool object with |allocatorId| for |component|.
     */
    c2_status_t createBlockPool(
            C2PlatformAllocatorStore::id_t allocatorId,
            std::shared_ptr<const C2Component> component,
            std::shared_ptr<C2BlockPool> *pool);

    /**
     * Create a C2BlockPool object with |allocatorParam| for |component|.
     */
    c2_status_t createBlockPool(
            C2PlatformAllocatorDesc &allocatorParam,
            std::shared_ptr<const C2Component> component,
            std::shared_ptr<C2BlockPool> *pool);

    /**
     * Query parameters that |intf| wants from the previous component.
     */
    c2_status_t queryParamsForPreviousComponent(
            const std::shared_ptr<C2ComponentInterface> &intf,
            std::vector<std::unique_ptr<C2Param>> *params);

private:
    status_t mInit;
    std::unique_ptr<Plugin> mPlugin;
    std::shared_ptr<C2ComponentStore> mStore;
    std::list<FilterWrapper::Component> mComponents;

    std::mutex mCacheMutex;
    std::map<std::string, C2Component::Traits> mCachedTraits;

    std::mutex mWrappedComponentsMutex;
    std::list<std::vector<std::weak_ptr<const C2Component>>> mWrappedComponents;

    std::vector<FilterWrapper::Component> createFilters();
    C2Component::Traits getTraits(const std::shared_ptr<C2ComponentInterface> &intf);

    C2_DO_NOT_COPY(FilterWrapper);
};

}  // namespace android

#endif  // CODEC2_HIDL_PLUGIN_FILTER_WRAPPER_H
