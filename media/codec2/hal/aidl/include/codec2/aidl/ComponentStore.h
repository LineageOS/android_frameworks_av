/*
 * Copyright 2018 The Android Open Source Project
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

#ifndef CODEC2_AIDL_UTILS_COMPONENTSTORE_H
#define CODEC2_AIDL_UTILS_COMPONENTSTORE_H

#include <android/binder_auto_utils.h>
#include <codec2/aidl/ComponentInterface.h>
#include <codec2/aidl/Configurable.h>

#include <aidl/android/hardware/media/bufferpool2/IClientManager.h>
#include <aidl/android/hardware/media/c2/BnComponentStore.h>
#include <aidl/android/hardware/media/c2/IInputSurface.h>

#include <C2Component.h>
#include <C2Param.h>
#include <C2.h>

#include <chrono>
#include <map>
#include <memory>
#include <mutex>
#include <set>
#include <vector>

namespace android {
class FilterWrapper;
}  // namespace android

namespace aidl {
namespace android {
namespace hardware {
namespace media {
namespace c2 {
namespace utils {

struct Component;

using ::aidl::android::hardware::media::bufferpool2::IClientManager;

struct ComponentStore : public BnComponentStore {
    ComponentStore(const std::shared_ptr<C2ComponentStore>& store);
    virtual ~ComponentStore();

    /**
     * Returns the status of the construction of this object.
     */
    c2_status_t status() const;

    /**
     * This function is called by CachedConfigurable::init() to validate
     * supported parameters.
     */
    c2_status_t validateSupportedParams(
            const std::vector<std::shared_ptr<C2ParamDescriptor>>& params);

    /**
     * Returns the store's ParameterCache. This is used for validation by
     * Configurable::init().
     */
    std::shared_ptr<ParameterCache> getParameterCache() const;

    static std::shared_ptr<::android::FilterWrapper> GetFilterWrapper();

    // Methods from ::aidl::android::hardware::media::c2::IComponentStore.
    virtual ::ndk::ScopedAStatus createComponent(
            const std::string& name,
            const std::shared_ptr<IComponentListener>& listener,
            const std::shared_ptr<IClientManager>& pool,
            std::shared_ptr<IComponent> *component) override;
    virtual ::ndk::ScopedAStatus createInterface(
            const std::string& name,
            std::shared_ptr<IComponentInterface> *intf) override;
    virtual ::ndk::ScopedAStatus listComponents(
            std::vector<IComponentStore::ComponentTraits>* traits) override;
    virtual ::ndk::ScopedAStatus createInputSurface(
            std::shared_ptr<IInputSurface> *inputSurface) override;
    virtual ::ndk::ScopedAStatus getStructDescriptors(
            const std::vector<int32_t>& indices,
            std::vector<StructDescriptor> *descs) override;
    virtual ::ndk::ScopedAStatus getPoolClientManager(
            std::shared_ptr<IClientManager> *manager) override;
    virtual ::ndk::ScopedAStatus copyBuffer(
            const Buffer& src,
            const Buffer& dst) override;
    virtual ::ndk::ScopedAStatus getConfigurable(
            std::shared_ptr<IConfigurable> *configurable) override;

    /**
     * Dumps information when lshal is called.
     */
    virtual binder_status_t dump(
            int fd, const char** args, uint32_t numArgs) override;

protected:
    std::shared_ptr<CachedConfigurable> mConfigurable;
    struct StoreParameterCache;
    std::shared_ptr<StoreParameterCache> mParameterCache;

    // Does bookkeeping for an interface that has been loaded.
    void onInterfaceLoaded(const std::shared_ptr<C2ComponentInterface> &intf);

    c2_status_t mInit;
    std::shared_ptr<C2ComponentStore> mStore;
    std::shared_ptr<C2ParamReflector> mParamReflector;

    std::map<C2Param::CoreIndex, std::shared_ptr<C2StructDescriptor>> mStructDescriptors;
    std::set<C2Param::CoreIndex> mUnsupportedStructDescriptors;
    std::set<C2String> mLoadedInterfaces;
    mutable std::mutex mStructDescriptorsMutex;

    // ComponentStore keeps track of live Components.

    struct ComponentStatus {
        std::shared_ptr<C2Component> c2Component;
        std::chrono::system_clock::time_point birthTime;
    };

    mutable std::mutex mComponentRosterMutex;
    std::map<Component*, ComponentStatus> mComponentRoster;

    // Called whenever Component is created.
    void reportComponentBirth(Component* component);
    // Called only from the destructor of Component.
    void reportComponentDeath(Component* component);

    friend Component;

    // Helper functions for dumping.

    std::ostream& dump(
            std::ostream& out,
            const std::shared_ptr<const C2Component::Traits>& comp);

    std::ostream& dump(
            std::ostream& out,
            ComponentStatus& compStatus);

};

}  // namespace utils
}  // namespace c2
}  // namespace media
}  // namespace hardware
}  // namespace android
}  // namespace aidl

#endif  // CODEC2_AIDL_UTILS_COMPONENTSTORE_H
