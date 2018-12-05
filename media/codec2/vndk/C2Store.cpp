/*
 * Copyright (C) 2017 The Android Open Source Project
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

#define LOG_TAG "C2Store"
#define LOG_NDEBUG 0
#include <utils/Log.h>

#include <C2AllocatorGralloc.h>
#include <C2AllocatorIon.h>
#include <C2BufferPriv.h>
#include <C2BqBufferPriv.h>
#include <C2Component.h>
#include <C2Config.h>
#include <C2PlatformStorePluginLoader.h>
#include <C2PlatformSupport.h>
#include <util/C2InterfaceHelper.h>

#include <dlfcn.h>
#include <unistd.h> // getpagesize

#include <map>
#include <memory>
#include <mutex>

namespace android {

/**
 * Returns the preferred component store in this process to access its interface.
 */
std::shared_ptr<C2ComponentStore> GetPreferredCodec2ComponentStore();

/**
 * The platform allocator store provides basic allocator-types for the framework based on ion and
 * gralloc. Allocators are not meant to be updatable.
 *
 * \todo Provide allocator based on ashmem
 * \todo Move ion allocation into its HIDL or provide some mapping from memory usage to ion flags
 * \todo Make this allocator store extendable
 */
class C2PlatformAllocatorStoreImpl : public C2PlatformAllocatorStore {
public:
    C2PlatformAllocatorStoreImpl();

    virtual c2_status_t fetchAllocator(
            id_t id, std::shared_ptr<C2Allocator> *const allocator) override;

    virtual std::vector<std::shared_ptr<const C2Allocator::Traits>> listAllocators_nb()
            const override {
        return std::vector<std::shared_ptr<const C2Allocator::Traits>>(); /// \todo
    }

    virtual C2String getName() const override {
        return "android.allocator-store";
    }

    void setComponentStore(std::shared_ptr<C2ComponentStore> store);

    ~C2PlatformAllocatorStoreImpl() override = default;

private:
    /// returns a shared-singleton ion allocator
    std::shared_ptr<C2Allocator> fetchIonAllocator();

    /// returns a shared-singleton gralloc allocator
    std::shared_ptr<C2Allocator> fetchGrallocAllocator();

    /// returns a shared-singleton bufferqueue supporting gralloc allocator
    std::shared_ptr<C2Allocator> fetchBufferQueueAllocator();

    /// component store to use
    std::mutex _mComponentStoreSetLock; // protects the entire updating _mComponentStore and its
                                        // dependencies
    std::mutex _mComponentStoreReadLock; // must protect only read/write of _mComponentStore
    std::shared_ptr<C2ComponentStore> _mComponentStore;
};

C2PlatformAllocatorStoreImpl::C2PlatformAllocatorStoreImpl() {
}

c2_status_t C2PlatformAllocatorStoreImpl::fetchAllocator(
        id_t id, std::shared_ptr<C2Allocator> *const allocator) {
    allocator->reset();
    switch (id) {
    // TODO: should we implement a generic registry for all, and use that?
    case C2PlatformAllocatorStore::ION:
    case C2AllocatorStore::DEFAULT_LINEAR:
        *allocator = fetchIonAllocator();
        break;

    case C2PlatformAllocatorStore::GRALLOC:
    case C2AllocatorStore::DEFAULT_GRAPHIC:
        *allocator = fetchGrallocAllocator();
        break;

    case C2PlatformAllocatorStore::BUFFERQUEUE:
        *allocator = fetchBufferQueueAllocator();
        break;

    default:
        // Try to create allocator from platform store plugins.
        c2_status_t res =
                C2PlatformStorePluginLoader::GetInstance()->createAllocator(id, allocator);
        if (res != C2_OK) {
            return res;
        }
        break;
    }
    if (*allocator == nullptr) {
        return C2_NO_MEMORY;
    }
    return C2_OK;
}

namespace {

std::mutex gIonAllocatorMutex;
std::weak_ptr<C2AllocatorIon> gIonAllocator;

void UseComponentStoreForIonAllocator(
        const std::shared_ptr<C2AllocatorIon> allocator,
        std::shared_ptr<C2ComponentStore> store) {
    C2AllocatorIon::UsageMapperFn mapper;
    uint64_t minUsage = 0;
    uint64_t maxUsage = C2MemoryUsage(C2MemoryUsage::CPU_READ, C2MemoryUsage::CPU_WRITE).expected;
    size_t blockSize = getpagesize();

    // query min and max usage as well as block size via supported values
    C2StoreIonUsageInfo usageInfo;
    std::vector<C2FieldSupportedValuesQuery> query = {
        C2FieldSupportedValuesQuery::Possible(C2ParamField::Make(usageInfo, usageInfo.usage)),
        C2FieldSupportedValuesQuery::Possible(C2ParamField::Make(usageInfo, usageInfo.capacity)),
    };
    c2_status_t res = store->querySupportedValues_sm(query);
    if (res == C2_OK) {
        if (query[0].status == C2_OK) {
            const C2FieldSupportedValues &fsv = query[0].values;
            if (fsv.type == C2FieldSupportedValues::FLAGS && !fsv.values.empty()) {
                minUsage = fsv.values[0].u64;
                maxUsage = 0;
                for (C2Value::Primitive v : fsv.values) {
                    maxUsage |= v.u64;
                }
            }
        }
        if (query[1].status == C2_OK) {
            const C2FieldSupportedValues &fsv = query[1].values;
            if (fsv.type == C2FieldSupportedValues::RANGE && fsv.range.step.u32 > 0) {
                blockSize = fsv.range.step.u32;
            }
        }

        mapper = [store](C2MemoryUsage usage, size_t capacity,
                         size_t *align, unsigned *heapMask, unsigned *flags) -> c2_status_t {
            if (capacity > UINT32_MAX) {
                return C2_BAD_VALUE;
            }
            C2StoreIonUsageInfo usageInfo = { usage.expected, capacity };
            std::vector<std::unique_ptr<C2SettingResult>> failures; // TODO: remove
            c2_status_t res = store->config_sm({&usageInfo}, &failures);
            if (res == C2_OK) {
                *align = usageInfo.minAlignment;
                *heapMask = usageInfo.heapMask;
                *flags = usageInfo.allocFlags;
            }
            return res;
        };
    }

    allocator->setUsageMapper(mapper, minUsage, maxUsage, blockSize);
}

}

void C2PlatformAllocatorStoreImpl::setComponentStore(std::shared_ptr<C2ComponentStore> store) {
    // technically this set lock is not needed, but is here for safety in case we add more
    // getter orders
    std::lock_guard<std::mutex> lock(_mComponentStoreSetLock);
    {
        std::lock_guard<std::mutex> lock(_mComponentStoreReadLock);
        _mComponentStore = store;
    }
    std::shared_ptr<C2AllocatorIon> allocator;
    {
        std::lock_guard<std::mutex> lock(gIonAllocatorMutex);
        allocator = gIonAllocator.lock();
    }
    if (allocator) {
        UseComponentStoreForIonAllocator(allocator, store);
    }
}

std::shared_ptr<C2Allocator> C2PlatformAllocatorStoreImpl::fetchIonAllocator() {
    std::lock_guard<std::mutex> lock(gIonAllocatorMutex);
    std::shared_ptr<C2AllocatorIon> allocator = gIonAllocator.lock();
    if (allocator == nullptr) {
        std::shared_ptr<C2ComponentStore> componentStore;
        {
            std::lock_guard<std::mutex> lock(_mComponentStoreReadLock);
            componentStore = _mComponentStore;
        }
        allocator = std::make_shared<C2AllocatorIon>(C2PlatformAllocatorStore::ION);
        UseComponentStoreForIonAllocator(allocator, componentStore);
        gIonAllocator = allocator;
    }
    return allocator;
}

std::shared_ptr<C2Allocator> C2PlatformAllocatorStoreImpl::fetchGrallocAllocator() {
    static std::mutex mutex;
    static std::weak_ptr<C2Allocator> grallocAllocator;
    std::lock_guard<std::mutex> lock(mutex);
    std::shared_ptr<C2Allocator> allocator = grallocAllocator.lock();
    if (allocator == nullptr) {
        allocator = std::make_shared<C2AllocatorGralloc>(C2PlatformAllocatorStore::GRALLOC);
        grallocAllocator = allocator;
    }
    return allocator;
}

std::shared_ptr<C2Allocator> C2PlatformAllocatorStoreImpl::fetchBufferQueueAllocator() {
    static std::mutex mutex;
    static std::weak_ptr<C2Allocator> grallocAllocator;
    std::lock_guard<std::mutex> lock(mutex);
    std::shared_ptr<C2Allocator> allocator = grallocAllocator.lock();
    if (allocator == nullptr) {
        allocator = std::make_shared<C2AllocatorGralloc>(
                C2PlatformAllocatorStore::BUFFERQUEUE, true);
        grallocAllocator = allocator;
    }
    return allocator;
}

namespace {
    std::mutex gPreferredComponentStoreMutex;
    std::shared_ptr<C2ComponentStore> gPreferredComponentStore;

    std::mutex gPlatformAllocatorStoreMutex;
    std::weak_ptr<C2PlatformAllocatorStoreImpl> gPlatformAllocatorStore;
}

std::shared_ptr<C2AllocatorStore> GetCodec2PlatformAllocatorStore() {
    std::lock_guard<std::mutex> lock(gPlatformAllocatorStoreMutex);
    std::shared_ptr<C2PlatformAllocatorStoreImpl> store = gPlatformAllocatorStore.lock();
    if (store == nullptr) {
        store = std::make_shared<C2PlatformAllocatorStoreImpl>();
        store->setComponentStore(GetPreferredCodec2ComponentStore());
        gPlatformAllocatorStore = store;
    }
    return store;
}

void SetPreferredCodec2ComponentStore(std::shared_ptr<C2ComponentStore> componentStore) {
    static std::mutex mutex;
    std::lock_guard<std::mutex> lock(mutex); // don't interleve set-s

    // update preferred store
    {
        std::lock_guard<std::mutex> lock(gPreferredComponentStoreMutex);
        gPreferredComponentStore = componentStore;
    }

    // update platform allocator's store as well if it is alive
    std::shared_ptr<C2PlatformAllocatorStoreImpl> allocatorStore;
    {
        std::lock_guard<std::mutex> lock(gPlatformAllocatorStoreMutex);
        allocatorStore = gPlatformAllocatorStore.lock();
    }
    if (allocatorStore) {
        allocatorStore->setComponentStore(componentStore);
    }
}

std::shared_ptr<C2ComponentStore> GetPreferredCodec2ComponentStore() {
    std::lock_guard<std::mutex> lock(gPreferredComponentStoreMutex);
    return gPreferredComponentStore ? gPreferredComponentStore : GetCodec2PlatformComponentStore();
}

namespace {

class _C2BlockPoolCache {
public:
    _C2BlockPoolCache() : mBlockPoolSeqId(C2BlockPool::PLATFORM_START + 1) {}

    c2_status_t _createBlockPool(
            C2PlatformAllocatorStore::id_t allocatorId,
            std::shared_ptr<const C2Component> component,
            C2BlockPool::local_id_t poolId,
            std::shared_ptr<C2BlockPool> *pool) {
        std::shared_ptr<C2AllocatorStore> allocatorStore =
                GetCodec2PlatformAllocatorStore();
        std::shared_ptr<C2Allocator> allocator;
        c2_status_t res = C2_NOT_FOUND;

        switch(allocatorId) {
            case C2PlatformAllocatorStore::ION:
            case C2AllocatorStore::DEFAULT_LINEAR:
                res = allocatorStore->fetchAllocator(
                        C2AllocatorStore::DEFAULT_LINEAR, &allocator);
                if (res == C2_OK) {
                    std::shared_ptr<C2BlockPool> ptr =
                            std::make_shared<C2PooledBlockPool>(
                                    allocator, poolId);
                    *pool = ptr;
                    mBlockPools[poolId] = ptr;
                    mComponents[poolId] = component;
                }
                break;
            case C2PlatformAllocatorStore::GRALLOC:
            case C2AllocatorStore::DEFAULT_GRAPHIC:
                res = allocatorStore->fetchAllocator(
                        C2AllocatorStore::DEFAULT_GRAPHIC, &allocator);
                if (res == C2_OK) {
                    std::shared_ptr<C2BlockPool> ptr =
                        std::make_shared<C2PooledBlockPool>(allocator, poolId);
                    *pool = ptr;
                    mBlockPools[poolId] = ptr;
                    mComponents[poolId] = component;
                }
                break;
            case C2PlatformAllocatorStore::BUFFERQUEUE:
                res = allocatorStore->fetchAllocator(
                        C2PlatformAllocatorStore::BUFFERQUEUE, &allocator);
                if (res == C2_OK) {
                    std::shared_ptr<C2BlockPool> ptr =
                            std::make_shared<C2BufferQueueBlockPool>(
                                    allocator, poolId);
                    *pool = ptr;
                    mBlockPools[poolId] = ptr;
                    mComponents[poolId] = component;
                }
                break;
            default:
                // Try to create block pool from platform store plugins.
                std::shared_ptr<C2BlockPool> ptr;
                res = C2PlatformStorePluginLoader::GetInstance()->createBlockPool(
                        allocatorId, poolId, &ptr);
                if (res == C2_OK) {
                    *pool = ptr;
                    mBlockPools[poolId] = ptr;
                    mComponents[poolId] = component;
                }
                break;
        }
        return res;
    }

    c2_status_t createBlockPool(
            C2PlatformAllocatorStore::id_t allocatorId,
            std::shared_ptr<const C2Component> component,
            std::shared_ptr<C2BlockPool> *pool) {
        return _createBlockPool(allocatorId, component, mBlockPoolSeqId++, pool);
    }

    bool getBlockPool(
            C2BlockPool::local_id_t blockPoolId,
            std::shared_ptr<const C2Component> component,
            std::shared_ptr<C2BlockPool> *pool) {
        // TODO: use one iterator for multiple blockpool type scalability.
        std::shared_ptr<C2BlockPool> ptr;
        auto it = mBlockPools.find(blockPoolId);
        if (it != mBlockPools.end()) {
            ptr = it->second.lock();
            if (!ptr) {
                mBlockPools.erase(it);
                mComponents.erase(blockPoolId);
            } else {
                auto found = mComponents.find(blockPoolId);
                if (component == found->second.lock()) {
                    *pool = ptr;
                    return true;
                }
            }
        }
        return false;
    }

private:
    C2BlockPool::local_id_t mBlockPoolSeqId;

    std::map<C2BlockPool::local_id_t, std::weak_ptr<C2BlockPool>> mBlockPools;
    std::map<C2BlockPool::local_id_t, std::weak_ptr<const C2Component>> mComponents;
};

static std::unique_ptr<_C2BlockPoolCache> sBlockPoolCache =
    std::make_unique<_C2BlockPoolCache>();
static std::mutex sBlockPoolCacheMutex;

} // anynymous namespace

c2_status_t GetCodec2BlockPool(
        C2BlockPool::local_id_t id, std::shared_ptr<const C2Component> component,
        std::shared_ptr<C2BlockPool> *pool) {
    pool->reset();
    std::lock_guard<std::mutex> lock(sBlockPoolCacheMutex);
    std::shared_ptr<C2AllocatorStore> allocatorStore = GetCodec2PlatformAllocatorStore();
    std::shared_ptr<C2Allocator> allocator;
    c2_status_t res = C2_NOT_FOUND;

    if (id >= C2BlockPool::PLATFORM_START) {
        if (sBlockPoolCache->getBlockPool(id, component, pool)) {
            return C2_OK;
        }
    }

    switch (id) {
    case C2BlockPool::BASIC_LINEAR:
        res = allocatorStore->fetchAllocator(C2AllocatorStore::DEFAULT_LINEAR, &allocator);
        if (res == C2_OK) {
            *pool = std::make_shared<C2BasicLinearBlockPool>(allocator);
        }
        break;
    case C2BlockPool::BASIC_GRAPHIC:
        res = allocatorStore->fetchAllocator(C2AllocatorStore::DEFAULT_GRAPHIC, &allocator);
        if (res == C2_OK) {
            *pool = std::make_shared<C2BasicGraphicBlockPool>(allocator);
        }
        break;
    // TODO: remove this. this is temporary
    case C2BlockPool::PLATFORM_START:
        res = sBlockPoolCache->_createBlockPool(
                C2PlatformAllocatorStore::BUFFERQUEUE, component, id, pool);
        break;
    default:
        break;
    }
    return res;
}

c2_status_t CreateCodec2BlockPool(
        C2PlatformAllocatorStore::id_t allocatorId,
        std::shared_ptr<const C2Component> component,
        std::shared_ptr<C2BlockPool> *pool) {
    pool->reset();

    std::lock_guard<std::mutex> lock(sBlockPoolCacheMutex);
    return sBlockPoolCache->createBlockPool(allocatorId, component, pool);
}

class C2PlatformComponentStore : public C2ComponentStore {
public:
    virtual std::vector<std::shared_ptr<const C2Component::Traits>> listComponents() override;
    virtual std::shared_ptr<C2ParamReflector> getParamReflector() const override;
    virtual C2String getName() const override;
    virtual c2_status_t querySupportedValues_sm(
            std::vector<C2FieldSupportedValuesQuery> &fields) const override;
    virtual c2_status_t querySupportedParams_nb(
            std::vector<std::shared_ptr<C2ParamDescriptor>> *const params) const override;
    virtual c2_status_t query_sm(
            const std::vector<C2Param*> &stackParams,
            const std::vector<C2Param::Index> &heapParamIndices,
            std::vector<std::unique_ptr<C2Param>> *const heapParams) const override;
    virtual c2_status_t createInterface(
            C2String name, std::shared_ptr<C2ComponentInterface> *const interface) override;
    virtual c2_status_t createComponent(
            C2String name, std::shared_ptr<C2Component> *const component) override;
    virtual c2_status_t copyBuffer(
            std::shared_ptr<C2GraphicBuffer> src, std::shared_ptr<C2GraphicBuffer> dst) override;
    virtual c2_status_t config_sm(
            const std::vector<C2Param*> &params,
            std::vector<std::unique_ptr<C2SettingResult>> *const failures) override;
    C2PlatformComponentStore();

    virtual ~C2PlatformComponentStore() override = default;

private:

    /**
     * An object encapsulating a loaded component module.
     *
     * \todo provide a way to add traits to known components here to avoid loading the .so-s
     * for listComponents
     */
    struct ComponentModule : public C2ComponentFactory,
            public std::enable_shared_from_this<ComponentModule> {
        virtual c2_status_t createComponent(
                c2_node_id_t id, std::shared_ptr<C2Component> *component,
                ComponentDeleter deleter = std::default_delete<C2Component>()) override;
        virtual c2_status_t createInterface(
                c2_node_id_t id, std::shared_ptr<C2ComponentInterface> *interface,
                InterfaceDeleter deleter = std::default_delete<C2ComponentInterface>()) override;

        /**
         * \returns the traits of the component in this module.
         */
        std::shared_ptr<const C2Component::Traits> getTraits();

        /**
         * Creates an uninitialized component module.
         *
         * \param name[in]  component name.
         *
         * \note Only used by ComponentLoader.
         */
        ComponentModule()
            : mInit(C2_NO_INIT),
              mLibHandle(nullptr),
              createFactory(nullptr),
              destroyFactory(nullptr),
              mComponentFactory(nullptr) {
        }

        /**
         * Initializes a component module with a given library path. Must be called exactly once.
         *
         * \note Only used by ComponentLoader.
         *
         * \param alias[in]   module alias
         * \param libPath[in] library path
         *
         * \retval C2_OK        the component module has been successfully loaded
         * \retval C2_NO_MEMORY not enough memory to loading the component module
         * \retval C2_NOT_FOUND could not locate the component module
         * \retval C2_CORRUPTED the component module could not be loaded (unexpected)
         * \retval C2_REFUSED   permission denied to load the component module (unexpected)
         * \retval C2_TIMED_OUT could not load the module within the time limit (unexpected)
         */
        c2_status_t init(std::string alias, std::string libPath);

        virtual ~ComponentModule() override;

    protected:
        std::recursive_mutex mLock; ///< lock protecting mTraits
        std::shared_ptr<C2Component::Traits> mTraits; ///< cached component traits

        c2_status_t mInit; ///< initialization result

        void *mLibHandle; ///< loaded library handle
        C2ComponentFactory::CreateCodec2FactoryFunc createFactory; ///< loaded create function
        C2ComponentFactory::DestroyCodec2FactoryFunc destroyFactory; ///< loaded destroy function
        C2ComponentFactory *mComponentFactory; ///< loaded/created component factory
    };

    /**
     * An object encapsulating a loadable component module.
     *
     * \todo make this also work for enumerations
     */
    struct ComponentLoader {
        /**
         * Load the component module.
         *
         * This method simply returns the component module if it is already currently loaded, or
         * attempts to load it if it is not.
         *
         * \param module[out] pointer to the shared pointer where the loaded module shall be stored.
         *                    This will be nullptr on error.
         *
         * \retval C2_OK        the component module has been successfully loaded
         * \retval C2_NO_MEMORY not enough memory to loading the component module
         * \retval C2_NOT_FOUND could not locate the component module
         * \retval C2_CORRUPTED the component module could not be loaded
         * \retval C2_REFUSED   permission denied to load the component module
         */
        c2_status_t fetchModule(std::shared_ptr<ComponentModule> *module) {
            c2_status_t res = C2_OK;
            std::lock_guard<std::mutex> lock(mMutex);
            std::shared_ptr<ComponentModule> localModule = mModule.lock();
            if (localModule == nullptr) {
                localModule = std::make_shared<ComponentModule>();
                res = localModule->init(mAlias, mLibPath);
                if (res == C2_OK) {
                    mModule = localModule;
                }
            }
            *module = localModule;
            return res;
        }

        /**
         * Creates a component loader for a specific library path (or name).
         */
        ComponentLoader(std::string alias, std::string libPath)
            : mAlias(alias), mLibPath(libPath) {}

    private:
        std::mutex mMutex; ///< mutex guarding the module
        std::weak_ptr<ComponentModule> mModule; ///< weak reference to the loaded module
        std::string mAlias; ///< component alias
        std::string mLibPath; ///< library path
    };

    struct Interface : public C2InterfaceHelper {
        std::shared_ptr<C2StoreIonUsageInfo> mIonUsageInfo;

        Interface(std::shared_ptr<C2ReflectorHelper> reflector)
            : C2InterfaceHelper(reflector) {
            setDerivedInstance(this);

            struct Setter {
                static C2R setIonUsage(bool /* mayBlock */, C2P<C2StoreIonUsageInfo> &me) {
                    me.set().heapMask = ~0;
                    me.set().allocFlags = 0;
                    me.set().minAlignment = 0;
                    return C2R::Ok();
                }
            };

            addParameter(
                DefineParam(mIonUsageInfo, "ion-usage")
                .withDefault(new C2StoreIonUsageInfo())
                .withFields({
                    C2F(mIonUsageInfo, usage).flags({C2MemoryUsage::CPU_READ | C2MemoryUsage::CPU_WRITE}),
                    C2F(mIonUsageInfo, capacity).inRange(0, UINT32_MAX, 1024),
                    C2F(mIonUsageInfo, heapMask).any(),
                    C2F(mIonUsageInfo, allocFlags).flags({}),
                    C2F(mIonUsageInfo, minAlignment).equalTo(0)
                })
                .withSetter(Setter::setIonUsage)
                .build());
        }
    };

    /**
     * Retrieves the component loader for a component.
     *
     * \return a non-ref-holding pointer to the component loader.
     *
     * \retval C2_OK        the component loader has been successfully retrieved
     * \retval C2_NO_MEMORY not enough memory to locate the component loader
     * \retval C2_NOT_FOUND could not locate the component to be loaded
     * \retval C2_CORRUPTED the component loader could not be identified due to some modules being
     *                      corrupted (this can happen if the name does not refer to an already
     *                      identified component but some components could not be loaded due to
     *                      bad library)
     * \retval C2_REFUSED   permission denied to find the component loader for the named component
     *                      (this can happen if the name does not refer to an already identified
     *                      component but some components could not be loaded due to lack of
     *                      permissions)
     */
    c2_status_t findComponent(C2String name, ComponentLoader **loader);

    std::map<C2String, ComponentLoader> mComponents; ///< map of name -> components
    std::vector<C2String> mComponentsList; ///< list of components
    std::shared_ptr<C2ReflectorHelper> mReflector;
    Interface mInterface;
};

c2_status_t C2PlatformComponentStore::ComponentModule::init(
        std::string alias, std::string libPath) {
    ALOGV("in %s", __func__);
    ALOGV("loading dll");
    mLibHandle = dlopen(libPath.c_str(), RTLD_NOW|RTLD_NODELETE);
    if (mLibHandle == nullptr) {
        // could be access/symbol or simply not being there
        ALOGD("could not dlopen %s: %s", libPath.c_str(), dlerror());
        mInit = C2_CORRUPTED;
    } else {
        createFactory =
            (C2ComponentFactory::CreateCodec2FactoryFunc)dlsym(mLibHandle, "CreateCodec2Factory");
        destroyFactory =
            (C2ComponentFactory::DestroyCodec2FactoryFunc)dlsym(mLibHandle, "DestroyCodec2Factory");

        mComponentFactory = createFactory();
        if (mComponentFactory == nullptr) {
            ALOGD("could not create factory in %s", libPath.c_str());
            mInit = C2_NO_MEMORY;
        } else {
            mInit = C2_OK;
        }
    }
    if (mInit != C2_OK) {
        return mInit;
    }

    std::shared_ptr<C2ComponentInterface> intf;
    c2_status_t res = createInterface(0, &intf);
    if (res != C2_OK) {
        ALOGD("failed to create interface: %d", res);
        return mInit;
    }

    std::shared_ptr<C2Component::Traits> traits(new (std::nothrow) C2Component::Traits);
    if (traits) {
        if (alias != intf->getName()) {
            ALOGV("%s is alias to %s", alias.c_str(), intf->getName().c_str());
        }
        traits->name = alias;
        // TODO: get this from interface properly.
        bool encoder = (traits->name.find("encoder") != std::string::npos);
        uint32_t mediaTypeIndex = encoder ? C2PortMimeConfig::output::PARAM_TYPE
                : C2PortMimeConfig::input::PARAM_TYPE;
        std::vector<std::unique_ptr<C2Param>> params;
        res = intf->query_vb({}, { mediaTypeIndex }, C2_MAY_BLOCK, &params);
        if (res != C2_OK) {
            ALOGD("failed to query interface: %d", res);
            return mInit;
        }
        if (params.size() != 1u) {
            ALOGD("failed to query interface: unexpected vector size: %zu", params.size());
            return mInit;
        }
        C2PortMimeConfig *mediaTypeConfig = (C2PortMimeConfig *)(params[0].get());
        if (mediaTypeConfig == nullptr) {
            ALOGD("failed to query media type");
            return mInit;
        }
        traits->mediaType = mediaTypeConfig->m.value;
        // TODO: get this properly.
        traits->rank = 0x200;

        // TODO: define these values properly
        bool decoder = (traits->name.find("decoder") != std::string::npos);
        traits->kind =
                decoder ? C2Component::KIND_DECODER :
                encoder ? C2Component::KIND_ENCODER :
                C2Component::KIND_OTHER;
        if (strncmp(traits->mediaType.c_str(), "audio/", 6) == 0) {
            traits->domain = C2Component::DOMAIN_AUDIO;
        } else if (strncmp(traits->mediaType.c_str(), "video/", 6) == 0) {
            traits->domain = C2Component::DOMAIN_VIDEO;
        } else if (strncmp(traits->mediaType.c_str(), "image/", 6) == 0) {
            traits->domain = C2Component::DOMAIN_IMAGE;
        } else {
            traits->domain = C2Component::DOMAIN_OTHER;
        }
    }
    mTraits = traits;

    return mInit;
}

C2PlatformComponentStore::ComponentModule::~ComponentModule() {
    ALOGV("in %s", __func__);
    if (destroyFactory && mComponentFactory) {
        destroyFactory(mComponentFactory);
    }
    if (mLibHandle) {
        ALOGV("unloading dll");
        dlclose(mLibHandle);
    }
}

c2_status_t C2PlatformComponentStore::ComponentModule::createInterface(
        c2_node_id_t id, std::shared_ptr<C2ComponentInterface> *interface,
        std::function<void(::C2ComponentInterface*)> deleter) {
    interface->reset();
    if (mInit != C2_OK) {
        return mInit;
    }
    std::shared_ptr<ComponentModule> module = shared_from_this();
    c2_status_t res = mComponentFactory->createInterface(
            id, interface, [module, deleter](C2ComponentInterface *p) mutable {
                // capture module so that we ensure we still have it while deleting interface
                deleter(p); // delete interface first
                module.reset(); // remove module ref (not technically needed)
    });
    return res;
}

c2_status_t C2PlatformComponentStore::ComponentModule::createComponent(
        c2_node_id_t id, std::shared_ptr<C2Component> *component,
        std::function<void(::C2Component*)> deleter) {
    component->reset();
    if (mInit != C2_OK) {
        return mInit;
    }
    std::shared_ptr<ComponentModule> module = shared_from_this();
    c2_status_t res = mComponentFactory->createComponent(
            id, component, [module, deleter](C2Component *p) mutable {
                // capture module so that we ensure we still have it while deleting component
                deleter(p); // delete component first
                module.reset(); // remove module ref (not technically needed)
    });
    return res;
}

std::shared_ptr<const C2Component::Traits> C2PlatformComponentStore::ComponentModule::getTraits() {
    std::unique_lock<std::recursive_mutex> lock(mLock);
    return mTraits;
}

C2PlatformComponentStore::C2PlatformComponentStore()
    : mReflector(std::make_shared<C2ReflectorHelper>()),
      mInterface(mReflector) {

    auto emplace = [this](const char *alias, const char *libPath) {
        // ComponentLoader is neither copiable nor movable, so it must be
        // constructed in-place. Now ComponentLoader takes two arguments in
        // constructor, so we need to use piecewise_construct to achieve this
        // behavior.
        mComponents.emplace(
                std::piecewise_construct,
                std::forward_as_tuple(alias),
                std::forward_as_tuple(alias, libPath));
        mComponentsList.emplace_back(alias);
    };
    // TODO: move this also into a .so so it can be updated
    emplace("c2.android.avc.decoder", "libcodec2_soft_avcdec.so");
    emplace("c2.android.avc.encoder", "libcodec2_soft_avcenc.so");
    emplace("c2.android.aac.decoder", "libcodec2_soft_aacdec.so");
    emplace("c2.android.aac.encoder", "libcodec2_soft_aacenc.so");
    emplace("c2.android.amrnb.decoder", "libcodec2_soft_amrnbdec.so");
    emplace("c2.android.amrnb.encoder", "libcodec2_soft_amrnbenc.so");
    emplace("c2.android.amrwb.decoder", "libcodec2_soft_amrwbdec.so");
    emplace("c2.android.amrwb.encoder", "libcodec2_soft_amrwbenc.so");
    emplace("c2.android.hevc.decoder", "libcodec2_soft_hevcdec.so");
    emplace("c2.android.g711.alaw.decoder", "libcodec2_soft_g711alawdec.so");
    emplace("c2.android.g711.mlaw.decoder", "libcodec2_soft_g711mlawdec.so");
    emplace("c2.android.mpeg2.decoder", "libcodec2_soft_mpeg2dec.so");
    emplace("c2.android.h263.decoder", "libcodec2_soft_h263dec.so");
    emplace("c2.android.h263.encoder", "libcodec2_soft_h263enc.so");
    emplace("c2.android.mpeg4.decoder", "libcodec2_soft_mpeg4dec.so");
    emplace("c2.android.mpeg4.encoder", "libcodec2_soft_mpeg4enc.so");
    emplace("c2.android.mp3.decoder", "libcodec2_soft_mp3dec.so");
    emplace("c2.android.vorbis.decoder", "libcodec2_soft_vorbisdec.so");
    emplace("c2.android.opus.decoder", "libcodec2_soft_opusdec.so");
    emplace("c2.android.vp8.decoder", "libcodec2_soft_vp8dec.so");
    emplace("c2.android.vp9.decoder", "libcodec2_soft_vp9dec.so");
    emplace("c2.android.vp8.encoder", "libcodec2_soft_vp8enc.so");
    emplace("c2.android.vp9.encoder", "libcodec2_soft_vp9enc.so");
    emplace("c2.android.av1.decoder", "libcodec2_soft_av1dec.so");
    emplace("c2.android.raw.decoder", "libcodec2_soft_rawdec.so");
    emplace("c2.android.flac.decoder", "libcodec2_soft_flacdec.so");
    emplace("c2.android.flac.encoder", "libcodec2_soft_flacenc.so");
    emplace("c2.android.gsm.decoder", "libcodec2_soft_gsmdec.so");
    emplace("c2.android.xaac.decoder", "libcodec2_soft_xaacdec.so");

    // "Aliases"
    // TODO: use aliases proper from C2Component::Traits
    emplace("OMX.google.h264.decoder", "libcodec2_soft_avcdec.so");
    emplace("OMX.google.h264.encoder", "libcodec2_soft_avcenc.so");
    emplace("OMX.google.aac.decoder", "libcodec2_soft_aacdec.so");
    emplace("OMX.google.aac.encoder", "libcodec2_soft_aacenc.so");
    emplace("OMX.google.amrnb.decoder", "libcodec2_soft_amrnbdec.so");
    emplace("OMX.google.amrnb.encoder", "libcodec2_soft_amrnbenc.so");
    emplace("OMX.google.amrwb.decoder", "libcodec2_soft_amrwbdec.so");
    emplace("OMX.google.amrwb.encoder", "libcodec2_soft_amrwbenc.so");
    emplace("OMX.google.hevc.decoder", "libcodec2_soft_hevcdec.so");
    emplace("OMX.google.g711.alaw.decoder", "libcodec2_soft_g711alawdec.so");
    emplace("OMX.google.g711.mlaw.decoder", "libcodec2_soft_g711mlawdec.so");
    emplace("OMX.google.mpeg2.decoder", "libcodec2_soft_mpeg2dec.so");
    emplace("OMX.google.h263.decoder", "libcodec2_soft_h263dec.so");
    emplace("OMX.google.h263.encoder", "libcodec2_soft_h263enc.so");
    emplace("OMX.google.mpeg4.decoder", "libcodec2_soft_mpeg4dec.so");
    emplace("OMX.google.mpeg4.encoder", "libcodec2_soft_mpeg4enc.so");
    emplace("OMX.google.mp3.decoder", "libcodec2_soft_mp3dec.so");
    emplace("OMX.google.vorbis.decoder", "libcodec2_soft_vorbisdec.so");
    emplace("OMX.google.opus.decoder", "libcodec2_soft_opusdec.so");
    emplace("OMX.google.vp8.decoder", "libcodec2_soft_vp8dec.so");
    emplace("OMX.google.vp9.decoder", "libcodec2_soft_vp9dec.so");
    emplace("OMX.google.vp8.encoder", "libcodec2_soft_vp8enc.so");
    emplace("OMX.google.vp9.encoder", "libcodec2_soft_vp9enc.so");
    emplace("OMX.google.raw.decoder", "libcodec2_soft_rawdec.so");
    emplace("OMX.google.flac.decoder", "libcodec2_soft_flacdec.so");
    emplace("OMX.google.flac.encoder", "libcodec2_soft_flacenc.so");
    emplace("OMX.google.gsm.decoder", "libcodec2_soft_gsmdec.so");
    emplace("OMX.google.xaac.decoder", "libcodec2_soft_xaacdec.so");
}

c2_status_t C2PlatformComponentStore::copyBuffer(
        std::shared_ptr<C2GraphicBuffer> src, std::shared_ptr<C2GraphicBuffer> dst) {
    (void)src;
    (void)dst;
    return C2_OMITTED;
}

c2_status_t C2PlatformComponentStore::query_sm(
        const std::vector<C2Param*> &stackParams,
        const std::vector<C2Param::Index> &heapParamIndices,
        std::vector<std::unique_ptr<C2Param>> *const heapParams) const {
    return mInterface.query(stackParams, heapParamIndices, C2_MAY_BLOCK, heapParams);
}

c2_status_t C2PlatformComponentStore::config_sm(
        const std::vector<C2Param*> &params,
        std::vector<std::unique_ptr<C2SettingResult>> *const failures) {
    return mInterface.config(params, C2_MAY_BLOCK, failures);
}

std::vector<std::shared_ptr<const C2Component::Traits>> C2PlatformComponentStore::listComponents() {
    // This method SHALL return within 500ms.
    std::vector<std::shared_ptr<const C2Component::Traits>> list;
    for (const C2String &alias : mComponentsList) {
        ComponentLoader &loader = mComponents.at(alias);
        std::shared_ptr<ComponentModule> module;
        c2_status_t res = loader.fetchModule(&module);
        if (res == C2_OK) {
            std::shared_ptr<const C2Component::Traits> traits = module->getTraits();
            if (traits) {
                list.push_back(traits);
            }
        }
    }
    return list;
}

c2_status_t C2PlatformComponentStore::findComponent(C2String name, ComponentLoader **loader) {
    *loader = nullptr;
    auto pos = mComponents.find(name);
    // TODO: check aliases
    if (pos == mComponents.end()) {
        return C2_NOT_FOUND;
    }
    *loader = &pos->second;
    return C2_OK;
}

c2_status_t C2PlatformComponentStore::createComponent(
        C2String name, std::shared_ptr<C2Component> *const component) {
    // This method SHALL return within 100ms.
    component->reset();
    ComponentLoader *loader;
    c2_status_t res = findComponent(name, &loader);
    if (res == C2_OK) {
        std::shared_ptr<ComponentModule> module;
        res = loader->fetchModule(&module);
        if (res == C2_OK) {
            // TODO: get a unique node ID
            res = module->createComponent(0, component);
        }
    }
    return res;
}

c2_status_t C2PlatformComponentStore::createInterface(
        C2String name, std::shared_ptr<C2ComponentInterface> *const interface) {
    // This method SHALL return within 100ms.
    interface->reset();
    ComponentLoader *loader;
    c2_status_t res = findComponent(name, &loader);
    if (res == C2_OK) {
        std::shared_ptr<ComponentModule> module;
        res = loader->fetchModule(&module);
        if (res == C2_OK) {
            // TODO: get a unique node ID
            res = module->createInterface(0, interface);
        }
    }
    return res;
}

c2_status_t C2PlatformComponentStore::querySupportedParams_nb(
        std::vector<std::shared_ptr<C2ParamDescriptor>> *const params) const {
    return mInterface.querySupportedParams(params);
}

c2_status_t C2PlatformComponentStore::querySupportedValues_sm(
        std::vector<C2FieldSupportedValuesQuery> &fields) const {
    return mInterface.querySupportedValues(fields, C2_MAY_BLOCK);
}

C2String C2PlatformComponentStore::getName() const {
    return "android.componentStore.platform";
}

std::shared_ptr<C2ParamReflector> C2PlatformComponentStore::getParamReflector() const {
    return mReflector;
}

std::shared_ptr<C2ComponentStore> GetCodec2PlatformComponentStore() {
    static std::mutex mutex;
    static std::weak_ptr<C2ComponentStore> platformStore;
    std::lock_guard<std::mutex> lock(mutex);
    std::shared_ptr<C2ComponentStore> store = platformStore.lock();
    if (store == nullptr) {
        store = std::make_shared<C2PlatformComponentStore>();
        platformStore = store;
    }
    return store;
}

} // namespace android
