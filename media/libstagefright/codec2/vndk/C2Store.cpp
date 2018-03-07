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

#include <C2AllocatorGralloc.h>
#include <C2AllocatorIon.h>
#include <C2BufferPriv.h>
#include <C2Component.h>
#include <C2PlatformSupport.h>

#define LOG_TAG "C2Store"
#define LOG_NDEBUG 0
#include <utils/Log.h>

#include <dlfcn.h>

#include <map>
#include <memory>
#include <mutex>

namespace android {

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
    C2PlatformAllocatorStoreImpl(
        /* ionmapper */
    );

    virtual c2_status_t fetchAllocator(
            id_t id, std::shared_ptr<C2Allocator> *const allocator) override;

    virtual std::vector<std::shared_ptr<const C2Allocator::Traits>> listAllocators_nb()
            const override {
        return std::vector<std::shared_ptr<const C2Allocator::Traits>>(); /// \todo
    }

    virtual C2String getName() const override {
        return "android.allocator-store";
    }

private:
    /// returns a shared-singleton ion allocator
    std::shared_ptr<C2Allocator> fetchIonAllocator();

    /// returns a shared-singleton gralloc allocator
    std::shared_ptr<C2Allocator> fetchGrallocAllocator();
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

    default:
        return C2_NOT_FOUND;
    }
    if (*allocator == nullptr) {
        return C2_NO_MEMORY;
    }
    return C2_OK;
}

std::shared_ptr<C2Allocator> C2PlatformAllocatorStoreImpl::fetchIonAllocator() {
    static std::mutex mutex;
    static std::weak_ptr<C2Allocator> ionAllocator;
    std::lock_guard<std::mutex> lock(mutex);
    std::shared_ptr<C2Allocator> allocator = ionAllocator.lock();
    if (allocator == nullptr) {
        allocator = std::make_shared<C2AllocatorIon>(C2PlatformAllocatorStore::ION);
        ionAllocator = allocator;
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

std::shared_ptr<C2AllocatorStore> GetCodec2PlatformAllocatorStore() {
    return std::make_shared<C2PlatformAllocatorStoreImpl>();
}

c2_status_t GetCodec2BlockPool(
        C2BlockPool::local_id_t id, std::shared_ptr<const C2Component> component,
        std::shared_ptr<C2BlockPool> *pool) {
    pool->reset();
    if (!component) {
        return C2_BAD_VALUE;
    }
    // TODO support pre-registered block pools
    std::shared_ptr<C2AllocatorStore> allocatorStore = GetCodec2PlatformAllocatorStore();
    std::shared_ptr<C2Allocator> allocator;
    c2_status_t res = C2_NOT_FOUND;

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
    if (!component) {
        return C2_BAD_VALUE;
    }
    // TODO: support caching block pool along with GetCodec2BlockPool.
    static std::atomic_int sBlockPoolId(C2BlockPool::PLATFORM_START);
    std::shared_ptr<C2AllocatorStore> allocatorStore = GetCodec2PlatformAllocatorStore();
    std::shared_ptr<C2Allocator> allocator;
    c2_status_t res = C2_NOT_FOUND;

    switch (allocatorId) {
    case C2PlatformAllocatorStore::ION:
        res = allocatorStore->fetchAllocator(C2AllocatorStore::DEFAULT_LINEAR, &allocator);
        if (res == C2_OK) {
            *pool = std::make_shared<C2PooledBlockPool>(allocator, sBlockPoolId++);
            if (!*pool) {
                res = C2_NO_MEMORY;
            }
        }
        break;
    case C2PlatformAllocatorStore::GRALLOC:
        // TODO: support gralloc
        break;
    default:
        break;
    }
    return res;
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
         * \param libPath[in] library path (or name)
         *
         * \retval C2_OK        the component module has been successfully loaded
         * \retval C2_NO_MEMORY not enough memory to loading the component module
         * \retval C2_NOT_FOUND could not locate the component module
         * \retval C2_CORRUPTED the component module could not be loaded (unexpected)
         * \retval C2_REFUSED   permission denied to load the component module (unexpected)
         * \retval C2_TIMED_OUT could not load the module within the time limit (unexpected)
         */
        c2_status_t init(std::string libPath);

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
                res = localModule->init(mLibPath);
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
        ComponentLoader(std::string libPath)
            : mLibPath(libPath) {}

    private:
        std::mutex mMutex; ///< mutex guarding the module
        std::weak_ptr<ComponentModule> mModule; ///< weak reference to the loaded module
        std::string mLibPath; ///< library path (or name)
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

    std::map<C2String, ComponentLoader> mComponents; ///< list of components
};

c2_status_t C2PlatformComponentStore::ComponentModule::init(std::string libPath) {
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
    if (!mTraits) {
        std::shared_ptr<C2ComponentInterface> intf;
        c2_status_t res = createInterface(0, &intf);
        if (res != C2_OK) {
            ALOGD("failed to create interface: %d", res);
            return nullptr;
        }

        std::shared_ptr<C2Component::Traits> traits(new (std::nothrow) C2Component::Traits);
        if (traits) {
            traits->name = intf->getName();
            // TODO: get this from interface properly.
            bool encoder = (traits->name.find("encoder") != std::string::npos);
            uint32_t mediaTypeIndex = encoder ? C2PortMimeConfig::output::PARAM_TYPE
                    : C2PortMimeConfig::input::PARAM_TYPE;
            std::vector<std::unique_ptr<C2Param>> params;
            res = intf->query_vb({}, { mediaTypeIndex }, C2_MAY_BLOCK, &params);
            if (res != C2_OK) {
                ALOGD("failed to query interface: %d", res);
                return nullptr;
            }
            if (params.size() != 1u) {
                ALOGD("failed to query interface: unexpected vector size: %zu", params.size());
                return nullptr;
            }
            C2PortMimeConfig *mediaTypeConfig = (C2PortMimeConfig *)(params[0].get());
            if (mediaTypeConfig == nullptr) {
                ALOGD("failed to query media type");
                return nullptr;
            }
            traits->mediaType = mediaTypeConfig->m.value;
            // TODO: get this properly.
            traits->rank = 0x200;
        }

        mTraits = traits;
    }
    return mTraits;
}

C2PlatformComponentStore::C2PlatformComponentStore() {
    // TODO: move this also into a .so so it can be updated
    mComponents.emplace("c2.google.avc.decoder", "libstagefright_soft_c2avcdec.so");
    mComponents.emplace("c2.google.avc.encoder", "libstagefright_soft_c2avcenc.so");
    mComponents.emplace("c2.google.aac.decoder", "libstagefright_soft_c2aacdec.so");
    mComponents.emplace("c2.google.aac.encoder", "libstagefright_soft_c2aacenc.so");
    mComponents.emplace("c2.google.amrnb.decoder", "libstagefright_soft_c2amrnbdec.so");
    mComponents.emplace("c2.google.amrnb.encoder", "libstagefright_soft_c2amrnbenc.so");
    mComponents.emplace("c2.google.amrwb.decoder", "libstagefright_soft_c2amrwbdec.so");
    mComponents.emplace("c2.google.amrwb.encoder", "libstagefright_soft_c2amrwbenc.so");
    mComponents.emplace("c2.google.hevc.decoder", "libstagefright_soft_c2hevcdec.so");
    mComponents.emplace("c2.google.g711.alaw.decoder", "libstagefright_soft_c2g711alawdec.so");
    mComponents.emplace("c2.google.g711.mlaw.decoder", "libstagefright_soft_c2g711mlawdec.so");
    mComponents.emplace("c2.google.mpeg2.decoder", "libstagefright_soft_c2mpeg2dec.so");
    mComponents.emplace("c2.google.h263.decoder", "libstagefright_soft_c2h263dec.so");
    mComponents.emplace("c2.google.h263.encoder", "libstagefright_soft_c2h263enc.so");
    mComponents.emplace("c2.google.mpeg4.decoder", "libstagefright_soft_c2mpeg4dec.so");
    mComponents.emplace("c2.google.mpeg4.encoder", "libstagefright_soft_c2mpeg4enc.so");
    mComponents.emplace("c2.google.mp3.decoder", "libstagefright_soft_c2mp3dec.so");
    mComponents.emplace("c2.google.vorbis.decoder", "libstagefright_soft_c2vorbisdec.so");
    mComponents.emplace("c2.google.opus.decoder", "libstagefright_soft_c2opusdec.so");
    mComponents.emplace("c2.google.vp8.decoder", "libstagefright_soft_c2vp8dec.so");
    mComponents.emplace("c2.google.vp9.decoder", "libstagefright_soft_c2vp9dec.so");
    mComponents.emplace("c2.google.vp8.encoder", "libstagefright_soft_c2vp8enc.so");
    mComponents.emplace("c2.google.vp9.encoder", "libstagefright_soft_c2vp9enc.so");
    mComponents.emplace("c2.google.raw.decoder", "libstagefright_soft_c2rawdec.so");
    mComponents.emplace("c2.google.flac.decoder", "libstagefright_soft_c2flacdec.so");
    mComponents.emplace("c2.google.flac.encoder", "libstagefright_soft_c2flacenc.so");
    mComponents.emplace("c2.google.gsm.decoder", "libstagefright_soft_c2gsmdec.so");
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
    // there are no supported configs
    (void)heapParams;
    return stackParams.empty() && heapParamIndices.empty() ? C2_OK : C2_BAD_INDEX;
}

c2_status_t C2PlatformComponentStore::config_sm(
        const std::vector<C2Param*> &params,
        std::vector<std::unique_ptr<C2SettingResult>> *const failures) {
    // there are no supported configs
    (void)failures;
    return params.empty() ? C2_OK : C2_BAD_INDEX;
}

std::vector<std::shared_ptr<const C2Component::Traits>> C2PlatformComponentStore::listComponents() {
    // This method SHALL return within 500ms.
    std::vector<std::shared_ptr<const C2Component::Traits>> list;
    for (auto &it : mComponents) {
        ComponentLoader &loader = it.second;
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
    // there are no supported config params
    (void)params;
    return C2_OK;
}

c2_status_t C2PlatformComponentStore::querySupportedValues_sm(
        std::vector<C2FieldSupportedValuesQuery> &fields) const {
    // there are no supported config params
    return fields.empty() ? C2_OK : C2_BAD_INDEX;
}

C2String C2PlatformComponentStore::getName() const {
    return "android.componentStore.platform";
}

std::shared_ptr<C2ParamReflector> C2PlatformComponentStore::getParamReflector() const {
    // TODO
    return nullptr;
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
