/*
 * Copyright (C) 2018 The Android Open Source Project
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
#define LOG_TAG "Codec2-ComponentStore"
#include <log/log.h>

#include <codec2/hidl/1.0/ComponentStore.h>
#include <codec2/hidl/1.0/InputSurface.h>
#include <codec2/hidl/1.0/Component.h>
#include <codec2/hidl/1.0/ConfigurableC2Intf.h>
#include <codec2/hidl/1.0/types.h>

#include <media/stagefright/bqhelper/WGraphicBufferProducer.h>
#include <media/stagefright/bqhelper/GraphicBufferSource.h>

#include <C2PlatformSupport.h>
#include <util/C2InterfaceHelper.h>

#include <utils/Errors.h>

#include <android-base/file.h>

#ifdef LOG
#undef LOG
#endif

#ifdef PLOG
#undef PLOG
#endif

#include <android-base/logging.h>

#include <ostream>
#include <sstream>
#include <iomanip>

namespace hardware {
namespace google {
namespace media {
namespace c2 {
namespace V1_0 {
namespace utils {

using namespace ::android;
using ::android::GraphicBufferSource;
using namespace ::android::hardware::media::bufferpool::V1_0::implementation;

namespace /* unnamed */ {

struct StoreIntf : public ConfigurableC2Intf {
    StoreIntf(const std::shared_ptr<C2ComponentStore>& store) :
        ConfigurableC2Intf(store ? store->getName() : ""),
        mStore(store) {
    }

    c2_status_t config(
            const std::vector<C2Param*> &params,
            c2_blocking_t mayBlock,
            std::vector<std::unique_ptr<C2SettingResult>> *const failures
            ) override {
        // Assume all params are blocking
        // TODO: Filter for supported params
        if (mayBlock == C2_DONT_BLOCK && params.size() != 0) {
            return C2_BLOCKING;
        }
        return mStore->config_sm(params, failures);
    }

    c2_status_t query(
            const std::vector<C2Param::Index> &indices,
            c2_blocking_t mayBlock,
            std::vector<std::unique_ptr<C2Param>> *const params) const override {
        // Assume all params are blocking
        // TODO: Filter for supported params
        if (mayBlock == C2_DONT_BLOCK && indices.size() != 0) {
            return C2_BLOCKING;
        }
        return mStore->query_sm({}, indices, params);
    }

    c2_status_t querySupportedParams(
            std::vector<std::shared_ptr<C2ParamDescriptor>> *const params
            ) const override {
        return mStore->querySupportedParams_nb(params);
    }

    c2_status_t querySupportedValues(
            std::vector<C2FieldSupportedValuesQuery> &fields,
            c2_blocking_t mayBlock) const override {
        // Assume all params are blocking
        // TODO: Filter for supported params
        if (mayBlock == C2_DONT_BLOCK && fields.size() != 0) {
            return C2_BLOCKING;
        }
        return mStore->querySupportedValues_sm(fields);
    }

protected:
    std::shared_ptr<C2ComponentStore> mStore;
};

} // unnamed namespace

ComponentStore::ComponentStore(const std::shared_ptr<C2ComponentStore>& store) :
    Configurable(new CachedConfigurable(std::make_unique<StoreIntf>(store))),
    mStore(store) {

    std::shared_ptr<C2ComponentStore> platformStore = android::GetCodec2PlatformComponentStore();
    SetPreferredCodec2ComponentStore(store);

    // Retrieve struct descriptors
    mParamReflector = mStore->getParamReflector();

    // Retrieve supported parameters from store
    mInit = init(this);
}

c2_status_t ComponentStore::validateSupportedParams(
        const std::vector<std::shared_ptr<C2ParamDescriptor>>& params) {
    c2_status_t res = C2_OK;

    for (const std::shared_ptr<C2ParamDescriptor> &desc : params) {
        if (!desc) {
            // All descriptors should be valid
            res = res ? res : C2_BAD_VALUE;
            continue;
        }
        C2Param::CoreIndex coreIndex = desc->index().coreIndex();
        std::lock_guard<std::mutex> lock(mStructDescriptorsMutex);
        auto it = mStructDescriptors.find(coreIndex);
        if (it == mStructDescriptors.end()) {
            std::shared_ptr<C2StructDescriptor> structDesc =
                    mParamReflector->describe(coreIndex);
            if (!structDesc) {
                // All supported params must be described
                res = C2_BAD_INDEX;
            }
            mStructDescriptors.insert({ coreIndex, structDesc });
        }
    }
    return res;
}

// Methods from ::android::hardware::media::c2::V1_0::IComponentStore
Return<void> ComponentStore::createComponent(
        const hidl_string& name,
        const sp<IComponentListener>& listener,
        const sp<IClientManager>& pool,
        createComponent_cb _hidl_cb) {

    sp<Component> component;
    std::shared_ptr<C2Component> c2component;
    Status status = static_cast<Status>(
            mStore->createComponent(name, &c2component));

    if (status == Status::OK) {
        onInterfaceLoaded(c2component->intf());
        component = new Component(c2component, listener, this, pool);
        if (!component) {
            status = Status::CORRUPTED;
        } else if (component->status() != C2_OK) {
            status = static_cast<Status>(component->status());
        } else {
            component->initListener(component);
            if (component->status() != C2_OK) {
                status = static_cast<Status>(component->status());
            } else {
                std::lock_guard<std::mutex> lock(mComponentRosterMutex);
                component->setLocalId(
                        mComponentRoster.emplace(
                            Component::InterfaceKey(component),
                            c2component)
                        .first);
            }
        }
    }
    _hidl_cb(status, component);
    return Void();
}

Return<void> ComponentStore::createInterface(
        const hidl_string& name,
        createInterface_cb _hidl_cb) {
    std::shared_ptr<C2ComponentInterface> c2interface;
    c2_status_t res = mStore->createInterface(name, &c2interface);
    sp<IComponentInterface> interface;
    if (res == C2_OK) {
        onInterfaceLoaded(c2interface);
        interface = new ComponentInterface(c2interface, this);
    }
    _hidl_cb((Status)res, interface);
    return Void();
}

Return<void> ComponentStore::listComponents(listComponents_cb _hidl_cb) {
    std::vector<std::shared_ptr<const C2Component::Traits>> c2traits =
            mStore->listComponents();
    hidl_vec<IComponentStore::ComponentTraits> traits(c2traits.size());
    size_t ix = 0;
    for (const std::shared_ptr<const C2Component::Traits> &c2trait : c2traits) {
        if (c2trait) {
            objcpy(&traits[ix++], *c2trait);
        }
    }
    traits.resize(ix);
    _hidl_cb(traits);
    return Void();
}

Return<sp<IInputSurface>> ComponentStore::createInputSurface() {
    sp<GraphicBufferSource> source = new GraphicBufferSource();
    if (source->initCheck() != OK) {
        return nullptr;
    }
    typedef ::android::hardware::graphics::bufferqueue::V1_0::
            IGraphicBufferProducer HGbp;
    typedef ::android::TWGraphicBufferProducer<HGbp> B2HGbp;
    return new InputSurface(
            this,
            std::make_shared<C2ReflectorHelper>(),
            new B2HGbp(source->getIGraphicBufferProducer()),
            source);
}

void ComponentStore::onInterfaceLoaded(const std::shared_ptr<C2ComponentInterface> &intf) {
    // invalidate unsupported struct descriptors if a new interface is loaded as it may have
    // exposed new descriptors
    std::lock_guard<std::mutex> lock(mStructDescriptorsMutex);
    if (!mLoadedInterfaces.count(intf->getName())) {
        mUnsupportedStructDescriptors.clear();
        mLoadedInterfaces.emplace(intf->getName());
    }
}

Return<void> ComponentStore::getStructDescriptors(
        const hidl_vec<uint32_t>& indices,
        getStructDescriptors_cb _hidl_cb) {
    hidl_vec<StructDescriptor> descriptors(indices.size());
    size_t dstIx = 0;
    Status res = Status::OK;
    for (size_t srcIx = 0; srcIx < indices.size(); ++srcIx) {
        std::lock_guard<std::mutex> lock(mStructDescriptorsMutex);
        const C2Param::CoreIndex coreIndex = C2Param::CoreIndex(indices[srcIx]).coreIndex();
        const auto item = mStructDescriptors.find(coreIndex);
        if (item == mStructDescriptors.end()) {
            // not in the cache, and not known to be unsupported, query local reflector
            if (!mUnsupportedStructDescriptors.count(coreIndex)) {
                std::shared_ptr<C2StructDescriptor> structDesc =
                    mParamReflector->describe(coreIndex);
                if (!structDesc) {
                    mUnsupportedStructDescriptors.emplace(coreIndex);
                } else {
                    mStructDescriptors.insert({ coreIndex, structDesc });
                    objcpy(&descriptors[dstIx++], *structDesc);
                    continue;
                }
            }
            res = Status::NOT_FOUND;
        } else if (item->second) {
            objcpy(&descriptors[dstIx++], *item->second);
        } else {
            res = Status::NO_MEMORY;
        }
    }
    descriptors.resize(dstIx);
    _hidl_cb(res, descriptors);
    return Void();
}

Return<sp<IClientManager>> ComponentStore::getPoolClientManager() {
    return ClientManager::getInstance();
}

Return<Status> ComponentStore::copyBuffer(const Buffer& src, const Buffer& dst) {
    // TODO implement
    (void)src;
    (void)dst;
    return Status::OMITTED;
}

void ComponentStore::reportComponentDeath(
        const Component::LocalId& componentLocalId) {
    std::lock_guard<std::mutex> lock(mComponentRosterMutex);
    mComponentRoster.erase(componentLocalId);
}

std::shared_ptr<C2Component> ComponentStore::findC2Component(
        const sp<IComponent>& component) const {
    std::lock_guard<std::mutex> lock(mComponentRosterMutex);
    Component::LocalId it = mComponentRoster.find(
            Component::InterfaceKey(component));
    if (it == mComponentRoster.end()) {
        return std::shared_ptr<C2Component>();
    }
    return it->second.lock();
}

// Debug dump

namespace /* unnamed */ {

// Dump component traits
std::ostream& dump(
        std::ostream& out,
        const std::shared_ptr<const C2Component::Traits>& comp) {

    constexpr const char indent[] = "    ";

    out << indent << "name: " << comp->name << std::endl;
    out << indent << "domain: " << comp->domain << std::endl;
    out << indent << "kind: " << comp->kind << std::endl;
    out << indent << "rank: " << comp->rank << std::endl;
    out << indent << "mediaType: " << comp->mediaType << std::endl;
    out << indent << "aliases:";
    for (const auto& alias : comp->aliases) {
        out << ' ' << alias;
    }
    out << std::endl;

    return out;
}

// Dump component
std::ostream& dump(
        std::ostream& out,
        const std::shared_ptr<C2Component>& comp) {

    constexpr const char indent[] = "    ";

    std::shared_ptr<C2ComponentInterface> intf = comp->intf();
    if (!intf) {
        out << indent << "Unknown -- null interface" << std::endl;
        return out;
    }
    out << indent << "name: " << intf->getName() << std::endl;
    out << indent << "id: " << intf->getId() << std::endl;
    return out;
}

} // unnamed namespace

Return<void> ComponentStore::debug(
        const hidl_handle& handle,
        const hidl_vec<hidl_string>& /* args */) {
    LOG(INFO) << "debug -- dumping...";
    const native_handle_t *h = handle.getNativeHandle();
    if (!h || h->numFds != 1) {
       LOG(ERROR) << "debug -- dumping failed -- "
               "invalid file descriptor to dump to";
       return Void();
    }
    std::ostringstream out;

    { // Populate "out".

        constexpr const char indent[] = "  ";

        // Show name.
        out << "Beginning of dump -- C2ComponentStore: "
                << mStore->getName() << std::endl << std::endl;

        // Retrieve the list of supported components.
        std::vector<std::shared_ptr<const C2Component::Traits>> traitsList =
                mStore->listComponents();

        // Dump the traits of supported components.
        out << indent << "Supported components:" << std::endl << std::endl;
        if (traitsList.size() == 0) {
            out << indent << indent << "NONE" << std::endl << std::endl;
        } else {
            for (const auto& traits : traitsList) {
                dump(out, traits) << std::endl;
            }
        }

        // Retrieve the list of active components.
        std::list<std::shared_ptr<C2Component>> activeComps;
        {
            std::lock_guard<std::mutex> lock(mComponentRosterMutex);
            auto i = mComponentRoster.begin();
            while (i != mComponentRoster.end()) {
                std::shared_ptr<C2Component> c2comp = i->second.lock();
                if (!c2comp) {
                    auto j = i;
                    ++i;
                    mComponentRoster.erase(j);
                } else {
                    ++i;
                    activeComps.emplace_back(c2comp);
                }
            }
        }

        // Dump active components.
        out << indent << "Active components:" << std::endl << std::endl;
        if (activeComps.size() == 0) {
            out << indent << indent << "NONE" << std::endl << std::endl;
        } else {
            for (const std::shared_ptr<C2Component>& c2comp : activeComps) {
                dump(out, c2comp) << std::endl;
            }
        }

        out << "End of dump -- C2ComponentStore: "
                << mStore->getName() << std::endl;
    }

    if (!android::base::WriteStringToFd(out.str(), h->data[0])) {
        PLOG(WARNING) << "debug -- dumping failed -- write()";
    } else {
        LOG(INFO) << "debug -- dumping succeeded";
    }
    return Void();
}


}  // namespace utils
}  // namespace V1_0
}  // namespace c2
}  // namespace media
}  // namespace google
}  // namespace hardware
