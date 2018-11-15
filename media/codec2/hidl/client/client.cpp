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
#define LOG_TAG "Codec2Client"
#include <log/log.h>

#include <codec2/hidl/client.h>

#include <deque>
#include <limits>
#include <map>
#include <type_traits>
#include <vector>

#include <android-base/properties.h>
#include <bufferpool/ClientManager.h>
#include <cutils/native_handle.h>
#include <gui/bufferqueue/1.0/H2BGraphicBufferProducer.h>
#include <hidl/HidlSupport.h>
#include <media/stagefright/bqhelper/WGraphicBufferProducer.h>
#undef LOG

#include <android/hardware/media/bufferpool/1.0/IClientManager.h>
#include <hardware/google/media/c2/1.0/IComponent.h>
#include <hardware/google/media/c2/1.0/IComponentInterface.h>
#include <hardware/google/media/c2/1.0/IComponentListener.h>
#include <hardware/google/media/c2/1.0/IComponentStore.h>
#include <hardware/google/media/c2/1.0/IConfigurable.h>

#include <C2Debug.h>
#include <C2BufferPriv.h>
#include <C2PlatformSupport.h>

namespace android {

using ::android::hardware::hidl_vec;
using ::android::hardware::hidl_string;
using ::android::hardware::Return;
using ::android::hardware::Void;
using ::android::TWGraphicBufferProducer;

using namespace ::hardware::google::media::c2::V1_0;
using namespace ::hardware::google::media::c2::V1_0::utils;
using namespace ::android::hardware::media::bufferpool::V1_0;
using namespace ::android::hardware::media::bufferpool::V1_0::implementation;

namespace /* unnamed */ {

// c2_status_t value that corresponds to hwbinder transaction failure.
constexpr c2_status_t C2_TRANSACTION_FAILED = C2_CORRUPTED;

// List of known IComponentStore services in the decreasing order of preference.
constexpr const char* kClientNames[] = {
        "default",
        "software",
    };

// Number of known IComponentStore services.
constexpr size_t kNumClients = std::extent<decltype(kClientNames)>::value;

typedef std::array<std::shared_ptr<Codec2Client>, kNumClients> ClientList;

// Convenience methods to obtain known clients.
std::shared_ptr<Codec2Client> getClient(size_t index) {
    return Codec2Client::CreateFromService(kClientNames[index]);
}

ClientList getClientList() {
    ClientList list;
    for (size_t i = 0; i < list.size(); ++i) {
        list[i] = getClient(i);
    }
    return list;
}

} // unnamed

// Codec2ConfigurableClient

const C2String& Codec2ConfigurableClient::getName() const {
    return mName;
}

Codec2ConfigurableClient::Base* Codec2ConfigurableClient::base() const {
    return static_cast<Base*>(mBase.get());
}

Codec2ConfigurableClient::Codec2ConfigurableClient(
        const sp<Codec2ConfigurableClient::Base>& base) : mBase(base) {
    Return<void> transStatus = base->getName(
            [this](const hidl_string& name) {
                mName = name.c_str();
            });
    if (!transStatus.isOk()) {
        ALOGE("Cannot obtain name from IConfigurable.");
    }
}

c2_status_t Codec2ConfigurableClient::query(
        const std::vector<C2Param*> &stackParams,
        const std::vector<C2Param::Index> &heapParamIndices,
        c2_blocking_t mayBlock,
        std::vector<std::unique_ptr<C2Param>>* const heapParams) const {
    hidl_vec<ParamIndex> indices(
            stackParams.size() + heapParamIndices.size());
    size_t numIndices = 0;
    for (C2Param* const& stackParam : stackParams) {
        if (!stackParam) {
            ALOGW("query -- null stack param encountered.");
            continue;
        }
        indices[numIndices++] = static_cast<ParamIndex>(stackParam->index());
    }
    size_t numStackIndices = numIndices;
    for (const C2Param::Index& index : heapParamIndices) {
        indices[numIndices++] =
                static_cast<ParamIndex>(static_cast<uint32_t>(index));
    }
    indices.resize(numIndices);
    if (heapParams) {
        heapParams->reserve(heapParams->size() + numIndices);
    }
    c2_status_t status;
    Return<void> transStatus = base()->query(
            indices,
            mayBlock == C2_MAY_BLOCK,
            [&status, &numStackIndices, &stackParams, heapParams](
                    Status s, const Params& p) {
                status = static_cast<c2_status_t>(s);
                if (status != C2_OK && status != C2_BAD_INDEX) {
                    ALOGE("query -- call failed. "
                            "Error code = %d", static_cast<int>(status));
                    return;
                }
                std::vector<C2Param*> paramPointers;
                c2_status_t parseStatus = parseParamsBlob(&paramPointers, p);
                if (parseStatus != C2_OK) {
                    ALOGE("query -- error while parsing params. "
                            "Error code = %d", static_cast<int>(status));
                    status = parseStatus;
                    return;
                }
                size_t i = 0;
                for (auto it = paramPointers.begin(); it != paramPointers.end(); ) {
                    C2Param* paramPointer = *it;
                    if (numStackIndices > 0) {
                        --numStackIndices;
                        if (!paramPointer) {
                            ALOGW("query -- null stack param.");
                            ++it;
                            continue;
                        }
                        for (; i < stackParams.size() && !stackParams[i]; ) {
                            ++i;
                        }
                        if (i >= stackParams.size()) {
                            ALOGE("query -- unexpected error.");
                            status = C2_CORRUPTED;
                            return;
                        }
                        if (stackParams[i]->index() != paramPointer->index()) {
                            ALOGW("query -- param skipped. index = %d",
                                    static_cast<int>(stackParams[i]->index()));
                            stackParams[i++]->invalidate();
                            continue;
                        }
                        if (!stackParams[i++]->updateFrom(*paramPointer)) {
                            ALOGW("query -- param update failed. index = %d",
                                    static_cast<int>(paramPointer->index()));
                        }
                    } else {
                        if (!paramPointer) {
                            ALOGW("query -- null heap param.");
                            ++it;
                            continue;
                        }
                        if (!heapParams) {
                            ALOGW("query -- unexpected extra stack param.");
                        } else {
                            heapParams->emplace_back(C2Param::Copy(*paramPointer));
                        }
                    }
                    ++it;
                }
            });
    if (!transStatus.isOk()) {
        ALOGE("query -- transaction failed.");
        return C2_TRANSACTION_FAILED;
    }
    return status;
}

c2_status_t Codec2ConfigurableClient::config(
        const std::vector<C2Param*> &params,
        c2_blocking_t mayBlock,
        std::vector<std::unique_ptr<C2SettingResult>>* const failures) {
    Params hidlParams;
    Status hidlStatus = createParamsBlob(&hidlParams, params);
    if (hidlStatus != Status::OK) {
        ALOGE("config -- bad input.");
        return C2_TRANSACTION_FAILED;
    }
    c2_status_t status;
    Return<void> transStatus = base()->config(
            hidlParams,
            mayBlock == C2_MAY_BLOCK,
            [&status, &params, failures](
                    Status s,
                    const hidl_vec<SettingResult> f,
                    const Params& o) {
                status = static_cast<c2_status_t>(s);
                if (status != C2_OK) {
                    ALOGD("config -- call failed. "
                            "Error code = %d", static_cast<int>(status));
                }
                size_t i = failures->size();
                failures->resize(i + f.size());
                for (const SettingResult& sf : f) {
                    status = objcpy(&(*failures)[i++], sf);
                    if (status != C2_OK) {
                        ALOGE("config -- invalid returned SettingResult. "
                                "Error code = %d", static_cast<int>(status));
                        return;
                    }
                }
                status = updateParamsFromBlob(params, o);
            });
    if (!transStatus.isOk()) {
        ALOGE("config -- transaction failed.");
        return C2_TRANSACTION_FAILED;
    }
    return status;
}

c2_status_t Codec2ConfigurableClient::querySupportedParams(
        std::vector<std::shared_ptr<C2ParamDescriptor>>* const params) const {
    // TODO: Cache and query properly!
    c2_status_t status;
    Return<void> transStatus = base()->querySupportedParams(
            std::numeric_limits<uint32_t>::min(),
            std::numeric_limits<uint32_t>::max(),
            [&status, params](
                    Status s,
                    const hidl_vec<ParamDescriptor>& p) {
                status = static_cast<c2_status_t>(s);
                if (status != C2_OK) {
                    ALOGE("querySupportedParams -- call failed. "
                            "Error code = %d", static_cast<int>(status));
                    return;
                }
                size_t i = params->size();
                params->resize(i + p.size());
                for (const ParamDescriptor& sp : p) {
                    status = objcpy(&(*params)[i++], sp);
                    if (status != C2_OK) {
                        ALOGE("querySupportedParams -- "
                                "invalid returned ParamDescriptor. "
                                "Error code = %d", static_cast<int>(status));
                        return;
                    }
                }
            });
    if (!transStatus.isOk()) {
        ALOGE("querySupportedParams -- transaction failed.");
        return C2_TRANSACTION_FAILED;
    }
    return status;
}

c2_status_t Codec2ConfigurableClient::querySupportedValues(
        std::vector<C2FieldSupportedValuesQuery>& fields,
        c2_blocking_t mayBlock) const {
    hidl_vec<FieldSupportedValuesQuery> inFields(fields.size());
    for (size_t i = 0; i < fields.size(); ++i) {
        Status hidlStatus = objcpy(&inFields[i], fields[i]);
        if (hidlStatus != Status::OK) {
            ALOGE("querySupportedValues -- bad input");
            return C2_TRANSACTION_FAILED;
        }
    }

    c2_status_t status;
    Return<void> transStatus = base()->querySupportedValues(
            inFields,
            mayBlock == C2_MAY_BLOCK,
            [&status, &inFields, &fields](
                    Status s,
                    const hidl_vec<FieldSupportedValuesQueryResult>& r) {
                status = static_cast<c2_status_t>(s);
                if (status != C2_OK) {
                    ALOGE("querySupportedValues -- call failed. "
                            "Error code = %d", static_cast<int>(status));
                    return;
                }
                if (r.size() != fields.size()) {
                    ALOGE("querySupportedValues -- input and output lists "
                            "have different sizes.");
                    status = C2_CORRUPTED;
                    return;
                }
                for (size_t i = 0; i < fields.size(); ++i) {
                    status = objcpy(&fields[i], inFields[i], r[i]);
                    if (status != C2_OK) {
                        ALOGE("querySupportedValues -- invalid returned value. "
                                "Error code = %d", static_cast<int>(status));
                        return;
                    }
                }
            });
    if (!transStatus.isOk()) {
        ALOGE("querySupportedValues -- transaction failed.");
        return C2_TRANSACTION_FAILED;
    }
    return status;
}

// Codec2Client::Component::HidlListener
struct Codec2Client::Component::HidlListener : public IComponentListener {
    std::weak_ptr<Component> component;
    std::weak_ptr<Listener> base;

    virtual Return<void> onWorkDone(const WorkBundle& workBundle) override {
        std::list<std::unique_ptr<C2Work>> workItems;
        c2_status_t status = objcpy(&workItems, workBundle);
        if (status != C2_OK) {
            ALOGI("onWorkDone -- received corrupted WorkBundle. "
                    "status = %d.", static_cast<int>(status));
            return Void();
        }
        // release input buffers potentially held by the component from queue
        size_t numDiscardedInputBuffers = 0;
        std::shared_ptr<Codec2Client::Component> strongComponent = component.lock();
        if (strongComponent) {
            numDiscardedInputBuffers = strongComponent->handleOnWorkDone(workItems);
        }
        if (std::shared_ptr<Codec2Client::Listener> listener = base.lock()) {
            listener->onWorkDone(component, workItems, numDiscardedInputBuffers);
        } else {
            ALOGD("onWorkDone -- listener died.");
        }
        return Void();
    }

    virtual Return<void> onTripped(
            const hidl_vec<SettingResult>& settingResults) override {
        std::vector<std::shared_ptr<C2SettingResult>> c2SettingResults(
                settingResults.size());
        c2_status_t status;
        for (size_t i = 0; i < settingResults.size(); ++i) {
            std::unique_ptr<C2SettingResult> c2SettingResult;
            status = objcpy(&c2SettingResult, settingResults[i]);
            if (status != C2_OK) {
                ALOGI("onTripped -- received corrupted SettingResult. "
                        "status = %d.", static_cast<int>(status));
                return Void();
            }
            c2SettingResults[i] = std::move(c2SettingResult);
        }
        if (std::shared_ptr<Codec2Client::Listener> listener = base.lock()) {
            listener->onTripped(component, c2SettingResults);
        } else {
            ALOGD("onTripped -- listener died.");
        }
        return Void();
    }

    virtual Return<void> onError(Status s, uint32_t errorCode) override {
        ALOGD("onError -- status = %d, errorCode = %u.",
                static_cast<int>(s),
                static_cast<unsigned>(errorCode));
        if (std::shared_ptr<Listener> listener = base.lock()) {
            listener->onError(component, s == Status::OK ?
                    errorCode : static_cast<c2_status_t>(s));
        } else {
            ALOGD("onError -- listener died.");
        }
        return Void();
    }

    virtual Return<void> onFramesRendered(
            const hidl_vec<RenderedFrame>& renderedFrames) override {
        std::shared_ptr<Listener> listener = base.lock();
        std::vector<Codec2Client::Listener::RenderedFrame> rfs;
        rfs.reserve(renderedFrames.size());
        for (const RenderedFrame& rf : renderedFrames) {
            if (rf.slotId >= 0) {
                if (listener) {
                    rfs.emplace_back(rf.bufferQueueId,
                                     rf.slotId,
                                     rf.timestampNs);
                }
            } else {
                std::shared_ptr<Codec2Client::Component> strongComponent =
                        component.lock();
                if (strongComponent) {
                    uint64_t frameIndex = rf.bufferQueueId;
                    size_t bufferIndex = static_cast<size_t>(~rf.slotId);
                    ALOGV("Received death notification of input buffer: "
                          "frameIndex = %llu, bufferIndex = %zu.",
                          static_cast<long long unsigned>(frameIndex),
                          bufferIndex);
                    std::shared_ptr<C2Buffer> buffer =
                            strongComponent->freeInputBuffer(
                                frameIndex, bufferIndex);
                    if (buffer) {
                        listener->onInputBufferDone(buffer);
                    }
                }
            }
        }
        if (!rfs.empty()) {
            if (listener) {
                listener->onFramesRendered(rfs);
            } else {
                ALOGD("onFramesRendered -- listener died.");
            }
        }
        return Void();
    }
};

// Codec2Client
Codec2Client::Base* Codec2Client::base() const {
    return static_cast<Base*>(mBase.get());
}

Codec2Client::Codec2Client(const sp<Codec2Client::Base>& base, std::string instanceName) :
    Codec2ConfigurableClient(base), mListed(false), mInstanceName(instanceName) {
    Return<sp<IClientManager>> transResult = base->getPoolClientManager();
    if (!transResult.isOk()) {
        ALOGE("getPoolClientManager -- failed transaction.");
    } else {
        mHostPoolManager = static_cast<sp<IClientManager>>(transResult);
    }
}

c2_status_t Codec2Client::createComponent(
        const C2String& name,
        const std::shared_ptr<Codec2Client::Listener>& listener,
        std::shared_ptr<Codec2Client::Component>* const component) {

    // TODO: Add support for Bufferpool


    c2_status_t status;
    sp<Component::HidlListener> hidlListener = new Component::HidlListener();
    hidlListener->base = listener;
    Return<void> transStatus = base()->createComponent(
            name,
            hidlListener,
            ClientManager::getInstance(),
            [&status, component, hidlListener](
                    Status s,
                    const sp<IComponent>& c) {
                status = static_cast<c2_status_t>(s);
                if (status != C2_OK) {
                    return;
                }
                *component = std::make_shared<Codec2Client::Component>(c);
                hidlListener->component = *component;
            });
    if (!transStatus.isOk()) {
        ALOGE("createComponent -- failed transaction.");
        return C2_TRANSACTION_FAILED;
    }

    if (status != C2_OK) {
        return status;
    }

    if (!*component) {
        ALOGE("createComponent -- null component.");
        return C2_CORRUPTED;
    }

    status = (*component)->setDeathListener(*component, listener);
    if (status != C2_OK) {
        ALOGE("createComponent -- setDeathListener returned error: %d.",
                static_cast<int>(status));
    }

    (*component)->mBufferPoolSender.setReceiver(mHostPoolManager);
    return status;
}

c2_status_t Codec2Client::createInterface(
        const C2String& name,
        std::shared_ptr<Codec2Client::Interface>* const interface) {
    c2_status_t status;
    Return<void> transStatus = base()->createInterface(
            name,
            [&status, interface](
                    Status s,
                    const sp<IComponentInterface>& i) {
                status = static_cast<c2_status_t>(s);
                if (status != C2_OK) {
                    ALOGE("createInterface -- call failed. "
                            "Error code = %d", static_cast<int>(status));
                    return;
                }
                *interface = std::make_shared<Codec2Client::Interface>(i);
            });
    if (!transStatus.isOk()) {
        ALOGE("createInterface -- failed transaction.");
        return C2_TRANSACTION_FAILED;
    }
    return status;
}

c2_status_t Codec2Client::createInputSurface(
        std::shared_ptr<Codec2Client::InputSurface>* const inputSurface) {
    Return<sp<IInputSurface>> transResult = base()->createInputSurface();
    if (!transResult.isOk()) {
        ALOGE("createInputSurface -- failed transaction.");
        return C2_TRANSACTION_FAILED;
    }
    sp<IInputSurface> result = static_cast<sp<IInputSurface>>(transResult);
    if (!result) {
        *inputSurface = nullptr;
        return C2_OK;
    }
    *inputSurface = std::make_shared<InputSurface>(result);
    if (!*inputSurface) {
        ALOGE("createInputSurface -- unknown error.");
        return C2_CORRUPTED;
    }
    return C2_OK;
}

const std::vector<C2Component::Traits>& Codec2Client::listComponents() const {
    std::lock_guard<std::mutex> lock(mMutex);
    if (mListed) {
        return mTraitsList;
    }
    Return<void> transStatus = base()->listComponents(
            [this](const hidl_vec<IComponentStore::ComponentTraits>& t) {
                mTraitsList.resize(t.size());
                mAliasesBuffer.resize(t.size());
                for (size_t i = 0; i < t.size(); ++i) {
                    c2_status_t status = objcpy(
                            &mTraitsList[i], &mAliasesBuffer[i], t[i]);
                    if (status != C2_OK) {
                        ALOGE("listComponents -- corrupted output.");
                        return;
                    }
                }
            });
    if (!transStatus.isOk()) {
        ALOGE("listComponents -- failed transaction.");
    }
    mListed = true;
    return mTraitsList;
}

c2_status_t Codec2Client::copyBuffer(
        const std::shared_ptr<C2Buffer>& src,
        const std::shared_ptr<C2Buffer>& dst) {
    // TODO: Implement?
    (void)src;
    (void)dst;
    ALOGE("copyBuffer not implemented");
    return C2_OMITTED;
}

std::shared_ptr<C2ParamReflector>
        Codec2Client::getParamReflector() {
    // TODO: this is not meant to be exposed as C2ParamReflector on the client side; instead, it
    // should reflect the HAL API.
    struct SimpleParamReflector : public C2ParamReflector {
        virtual std::unique_ptr<C2StructDescriptor> describe(C2Param::CoreIndex coreIndex) const {
            hidl_vec<ParamIndex> indices(1);
            indices[0] = static_cast<ParamIndex>(coreIndex.coreIndex());
            std::unique_ptr<C2StructDescriptor> descriptor;
            Return<void> transStatus = mBase->getStructDescriptors(
                    indices,
                    [&descriptor](
                            Status s,
                            const hidl_vec<StructDescriptor>& sd) {
                        c2_status_t status = static_cast<c2_status_t>(s);
                        if (status != C2_OK) {
                            ALOGE("getStructDescriptors -- call failed. "
                                    "Error code = %d", static_cast<int>(status));
                            descriptor.reset();
                            return;
                        }
                        if (sd.size() != 1) {
                            ALOGD("getStructDescriptors -- returned vector of size %zu.",
                                    sd.size());
                            descriptor.reset();
                            return;
                        }
                        status = objcpy(&descriptor, sd[0]);
                        if (status != C2_OK) {
                            ALOGD("getStructDescriptors -- failed to convert. "
                                    "Error code = %d", static_cast<int>(status));
                            descriptor.reset();
                            return;
                        }
                    });
            return descriptor;
        }

        SimpleParamReflector(sp<Base> base)
            : mBase(base) { }

        sp<Base> mBase;
    };

    return std::make_shared<SimpleParamReflector>(base());
};

std::shared_ptr<Codec2Client> Codec2Client::CreateFromService(
        const char* instanceName, bool waitForService) {
    if (!instanceName) {
        return nullptr;
    }
    sp<Base> baseStore = waitForService ?
            Base::getService(instanceName) :
            Base::tryGetService(instanceName);
    if (!baseStore) {
        if (waitForService) {
            ALOGE("Codec2.0 service inaccessible. Check the device manifest.");
        } else {
            ALOGW("Codec2.0 service not available right now. Try again later.");
        }
        return nullptr;
    }
    return std::make_shared<Codec2Client>(baseStore, instanceName);
}

c2_status_t Codec2Client::ForAllStores(
        const std::string &key,
        std::function<c2_status_t(const std::shared_ptr<Codec2Client>&)> predicate) {
    c2_status_t status = C2_NO_INIT;  // no IComponentStores present

    // Cache the mapping key -> index of Codec2Client in getClient().
    static std::mutex key2IndexMutex;
    static std::map<std::string, size_t> key2Index;

    // By default try all stores. However, try the last known client first. If the last known
    // client fails, retry once. We do this by pushing the last known client in front of the
    // list of all clients.
    std::deque<size_t> indices;
    for (size_t index = kNumClients; index > 0; ) {
        indices.push_front(--index);
    }

    bool wasMapped = false;
    std::unique_lock<std::mutex> lock(key2IndexMutex);
    auto it = key2Index.find(key);
    if (it != key2Index.end()) {
        indices.push_front(it->second);
        wasMapped = true;
    }
    lock.unlock();

    for (size_t index : indices) {
        std::shared_ptr<Codec2Client> client = getClient(index);
        if (client) {
            status = predicate(client);
            if (status == C2_OK) {
                lock.lock();
                key2Index[key] = index; // update last known client index
                return status;
            }
        }
        if (wasMapped) {
            ALOGI("Could not find '%s' in last instance. Retrying...", key.c_str());
            wasMapped = false;
        }
    }
    return status;  // return the last status from a valid client
}

std::shared_ptr<Codec2Client::Component>
        Codec2Client::CreateComponentByName(
        const char* componentName,
        const std::shared_ptr<Listener>& listener,
        std::shared_ptr<Codec2Client>* owner) {
    std::shared_ptr<Component> component;
    c2_status_t status = ForAllStores(
            componentName,
            [owner, &component, componentName, &listener](
                    const std::shared_ptr<Codec2Client> &client) -> c2_status_t {
                c2_status_t status = client->createComponent(componentName, listener, &component);
                if (status == C2_OK) {
                    if (owner) {
                        *owner = client;
                    }
                } else if (status != C2_NOT_FOUND) {
                    ALOGD("IComponentStore(%s)::createComponent('%s') returned %s",
                            client->getInstanceName().c_str(), componentName, asString(status));
                }
                return status;
            });
    if (status != C2_OK) {
        ALOGI("Could not create component '%s' (%s)", componentName, asString(status));
    }
    return component;
}

std::shared_ptr<Codec2Client::Interface>
        Codec2Client::CreateInterfaceByName(
        const char* interfaceName,
        std::shared_ptr<Codec2Client>* owner) {
    std::shared_ptr<Interface> interface;
    c2_status_t status = ForAllStores(
            interfaceName,
            [owner, &interface, interfaceName](
                    const std::shared_ptr<Codec2Client> &client) -> c2_status_t {
                c2_status_t status = client->createInterface(interfaceName, &interface);
                if (status == C2_OK) {
                    if (owner) {
                        *owner = client;
                    }
                } else if (status != C2_NOT_FOUND) {
                    ALOGD("IComponentStore(%s)::createInterface('%s') returned %s",
                            client->getInstanceName().c_str(), interfaceName, asString(status));
                }
                return status;
            });
    if (status != C2_OK) {
        ALOGI("Could not create interface '%s' (%s)", interfaceName, asString(status));
    }
    return interface;
}

std::shared_ptr<Codec2Client::InputSurface> Codec2Client::CreateInputSurface() {
    uint32_t serviceMask = ::android::base::GetUintProperty(
            "debug.stagefright.c2inputsurface", uint32_t(0));
    for (size_t i = 0; i < kNumClients; ++i) {
        if ((1 << i) & serviceMask) {
            std::shared_ptr<Codec2Client> client = getClient(i);
            std::shared_ptr<Codec2Client::InputSurface> inputSurface;
            if (client &&
                    client->createInputSurface(&inputSurface) == C2_OK &&
                    inputSurface) {
                return inputSurface;
            }
        }
    }
    ALOGW("Could not create an input surface from any Codec2.0 services.");
    return nullptr;
}

const std::vector<C2Component::Traits>& Codec2Client::ListComponents() {
    static std::vector<C2Component::Traits> traitsList = [](){
        std::vector<C2Component::Traits> list;
        size_t listSize = 0;
        ClientList clientList = getClientList();
        for (const std::shared_ptr<Codec2Client>& client : clientList) {
            if (!client) {
                continue;
            }
            listSize += client->listComponents().size();
        }
        list.reserve(listSize);
        for (const std::shared_ptr<Codec2Client>& client : clientList) {
            if (!client) {
                continue;
            }
            list.insert(
                    list.end(),
                    client->listComponents().begin(),
                    client->listComponents().end());
        }
        return list;
    }();

    return traitsList;
}

// Codec2Client::Listener

Codec2Client::Listener::~Listener() {
}

// Codec2Client::Component

Codec2Client::Component::Base* Codec2Client::Component::base() const {
    return static_cast<Base*>(mBase.get());
}

Codec2Client::Component::Component(const sp<Codec2Client::Component::Base>& base) :
    Codec2Client::Configurable(base),
    mBufferPoolSender(nullptr) {
}

Codec2Client::Component::~Component() {
}

c2_status_t Codec2Client::Component::createBlockPool(
        C2Allocator::id_t id,
        C2BlockPool::local_id_t* blockPoolId,
        std::shared_ptr<Codec2Client::Configurable>* configurable) {
    c2_status_t status;
    Return<void> transStatus = base()->createBlockPool(
            static_cast<uint32_t>(id),
            [&status, blockPoolId, configurable](
                    Status s,
                    uint64_t pId,
                    const sp<IConfigurable>& c) {
                status = static_cast<c2_status_t>(s);
                configurable->reset();
                if (status != C2_OK) {
                    ALOGE("createBlockPool -- call failed. "
                            "Error code = %d", static_cast<int>(status));
                    return;
                }
                *blockPoolId = static_cast<C2BlockPool::local_id_t>(pId);
                *configurable = std::make_shared<Codec2Client::Configurable>(c);
            });
    if (!transStatus.isOk()) {
        ALOGE("createBlockPool -- transaction failed.");
        return C2_TRANSACTION_FAILED;
    }
    return status;
}

c2_status_t Codec2Client::Component::destroyBlockPool(
        C2BlockPool::local_id_t localId) {
    Return<Status> transResult = base()->destroyBlockPool(
            static_cast<uint64_t>(localId));
    if (!transResult.isOk()) {
        ALOGE("destroyBlockPool -- transaction failed.");
        return C2_TRANSACTION_FAILED;
    }
    return static_cast<c2_status_t>(static_cast<Status>(transResult));
}

size_t Codec2Client::Component::handleOnWorkDone(
        const std::list<std::unique_ptr<C2Work>> &workItems) {
    // Input buffers' lifetime management
    std::vector<uint64_t> inputDone;
    for (const std::unique_ptr<C2Work> &work : workItems) {
        if (work) {
            if (work->worklets.empty()
                    || !work->worklets.back()
                    || (work->worklets.back()->output.flags & C2FrameData::FLAG_INCOMPLETE) == 0) {
                // input is complete
                inputDone.emplace_back(work->input.ordinal.frameIndex.peeku());
            }
        }
    }

    size_t numDiscardedInputBuffers = 0;
    {
        std::lock_guard<std::mutex> lock(mInputBuffersMutex);
        for (uint64_t inputIndex : inputDone) {
            auto it = mInputBuffers.find(inputIndex);
            if (it == mInputBuffers.end()) {
                ALOGV("onWorkDone -- returned consumed/unknown "
                      "input frame: index %llu",
                        (long long)inputIndex);
            } else {
                ALOGV("onWorkDone -- processed input frame: "
                      "index %llu (containing %zu buffers)",
                        (long long)inputIndex, it->second.size());
                mInputBuffers.erase(it);
                mInputBufferCount.erase(inputIndex);
                ++numDiscardedInputBuffers;
            }
        }
    }

    // Output bufferqueue-based blocks' lifetime management
    mOutputBufferQueueMutex.lock();
    sp<IGraphicBufferProducer> igbp = mOutputIgbp;
    uint64_t bqId = mOutputBqId;
    uint32_t generation = mOutputGeneration;
    mOutputBufferQueueMutex.unlock();

    if (igbp) {
        holdBufferQueueBlocks(workItems, igbp, bqId, generation);
    }
    return numDiscardedInputBuffers;
}

std::shared_ptr<C2Buffer> Codec2Client::Component::freeInputBuffer(
        uint64_t frameIndex,
        size_t bufferIndex) {
    std::shared_ptr<C2Buffer> buffer;
    std::lock_guard<std::mutex> lock(mInputBuffersMutex);
    auto it = mInputBuffers.find(frameIndex);
    if (it == mInputBuffers.end()) {
        ALOGI("freeInputBuffer -- Unrecognized input frame index %llu.",
              static_cast<long long unsigned>(frameIndex));
        return nullptr;
    }
    if (bufferIndex >= it->second.size()) {
        ALOGI("freeInputBuffer -- Input buffer no. %zu is invalid in "
              "input frame index %llu.",
              bufferIndex, static_cast<long long unsigned>(frameIndex));
        return nullptr;
    }
    buffer = it->second[bufferIndex];
    if (!buffer) {
        ALOGI("freeInputBuffer -- Input buffer no. %zu in "
              "input frame index %llu has already been freed.",
              bufferIndex, static_cast<long long unsigned>(frameIndex));
        return nullptr;
    }
    it->second[bufferIndex] = nullptr;
    if (--mInputBufferCount[frameIndex] == 0) {
        mInputBuffers.erase(it);
        mInputBufferCount.erase(frameIndex);
    }
    return buffer;
}

c2_status_t Codec2Client::Component::queue(
        std::list<std::unique_ptr<C2Work>>* const items) {
    // remember input buffers queued to hold reference to them
    {
        std::lock_guard<std::mutex> lock(mInputBuffersMutex);
        for (const std::unique_ptr<C2Work> &work : *items) {
            if (!work) {
                continue;
            }
            if (work->input.buffers.size() == 0) {
                continue;
            }

            uint64_t inputIndex = work->input.ordinal.frameIndex.peeku();
            auto res = mInputBuffers.emplace(inputIndex, work->input.buffers);
            if (!res.second) {
                // TODO: append? - for now we are replacing
                res.first->second = work->input.buffers;
                ALOGI("queue -- duplicate input frame: index %llu. "
                      "Discarding the old input frame...",
                        (long long)inputIndex);
            }
            mInputBufferCount[inputIndex] = work->input.buffers.size();
            ALOGV("queue -- queueing input frame: "
                  "index %llu (containing %zu buffers)",
                    (long long)inputIndex, work->input.buffers.size());
        }
    }

    WorkBundle workBundle;
    Status hidlStatus = objcpy(&workBundle, *items, &mBufferPoolSender);
    if (hidlStatus != Status::OK) {
        ALOGE("queue -- bad input.");
        return C2_TRANSACTION_FAILED;
    }
    Return<Status> transStatus = base()->queue(workBundle);
    if (!transStatus.isOk()) {
        ALOGE("queue -- transaction failed.");
        return C2_TRANSACTION_FAILED;
    }
    c2_status_t status =
            static_cast<c2_status_t>(static_cast<Status>(transStatus));
    if (status != C2_OK) {
        ALOGE("queue -- call failed. "
                "Error code = %d", static_cast<int>(status));
    }
    return status;
}

c2_status_t Codec2Client::Component::flush(
        C2Component::flush_mode_t mode,
        std::list<std::unique_ptr<C2Work>>* const flushedWork) {
    (void)mode; // Flush mode isn't supported in HIDL yet.
    c2_status_t status;
    Return<void> transStatus = base()->flush(
            [&status, flushedWork](
                    Status s, const WorkBundle& wb) {
                status = static_cast<c2_status_t>(s);
                if (status != C2_OK) {
                    ALOGE("flush -- call failed. "
                            "Error code = %d", static_cast<int>(status));
                    return;
                }
                status = objcpy(flushedWork, wb);
            });
    if (!transStatus.isOk()) {
        ALOGE("flush -- transaction failed.");
        return C2_TRANSACTION_FAILED;
    }

    // Indices of flushed work items.
    std::vector<uint64_t> flushedIndices;
    for (const std::unique_ptr<C2Work> &work : *flushedWork) {
        if (work) {
            if (work->worklets.empty()
                    || !work->worklets.back()
                    || (work->worklets.back()->output.flags &
                        C2FrameData::FLAG_INCOMPLETE) == 0) {
                // input is complete
                flushedIndices.emplace_back(
                        work->input.ordinal.frameIndex.peeku());
            }
        }
    }

    // Input buffers' lifetime management
    for (uint64_t flushedIndex : flushedIndices) {
        std::lock_guard<std::mutex> lock(mInputBuffersMutex);
        auto it = mInputBuffers.find(flushedIndex);
        if (it == mInputBuffers.end()) {
            ALOGV("flush -- returned consumed/unknown input frame: "
                  "index %llu",
                    (long long)flushedIndex);
        } else {
            ALOGV("flush -- returned unprocessed input frame: "
                  "index %llu (containing %zu buffers)",
                    (long long)flushedIndex, mInputBufferCount[flushedIndex]);
            mInputBuffers.erase(it);
            mInputBufferCount.erase(flushedIndex);
        }
    }

    // Output bufferqueue-based blocks' lifetime management
    mOutputBufferQueueMutex.lock();
    sp<IGraphicBufferProducer> igbp = mOutputIgbp;
    uint64_t bqId = mOutputBqId;
    uint32_t generation = mOutputGeneration;
    mOutputBufferQueueMutex.unlock();

    if (igbp) {
        holdBufferQueueBlocks(*flushedWork, igbp, bqId, generation);
    }

    return status;
}

c2_status_t Codec2Client::Component::drain(C2Component::drain_mode_t mode) {
    Return<Status> transStatus = base()->drain(
            mode == C2Component::DRAIN_COMPONENT_WITH_EOS);
    if (!transStatus.isOk()) {
        ALOGE("drain -- transaction failed.");
        return C2_TRANSACTION_FAILED;
    }
    c2_status_t status =
            static_cast<c2_status_t>(static_cast<Status>(transStatus));
    if (status != C2_OK) {
        ALOGE("drain -- call failed. "
                "Error code = %d", static_cast<int>(status));
    }
    return status;
}

c2_status_t Codec2Client::Component::start() {
    Return<Status> transStatus = base()->start();
    if (!transStatus.isOk()) {
        ALOGE("start -- transaction failed.");
        return C2_TRANSACTION_FAILED;
    }
    c2_status_t status =
            static_cast<c2_status_t>(static_cast<Status>(transStatus));
    if (status != C2_OK) {
        ALOGE("start -- call failed. "
                "Error code = %d", static_cast<int>(status));
    }
    return status;
}

c2_status_t Codec2Client::Component::stop() {
    Return<Status> transStatus = base()->stop();
    if (!transStatus.isOk()) {
        ALOGE("stop -- transaction failed.");
        return C2_TRANSACTION_FAILED;
    }
    c2_status_t status =
            static_cast<c2_status_t>(static_cast<Status>(transStatus));
    if (status != C2_OK) {
        ALOGE("stop -- call failed. "
                "Error code = %d", static_cast<int>(status));
    }
    mInputBuffersMutex.lock();
    mInputBuffers.clear();
    mInputBufferCount.clear();
    mInputBuffersMutex.unlock();
    return status;
}

c2_status_t Codec2Client::Component::reset() {
    Return<Status> transStatus = base()->reset();
    if (!transStatus.isOk()) {
        ALOGE("reset -- transaction failed.");
        return C2_TRANSACTION_FAILED;
    }
    c2_status_t status =
            static_cast<c2_status_t>(static_cast<Status>(transStatus));
    if (status != C2_OK) {
        ALOGE("reset -- call failed. "
                "Error code = %d", static_cast<int>(status));
    }
    mInputBuffersMutex.lock();
    mInputBuffers.clear();
    mInputBufferCount.clear();
    mInputBuffersMutex.unlock();
    return status;
}

c2_status_t Codec2Client::Component::release() {
    Return<Status> transStatus = base()->release();
    if (!transStatus.isOk()) {
        ALOGE("release -- transaction failed.");
        return C2_TRANSACTION_FAILED;
    }
    c2_status_t status =
            static_cast<c2_status_t>(static_cast<Status>(transStatus));
    if (status != C2_OK) {
        ALOGE("release -- call failed. "
                "Error code = %d", static_cast<int>(status));
    }
    mInputBuffersMutex.lock();
    mInputBuffers.clear();
    mInputBufferCount.clear();
    mInputBuffersMutex.unlock();
    return status;
}

c2_status_t Codec2Client::Component::setOutputSurface(
        C2BlockPool::local_id_t blockPoolId,
        const sp<IGraphicBufferProducer>& surface,
        uint32_t generation) {
    sp<HGraphicBufferProducer> igbp = surface->getHalInterface();
    if (!igbp) {
        igbp = new TWGraphicBufferProducer<HGraphicBufferProducer>(surface);
    }

    Return<Status> transStatus = base()->setOutputSurface(
            static_cast<uint64_t>(blockPoolId), igbp);
    if (!transStatus.isOk()) {
        ALOGE("setOutputSurface -- transaction failed.");
        return C2_TRANSACTION_FAILED;
    }
    c2_status_t status =
            static_cast<c2_status_t>(static_cast<Status>(transStatus));
    if (status != C2_OK) {
        ALOGE("setOutputSurface -- call failed. "
                "Error code = %d", static_cast<int>(status));
    } else {
        std::lock_guard<std::mutex> lock(mOutputBufferQueueMutex);
        if (mOutputIgbp != surface) {
            mOutputIgbp = surface;
            if (!surface) {
                mOutputBqId = 0;
            } else if (surface->getUniqueId(&mOutputBqId) != OK) {
                ALOGE("setOutputSurface -- cannot obtain bufferqueue id.");
            }
        }
        mOutputGeneration = generation;
    }
    return status;
}

status_t Codec2Client::Component::queueToOutputSurface(
        const C2ConstGraphicBlock& block,
        const QueueBufferInput& input,
        QueueBufferOutput* output) {
    uint32_t generation;
    uint64_t bqId;
    int32_t bqSlot;
    if (!getBufferQueueAssignment(block, &generation, &bqId, &bqSlot) ||
            bqId == 0) {
        // Block not from bufferqueue -- it must be attached before queuing.

        mOutputBufferQueueMutex.lock();
        sp<IGraphicBufferProducer> outputIgbp = mOutputIgbp;
        uint32_t outputGeneration = mOutputGeneration;
        mOutputBufferQueueMutex.unlock();

        status_t status = !attachToBufferQueue(block,
                                               outputIgbp,
                                               outputGeneration,
                                               &bqSlot);
        if (status != OK) {
            ALOGW("queueToOutputSurface -- attaching failed.");
            return INVALID_OPERATION;
        }

        status = outputIgbp->queueBuffer(static_cast<int>(bqSlot),
                                         input, output);
        if (status != OK) {
            ALOGE("queueToOutputSurface -- queueBuffer() failed "
                    "on non-bufferqueue-based block. "
                    "Error code = %d.",
                    static_cast<int>(status));
            return status;
        }
        return OK;
    }

    mOutputBufferQueueMutex.lock();
    sp<IGraphicBufferProducer> outputIgbp = mOutputIgbp;
    uint64_t outputBqId = mOutputBqId;
    uint32_t outputGeneration = mOutputGeneration;
    mOutputBufferQueueMutex.unlock();

    if (!outputIgbp) {
        ALOGV("queueToOutputSurface -- output surface is null.");
        return NO_INIT;
    }

    if (bqId != outputBqId) {
        ALOGV("queueToOutputSurface -- bufferqueue ids mismatch.");
        return DEAD_OBJECT;
    }

    if (generation != outputGeneration) {
        ALOGV("queueToOutputSurface -- generation numbers mismatch.");
        return DEAD_OBJECT;
    }

    status_t status = outputIgbp->queueBuffer(static_cast<int>(bqSlot),
                                              input, output);
    if (status != OK) {
        ALOGD("queueToOutputSurface -- queueBuffer() failed "
                "on bufferqueue-based block. "
                "Error code = %d.",
                static_cast<int>(status));
        return status;
    }
    if (!yieldBufferQueueBlock(block)) {
        ALOGD("queueToOutputSurface -- cannot yield bufferqueue-based block "
                "to the bufferqueue.");
        return UNKNOWN_ERROR;
    }
    return OK;
}

c2_status_t Codec2Client::Component::connectToOmxInputSurface(
        const sp<HGraphicBufferProducer>& producer,
        const sp<HGraphicBufferSource>& source) {
    Return<Status> transStatus = base()->connectToOmxInputSurface(
            producer, source);
    if (!transStatus.isOk()) {
        ALOGE("connectToOmxInputSurface -- transaction failed.");
        return C2_TRANSACTION_FAILED;
    }
    c2_status_t status =
            static_cast<c2_status_t>(static_cast<Status>(transStatus));
    if (status != C2_OK) {
        ALOGE("connectToOmxInputSurface -- call failed. "
                "Error code = %d", static_cast<int>(status));
    }
    return status;
}

c2_status_t Codec2Client::Component::disconnectFromInputSurface() {
    Return<Status> transStatus = base()->disconnectFromInputSurface();
    if (!transStatus.isOk()) {
        ALOGE("disconnectToInputSurface -- transaction failed.");
        return C2_TRANSACTION_FAILED;
    }
    c2_status_t status =
            static_cast<c2_status_t>(static_cast<Status>(transStatus));
    if (status != C2_OK) {
        ALOGE("disconnectFromInputSurface -- call failed. "
                "Error code = %d", static_cast<int>(status));
    }
    return status;
}

c2_status_t Codec2Client::Component::setDeathListener(
        const std::shared_ptr<Component>& component,
        const std::shared_ptr<Listener>& listener) {

    struct HidlDeathRecipient : public hardware::hidl_death_recipient {
        std::weak_ptr<Component> component;
        std::weak_ptr<Listener> base;

        virtual void serviceDied(
                uint64_t /* cookie */,
                const wp<::android::hidl::base::V1_0::IBase>& /* who */
                ) override {
            if (std::shared_ptr<Codec2Client::Listener> listener = base.lock()) {
                listener->onDeath(component);
            } else {
                ALOGW("onDeath -- listener died.");
            }
        }
    };

    sp<HidlDeathRecipient> deathRecipient = new HidlDeathRecipient();
    deathRecipient->base = listener;
    deathRecipient->component = component;

    component->mDeathRecipient = deathRecipient;
    Return<bool> transResult = component->base()->linkToDeath(
            component->mDeathRecipient, 0);
    if (!transResult.isOk()) {
        ALOGE("setDeathListener -- failed transaction: linkToDeath.");
        return C2_TRANSACTION_FAILED;
    }
    if (!static_cast<bool>(transResult)) {
        ALOGE("setDeathListener -- linkToDeath call failed.");
        return C2_CORRUPTED;
    }
    return C2_OK;
}

// Codec2Client::InputSurface

Codec2Client::InputSurface::Base* Codec2Client::InputSurface::base() const {
    return static_cast<Base*>(mBase.get());
}

Codec2Client::InputSurface::InputSurface(const sp<IInputSurface>& base) :
    mBase(base),
    mGraphicBufferProducer(new
            ::android::hardware::graphics::bufferqueue::V1_0::utils::
            H2BGraphicBufferProducer(base)) {
}

c2_status_t Codec2Client::InputSurface::connectToComponent(
        const std::shared_ptr<Codec2Client::Component>& component,
        std::shared_ptr<Connection>* connection) {
    c2_status_t status;
    Return<void> transStatus = base()->connectToComponent(
        component->base(),
        [&status, connection](
                Status s,
                const sp<IInputSurfaceConnection>& c) {
            status = static_cast<c2_status_t>(s);
            if (status != C2_OK) {
                ALOGE("connectToComponent -- call failed. "
                        "Error code = %d", static_cast<int>(status));
                return;
            }
            *connection = std::make_shared<Connection>(c);
        });
    if (!transStatus.isOk()) {
        ALOGE("connect -- transaction failed.");
        return C2_TRANSACTION_FAILED;
    }
    return status;
}

std::shared_ptr<Codec2Client::Configurable>
        Codec2Client::InputSurface::getConfigurable() const {
    Return<sp<IConfigurable>> transResult = base()->getConfigurable();
    if (!transResult.isOk()) {
        ALOGW("getConfigurable -- transaction failed.");
        return nullptr;
    }
    if (!static_cast<sp<IConfigurable>>(transResult)) {
        ALOGW("getConfigurable -- null pointer.");
        return nullptr;
    }
    return std::make_shared<Configurable>(transResult);
}

const sp<IGraphicBufferProducer>&
        Codec2Client::InputSurface::getGraphicBufferProducer() const {
    return mGraphicBufferProducer;
}

const sp<IInputSurface>& Codec2Client::InputSurface::getHalInterface() const {
    return mBase;
}

// Codec2Client::InputSurfaceConnection

Codec2Client::InputSurfaceConnection::Base*
        Codec2Client::InputSurfaceConnection::base() const {
    return static_cast<Base*>(mBase.get());
}

Codec2Client::InputSurfaceConnection::InputSurfaceConnection(
        const sp<Codec2Client::InputSurfaceConnection::Base>& base) :
    mBase(base) {
}

c2_status_t Codec2Client::InputSurfaceConnection::disconnect() {
    Return<Status> transResult = base()->disconnect();
    return static_cast<c2_status_t>(static_cast<Status>(transResult));
}

}  // namespace android

