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

//#define LOG_NDEBUG 0
#define LOG_TAG "Codec2Client"
#define ATRACE_TAG  ATRACE_TAG_VIDEO
#include <android-base/logging.h>
#include <utils/Trace.h>

#include <codec2/aidl/GraphicBufferAllocator.h>
#include <codec2/hidl/client.h>
#include <C2Debug.h>
#include <C2BufferPriv.h>
#include <C2Config.h> // for C2StreamUsageTuning
#include <C2PlatformSupport.h>

#include <android/hardware/media/bufferpool/2.0/IClientManager.h>
#include <android/hardware/media/c2/1.0/IComponent.h>
#include <android/hardware/media/c2/1.0/IComponentInterface.h>
#include <android/hardware/media/c2/1.0/IComponentListener.h>
#include <android/hardware/media/c2/1.0/IComponentStore.h>
#include <android/hardware/media/c2/1.0/IConfigurable.h>
#include <android/hidl/manager/1.2/IServiceManager.h>

#include <aidl/android/hardware/media/bufferpool2/IClientManager.h>
#include <aidl/android/hardware/media/c2/BnComponentListener.h>
#include <aidl/android/hardware/media/c2/FieldSupportedValues.h>
#include <aidl/android/hardware/media/c2/FieldSupportedValuesQuery.h>
#include <aidl/android/hardware/media/c2/FieldSupportedValuesQueryResult.h>
#include <aidl/android/hardware/media/c2/IComponent.h>
#include <aidl/android/hardware/media/c2/IComponentInterface.h>
#include <aidl/android/hardware/media/c2/IComponentStore.h>
#include <aidl/android/hardware/media/c2/IConfigurable.h>
#include <aidl/android/hardware/media/c2/ParamDescriptor.h>
#include <aidl/android/hardware/media/c2/StructDescriptor.h>

#include <aidlcommonsupport/NativeHandle.h>
#include <android/api-level.h>
#include <android/binder_auto_utils.h>
#include <android/binder_ibinder.h>
#include <android/binder_manager.h>
#include <android-base/properties.h>
#include <android-base/stringprintf.h>
#include <bufferpool/ClientManager.h>
#include <bufferpool2/ClientManager.h>
#include <codec2/aidl/BufferTypes.h>
#include <codec2/aidl/ParamTypes.h>
#include <codec2/hidl/1.0/types.h>
#include <codec2/hidl/1.1/types.h>
#include <codec2/hidl/1.2/types.h>
#include <codec2/hidl/output.h>

#include <cutils/native_handle.h>
#include <gui/bufferqueue/2.0/B2HGraphicBufferProducer.h>
#include <gui/bufferqueue/2.0/H2BGraphicBufferProducer.h>
#include <hardware/gralloc.h> // for GRALLOC_USAGE_*
#include <hidl/HidlSupport.h>
#include <system/window.h> // for NATIVE_WINDOW_QUERY_*
#include <media/stagefright/foundation/ADebug.h> // for asString(status_t)

#include <deque>
#include <iterator>
#include <limits>
#include <map>
#include <mutex>
#include <optional>
#include <sstream>
#include <thread>
#include <type_traits>
#include <vector>

namespace android {

using ::android::hardware::hidl_vec;
using ::android::hardware::hidl_string;
using ::android::hardware::Return;
using ::android::hardware::Void;

using HGraphicBufferProducer1 = ::android::hardware::graphics::bufferqueue::
        V1_0::IGraphicBufferProducer;
using HGraphicBufferProducer2 = ::android::hardware::graphics::bufferqueue::
        V2_0::IGraphicBufferProducer;
using B2HGraphicBufferProducer2 = ::android::hardware::graphics::bufferqueue::
        V2_0::utils::B2HGraphicBufferProducer;
using H2BGraphicBufferProducer2 = ::android::hardware::graphics::bufferqueue::
        V2_0::utils::H2BGraphicBufferProducer;
using ::android::hardware::media::c2::V1_2::SurfaceSyncObj;

using AidlGraphicBufferAllocator = ::aidl::android::hardware::media::c2::
        implementation::GraphicBufferAllocator;

namespace bufferpool2_aidl = ::aidl::android::hardware::media::bufferpool2;
namespace bufferpool_hidl = ::android::hardware::media::bufferpool::V2_0;
namespace c2_aidl = ::aidl::android::hardware::media::c2;
namespace c2_hidl_base = ::android::hardware::media::c2;
namespace c2_hidl = ::android::hardware::media::c2::V1_2;

using c2_hidl::utils::operator<<;

namespace /* unnamed */ {

// c2_status_t value that corresponds to hwbinder transaction failure.
constexpr c2_status_t C2_TRANSACTION_FAILED = C2_CORRUPTED;

// By default prepare buffer to be displayed on any of the common surfaces
constexpr uint64_t kDefaultConsumerUsage =
    (GRALLOC_USAGE_HW_TEXTURE | GRALLOC_USAGE_HW_COMPOSER);

// Searches for a name in GetServiceNames() and returns the index found. If the
// name is not found, the returned index will be equal to
// GetServiceNames().size().
size_t getServiceIndex(char const* name) {
    std::vector<std::string> const& names = Codec2Client::GetServiceNames();
    size_t i = 0;
    for (; i < names.size(); ++i) {
        if (name == names[i]) {
            break;
        }
    }
    return i;
}

class Client2Store : public C2ComponentStore {
    std::shared_ptr<Codec2Client> mClient;

public:
    Client2Store(std::shared_ptr<Codec2Client> const& client)
        : mClient(client) { }

    virtual ~Client2Store() = default;

    virtual c2_status_t config_sm(
            std::vector<C2Param*> const &params,
            std::vector<std::unique_ptr<C2SettingResult>>* const failures) {
        return mClient->config(params, C2_MAY_BLOCK, failures);
    };

    virtual c2_status_t copyBuffer(
            std::shared_ptr<C2GraphicBuffer>,
            std::shared_ptr<C2GraphicBuffer>) {
        return C2_OMITTED;
    }

    virtual c2_status_t createComponent(
            C2String, std::shared_ptr<C2Component>* const component) {
        component->reset();
        return C2_OMITTED;
    }

    virtual c2_status_t createInterface(
            C2String, std::shared_ptr<C2ComponentInterface>* const interface) {
        interface->reset();
        return C2_OMITTED;
    }

    virtual c2_status_t query_sm(
            std::vector<C2Param*> const& stackParams,
            std::vector<C2Param::Index> const& heapParamIndices,
            std::vector<std::unique_ptr<C2Param>>* const heapParams) const {
        return mClient->query(stackParams, heapParamIndices, C2_MAY_BLOCK, heapParams);
    }

    virtual c2_status_t querySupportedParams_nb(
            std::vector<std::shared_ptr<C2ParamDescriptor>>* const params) const {
        return mClient->querySupportedParams(params);
    }

    virtual c2_status_t querySupportedValues_sm(
            std::vector<C2FieldSupportedValuesQuery>& fields) const {
        return mClient->querySupportedValues(fields, C2_MAY_BLOCK);
    }

    virtual C2String getName() const {
        return mClient->getName();
    }

    virtual std::shared_ptr<C2ParamReflector> getParamReflector() const {
        return mClient->getParamReflector();
    }

    virtual std::vector<std::shared_ptr<C2Component::Traits const>> listComponents() {
        return std::vector<std::shared_ptr<C2Component::Traits const>>();
    }
};

c2_status_t GetC2Status(const ::ndk::ScopedAStatus &transStatus, const char *method) {
    if (!transStatus.isOk()) {
        if (transStatus.getExceptionCode() == EX_SERVICE_SPECIFIC) {
            c2_status_t status = static_cast<c2_status_t>(transStatus.getServiceSpecificError());
            LOG(DEBUG) << method << " -- call failed: " << status << ".";
            return status;
        } else {
            LOG(ERROR) << method << " -- transaction failed.";
            return C2_TRANSACTION_FAILED;
        }
    }
    return C2_OK;
}

}  // unnamed namespace

// This class caches a Codec2Client object and its component traits. The client
// will be created the first time it is needed, and it can be refreshed if the
// service dies (by calling invalidate()). The first time listComponents() is
// called from the client, the result will be cached.
class Codec2Client::Cache {
    // Cached client
    std::shared_ptr<Codec2Client> mClient;
    mutable std::mutex mClientMutex;

    // Cached component traits
    std::vector<C2Component::Traits> mTraits;
    std::once_flag mTraitsInitializationFlag;

    // The index of the service. This is based on GetServiceNames().
    size_t mIndex;
    // Called by s() exactly once to initialize the cache. The index must be a
    // valid index into the vector returned by GetServiceNames(). Calling
    // init(index) will associate the cache to the service with name
    // GetServiceNames()[index].
    void init(size_t index) {
        mIndex = index;
    }

public:
    Cache() = default;

    // Initializes mClient if needed, then returns mClient.
    // If the service is unavailable but listed in the manifest, this function
    // will block indefinitely.
    std::shared_ptr<Codec2Client> getClient() {
        std::scoped_lock lock{mClientMutex};
        if (!mClient) {
            mClient = Codec2Client::_CreateFromIndex(mIndex);
        }
        CHECK(mClient) << "Failed to create Codec2Client to service \""
                       << GetServiceNames()[mIndex] << "\". (Index = "
                       << mIndex << ").";
        return mClient;
    }

    // Causes a subsequent call to getClient() to create a new client. This
    // function should be called after the service dies.
    //
    // Note: This function is called only by ForAllServices().
    void invalidate() {
        std::scoped_lock lock{mClientMutex};
        mClient = nullptr;
    }

    // Returns a list of traits for components supported by the service. This
    // list is cached.
    std::vector<C2Component::Traits> const& getTraits() {
        std::call_once(mTraitsInitializationFlag, [this]() {
            bool success{false};
            // Spin until _listComponents() is successful.
            while (true) {
                std::shared_ptr<Codec2Client> client = getClient();
                mTraits = client->_listComponents(&success);
                if (success) {
                    break;
                }
                invalidate();
                using namespace std::chrono_literals;
                static constexpr auto kServiceRetryPeriod = 5s;
                LOG(INFO) << "Failed to retrieve component traits from service "
                             "\"" << GetServiceNames()[mIndex] << "\". "
                             "Retrying...";
                std::this_thread::sleep_for(kServiceRetryPeriod);
            }
        });
        return mTraits;
    }

    // List() returns the list of all caches.
    static std::vector<Cache>& List() {
        static std::vector<Cache> sCaches{[]() {
            size_t numServices = GetServiceNames().size();
            std::vector<Cache> caches(numServices);
            for (size_t i = 0; i < numServices; ++i) {
                caches[i].init(i);
            }
            return caches;
        }()};
        return sCaches;
    }
};
// Codec2ConfigurableClient::HidlImpl

struct Codec2ConfigurableClient::HidlImpl : public Codec2ConfigurableClient::ImplBase {
    typedef c2_hidl::IConfigurable Base;

    // base cannot be null.
    explicit HidlImpl(const sp<Base>& base);

    const C2String& getName() const override {
        return mName;
    }

    c2_status_t query(
            const std::vector<C2Param*>& stackParams,
            const std::vector<C2Param::Index> &heapParamIndices,
            c2_blocking_t mayBlock,
            std::vector<std::unique_ptr<C2Param>>* const heapParams) const override;

    c2_status_t config(
            const std::vector<C2Param*> &params,
            c2_blocking_t mayBlock,
            std::vector<std::unique_ptr<C2SettingResult>>* const failures) override;

    c2_status_t querySupportedParams(
            std::vector<std::shared_ptr<C2ParamDescriptor>>* const params
            ) const override;

    c2_status_t querySupportedValues(
            std::vector<C2FieldSupportedValuesQuery>& fields,
            c2_blocking_t mayBlock) const override;

private:
    sp<Base> mBase;
    const C2String mName;
};

Codec2ConfigurableClient::HidlImpl::HidlImpl(const sp<Base>& base)
      : mBase{base},
        mName{[base]() -> C2String {
                C2String outName;
                Return<void> transStatus = base->getName(
                        [&outName](const hidl_string& name) {
                            outName = name.c_str();
                        });
                return transStatus.isOk() ? outName : "";
            }()} {
}

c2_status_t Codec2ConfigurableClient::HidlImpl::query(
        const std::vector<C2Param*> &stackParams,
        const std::vector<C2Param::Index> &heapParamIndices,
        c2_blocking_t mayBlock,
        std::vector<std::unique_ptr<C2Param>>* const heapParams) const {
    hidl_vec<c2_hidl::ParamIndex> indices(
            stackParams.size() + heapParamIndices.size());
    size_t numIndices = 0;
    for (C2Param* const& stackParam : stackParams) {
        if (!stackParam) {
            LOG(WARNING) << "query -- null stack param encountered.";
            continue;
        }
        indices[numIndices++] = static_cast<c2_hidl::ParamIndex>(stackParam->index());
    }
    size_t numStackIndices = numIndices;
    for (const C2Param::Index& index : heapParamIndices) {
        indices[numIndices++] =
                static_cast<c2_hidl::ParamIndex>(static_cast<uint32_t>(index));
    }
    indices.resize(numIndices);
    if (heapParams) {
        heapParams->reserve(heapParams->size() + numIndices);
    }
    c2_status_t status;
    Return<void> transStatus = mBase->query(
            indices,
            mayBlock == C2_MAY_BLOCK,
            [&status, &numStackIndices, &stackParams, heapParams](
                    c2_hidl::Status s, const c2_hidl::Params& p) {
                status = static_cast<c2_status_t>(s);
                if (status != C2_OK && status != C2_BAD_INDEX) {
                    LOG(DEBUG) << "query -- call failed: "
                               << status << ".";
                    return;
                }
                std::vector<C2Param*> paramPointers;
                if (!c2_hidl::utils::parseParamsBlob(&paramPointers, p)) {
                    LOG(ERROR) << "query -- error while parsing params.";
                    status = C2_CORRUPTED;
                    return;
                }
                size_t i = 0;
                for (auto it = paramPointers.begin();
                        it != paramPointers.end(); ) {
                    C2Param* paramPointer = *it;
                    if (numStackIndices > 0) {
                        --numStackIndices;
                        if (!paramPointer) {
                            LOG(WARNING) << "query -- null stack param.";
                            ++it;
                            continue;
                        }
                        for (; i < stackParams.size() && !stackParams[i]; ) {
                            ++i;
                        }
                        if (i >= stackParams.size()) {
                            LOG(ERROR) << "query -- unexpected error.";
                            status = C2_CORRUPTED;
                            return;
                        }
                        if (stackParams[i]->index() != paramPointer->index()) {
                            LOG(WARNING) << "query -- param skipped: "
                                            "index = "
                                         << stackParams[i]->index() << ".";
                            stackParams[i++]->invalidate();
                            continue;
                        }
                        if (!stackParams[i++]->updateFrom(*paramPointer)) {
                            LOG(WARNING) << "query -- param update failed: "
                                            "index = "
                                         << paramPointer->index() << ".";
                        }
                    } else {
                        if (!paramPointer) {
                            LOG(WARNING) << "query -- null heap param.";
                            ++it;
                            continue;
                        }
                        if (!heapParams) {
                            LOG(WARNING) << "query -- "
                                            "unexpected extra stack param.";
                        } else {
                            heapParams->emplace_back(
                                    C2Param::Copy(*paramPointer));
                        }
                    }
                    ++it;
                }
            });
    if (!transStatus.isOk()) {
        LOG(ERROR) << "query -- transaction failed.";
        return C2_TRANSACTION_FAILED;
    }
    return status;
}

c2_status_t Codec2ConfigurableClient::HidlImpl::config(
        const std::vector<C2Param*> &params,
        c2_blocking_t mayBlock,
        std::vector<std::unique_ptr<C2SettingResult>>* const failures) {
    c2_hidl::Params hidlParams;
    if (!c2_hidl::utils::createParamsBlob(&hidlParams, params)) {
        LOG(ERROR) << "config -- bad input.";
        return C2_TRANSACTION_FAILED;
    }
    c2_status_t status;
    Return<void> transStatus = mBase->config(
            hidlParams,
            mayBlock == C2_MAY_BLOCK,
            [&status, &params, failures](
                    c2_hidl::Status s,
                    const hidl_vec<c2_hidl::SettingResult> f,
                    const c2_hidl::Params& o) {
                status = static_cast<c2_status_t>(s);
                if (status != C2_OK && status != C2_BAD_INDEX) {
                    LOG(DEBUG) << "config -- call failed: "
                               << status << ".";
                }
                size_t i = failures->size();
                failures->resize(i + f.size());
                for (const c2_hidl::SettingResult& sf : f) {
                    if (!c2_hidl::utils::objcpy(&(*failures)[i++], sf)) {
                        LOG(ERROR) << "config -- "
                                   << "invalid SettingResult returned.";
                        return;
                    }
                }
                if (!c2_hidl::utils::updateParamsFromBlob(params, o)) {
                    LOG(ERROR) << "config -- "
                               << "failed to parse returned params.";
                    status = C2_CORRUPTED;
                }
            });
    if (!transStatus.isOk()) {
        LOG(ERROR) << "config -- transaction failed.";
        return C2_TRANSACTION_FAILED;
    }
    return status;
}

c2_status_t Codec2ConfigurableClient::HidlImpl::querySupportedParams(
        std::vector<std::shared_ptr<C2ParamDescriptor>>* const params) const {
    // TODO: Cache and query properly!
    c2_status_t status;
    Return<void> transStatus = mBase->querySupportedParams(
            std::numeric_limits<uint32_t>::min(),
            std::numeric_limits<uint32_t>::max(),
            [&status, params](
                    c2_hidl::Status s,
                    const hidl_vec<c2_hidl::ParamDescriptor>& p) {
                status = static_cast<c2_status_t>(s);
                if (status != C2_OK) {
                    LOG(DEBUG) << "querySupportedParams -- call failed: "
                               << status << ".";
                    return;
                }
                size_t i = params->size();
                params->resize(i + p.size());
                for (const c2_hidl::ParamDescriptor& sp : p) {
                    if (!c2_hidl::utils::objcpy(&(*params)[i++], sp)) {
                        LOG(ERROR) << "querySupportedParams -- "
                                   << "invalid returned ParamDescriptor.";
                        return;
                    }
                }
            });
    if (!transStatus.isOk()) {
        LOG(ERROR) << "querySupportedParams -- transaction failed.";
        return C2_TRANSACTION_FAILED;
    }
    return status;
}

c2_status_t Codec2ConfigurableClient::HidlImpl::querySupportedValues(
        std::vector<C2FieldSupportedValuesQuery>& fields,
        c2_blocking_t mayBlock) const {
    hidl_vec<c2_hidl::FieldSupportedValuesQuery> inFields(fields.size());
    for (size_t i = 0; i < fields.size(); ++i) {
        if (!c2_hidl::utils::objcpy(&inFields[i], fields[i])) {
            LOG(ERROR) << "querySupportedValues -- bad input";
            return C2_TRANSACTION_FAILED;
        }
    }

    c2_status_t status;
    Return<void> transStatus = mBase->querySupportedValues(
            inFields,
            mayBlock == C2_MAY_BLOCK,
            [&status, &inFields, &fields](
                    c2_hidl::Status s,
                    const hidl_vec<c2_hidl::FieldSupportedValuesQueryResult>& r) {
                status = static_cast<c2_status_t>(s);
                if (status != C2_OK) {
                    LOG(DEBUG) << "querySupportedValues -- call failed: "
                               << status << ".";
                    return;
                }
                if (r.size() != fields.size()) {
                    LOG(ERROR) << "querySupportedValues -- "
                                  "input and output lists "
                                  "have different sizes.";
                    status = C2_CORRUPTED;
                    return;
                }
                for (size_t i = 0; i < fields.size(); ++i) {
                    if (!c2_hidl::utils::objcpy(&fields[i], inFields[i], r[i])) {
                        LOG(ERROR) << "querySupportedValues -- "
                                      "invalid returned value.";
                        status = C2_CORRUPTED;
                        return;
                    }
                }
            });
    if (!transStatus.isOk()) {
        LOG(ERROR) << "querySupportedValues -- transaction failed.";
        return C2_TRANSACTION_FAILED;
    }
    return status;
}

// Codec2ConfigurableClient::AidlImpl

struct Codec2ConfigurableClient::AidlImpl : public Codec2ConfigurableClient::ImplBase {
    typedef c2_aidl::IConfigurable Base;

    // base cannot be null.
    explicit AidlImpl(const std::shared_ptr<Base>& base);

    const C2String& getName() const override {
        return mName;
    }

    c2_status_t query(
            const std::vector<C2Param*>& stackParams,
            const std::vector<C2Param::Index> &heapParamIndices,
            c2_blocking_t mayBlock,
            std::vector<std::unique_ptr<C2Param>>* const heapParams) const override;

    c2_status_t config(
            const std::vector<C2Param*> &params,
            c2_blocking_t mayBlock,
            std::vector<std::unique_ptr<C2SettingResult>>* const failures) override;

    c2_status_t querySupportedParams(
            std::vector<std::shared_ptr<C2ParamDescriptor>>* const params
            ) const override;

    c2_status_t querySupportedValues(
            std::vector<C2FieldSupportedValuesQuery>& fields,
            c2_blocking_t mayBlock) const override;

private:
    std::shared_ptr<Base> mBase;
    const C2String mName;
};

Codec2ConfigurableClient::AidlImpl::AidlImpl(const std::shared_ptr<Base>& base)
      : mBase{base},
        mName{[base]() -> C2String {
                std::string outName;
                ndk::ScopedAStatus status = base->getName(&outName);
                return status.isOk() ? outName : "";
            }()} {
}

c2_status_t Codec2ConfigurableClient::AidlImpl::query(
        const std::vector<C2Param*> &stackParams,
        const std::vector<C2Param::Index> &heapParamIndices,
        c2_blocking_t mayBlock,
        std::vector<std::unique_ptr<C2Param>>* const heapParams) const {
    std::vector<int> indices(
            stackParams.size() + heapParamIndices.size());
    size_t numIndices = 0;
    for (C2Param* const& stackParam : stackParams) {
        if (!stackParam) {
            LOG(WARNING) << "query -- null stack param encountered.";
            continue;
        }
        indices[numIndices++] = int(stackParam->index());
    }
    size_t numStackIndices = numIndices;
    for (const C2Param::Index& index : heapParamIndices) {
        indices[numIndices++] = int(static_cast<uint32_t>(index));
    }
    indices.resize(numIndices);
    if (heapParams) {
        heapParams->reserve(heapParams->size() + numIndices);
    }
    c2_aidl::IConfigurable::QueryResult result;
    ndk::ScopedAStatus transStatus = mBase->query(indices, (mayBlock == C2_MAY_BLOCK), &result);
    c2_status_t status = GetC2Status(transStatus, "query");
    if (status != C2_OK) {
        return status;
    }
    status = static_cast<c2_status_t>(result.status.status);

    std::vector<C2Param*> paramPointers;
    if (!c2_aidl::utils::ParseParamsBlob(&paramPointers, result.params)) {
        LOG(ERROR) << "query -- error while parsing params.";
        return C2_CORRUPTED;
    }
    size_t i = 0;
    size_t numQueried = 0;
    for (auto it = paramPointers.begin(); it != paramPointers.end(); ) {
        C2Param* paramPointer = *it;
        if (numStackIndices > 0) {
            --numStackIndices;
            if (!paramPointer) {
                LOG(DEBUG) << "query -- null stack param.";
                ++it;
                continue;
            }
            for (; i < stackParams.size() && !stackParams[i]; ) {
                ++i;
            }
            if (i >= stackParams.size()) {
                LOG(ERROR) << "query -- unexpected error.";
                status = C2_CORRUPTED;
                break;
            }
            if (stackParams[i]->index() != paramPointer->index()) {
                LOG(DEBUG) << "query -- param skipped: "
                              "index = "
                           << stackParams[i]->index() << ".";
                stackParams[i++]->invalidate();
                // this means that the param could not be queried.
                // signalling C2_BAD_INDEX to the client.
                status = C2_BAD_INDEX;
                continue;
            }
            if (stackParams[i++]->updateFrom(*paramPointer)) {
                ++numQueried;
            } else {
                LOG(WARNING) << "query -- param update failed: "
                                "index = "
                             << paramPointer->index() << ".";
            }
        } else {
            if (!paramPointer) {
                LOG(DEBUG) << "query -- null heap param.";
                ++it;
                continue;
            }
            if (!heapParams) {
                LOG(WARNING) << "query -- "
                                "unexpected extra stack param.";
            } else {
                heapParams->emplace_back(C2Param::Copy(*paramPointer));
                ++numQueried;
            }
        }
        ++it;
    }
    if (status == C2_OK && indices.size() != numQueried) {
        status = C2_BAD_INDEX;
    }
    return status;
}

c2_status_t Codec2ConfigurableClient::AidlImpl::config(
        const std::vector<C2Param*> &params,
        c2_blocking_t mayBlock,
        std::vector<std::unique_ptr<C2SettingResult>>* const failures) {
    c2_aidl::Params aidlParams;
    if (!c2_aidl::utils::CreateParamsBlob(&aidlParams, params)) {
        LOG(ERROR) << "config -- bad input.";
        return C2_TRANSACTION_FAILED;
    }
    c2_aidl::IConfigurable::ConfigResult result;
    ndk::ScopedAStatus transStatus = mBase->config(aidlParams, (mayBlock == C2_MAY_BLOCK), &result);
    c2_status_t status = GetC2Status(transStatus, "config");
    if (status != C2_OK) {
        return status;
    }
    status = static_cast<c2_status_t>(result.status.status);
    size_t i = failures->size();
    failures->resize(i + result.failures.size());
    for (const c2_aidl::SettingResult& sf : result.failures) {
        if (!c2_aidl::utils::FromAidl(&(*failures)[i++], sf)) {
            LOG(ERROR) << "config -- invalid SettingResult returned.";
            return C2_CORRUPTED;
        }
    }
    if (!c2_aidl::utils::UpdateParamsFromBlob(params, result.params)) {
        LOG(ERROR) << "config -- "
                   << "failed to parse returned params.";
        status = C2_CORRUPTED;
    }
    return status;
}

c2_status_t Codec2ConfigurableClient::AidlImpl::querySupportedParams(
        std::vector<std::shared_ptr<C2ParamDescriptor>>* const params) const {
    // TODO: Cache and query properly!
    std::vector<c2_aidl::ParamDescriptor> result;
    ndk::ScopedAStatus transStatus = mBase->querySupportedParams(
            std::numeric_limits<uint32_t>::min(),
            std::numeric_limits<uint32_t>::max(),
            &result);
    c2_status_t status = GetC2Status(transStatus, "querySupportedParams");
    if (status != C2_OK) {
        return status;
    }
    size_t i = params->size();
    params->resize(i + result.size());
    for (const c2_aidl::ParamDescriptor& sp : result) {
        if (!c2_aidl::utils::FromAidl(&(*params)[i++], sp)) {
            LOG(ERROR) << "querySupportedParams -- invalid returned ParamDescriptor.";
            return C2_CORRUPTED;
        }
    }
    return status;
}

c2_status_t Codec2ConfigurableClient::AidlImpl::querySupportedValues(
        std::vector<C2FieldSupportedValuesQuery>& fields,
        c2_blocking_t mayBlock) const {
    std::vector<c2_aidl::FieldSupportedValuesQuery> inFields(fields.size());
    for (size_t i = 0; i < fields.size(); ++i) {
        if (!c2_aidl::utils::ToAidl(&inFields[i], fields[i])) {
            LOG(ERROR) << "querySupportedValues -- bad input";
            return C2_TRANSACTION_FAILED;
        }
    }

    c2_aidl::IConfigurable::QuerySupportedValuesResult result;

    ndk::ScopedAStatus transStatus = mBase->querySupportedValues(
            inFields, (mayBlock == C2_MAY_BLOCK), &result);
    c2_status_t status = GetC2Status(transStatus, "querySupportedValues");
    if (status != C2_OK) {
        return status;
    }
    status = static_cast<c2_status_t>(result.status.status);
    if (result.values.size() != fields.size()) {
        LOG(ERROR) << "querySupportedValues -- "
                      "input and output lists "
                      "have different sizes.";
        return C2_CORRUPTED;
    }
    for (size_t i = 0; i < fields.size(); ++i) {
        if (!c2_aidl::utils::FromAidl(&fields[i], inFields[i], result.values[i])) {
            LOG(ERROR) << "querySupportedValues -- "
                          "invalid returned value.";
            return C2_CORRUPTED;
        }
    }
    return status;
}

// Codec2ConfigurableClient

Codec2ConfigurableClient::Codec2ConfigurableClient(const sp<HidlBase> &hidlBase)
    : mImpl(new Codec2ConfigurableClient::HidlImpl(hidlBase)) {
}

Codec2ConfigurableClient::Codec2ConfigurableClient(
        const std::shared_ptr<AidlBase> &aidlBase)
    : mImpl(new Codec2ConfigurableClient::AidlImpl(aidlBase)) {
}

const C2String& Codec2ConfigurableClient::getName() const {
    return mImpl->getName();
}

c2_status_t Codec2ConfigurableClient::query(
        const std::vector<C2Param*>& stackParams,
        const std::vector<C2Param::Index> &heapParamIndices,
        c2_blocking_t mayBlock,
        std::vector<std::unique_ptr<C2Param>>* const heapParams) const {
    return mImpl->query(stackParams, heapParamIndices, mayBlock, heapParams);
}

c2_status_t Codec2ConfigurableClient::config(
        const std::vector<C2Param*> &params,
        c2_blocking_t mayBlock,
        std::vector<std::unique_ptr<C2SettingResult>>* const failures) {
    return mImpl->config(params, mayBlock, failures);
}

c2_status_t Codec2ConfigurableClient::querySupportedParams(
        std::vector<std::shared_ptr<C2ParamDescriptor>>* const params) const {
    return mImpl->querySupportedParams(params);
}

c2_status_t Codec2ConfigurableClient::querySupportedValues(
        std::vector<C2FieldSupportedValuesQuery>& fields,
        c2_blocking_t mayBlock) const {
    return mImpl->querySupportedValues(fields, mayBlock);
}


// Codec2Client::Component::HidlListener
struct Codec2Client::Component::HidlListener : public c2_hidl::IComponentListener {
    std::weak_ptr<Component> component;
    std::weak_ptr<Listener> base;

    virtual Return<void> onWorkDone(const c2_hidl::WorkBundle& workBundle) override {
        std::list<std::unique_ptr<C2Work>> workItems;
        if (!c2_hidl::utils::objcpy(&workItems, workBundle)) {
            LOG(DEBUG) << "onWorkDone -- received corrupted WorkBundle.";
            return Void();
        }
        // release input buffers potentially held by the component from queue
        std::shared_ptr<Codec2Client::Component> strongComponent =
                component.lock();
        if (strongComponent) {
            strongComponent->handleOnWorkDone(workItems);
        }
        if (std::shared_ptr<Codec2Client::Listener> listener = base.lock()) {
            listener->onWorkDone(component, workItems);
        } else {
            LOG(DEBUG) << "onWorkDone -- listener died.";
        }
        return Void();
    }

    virtual Return<void> onTripped(
            const hidl_vec<c2_hidl::SettingResult>& settingResults) override {
        std::vector<std::shared_ptr<C2SettingResult>> c2SettingResults(
                settingResults.size());
        for (size_t i = 0; i < settingResults.size(); ++i) {
            std::unique_ptr<C2SettingResult> c2SettingResult;
            if (!c2_hidl::utils::objcpy(&c2SettingResult, settingResults[i])) {
                LOG(DEBUG) << "onTripped -- received corrupted SettingResult.";
                return Void();
            }
            c2SettingResults[i] = std::move(c2SettingResult);
        }
        if (std::shared_ptr<Codec2Client::Listener> listener = base.lock()) {
            listener->onTripped(component, c2SettingResults);
        } else {
            LOG(DEBUG) << "onTripped -- listener died.";
        }
        return Void();
    }

    virtual Return<void> onError(c2_hidl::Status s, uint32_t errorCode) override {
        LOG(DEBUG) << "onError --"
                   << " status = " << s
                   << ", errorCode = " << errorCode
                   << ".";
        if (std::shared_ptr<Listener> listener = base.lock()) {
            listener->onError(component, s == c2_hidl::Status::OK ?
                    errorCode : static_cast<c2_status_t>(s));
        } else {
            LOG(DEBUG) << "onError -- listener died.";
        }
        return Void();
    }

    virtual Return<void> onFramesRendered(
            const hidl_vec<RenderedFrame>& renderedFrames) override {
        std::shared_ptr<Listener> listener = base.lock();
        if (!listener) {
            LOG(DEBUG) << "onFramesRendered -- listener died.";
            return Void();
        }
        for (const RenderedFrame& renderedFrame : renderedFrames) {
            listener->onFrameRendered(
                    renderedFrame.bufferQueueId,
                    renderedFrame.slotId,
                    renderedFrame.timestampNs);
        }
        return Void();
    }

    virtual Return<void> onInputBuffersReleased(
            const hidl_vec<InputBuffer>& inputBuffers) override {
        std::shared_ptr<Listener> listener = base.lock();
        if (!listener) {
            LOG(DEBUG) << "onInputBuffersReleased -- listener died.";
            return Void();
        }
        for (const InputBuffer& inputBuffer : inputBuffers) {
            LOG(VERBOSE) << "onInputBuffersReleased --"
                            " received death notification of"
                            " input buffer:"
                            " frameIndex = " << inputBuffer.frameIndex
                         << ", bufferIndex = " << inputBuffer.arrayIndex
                         << ".";
            listener->onInputBufferDone(
                    inputBuffer.frameIndex, inputBuffer.arrayIndex);
        }
        return Void();
    }

};

// Codec2Client::Component::AidlListener
struct Codec2Client::Component::AidlListener : public c2_aidl::BnComponentListener {
    std::weak_ptr<Component> component;
    std::weak_ptr<Listener> base;

    virtual ::ndk::ScopedAStatus onWorkDone(const c2_aidl::WorkBundle& workBundle) override {
        std::list<std::unique_ptr<C2Work>> workItems;
        if (!c2_aidl::utils::FromAidl(&workItems, workBundle)) {
            LOG(DEBUG) << "onWorkDone -- received corrupted WorkBundle.";
            return ::ndk::ScopedAStatus::ok();
        }
        // release input buffers potentially held by the component from queue
        std::shared_ptr<Codec2Client::Component> strongComponent =
                component.lock();
        if (strongComponent) {
            strongComponent->handleOnWorkDone(workItems);
        }
        if (std::shared_ptr<Codec2Client::Listener> listener = base.lock()) {
            listener->onWorkDone(component, workItems);
        } else {
            LOG(DEBUG) << "onWorkDone -- listener died.";
        }
        return ::ndk::ScopedAStatus::ok();
    }

    virtual ::ndk::ScopedAStatus onTripped(
            const std::vector<c2_aidl::SettingResult>& settingResults) override {
        std::vector<std::shared_ptr<C2SettingResult>> c2SettingResults(
                settingResults.size());
        for (size_t i = 0; i < settingResults.size(); ++i) {
            std::unique_ptr<C2SettingResult> c2SettingResult;
            if (!c2_aidl::utils::FromAidl(&c2SettingResult, settingResults[i])) {
                LOG(DEBUG) << "onTripped -- received corrupted SettingResult.";
                return ::ndk::ScopedAStatus::ok();
            }
            c2SettingResults[i] = std::move(c2SettingResult);
        }
        if (std::shared_ptr<Codec2Client::Listener> listener = base.lock()) {
            listener->onTripped(component, c2SettingResults);
        } else {
            LOG(DEBUG) << "onTripped -- listener died.";
        }
        return ::ndk::ScopedAStatus::ok();
    }

    virtual ::ndk::ScopedAStatus onError(const c2_aidl::Status &s, int32_t errorCode) override {
        LOG(DEBUG) << "onError --"
                   << " status = " << s.status
                   << ", errorCode = " << errorCode
                   << ".";
        if (std::shared_ptr<Listener> listener = base.lock()) {
            listener->onError(component, s.status == c2_aidl::Status::OK ?
                    errorCode : static_cast<c2_status_t>(s.status));
        } else {
            LOG(DEBUG) << "onError -- listener died.";
        }
        return ::ndk::ScopedAStatus::ok();
    }

    virtual ::ndk::ScopedAStatus onFramesRendered(
            const std::vector<RenderedFrame>& renderedFrames) override {
        std::shared_ptr<Listener> listener = base.lock();
        if (!listener) {
            LOG(DEBUG) << "onFramesRendered -- listener died.";
            return ::ndk::ScopedAStatus::ok();
        }
        for (const RenderedFrame& renderedFrame : renderedFrames) {
            listener->onFrameRendered(
                    renderedFrame.bufferQueueId,
                    renderedFrame.slotId,
                    renderedFrame.timestampNs);
        }
        return ::ndk::ScopedAStatus::ok();
    }

    virtual ::ndk::ScopedAStatus onInputBuffersReleased(
            const std::vector<InputBuffer>& inputBuffers) override {
        std::shared_ptr<Listener> listener = base.lock();
        if (!listener) {
            LOG(DEBUG) << "onInputBuffersReleased -- listener died.";
            return ::ndk::ScopedAStatus::ok();
        }
        for (const InputBuffer& inputBuffer : inputBuffers) {
            LOG(VERBOSE) << "onInputBuffersReleased --"
                            " received death notification of"
                            " input buffer:"
                            " frameIndex = " << inputBuffer.frameIndex
                         << ", bufferIndex = " << inputBuffer.arrayIndex
                         << ".";
            listener->onInputBufferDone(
                    inputBuffer.frameIndex, inputBuffer.arrayIndex);
        }
        return ::ndk::ScopedAStatus::ok();
    }

};

// Codec2Client::Component::HidlBufferPoolSender
struct Codec2Client::Component::HidlBufferPoolSender :
        hardware::media::c2::V1_1::utils::DefaultBufferPoolSender {
    HidlBufferPoolSender()
          : hardware::media::c2::V1_1::utils::DefaultBufferPoolSender() {
    }
};

// Codec2Client::Component::AidlBufferPoolSender
struct Codec2Client::Component::AidlBufferPoolSender :
        c2_aidl::utils::DefaultBufferPoolSender {
    AidlBufferPoolSender()
          : c2_aidl::utils::DefaultBufferPoolSender() {
    }
};

// Codec2Client::Component::OutputBufferQueue
struct Codec2Client::Component::OutputBufferQueue :
        hardware::media::c2::OutputBufferQueue {
    OutputBufferQueue()
          : hardware::media::c2::OutputBufferQueue() {
    }
};

// The class holds GraphicBufferAllocator and the associated id of
// HAL side BlockPool.
// This is tightly coupled with BlockPool creation and destruction.
// The life cycle inside class will be as follows.
//
// On createBlockPool client request.
//    1. this::create() creates a GraphicBufferAllocator and set it as
//        the current.
//    2. C2AIDL_HAL::createBlockPool() creates a C2BlockPool using
//        the GraphicBufferAllocator created in #1.
//    3. this::setCurrentId() associates the id returned in #2 to the current
//
// On destroyBlockPool cliet request
//    1. C2AIDL_HAL::destroyBlockPool() destroys the block pool
//       from HAL process.
//    2. this::remove() destroys GraphicBufferAllocator which is associatted
//       with the C2BlockPool in #1.
//
struct Codec2Client::Component::GraphicBufferAllocators {
private:
    std::optional<C2BlockPool::local_id_t> mCurrentId;
    std::shared_ptr<AidlGraphicBufferAllocator> mCurrent;

    // A new BlockPool is created before the old BlockPool is destroyed.
    // This holds the reference of the old BlockPool when a new BlockPool is
    // created until the old BlockPool is explicitly requested for destruction.
    std::map<C2BlockPool::local_id_t, std::shared_ptr<AidlGraphicBufferAllocator>> mOlds;
    std::mutex mMutex;

public:
    // Creates a GraphicBufferAllocator which will be passed to HAL
    // for creating C2BlockPool. And the created GraphicBufferAllocator
    // will be used afterwards by current().
    std::shared_ptr<AidlGraphicBufferAllocator> create() {
        std::unique_lock<std::mutex> l(mMutex);
        if (mCurrent) {
            // If this is not stopped.
            mCurrent->reset();
            if (mCurrentId.has_value()) {
                mOlds.emplace(mCurrentId.value(), mCurrent);
            }
            mCurrentId.reset();
            mCurrent.reset();
        }
        // TODO: integrate initial value with CCodec/CCodecBufferChannel
        mCurrent =
                AidlGraphicBufferAllocator::CreateGraphicBufferAllocator(3 /* maxDequeueCount */);
        ALOGD("GraphicBufferAllocator created");
        return mCurrent;
    }

    // Associates the blockpool Id returned from HAL to the
    // current GraphicBufferAllocator.
    void setCurrentId(C2BlockPool::local_id_t id) {
        std::unique_lock<std::mutex> l(mMutex);
        CHECK(!mCurrentId.has_value());
        mCurrentId = id;
    }

    // Returns the current GraphicBufferAllocator.
    std::shared_ptr<AidlGraphicBufferAllocator> current() {
        std::unique_lock<std::mutex> l(mMutex);
        return mCurrent;
    }

    // Removes the GraphicBufferAllocator associated with given \p id.
    void remove(C2BlockPool::local_id_t id) {
        std::unique_lock<std::mutex> l(mMutex);
        mOlds.erase(id);
        if (mCurrentId == id) {
            if (mCurrent) {
                mCurrent->reset();
                mCurrent.reset();
            }
            mCurrentId.reset();
        }
    }
};

// Codec2Client
Codec2Client::Codec2Client(sp<HidlBase> const& base,
                           sp<c2_hidl::IConfigurable> const& configurable,
                           size_t serviceIndex)
      : Configurable{configurable},
        mHidlBase1_0{base},
        mHidlBase1_1{HidlBase1_1::castFrom(base)},
        mHidlBase1_2{HidlBase1_2::castFrom(base)},
        mServiceIndex{serviceIndex} {
    Return<sp<bufferpool_hidl::IClientManager>> transResult = base->getPoolClientManager();
    if (!transResult.isOk()) {
        LOG(ERROR) << "getPoolClientManager -- transaction failed.";
    } else {
        mHidlHostPoolManager = static_cast<sp<bufferpool_hidl::IClientManager>>(transResult);
    }
}

Codec2Client::Codec2Client(std::shared_ptr<AidlBase> const& base,
                           std::shared_ptr<c2_aidl::IConfigurable> const& configurable,
                           size_t serviceIndex)
      : Configurable{configurable},
        mAidlBase{base},
        mServiceIndex{serviceIndex} {
    ::ndk::ScopedAStatus transStatus = base->getPoolClientManager(&mAidlHostPoolManager);
    if (!transStatus.isOk()) {
        LOG(ERROR) << "getPoolClientManager -- transaction failed.";
        mAidlHostPoolManager.reset();
    }
}

sp<Codec2Client::HidlBase> const& Codec2Client::getHidlBase() const {
    return mHidlBase1_0;
}

sp<Codec2Client::HidlBase1_0> const& Codec2Client::getHidlBase1_0() const {
    return mHidlBase1_0;
}

sp<Codec2Client::HidlBase1_1> const& Codec2Client::getHidlBase1_1() const {
    return mHidlBase1_1;
}

sp<Codec2Client::HidlBase1_2> const& Codec2Client::getHidlBase1_2() const {
    return mHidlBase1_2;
}

::ndk::SpAIBinder Codec2Client::getAidlBase() const {
    return mAidlBase ? mAidlBase->asBinder() : nullptr;
}

std::string const& Codec2Client::getServiceName() const {
    return GetServiceNames()[mServiceIndex];
}

c2_status_t Codec2Client::createComponent(
        const C2String& name,
        const std::shared_ptr<Codec2Client::Listener>& listener,
        std::shared_ptr<Codec2Client::Component>* const component) {
    if (mAidlBase) {
        std::shared_ptr<Component::AidlListener> aidlListener =
                Component::AidlListener::make<Component::AidlListener>();
        aidlListener->base = listener;
        std::shared_ptr<c2_aidl::IComponent> aidlComponent;
        ::ndk::ScopedAStatus transStatus = mAidlBase->createComponent(
                name,
                aidlListener,
                bufferpool2_aidl::implementation::ClientManager::getInstance(),
                &aidlComponent);
        c2_status_t status = GetC2Status(transStatus, "createComponent");
        if (status != C2_OK) {
            return status;
        } else if (!aidlComponent) {
            LOG(ERROR) << "createComponent(" << name.c_str()
                       << ") -- null component.";
            return C2_CORRUPTED;
        }
        *component = std::make_shared<Codec2Client::Component>(aidlComponent);
        status = (*component)->setDeathListener((*component), listener);
        if (status != C2_OK) {
            LOG(ERROR) << "createComponent(" << name.c_str()
                       << ") -- failed to set up death listener: "
                       << status << ".";
        }
        (*component)->mAidlBufferPoolSender->setReceiver(mAidlHostPoolManager);
        aidlListener->component = *component;
        return status;
    }

    c2_status_t status;
    sp<Component::HidlListener> hidlListener = new Component::HidlListener{};
    hidlListener->base = listener;
    Return<void> transStatus;
    if (mHidlBase1_2) {
        transStatus = mHidlBase1_2->createComponent_1_2(
            name,
            hidlListener,
            bufferpool_hidl::implementation::ClientManager::getInstance(),
            [&status, component, hidlListener](
                    c2_hidl::Status s,
                    const sp<c2_hidl::IComponent>& c) {
                status = static_cast<c2_status_t>(s);
                if (status != C2_OK) {
                    return;
                }
                *component = std::make_shared<Codec2Client::Component>(c);
                hidlListener->component = *component;
            });
    }
    else if (mHidlBase1_1) {
        transStatus = mHidlBase1_1->createComponent_1_1(
            name,
            hidlListener,
            bufferpool_hidl::implementation::ClientManager::getInstance(),
            [&status, component, hidlListener](
                    c2_hidl::Status s,
                    const sp<c2_hidl_base::V1_1::IComponent>& c) {
                status = static_cast<c2_status_t>(s);
                if (status != C2_OK) {
                    return;
                }
                *component = std::make_shared<Codec2Client::Component>(c);
                hidlListener->component = *component;
            });
    } else if (mHidlBase1_0) { // ver1_0
        transStatus = mHidlBase1_0->createComponent(
            name,
            hidlListener,
            bufferpool_hidl::implementation::ClientManager::getInstance(),
            [&status, component, hidlListener](
                    c2_hidl::Status s,
                    const sp<c2_hidl_base::V1_0::IComponent>& c) {
                status = static_cast<c2_status_t>(s);
                if (status != C2_OK) {
                    return;
                }
                *component = std::make_shared<Codec2Client::Component>(c);
                hidlListener->component = *component;
            });
    } else {
        status = C2_CORRUPTED;
    }
    if (!transStatus.isOk()) {
        LOG(ERROR) << "createComponent(" << name.c_str()
                   << ") -- transaction failed.";
        return C2_TRANSACTION_FAILED;
    } else if (status != C2_OK) {
        if (status == C2_NOT_FOUND) {
            LOG(VERBOSE) << "createComponent(" << name.c_str()
                         << ") -- component not found.";
        } else {
            LOG(ERROR) << "createComponent(" << name.c_str()
                       << ") -- call failed: " << status << ".";
        }
        return status;
    } else if (!*component) {
        LOG(ERROR) << "createComponent(" << name.c_str()
                   << ") -- null component.";
        return C2_CORRUPTED;
    }

    status = (*component)->setDeathListener(*component, listener);
    if (status != C2_OK) {
        LOG(ERROR) << "createComponent(" << name.c_str()
                   << ") -- failed to set up death listener: "
                   << status << ".";
    }

    (*component)->mHidlBufferPoolSender->setReceiver(mHidlHostPoolManager);
    return status;
}

c2_status_t Codec2Client::createInterface(
        const C2String& name,
        std::shared_ptr<Codec2Client::Interface>* const interface) {
    if (mAidlBase) {
        std::shared_ptr<c2_aidl::IComponentInterface> aidlInterface;
        ::ndk::ScopedAStatus transStatus = mAidlBase->createInterface(
                name,
                &aidlInterface);
        c2_status_t status = GetC2Status(transStatus, "createInterface");
        if (status != C2_OK) {
            return status;
        } else if (!aidlInterface) {
            LOG(ERROR) << "createInterface(" << name.c_str()
                       << ") -- null interface.";
            return C2_CORRUPTED;
        }
        interface->reset(new Codec2Client::Interface(aidlInterface));
        return C2_OK;
    }

    c2_status_t status;
    Return<void> transStatus = mHidlBase1_0->createInterface(
            name,
            [&status, interface](
                    c2_hidl::Status s,
                    const sp<c2_hidl::IComponentInterface>& i) {
                status = static_cast<c2_status_t>(s);
                if (status != C2_OK) {
                    return;
                }
                *interface = std::make_shared<Interface>(i);
            });
    if (!transStatus.isOk()) {
        LOG(ERROR) << "createInterface(" << name.c_str()
                   << ") -- transaction failed.";
        return C2_TRANSACTION_FAILED;
    } else if (status != C2_OK) {
        if (status == C2_NOT_FOUND) {
            LOG(VERBOSE) << "createInterface(" << name.c_str()
                         << ") -- component not found.";
        } else {
            LOG(ERROR) << "createInterface(" << name.c_str()
                       << ") -- call failed: " << status << ".";
        }
        return status;
    }

    return status;
}

c2_status_t Codec2Client::createInputSurface(
        std::shared_ptr<InputSurface>* const inputSurface) {
    if (mAidlBase) {
        // FIXME
        return C2_OMITTED;
    }

    c2_status_t status;
    Return<void> transStatus = mHidlBase1_0->createInputSurface(
            [&status, inputSurface](
                    c2_hidl::Status s,
                    const sp<c2_hidl::IInputSurface>& i) {
                status = static_cast<c2_status_t>(s);
                if (status != C2_OK) {
                    return;
                }
                *inputSurface = std::make_shared<InputSurface>(i);
            });
    if (!transStatus.isOk()) {
        LOG(ERROR) << "createInputSurface -- transaction failed.";
        return C2_TRANSACTION_FAILED;
    } else if (status != C2_OK) {
        LOG(DEBUG) << "createInputSurface -- call failed: "
                   << status << ".";
    }
    return status;
}

std::vector<C2Component::Traits> const& Codec2Client::listComponents() const {
    return Cache::List()[mServiceIndex].getTraits();
}

std::vector<C2Component::Traits> Codec2Client::_listComponents(
        bool* success) const {
    std::vector<C2Component::Traits> traits;
    std::string const& serviceName = getServiceName();

    if (mAidlBase) {
        std::vector<c2_aidl::IComponentStore::ComponentTraits> aidlTraits;
        ::ndk::ScopedAStatus transStatus = mAidlBase->listComponents(&aidlTraits);
        if (!transStatus.isOk()) {
            LOG(ERROR) << "_listComponents -- transaction failed.";
            *success = false;
        } else {
            traits.resize(aidlTraits.size());
            *success = true;
            for (size_t i = 0; i < aidlTraits.size(); ++i) {
                if (!c2_aidl::utils::FromAidl(&traits[i], aidlTraits[i])) {
                    LOG(ERROR) << "_listComponents -- corrupted output.";
                    *success = false;
                    traits.clear();
                    break;
                }
                traits[i].owner = serviceName;
            }
        }
        return traits;
    }
    Return<void> transStatus = mHidlBase1_0->listComponents(
            [&traits, &serviceName](c2_hidl::Status s,
                   const hidl_vec<c2_hidl::IComponentStore::ComponentTraits>& t) {
                if (s != c2_hidl::Status::OK) {
                    LOG(DEBUG) << "_listComponents -- call failed: "
                               << static_cast<c2_status_t>(s) << ".";
                    return;
                }
                traits.resize(t.size());
                for (size_t i = 0; i < t.size(); ++i) {
                    if (!c2_hidl::utils::objcpy(&traits[i], t[i])) {
                        LOG(ERROR) << "_listComponents -- corrupted output.";
                        return;
                    }
                    traits[i].owner = serviceName;
                }
            });
    if (!transStatus.isOk()) {
        LOG(ERROR) << "_listComponents -- transaction failed.";
        *success = false;
    } else {
        *success = true;
    }
    return traits;
}

c2_status_t Codec2Client::copyBuffer(
        const std::shared_ptr<C2Buffer>& src,
        const std::shared_ptr<C2Buffer>& dst) {
    // TODO: Implement?
    (void)src;
    (void)dst;
    LOG(ERROR) << "copyBuffer not implemented";
    return C2_OMITTED;
}

std::shared_ptr<C2ParamReflector> Codec2Client::getParamReflector() {
    // TODO: this is not meant to be exposed as C2ParamReflector on the client side; instead, it
    // should reflect the HAL API.
    struct HidlSimpleParamReflector : public C2ParamReflector {
        std::unique_ptr<C2StructDescriptor> describe(
                C2Param::CoreIndex coreIndex) const override {
            hidl_vec<c2_hidl::ParamIndex> indices(1);
            indices[0] = static_cast<c2_hidl::ParamIndex>(coreIndex.coreIndex());
            std::unique_ptr<C2StructDescriptor> descriptor;
            Return<void> transStatus = mBase->getStructDescriptors(
                    indices,
                    [&descriptor](
                            c2_hidl::Status s,
                            const hidl_vec<c2_hidl::StructDescriptor>& sd) {
                        c2_status_t status = static_cast<c2_status_t>(s);
                        if (status != C2_OK) {
                            LOG(DEBUG) << "SimpleParamReflector -- "
                                          "getStructDescriptors() failed: "
                                       << status << ".";
                            descriptor.reset();
                            return;
                        }
                        if (sd.size() != 1) {
                            LOG(DEBUG) << "SimpleParamReflector -- "
                                          "getStructDescriptors() "
                                          "returned vector of size "
                                       << sd.size() << ". "
                                          "It should be 1.";
                            descriptor.reset();
                            return;
                        }
                        if (!c2_hidl::utils::objcpy(&descriptor, sd[0])) {
                            LOG(DEBUG) << "SimpleParamReflector -- "
                                          "getStructDescriptors() returned "
                                          "corrupted data.";
                            descriptor.reset();
                            return;
                        }
                    });
            if (!transStatus.isOk()) {
                LOG(DEBUG) << "SimpleParamReflector -- transaction failed: "
                           << transStatus.description();
                descriptor.reset();
            }
            return descriptor;
        }

        HidlSimpleParamReflector(sp<HidlBase> base)
            : mBase(base) { }

        sp<HidlBase> mBase;
    };
    struct AidlSimpleParamReflector : public C2ParamReflector {
        std::unique_ptr<C2StructDescriptor> describe(
                C2Param::CoreIndex coreIndex) const override {
            std::vector<c2_aidl::StructDescriptor> aidlDesc;
            std::unique_ptr<C2StructDescriptor> descriptor;
            ::ndk::ScopedAStatus transStatus = mBase->getStructDescriptors(
                    {int32_t(coreIndex.coreIndex())},
                    &aidlDesc);
            c2_status_t status = GetC2Status(transStatus, "describe");
            if (status != C2_OK) {
                descriptor.reset();
            } else if (!c2_aidl::utils::FromAidl(&descriptor, aidlDesc[0])) {
                LOG(ERROR) << "describe -- conversion failed.";
                descriptor.reset();
            }
            return descriptor;
        }

        AidlSimpleParamReflector(const std::shared_ptr<AidlBase> &base)
            : mBase(base) { }

        std::shared_ptr<AidlBase> mBase;
    };

    if (mAidlBase) {
        return std::make_shared<AidlSimpleParamReflector>(mAidlBase);
    }
    return std::make_shared<HidlSimpleParamReflector>(mHidlBase1_0);
};

std::vector<std::string> Codec2Client::CacheServiceNames() {
    std::vector<std::string> names;

    if (c2_aidl::utils::IsSelected()) {
        if (__builtin_available(android __ANDROID_API_S__, *)) {
            // Get AIDL service names
            AServiceManager_forEachDeclaredInstance(
                    AidlBase::descriptor, &names, [](const char *name, void *context) {
                        std::vector<std::string> *names = (std::vector<std::string> *)context;
                        names->emplace_back(name);
                    });
        } else {
            LOG(FATAL) << "C2 AIDL cannot be selected on Android version older than 35";
        }
    } else {
        // Get HIDL service names
        using ::android::hardware::media::c2::V1_0::IComponentStore;
        using ::android::hidl::manager::V1_2::IServiceManager;
        while (true) {
            sp<IServiceManager> serviceManager = IServiceManager::getService();
            CHECK(serviceManager) << "Hardware service manager is not running.";

            Return<void> transResult;
            transResult = serviceManager->listManifestByInterface(
                    IComponentStore::descriptor,
                    [&names](
                            hidl_vec<hidl_string> const& instanceNames) {
                        names.insert(names.end(), instanceNames.begin(), instanceNames.end());
                    });
            if (transResult.isOk()) {
                break;
            }
            LOG(ERROR) << "Could not retrieve the list of service instances of "
                       << IComponentStore::descriptor
                       << ". Retrying...";
        }
    }
    // Sort service names in each category.
    std::stable_sort(
        names.begin(), names.end(),
        [](const std::string &a, const std::string &b) {
            // First compare by prefix: default -> vendor -> {everything else}
            constexpr int DEFAULT = 1;
            constexpr int VENDOR = 2;
            constexpr int OTHER = 3;
            int aPrefix = ((a.compare(0, 7, "default") == 0) ? DEFAULT :
                           (a.compare(0, 6, "vendor") == 0) ? VENDOR :
                           OTHER);
            int bPrefix = ((b.compare(0, 7, "default") == 0) ? DEFAULT :
                           (b.compare(0, 6, "vendor") == 0) ? VENDOR :
                           OTHER);
            if (aPrefix != bPrefix) {
                return aPrefix < bPrefix;
            }
            // If the prefix is the same, compare alphabetically
            return a < b;
        });

    // Summarize to logcat.
    if (names.empty()) {
        LOG(INFO) << "No Codec2 services declared in the manifest.";
    } else {
        std::stringstream stringOutput;
        stringOutput << "Available Codec2 services:";
        for (std::string const& name : names) {
            stringOutput << " \"" << name << "\"";
        }
        LOG(INFO) << stringOutput.str();
    }

    return names;
}

std::vector<std::string> const& Codec2Client::GetServiceNames() {
    static std::vector<std::string> sServiceNames = CacheServiceNames();
    return sServiceNames;
}

std::shared_ptr<Codec2Client> Codec2Client::CreateFromService(
        const char* name,
        bool setAsPreferredCodec2ComponentStore) {
    size_t index = getServiceIndex(name);
    if (index == GetServiceNames().size()) {
        if (setAsPreferredCodec2ComponentStore) {
            LOG(WARNING) << "CreateFromService(" << name
                         << ") -- preferred C2ComponentStore not set.";
        }
        return nullptr;
    }
    std::shared_ptr<Codec2Client> client = _CreateFromIndex(index);
    if (setAsPreferredCodec2ComponentStore) {
        SetPreferredCodec2ComponentStore(
                std::make_shared<Client2Store>(client));
        LOG(INFO) << "CreateFromService(" << name
                  << ") -- service set as preferred C2ComponentStore.";
    }
    return client;
}

std::vector<std::shared_ptr<Codec2Client>> Codec2Client::
        CreateFromAllServices() {
    std::vector<std::shared_ptr<Codec2Client>> clients(
            GetServiceNames().size());
    for (size_t i = GetServiceNames().size(); i > 0; ) {
        --i;
        clients[i] = _CreateFromIndex(i);
    }
    return clients;
}

std::shared_ptr<Codec2Client> Codec2Client::_CreateFromIndex(size_t index) {
    std::string const& name = GetServiceNames()[index];
    LOG(VERBOSE) << "Creating a Codec2 client to service \"" << name << "\"";

    if (c2_aidl::utils::IsSelected()) {
        if (__builtin_available(android __ANDROID_API_S__, *)) {
            std::string instanceName =
                ::android::base::StringPrintf("%s/%s", AidlBase::descriptor, name.c_str());
            if (AServiceManager_isDeclared(instanceName.c_str())) {
                std::shared_ptr<AidlBase> baseStore = AidlBase::fromBinder(
                        ::ndk::SpAIBinder(AServiceManager_waitForService(instanceName.c_str())));
                CHECK(baseStore) << "Codec2 AIDL service \"" << name << "\""
                                    " inaccessible for unknown reasons.";
                LOG(VERBOSE) << "Client to Codec2 AIDL service \"" << name << "\" created";
                std::shared_ptr<c2_aidl::IConfigurable> configurable;
                ::ndk::ScopedAStatus transStatus = baseStore->getConfigurable(&configurable);
                CHECK(transStatus.isOk()) << "Codec2 AIDL service \"" << name << "\""
                                            "does not have IConfigurable.";
                return std::make_shared<Codec2Client>(baseStore, configurable, index);
            } else {
                LOG(ERROR) << "Codec2 AIDL service \"" << name << "\" is not declared";
            }
        } else {
            LOG(FATAL) << "C2 AIDL cannot be selected on Android version older than 35";
        }
    } else {
        std::string instanceName = "android.hardware.media.c2/" + name;
        sp<HidlBase> baseStore = HidlBase::getService(name);
        CHECK(baseStore) << "Codec2 service \"" << name << "\""
                            " inaccessible for unknown reasons.";
        LOG(VERBOSE) << "Client to Codec2 service \"" << name << "\" created";
        Return<sp<c2_hidl::IConfigurable>> transResult = baseStore->getConfigurable();
        CHECK(transResult.isOk()) << "Codec2 service \"" << name << "\""
                                    "does not have IConfigurable.";
        sp<c2_hidl::IConfigurable> configurable =
            static_cast<sp<c2_hidl::IConfigurable>>(transResult);
        return std::make_shared<Codec2Client>(baseStore, configurable, index);
    }
    return nullptr;
}

c2_status_t Codec2Client::ForAllServices(
        const std::string &key,
        size_t numberOfAttempts,
        std::function<c2_status_t(const std::shared_ptr<Codec2Client>&)>
            predicate) {
    c2_status_t status = C2_NO_INIT;  // no IComponentStores present

    // Cache the mapping key -> index of Codec2Client in Cache::List().
    static std::mutex key2IndexMutex;
    static std::map<std::string, size_t> key2Index;

    // By default try all stores. However, try the last known client first. If
    // the last known client fails, retry once. We do this by pushing the last
    // known client in front of the list of all clients.
    std::deque<size_t> indices;
    for (size_t index = Cache::List().size(); index > 0; ) {
        indices.push_front(--index);
    }

    bool wasMapped = false;
    {
        std::scoped_lock lock{key2IndexMutex};
        auto it = key2Index.find(key);
        if (it != key2Index.end()) {
            indices.push_front(it->second);
            wasMapped = true;
        }
    }

    for (size_t index : indices) {
        Cache& cache = Cache::List()[index];
        for (size_t tries = numberOfAttempts; tries > 0; --tries) {
            std::shared_ptr<Codec2Client> client{cache.getClient()};
            status = predicate(client);
            if (status == C2_OK) {
                std::scoped_lock lock{key2IndexMutex};
                key2Index[key] = index; // update last known client index
                return C2_OK;
            } else if (status == C2_NO_MEMORY) {
                return C2_NO_MEMORY;
            } else if (status == C2_TRANSACTION_FAILED) {
                LOG(WARNING) << "\"" << key << "\" failed for service \""
                             << client->getName()
                             << "\" due to transaction failure. "
                             << "(Service may have crashed.)"
                             << (tries > 1 ? " Retrying..." : "");
                cache.invalidate();
                continue;
            }
            if (wasMapped) {
                LOG(INFO) << "\"" << key << "\" became invalid in service \""
                          << client->getName() << "\". Retrying...";
                wasMapped = false;
            }
            break;
        }
    }
    return status; // return the last status from a valid client
}

c2_status_t Codec2Client::CreateComponentByName(
        const char* componentName,
        const std::shared_ptr<Listener>& listener,
        std::shared_ptr<Component>* component,
        std::shared_ptr<Codec2Client>* owner,
        size_t numberOfAttempts) {
    std::string key{"create:"};
    key.append(componentName);
    c2_status_t status = ForAllServices(
            key,
            numberOfAttempts,
            [owner, component, componentName, &listener](
                    const std::shared_ptr<Codec2Client> &client)
                        -> c2_status_t {
                c2_status_t status = client->createComponent(componentName,
                                                             listener,
                                                             component);
                if (status == C2_OK) {
                    if (owner) {
                        *owner = client;
                    }
                } else if (status != C2_NOT_FOUND) {
                    LOG(DEBUG) << "IComponentStore("
                                   << client->getServiceName()
                               << ")::createComponent(\"" << componentName
                               << "\") returned status = "
                               << status << ".";
                }
                return status;
            });
    if (status != C2_OK) {
        LOG(DEBUG) << "Failed to create component \"" << componentName
                   << "\" from all known services. "
                      "Last returned status = " << status << ".";
    }
    return status;
}

std::shared_ptr<Codec2Client::Interface> Codec2Client::CreateInterfaceByName(
        const char* interfaceName,
        std::shared_ptr<Codec2Client>* owner,
        size_t numberOfAttempts) {
    std::string key{"create:"};
    key.append(interfaceName);
    std::shared_ptr<Interface> interface;
    c2_status_t status = ForAllServices(
            key,
            numberOfAttempts,
            [owner, &interface, interfaceName](
                    const std::shared_ptr<Codec2Client> &client)
                        -> c2_status_t {
                c2_status_t status = client->createInterface(interfaceName,
                                                             &interface);
                if (status == C2_OK) {
                    if (owner) {
                        *owner = client;
                    }
                } else if (status != C2_NOT_FOUND) {
                    LOG(DEBUG) << "IComponentStore("
                                   << client->getServiceName()
                               << ")::createInterface(\"" << interfaceName
                               << "\") returned status = "
                               << status << ".";
                }
                return status;
            });
    if (status != C2_OK) {
        LOG(DEBUG) << "Failed to create interface \"" << interfaceName
                   << "\" from all known services. "
                      "Last returned status = " << status << ".";
    }
    return interface;
}

std::vector<C2Component::Traits> const& Codec2Client::ListComponents() {
    static std::vector<C2Component::Traits> sList{[]() {
        std::vector<C2Component::Traits> list;
        for (Cache& cache : Cache::List()) {
            std::vector<C2Component::Traits> const& traits = cache.getTraits();
            list.insert(list.end(), traits.begin(), traits.end());
        }
        return list;
    }()};
    return sList;
}

std::shared_ptr<Codec2Client::InputSurface> Codec2Client::CreateInputSurface(
        char const* serviceName) {
    int32_t inputSurfaceSetting = ::android::base::GetIntProperty(
            "debug.stagefright.c2inputsurface", int32_t(0));
    if (inputSurfaceSetting <= 0) {
        return nullptr;
    }
    size_t index = GetServiceNames().size();
    if (serviceName) {
        index = getServiceIndex(serviceName);
        if (index == GetServiceNames().size()) {
            LOG(DEBUG) << "CreateInputSurface -- invalid service name: \""
                       << serviceName << "\"";
        }
    }

    std::shared_ptr<Codec2Client::InputSurface> inputSurface;
    if (index != GetServiceNames().size()) {
        std::shared_ptr<Codec2Client> client = Cache::List()[index].getClient();
        if (client->createInputSurface(&inputSurface) == C2_OK) {
            return inputSurface;
        }
    }
    LOG(INFO) << "CreateInputSurface -- attempting to create an input surface "
                 "from all services...";
    for (Cache& cache : Cache::List()) {
        std::shared_ptr<Codec2Client> client = cache.getClient();
        if (client->createInputSurface(&inputSurface) == C2_OK) {
            LOG(INFO) << "CreateInputSurface -- input surface obtained from "
                         "service \"" << client->getServiceName() << "\"";
            return inputSurface;
        }
    }
    LOG(WARNING) << "CreateInputSurface -- failed to create an input surface "
                    "from all services";
    return nullptr;
}

// Codec2Client::Interface
Codec2Client::Interface::Interface(const sp<HidlBase>& base)
      : Configurable{
            [base]() -> sp<c2_hidl::IConfigurable> {
                Return<sp<c2_hidl::IConfigurable>> transResult =
                        base->getConfigurable();
                return transResult.isOk() ?
                        static_cast<sp<c2_hidl::IConfigurable>>(transResult) :
                        nullptr;
            }()
        },
        mHidlBase{base} {
}

Codec2Client::Interface::Interface(const std::shared_ptr<AidlBase>& base)
      : Configurable{
            [base]() -> std::shared_ptr<c2_aidl::IConfigurable> {
                std::shared_ptr<c2_aidl::IConfigurable> aidlConfigurable;
                ::ndk::ScopedAStatus transStatus =
                    base->getConfigurable(&aidlConfigurable);
                return transStatus.isOk() ? aidlConfigurable : nullptr;
            }()
        },
        mAidlBase{base} {
}

// Codec2Client::Component

class Codec2Client::Component::AidlDeathManager {
public:
    AidlDeathManager()
        : mSeq(0),
          mDeathRecipient(AIBinder_DeathRecipient_new(OnBinderDied)) {
    }

    ~AidlDeathManager() = default;

    bool linkToDeath(
            const std::shared_ptr<Component> &comp,
            const std::shared_ptr<Listener> &listener,
            size_t *seqPtr) {
        std::unique_lock lock(mMutex);
        size_t seq = mSeq++;
        if (!mMap.try_emplace(seq, comp, listener).second) {
            return false;
        }
        if (STATUS_OK != AIBinder_linkToDeath(
                comp->mAidlBase->asBinder().get(), mDeathRecipient.get(), (void *)seq)) {
            mMap.erase(seq);
            return false;
        }
        *seqPtr = seq;
        return true;
    }

    void unlinkToDeath(size_t seq, const std::shared_ptr<AidlBase> &base) {
        std::unique_lock lock(mMutex);
        AIBinder_unlinkToDeath(base->asBinder().get(), mDeathRecipient.get(), (void *)seq);
        mMap.erase(seq);
    }

private:
    std::mutex mMutex;
    size_t mSeq;
    typedef std::tuple<std::weak_ptr<Component>, std::weak_ptr<Listener>> Context;
    std::map<size_t, Context> mMap;
    ::ndk::ScopedAIBinder_DeathRecipient mDeathRecipient;

    bool extractContext(size_t seq, Context *context) {
        std::unique_lock lock(mMutex);
        auto node = mMap.extract(seq);
        if (!node) {
            return false;
        }
        *context = node.mapped();
        return true;
    }

    static void OnBinderDied(void *cookie) {
        size_t seq = size_t(cookie);
        Context context;
        if (!Component::GetAidlDeathManager()->extractContext(seq, &context)) {
            return;
        }
        std::weak_ptr<Component> weakComponent;
        std::weak_ptr<Listener> weakListener;
        std::tie(weakComponent, weakListener) = context;
        if (std::shared_ptr<Listener> listener = weakListener.lock()) {
            listener->onDeath(weakComponent);
        } else {
            LOG(DEBUG) << "onDeath -- listener died.";
        }
    }
};

Codec2Client::Component::Component(const sp<HidlBase>& base)
      : Configurable{
            [base]() -> sp<c2_hidl::IConfigurable> {
                Return<sp<c2_hidl::IComponentInterface>> transResult1 =
                        base->getInterface();
                if (!transResult1.isOk()) {
                    return nullptr;
                }
                Return<sp<c2_hidl::IConfigurable>> transResult2 =
                        static_cast<sp<c2_hidl::IComponentInterface>>(transResult1)->
                        getConfigurable();
                return transResult2.isOk() ?
                        static_cast<sp<c2_hidl::IConfigurable>>(transResult2) :
                        nullptr;
            }()
        },
        mHidlBase1_0{base},
        mHidlBase1_1{HidlBase1_1::castFrom(base)},
        mHidlBase1_2{HidlBase1_2::castFrom(base)},
        mHidlBufferPoolSender{std::make_unique<HidlBufferPoolSender>()},
        mOutputBufferQueue{std::make_unique<OutputBufferQueue>()} {
}

Codec2Client::Component::Component(const sp<HidlBase1_1>& base)
      : Configurable{
            [base]() -> sp<c2_hidl::IConfigurable> {
                Return<sp<c2_hidl::IComponentInterface>> transResult1 =
                        base->getInterface();
                if (!transResult1.isOk()) {
                    return nullptr;
                }
                Return<sp<c2_hidl::IConfigurable>> transResult2 =
                        static_cast<sp<c2_hidl::IComponentInterface>>(transResult1)->
                        getConfigurable();
                return transResult2.isOk() ?
                        static_cast<sp<c2_hidl::IConfigurable>>(transResult2) :
                        nullptr;
            }()
        },
        mHidlBase1_0{base},
        mHidlBase1_1{base},
        mHidlBase1_2{HidlBase1_2::castFrom(base)},
        mHidlBufferPoolSender{std::make_unique<HidlBufferPoolSender>()},
        mOutputBufferQueue{std::make_unique<OutputBufferQueue>()} {
}

Codec2Client::Component::Component(const sp<HidlBase1_2>& base)
      : Configurable{
            [base]() -> sp<c2_hidl::IConfigurable> {
                Return<sp<c2_hidl::IComponentInterface>> transResult1 =
                        base->getInterface();
                if (!transResult1.isOk()) {
                    return nullptr;
                }
                Return<sp<c2_hidl::IConfigurable>> transResult2 =
                        static_cast<sp<c2_hidl::IComponentInterface>>(transResult1)->
                        getConfigurable();
                return transResult2.isOk() ?
                        static_cast<sp<c2_hidl::IConfigurable>>(transResult2) :
                        nullptr;
            }()
        },
        mHidlBase1_0{base},
        mHidlBase1_1{base},
        mHidlBase1_2{base},
        mHidlBufferPoolSender{std::make_unique<HidlBufferPoolSender>()},
        mOutputBufferQueue{std::make_unique<OutputBufferQueue>()} {
}

Codec2Client::Component::Component(const std::shared_ptr<AidlBase> &base)
      : Configurable{
            [base]() -> std::shared_ptr<c2_aidl::IConfigurable> {
                std::shared_ptr<c2_aidl::IComponentInterface> aidlIntf;
                ::ndk::ScopedAStatus transStatus = base->getInterface(&aidlIntf);
                if (!transStatus.isOk()) {
                    return nullptr;
                }
                std::shared_ptr<c2_aidl::IConfigurable> aidlConfigurable;
                transStatus = aidlIntf->getConfigurable(&aidlConfigurable);
                return transStatus.isOk() ? aidlConfigurable : nullptr;
            }()
        },
        mAidlBase{base},
        mAidlBufferPoolSender{std::make_unique<AidlBufferPoolSender>()},
        mGraphicBufferAllocators{std::make_unique<GraphicBufferAllocators>()} {
}

Codec2Client::Component::~Component() {
    if (mAidlDeathSeq) {
        GetAidlDeathManager()->unlinkToDeath(*mAidlDeathSeq, mAidlBase);
    }
}

c2_status_t Codec2Client::Component::createBlockPool(
        C2Allocator::id_t id,
        C2BlockPool::local_id_t* blockPoolId,
        std::shared_ptr<Codec2Client::Configurable>* configurable) {
    if (mAidlBase) {
        c2_aidl::IComponent::BlockPool aidlBlockPool;
        c2_status_t status = C2_OK;

        // TODO: Temporary mapping for the current CCodecBufferChannel.
        // Handle this properly and remove this temporary allocator mapping.
        id = id == C2PlatformAllocatorStore::BUFFERQUEUE ?
                C2PlatformAllocatorStore::IGBA : id;

        c2_aidl::IComponent::BlockPoolAllocator allocator;
        allocator.allocatorId = id;
        if (id == C2PlatformAllocatorStore::IGBA)  {
            std::shared_ptr<AidlGraphicBufferAllocator> gba =
                    mGraphicBufferAllocators->create();
            ::ndk::ScopedFileDescriptor waitableFd;
            ::ndk::ScopedAStatus ret = gba->getWaitableFd(&waitableFd);
            status = GetC2Status(ret, "Gba::getWaitableFd");
            if (status != C2_OK) {
                return status;
            }
            c2_aidl::IComponent::GbAllocator gbAllocator;
            gbAllocator.waitableFd = std::move(waitableFd);
            gbAllocator.igba =
                    c2_aidl::IGraphicBufferAllocator::fromBinder(gba->asBinder());
            allocator.gbAllocator = std::move(gbAllocator);
            ::ndk::ScopedAStatus transStatus = mAidlBase->createBlockPool(
                    allocator, &aidlBlockPool);
            status = GetC2Status(transStatus, "createBlockPool");
            if (status != C2_OK) {
                return status;
            }
            mGraphicBufferAllocators->setCurrentId(aidlBlockPool.blockPoolId);
        } else {
            ::ndk::ScopedAStatus transStatus = mAidlBase->createBlockPool(
                    allocator, &aidlBlockPool);
            status = GetC2Status(transStatus, "createBlockPool");
            if (status != C2_OK) {
                return status;
            }
        }
        *blockPoolId = aidlBlockPool.blockPoolId;
        *configurable = std::make_shared<Configurable>(aidlBlockPool.configurable);
        return C2_OK;
    }
    c2_status_t status;
    Return<void> transStatus = mHidlBase1_0->createBlockPool(
            static_cast<uint32_t>(id),
            [&status, blockPoolId, configurable](
                    c2_hidl::Status s,
                    uint64_t pId,
                    const sp<c2_hidl::IConfigurable>& c) {
                status = static_cast<c2_status_t>(s);
                configurable->reset();
                if (status != C2_OK) {
                    LOG(DEBUG) << "createBlockPool -- call failed: "
                               << status << ".";
                    return;
                }
                *blockPoolId = static_cast<C2BlockPool::local_id_t>(pId);
                *configurable = std::make_shared<Configurable>(c);
            });
    if (!transStatus.isOk()) {
        LOG(ERROR) << "createBlockPool -- transaction failed.";
        return C2_TRANSACTION_FAILED;
    }
    return status;
}

c2_status_t Codec2Client::Component::destroyBlockPool(
        C2BlockPool::local_id_t localId) {
    if (mAidlBase) {
        mGraphicBufferAllocators->remove(localId);
        ::ndk::ScopedAStatus transStatus = mAidlBase->destroyBlockPool(localId);
        return GetC2Status(transStatus, "destroyBlockPool");
    }
    Return<c2_hidl::Status> transResult = mHidlBase1_0->destroyBlockPool(
            static_cast<uint64_t>(localId));
    if (!transResult.isOk()) {
        LOG(ERROR) << "destroyBlockPool -- transaction failed.";
        return C2_TRANSACTION_FAILED;
    }
    return static_cast<c2_status_t>(static_cast<c2_hidl::Status>(transResult));
}

void Codec2Client::Component::handleOnWorkDone(
        const std::list<std::unique_ptr<C2Work>> &workItems) {
    if (mAidlBase) {
        holdIgbaBlocks(workItems);
    } else {
        // Output bufferqueue-based blocks' lifetime management
        mOutputBufferQueue->holdBufferQueueBlocks(workItems);
    }
}

c2_status_t Codec2Client::Component::queue(
        std::list<std::unique_ptr<C2Work>>* const items) {
    if (mAidlBase) {
        c2_aidl::WorkBundle workBundle;
        if (!c2_aidl::utils::ToAidl(&workBundle, *items, mAidlBufferPoolSender.get())) {
            LOG(ERROR) << "queue -- bad input.";
            return C2_TRANSACTION_FAILED;
        }
        ::ndk::ScopedAStatus transStatus = mAidlBase->queue(workBundle);
        return GetC2Status(transStatus, "queue");
    }
    c2_hidl::WorkBundle workBundle;
    if (!c2_hidl::utils::objcpy(&workBundle, *items, mHidlBufferPoolSender.get())) {
        LOG(ERROR) << "queue -- bad input.";
        return C2_TRANSACTION_FAILED;
    }
    Return<c2_hidl::Status> transStatus = mHidlBase1_0->queue(workBundle);
    if (!transStatus.isOk()) {
        LOG(ERROR) << "queue -- transaction failed.";
        return C2_TRANSACTION_FAILED;
    }
    c2_status_t status =
            static_cast<c2_status_t>(static_cast<c2_hidl::Status>(transStatus));
    if (status != C2_OK) {
        LOG(DEBUG) << "queue -- call failed: " << status << ".";
    }
    return status;
}

c2_status_t Codec2Client::Component::flush(
        C2Component::flush_mode_t mode,
        std::list<std::unique_ptr<C2Work>>* const flushedWork) {
    (void)mode; // Flush mode isn't supported in HIDL/AIDL yet.
    c2_status_t status = C2_OK;
    if (mAidlBase) {
        c2_aidl::WorkBundle workBundle;
        ::ndk::ScopedAStatus transStatus = mAidlBase->flush(&workBundle);
        c2_status_t status = GetC2Status(transStatus, "flush");
        if (status != C2_OK) {
            return status;
        }
        if (!c2_aidl::utils::FromAidl(flushedWork, workBundle)) {
            LOG(DEBUG) << "flush -- flushedWork corrupted.";
            return C2_CORRUPTED;
        }
    } else {
        Return<void> transStatus = mHidlBase1_0->flush(
                [&status, flushedWork](
                        c2_hidl::Status s, const c2_hidl::WorkBundle& wb) {
                    status = static_cast<c2_status_t>(s);
                    if (status != C2_OK) {
                        LOG(DEBUG) << "flush -- call failed: " << status << ".";
                        return;
                    }
                    if (!c2_hidl::utils::objcpy(flushedWork, wb)) {
                        status = C2_CORRUPTED;
                    } else {
                        status = C2_OK;
                    }
                });
        if (!transStatus.isOk()) {
            LOG(ERROR) << "flush -- transaction failed.";
            return C2_TRANSACTION_FAILED;
        }
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

    if (mAidlBase) {
        holdIgbaBlocks(*flushedWork);
    } else {
        // Output bufferqueue-based blocks' lifetime management
        mOutputBufferQueue->holdBufferQueueBlocks(*flushedWork);
    }

    return status;
}

c2_status_t Codec2Client::Component::drain(C2Component::drain_mode_t mode) {
    if (mAidlBase) {
        ::ndk::ScopedAStatus transStatus = mAidlBase->drain(
                mode == C2Component::DRAIN_COMPONENT_WITH_EOS);
        return GetC2Status(transStatus, "drain");
    }
    Return<c2_hidl::Status> transStatus = mHidlBase1_0->drain(
            mode == C2Component::DRAIN_COMPONENT_WITH_EOS);
    if (!transStatus.isOk()) {
        LOG(ERROR) << "drain -- transaction failed.";
        return C2_TRANSACTION_FAILED;
    }
    c2_status_t status =
            static_cast<c2_status_t>(static_cast<c2_hidl::Status>(transStatus));
    if (status != C2_OK) {
        LOG(DEBUG) << "drain -- call failed: " << status << ".";
    }
    return status;
}

c2_status_t Codec2Client::Component::start() {
    if (mAidlBase) {
        ::ndk::ScopedAStatus transStatus = mAidlBase->start();
        return GetC2Status(transStatus, "start");
    }
    Return<c2_hidl::Status> transStatus = mHidlBase1_0->start();
    if (!transStatus.isOk()) {
        LOG(ERROR) << "start -- transaction failed.";
        return C2_TRANSACTION_FAILED;
    }
    c2_status_t status =
            static_cast<c2_status_t>(static_cast<c2_hidl::Status>(transStatus));
    if (status != C2_OK) {
        LOG(DEBUG) << "start -- call failed: " << status << ".";
    }
    return status;
}

c2_status_t Codec2Client::Component::stop() {
    if (mAidlBase) {
        ::ndk::ScopedAStatus transStatus = mAidlBase->stop();
        return GetC2Status(transStatus, "stop");
    }
    Return<c2_hidl::Status> transStatus = mHidlBase1_0->stop();
    if (!transStatus.isOk()) {
        LOG(ERROR) << "stop -- transaction failed.";
        return C2_TRANSACTION_FAILED;
    }
    c2_status_t status =
            static_cast<c2_status_t>(static_cast<c2_hidl::Status>(transStatus));
    if (status != C2_OK) {
        LOG(DEBUG) << "stop -- call failed: " << status << ".";
    }
    return status;
}

c2_status_t Codec2Client::Component::reset() {
    if (mAidlBase) {
        ::ndk::ScopedAStatus transStatus = mAidlBase->reset();
        return GetC2Status(transStatus, "reset");
    }
    Return<c2_hidl::Status> transStatus = mHidlBase1_0->reset();
    if (!transStatus.isOk()) {
        LOG(ERROR) << "reset -- transaction failed.";
        return C2_TRANSACTION_FAILED;
    }
    c2_status_t status =
            static_cast<c2_status_t>(static_cast<c2_hidl::Status>(transStatus));
    if (status != C2_OK) {
        LOG(DEBUG) << "reset -- call failed: " << status << ".";
    }
    return status;
}

c2_status_t Codec2Client::Component::release() {
    if (mAidlBase) {
        ::ndk::ScopedAStatus transStatus = mAidlBase->release();
        return GetC2Status(transStatus, "release");
    }
    Return<c2_hidl::Status> transStatus = mHidlBase1_0->release();
    if (!transStatus.isOk()) {
        LOG(ERROR) << "release -- transaction failed.";
        return C2_TRANSACTION_FAILED;
    }
    c2_status_t status =
            static_cast<c2_status_t>(static_cast<c2_hidl::Status>(transStatus));
    if (status != C2_OK) {
        LOG(DEBUG) << "release -- call failed: " << status << ".";
    }
    return status;
}

c2_status_t Codec2Client::Component::configureVideoTunnel(
        uint32_t avSyncHwId,
        native_handle_t** sidebandHandle) {
    *sidebandHandle = nullptr;
    if (mAidlBase) {
        ::aidl::android::hardware::common::NativeHandle handle;
        ::ndk::ScopedAStatus transStatus = mAidlBase->configureVideoTunnel(avSyncHwId, &handle);
        c2_status_t status = GetC2Status(transStatus, "configureVideoTunnel");
        if (status != C2_OK) {
            return status;
        }
        if (isAidlNativeHandleEmpty(handle)) {
            LOG(DEBUG) << "configureVideoTunnel -- empty handle returned";
        } else {
            *sidebandHandle = dupFromAidl(handle);
        }
        return C2_OK;
    }
    if (!mHidlBase1_1) {
        return C2_OMITTED;
    }
    c2_status_t status{};
    Return<void> transStatus = mHidlBase1_1->configureVideoTunnel(avSyncHwId,
            [&status, sidebandHandle](
                    c2_hidl::Status s, hardware::hidl_handle const& h) {
                status = static_cast<c2_status_t>(s);
                if (h.getNativeHandle()) {
                    *sidebandHandle = native_handle_clone(h.getNativeHandle());
                }
            });
    if (!transStatus.isOk()) {
        LOG(ERROR) << "configureVideoTunnel -- transaction failed.";
        return C2_TRANSACTION_FAILED;
    }
    return status;
}

c2_status_t Codec2Client::Component::setOutputSurface(
        C2BlockPool::local_id_t blockPoolId,
        const sp<IGraphicBufferProducer>& surface,
        uint32_t generation,
        int maxDequeueCount) {
    if (mAidlBase) {
        std::shared_ptr<AidlGraphicBufferAllocator> gba =
              mGraphicBufferAllocators->current();
        if (!gba) {
            LOG(ERROR) << "setOutputSurface for AIDL -- "
                       "GraphicBufferAllocator was not created.";
            return C2_CORRUPTED;
        }
        bool ret = gba->configure(surface, generation, maxDequeueCount);
        return ret ? C2_OK : C2_CORRUPTED;
    }
    uint64_t bqId = 0;
    sp<IGraphicBufferProducer> nullIgbp;
    sp<HGraphicBufferProducer2> nullHgbp;

    sp<HGraphicBufferProducer2> igbp = surface ?
            surface->getHalInterface<HGraphicBufferProducer2>() : nullHgbp;
    if (surface && !igbp) {
        igbp = new B2HGraphicBufferProducer2(surface);
    }

    std::scoped_lock lock(mOutputMutex);
    std::shared_ptr<SurfaceSyncObj> syncObj;

    if (!surface) {
        mOutputBufferQueue->configure(nullIgbp, generation, 0, maxDequeueCount, nullptr);
    } else if (surface->getUniqueId(&bqId) != OK) {
        LOG(ERROR) << "setOutputSurface -- "
                   "cannot obtain bufferqueue id.";
        bqId = 0;
        mOutputBufferQueue->configure(nullIgbp, generation, 0, maxDequeueCount, nullptr);
    } else {
        mOutputBufferQueue->configure(surface, generation, bqId, maxDequeueCount,
                                      mHidlBase1_2 ? &syncObj : nullptr);
    }

    // set consumer bits
    // TODO: should this get incorporated into setOutputSurface method so that consumer bits
    // can be set atomically?
    uint64_t consumerUsage = kDefaultConsumerUsage;
    {
        if (surface) {
            uint64_t usage = 0;
            status_t err = surface->getConsumerUsage(&usage);
            if (err != NO_ERROR) {
                ALOGD("setOutputSurface -- failed to get consumer usage bits (%d/%s). ignoring",
                        err, asString(err));
            } else {
                // Note: we are adding the default usage because components must support
                // producing output frames that can be displayed an all output surfaces.

                // TODO: do not set usage for tunneled scenario. It is unclear if consumer usage
                // is meaningful in a tunneled scenario; on one hand output buffers exist, but
                // they do not exist inside of C2 scope. Any buffer usage shall be communicated
                // through the sideband channel.

                consumerUsage = usage | kDefaultConsumerUsage;
            }
        }

        C2StreamUsageTuning::output outputUsage{
                0u, C2AndroidMemoryUsage::FromGrallocUsage(consumerUsage).expected};
        std::vector<std::unique_ptr<C2SettingResult>> failures;
        c2_status_t err = config({&outputUsage}, C2_MAY_BLOCK, &failures);
        if (err != C2_OK) {
            ALOGD("setOutputSurface -- failed to set consumer usage (%d/%s)",
                    err, asString(err));
        }
    }
    ALOGD("setOutputSurface -- generation=%u consumer usage=%#llx%s",
            generation, (long long)consumerUsage, syncObj ? " sync" : "");

    Return<c2_hidl::Status> transStatus = syncObj ?
            mHidlBase1_2->setOutputSurfaceWithSyncObj(
                    static_cast<uint64_t>(blockPoolId),
                    bqId == 0 ? nullHgbp : igbp, *syncObj) :
            mHidlBase1_0->setOutputSurface(
                    static_cast<uint64_t>(blockPoolId),
                    bqId == 0 ? nullHgbp : igbp);

    mOutputBufferQueue->expireOldWaiters();

    if (!transStatus.isOk()) {
        LOG(ERROR) << "setOutputSurface -- transaction failed.";
        return C2_TRANSACTION_FAILED;
    }
    c2_status_t status =
            static_cast<c2_status_t>(static_cast<c2_hidl::Status>(transStatus));
    if (status != C2_OK) {
        LOG(DEBUG) << "setOutputSurface -- call failed: " << status << ".";
    }
    ALOGD("Surface configure completed");
    return status;
}

status_t Codec2Client::Component::queueToOutputSurface(
        const C2ConstGraphicBlock& block,
        const QueueBufferInput& input,
        QueueBufferOutput* output) {
    ScopedTrace trace(ATRACE_TAG,"Codec2Client::Component::queueToOutputSurface");
    if (mAidlBase) {
        std::shared_ptr<AidlGraphicBufferAllocator> gba =
                mGraphicBufferAllocators->current();
        if (gba) {
            return gba->displayBuffer(block, input, output);
        } else {
            return C2_NOT_FOUND;
        }
    }
    return mOutputBufferQueue->outputBuffer(block, input, output);
}

void Codec2Client::Component::pollForRenderedFrames(FrameEventHistoryDelta* delta) {
    if (mAidlBase) {
        // TODO b/311348680
        return;
    }
    mOutputBufferQueue->pollForRenderedFrames(delta);
}

void Codec2Client::Component::setOutputSurfaceMaxDequeueCount(
        int maxDequeueCount) {
    if (mAidlBase) {
        std::shared_ptr<AidlGraphicBufferAllocator> gba =
                mGraphicBufferAllocators->current();
        if (gba) {
            gba->updateMaxDequeueBufferCount(maxDequeueCount);
        }
        return;
    }
    mOutputBufferQueue->updateMaxDequeueBufferCount(maxDequeueCount);
}

void Codec2Client::Component::stopUsingOutputSurface(
        C2BlockPool::local_id_t blockPoolId) {
    if (mAidlBase) {
        std::shared_ptr<AidlGraphicBufferAllocator> gba =
                mGraphicBufferAllocators->current();
        if (gba) {
            gba->reset();
        }
        return;
    }
    std::scoped_lock lock(mOutputMutex);
    mOutputBufferQueue->stop();
    Return<c2_hidl::Status> transStatus = mHidlBase1_0->setOutputSurface(
            static_cast<uint64_t>(blockPoolId), nullptr);
    if (!transStatus.isOk()) {
        LOG(ERROR) << "setOutputSurface(stopUsingOutputSurface) -- transaction failed.";
    } else {
        c2_status_t status =
                static_cast<c2_status_t>(static_cast<c2_hidl::Status>(transStatus));
        if (status != C2_OK) {
            LOG(DEBUG) << "setOutputSurface(stopUsingOutputSurface) -- call failed: "
                       << status << ".";
        }
    }
    mOutputBufferQueue->expireOldWaiters();
}

void Codec2Client::Component::onBufferReleasedFromOutputSurface(
        uint32_t generation) {
    if (mAidlBase) {
        std::shared_ptr<AidlGraphicBufferAllocator> gba =
                mGraphicBufferAllocators->current();
        if (gba) {
            gba->onBufferReleased(generation);
        }
        return;
    }
    mOutputBufferQueue->onBufferReleased(generation);
}

void Codec2Client::Component::holdIgbaBlocks(
        const std::list<std::unique_ptr<C2Work>>& workList) {
    if (!mAidlBase) {
        return;
    }
    std::shared_ptr<AidlGraphicBufferAllocator> gba =
            mGraphicBufferAllocators->current();
    if (!gba) {
        return;
    }
    std::shared_ptr<c2_aidl::IGraphicBufferAllocator> igba =
            c2_aidl::IGraphicBufferAllocator::fromBinder(gba->asBinder());
    for (const std::unique_ptr<C2Work>& work : workList) {
        if (!work) [[unlikely]] {
            continue;
        }
        for (const std::unique_ptr<C2Worklet>& worklet : work->worklets) {
            if (!worklet) {
                continue;
            }
            for (const std::shared_ptr<C2Buffer>& buffer : worklet->output.buffers) {
                if (buffer) {
                    for (const C2ConstGraphicBlock& block : buffer->data().graphicBlocks()) {
                        std::shared_ptr<_C2BlockPoolData> poolData =
                              _C2BlockFactory::GetGraphicBlockPoolData(block);
                        _C2BlockFactory::RegisterIgba(poolData, igba);
                    }
                }
            }
        }
    }
}

c2_status_t Codec2Client::Component::connectToInputSurface(
        const std::shared_ptr<InputSurface>& inputSurface,
        std::shared_ptr<InputSurfaceConnection>* connection) {
    if (mAidlBase) {
        // FIXME
        return C2_OMITTED;
    }
    c2_status_t status;
    Return<void> transStatus = mHidlBase1_0->connectToInputSurface(
            inputSurface->mBase,
            [&status, connection](
                    c2_hidl::Status s, const sp<c2_hidl::IInputSurfaceConnection>& c) {
                status = static_cast<c2_status_t>(s);
                if (status != C2_OK) {
                    LOG(DEBUG) << "connectToInputSurface -- call failed: "
                               << status << ".";
                    return;
                }
                *connection = std::make_shared<InputSurfaceConnection>(c);
            });
    if (!transStatus.isOk()) {
        LOG(ERROR) << "connectToInputSurface -- transaction failed";
        return C2_TRANSACTION_FAILED;
    }
    return status;
}

c2_status_t Codec2Client::Component::connectToOmxInputSurface(
        const sp<HGraphicBufferProducer1>& producer,
        const sp<HGraphicBufferSource>& source,
        std::shared_ptr<InputSurfaceConnection>* connection) {
    if (mAidlBase) {
        LOG(WARNING) << "Connecting to OMX input surface is not supported for AIDL C2 HAL";
        return C2_OMITTED;
    }
    c2_status_t status;
    Return<void> transStatus = mHidlBase1_0->connectToOmxInputSurface(
            producer, source,
            [&status, connection](
                    c2_hidl::Status s, const sp<c2_hidl::IInputSurfaceConnection>& c) {
                status = static_cast<c2_status_t>(s);
                if (status != C2_OK) {
                    LOG(DEBUG) << "connectToOmxInputSurface -- call failed: "
                               << status << ".";
                    return;
                }
                *connection = std::make_shared<InputSurfaceConnection>(c);
            });
    if (!transStatus.isOk()) {
        LOG(ERROR) << "connectToOmxInputSurface -- transaction failed.";
        return C2_TRANSACTION_FAILED;
    }
    return status;
}

c2_status_t Codec2Client::Component::disconnectFromInputSurface() {
    if (mAidlBase) {
        // FIXME
        return C2_OMITTED;
    }
    Return<c2_hidl::Status> transStatus = mHidlBase1_0->disconnectFromInputSurface();
    if (!transStatus.isOk()) {
        LOG(ERROR) << "disconnectToInputSurface -- transaction failed.";
        return C2_TRANSACTION_FAILED;
    }
    c2_status_t status =
            static_cast<c2_status_t>(static_cast<c2_hidl::Status>(transStatus));
    if (status != C2_OK) {
        LOG(DEBUG) << "disconnectFromInputSurface -- call failed: "
                   << status << ".";
    }
    return status;
}

Codec2Client::Component::AidlDeathManager *Codec2Client::Component::GetAidlDeathManager() {
    // This object never gets destructed
    static AidlDeathManager *sManager = new AidlDeathManager();
    return sManager;
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
                LOG(DEBUG) << "onDeath -- listener died.";
            }
        }
    };

    if (component->mAidlBase) {
        size_t seq;
        if (GetAidlDeathManager()->linkToDeath(component, listener, &seq)) {
            component->mAidlDeathSeq = seq;
        }
        return C2_OK;
    }

    sp<HidlDeathRecipient> deathRecipient = new HidlDeathRecipient();
    deathRecipient->base = listener;
    deathRecipient->component = component;

    component->mDeathRecipient = deathRecipient;
    Return<bool> transResult = component->mHidlBase1_0->linkToDeath(
            component->mDeathRecipient, 0);
    if (!transResult.isOk()) {
        LOG(ERROR) << "setDeathListener -- linkToDeath() transaction failed.";
        return C2_TRANSACTION_FAILED;
    }
    if (!static_cast<bool>(transResult)) {
        LOG(DEBUG) << "setDeathListener -- linkToDeath() call failed.";
        return C2_CORRUPTED;
    }
    return C2_OK;
}

// Codec2Client::InputSurface
Codec2Client::InputSurface::InputSurface(const sp<c2_hidl::IInputSurface>& base)
      : Configurable{
            [base]() -> sp<c2_hidl::IConfigurable> {
                Return<sp<c2_hidl::IConfigurable>> transResult =
                        base->getConfigurable();
                return transResult.isOk() ?
                        static_cast<sp<c2_hidl::IConfigurable>>(transResult) :
                        nullptr;
            }()
        },
        mBase{base},
        mGraphicBufferProducer{new
            H2BGraphicBufferProducer2([base]() -> sp<HGraphicBufferProducer2> {
                Return<sp<HGraphicBufferProducer2>> transResult =
                        base->getGraphicBufferProducer();
                return transResult.isOk() ?
                        static_cast<sp<HGraphicBufferProducer2>>(transResult) :
                        nullptr;
            }())} {
}

sp<IGraphicBufferProducer>
        Codec2Client::InputSurface::getGraphicBufferProducer() const {
    return mGraphicBufferProducer;
}

sp<c2_hidl::IInputSurface> Codec2Client::InputSurface::getHalInterface() const {
    return mBase;
}

// Codec2Client::InputSurfaceConnection
Codec2Client::InputSurfaceConnection::InputSurfaceConnection(
        const sp<c2_hidl::IInputSurfaceConnection>& base)
      : Configurable{
            [base]() -> sp<c2_hidl::IConfigurable> {
                Return<sp<c2_hidl::IConfigurable>> transResult =
                        base->getConfigurable();
                return transResult.isOk() ?
                        static_cast<sp<c2_hidl::IConfigurable>>(transResult) :
                        nullptr;
            }()
        },
        mBase{base} {
}

c2_status_t Codec2Client::InputSurfaceConnection::disconnect() {
    Return<c2_hidl::Status> transResult = mBase->disconnect();
    return static_cast<c2_status_t>(static_cast<c2_hidl::Status>(transResult));
}

}  // namespace android
