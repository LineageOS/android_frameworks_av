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

#include <android_media_codec.h>

#include <codec2/aidl/GraphicBufferAllocator.h>
#include <codec2/aidl/LegacyGraphicBufferAllocator.h>
#include <codec2/common/HalSelection.h>
#include <codec2/hidl/client.h>
#include <com_android_graphics_libgui_flags.h>

#include <C2BufferPriv.h>
#include <C2Component.h>
#include <C2Config.h> // for C2StreamUsageTuning
#include <C2Debug.h>
#include <C2DmaBufAllocator.h>
#include <C2IgbaInterfaceImpl.h>
#include <C2PlatformSupport.h>
#include <util/C2InterfaceHelper.h>

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
#include <android-base/scopeguard.h>
#include <android-base/stringprintf.h>
#include <apex/ApexCodecs.h>
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
#include <media/stagefright/foundation/ADebug.h> // for asString(status_t)
#include <utils/AndroidThreads.h>
#include <private/android/AHardwareBufferHelpers.h>
#include <system/window.h> // for NATIVE_WINDOW_QUERY_*

#include <algorithm>
#include <deque>
#include <iterator>
#include <limits>
#include <map>
#include <mutex>
#include <optional>
#include <ranges>
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

using AidlGraphicBufferAllocator =
        ::aidl::android::hardware::media::c2::implementation::LegacyGraphicBufferAllocator;

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
        } else if (transStatus.getExceptionCode() == EX_UNSUPPORTED_OPERATION) {
            LOG(DEBUG) << method << " -- call failed: EX_UNSUPPORTED_OPERATION.";
            return C2_OMITTED;
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

// Codec2ConfigurableClient::ApexImpl

struct Codec2ConfigurableClient::ApexImpl : public Codec2ConfigurableClient::ImplBase {
    ApexImpl(ApexCodec_Configurable *base, const C2String &name);

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
    ApexCodec_Configurable* mBase;
    const C2String mName;
};

Codec2ConfigurableClient::ApexImpl::ApexImpl(ApexCodec_Configurable *base, const C2String &name)
      : mBase{base},
        mName{name} {
}

c2_status_t Codec2ConfigurableClient::ApexImpl::query(
        const std::vector<C2Param*> &stackParams,
        const std::vector<C2Param::Index> &heapParamIndices,
        [[maybe_unused]] c2_blocking_t mayBlock,
        std::vector<std::unique_ptr<C2Param>>* const heapParams) const {
    if (mBase == nullptr) {
        return C2_OMITTED;
    }

    if (__builtin_available(android 36, *)) {
        std::vector<uint32_t> indices(
                stackParams.size() + heapParamIndices.size());
        size_t numIndices = 0;
        for (C2Param* const& stackParam : stackParams) {
            if (!stackParam) {
                LOG(WARNING) << "query -- null stack param encountered.";
                continue;
            }
            indices[numIndices++] = uint32_t(stackParam->index());
        }
        size_t numStackIndices = numIndices;
        for (const C2Param::Index& index : heapParamIndices) {
            indices[numIndices++] = uint32_t(index);
        }
        indices.resize(numIndices);
        if (heapParams) {
            heapParams->reserve(heapParams->size() + numIndices);
        }
        if (numIndices == 0) {
            return C2_OK;
        }
        // Since flex params have variable sizes, it is impossible to accurately
        // calculate the size of the buffer before query. Pick a reasonable
        // 1K padding to accommodate most cases. We have retry logic later
        // if the size was indeed insufficient.
        std::vector<uint8_t> configBuffer(numIndices * 16u + 1024);
        ApexCodec_LinearBuffer config{configBuffer.data(), configBuffer.capacity()};
        size_t writtenOrRequested = 0;
        ApexCodec_Status status = ApexCodec_Configurable_query(
                mBase, indices.data(), indices.size(), &config, &writtenOrRequested);
        if (status == APEXCODEC_STATUS_NO_MEMORY) {
            configBuffer.resize(writtenOrRequested);
            config.data = configBuffer.data();
            config.size = configBuffer.capacity();
            status = ApexCodec_Configurable_query(
                    mBase, indices.data(), indices.size(), &config, &writtenOrRequested);
        }
        size_t written = writtenOrRequested;
        if (status != APEXCODEC_STATUS_OK && status != APEXCODEC_STATUS_BAD_INDEX) {
            written = 0;
        }
        configBuffer.resize(written);
        std::vector<C2Param*> paramPointers;
        if (!::android::parseParamsBlob(&paramPointers, configBuffer)) {
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
                    status = APEXCODEC_STATUS_CORRUPTED;
                    break;
                }
                if (stackParams[i]->index() != paramPointer->index()) {
                    LOG(DEBUG) << "query -- param skipped: "
                                "index = "
                            << stackParams[i]->index() << ".";
                    stackParams[i++]->invalidate();
                    // this means that the param could not be queried.
                    // signalling C2_BAD_INDEX to the client.
                    status = APEXCODEC_STATUS_BAD_INDEX;
                    continue;
                }
                if (stackParams[i++]->updateFrom(*paramPointer)) {
                    LOG(VERBOSE) << "query -- param : index = "
                                 << paramPointer->index() << ".";
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
        if (status == APEXCODEC_STATUS_OK && indices.size() != numQueried) {
            status = APEXCODEC_STATUS_BAD_INDEX;
        }
        return (c2_status_t)status;
    } else {
        return C2_OMITTED;
    }
}

namespace {
struct ParamOrField : public C2ParamField {
    explicit ParamOrField(const ApexCodec_ParamFieldValues& field)
            : C2ParamField(field.index, field.offset, field.size) {}
};

static bool FromApex(
        ApexCodec_SupportedValues *apexValues,
        C2FieldSupportedValues* c2Values) {
    if (__builtin_available(android 36, *)) {
        if (apexValues == nullptr) {
            c2Values->type = C2FieldSupportedValues::EMPTY;
            return true;
        }
        ApexCodec_SupportedValuesType type = APEXCODEC_SUPPORTED_VALUES_EMPTY;
        ApexCodec_SupportedValuesNumberType numberType = APEXCODEC_SUPPORTED_VALUES_TYPE_NONE;
        ApexCodec_Value* values = nullptr;
        uint32_t numValues = 0;
        ApexCodec_SupportedValues_getTypeAndValues(
                apexValues, &type, &numberType, &values, &numValues);
        c2Values->type = (C2FieldSupportedValues::type_t)type;
        std::function<C2Value::Primitive(const ApexCodec_Value &)> getPrimitive;
        switch (numberType) {
            case APEXCODEC_SUPPORTED_VALUES_TYPE_NONE:
                getPrimitive = [](const ApexCodec_Value &) -> C2Value::Primitive {
                    return C2Value::Primitive();
                };
                break;
            case APEXCODEC_SUPPORTED_VALUES_TYPE_INT32:
                getPrimitive = [](const ApexCodec_Value &value) -> C2Value::Primitive {
                    return C2Value::Primitive(value.i32);
                };
                break;
            case APEXCODEC_SUPPORTED_VALUES_TYPE_UINT32:
                getPrimitive = [](const ApexCodec_Value &value) -> C2Value::Primitive {
                    return C2Value::Primitive(value.u32);
                };
                break;
            case APEXCODEC_SUPPORTED_VALUES_TYPE_INT64:
                getPrimitive = [](const ApexCodec_Value &value) -> C2Value::Primitive {
                    return C2Value::Primitive(value.i64);
                };
                break;
            case APEXCODEC_SUPPORTED_VALUES_TYPE_UINT64:
                getPrimitive = [](const ApexCodec_Value &value) -> C2Value::Primitive {
                    return C2Value::Primitive(value.u64);
                };
                break;
            case APEXCODEC_SUPPORTED_VALUES_TYPE_FLOAT:
                getPrimitive = [](const ApexCodec_Value &value) -> C2Value::Primitive {
                    return C2Value::Primitive(value.f);
                };
                break;
            default:
                LOG(ERROR) << "Unsupported number type: " << numberType;
                return false;
        }
        switch (type) {
            case APEXCODEC_SUPPORTED_VALUES_EMPTY:
                break;
            case APEXCODEC_SUPPORTED_VALUES_RANGE:
                c2Values->range.min   = getPrimitive(values[0]);
                c2Values->range.max   = getPrimitive(values[1]);
                c2Values->range.step  = getPrimitive(values[2]);
                c2Values->range.num   = getPrimitive(values[3]);
                c2Values->range.denom = getPrimitive(values[4]);
                break;
            case APEXCODEC_SUPPORTED_VALUES_VALUES:
            case APEXCODEC_SUPPORTED_VALUES_FLAGS:
                c2Values->values.clear();
                for (uint32_t i = 0; i < numValues; ++i) {
                    c2Values->values.push_back(getPrimitive(values[i]));
                }
                break;
            default:
                LOG(ERROR) << "Unsupported supported values type: " << type;
                return false;
        }
        return true;
    } else {
        return false;
    }
}

}  // anonymous namespace

c2_status_t Codec2ConfigurableClient::ApexImpl::config(
        const std::vector<C2Param*> &params,
        c2_blocking_t mayBlock,
        std::vector<std::unique_ptr<C2SettingResult>>* const failures) {
    (void)mayBlock;
    if (mBase == nullptr) {
        return C2_OMITTED;
    }

    if (__builtin_available(android 36, *)) {
        std::vector<uint8_t> configBuffer;
        if (!::android::_createParamsBlob(&configBuffer, params)) {
            LOG(ERROR) << "config -- bad input.";
            return C2_TRANSACTION_FAILED;
        }
        ApexCodec_SettingResults* result = nullptr;
        ApexCodec_LinearBuffer config{configBuffer.data(), configBuffer.size()};
        ApexCodec_Status status = ApexCodec_Configurable_config(
                mBase, &config, &result);
        base::ScopeGuard guard([result] {
            if (result) {
                ApexCodec_SettingResults_destroy(result);
            }
        });
        size_t index = 0;
        ApexCodec_SettingResultFailure failure;
        ApexCodec_ParamFieldValues field;
        ApexCodec_ParamFieldValues* conflicts = nullptr;
        size_t numConflicts = 0;
        ApexCodec_Status getResultStatus = ApexCodec_SettingResults_getResultAtIndex(
            result, 0, &failure, &field, &conflicts, &numConflicts);
        while (getResultStatus == APEXCODEC_STATUS_OK) {
            std::unique_ptr<C2SettingResult> settingResult;
            settingResult.reset(new C2SettingResult{
                C2SettingResult::Failure(failure), C2ParamFieldValues(ParamOrField(field)), {}
            });
            // TODO: settingResult->field.values = ?
            for (size_t i = 0; i < numConflicts; ++i) {
                settingResult->conflicts.emplace_back(ParamOrField(conflicts[i]));
                C2ParamFieldValues& conflict = settingResult->conflicts.back();
                conflict.values = std::make_unique<C2FieldSupportedValues>();
                FromApex(conflicts[i].values, conflict.values.get());
            }
            failures->push_back(std::move(settingResult));
            getResultStatus = ApexCodec_SettingResults_getResultAtIndex(
                    result, ++index, &failure, &field, &conflicts, &numConflicts);
        }
        if (!::android::updateParamsFromBlob(params, configBuffer)) {
            LOG(ERROR) << "config -- "
                    << "failed to parse returned params.";
            status = APEXCODEC_STATUS_CORRUPTED;
        }
        return (c2_status_t)status;
    } else {
        return C2_OMITTED;
    }
}

c2_status_t Codec2ConfigurableClient::ApexImpl::querySupportedParams(
        std::vector<std::shared_ptr<C2ParamDescriptor>>* const params) const {
    if (mBase == nullptr) {
        return C2_OMITTED;
    }

    if (__builtin_available(android 36, *)) {
        // TODO: Cache and query properly!
        ApexCodec_ParamDescriptors* paramDescs = nullptr;
        ApexCodec_Configurable_querySupportedParams(mBase, &paramDescs);
        base::ScopeGuard guard([paramDescs] {
            if (paramDescs) {
                ApexCodec_ParamDescriptors_destroy(paramDescs);
            }
        });
        uint32_t *indices = nullptr;
        size_t numIndices = 0;
        ApexCodec_Status status = ApexCodec_ParamDescriptors_getIndices(
                paramDescs, &indices, &numIndices);
        if (status != APEXCODEC_STATUS_OK) {
            return (c2_status_t)status;
        }
        if (numIndices > 0) {
            for (int i = 0; i < numIndices; ++i) {
                uint32_t index = indices[i];
                ApexCodec_ParamAttribute attr = (ApexCodec_ParamAttribute)0;
                const char* name = nullptr;
                uint32_t* dependencies = nullptr;
                size_t numDependencies = 0;
                ApexCodec_Status status = ApexCodec_ParamDescriptors_getDescriptor(
                        paramDescs, index, &attr, &name, &dependencies, &numDependencies);
                if (status != APEXCODEC_STATUS_OK) {
                    LOG(WARNING) << "querySupportedParams -- "
                                << "failed to get descriptor for index "
                                << std::hex << index << std::dec << " with status " << status;
                    continue;
                }
                params->push_back(std::make_shared<C2ParamDescriptor>(
                        C2Param::Index(index), C2ParamDescriptor::attrib_t(attr), name,
                        std::vector<C2Param::Index>(dependencies, dependencies + numDependencies)));
            }
        }
        return (c2_status_t)status;
    } else {
        return C2_OMITTED;
    }
}

c2_status_t Codec2ConfigurableClient::ApexImpl::querySupportedValues(
        std::vector<C2FieldSupportedValuesQuery>& fields,
        [[maybe_unused]] c2_blocking_t mayBlock) const {
    if (mBase == nullptr) {
        return C2_OMITTED;
    }

    if (__builtin_available(android 36, *)) {
        std::vector<ApexCodec_SupportedValuesQuery> queries(fields.size());
        for (size_t i = 0; i < fields.size(); ++i) {
            queries[i].index  = _C2ParamInspector::GetIndex(fields[i].field());
            queries[i].offset = _C2ParamInspector::GetOffset(fields[i].field());
            queries[i].type   = (ApexCodec_SupportedValuesQueryType)fields[i].type();
            queries[i].status = APEXCODEC_STATUS_OK;
            queries[i].values = nullptr;
        }
        ApexCodec_Status status = ApexCodec_Configurable_querySupportedValues(
                mBase, queries.data(), queries.size());
        for (size_t i = 0; i < fields.size(); ++i) {
            fields[i].status = (c2_status_t)queries[i].status;
            FromApex(queries[i].values, &fields[i].values);
            if (queries[i].values) {
                ApexCodec_SupportedValues_destroy(queries[i].values);
                queries[i].values = nullptr;
            }
        }
        return (c2_status_t)status;
    } else {
        return C2_OMITTED;
    }
}

// Codec2ConfigurableClient

Codec2ConfigurableClient::Codec2ConfigurableClient(const sp<HidlBase> &hidlBase)
    : mImpl(new Codec2ConfigurableClient::HidlImpl(hidlBase)) {
}

Codec2ConfigurableClient::Codec2ConfigurableClient(
        const std::shared_ptr<AidlBase> &aidlBase)
    : mImpl(new Codec2ConfigurableClient::AidlImpl(aidlBase)) {
}

Codec2ConfigurableClient::Codec2ConfigurableClient(
        ApexCodec_Configurable *apexBase, const C2String &name)
    : mImpl(new Codec2ConfigurableClient::ApexImpl(apexBase, name)) {
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

// Codec2Client::Component::ApexHandler
class Codec2Client::Component::ApexHandler {
public:
    ApexHandler(ApexCodec_ComponentStore *apexStore,
                ApexCodec_Component *apexComponent,
                const C2String &name,
                const std::shared_ptr<Listener> &listener,
                const std::shared_ptr<Component> &comp)
          : mApexStore(apexStore),
            mApexComponent(apexComponent),
            mListener(listener),
            mComponent(comp),
            mComponentName(name),
            mStopped(false),
            mPendingFlush(false),
            mOutputBufferType(APEXCODEC_BUFFER_TYPE_EMPTY),
            mLinearBlockCapacity(4096) {
    }

    void start() {
        std::shared_ptr<Component> comp = mComponent.lock();
        if (!comp) {
            LOG(ERROR) << "ApexHandler::start -- component died.";
            return;
        }
        C2ComponentDomainSetting domain;
        C2ComponentKindSetting kind;
        c2_status_t status = comp->query({&domain, &kind}, {}, C2_MAY_BLOCK, {});
        if (status != C2_OK) {
            LOG(ERROR) << "ApexHandler::start -- failed to query component domain and kind";
            return;
        }
        if (kind.value != C2Component::KIND_DECODER
                && kind.value != C2Component::KIND_ENCODER) {
            LOG(ERROR) << "ApexHandler::start -- unrecognized component kind " << kind.value;
            return;
        }
        ApexCodec_BufferType outputBufferType = APEXCODEC_BUFFER_TYPE_EMPTY;
        if (domain.value == C2Component::DOMAIN_AUDIO) {
            // For both encoders and decoders the output buffer type is linear.
            outputBufferType = APEXCODEC_BUFFER_TYPE_LINEAR;
        } else if (domain.value == C2Component::DOMAIN_VIDEO
                    || domain.value == C2Component::DOMAIN_IMAGE) {
            // For video / image domain the decoder outputs a graphic buffer, and the encoder
            // outputs a linear buffer.
            outputBufferType = (kind.value == C2Component::KIND_DECODER)
                    ? APEXCODEC_BUFFER_TYPE_GRAPHIC : APEXCODEC_BUFFER_TYPE_LINEAR;
        } else {
            LOG(ERROR) << "ApexHandler::start -- unrecognized component domain " << domain.value;
            return;
        }
        {
            std::unique_lock<std::mutex> l(mMutex);
            mStopped = false;
            mOutputBufferType = outputBufferType;
        }
        mThread = std::thread([this]() {
            run();
        });
    }

    void queue(std::list<std::unique_ptr<C2Work>>& workItems) {
        std::unique_lock<std::mutex> l(mMutex);
        mWorkQueue.splice(mWorkQueue.end(), workItems);
        LOG(VERBOSE) << "queue: mWorkQueue size=" << mWorkQueue.size();
        mCondition.notify_all();
    }

    c2_status_t stop() {
        std::unique_lock<std::mutex> l(mMutex);
        if (mStopped) {
            return C2_BAD_STATE;
        }
        mStopped = true;
        mCondition.notify_all();
        l.unlock();
        if (mThread.joinable()) {
            mThread.join();
        }
        return C2_OK;
    }

    void flush(std::list<std::unique_ptr<C2Work>>* const flushedWork) {
        std::unique_lock<std::mutex> l(mMutex);
        mPendingFlush = true;
        mCondition.notify_all();
        mCondition.wait(l, [this]() {
            return !mPendingFlush || mStopped;
        });
        if (flushedWork) {
            LOG(VERBOSE) << "flush: with flushedWork, returning work size=" << mFlushedWork.size();
            flushedWork->splice(flushedWork->end(), mFlushedWork);
        } else {
            LOG(VERBOSE) << "flush: without flushedWork, onWorkDone size=" << mFlushedWork.size();
            std::shared_ptr<Listener> listener = mListener.lock();
            if (listener) {
                listener->onWorkDone(mComponent, mFlushedWork);
            } else {
                LOG(WARNING) << "flush: listener is not available";
            }
        }
        mFlushedWork.clear();
    }

private:
    static bool ParseParamsBlob(
            std::vector<C2Param*> *outputConfigUpdatePtrs,
            const ApexCodec_LinearBuffer *outputConfigUpdates) {
        if (!outputConfigUpdatePtrs || !outputConfigUpdates) {
            return false;
        }
        hidl_vec<uint8_t> outputConfigUpdatesVec;
        outputConfigUpdatesVec.setToExternal(
                outputConfigUpdates->data, outputConfigUpdates->size);
        return parseParamsBlob(outputConfigUpdatePtrs, outputConfigUpdatesVec);
    }
    void run() {
        androidSetThreadPriority(gettid(), ANDROID_PRIORITY_AUDIO);
        if (__builtin_available(android 36, *)) {
            ApexCodec_Buffer *input = ApexCodec_Buffer_create();
            ApexCodec_Buffer *output = ApexCodec_Buffer_create();
            ApexCodec_Component_start(mApexComponent);
            while (true) {
                std::unique_lock<std::mutex> l(mMutex);
                mCondition.wait(l, [this]() {
                    return !mWorkQueue.empty() || mStopped || mPendingFlush;
                });
                if (mStopped) {
                    break;
                }
                if (mPendingFlush) {
                    LOG(VERBOSE) << "ApexHandler::run -- processing pending flush";
                    ApexCodec_Component_flush(mApexComponent);
                    for (auto& [frameIndex, workItem] : mWorkMap) {
                        LOG(VERBOSE) << "flushed #" << frameIndex;
                        if (workItem) {
                            for (std::unique_ptr<C2Worklet> &worklet : workItem->worklets) {
                                worklet->output.configUpdate.clear();
                                worklet->output.buffers.clear();
                                worklet->output.flags = (C2FrameData::flags_t)0;
                            }
                            mFlushedWork.push_back(std::move(workItem));
                        }
                    }
                    LOG(VERBOSE) << "flushed work queue size=" << mWorkQueue.size();
                    mFlushedWork.splice(mFlushedWork.end(), mWorkQueue);
                    mWorkQueue.clear();
                    mWorkMap.clear();
                    mPendingFlush = false;
                    mCondition.notify_all();
                    continue;
                }
                if (mWorkQueue.empty()) {
                    continue;
                }
                LOG(VERBOSE) << "ApexHandler::run -- processing " << mWorkQueue.size()
                             << " work items";
                std::list<std::unique_ptr<C2Work>> workItems;
                mWorkQueue.swap(workItems);
                for (auto it = workItems.begin(); it != workItems.end(); ++it) {
                    std::unique_ptr<C2Work> &workItem = *it;
                    if (mStopped) {
                        break;
                    }
                    if (mPendingFlush) {
                        mWorkQueue.splice(mWorkQueue.begin(), workItems, it, workItems.end());
                        break;
                    }
                    LOG(VERBOSE) << "ApexHandler::run -- handle workItem frameIndex = "
                                 << workItem->input.ordinal.frameIndex.peekll();
                    l.unlock();
                    handleWork(std::move(workItem), input, output);
                    l.lock();
                }
            }
            mWorkQueue.clear();
            mWorkMap.clear();
            ApexCodec_Buffer_destroy(input);
            ApexCodec_Buffer_destroy(output);
            ApexCodec_Component_reset(mApexComponent);
        }
    }

    void handleWork(std::unique_ptr<C2Work> &&workItem,
                    ApexCodec_Buffer *input,
                    ApexCodec_Buffer *output) {
        if (__builtin_available(android 36, *)) {
            std::shared_ptr<Listener> listener = mListener.lock();
            if (!listener) {
                LOG(DEBUG) << "handleWork -- listener died.";
                return;
            }
            ApexCodec_Buffer_clear(input);
            ApexCodec_BufferFlags flags = (ApexCodec_BufferFlags)workItem->input.flags;
            uint64_t frameIndex = workItem->input.ordinal.frameIndex.peekll();
            uint64_t timestampUs = workItem->input.ordinal.timestamp.peekll();

            if (workItem->input.buffers.size() > 1) {
                LOG(ERROR) << "handleWork -- input buffer size is "
                           << workItem->input.buffers.size();
                listener->onError(mComponent, C2_CORRUPTED);
                return;
            }
            std::shared_ptr<C2Buffer> buffer;
            std::optional<C2ReadView> linearView;
            if (!workItem->input.buffers.empty()) {
                buffer = workItem->input.buffers[0];
            }
            if (!fillMemory(buffer, input, &linearView, flags, frameIndex, timestampUs)) {
                LOG(ERROR) << "handleWork -- failed to map input";
                listener->onError(mComponent, C2_CORRUPTED);
                return;
            }

            std::vector<uint8_t> configUpdatesVector;
            if (!_createParamsBlob(&configUpdatesVector, workItem->input.configUpdate)) {
                LOG(ERROR) << "handleWork -- failed to create config updates";
                listener->onError(mComponent, C2_CORRUPTED);
                return;
            }
            ApexCodec_LinearBuffer configUpdates;
            configUpdates.data = configUpdatesVector.data();
            configUpdates.size = configUpdatesVector.size();
            ApexCodec_Buffer_setConfigUpdates(input, &configUpdates);
            mWorkMap.insert_or_assign(
                    workItem->input.ordinal.frameIndex.peekll(), std::move(workItem));

            std::list<std::unique_ptr<C2Work>> workItems;
            bool inputDrained = false;
            while (!inputDrained) {
                ApexCodec_Buffer_clear(output);
                std::shared_ptr<C2LinearBlock> linearBlock;
                std::optional<C2WriteView> linearView;
                std::shared_ptr<C2GraphicBlock> graphicBlock;
                allocOutputBuffer(output, &linearBlock, &linearView, &graphicBlock);

                size_t consumed = 0;
                size_t produced = 0;
                bool ownedByClient = false;
                ApexCodec_LinearBuffer outputConfigUpdates;
                std::vector<C2Param*> outputConfigUpdatePtrs;
                ApexCodec_BufferFlags outputFlags = (ApexCodec_BufferFlags)0;

                ApexCodec_Status status = ApexCodec_Component_process(
                        mApexComponent, input, output, &consumed, &produced);
                LOG(VERBOSE) << "handleWork -- component process, consumed " << consumed
                             << ", produced " << produced << ", status " << status;
                if (status == APEXCODEC_STATUS_NO_MEMORY) {
                    LOG(INFO) << "handleWork -- output buffer is too small";
                    status = ApexCodec_Buffer_getConfigUpdates(
                            output, &outputConfigUpdates, &ownedByClient);
                    if (status != APEXCODEC_STATUS_OK) {
                        LOG(WARNING) << "handleWork -- failed to get output config updates";
                        return;
                    }
                    if (ownedByClient) {
                        LOG(WARNING) << "handleWork -- output config updates are owned by client";
                        return;
                    }
                    ParseParamsBlob(&outputConfigUpdatePtrs, &outputConfigUpdates);
                    C2StreamMaxBufferSizeInfo::output outSize{0 /* stream */, 0 /* value */};
                    bool updated = false;
                    LOG(INFO) << "out size index = " << outSize.index();
                    for (const C2Param *param : outputConfigUpdatePtrs) {
                        if (!param) {
                            LOG(WARNING) << "handleWork -- param null";
                            continue;
                        }
                        LOG(INFO) << "param index = " << param->index();
                        if (param->index() == outSize.index()) {
                            updated = outSize.updateFrom(*param);
                            if (updated) {
                                break;
                            }
                        }
                    }
                    if (!updated) {
                        LOG(WARNING) << "handleWork -- output config updates "
                                     << "doesn't contain buffer size";
                        return;
                    }
                    mLinearBlockCapacity = align(outSize.value, 4096);
                    LOG(INFO) << "handleWork -- output buffer size updated: outSize.value = "
                              << outSize.value << " capacity = " << mLinearBlockCapacity;
                    continue;
                } else if (status != APEXCODEC_STATUS_OK) {
                    LOG(ERROR) << "handleWork -- component process failed with status " << status;
                    produced = 0;
                    listener->onError(mComponent, (c2_status_t)status);
                    return;
                }
                LOG(VERBOSE) << "handleWork -- produced " << produced << " bytes";
                if (ApexCodec_Buffer_getType(output) == APEXCODEC_BUFFER_TYPE_LINEAR) {
                    uint64_t outputFrameIndex;
                    uint64_t outputTimestampUs;
                    ApexCodec_Status status = ApexCodec_Buffer_getBufferInfo(
                            output, &outputFlags, &outputFrameIndex, &outputTimestampUs);
                    if (status != APEXCODEC_STATUS_OK) {
                        LOG(WARNING) << "handleWork -- failed to get output buffer info: status = "
                                     << status;
                        outputFrameIndex = ~(uint64_t(0));
                    }
                    auto it = mWorkMap.find(outputFrameIndex);
                    std::unique_ptr<C2Work> outputWorkItem;
                    if (it != mWorkMap.end()) {
                        if (produced == 0 && (outputFlags & APEXCODEC_FLAG_INCOMPLETE)) {
                            status = ApexCodec_Buffer_getConfigUpdates(
                                    output, &outputConfigUpdates, &ownedByClient);
                            if (status == APEXCODEC_STATUS_OK) {
                                if (ownedByClient) {
                                    LOG(WARNING) << "handleWork -- output config updates "
                                                 << "are owned by client";
                                    return;
                                }
                                ParseParamsBlob(&outputConfigUpdatePtrs, &outputConfigUpdates);
                                std::unique_ptr<C2Worklet> &worklet = it->second->worklets.front();
                                std::ranges::transform(
                                        outputConfigUpdatePtrs,
                                        std::back_inserter(worklet->output.configUpdate),
                                        [](C2Param* param) { return C2Param::Copy(*param); });
                            }
                        } else if (outputFlags & APEXCODEC_FLAG_INCOMPLETE) {
                            outputWorkItem = std::make_unique<C2Work>();
                            outputWorkItem->input.ordinal = it->second->input.ordinal;
                            outputWorkItem->input.flags = it->second->input.flags;
                            outputWorkItem->worklets.emplace_back(new C2Worklet);
                        } else {
                            outputWorkItem = std::move(it->second);
                            mWorkMap.erase(it);
                        }
                    } else {
                        LOG(WARNING) << "handleWork -- no work item found for output frame index "
                                    << outputFrameIndex;
                        outputWorkItem = std::make_unique<C2Work>();
                        outputWorkItem->input.ordinal.frameIndex = outputFrameIndex;
                        outputWorkItem->input.ordinal.timestamp = outputTimestampUs;
                        outputWorkItem->input.flags = (C2FrameData::flags_t)outputFlags;
                        outputWorkItem->worklets.emplace_back(new C2Worklet);
                    }
                    if (outputWorkItem) {
                        const std::unique_ptr<C2Worklet> &worklet =
                                outputWorkItem->worklets.front();
                        if (worklet == nullptr) {
                            LOG(ERROR) << "handleWork -- output work item has null worklet";
                            return;
                        }
                        worklet->output.ordinal.frameIndex = outputFrameIndex;
                        worklet->output.ordinal.timestamp = outputTimestampUs;
                        status = ApexCodec_Buffer_getConfigUpdates(
                                output, &outputConfigUpdates, &ownedByClient);
                        if (status != APEXCODEC_STATUS_OK &&
                                status != APEXCODEC_STATUS_NOT_FOUND) {
                            LOG(WARNING) << "handleWork -- failed to get output config updates";
                            return;
                        }
                        if (status == APEXCODEC_STATUS_OK) {
                            if (ownedByClient) {
                                LOG(WARNING) << "handleWork -- output config updates "
                                             << "are owned by client";
                                return;
                            }
                            ParseParamsBlob(&outputConfigUpdatePtrs, &outputConfigUpdates);
                            std::ranges::transform(
                                    outputConfigUpdatePtrs,
                                    std::back_inserter(worklet->output.configUpdate),
                                    [](C2Param* param) { return C2Param::Copy(*param); });
                        }
                        worklet->output.flags = (C2FrameData::flags_t)outputFlags;
                        if (produced > 0) {
                            worklet->output.buffers.push_back(C2Buffer::CreateLinearBuffer(
                                    linearBlock->share(0, produced, C2Fence())));
                        }
                        outputWorkItem->workletsProcessed = 1u;
                        outputWorkItem->result = C2_OK;
                        workItems.push_back(std::move(outputWorkItem));
                    }
                }

                ApexCodec_BufferType inputType = ApexCodec_Buffer_getType(input);
                // determine whether the input buffer is drained
                if (inputType == APEXCODEC_BUFFER_TYPE_LINEAR) {
                    ApexCodec_LinearBuffer inputBuffer;
                    status = ApexCodec_Buffer_getLinearBuffer(input, &inputBuffer);
                    if (status != APEXCODEC_STATUS_OK) {
                        LOG(WARNING) << "handleWork -- failed to get input linear buffer";
                        inputDrained = true;
                    } else if (inputBuffer.size < consumed) {
                        LOG(WARNING) << "handleWork -- component consumed more bytes "
                                     << "than the input buffer size";
                        inputDrained = true;
                    } else {
                        LOG(VERBOSE) << "handleWork -- consumed " << consumed << " bytes";
                        inputBuffer.data += consumed;
                        inputBuffer.size -= consumed;
                        if (inputBuffer.size == 0) {
                            if ((flags & APEXCODEC_FLAG_END_OF_STREAM)
                                    && !(outputFlags & APEXCODEC_FLAG_END_OF_STREAM)) {
                                LOG(VERBOSE) << "handleWork -- draining...";
                            } else {
                                inputDrained = true;
                            }
                        }
                    }
                } else if (inputType == APEXCODEC_BUFFER_TYPE_GRAPHIC) {
                    inputDrained = (consumed > 0);
                }
                if ((outputFlags & APEXCODEC_FLAG_END_OF_STREAM) ||
                    (inputDrained && (flags & APEXCODEC_FLAG_END_OF_STREAM))) {
                    inputDrained = true;
                }
            }

            if (!workItems.empty()) {
                listener->onWorkDone(mComponent, workItems);
            }
        }
    }

    bool ensureBlockPool() {
        std::shared_ptr<Component> comp = mComponent.lock();
        if (!comp) {
            return false;
        }
        std::vector<std::unique_ptr<C2Param>> heapParams;
        comp->query({}, {C2PortBlockPoolsTuning::output::PARAM_TYPE}, C2_MAY_BLOCK, &heapParams);
        if (heapParams.size() != 1) {
            return false;
        }
        const C2Param* param = heapParams[0].get();
        if (param->type() != C2PortBlockPoolsTuning::output::PARAM_TYPE) {
            return false;
        }
        const C2PortBlockPoolsTuning::output *blockPools =
                static_cast<const C2PortBlockPoolsTuning::output *>(param);
        if (blockPools->flexCount() == 0) {
            return false;
        }
        C2BlockPool::local_id_t blockPoolId = blockPools->m.values[0];
        if (mBlockPool && mBlockPool->getLocalId() == blockPoolId) {
            // no need to update
            return true;
        }
        return C2_OK == GetCodec2BlockPool(blockPoolId, nullptr, &mBlockPool);
    }

    void allocOutputBuffer(
            ApexCodec_Buffer* output,
            std::shared_ptr<C2LinearBlock> *linearBlock,
            std::optional<C2WriteView> *linearView,
            std::shared_ptr<C2GraphicBlock> *graphicBlock) {
        if (__builtin_available(android 36, *)) {
            switch (mOutputBufferType) {
                case APEXCODEC_BUFFER_TYPE_LINEAR: {
                    if (!ensureBlockPool()) {
                        LOG(ERROR) << "allocOutputBuffer -- failed to ensure block pool";
                        return;
                    }
                    c2_status_t status = mBlockPool->fetchLinearBlock(
                            mLinearBlockCapacity,
                            C2MemoryUsage(C2MemoryUsage::CPU_READ | C2MemoryUsage::CPU_WRITE),
                            linearBlock);
                    if (!(*linearBlock)) {
                        LOG(ERROR) << "allocOutputBuffer -- failed to fetch linearBlock";
                        return;
                    }
                    if (__builtin_available(android 37, *)) {
                        ApexCodec_MapFn mapFn = ::mmap;
                        ApexCodec_UnmapFn unmapFn = ::munmap;
                        if (android::media::codec::provider_->in_process_sw_codec_lfi()) {
                            mapFn = ApexCodec_GetMapFn(mApexStore, mComponentName.c_str());
                            unmapFn = ApexCodec_GetUnmapFn(mApexStore, mComponentName.c_str());
                        }
                        linearView->emplace(_C2BlockFactory::MapLinearWithMapper(
                                *linearBlock, mapFn, unmapFn).get());
                    } else {
                        linearView->emplace((*linearBlock)->map().get());
                    }
                    if ((*linearView)->error() != C2_OK) {
                        LOG(ERROR) << "allocOutputBuffer -- failed to map linearView";
                        return;
                    }
                    ApexCodec_LinearBuffer linear;
                    linear.data = (*linearView)->data();
                    linear.size = (*linearView)->capacity();
                    LOG(VERBOSE) << "linearView data=0x"
                                 << std::hex << intptr_t(linear.data) << std::dec
                                 << " size=" << linear.size;
                    ApexCodec_Status apexStatus = ApexCodec_Buffer_setLinearBuffer(
                            output, &linear);
                    if (apexStatus != APEXCODEC_STATUS_OK) {
                        LOG(ERROR) << "allocOutputBuffer -- failed to set linear buffer";
                        return;
                    }
                    break;
                }
                case APEXCODEC_BUFFER_TYPE_GRAPHIC: {
                    if (!ensureBlockPool()) {
                        return;
                    }
                    {
                        std::shared_ptr<Component> comp = mComponent.lock();
                        if (!comp) {
                            return;
                        }
                        C2StreamMaxPictureSizeTuning::output maxPictureSize(0u /* stream */);
                        C2StreamPictureSizeInfo::output pictureSize(0u /* stream */);
                        C2StreamPixelFormatInfo::output pixelFormat(0u /* stream */);
                        comp->query({&maxPictureSize, &pictureSize, &pixelFormat},
                                    {}, C2_MAY_BLOCK, {});
                        mWidth = maxPictureSize ? maxPictureSize.width : pictureSize.width;
                        mHeight = maxPictureSize ? maxPictureSize.height : pictureSize.height;
                        mFormat = pixelFormat ? pixelFormat.value : HAL_PIXEL_FORMAT_YCBCR_420_888;
                    }
                    c2_status_t status = mBlockPool->fetchGraphicBlock(
                            mWidth, mHeight, mFormat,
                            C2MemoryUsage(C2MemoryUsage::CPU_READ | C2MemoryUsage::CPU_WRITE),
                            graphicBlock);
                    if (!(*graphicBlock)) {
                        return;
                    }
                    const C2Handle *handle = (*graphicBlock)->handle();
                    uint32_t width, height, format, stride, igbp_slot, generation;
                    uint64_t usage, igbp_id;
                    _UnwrapNativeCodec2GrallocMetadata(
                            handle, &width, &height, &format, &usage, &stride, &generation,
                            &igbp_id, &igbp_slot);
                    native_handle_t *grallocHandle = UnwrapNativeCodec2GrallocHandle(handle);
                    sp<GraphicBuffer> graphicBuffer = new GraphicBuffer(
                            grallocHandle, GraphicBuffer::CLONE_HANDLE,
                            width, height, format, 1, usage, stride);
                    native_handle_delete(grallocHandle);
                    AHardwareBuffer *hardwareBuffer =
                        AHardwareBuffer_from_GraphicBuffer(graphicBuffer.get());
                    AHardwareBuffer_acquire(hardwareBuffer);
                    ApexCodec_Status apexStatus = ApexCodec_Buffer_setGraphicBuffer(
                            output, hardwareBuffer);
                    if (apexStatus != APEXCODEC_STATUS_OK) {
                        LOG(ERROR) << "allocOutputBuffer -- failed to set graphic buffer";
                        return;
                    }
                    break;
                }
                default: {
                    LOG(ERROR) << "allocOutputBuffer -- unsupported output buffer type: "
                            << mOutputBufferType;
                    return;
                }
            }
        } else {
            LOG(ERROR) << "allocOutputBuffer -- ApexCodec is not supported";
        }
    }

    bool fillMemory(
            const std::shared_ptr<C2Buffer>& buffer,
            ApexCodec_Buffer* apexBuffer,
            std::optional<C2ReadView>* linearView,
            ApexCodec_BufferFlags flags,
            uint64_t frameIndex,
            uint64_t timestampUs) {
        if (__builtin_available(android 36, *)) {
            LOG(VERBOSE) << "FillMemory -- buffer " << std::hex << buffer
                         << " apexBuffer " << apexBuffer
                         << " flags " << std::dec << flags
                         << " frameIndex " << frameIndex
                         << " timestampUs " << timestampUs;
            if (!buffer) {
                ApexCodec_Status status = ApexCodec_Buffer_setLinearBuffer(apexBuffer, nullptr);
                if (status != APEXCODEC_STATUS_OK) {
                    LOG(ERROR) << "FillMemory -- failed to set linear buffer";
                    return false;
                }
                ApexCodec_Buffer_setBufferInfo(apexBuffer, flags, frameIndex, timestampUs);
                return true;
            }
            if (buffer->data().type() == C2BufferData::LINEAR) {
                if (buffer->data().linearBlocks().size() > 1) {
                    return false;
                } else if (buffer->data().linearBlocks().empty() ||
                           buffer->data().linearBlocks().front().size() == 0) {
                    ApexCodec_Status status = ApexCodec_Buffer_setLinearBuffer(apexBuffer, nullptr);
                    if (status != APEXCODEC_STATUS_OK) {
                        LOG(ERROR) << "fillMemory -- failed to set linear buffer";
                        return false;
                    }
                    ApexCodec_Buffer_setBufferInfo(apexBuffer, flags, frameIndex, timestampUs);
                    return true;
                }
                C2ConstLinearBlock linearBlock =
                        buffer->data().linearBlocks().front();
                if (__builtin_available(android 37, *)) {
                    ApexCodec_MapFn mapFn = ::mmap;
                    ApexCodec_UnmapFn unmapFn = ::munmap;
                    if (android::media::codec::provider_->in_process_sw_codec_lfi()) {
                        mapFn = ApexCodec_GetMapFn(mApexStore, mComponentName.c_str());
                        unmapFn = ApexCodec_GetUnmapFn(mApexStore, mComponentName.c_str());
                    }
                    linearView->emplace(_C2BlockFactory::MapConstLinearWithMapper(
                            linearBlock, mapFn, unmapFn).get());
                } else {
                    linearView->emplace(linearBlock.map().get());
                }
                if ((*linearView)->error() != C2_OK) {
                    return false;
                }
                ApexCodec_LinearBuffer linear;
                linear.data = const_cast<uint8_t*>((*linearView)->data());
                linear.size = (*linearView)->capacity();
                ApexCodec_Status status = ApexCodec_Buffer_setLinearBuffer(apexBuffer, &linear);
                if (status != APEXCODEC_STATUS_OK) {
                    LOG(ERROR) << "fillMemory -- failed to set linear buffer";
                    return false;
                }
                ApexCodec_Buffer_setBufferInfo(apexBuffer, flags, frameIndex, timestampUs);
                return true;
            } else if (buffer->data().type() == C2BufferData::GRAPHIC) {
                if (buffer->data().graphicBlocks().empty()) {
                    ApexCodec_Status status = ApexCodec_Buffer_setGraphicBuffer(
                            apexBuffer, nullptr);
                    if (status != APEXCODEC_STATUS_OK) {
                        LOG(ERROR) << "fillMemory -- failed to set graphic buffer";
                        return false;
                    }
                    ApexCodec_Buffer_setBufferInfo(apexBuffer, flags, frameIndex, timestampUs);
                    return true;
                } else if (buffer->data().graphicBlocks().size() > 1) {
                    return false;
                }
                const C2Handle *handle = buffer->data().graphicBlocks().front().handle();
                uint32_t width, height, format, stride, igbp_slot, generation;
                uint64_t usage, igbp_id;
                _UnwrapNativeCodec2GrallocMetadata(
                        handle, &width, &height, &format, &usage, &stride, &generation,
                        &igbp_id, &igbp_slot);
                native_handle_t *grallocHandle = UnwrapNativeCodec2GrallocHandle(handle);
                sp<GraphicBuffer> graphicBuffer = new GraphicBuffer(
                        grallocHandle, GraphicBuffer::CLONE_HANDLE,
                        width, height, format, 1, usage, stride);
                native_handle_delete(grallocHandle);
                AHardwareBuffer *hardwareBuffer =
                    AHardwareBuffer_from_GraphicBuffer(graphicBuffer.get());
                AHardwareBuffer_acquire(hardwareBuffer);
                ApexCodec_Status status = ApexCodec_Buffer_setGraphicBuffer(
                        apexBuffer, hardwareBuffer);
                if (status != APEXCODEC_STATUS_OK) {
                    LOG(ERROR) << "fillMemory -- failed to set graphic buffer";
                    return false;
                }
                ApexCodec_Buffer_setBufferInfo(apexBuffer, flags, frameIndex, timestampUs);
                return true;
            }
        }
        return false;
    }

    ApexCodec_ComponentStore *mApexStore;
    ApexCodec_Component *mApexComponent;
    std::weak_ptr<Listener> mListener;
    std::weak_ptr<Component> mComponent;
    C2String mComponentName;

    std::thread mThread;
    std::mutex mMutex;
    std::condition_variable mCondition;
    bool mStopped;
    bool mPendingFlush;
    ApexCodec_BufferType mOutputBufferType;

    size_t mLinearBlockCapacity;
    uint32_t mWidth;
    uint32_t mHeight;
    uint32_t mFormat;

    std::shared_ptr<C2BlockPool> mBlockPool;
    std::list<std::unique_ptr<C2Work>> mWorkQueue;
    std::map<uint64_t, std::unique_ptr<C2Work>> mWorkMap;
    std::list<std::unique_ptr<C2Work>> mFlushedWork;
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
    std::shared_ptr<C2IgbaInterface> mCurrentInterface;

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
            mCurrentInterface.reset();
        }
        // TODO: integrate initial value with CCodec/CCodecBufferChannel
        mCurrent = AidlGraphicBufferAllocator::CreateLegacyGraphicBufferAllocator(
                3 /* maxDequeueCount */);
        mCurrentInterface = std::make_shared<C2IgbaInterfaceImpl>(
                c2_aidl::IGraphicBufferAllocator::fromBinder(mCurrent->asBinder()));
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

    // Returns C2IgbaInterface of the current GraphicBufferAllocator.
    std::shared_ptr<C2IgbaInterface> currentInterface() {
        std::unique_lock<std::mutex> l(mMutex);
        return mCurrentInterface;
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
            mCurrentInterface.reset();
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

Codec2Client::Codec2Client(ApexCodec_ComponentStore *base,
                           size_t serviceIndex)
      : Configurable{nullptr, "android.componentStore.apexCodecs"},
        mApexBase{base},
        mServiceIndex{serviceIndex} {
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
    if (mApexBase) {
        return createComponent_apex(name, listener, component);
    } else if (mAidlBase) {
        return createComponent_aidl(name, listener, component);
    } else {
        return createComponent_hidl(name, listener, component);
    }
}

c2_status_t Codec2Client::createComponent_apex(
        const C2String& name,
        const std::shared_ptr<Codec2Client::Listener>& listener,
        std::shared_ptr<Codec2Client::Component>* const component) {
    if (__builtin_available(android 36, *)) {
        ApexCodec_Component *apexComponent = nullptr;
        ApexCodec_Status status = ApexCodec_Component_create(
                mApexBase, name.c_str(), &apexComponent);
        if (status != APEXCODEC_STATUS_OK) {
            return (c2_status_t)status;
        }
        *component = std::make_shared<Codec2Client::Component>(apexComponent, name);
        (*component)->initApexHandler(mApexBase, name, listener, *component);
        return C2_OK;
    } else {
        return C2_OMITTED;
    }
}

c2_status_t Codec2Client::createComponent_aidl(
        const C2String& name,
        const std::shared_ptr<Codec2Client::Listener>& listener,
        std::shared_ptr<Codec2Client::Component>* const component) {
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

c2_status_t Codec2Client::createComponent_hidl(
        const C2String& name,
        const std::shared_ptr<Codec2Client::Listener>& listener,
        std::shared_ptr<Codec2Client::Component>* const component) {
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
    if (mApexBase) {
        if (__builtin_available(android 36, *)) {
            ApexCodec_Component *comp = nullptr;
            c2_status_t status =
                (c2_status_t)ApexCodec_Component_create(mApexBase, name.c_str(), &comp);
            if (status != C2_OK) {
                return status;
            }
            // interface owns |comp| and will release it in the destructor.
            interface->reset(new Codec2Client::Interface(comp, name));
            return C2_OK;
        } else {
            return C2_OMITTED;
        }
    }
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
    if (mApexBase) {
        // Not supported for APEX.
        return C2_OMITTED;
    }
    if (!mAidlBase) {
        // Only AIDL supports InputSurface.
        return C2_OMITTED;
    }
    if (!IsCodec2AidlInputSurfaceSelected()) {
        return C2_OMITTED;
    }
    std::shared_ptr<c2_aidl::IInputSurface> interface;
    ndk::ScopedAStatus status = mAidlBase->createInputSurface(&interface);
    c2_status_t c2Status = GetC2Status(status, "createInputSurface");
    if (c2Status != C2_OK) {
        LOG(ERROR) << "createInputSurface() failed: " << c2Status;
        return c2Status;
    }
    *inputSurface = std::make_shared<InputSurface>(interface);
    return C2_OK;
}

std::vector<C2Component::Traits> const& Codec2Client::listComponents() const {
    return Cache::List()[mServiceIndex].getTraits();
}

std::vector<C2Component::Traits> Codec2Client::_listComponents(
        bool* success) const {
    std::vector<C2Component::Traits> traits;
    std::string const& serviceName = getServiceName();

    if (mApexBase) {
        if (__builtin_available(android 36, *)) {
            for (size_t i = 0; ; ++i) {
                ApexCodec_ComponentTraits *apexTraits = ApexCodec_Traits_get(mApexBase, i);
                if (!apexTraits) {
                    break;
                }
                traits.emplace_back();
                C2Component::Traits& trait = traits.back();
                trait.name      = apexTraits->name;
                trait.mediaType = apexTraits->mediaType;
                trait.domain    = (C2Component::domain_t)apexTraits->domain;
                trait.kind      = (C2Component::kind_t)apexTraits->kind;
                trait.owner     = serviceName;
                trait.rank      = 16;
            }
            *success = true;
        } else {
            *success = false;
            LOG(WARNING) << "ApexCodecs not supported on Android version older than 36";
        }
        return traits;
    }
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
    struct ApexSimpleParamReflector : public C2ReflectorHelper {
        ApexSimpleParamReflector() {
            // common
            addStructDescriptor((C2ApiFeaturesSetting *)nullptr);
            addStructDescriptor((C2ComponentNameSetting *)nullptr);
            addStructDescriptor((C2ComponentKindSetting *)nullptr);
            addStructDescriptor((C2ComponentDomainSetting *)nullptr);
            addStructDescriptor((C2ComponentAttributesSetting *)nullptr);
            addStructDescriptor((C2ComponentTimeStretchTuning *)nullptr);
            addStructDescriptor((C2StreamProfileLevelInfo *)nullptr);
            addStructDescriptor((C2PortMediaTypeSetting *)nullptr);
            addStructDescriptor((C2StreamBufferTypeSetting *)nullptr);
            addStructDescriptor((C2PortRequestedDelayTuning *)nullptr);
            addStructDescriptor((C2StreamMaxReferenceAgeTuning *)nullptr);
            addStructDescriptor((C2StreamMaxReferenceCountTuning *)nullptr);
            addStructDescriptor((C2MaxPrivateBufferCountTuning *)nullptr);
            addStructDescriptor((C2PortStreamCountTuning *)nullptr);
            addStructDescriptor((C2SubscribedParamIndicesTuning *)nullptr);
            addStructDescriptor((C2PortAllocatorsTuning *)nullptr);
            addStructDescriptor((C2PortBlockPoolsTuning *)nullptr);
            addStructDescriptor((C2StreamBitrateInfo *)nullptr);
            addStructDescriptor((C2StreamMaxBufferSizeInfo *)nullptr);

            // audio
            addStructDescriptor((C2StreamSampleRateInfo *)nullptr);
            addStructDescriptor((C2StreamChannelCountInfo *)nullptr);
            addStructDescriptor((C2StreamMaxChannelCountInfo *)nullptr);
            addStructDescriptor((C2StreamChannelMaskInfo *)nullptr);
            addStructDescriptor((C2StreamPcmEncodingInfo *)nullptr);
            addStructDescriptor((C2StreamAacPackagingInfo *)nullptr);
            addStructDescriptor((C2StreamAacSbrModeTuning *)nullptr);
            addStructDescriptor((C2StreamDrcCompressionModeTuning *)nullptr);
            addStructDescriptor((C2StreamDrcTargetReferenceLevelTuning *)nullptr);
            addStructDescriptor((C2StreamDrcEncodedTargetLevelTuning *)nullptr);
            addStructDescriptor((C2StreamDrcBoostFactorTuning *)nullptr);
            addStructDescriptor((C2StreamDrcAttenuationFactorTuning *)nullptr);
            addStructDescriptor((C2StreamDrcEffectTypeTuning *)nullptr);
            addStructDescriptor((C2StreamDrcAlbumModeTuning *)nullptr);
            addStructDescriptor((C2StreamDrcOutputLoudnessTuning *)nullptr);
            addStructDescriptor((C2StreamAudioFrameSizeInfo *)nullptr);
            addStructDescriptor((C2AudioPresentationIdTuning *)nullptr);
        }
    };
    if (mApexBase) {
        return std::make_shared<ApexSimpleParamReflector>();
    }
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

    if (__builtin_available(android 36, *)) {
        if (android::media::codec::provider_->in_process_sw_audio_codec_support()
                && nullptr != ApexCodec_GetComponentStore()) {
            names.push_back("__ApexCodecs__");
        }
    }

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

    if (name == "__ApexCodecs__") {
        if (__builtin_available(android 36, *)) {
            return std::make_shared<Codec2Client>(ApexCodec_GetComponentStore(), index);
        } else {
            LOG(FATAL) << "ApexCodecs not supported on Android version older than 36";
        }
    } else if (c2_aidl::utils::IsSelected()) {
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
    if (!IsCodec2AidlInputSurfaceSelected()) {
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

std::shared_ptr<Codec2Client::InputSurface> Codec2Client::CreateInputSurfaceFromInterface(
        const ::ndk::SpAIBinder &interface) {
    return std::make_shared<Codec2Client::InputSurface>(
            c2_aidl::IInputSurface::fromBinder(interface));
}

bool Codec2Client::IsAidlSelected() {
    return c2_aidl::utils::IsSelected();
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

Codec2Client::Interface::Interface(
        ApexCodec_Component *base, const C2String &name)
      : Configurable{[base]() -> ApexCodec_Configurable * {
            if (__builtin_available(android 36, *)) {
                return ApexCodec_Component_getConfigurable(base);
            } else {
                return nullptr;
            }
        }(), name},
        mApexBase{base} {
}

Codec2Client::Interface::~Interface() {
    if (mApexBase) {
        if (__builtin_available(android 36, *)) {
            ApexCodec_Component_destroy(mApexBase);
        }
        mApexBase = nullptr;
    }
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
        if (mMap.erase(seq) > 0) {
            AIBinder_unlinkToDeath(base->asBinder().get(), mDeathRecipient.get(), (void *)seq);
        }
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

Codec2Client::Component::Component(ApexCodec_Component *base, const C2String &name)
      : Configurable{[base]() -> ApexCodec_Configurable * {
            if (__builtin_available(android 36, *)) {
                return ApexCodec_Component_getConfigurable(base);
            } else {
                return nullptr;
            }
        }(), name},
        mApexBase{base} {
}

Codec2Client::Component::~Component() {
    if (mAidlDeathSeq) {
        GetAidlDeathManager()->unlinkToDeath(*mAidlDeathSeq, mAidlBase);
    }
    if (mApexBase) {
        if (__builtin_available(android 36, *)) {
            ApexCodec_Component_destroy(mApexBase);
        }
        mApexBase = nullptr;
    }
}

c2_status_t Codec2Client::Component::createBlockPool(
        C2Allocator::id_t id,
        C2BlockPool::local_id_t* blockPoolId,
        std::shared_ptr<Codec2Client::Configurable>* configurable) {
    if (mApexBase) {
        std::shared_ptr<C2BlockPool> blockPool;
        CreateCodec2BlockPool(id, nullptr, &blockPool);
        *blockPoolId = blockPool->getLocalId();
        *configurable = nullptr;
        mBlockPools[*blockPoolId] = blockPool;
        return C2_OK;
    }
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
    if (mApexBase) {
        mBlockPools.erase(localId);
        return C2_OK;
    }
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
    if (mApexBase) {
        // no-op
        return;
    } else if (mAidlBase) {
        holdIgbaBlocks(workItems);
    } else {
        // Output bufferqueue-based blocks' lifetime management
        mOutputBufferQueue->holdBufferQueueBlocks(workItems);
    }
}

c2_status_t Codec2Client::Component::queue(
        std::list<std::unique_ptr<C2Work>>* const items) {
    if (mApexBase) {
        mApexHandler->queue(*items);
        return C2_OK;
    }
    if (mAidlBase) {
        c2_aidl::WorkBundle workBundle;
        {
            ScopedTrace trace(ATRACE_TAG, "CCodec::Codec2Client::ToAidl");
            if (!c2_aidl::utils::ToAidl(&workBundle, *items, mAidlBufferPoolSender.get())) {
                LOG(ERROR) << "queue -- bad input.";
                return C2_TRANSACTION_FAILED;
            }
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
    if (mApexBase) {
        if (__builtin_available(android 36, *)) {
            mApexHandler->flush(flushedWork);
            return C2_OK;
        } else {
            return C2_OMITTED;
        }
    }
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
    if (mApexBase) {
        return C2_OMITTED;
    }
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
    if (mApexBase) {
        mApexHandler->start();
        return C2_OK;
    }
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
    if (mApexBase) {
        return mApexHandler->stop();
    }
    if (mAidlBase) {
        std::shared_ptr<AidlGraphicBufferAllocator> gba =
                mGraphicBufferAllocators->current();
        if (gba) {
            gba->onRequestStop();
        }
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
    if (mApexBase) {
        // ApexHandler::stop() resets the underlying component
        mApexHandler->stop();
        // stop() may return C2_BAD_STATE, but it's OK.
        return C2_OK;
    }
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
    if (mApexBase) {
        // ApexHandler::stop() resets the underlying component
        mApexHandler->stop();
        // stop() may return C2_BAD_STATE, but it's OK.
        return C2_OK;
    }
    if (mAidlBase) {
        std::shared_ptr<AidlGraphicBufferAllocator> gba =
                mGraphicBufferAllocators->current();
        if (gba) {
            gba->onRequestStop();
        }
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
    if (mApexBase) {
        // tunneling is not supported in APEX
        return C2_OMITTED;
    }
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
    if (mApexBase) {
        return C2_OMITTED;
    }
    if (mAidlBase) {
        std::shared_ptr<AidlGraphicBufferAllocator> gba =
              mGraphicBufferAllocators->current();
        if (!gba) {
            LOG(ERROR) << "setOutputSurface for AIDL -- "
                       "GraphicBufferAllocator was not created.";
            return C2_CORRUPTED;
        }
        // Note: Consumer usage is set ahead of the HAL allocator(gba) being set.
        // This is same as HIDL.
        uint64_t consumerUsage = configConsumerUsage(surface);
        bool ret = gba->configure(surface, generation, maxDequeueCount);
        ALOGD("setOutputSurface -- generation=%u consumer usage=%#llx",
              generation, (long long)consumerUsage);
        return ret ? C2_OK : C2_CORRUPTED;
    }
    uint64_t bqId = 0;

    std::scoped_lock lock(mOutputMutex);
    std::shared_ptr<SurfaceSyncObj> syncObj;

    if (!surface) {
        mOutputBufferQueue->configure(nullptr, generation, 0, maxDequeueCount, nullptr);
    } else if (surface->getUniqueId(&bqId) != OK) {
        LOG(ERROR) << "setOutputSurface -- "
                   "cannot obtain bufferqueue id.";
        bqId = 0;
        mOutputBufferQueue->configure(nullptr, generation, 0, maxDequeueCount, nullptr);
    } else {
        mOutputBufferQueue->configure(surface, generation, bqId, maxDequeueCount,
                                      mHidlBase1_2 ? &syncObj : nullptr);
    }

    uint64_t consumerUsage = configConsumerUsage(surface);
    ALOGD("setOutputSurface -- generation=%u consumer usage=%#llx%s",
          generation, (long long)consumerUsage, syncObj ? " sync" : "");

    sp<HGraphicBufferProducer2> hgbp = bqId == 0 ? nullptr : mOutputBufferQueue->getHgbp();
    Return<c2_hidl::Status> transStatus =
            syncObj ? mHidlBase1_2->setOutputSurfaceWithSyncObj(static_cast<uint64_t>(blockPoolId),
                                                                hgbp, *syncObj)
                    : mHidlBase1_0->setOutputSurface(static_cast<uint64_t>(blockPoolId), hgbp);

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
    ScopedTrace trace(ATRACE_TAG,"CCodec::Codec2Client::Component::queueToOutputSurface");
    if (mApexBase) {
        return C2_OMITTED;
    }
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

uint64_t Codec2Client::Component::configConsumerUsage(
        const sp<IGraphicBufferProducer>& surface) {
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
    return consumerUsage;
}

void Codec2Client::Component::pollForRenderedFrames(FrameEventHistoryDelta* delta) {
    if (mApexBase) {
        return;
    }
    if (mAidlBase) {
        std::shared_ptr<AidlGraphicBufferAllocator> gba =
                mGraphicBufferAllocators->current();
        if (gba) {
            gba->pollForRenderedFrames(delta);
        }
        return;
    }
    mOutputBufferQueue->pollForRenderedFrames(delta);
}

void Codec2Client::Component::setOutputSurfaceMaxDequeueCount(
        int maxDequeueCount) {
    if (mApexBase) {
        return;
    }
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
    if (mApexBase) {
        return;
    }
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
    if (mApexBase) {
        return;
    }
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

void Codec2Client::Component::onBufferAttachedToOutputSurface(
        uint32_t generation) {
    if (mApexBase) {
        return;
    }
    if (mAidlBase) {
        std::shared_ptr<AidlGraphicBufferAllocator> gba =
                mGraphicBufferAllocators->current();
        if (gba) {
            gba->onBufferAttached(generation);
        }
        return;
    }
    mOutputBufferQueue->onBufferAttached(generation);
}

void Codec2Client::Component::onBufferDetachedFromOutputSurface(uint32_t generation,
                                                                uint64_t bufferId) {
    (void)generation;
    (void)bufferId;
}

void Codec2Client::Component::onBuffersRemovedFromOutputSurface(
        uint32_t generation, const std::vector<uint64_t>& removedBufferIds) {
    (void)generation;
    (void)removedBufferIds;
}

void Codec2Client::Component::holdIgbaBlocks(
        const std::list<std::unique_ptr<C2Work>>& workList) {
    if (!mAidlBase) {
        return;
    }
    std::shared_ptr<C2IgbaInterface> igbaIntf = mGraphicBufferAllocators->currentInterface();
    if (!igbaIntf) {
        return;
    }
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
                        _C2BlockFactory::RegisterIgba(poolData, igbaIntf);
                    }
                }
            }
        }
    }
}

Codec2Client::Component::AidlDeathManager *Codec2Client::Component::GetAidlDeathManager() {
    // This object never gets destructed
    static AidlDeathManager *sManager = new AidlDeathManager();
    return sManager;
}

c2_status_t Codec2Client::Component::initApexHandler(
            ApexCodec_ComponentStore *store,
            const C2String &name,
            const std::shared_ptr<Listener> &listener,
            const std::shared_ptr<Component> &comp) {
    if (!mApexBase) {
        return C2_BAD_STATE;
    }
    if (!store) {
        return C2_BAD_VALUE;
    }
    mApexHandler = std::make_unique<ApexHandler>(store, comp->mApexBase, name, listener, comp);
    return C2_OK;
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
Codec2Client::InputSurface::InputSurface(const std::shared_ptr<c2_aidl::IInputSurface>& base)
      : Configurable{
            [base]() -> std::shared_ptr<c2_aidl::IConfigurable> {
                std::shared_ptr<c2_aidl::IConfigurable> aidlConfigurable;
                ::ndk::ScopedAStatus transStatus =
                    base->getConfigurable(&aidlConfigurable);
                return transStatus.isOk() ? aidlConfigurable : nullptr;
            }()
        },
        mBase{base}, mNativeWindow{nullptr} {
}

ANativeWindow *Codec2Client::InputSurface::getNativeWindow() {
    std::call_once(mWindowInitOnce, [this]() {
        ::aidl::android::view::Surface surface;
        ::ndk::ScopedAStatus transStatus = mBase->getSurface(&surface);
        c2_status_t c2Status = GetC2Status(transStatus, "InputSurface::getNativeWindow");
        if (c2Status != C2_OK) {
            LOG(ERROR) << "InputSurface::getNativeWindow -- cannot get window: " << c2Status;
            return;
        }
        mNativeWindow = surface.release();
    });
    return mNativeWindow;
}

::ndk::SpAIBinder Codec2Client::InputSurface::getHalInterface() const {
    return mBase ? mBase->asBinder() : nullptr;
}

c2_status_t Codec2Client::InputSurface::connect(
        const std::shared_ptr<Codec2Client::Component> &comp,
        std::shared_ptr<Connection> *connection) {
    if (!comp) {
        LOG(ERROR) << "InputSurface:connect, component invalid";
        return C2_BAD_VALUE;
    }
    std::shared_ptr<Codec2Client::Component::AidlBase> aidlBase = comp->mAidlBase;
    if (!aidlBase) {
        LOG(ERROR) << "InputSurface:connect, component invalid";
        return C2_BAD_VALUE;
    }
    std::shared_ptr<c2_aidl::IInputSink> sink;
    ::ndk::ScopedAStatus transResult = aidlBase->asInputSink(&sink);
    if (GetC2Status(transResult, "InputSurface:Component:asInputSink") != C2_OK) {
        LOG(ERROR) << "InputSurface:connect sink conversion failed";
        return C2_CORRUPTED;
    }
    if (!mBase) {
        LOG(ERROR) << "InputSurface:connect failed, no valid base";
        return C2_CORRUPTED;
    }
    std::shared_ptr<ConnectionBase> base;
    transResult = mBase->connect(sink, &base);
    c2_status_t c2Status = GetC2Status(transResult, "InputSurface:connect");
    if (c2Status != C2_OK) {
        LOG(ERROR) << "IInputSurface:connect failed: " << c2Status;
        return c2Status;
    }
    *connection = std::make_shared<Connection>(base);
    return C2_OK;
}

// Codec2Client::InputSurfaceConnection
Codec2Client::InputSurfaceConnection::InputSurfaceConnection(
        const std::shared_ptr<c2_aidl::IInputSurfaceConnection>& base) : mBase{base} {
}

c2_status_t Codec2Client::InputSurfaceConnection::disconnect() {
    if (!mBase) {
        LOG(ERROR) << "InputSurfaceConnection:disconnect failed, no valid base";
        return C2_CORRUPTED;
    }
    ::ndk::ScopedAStatus transResult = mBase->disconnect();
    return GetC2Status(transResult, "InputSurfaceConnection::disconnect");
}

c2_status_t Codec2Client::InputSurfaceConnection::signalEos() {
    if (!mBase) {
        LOG(ERROR) << "InputSurfaceConnection:signalEos failed, no valid base";
        return C2_CORRUPTED;
    }
    ::ndk::ScopedAStatus transResult = mBase->signalEndOfStream();
    return GetC2Status(transResult, "InputSurfaceConnection::signalEndOfStream");
}

c2_status_t Codec2Client::InputSurfaceConnection::notifiesInputBufferDoneToClient(
        bool* inputBufferDone) {
    if (!mBase) {
        LOG(ERROR)
                << "InputSurfaceConnection:notifiesInputBufferDoneToClient failed, no valid base";
        return C2_CORRUPTED;
    }
    ::ndk::ScopedAStatus transResult = mBase->notifiesInputBufferDoneToClient(inputBufferDone);
    return GetC2Status(transResult, "InputSurfaceConnection::notifiesInputBufferDoneToClient");
}

}  // namespace android
