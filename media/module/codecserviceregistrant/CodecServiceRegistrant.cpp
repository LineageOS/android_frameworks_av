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
#define LOG_TAG "CodecServiceRegistrant"

#include <android/api-level.h>
#include <android-base/logging.h>
#include <android-base/properties.h>
#include <android-base/stringprintf.h>

#include <C2Component.h>
#include <C2PlatformSupport.h>

#include <android/hidl/manager/1.2/IServiceManager.h>
#include <codec2/hidl/1.0/ComponentStore.h>
#include <codec2/hidl/1.1/ComponentStore.h>
#include <codec2/hidl/1.2/ComponentStore.h>
#include <codec2/hidl/1.2/Configurable.h>
#include <codec2/hidl/1.2/types.h>
#include <hidl/HidlSupport.h>
#include <hidl/HidlTransportSupport.h>

#include <android/binder_interface_utils.h>
#include <android/binder_manager.h>
#include <android/binder_process.h>
#include <codec2/aidl/ComponentStore.h>
#include <codec2/aidl/ParamTypes.h>

#include <media/CodecServiceRegistrant.h>

namespace /* unnamed */ {

using ::android::hardware::hidl_vec;
using ::android::hardware::hidl_string;
using ::android::hardware::Return;
using ::android::sp;
using ::ndk::ScopedAStatus;
namespace c2_hidl = ::android::hardware::media::c2::V1_2;
namespace c2_aidl = ::aidl::android::hardware::media::c2;

constexpr c2_status_t C2_TRANSACTION_FAILED = C2_CORRUPTED;

// Converter from IComponentStore to C2ComponentStore.
class H2C2ComponentStore : public C2ComponentStore {
protected:
    using HidlComponentStore =
        ::android::hardware::media::c2::V1_0::IComponentStore;
    using HidlConfigurable =
        ::android::hardware::media::c2::V1_0::IConfigurable;
    sp<HidlComponentStore> mHidlStore;
    sp<HidlConfigurable> mHidlConfigurable;

    using AidlComponentStore =
        ::aidl::android::hardware::media::c2::IComponentStore;
    using AidlConfigurable =
        ::aidl::android::hardware::media::c2::IConfigurable;
    std::shared_ptr<AidlComponentStore> mAidlStore;
    std::shared_ptr<AidlConfigurable> mAidlConfigurable;
public:
    explicit H2C2ComponentStore(nullptr_t) {
    }

    explicit H2C2ComponentStore(sp<HidlComponentStore> const& store)
          : mHidlStore{store},
            mHidlConfigurable{[store]() -> sp<HidlConfigurable>{
                if (!store) {
                    return nullptr;
                }
                Return<sp<HidlConfigurable>> transResult =
                    store->getConfigurable();
                return transResult.isOk() ?
                        static_cast<sp<HidlConfigurable>>(transResult) :
                        nullptr;
            }()} {
        if (!mHidlConfigurable) {
            LOG(ERROR) << "Preferred store is corrupted.";
        }
    }

    explicit H2C2ComponentStore(std::shared_ptr<AidlComponentStore> const& store)
          : mAidlStore{store},
            mAidlConfigurable{[store]() -> std::shared_ptr<AidlConfigurable>{
                if (!store) {
                    return nullptr;
                }
                std::shared_ptr<AidlConfigurable> configurable;
                ScopedAStatus status = store->getConfigurable(&configurable);
                if (!status.isOk()) {
                    return nullptr;
                }
                return configurable;
            }()} {
        if (!mAidlConfigurable) {
            LOG(ERROR) << "Preferred store is corrupted.";
        }
    }

    virtual ~H2C2ComponentStore() override = default;

    c2_status_t config_sm(
            std::vector<C2Param*> const &params,
            std::vector<std::unique_ptr<C2SettingResult>>* const failures
            ) override {
        if (mAidlStore) {
            return config_sm_aidl(params, failures);
        } else if (mHidlStore) {
            return config_sm_hidl(params, failures);
        } else {
            return C2_OMITTED;
        }
    }

    c2_status_t config_sm_aidl(
            std::vector<C2Param*> const &params,
            std::vector<std::unique_ptr<C2SettingResult>>* const failures
            ) {
        c2_aidl::Params aidlParams;
        if (!c2_aidl::utils::CreateParamsBlob(&aidlParams, params)) {
            LOG(ERROR) << "config -- bad input.";
            return C2_TRANSACTION_FAILED;
        }
        c2_status_t status = C2_OK;
        c2_aidl::IConfigurable::ConfigResult configResult;
        ScopedAStatus transResult = mAidlConfigurable->config(
                aidlParams, true, &configResult);
        if (!transResult.isOk()) {
            if (transResult.getExceptionCode() == EX_SERVICE_SPECIFIC) {
                status = c2_status_t(transResult.getServiceSpecificError());
                if (status != C2_BAD_INDEX) {
                    LOG(DEBUG) << "config -- call failed: "
                               << status << ".";
                }
            } else {
                LOG(ERROR) << "config -- transaction failed.";
                return C2_TRANSACTION_FAILED;
            }
        }
        status = static_cast<c2_status_t>(configResult.status.status);
        if (status != C2_BAD_INDEX) {
            LOG(DEBUG) << "config -- call failed: "
                       << status << ".";
        }
        size_t i = failures->size();
        failures->resize(i + configResult.failures.size());
        for (const c2_aidl::SettingResult& sf : configResult.failures) {
            if (!c2_aidl::utils::FromAidl(&(*failures)[i++], sf)) {
                LOG(ERROR) << "config -- "
                           << "invalid SettingResult returned.";
                status = C2_CORRUPTED;
            }
        }
        if (!c2_aidl::utils::UpdateParamsFromBlob(params, configResult.params)) {
            LOG(ERROR) << "config -- "
                       << "failed to parse returned params.";
            status = C2_CORRUPTED;
        }
        return status;
    };

    c2_status_t config_sm_hidl(
            std::vector<C2Param*> const &params,
            std::vector<std::unique_ptr<C2SettingResult>>* const failures
            ) {
        c2_hidl::Params hidlParams;
        if (!c2_hidl::utils::createParamsBlob(&hidlParams, params)) {
            LOG(ERROR) << "config -- bad input.";
            return C2_TRANSACTION_FAILED;
        }
        c2_status_t status{};
        Return<void> transResult = mHidlConfigurable->config(
                hidlParams,
                true,
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
        if (!transResult.isOk()) {
            LOG(ERROR) << "config -- transaction failed.";
            return C2_TRANSACTION_FAILED;
        }
        return status;
    };

    c2_status_t copyBuffer(
            std::shared_ptr<C2GraphicBuffer>,
            std::shared_ptr<C2GraphicBuffer>) override {
        LOG(ERROR) << "copyBuffer -- not supported.";
        return C2_OMITTED;
    }

    c2_status_t createComponent(
            C2String, std::shared_ptr<C2Component> *const component) override {
        component->reset();
        LOG(ERROR) << "createComponent -- not supported.";
        return C2_OMITTED;
    }

    c2_status_t createInterface(
            C2String, std::shared_ptr<C2ComponentInterface> *const interface) override {
        interface->reset();
        LOG(ERROR) << "createInterface -- not supported.";
        return C2_OMITTED;
    }

    c2_status_t query_sm(
            const std::vector<C2Param *> &stackParams,
            const std::vector<C2Param::Index> &heapParamIndices,
            std::vector<std::unique_ptr<C2Param>> *const heapParams) const override {
        if (mAidlStore) {
            return query_sm_aidl(stackParams, heapParamIndices, heapParams);
        } else if (mHidlStore) {
            return query_sm_hidl(stackParams, heapParamIndices, heapParams);
        } else {
            return C2_OMITTED;
        }
    }

    static c2_status_t UpdateQueryResult(
            const std::vector<C2Param *> &paramPointers,
            size_t numStackIndices,
            const std::vector<C2Param *> &stackParams,
            std::vector<std::unique_ptr<C2Param>> *const heapParams) {
        c2_status_t status = C2_OK;
        size_t i = 0;
        for (auto it = paramPointers.begin(); it != paramPointers.end(); ) {
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
                    break;
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
        return status;
    }

    c2_status_t query_sm_aidl(
            const std::vector<C2Param *> &stackParams,
            const std::vector<C2Param::Index> &heapParamIndices,
            std::vector<std::unique_ptr<C2Param>> *const heapParams) const {
        std::vector<int32_t> indices;
        size_t numIndices = 0;
        for (C2Param* const& stackParam : stackParams) {
            if (!stackParam) {
                LOG(WARNING) << "query -- null stack param encountered.";
                continue;
            }
            indices[numIndices++] = stackParam->index();
        }
        size_t numStackIndices = numIndices;
        for (const C2Param::Index& index : heapParamIndices) {
            indices[numIndices++] = static_cast<uint32_t>(index);
        }
        indices.resize(numIndices);
        if (heapParams) {
            heapParams->reserve(heapParams->size() + numIndices);
        }
        c2_status_t status = C2_OK;
        c2_aidl::IConfigurable::QueryResult aidlResult;
        ScopedAStatus transResult = mAidlConfigurable->query(indices, true, &aidlResult);
        if (!transResult.isOk()) {
            if (transResult.getExceptionCode() == EX_SERVICE_SPECIFIC) {
                status = c2_status_t(transResult.getServiceSpecificError());
                LOG(DEBUG) << "query -- call failed: " << status << ".";
                return status;
            } else {
                LOG(ERROR) << "query -- transaction failed.";
                return C2_TRANSACTION_FAILED;
            }
        }
        status = static_cast<c2_status_t>(aidlResult.status.status);
        if (status != C2_OK) {
            LOG(DEBUG) << "query -- call failed: " << status << ".";
        }
        std::vector<C2Param*> paramPointers;
        if (!c2_aidl::utils::ParseParamsBlob(&paramPointers, aidlResult.params)) {
            LOG(ERROR) << "query -- error while parsing params.";
            return C2_CORRUPTED;
        }
        return UpdateQueryResult(paramPointers, numStackIndices, stackParams, heapParams);
    }

    c2_status_t query_sm_hidl(
            const std::vector<C2Param *> &stackParams,
            const std::vector<C2Param::Index> &heapParamIndices,
            std::vector<std::unique_ptr<C2Param>> *const heapParams) const {
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
        Return<void> transResult = mHidlConfigurable->query(
                indices,
                true,
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
                    status = UpdateQueryResult(
                            paramPointers, numStackIndices, stackParams, heapParams);
                });
        if (!transResult.isOk()) {
            LOG(ERROR) << "query -- transaction failed.";
            return C2_TRANSACTION_FAILED;
        }
        return status;
    }

    c2_status_t querySupportedParams_nb(
            std::vector<std::shared_ptr<C2ParamDescriptor>> *const params) const override {
        if (mAidlStore) {
            return querySupportedParams_nb_aidl(params);
        } else if (mHidlStore) {
            return querySupportedParams_nb_hidl(params);
        } else {
            return C2_OMITTED;
        }
    }

    c2_status_t querySupportedParams_nb_aidl(
            std::vector<std::shared_ptr<C2ParamDescriptor>> *const params) const {
        c2_status_t status = C2_OK;
        std::vector<c2_aidl::ParamDescriptor> aidlParams;
        ScopedAStatus transResult = mAidlConfigurable->querySupportedParams(
                std::numeric_limits<uint32_t>::min(),
                std::numeric_limits<uint32_t>::max(),
                &aidlParams);
        if (!transResult.isOk()) {
            if (transResult.getExceptionCode() == EX_SERVICE_SPECIFIC) {
                status = c2_status_t(transResult.getServiceSpecificError());
                LOG(DEBUG) << "querySupportedParams -- call failed: "
                           << status << ".";
                return status;
            } else {
                LOG(ERROR) << "querySupportedParams -- transaction failed.";
                return C2_TRANSACTION_FAILED;
            }
        }

        size_t i = params->size();
        params->resize(i + aidlParams.size());
        for (const c2_aidl::ParamDescriptor& sp : aidlParams) {
            if (!c2_aidl::utils::FromAidl(&(*params)[i++], sp)) {
                LOG(ERROR) << "querySupportedParams -- "
                           << "invalid returned ParamDescriptor.";
                break;
            }
        }
        return status;
    }

    c2_status_t querySupportedParams_nb_hidl(
            std::vector<std::shared_ptr<C2ParamDescriptor>> *const params) const {
        c2_status_t status;
        Return<void> transResult = mHidlConfigurable->querySupportedParams(
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
        if (!transResult.isOk()) {
            LOG(ERROR) << "querySupportedParams -- transaction failed.";
            return C2_TRANSACTION_FAILED;
        }
        return status;
    }

    c2_status_t querySupportedValues_sm(
            std::vector<C2FieldSupportedValuesQuery> &fields) const override {
        if (mAidlStore) {
            return querySupportedValues_sm_aidl(fields);
        } else if (mHidlStore) {
            return querySupportedValues_sm_hidl(fields);
        } else {
            return C2_OMITTED;
        }
    }

    c2_status_t querySupportedValues_sm_aidl(
            std::vector<C2FieldSupportedValuesQuery> &fields) const {
        std::vector<c2_aidl::FieldSupportedValuesQuery> aidlFields(fields.size());
        for (size_t i = 0; i < fields.size(); ++i) {
            if (!c2_aidl::utils::ToAidl(&aidlFields[i], fields[i])) {
                LOG(ERROR) << "querySupportedValues -- bad input";
                return C2_TRANSACTION_FAILED;
            }
        }

        c2_status_t status = C2_OK;
        c2_aidl::IConfigurable::QuerySupportedValuesResult queryResult;
        ScopedAStatus transResult = mAidlConfigurable->querySupportedValues(
                aidlFields, true, &queryResult);
        if (!transResult.isOk()) {
            if (transResult.getExceptionCode() == EX_SERVICE_SPECIFIC) {
                status = c2_status_t(transResult.getServiceSpecificError());
                LOG(DEBUG) << "querySupportedValues -- call failed: "
                           << status << ".";
                return status;
            } else {
                LOG(ERROR) << "querySupportedValues -- transaction failed.";
                return C2_TRANSACTION_FAILED;
            }
        }
        status = static_cast<c2_status_t>(queryResult.status.status);
        if (status != C2_OK) {
            LOG(DEBUG) << "querySupportedValues -- call failed: "
                       << status << ".";
        }
        if (queryResult.values.size() != fields.size()) {
            LOG(ERROR) << "querySupportedValues -- "
                          "input and output lists "
                          "have different sizes.";
            return C2_CORRUPTED;
        }
        for (size_t i = 0; i < fields.size(); ++i) {
            if (!c2_aidl::utils::FromAidl(&fields[i], aidlFields[i], queryResult.values[i])) {
                LOG(ERROR) << "querySupportedValues -- "
                              "invalid returned value.";
                return C2_CORRUPTED;
            }
        }
        return status;
    }

    c2_status_t querySupportedValues_sm_hidl(
            std::vector<C2FieldSupportedValuesQuery> &fields) const {
        hidl_vec<c2_hidl::FieldSupportedValuesQuery> inFields(fields.size());
        for (size_t i = 0; i < fields.size(); ++i) {
            if (!c2_hidl::utils::objcpy(&inFields[i], fields[i])) {
                LOG(ERROR) << "querySupportedValues -- bad input";
                return C2_TRANSACTION_FAILED;
            }
        }

        c2_status_t status;
        Return<void> transResult = mHidlConfigurable->querySupportedValues(
                inFields,
                true,
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
        if (!transResult.isOk()) {
            LOG(ERROR) << "querySupportedValues -- transaction failed.";
            return C2_TRANSACTION_FAILED;
        }
        return status;
    }

    C2String getName() const override {
        C2String outName = "(unknown)";
        if (mAidlStore) {
            ScopedAStatus transResult = mAidlConfigurable->getName(&outName);
            if (!transResult.isOk()) {
                LOG(ERROR) << "getName -- transaction failed.";
            }
        } else if (mHidlStore) {
            Return<void> transResult = mHidlConfigurable->getName(
                    [&outName](const hidl_string& name) {
                        outName = name.c_str();
                    });
            if (!transResult.isOk()) {
                LOG(ERROR) << "getName -- transaction failed.";
            }
        }
        return outName;
    }

    virtual std::shared_ptr<C2ParamReflector> getParamReflector() const override {
        struct SimpleParamReflector : public C2ParamReflector {
            std::unique_ptr<C2StructDescriptor> describe(
                    C2Param::CoreIndex coreIndex) const override {
                if (mAidlBase) {
                    return describe_aidl(coreIndex);
                } else if (mHidlBase) {
                    return describe_hidl(coreIndex);
                } else {
                    return nullptr;
                }
            }

            std::unique_ptr<C2StructDescriptor> describe_aidl(
                    C2Param::CoreIndex coreIndex) const {
                std::vector<int32_t> indices(1);
                indices[0] = coreIndex.coreIndex();
                std::unique_ptr<C2StructDescriptor> descriptor;
                std::vector<c2_aidl::StructDescriptor> aidlDescs;
                ScopedAStatus transResult = mAidlBase->getStructDescriptors(
                        indices, &aidlDescs);
                if (!transResult.isOk()) {
                    c2_status_t status = C2_TRANSACTION_FAILED;
                    if (transResult.getExceptionCode() == EX_SERVICE_SPECIFIC) {
                        status = c2_status_t(transResult.getServiceSpecificError());
                        LOG(DEBUG) << "SimpleParamReflector -- "
                                      "getStructDescriptors() failed: "
                                   << status << ".";
                        return nullptr;
                    }
                }
                if (aidlDescs.size() != 1) {
                    LOG(DEBUG) << "SimpleParamReflector -- "
                                  "getStructDescriptors() "
                                  "returned vector of size "
                               << aidlDescs.size() << ". "
                                  "It should be 1.";
                    return nullptr;
                }
                if (!c2_aidl::utils::FromAidl(&descriptor, aidlDescs[0])) {
                    LOG(DEBUG) << "SimpleParamReflector -- "
                                  "getStructDescriptors() returned "
                                  "corrupted data.";
                    return nullptr;
                }
                return descriptor;
            }

            std::unique_ptr<C2StructDescriptor> describe_hidl(
                    C2Param::CoreIndex coreIndex) const {
                hidl_vec<c2_hidl::ParamIndex> indices(1);
                indices[0] = static_cast<c2_hidl::ParamIndex>(coreIndex.coreIndex());
                std::unique_ptr<C2StructDescriptor> descriptor;
                Return<void> transResult = mHidlBase->getStructDescriptors(
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
                return descriptor;
            }

            explicit SimpleParamReflector(const sp<HidlComponentStore> &base)
                : mHidlBase(base) { }

            explicit SimpleParamReflector(const std::shared_ptr<AidlComponentStore> &base)
                : mAidlBase(base) { }

            std::shared_ptr<AidlComponentStore> mAidlBase;
            sp<HidlComponentStore> mHidlBase;
        };

        if (mAidlStore) {
            return std::make_shared<SimpleParamReflector>(mAidlStore);
        } else if (mHidlStore) {
            return std::make_shared<SimpleParamReflector>(mHidlStore);
        } else {
            return nullptr;
        }
    }

    virtual std::vector<std::shared_ptr<const C2Component::Traits>>
            listComponents() override {
        LOG(ERROR) << "listComponents -- not supported.";
        return {};
    }
};

bool ionPropertiesDefined() {
    using namespace ::android::base;
    std::string heapMask =
        GetProperty("ro.com.android.media.swcodec.ion.heapmask", "undefined");
    std::string flags =
        GetProperty("ro.com.android.media.swcodec.ion.flags", "undefined");
    std::string align =
        GetProperty("ro.com.android.media.swcodec.ion.align", "undefined");
    if (heapMask != "undefined" ||
            flags != "undefined" ||
            align != "undefined") {
        LOG(INFO)
                << "Some system properties for mediaswcodec ION usage are set: "
                << "heapmask = " << heapMask << ", "
                << "flags = " << flags << ", "
                << "align = " << align << ". "
                << "Preferred Codec2 store is defaulted to \"software\".";
        return true;
    }
    return false;
}

} // unnamed namespace

extern "C" void RegisterCodecServices() {
    const bool aidlSelected = c2_aidl::utils::IsSelected();
    constexpr int kThreadCount = 64;
    ABinderProcess_setThreadPoolMaxThreadCount(kThreadCount);
    ABinderProcess_startThreadPool();
    ::android::hardware::configureRpcThreadpool(kThreadCount, false);

    LOG(INFO) << "Creating software Codec2 service...";
    std::shared_ptr<C2ComponentStore> store =
        android::GetCodec2PlatformComponentStore();
    if (!store) {
        LOG(ERROR) << "Failed to create Codec2 service.";
        return;
    }

    using namespace ::android::hardware::media::c2;

    int platformVersion = android_get_device_api_level();
    // STOPSHIP: Remove code name checking once platform version bumps up to 35.
    std::string codeName =
        android::base::GetProperty("ro.build.version.codename", "");
    if (codeName == "VanillaIceCream") {
        platformVersion = __ANDROID_API_V__;
    }

    android::sp<V1_0::IComponentStore> hidlStore;
    std::shared_ptr<c2_aidl::IComponentStore> aidlStore;
    const char *hidlVer = "(unknown)";
    if (aidlSelected) {
        aidlStore = ::ndk::SharedRefBase::make<c2_aidl::utils::ComponentStore>(store);
    } else if (platformVersion >= __ANDROID_API_S__) {
        hidlStore = ::android::sp<V1_2::utils::ComponentStore>::make(store);
        hidlVer = "1.2";
    } else if (platformVersion == __ANDROID_API_R__) {
        hidlStore = ::android::sp<V1_1::utils::ComponentStore>::make(store);
        hidlVer = "1.1";
    } else if (platformVersion == __ANDROID_API_Q__) {
        hidlStore = ::android::sp<V1_0::utils::ComponentStore>::make(store);
        hidlVer = "1.0";
    } else {  // platformVersion < __ANDROID_API_Q__
        LOG(ERROR) << "The platform version " << platformVersion <<
                      " is not supported.";
        return;
    }
    if (!ionPropertiesDefined()) {
        using IComponentStore =
            ::android::hardware::media::c2::V1_0::IComponentStore;
        std::string const preferredStoreName = "default";
        if (aidlSelected) {
            std::shared_ptr<c2_aidl::IComponentStore> preferredStore;
            if (__builtin_available(android __ANDROID_API_S__, *)) {
                std::string instanceName = ::android::base::StringPrintf(
                        "%s/%s", c2_aidl::IComponentStore::descriptor, preferredStoreName.c_str());
                if (AServiceManager_isDeclared(instanceName.c_str())) {
                    preferredStore = c2_aidl::IComponentStore::fromBinder(::ndk::SpAIBinder(
                            AServiceManager_waitForService(instanceName.c_str())));
                }
            }
            if (preferredStore) {
                ::android::SetPreferredCodec2ComponentStore(
                        std::make_shared<H2C2ComponentStore>(preferredStore));
                LOG(INFO) <<
                        "Preferred Codec2 AIDL store is set to \"" <<
                        preferredStoreName << "\".";
            } else {
                LOG(INFO) <<
                        "Preferred Codec2 AIDL store is defaulted to \"software\".";
            }
        } else {
            sp<IComponentStore> preferredStore =
                IComponentStore::getService(preferredStoreName.c_str());
            if (preferredStore) {
                ::android::SetPreferredCodec2ComponentStore(
                        std::make_shared<H2C2ComponentStore>(preferredStore));
                LOG(INFO) <<
                        "Preferred Codec2 HIDL store is set to \"" <<
                        preferredStoreName << "\".";
            } else {
                LOG(INFO) <<
                        "Preferred Codec2 HIDL store is defaulted to \"software\".";
            }
        }
    }

    bool registered = false;
    const std::string aidlServiceName =
        std::string(c2_aidl::IComponentStore::descriptor) + "/software";
    if (__builtin_available(android __ANDROID_API_S__, *)) {
        if (AServiceManager_isDeclared(aidlServiceName.c_str())) {
            if (!aidlStore) {
                aidlStore = ::ndk::SharedRefBase::make<c2_aidl::utils::ComponentStore>(
                        std::make_shared<H2C2ComponentStore>(nullptr));
            }
            binder_exception_t ex = AServiceManager_addService(
                    aidlStore->asBinder().get(), aidlServiceName.c_str());
            if (ex == EX_NONE) {
                registered = true;
            } else {
                LOG(WARNING) << "Cannot register software Codec2 AIDL service. Exception: " << ex;
            }
        }
    }

    // If the software component store isn't declared in the manifest, we don't
    // need to create the service and register it.
    using ::android::hidl::manager::V1_2::IServiceManager;
    IServiceManager::Transport transport =
            android::hardware::defaultServiceManager1_2()->getTransport(
                    V1_2::utils::ComponentStore::descriptor, "software");
    if (transport == IServiceManager::Transport::HWBINDER) {
        if (!hidlStore) {
            hidlStore = ::android::sp<V1_2::utils::ComponentStore>::make(
                    std::make_shared<H2C2ComponentStore>(nullptr));
            hidlVer = "1.2";
        }
        if (hidlStore->registerAsService("software") == android::OK) {
            registered = true;
        } else {
            LOG(ERROR) << "Cannot register software Codec2 v" << hidlVer << " service.";
        }
    } else {
        LOG(INFO) << "The HIDL software Codec2 service is deprecated"
                     " so it is not being registered with hwservicemanager.";
    }

    if (registered) {
        LOG(INFO) << "Software Codec2 service created and registered.";
    }

    ABinderProcess_joinThreadPool();
    ::android::hardware::joinRpcThreadpool();
}

