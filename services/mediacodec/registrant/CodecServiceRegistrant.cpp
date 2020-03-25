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

#include <android-base/properties.h>
#include <android-base/logging.h>
#include <android-base/properties.h>

#include <C2Component.h>
#include <C2PlatformSupport.h>
#include <codec2/hidl/1.0/ComponentStore.h>
#include <codec2/hidl/1.1/ComponentStore.h>
#include <codec2/hidl/1.1/Configurable.h>
#include <codec2/hidl/1.1/types.h>
#include <hidl/HidlSupport.h>
#include <media/CodecServiceRegistrant.h>

namespace /* unnamed */ {

using ::android::hardware::hidl_vec;
using ::android::hardware::hidl_string;
using ::android::hardware::Return;
using ::android::hardware::Void;
using ::android::sp;
using namespace ::android::hardware::media::c2::V1_1;
using namespace ::android::hardware::media::c2::V1_1::utils;

constexpr c2_status_t C2_TRANSACTION_FAILED = C2_CORRUPTED;

// Converter from IComponentStore to C2ComponentStore.
class H2C2ComponentStore : public C2ComponentStore {
protected:
    using IComponentStore =
        ::android::hardware::media::c2::V1_0::IComponentStore;
    using IConfigurable =
        ::android::hardware::media::c2::V1_0::IConfigurable;
    sp<IComponentStore> mStore;
    sp<IConfigurable> mConfigurable;
public:
    explicit H2C2ComponentStore(sp<IComponentStore> const& store)
          : mStore{store},
            mConfigurable{[store]() -> sp<IConfigurable>{
                if (!store) {
                    return nullptr;
                }
                Return<sp<IConfigurable>> transResult =
                    store->getConfigurable();
                return transResult.isOk() ?
                        static_cast<sp<IConfigurable>>(transResult) :
                        nullptr;
            }()} {
        if (!mConfigurable) {
            LOG(ERROR) << "Preferred store is corrupted.";
        }
    }

    virtual ~H2C2ComponentStore() override = default;

    virtual c2_status_t config_sm(
            std::vector<C2Param*> const &params,
            std::vector<std::unique_ptr<C2SettingResult>>* const failures
            ) override {
        Params hidlParams;
        if (!createParamsBlob(&hidlParams, params)) {
            LOG(ERROR) << "config -- bad input.";
            return C2_TRANSACTION_FAILED;
        }
        c2_status_t status{};
        Return<void> transResult = mConfigurable->config(
                hidlParams,
                true,
                [&status, &params, failures](
                        Status s,
                        const hidl_vec<SettingResult> f,
                        const Params& o) {
                    status = static_cast<c2_status_t>(s);
                    if (status != C2_OK && status != C2_BAD_INDEX) {
                        LOG(DEBUG) << "config -- call failed: "
                                   << status << ".";
                    }
                    size_t i = failures->size();
                    failures->resize(i + f.size());
                    for (const SettingResult& sf : f) {
                        if (!objcpy(&(*failures)[i++], sf)) {
                            LOG(ERROR) << "config -- "
                                       << "invalid SettingResult returned.";
                            return;
                        }
                    }
                    if (!updateParamsFromBlob(params, o)) {
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

    virtual c2_status_t copyBuffer(
            std::shared_ptr<C2GraphicBuffer>,
            std::shared_ptr<C2GraphicBuffer>) override {
        LOG(ERROR) << "copyBuffer -- not supported.";
        return C2_OMITTED;
    }

    virtual c2_status_t createComponent(
            C2String, std::shared_ptr<C2Component> *const component) override {
        component->reset();
        LOG(ERROR) << "createComponent -- not supported.";
        return C2_OMITTED;
    }

    virtual c2_status_t createInterface(
            C2String, std::shared_ptr<C2ComponentInterface> *const interface) {
        interface->reset();
        LOG(ERROR) << "createInterface -- not supported.";
        return C2_OMITTED;
    }

    virtual c2_status_t query_sm(
            const std::vector<C2Param *> &stackParams,
            const std::vector<C2Param::Index> &heapParamIndices,
            std::vector<std::unique_ptr<C2Param>> *const heapParams) const
            override {
        hidl_vec<ParamIndex> indices(
                stackParams.size() + heapParamIndices.size());
        size_t numIndices = 0;
        for (C2Param* const& stackParam : stackParams) {
            if (!stackParam) {
                LOG(WARNING) << "query -- null stack param encountered.";
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
        Return<void> transResult = mConfigurable->query(
                indices,
                true,
                [&status, &numStackIndices, &stackParams, heapParams](
                        Status s, const Params& p) {
                    status = static_cast<c2_status_t>(s);
                    if (status != C2_OK && status != C2_BAD_INDEX) {
                        LOG(DEBUG) << "query -- call failed: "
                                   << status << ".";
                        return;
                    }
                    std::vector<C2Param*> paramPointers;
                    if (!parseParamsBlob(&paramPointers, p)) {
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
        if (!transResult.isOk()) {
            LOG(ERROR) << "query -- transaction failed.";
            return C2_TRANSACTION_FAILED;
        }
        return status;
    }

    virtual c2_status_t querySupportedParams_nb(
            std::vector<std::shared_ptr<C2ParamDescriptor>> *const params) const {
        c2_status_t status;
        Return<void> transResult = mConfigurable->querySupportedParams(
                std::numeric_limits<uint32_t>::min(),
                std::numeric_limits<uint32_t>::max(),
                [&status, params](
                        Status s,
                        const hidl_vec<ParamDescriptor>& p) {
                    status = static_cast<c2_status_t>(s);
                    if (status != C2_OK) {
                        LOG(DEBUG) << "querySupportedParams -- call failed: "
                                   << status << ".";
                        return;
                    }
                    size_t i = params->size();
                    params->resize(i + p.size());
                    for (const ParamDescriptor& sp : p) {
                        if (!objcpy(&(*params)[i++], sp)) {
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

    virtual c2_status_t querySupportedValues_sm(
            std::vector<C2FieldSupportedValuesQuery> &fields) const {
        hidl_vec<FieldSupportedValuesQuery> inFields(fields.size());
        for (size_t i = 0; i < fields.size(); ++i) {
            if (!objcpy(&inFields[i], fields[i])) {
                LOG(ERROR) << "querySupportedValues -- bad input";
                return C2_TRANSACTION_FAILED;
            }
        }

        c2_status_t status;
        Return<void> transResult = mConfigurable->querySupportedValues(
                inFields,
                true,
                [&status, &inFields, &fields](
                        Status s,
                        const hidl_vec<FieldSupportedValuesQueryResult>& r) {
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
                        if (!objcpy(&fields[i], inFields[i], r[i])) {
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

    virtual C2String getName() const {
        C2String outName;
        Return<void> transResult = mConfigurable->getName(
                [&outName](const hidl_string& name) {
                    outName = name.c_str();
                });
        if (!transResult.isOk()) {
            LOG(ERROR) << "getName -- transaction failed.";
        }
        return outName;
    }

    virtual std::shared_ptr<C2ParamReflector> getParamReflector() const
            override {
        struct SimpleParamReflector : public C2ParamReflector {
            virtual std::unique_ptr<C2StructDescriptor> describe(
                    C2Param::CoreIndex coreIndex) const {
                hidl_vec<ParamIndex> indices(1);
                indices[0] = static_cast<ParamIndex>(coreIndex.coreIndex());
                std::unique_ptr<C2StructDescriptor> descriptor;
                Return<void> transResult = mBase->getStructDescriptors(
                        indices,
                        [&descriptor](
                                Status s,
                                const hidl_vec<StructDescriptor>& sd) {
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
                            if (!objcpy(&descriptor, sd[0])) {
                                LOG(DEBUG) << "SimpleParamReflector -- "
                                              "getStructDescriptors() returned "
                                              "corrupted data.";
                                descriptor.reset();
                                return;
                            }
                        });
                return descriptor;
            }

            explicit SimpleParamReflector(sp<IComponentStore> base)
                : mBase(base) { }

            sp<IComponentStore> mBase;
        };

        return std::make_shared<SimpleParamReflector>(mStore);
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
    LOG(INFO) << "Creating software Codec2 service...";
    std::shared_ptr<C2ComponentStore> store =
        android::GetCodec2PlatformComponentStore();
    if (!store) {
        LOG(ERROR) << "Failed to create Codec2 service.";
        return;
    }

    using namespace ::android::hardware::media::c2;

    int platformVersion =
        android::base::GetIntProperty("ro.build.version.sdk", int32_t(29));
    // STOPSHIP: Remove code name checking once platform version bumps up to 30.
    std::string codeName =
        android::base::GetProperty("ro.build.version.codename", "");
    if (codeName == "R") {
        platformVersion = 30;
    }

    switch (platformVersion) {
        case 30: {
            android::sp<V1_1::IComponentStore> storeV1_1 =
                new V1_1::utils::ComponentStore(store);
            if (storeV1_1->registerAsService("software") != android::OK) {
                LOG(ERROR) << "Cannot register software Codec2 v1.1 service.";
                return;
            }
            break;
        }
        case 29: {
            android::sp<V1_0::IComponentStore> storeV1_0 =
                new V1_0::utils::ComponentStore(store);
            if (storeV1_0->registerAsService("software") != android::OK) {
                LOG(ERROR) << "Cannot register software Codec2 v1.0 service.";
                return;
            }
            break;
        }
        default: {
            LOG(ERROR) << "The platform version " << platformVersion <<
                          " is not supported.";
            return;
        }
    }
    if (!ionPropertiesDefined()) {
        using IComponentStore =
            ::android::hardware::media::c2::V1_0::IComponentStore;
        std::string const preferredStoreName = "default";
        sp<IComponentStore> preferredStore =
            IComponentStore::getService(preferredStoreName.c_str());
        if (preferredStore) {
            ::android::SetPreferredCodec2ComponentStore(
                    std::make_shared<H2C2ComponentStore>(preferredStore));
            LOG(INFO) <<
                    "Preferred Codec2 store is set to \"" <<
                    preferredStoreName << "\".";
        } else {
            LOG(INFO) <<
                    "Preferred Codec2 store is defaulted to \"software\".";
        }
    }
    LOG(INFO) << "Software Codec2 service created and registered.";
}

