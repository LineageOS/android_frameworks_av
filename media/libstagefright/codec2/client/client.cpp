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
#define LOG_TAG "Codec2Client-interfaces"
#include <log/log.h>

#include <media/stagefright/codec2/client.h>

#include <codec2/hidl/1.0/types.h>

#include <vendor/google/media/c2/1.0/IComponentListener.h>
#include <vendor/google/media/c2/1.0/IConfigurable.h>
#include <vendor/google/media/c2/1.0/IComponentInterface.h>
#include <vendor/google/media/c2/1.0/IComponent.h>
#include <vendor/google/media/c2/1.0/IComponentStore.h>

#include <hidl/HidlSupport.h>

#include <limits>
#include <type_traits>

namespace /* unnamed */ {

// TODO: Find the appropriate error code for this
constexpr c2_status_t C2_TRANSACTION_FAILED = C2_CORRUPTED;

} // unnamed namespace

namespace android {

using ::android::hardware::hidl_vec;
using ::android::hardware::hidl_string;
using ::android::hardware::Return;
using ::android::hardware::Void;

using namespace ::vendor::google::media::c2::V1_0;
using namespace ::vendor::google::media::c2::V1_0::implementation;

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
        const std::vector<C2Param::Index> &indices,
        c2_blocking_t mayBlock,
        std::vector<std::unique_ptr<C2Param>>* const params) const {
    hidl_vec<ParamIndex> hidlIndices(indices.size());
    size_t i = 0;
    for (const C2Param::Index& index : indices) {
        hidlIndices[i++] = static_cast<ParamIndex>(index.operator uint32_t());
    }
    c2_status_t status;
    Return<void> transStatus = base()->query(
            hidlIndices,
            mayBlock == C2_MAY_BLOCK,
            [&status, params](Status s, const Params& p) {
                status = static_cast<c2_status_t>(s);
                if (status != C2_OK) {
                    return;
                }
                status = copyParamsFromBlob(params, p);
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
                    return;
                }
                failures->clear();
                failures->resize(f.size());
                size_t i = 0;
                for (const SettingResult& sf : f) {
                    status = objcpy(&(*failures)[i++], sf);
                    if (status != C2_OK) {
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
                    return;
                }
                params->resize(p.size());
                size_t i = 0;
                for (const ParamDescriptor& sp : p) {
                    status = objcpy(&(*params)[i++], sp);
                    if (status != C2_OK) {
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

// Codec2Client

Codec2Client::Base* Codec2Client::base() const {
    return static_cast<Base*>(mBase.get());
}

Codec2Client::Codec2Client(const sp<Codec2Client::Base>& base) :
        Codec2ConfigurableClient(base), mListed(false) {
}

c2_status_t Codec2Client::createComponent(
        const C2String& name,
        const std::shared_ptr<Codec2Client::Listener>& listener,
        std::shared_ptr<Codec2Client::Component>* const component) {

    // TODO: Add support for Bufferpool

    struct HidlListener : public IComponentListener {
        std::shared_ptr<Codec2Client::Listener> base;
        std::weak_ptr<Codec2Client::Component> component;

        virtual Return<void> onWorkDone(const WorkBundle& workBundle) override {
            std::list<std::unique_ptr<C2Work>> workItems;
            c2_status_t status = objcpy(&workItems, workBundle);
            if (status != C2_OK) {
                ALOGE("onWorkDone -- received corrupted WorkBundle. "
                        "Error code: %d", static_cast<int>(status));
                return Void();
            }
            base->onWorkDone(component, workItems);
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
                    ALOGE("onTripped -- received corrupted SettingResult. "
                            "Error code: %d", static_cast<int>(status));
                    return Void();
                }
                c2SettingResults[i] = std::move(c2SettingResult);
            }
            base->onTripped(component, c2SettingResults);
            return Void();
        }

        virtual Return<void> onError(Status s, uint32_t errorCode) override {
            base->onError(component, s == Status::OK ?
                    errorCode : static_cast<c2_status_t>(s));
            return Void();
        }
    };

    c2_status_t status;
    sp<HidlListener> hidlListener = new HidlListener();
    hidlListener->base = listener;
    Return<void> transStatus = base()->createComponent(
            name,
            hidlListener,
            nullptr,
            [&status, component](
                    Status s,
                    const sp<IComponent>& c) {
                status = static_cast<c2_status_t>(s);
                if (status != C2_OK) {
                    return;
                }
                *component = std::make_shared<Codec2Client::Component>(c);
            });
    if (!transStatus.isOk()) {
        ALOGE("createComponent -- failed transaction.");
        return C2_TRANSACTION_FAILED;
    }
    if (status != C2_OK) {
        ALOGE("createComponent -- failed to create component.");
        return status;
    }
    hidlListener->component = *component;
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

const std::vector<C2Component::Traits>& Codec2Client::listComponents()
        const {
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
    // TODO: Implement this once there is a way to construct C2StructDescriptor
    // dynamically.
    ALOGE("getParamReflector -- not implemented.");
    return nullptr;
}

std::shared_ptr<Codec2Client> Codec2Client::CreateFromService(
        const char* instanceName, bool waitForService) {
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
    return std::make_shared<Codec2Client>(baseStore);
}

// Codec2Client::Listener

Codec2Client::Listener::~Listener() {
}

// Codec2Client::Component

Codec2Client::Component::Base* Codec2Client::Component::base() const {
    return static_cast<Base*>(mBase.get());
}

Codec2Client::Component::Component(const sp<Codec2Client::Component::Base>& base) :
        Codec2Client::Configurable(base) {
}

c2_status_t Codec2Client::Component::createBlockPool(
        C2Allocator::id_t id,
        C2BlockPool::local_id_t* localId,
        std::shared_ptr<Codec2Client::Configurable>* configurable) {
    c2_status_t status;
    Return<void> transStatus = base()->createBlockPool(
            static_cast<uint32_t>(id),
            [&status, localId, configurable](
                    Status s,
                    uint64_t pId,
                    const sp<IConfigurable>& c) {
                status = static_cast<c2_status_t>(s);
                if (status != C2_OK) {
                    return;
                }
                *localId = static_cast<C2BlockPool::local_id_t>(pId);
                *configurable = std::make_shared<Codec2Client::Configurable>(c);
            });
    if (!transStatus.isOk()) {
        ALOGE("createBlockPool -- transaction failed.");
        return C2_TRANSACTION_FAILED;
    }
    return status;
}

c2_status_t Codec2Client::Component::queue(
        std::list<std::unique_ptr<C2Work>>* const items) {
    WorkBundle workBundle;
    Status hidlStatus = objcpy(&workBundle, *items);
    if (hidlStatus != Status::OK) {
        ALOGE("queue -- bad input.");
        return C2_TRANSACTION_FAILED;
    }
    Return<Status> transStatus = base()->queue(workBundle);
    if (!transStatus.isOk()) {
        ALOGE("queue -- transaction failed.");
        return C2_TRANSACTION_FAILED;
    }
    return static_cast<c2_status_t>(static_cast<Status>(transStatus));
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
                    return;
                }
                status = objcpy(flushedWork, wb);
            });
    if (!transStatus.isOk()) {
        ALOGE("flush -- transaction failed.");
        return C2_TRANSACTION_FAILED;
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
    return static_cast<c2_status_t>(static_cast<Status>(transStatus));
}

c2_status_t Codec2Client::Component::start() {
    Return<Status> transStatus = base()->start();
    if (!transStatus.isOk()) {
        ALOGE("start -- transaction failed.");
        return C2_TRANSACTION_FAILED;
    }
    return static_cast<c2_status_t>(static_cast<Status>(transStatus));
}

c2_status_t Codec2Client::Component::stop() {
    Return<Status> transStatus = base()->stop();
    if (!transStatus.isOk()) {
        ALOGE("stop -- transaction failed.");
        return C2_TRANSACTION_FAILED;
    }
    return static_cast<c2_status_t>(static_cast<Status>(transStatus));
}

c2_status_t Codec2Client::Component::reset() {
    Return<Status> transStatus = base()->reset();
    if (!transStatus.isOk()) {
        ALOGE("reset -- transaction failed.");
        return C2_TRANSACTION_FAILED;
    }
    return static_cast<c2_status_t>(static_cast<Status>(transStatus));
}

c2_status_t Codec2Client::Component::release() {
    Return<Status> transStatus = base()->release();
    if (!transStatus.isOk()) {
        ALOGE("release -- transaction failed.");
        return C2_TRANSACTION_FAILED;
    }
    return static_cast<c2_status_t>(static_cast<Status>(transStatus));
}




}  // namespace android

