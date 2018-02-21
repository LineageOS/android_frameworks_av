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
#define LOG_TAG "Codec2-Component"
#include <log/log.h>

#include <codec2/hidl/1.0/Component.h>
#include <codec2/hidl/1.0/types.h>

namespace vendor {
namespace google {
namespace media {
namespace c2 {
namespace V1_0 {
namespace implementation {

using namespace ::android;

// Implementation of ConfigurableC2Intf based on C2ComponentInterface
struct CompIntf : public ConfigurableC2Intf {
    CompIntf(const std::shared_ptr<C2ComponentInterface>& intf) :
        ConfigurableC2Intf(intf->getName()),
        mIntf(intf) {
    }

    virtual c2_status_t config(
            const std::vector<C2Param*>& params,
            c2_blocking_t mayBlock,
            std::vector<std::unique_ptr<C2SettingResult>>* const failures
            ) override {
        return mIntf->config_vb(params, mayBlock, failures);
    }

    virtual c2_status_t query(
            const std::vector<C2Param::Index>& indices,
            c2_blocking_t mayBlock,
            std::vector<std::unique_ptr<C2Param>>* const params) override {
        return mIntf->query_vb({}, indices, mayBlock, params);
    }

    virtual c2_status_t querySupportedParams(
            std::vector<std::shared_ptr<C2ParamDescriptor>>* const params
            ) const override {
        return mIntf->querySupportedParams_nb(params);
    }

    virtual c2_status_t querySupportedValues(
            std::vector<C2FieldSupportedValuesQuery>& fields,
            c2_blocking_t mayBlock) const override {
        return mIntf->querySupportedValues_vb(fields, mayBlock);
    }

protected:
    std::shared_ptr<C2ComponentInterface> mIntf;
};

// ComponentInterface
ComponentInterface::ComponentInterface(
        const std::shared_ptr<C2ComponentInterface>& intf,
        const sp<ComponentStore>& store) :
    Configurable(new CachedConfigurable(std::make_unique<CompIntf>(intf))),
    mInterface(intf) {
    mInit = init(store.get());
}

c2_status_t ComponentInterface::status() const {
    return mInit;
}

// ComponentListener wrapper
struct Listener : public C2Component::Listener {
    Listener(const wp<IComponentListener>& listener) : mListener(listener) {
        // TODO: Should we track interface errors? We could reuse onError() or
        // create our own error channel.
    }

    virtual void onError_nb(
            std::weak_ptr<C2Component> /* c2component */,
            uint32_t errorCode) override {
        sp<IComponentListener> listener = mListener.promote();
        if (listener) {
            listener->onError(Status::OK, errorCode);
        }
    }

    virtual void onTripped_nb(
            std::weak_ptr<C2Component> /* c2component */,
            std::vector<std::shared_ptr<C2SettingResult>> c2settingResult
            ) override {
        sp<IComponentListener> listener = mListener.promote();
        if (listener) {
            hidl_vec<SettingResult> settingResults(c2settingResult.size());
            size_t ix = 0;
            for (const std::shared_ptr<C2SettingResult> &c2result :
                    c2settingResult) {
                if (c2result) {
                    objcpy(&settingResults[ix++], *c2result);
                }
            }
            settingResults.resize(ix);
            listener->onTripped(settingResults);
        }
    }

    virtual void onWorkDone_nb(
            std::weak_ptr<C2Component> /* c2component */,
            std::list<std::unique_ptr<C2Work>> c2workItems) override {
        sp<IComponentListener> listener = mListener.promote();
        if (listener) {
            WorkBundle workBundle;

            // TODO: Connect with bufferpool API to send Works & Buffers
            if (objcpy(&workBundle, c2workItems) != Status::OK) {
                ALOGE("onWorkDone() received corrupted work items.");
                return;
            }
            listener->onWorkDone(workBundle);

            // Finish buffer transfers: nothing else to do
        }
    }

protected:
    wp<IComponentListener> mListener;
};

// Component
Component::Component(
        const std::shared_ptr<C2Component>& component,
        const sp<IComponentListener>& listener,
        const sp<ComponentStore>& store) :
    Configurable(new CachedConfigurable(
            std::make_unique<CompIntf>(component->intf()))),
    mComponent(component),
    mInterface(component->intf()),
    mListener(listener) /* , // TODO: Do we need store for anything?
    mStore(store)*/ {
    std::shared_ptr<C2Component::Listener> c2listener =
            std::make_shared<Listener>(listener);
    c2_status_t res = mComponent->setListener_vb(c2listener, C2_DONT_BLOCK);
    // Retrieve supported parameters from store
    // TODO: We could cache this per component/interface type
    mInit = init(store.get());
    mInit = mInit != C2_OK ? res : mInit;
}

// Methods from ::android::hardware::media::c2::V1_0::IComponent
Return<Status> Component::queue(const WorkBundle& workBundle) {
    std::list<std::unique_ptr<C2Work>> c2works;

    // TODO: Connect with bufferpool API for buffer transfers
    if (objcpy(&c2works, workBundle) != C2_OK) {
        return Status::CORRUPTED;
    }
    (void)workBundle;
    return static_cast<Status>(mComponent->queue_nb(&c2works));
}

Return<void> Component::flush(flush_cb _hidl_cb) {
    std::list<std::unique_ptr<C2Work>> c2flushedWorks;
    c2_status_t c2res = mComponent->flush_sm(
            C2Component::FLUSH_COMPONENT,
            &c2flushedWorks);
    WorkBundle flushedWorkBundle;

    Status res = static_cast<Status>(c2res);
    if (c2res == C2_OK) {
        // TODO: Connect with bufferpool API for buffer transfers
        res = objcpy(&flushedWorkBundle, c2flushedWorks);
    }
    _hidl_cb(res, flushedWorkBundle);
    return Void();
}

Return<Status> Component::drain(bool withEos) {
    return static_cast<Status>(mComponent->drain_nb(withEos ?
            C2Component::DRAIN_COMPONENT_WITH_EOS :
            C2Component::DRAIN_COMPONENT_NO_EOS));
}

Return<Status> Component::connectToInputSurface(const sp<IInputSurface>& surface) {
    // TODO implement
    (void)surface;
    return Status::OK;
}

Return<Status> Component::connectToOmxInputSurface(
        const sp<::android::hardware::graphics::bufferqueue::V1_0::
        IGraphicBufferProducer>& producer,
        const sp<::android::hardware::media::omx::V1_0::
        IGraphicBufferSource>& source) {
    // TODO implement
    (void)producer;
    (void)source;
    return Status::OK;
}

Return<Status> Component::disconnectFromInputSurface() {
    // TODO implement
    return Status::OK;
}

Return<void> Component::createBlockPool(uint32_t allocatorId, createBlockPool_cb _hidl_cb) {
    // TODO implement
    (void)allocatorId;
    _hidl_cb(Status::OK, 0 /* blockPoolId */, nullptr /* configurable */);
    return Void();
}

Return<Status> Component::start() {
    return static_cast<Status>(mComponent->start());
}

Return<Status> Component::stop() {
    return static_cast<Status>(mComponent->stop());
}

Return<Status> Component::reset() {
    return static_cast<Status>(mComponent->reset());
}

Return<Status> Component::release() {
    return static_cast<Status>(mComponent->release());
}

}  // namespace implementation
}  // namespace V1_0
}  // namespace c2
}  // namespace media
}  // namespace google
}  // namespace vendor
