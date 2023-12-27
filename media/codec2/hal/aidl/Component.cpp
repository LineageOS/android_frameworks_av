/*
 * Copyright 2021 The Android Open Source Project
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
#define LOG_TAG "Codec2-Component-Aidl"
#include <android-base/logging.h>

#include <codec2/aidl/Component.h>
#include <codec2/aidl/ComponentStore.h>
#include <codec2/aidl/InputBufferManager.h>

#ifndef __ANDROID_APEX__
#include <FilterWrapper.h>
#endif

#include <android/binder_auto_utils.h>
#include <android/binder_interface_utils.h>
#include <utils/Timers.h>

#include <C2Debug.h>
#include <C2PlatformSupport.h>

#include <chrono>
#include <thread>

namespace aidl {
namespace android {
namespace hardware {
namespace media {
namespace c2 {
namespace utils {

using ::aidl::android::hardware::common::NativeHandle;
using ::aidl::android::hardware::media::bufferpool2::IClientManager;
using ::ndk::ScopedAStatus;
using ::android::MultiAccessUnitInterface;
using ::android::MultiAccessUnitHelper;

// ComponentListener wrapper
struct Component::Listener : public C2Component::Listener {

    Listener(const std::shared_ptr<Component>& component) :
        mComponent(component),
        mListener(component->mListener) {
    }

    virtual void onError_nb(
            std::weak_ptr<C2Component> /* c2component */,
            uint32_t errorCode) override {
        std::shared_ptr<IComponentListener> listener = mListener.lock();
        if (listener) {
            ScopedAStatus transStatus = listener->onError(Status{Status::OK}, errorCode);
            if (!transStatus.isOk()) {
                LOG(ERROR) << "Component::Listener::onError_nb -- "
                           << "transaction failed.";
            }
        }
    }

    virtual void onTripped_nb(
            std::weak_ptr<C2Component> /* c2component */,
            std::vector<std::shared_ptr<C2SettingResult>> c2settingResult
            ) override {
      std::shared_ptr<IComponentListener> listener = mListener.lock();
        if (listener) {
            std::vector<SettingResult> settingResults(c2settingResult.size());
            size_t ix = 0;
            for (const std::shared_ptr<C2SettingResult> &c2result :
                    c2settingResult) {
                if (c2result) {
                    if (!ToAidl(&settingResults[ix++], *c2result)) {
                        break;
                    }
                }
            }
            settingResults.resize(ix);
            ScopedAStatus transStatus = listener->onTripped(settingResults);
            if (!transStatus.isOk()) {
                LOG(ERROR) << "Component::Listener::onTripped_nb -- "
                           << "transaction failed.";
            }
        }
    }

    virtual void onWorkDone_nb(
            std::weak_ptr<C2Component> /* c2component */,
            std::list<std::unique_ptr<C2Work>> c2workItems) override {
        for (const std::unique_ptr<C2Work>& work : c2workItems) {
            if (work) {
                if (work->worklets.empty()
                        || !work->worklets.back()
                        || (work->worklets.back()->output.flags &
                            C2FrameData::FLAG_INCOMPLETE) == 0) {
                    InputBufferManager::
                            unregisterFrameData(mListener, work->input);
                }
            }
        }

        std::shared_ptr<IComponentListener> listener = mListener.lock();
        if (listener) {
            WorkBundle workBundle;

            std::shared_ptr<Component> strongComponent = mComponent.lock();
            if (!ToAidl(&workBundle, c2workItems, strongComponent ?
                    &strongComponent->mBufferPoolSender : nullptr)) {
                LOG(ERROR) << "Component::Listener::onWorkDone_nb -- "
                           << "received corrupted work items.";
                return;
            }
            ScopedAStatus transStatus = listener->onWorkDone(workBundle);
            if (!transStatus.isOk()) {
                LOG(ERROR) << "Component::Listener::onWorkDone_nb -- "
                           << "transaction failed.";
                return;
            }
            // If output blocks are originally owned by the client(not by HAL),
            // return the ownership to the client. (Since the blocks are
            // transferred to the client here.)
            ReturnOutputBlocksToClientIfNeeded(c2workItems);
        }
    }

protected:
    std::weak_ptr<Component> mComponent;
    std::weak_ptr<IComponentListener> mListener;
};

// Component listener for handle multiple access-units
struct MultiAccessUnitListener : public Component::Listener {
    MultiAccessUnitListener(const std::shared_ptr<Component>& component,
            const std::shared_ptr<MultiAccessUnitHelper> &helper):
        Listener(component), mHelper(helper) {
    }

    virtual void onError_nb(
            std::weak_ptr<C2Component> c2component,
            uint32_t errorCode) override {
        if (mHelper) {
            std::list<std::unique_ptr<C2Work>> worklist;
            mHelper->error(&worklist);
            if (!worklist.empty()) {
                Listener::onWorkDone_nb(c2component, std::move(worklist));
            }
        }
        Listener::onError_nb(c2component, errorCode);
    }

    virtual void onTripped_nb(
            std::weak_ptr<C2Component> c2component,
            std::vector<std::shared_ptr<C2SettingResult>> c2settingResult
            ) override {
        Listener::onTripped_nb(c2component,
                c2settingResult);
    }

    virtual void onWorkDone_nb(
            std::weak_ptr<C2Component> c2component,
            std::list<std::unique_ptr<C2Work>> c2workItems) override {
        if (mHelper) {
            std::list<std::unique_ptr<C2Work>> processedWork;
            mHelper->gather(c2workItems, &processedWork);
            if (!processedWork.empty()) {
                Listener::onWorkDone_nb(c2component, std::move(processedWork));
            }
        } else {
            Listener::onWorkDone_nb(c2component, std::move(c2workItems));
        }
    }

    protected:
        std::shared_ptr<MultiAccessUnitHelper> mHelper;
};

// Component::DeathContext
struct Component::DeathContext {
    std::weak_ptr<Component> mWeakComp;
};

// Component
Component::Component(
        const std::shared_ptr<C2Component>& component,
        const std::shared_ptr<IComponentListener>& listener,
        const std::shared_ptr<ComponentStore>& store,
        const std::shared_ptr<IClientManager>& clientPoolManager)
      : mComponent{component},
        mListener{listener},
        mStore{store},
        mBufferPoolSender{clientPoolManager},
        mDeathContext(nullptr) {
    // Retrieve supported parameters from store
    // TODO: We could cache this per component/interface type
    if (MultiAccessUnitHelper::isEnabledOnPlatform()) {
        c2_status_t err = C2_OK;
        C2ComponentDomainSetting domain;
        std::vector<std::unique_ptr<C2Param>> heapParams;
        err = component->intf()->query_vb({&domain}, {}, C2_MAY_BLOCK, &heapParams);
        if (err == C2_OK && (domain.value == C2Component::DOMAIN_AUDIO)) {
            std::vector<std::shared_ptr<C2ParamDescriptor>> params;
            bool isComponentSupportsLargeAudioFrame = false;
            component->intf()->querySupportedParams_nb(&params);
            for (const auto &paramDesc : params) {
                if (paramDesc->name().compare(C2_PARAMKEY_OUTPUT_LARGE_FRAME) == 0) {
                    isComponentSupportsLargeAudioFrame = true;
                    LOG(VERBOSE) << "Underlying component supports large frame audio";
                    break;
                }
            }
            if (!isComponentSupportsLargeAudioFrame) {
                mMultiAccessUnitIntf = std::make_shared<MultiAccessUnitInterface>(
                        component->intf(),
                        std::static_pointer_cast<C2ReflectorHelper>(
                                ::android::GetCodec2PlatformComponentStore()->getParamReflector()));
            }
        }
    }
    mInterface = SharedRefBase::make<ComponentInterface>(
            component->intf(), mMultiAccessUnitIntf, store->getParameterCache());
    mInit = mInterface->status();
}

c2_status_t Component::status() const {
    return mInit;
}

// Methods from ::android::hardware::media::c2::V1_1::IComponent
ScopedAStatus Component::queue(const WorkBundle& workBundle) {
    std::list<std::unique_ptr<C2Work>> c2works;

    if (!FromAidl(&c2works, workBundle)) {
        return ScopedAStatus::fromServiceSpecificError(Status::CORRUPTED);
    }

    // Register input buffers.
    for (const std::unique_ptr<C2Work>& work : c2works) {
        if (work) {
            InputBufferManager::
                    registerFrameData(mListener, work->input);
        }
    }
    c2_status_t err = C2_OK;
    if (mMultiAccessUnitHelper) {
        std::list<std::list<std::unique_ptr<C2Work>>> c2worklists;
        mMultiAccessUnitHelper->scatter(c2works, &c2worklists);
        for (auto &c2worklist : c2worklists) {
            err = mComponent->queue_nb(&c2worklist);
            if (err != C2_OK) {
                LOG(ERROR) << "Error Queuing to component.";
                return ScopedAStatus::fromServiceSpecificError(err);
            }
        }
        return ScopedAStatus::ok();
    }

    err = mComponent->queue_nb(&c2works);
    if (err == C2_OK) {
        return ScopedAStatus::ok();
    }
    return ScopedAStatus::fromServiceSpecificError(err);
}

ScopedAStatus Component::flush(WorkBundle *flushedWorkBundle) {
    std::list<std::unique_ptr<C2Work>> c2flushedWorks;
    c2_status_t c2res = mComponent->flush_sm(
            C2Component::FLUSH_COMPONENT,
            &c2flushedWorks);
    if (mMultiAccessUnitHelper) {
        c2res = mMultiAccessUnitHelper->flush(&c2flushedWorks);
    }
    // Unregister input buffers.
    for (const std::unique_ptr<C2Work>& work : c2flushedWorks) {
        if (work) {
            if (work->worklets.empty()
                    || !work->worklets.back()
                    || (work->worklets.back()->output.flags &
                        C2FrameData::FLAG_INCOMPLETE) == 0) {
                InputBufferManager::
                        unregisterFrameData(mListener, work->input);
            }
        }
    }

    if (c2res == C2_OK) {
        if (!ToAidl(flushedWorkBundle, c2flushedWorks, &mBufferPoolSender)) {
            c2res = C2_CORRUPTED;
        }
    }
    // If output blocks are originally owned by the client(not by HAL),
    // return the ownership to the client. (Since the blocks are
    // transferred to the client here.)
    ReturnOutputBlocksToClientIfNeeded(c2flushedWorks);
    if (c2res == C2_OK) {
        return ScopedAStatus::ok();
    }
    return ScopedAStatus::fromServiceSpecificError(c2res);
}

ScopedAStatus Component::drain(bool withEos) {
    c2_status_t res = mComponent->drain_nb(withEos ?
            C2Component::DRAIN_COMPONENT_WITH_EOS :
            C2Component::DRAIN_COMPONENT_NO_EOS);
    if (res == C2_OK) {
        return ScopedAStatus::ok();
    }
    return ScopedAStatus::fromServiceSpecificError(res);
}

namespace /* unnamed */ {

struct BlockPoolIntf : public ConfigurableC2Intf {
    BlockPoolIntf(const std::shared_ptr<C2BlockPool>& pool)
          : ConfigurableC2Intf{
                "C2BlockPool:" +
                    (pool ? std::to_string(pool->getLocalId()) : "null"),
                0},
            mPool{pool} {
    }

    virtual c2_status_t config(
            const std::vector<C2Param*>& params,
            c2_blocking_t mayBlock,
            std::vector<std::unique_ptr<C2SettingResult>>* const failures
            ) override {
        (void)params;
        (void)mayBlock;
        (void)failures;
        return C2_OK;
    }

    virtual c2_status_t query(
            const std::vector<C2Param::Index>& indices,
            c2_blocking_t mayBlock,
            std::vector<std::unique_ptr<C2Param>>* const params
            ) const override {
        (void)indices;
        (void)mayBlock;
        (void)params;
        return C2_OK;
    }

    virtual c2_status_t querySupportedParams(
            std::vector<std::shared_ptr<C2ParamDescriptor>>* const params
            ) const override {
        (void)params;
        return C2_OK;
    }

    virtual c2_status_t querySupportedValues(
            std::vector<C2FieldSupportedValuesQuery>& fields,
            c2_blocking_t mayBlock) const override {
        (void)fields;
        (void)mayBlock;
        return C2_OK;
    }

protected:
    std::shared_ptr<C2BlockPool> mPool;
};

} // unnamed namespace

ScopedAStatus Component::createBlockPool(
        const IComponent::BlockPoolAllocator &allocator,
        IComponent::BlockPool *blockPool) {
    std::shared_ptr<C2BlockPool> c2BlockPool;
    c2_status_t status = C2_OK;
    ::android::C2PlatformAllocatorDesc allocatorParam;
    allocatorParam.allocatorId = allocator.allocatorId;
    switch (allocator.allocatorId) {
        case ::android::C2PlatformAllocatorStore::IGBA: {
            allocatorParam.igba = allocator.gbAllocator->igba;
            allocatorParam.waitableFd.reset(
                    allocator.gbAllocator->waitableFd.dup().release());
        }
        break;
        default: {
            // no-op
        }
        break;
    }

#ifdef __ANDROID_APEX__
    status = ::android::CreateCodec2BlockPool(
            allocatorParam,
            mComponent,
            &c2BlockPool);
#else
    status = ComponentStore::GetFilterWrapper()->createBlockPool(
            allocatorParam,
            mComponent,
            &c2BlockPool);
#endif
    if (status != C2_OK) {
        return ScopedAStatus::fromServiceSpecificError(status);
    }
    {
        mBlockPoolsMutex.lock();
        mBlockPools.emplace(c2BlockPool->getLocalId(), c2BlockPool);
        mBlockPoolsMutex.unlock();
    }

    blockPool->blockPoolId = c2BlockPool ? c2BlockPool->getLocalId() : 0;
    blockPool->configurable = SharedRefBase::make<CachedConfigurable>(
            std::make_unique<BlockPoolIntf>(c2BlockPool));
    return ScopedAStatus::ok();
}

ScopedAStatus Component::destroyBlockPool(int64_t blockPoolId) {
    std::lock_guard<std::mutex> lock(mBlockPoolsMutex);
    if (mBlockPools.erase(blockPoolId) == 1) {
        return ScopedAStatus::ok();
    }
    return ScopedAStatus::fromServiceSpecificError(Status::CORRUPTED);
}

ScopedAStatus Component::start() {
    c2_status_t status = mComponent->start();
    if (status == C2_OK) {
        return ScopedAStatus::ok();
    }
    return ScopedAStatus::fromServiceSpecificError(status);
}

ScopedAStatus Component::stop() {
    InputBufferManager::unregisterFrameData(mListener);
    c2_status_t status = mComponent->stop();
    if (status == C2_OK) {
        return ScopedAStatus::ok();
    }
    return ScopedAStatus::fromServiceSpecificError(status);
}

ScopedAStatus Component::reset() {
    c2_status_t status = mComponent->reset();
    {
        std::lock_guard<std::mutex> lock(mBlockPoolsMutex);
        mBlockPools.clear();
    }
    if (mMultiAccessUnitHelper) {
        mMultiAccessUnitHelper->reset();
    }
    InputBufferManager::unregisterFrameData(mListener);
    if (status == C2_OK) {
        return ScopedAStatus::ok();
    }
    return ScopedAStatus::fromServiceSpecificError(status);
}

ScopedAStatus Component::release() {
    c2_status_t status = mComponent->release();
    {
        std::lock_guard<std::mutex> lock(mBlockPoolsMutex);
        mBlockPools.clear();
    }
    if (mMultiAccessUnitHelper) {
        mMultiAccessUnitHelper->reset();
    }
    InputBufferManager::unregisterFrameData(mListener);
    if (status == C2_OK) {
        return ScopedAStatus::ok();
    }
    return ScopedAStatus::fromServiceSpecificError(status);
}

ScopedAStatus Component::getInterface(
        std::shared_ptr<IComponentInterface> *intf) {
    *intf = mInterface;
    return ScopedAStatus::ok();
}

ScopedAStatus Component::configureVideoTunnel(
        int32_t avSyncHwId, NativeHandle *handle) {
    (void)avSyncHwId;
    (void)handle;
    return ScopedAStatus::fromServiceSpecificError(Status::OMITTED);
}

ScopedAStatus Component::connectToInputSurface(
        const std::shared_ptr<IInputSurface>& inputSurface,
        std::shared_ptr<IInputSurfaceConnection> *connection) {
    // TODO
    (void)inputSurface;
    (void)connection;
    return ScopedAStatus::fromServiceSpecificError(Status::OMITTED);
}

ScopedAStatus Component::asInputSink(
        std::shared_ptr<IInputSink> *sink) {
    // TODO
    (void)sink;
    return ScopedAStatus::fromServiceSpecificError(Status::OMITTED);
}

void Component::initListener(const std::shared_ptr<Component>& self) {
    if (__builtin_available(android __ANDROID_API_T__, *)) {
        std::shared_ptr<C2Component::Listener> c2listener;
        if (mMultiAccessUnitIntf) {
            mMultiAccessUnitHelper = std::make_shared<MultiAccessUnitHelper>(mMultiAccessUnitIntf);
        }
        c2listener = mMultiAccessUnitHelper ?
                std::make_shared<MultiAccessUnitListener>(self, mMultiAccessUnitHelper) :
                std::make_shared<Listener>(self);
        c2_status_t res = mComponent->setListener_vb(c2listener, C2_DONT_BLOCK);
        if (res != C2_OK) {
            mInit = res;
        }

        mDeathRecipient = ::ndk::ScopedAIBinder_DeathRecipient(
                AIBinder_DeathRecipient_new(OnBinderDied));
        mDeathContext = new DeathContext{ref<Component>()};
        AIBinder_DeathRecipient_setOnUnlinked(mDeathRecipient.get(), OnBinderUnlinked);
        AIBinder_linkToDeath(mListener->asBinder().get(), mDeathRecipient.get(), mDeathContext);
    } else {
        mInit = C2_NO_INIT;
    }
}

// static
void Component::OnBinderDied(void *cookie) {
    DeathContext *context = (DeathContext *)cookie;
    std::shared_ptr<Component> comp = context->mWeakComp.lock();
    if (comp) {
        comp->release();
    }
}

// static
void Component::OnBinderUnlinked(void *cookie) {
    delete (DeathContext *)cookie;
}

Component::~Component() {
    InputBufferManager::unregisterFrameData(mListener);
    mStore->reportComponentDeath(this);
    if (mDeathRecipient.get()) {
        AIBinder_unlinkToDeath(mListener->asBinder().get(), mDeathRecipient.get(), mDeathContext);
    }
}

} // namespace utils
} // namespace c2
} // namespace media
} // namespace hardware
} // namespace android
} // namespace aidl
