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
#include <android-base/logging.h>

#include <C2PlatformSupport.h>
#include <codec2/hidl/1.0/Component.h>
#include <codec2/hidl/1.0/ComponentStore.h>
#include <codec2/hidl/1.0/types.h>

#include <hidl/HidlBinderSupport.h>
#include <utils/Timers.h>

#include <C2BqBufferPriv.h>
#include <C2Debug.h>
#include <C2PlatformSupport.h>

#include <chrono>
#include <thread>

namespace hardware {
namespace google {
namespace media {
namespace c2 {
namespace V1_0 {
namespace utils {

using namespace ::android;

namespace /* unnamed */ {

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
        ALOGV("config");
        return mIntf->config_vb(params, mayBlock, failures);
    }

    virtual c2_status_t query(
            const std::vector<C2Param::Index>& indices,
            c2_blocking_t mayBlock,
            std::vector<std::unique_ptr<C2Param>>* const params
            ) const override {
        ALOGV("query");
        return mIntf->query_vb({}, indices, mayBlock, params);
    }

    virtual c2_status_t querySupportedParams(
            std::vector<std::shared_ptr<C2ParamDescriptor>>* const params
            ) const override {
        ALOGV("querySupportedParams");
        return mIntf->querySupportedParams_nb(params);
    }

    virtual c2_status_t querySupportedValues(
            std::vector<C2FieldSupportedValuesQuery>& fields,
            c2_blocking_t mayBlock) const override {
        ALOGV("querySupportedValues");
        return mIntf->querySupportedValues_vb(fields, mayBlock);
    }

protected:
    std::shared_ptr<C2ComponentInterface> mIntf;
};

} // unnamed namespace

// InputBufferManager
// ==================
//
// InputBufferManager presents a way to track and untrack input buffers in this
// (codec) process and send a notification to a listener, possibly in a
// different process, when a tracked buffer no longer has any references in this
// process. (In fact, this class would work for listeners in the same process
// too, but the optimization discussed below will not be beneficial.)
//
// InputBufferManager holds a collection of records representing tracked buffers
// and their callback listeners. Conceptually, one record is a triple (listener,
// frameIndex, bufferIndex) where
//
// - (frameIndex, bufferIndex) is a pair of indices used to identify the buffer.
// - listener is of type IComponentListener. Its onFramesRendered() function
//   will be called after the associated buffer dies. The argument of
//   onFramesRendered() is a list of RenderedFrame objects, each of which has
//   the following members:
//
//     uint64_t bufferQueueId
//     int32_t  slotId
//     int64_t  timestampNs
//
// When a tracked buffer associated to the triple (listener, frameIndex,
// bufferIndex) goes out of scope, listener->onFramesRendered() will be called
// with a RenderedFrame object whose members are set as follows:
//
//     bufferQueueId = frameIndex
//     slotId        = ~bufferIndex
//     timestampNs   = systemTime() at the time of notification
//
// The reason for the bitwise negation of bufferIndex is that onFramesRendered()
// may be used for a different purpose when slotId is non-negative (which is a
// more general use case).
//
// IPC Optimization
// ----------------
//
// Since onFramesRendered() generally is an IPC call, InputBufferManager tries
// not to call it too often. There is a mechanism to guarantee that any two
// calls to the same listener are at least kNotificationPeriodNs nanoseconds
// apart.
//
struct InputBufferManager {
    // The minimum time period between IPC calls to notify the client about the
    // destruction of input buffers.
    static constexpr nsecs_t kNotificationPeriodNs = 1000000;

    // Track all buffers in a C2FrameData object.
    //
    // input (C2FrameData) has the following two members that are of interest:
    //
    //   C2WorkOrdinal                ordinal
    //   vector<shared_ptr<C2Buffer>> buffers
    //
    // Calling registerFrameData(listener, input) will register multiple
    // triples (, frameIndex, bufferIndex) where frameIndex is equal to
    // input.ordinal.frameIndex and bufferIndex runs through the indices of
    // input.buffers such that input.buffers[bufferIndex] is not null.
    //
    // This should be called from queue().
    static void registerFrameData(
            const sp<IComponentListener>& listener,
            const C2FrameData& input);

    // Untrack all buffers in a C2FrameData object.
    //
    // Calling unregisterFrameData(listener, input) will unregister and remove
    // pending notifications for all triples (l, fi, bufferIndex) such that
    // l = listener and fi = input.ordinal.frameIndex.
    //
    // This should be called from onWorkDone() and flush().
    static void unregisterFrameData(
            const wp<IComponentListener>& listener,
            const C2FrameData& input);

    // Untrack all buffers associated to a given listener.
    //
    // Calling unregisterFrameData(listener) will unregister and remove
    // pending notifications for all triples (l, frameIndex, bufferIndex) such
    // that l = listener.
    //
    // This should be called when the component cleans up all input buffers,
    // i.e., when reset(), release(), stop() or ~Component() is called.
    static void unregisterFrameData(
            const wp<IComponentListener>& listener);

private:
    void _registerFrameData(
            const sp<IComponentListener>& listener,
            const C2FrameData& input);
    void _unregisterFrameData(
            const wp<IComponentListener>& listener,
            const C2FrameData& input);
    void _unregisterFrameData(
            const wp<IComponentListener>& listener);

    // The callback function tied to C2Buffer objects.
    //
    // Note: This function assumes that sInstance is the only instance of this
    //       class.
    static void onBufferDestroyed(const C2Buffer* buf, void* arg);
    void _onBufferDestroyed(const C2Buffer* buf, void* arg);

    // Comparison operator for weak pointers.
    struct CompareWeakComponentListener {
        constexpr bool operator()(
                const wp<IComponentListener>& x,
                const wp<IComponentListener>& y) const {
            return x.get_refs() < y.get_refs();
        }
    };

    // Persistent data to be passed as "arg" in onBufferDestroyed().
    // This is essentially the triple (listener, frameIndex, bufferIndex) plus a
    // weak pointer to the C2Buffer object.
    //
    // Note that the "key" is bufferIndex according to operator<(). This is
    // designed to work with TrackedBuffersMap defined below.
    struct TrackedBuffer {
        wp<IComponentListener> listener;
        uint64_t frameIndex;
        size_t bufferIndex;
        std::weak_ptr<C2Buffer> buffer;
        TrackedBuffer(const wp<IComponentListener>& listener,
                      uint64_t frameIndex,
                      size_t bufferIndex,
                      const std::shared_ptr<C2Buffer>& buffer)
              : listener(listener),
                frameIndex(frameIndex),
                bufferIndex(bufferIndex),
                buffer(buffer) {}
        TrackedBuffer(const TrackedBuffer&) = default;
        bool operator<(const TrackedBuffer& other) const {
            return bufferIndex < other.bufferIndex;
        }
    };

    // Map: listener -> frameIndex -> set<TrackedBuffer>.
    // Essentially, this is used to store triples (listener, frameIndex,
    // bufferIndex) that's searchable by listener and (listener, frameIndex).
    // However, the value of the innermost map is TrackedBuffer, which also
    // contains an extra copy of listener and frameIndex. This is needed
    // because onBufferDestroyed() needs to know listener and frameIndex too.
    typedef std::map<wp<IComponentListener>,
                     std::map<uint64_t,
                              std::set<TrackedBuffer>>,
                     CompareWeakComponentListener> TrackedBuffersMap;

    // Storage for pending (unsent) death notifications for one listener.
    // Each pair in member named "indices" are (frameIndex, bufferIndex) from
    // the (listener, frameIndex, bufferIndex) triple.
    struct DeathNotifications {

        // The number of pending notifications for this listener.
        // count may be 0, in which case the DeathNotifications object will
        // remain valid for only a small period (kNotificationPeriodNs
        // nanoseconds).
        size_t count;

        // The timestamp of the most recent callback on this listener. This is
        // used to guarantee that callbacks do not occur too frequently, and
        // also to trigger expiration of a DeathNotifications object that has
        // count = 0.
        nsecs_t lastSentNs;

        // Map: frameIndex -> vector of bufferIndices
        // This is essentially a collection of (framdeIndex, bufferIndex).
        std::map<uint64_t, std::vector<size_t>> indices;

        DeathNotifications()
              : count(0),
                lastSentNs(systemTime() - kNotificationPeriodNs),
                indices() {}
    };

    // Mutex for the management of all input buffers.
    std::mutex mMutex;

    // Tracked input buffers.
    TrackedBuffersMap mTrackedBuffersMap;

    // Death notifications to be sent.
    //
    // A DeathNotifications object is associated to each listener. An entry in
    // this map will be removed if its associated DeathNotifications has count =
    // 0 and lastSentNs < systemTime() - kNotificationPeriodNs.
    std::map<wp<IComponentListener>, DeathNotifications> mDeathNotifications;

    // Condition variable signaled when an entry is added to mDeathNotifications.
    std::condition_variable mOnBufferDestroyed;

    // Notify the clients about buffer destructions.
    // Return false if all destructions have been notified.
    // Return true and set timeToRetry to the duration to wait for before
    // retrying if some destructions have not been notified.
    bool processNotifications(nsecs_t* timeToRetryNs);

    // Main function for the input buffer manager thread.
    void main();

    // The thread that manages notifications.
    //
    // Note: This variable is declared last so its initialization will happen
    // after all other member variables have been initialized.
    std::thread mMainThread;

    // Private constructor.
    InputBufferManager();

    // The only instance of this class.
    static InputBufferManager& getInstance();

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
struct Component::Listener : public C2Component::Listener {

    Listener(const sp<Component>& component) :
        mComponent(component),
        mListener(component->mListener) {
    }

    virtual void onError_nb(
            std::weak_ptr<C2Component> /* c2component */,
            uint32_t errorCode) override {
        ALOGV("onError");
        sp<IComponentListener> listener = mListener.promote();
        if (listener) {
            Return<void> transStatus = listener->onError(Status::OK, errorCode);
            if (!transStatus.isOk()) {
                ALOGE("onError -- transaction failed.");
            }
        }
    }

    virtual void onTripped_nb(
            std::weak_ptr<C2Component> /* c2component */,
            std::vector<std::shared_ptr<C2SettingResult>> c2settingResult
            ) override {
        ALOGV("onTripped");
        sp<IComponentListener> listener = mListener.promote();
        if (listener) {
            hidl_vec<SettingResult> settingResults(c2settingResult.size());
            size_t ix = 0;
            for (const std::shared_ptr<C2SettingResult> &c2result :
                    c2settingResult) {
                if (c2result) {
                    if (objcpy(&settingResults[ix++], *c2result) !=
                            Status::OK) {
                        break;
                    }
                }
            }
            settingResults.resize(ix);
            Return<void> transStatus = listener->onTripped(settingResults);
            if (!transStatus.isOk()) {
                ALOGE("onTripped -- transaction failed.");
            }
        }
    }

    virtual void onWorkDone_nb(
            std::weak_ptr<C2Component> /* c2component */,
            std::list<std::unique_ptr<C2Work>> c2workItems) override {
        ALOGV("onWorkDone");
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

        sp<IComponentListener> listener = mListener.promote();
        if (listener) {
            WorkBundle workBundle;

            sp<Component> strongComponent = mComponent.promote();
            if (objcpy(&workBundle, c2workItems, strongComponent ?
                    &strongComponent->mBufferPoolSender : nullptr)
                    != Status::OK) {
                ALOGE("onWorkDone() received corrupted work items.");
                return;
            }
            Return<void> transStatus = listener->onWorkDone(workBundle);
            if (!transStatus.isOk()) {
                ALOGE("onWorkDone -- transaction failed.");
                return;
            }
            yieldBufferQueueBlocks(c2workItems, true);
        }
    }

protected:
    wp<Component> mComponent;
    wp<IComponentListener> mListener;
};

// Component
Component::Component(
        const std::shared_ptr<C2Component>& component,
        const sp<IComponentListener>& listener,
        const sp<ComponentStore>& store,
        const sp<::android::hardware::media::bufferpool::V1_0::
        IClientManager>& clientPoolManager) :
    Configurable(new CachedConfigurable(
            std::make_unique<CompIntf>(component->intf()))),
    mComponent(component),
    mInterface(component->intf()),
    mListener(listener),
    mStore(store),
    mBufferPoolSender(clientPoolManager) {
    // Retrieve supported parameters from store
    // TODO: We could cache this per component/interface type
    mInit = init(store.get());
}

c2_status_t Component::status() const {
    return mInit;
}

// Methods from ::android::hardware::media::c2::V1_0::IComponent
Return<Status> Component::queue(const WorkBundle& workBundle) {
    ALOGV("queue -- converting input");
    std::list<std::unique_ptr<C2Work>> c2works;

    if (objcpy(&c2works, workBundle) != C2_OK) {
        ALOGV("queue -- corrupted");
        return Status::CORRUPTED;
    }

    // Register input buffers.
    for (const std::unique_ptr<C2Work>& work : c2works) {
        if (work) {
            InputBufferManager::
                    registerFrameData(mListener, work->input);
        }
    }

    ALOGV("queue -- calling");
    return static_cast<Status>(mComponent->queue_nb(&c2works));
}

Return<void> Component::flush(flush_cb _hidl_cb) {
    std::list<std::unique_ptr<C2Work>> c2flushedWorks;
    ALOGV("flush -- calling");
    c2_status_t c2res = mComponent->flush_sm(
            C2Component::FLUSH_COMPONENT,
            &c2flushedWorks);

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

    WorkBundle flushedWorkBundle;
    Status res = static_cast<Status>(c2res);
    if (c2res == C2_OK) {
        ALOGV("flush -- converting output");
        res = objcpy(&flushedWorkBundle, c2flushedWorks, &mBufferPoolSender);
    }
    _hidl_cb(res, flushedWorkBundle);
    yieldBufferQueueBlocks(c2flushedWorks, true);
    return Void();
}

Return<Status> Component::drain(bool withEos) {
    ALOGV("drain");
    return static_cast<Status>(mComponent->drain_nb(withEos ?
            C2Component::DRAIN_COMPONENT_WITH_EOS :
            C2Component::DRAIN_COMPONENT_NO_EOS));
}

Return<Status> Component::setOutputSurface(
        uint64_t blockPoolId,
        const sp<HGraphicBufferProducer>& surface) {
    std::shared_ptr<C2BlockPool> pool;
    GetCodec2BlockPool(blockPoolId, mComponent, &pool);
    if (pool && pool->getAllocatorId() == C2PlatformAllocatorStore::BUFFERQUEUE) {
        std::shared_ptr<C2BufferQueueBlockPool> bqPool =
                std::static_pointer_cast<C2BufferQueueBlockPool>(pool);
        C2BufferQueueBlockPool::OnRenderCallback cb =
            [this](uint64_t producer, int32_t slot, int64_t nsecs) {
                // TODO: batch this
                hidl_vec<IComponentListener::RenderedFrame> rendered;
                rendered.resize(1);
                rendered[0] = { producer, slot, nsecs };
                (void)mListener->onFramesRendered(rendered).isOk();
        };
        if (bqPool) {
            bqPool->setRenderCallback(cb);
            bqPool->configureProducer(surface);
        }
    }
    return Status::OK;
}

Return<Status> Component::connectToOmxInputSurface(
        const sp<HGraphicBufferProducer>& producer,
        const sp<::android::hardware::media::omx::V1_0::
        IGraphicBufferSource>& source) {
    // TODO implement
    (void)producer;
    (void)source;
    return Status::OMITTED;
}

Return<Status> Component::disconnectFromInputSurface() {
    // TODO implement
    return Status::OK;
}

namespace /* unnamed */ {

struct BlockPoolIntf : public ConfigurableC2Intf {
    BlockPoolIntf(const std::shared_ptr<C2BlockPool>& pool) :
        ConfigurableC2Intf("C2BlockPool:" +
                           (pool ? std::to_string(pool->getLocalId()) :
                           "null")),
        mPool(pool) {
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

Return<void> Component::createBlockPool(
        uint32_t allocatorId,
        createBlockPool_cb _hidl_cb) {
    std::shared_ptr<C2BlockPool> blockPool;
    c2_status_t status = CreateCodec2BlockPool(
            static_cast<C2PlatformAllocatorStore::id_t>(allocatorId),
            mComponent,
            &blockPool);
    if (status != C2_OK) {
        blockPool = nullptr;
    }
    if (blockPool) {
        mBlockPoolsMutex.lock();
        mBlockPools.emplace(blockPool->getLocalId(), blockPool);
        mBlockPoolsMutex.unlock();
    } else if (status == C2_OK) {
        status = C2_CORRUPTED;
    }

    _hidl_cb(static_cast<Status>(status),
            blockPool ? blockPool->getLocalId() : 0,
            new CachedConfigurable(
            std::make_unique<BlockPoolIntf>(blockPool)));
    return Void();
}

Return<Status> Component::destroyBlockPool(uint64_t blockPoolId) {
    std::lock_guard<std::mutex> lock(mBlockPoolsMutex);
    return mBlockPools.erase(blockPoolId) == 1 ?
            Status::OK : Status::CORRUPTED;
}

Return<Status> Component::start() {
    ALOGV("start");
    return static_cast<Status>(mComponent->start());
}

Return<Status> Component::stop() {
    ALOGV("stop");
    InputBufferManager::unregisterFrameData(mListener);
    return static_cast<Status>(mComponent->stop());
}

Return<Status> Component::reset() {
    ALOGV("reset");
    Status status = static_cast<Status>(mComponent->reset());
    {
        std::lock_guard<std::mutex> lock(mBlockPoolsMutex);
        mBlockPools.clear();
    }
    InputBufferManager::unregisterFrameData(mListener);
    return status;
}

Return<Status> Component::release() {
    ALOGV("release");
    Status status = static_cast<Status>(mComponent->release());
    {
        std::lock_guard<std::mutex> lock(mBlockPoolsMutex);
        mBlockPools.clear();
    }
    InputBufferManager::unregisterFrameData(mListener);
    return status;
}

void Component::setLocalId(const Component::LocalId& localId) {
    mLocalId = localId;
}

void Component::initListener(const sp<Component>& self) {
    std::shared_ptr<C2Component::Listener> c2listener =
            std::make_shared<Listener>(self);
    c2_status_t res = mComponent->setListener_vb(c2listener, C2_DONT_BLOCK);
    if (res != C2_OK) {
        mInit = res;
    }
}

Component::~Component() {
    InputBufferManager::unregisterFrameData(mListener);
    mStore->reportComponentDeath(mLocalId);
}

Component::InterfaceKey::InterfaceKey(const sp<IComponent>& component) {
    isRemote = component->isRemote();
    if (isRemote) {
        remote = ::android::hardware::toBinder(component);
    } else {
        local = component;
    }
}

// InputBufferManager implementation

constexpr nsecs_t InputBufferManager::kNotificationPeriodNs;

void InputBufferManager::registerFrameData(
        const sp<IComponentListener>& listener,
        const C2FrameData& input) {
    getInstance()._registerFrameData(listener, input);
}

void InputBufferManager::unregisterFrameData(
        const wp<IComponentListener>& listener,
        const C2FrameData& input) {
    getInstance()._unregisterFrameData(listener, input);
}

void InputBufferManager::unregisterFrameData(
        const wp<IComponentListener>& listener) {
    getInstance()._unregisterFrameData(listener);
}

void InputBufferManager::_registerFrameData(
        const sp<IComponentListener>& listener,
        const C2FrameData& input) {
    uint64_t frameIndex = input.ordinal.frameIndex.peeku();
    ALOGV("InputBufferManager::_registerFrameData called "
          "(listener @ %p, frameIndex = %llu)",
          listener.get(),
          static_cast<long long unsigned>(frameIndex));
    std::lock_guard<std::mutex> lock(mMutex);

    std::set<TrackedBuffer> &bufferIds =
            mTrackedBuffersMap[listener][frameIndex];

    for (size_t i = 0; i < input.buffers.size(); ++i) {
        if (!input.buffers[i]) {
            ALOGV("InputBufferManager::_registerFrameData: "
                  "Input buffer at index %zu is null", i);
            continue;
        }
        const TrackedBuffer &bufferId =
                *bufferIds.emplace(listener, frameIndex, i, input.buffers[i]).
                first;

        c2_status_t status = input.buffers[i]->registerOnDestroyNotify(
                onBufferDestroyed,
                const_cast<void*>(reinterpret_cast<const void*>(&bufferId)));
        if (status != C2_OK) {
            ALOGD("InputBufferManager: registerOnDestroyNotify failed "
                  "(listener @ %p, frameIndex = %llu, bufferIndex = %zu) "
                  "=> %s (%d)",
                  listener.get(),
                  static_cast<unsigned long long>(frameIndex),
                  i,
                  asString(status), static_cast<int>(status));
        }
    }

    mDeathNotifications.emplace(listener, DeathNotifications());
}

// Remove a pair (listener, frameIndex) from mTrackedBuffersMap and
// mDeathNotifications. This implies all bufferIndices are removed.
//
// This is called from onWorkDone() and flush().
void InputBufferManager::_unregisterFrameData(
        const wp<IComponentListener>& listener,
        const C2FrameData& input) {
    uint64_t frameIndex = input.ordinal.frameIndex.peeku();
    ALOGV("InputBufferManager::_unregisterFrameData called "
          "(listener @ %p, frameIndex = %llu)",
          listener.unsafe_get(),
          static_cast<long long unsigned>(frameIndex));
    std::lock_guard<std::mutex> lock(mMutex);

    auto findListener = mTrackedBuffersMap.find(listener);
    if (findListener != mTrackedBuffersMap.end()) {
        std::map<uint64_t, std::set<TrackedBuffer>> &frameIndex2BufferIds
                = findListener->second;
        auto findFrameIndex = frameIndex2BufferIds.find(frameIndex);
        if (findFrameIndex != frameIndex2BufferIds.end()) {
            std::set<TrackedBuffer> &bufferIds = findFrameIndex->second;
            for (const TrackedBuffer& bufferId : bufferIds) {
                std::shared_ptr<C2Buffer> buffer = bufferId.buffer.lock();
                if (buffer) {
                    c2_status_t status = buffer->unregisterOnDestroyNotify(
                            onBufferDestroyed,
                            const_cast<void*>(
                            reinterpret_cast<const void*>(&bufferId)));
                    if (status != C2_OK) {
                        ALOGD("InputBufferManager: "
                              "unregisterOnDestroyNotify failed "
                              "(listener @ %p, "
                              "frameIndex = %llu, "
                              "bufferIndex = %zu) "
                              "=> %s (%d)",
                              bufferId.listener.unsafe_get(),
                              static_cast<unsigned long long>(
                                  bufferId.frameIndex),
                              bufferId.bufferIndex,
                              asString(status), static_cast<int>(status));
                    }
                }
            }

            frameIndex2BufferIds.erase(findFrameIndex);
            if (frameIndex2BufferIds.empty()) {
                mTrackedBuffersMap.erase(findListener);
            }
        }
    }

    auto findListenerD = mDeathNotifications.find(listener);
    if (findListenerD != mDeathNotifications.end()) {
        DeathNotifications &deathNotifications = findListenerD->second;
        auto findFrameIndex = deathNotifications.indices.find(frameIndex);
        if (findFrameIndex != deathNotifications.indices.end()) {
            std::vector<size_t> &bufferIndices = findFrameIndex->second;
            deathNotifications.count -= bufferIndices.size();
            deathNotifications.indices.erase(findFrameIndex);
        }
    }
}

// Remove listener from mTrackedBuffersMap and mDeathNotifications. This implies
// all frameIndices and bufferIndices are removed.
//
// This is called when the component cleans up all input buffers, i.e., when
// reset(), release(), stop() or ~Component() is called.
void InputBufferManager::_unregisterFrameData(
        const wp<IComponentListener>& listener) {
    ALOGV("InputBufferManager::_unregisterFrameData called (listener @ %p)",
            listener.unsafe_get());
    std::lock_guard<std::mutex> lock(mMutex);

    auto findListener = mTrackedBuffersMap.find(listener);
    if (findListener != mTrackedBuffersMap.end()) {
        std::map<uint64_t, std::set<TrackedBuffer>> &frameIndex2BufferIds =
                findListener->second;
        for (auto findFrameIndex = frameIndex2BufferIds.begin();
                findFrameIndex != frameIndex2BufferIds.end();
                ++findFrameIndex) {
            std::set<TrackedBuffer> &bufferIds = findFrameIndex->second;
            for (const TrackedBuffer& bufferId : bufferIds) {
                std::shared_ptr<C2Buffer> buffer = bufferId.buffer.lock();
                if (buffer) {
                    c2_status_t status = buffer->unregisterOnDestroyNotify(
                            onBufferDestroyed,
                            const_cast<void*>(
                            reinterpret_cast<const void*>(&bufferId)));
                    if (status != C2_OK) {
                        ALOGD("InputBufferManager: "
                              "unregisterOnDestroyNotify failed "
                              "(listener @ %p, "
                              "frameIndex = %llu, "
                              "bufferIndex = %zu) "
                              "=> %s (%d)",
                              bufferId.listener.unsafe_get(),
                              static_cast<unsigned long long>(bufferId.frameIndex),
                              bufferId.bufferIndex,
                              asString(status), static_cast<int>(status));
                    }
                }
            }
        }
        mTrackedBuffersMap.erase(findListener);
    }

    mDeathNotifications.erase(listener);
}

// Move a buffer from mTrackedBuffersMap to mDeathNotifications.
// This is called when a registered C2Buffer object is destroyed.
void InputBufferManager::onBufferDestroyed(const C2Buffer* buf, void* arg) {
    getInstance()._onBufferDestroyed(buf, arg);
}

void InputBufferManager::_onBufferDestroyed(const C2Buffer* buf, void* arg) {
    if (!buf || !arg) {
        ALOGW("InputBufferManager::_onBufferDestroyed called "
              "with null argument(s) (buf @ %p, arg @ %p)",
              buf, arg);
        return;
    }
    TrackedBuffer id(*reinterpret_cast<TrackedBuffer*>(arg));
    ALOGV("InputBufferManager::_onBufferDestroyed called "
          "(listener @ %p, frameIndex = %llu, bufferIndex = %zu)",
          id.listener.unsafe_get(),
          static_cast<unsigned long long>(id.frameIndex),
          id.bufferIndex);

    std::lock_guard<std::mutex> lock(mMutex);

    auto findListener = mTrackedBuffersMap.find(id.listener);
    if (findListener == mTrackedBuffersMap.end()) {
        ALOGD("InputBufferManager::_onBufferDestroyed received "
              "invalid listener "
              "(listener @ %p, frameIndex = %llu, bufferIndex = %zu)",
              id.listener.unsafe_get(),
              static_cast<unsigned long long>(id.frameIndex),
              id.bufferIndex);
        return;
    }

    std::map<uint64_t, std::set<TrackedBuffer>> &frameIndex2BufferIds
            = findListener->second;
    auto findFrameIndex = frameIndex2BufferIds.find(id.frameIndex);
    if (findFrameIndex == frameIndex2BufferIds.end()) {
        ALOGD("InputBufferManager::_onBufferDestroyed received "
              "invalid frame index "
              "(listener @ %p, frameIndex = %llu, bufferIndex = %zu)",
              id.listener.unsafe_get(),
              static_cast<unsigned long long>(id.frameIndex),
              id.bufferIndex);
        return;
    }

    std::set<TrackedBuffer> &bufferIds = findFrameIndex->second;
    auto findBufferId = bufferIds.find(id);
    if (findBufferId == bufferIds.end()) {
        ALOGD("InputBufferManager::_onBufferDestroyed received "
              "invalid buffer index: "
              "(listener @ %p, frameIndex = %llu, bufferIndex = %zu)",
              id.listener.unsafe_get(),
              static_cast<unsigned long long>(id.frameIndex),
              id.bufferIndex);
    }

    bufferIds.erase(findBufferId);
    if (bufferIds.empty()) {
        frameIndex2BufferIds.erase(findFrameIndex);
        if (frameIndex2BufferIds.empty()) {
            mTrackedBuffersMap.erase(findListener);
        }
    }

    DeathNotifications &deathNotifications = mDeathNotifications[id.listener];
    deathNotifications.indices[id.frameIndex].emplace_back(id.bufferIndex);
    ++deathNotifications.count;
    mOnBufferDestroyed.notify_one();
}

// Notify the clients about buffer destructions.
// Return false if all destructions have been notified.
// Return true and set timeToRetry to the time point to wait for before
// retrying if some destructions have not been notified.
bool InputBufferManager::processNotifications(nsecs_t* timeToRetryNs) {

    struct Notification {
        sp<IComponentListener> listener;
        hidl_vec<IComponentListener::RenderedFrame> renderedFrames;
        Notification(const sp<IComponentListener>& l, size_t s)
              : listener(l), renderedFrames(s) {}
    };
    std::list<Notification> notifications;

    bool retry = false;
    {
        std::lock_guard<std::mutex> lock(mMutex);
        *timeToRetryNs = kNotificationPeriodNs;
        nsecs_t timeNowNs = systemTime();
        for (auto it = mDeathNotifications.begin();
                it != mDeathNotifications.end(); ) {
            sp<IComponentListener> listener = it->first.promote();
            if (!listener) {
                ++it;
                continue;
            }
            DeathNotifications &deathNotifications = it->second;

            nsecs_t timeSinceLastNotifiedNs =
                    timeNowNs - deathNotifications.lastSentNs;
            // If not enough time has passed since the last callback, leave the
            // notifications for this listener untouched for now and retry
            // later.
            if (timeSinceLastNotifiedNs < kNotificationPeriodNs) {
                retry = true;
                *timeToRetryNs = std::min(*timeToRetryNs,
                        kNotificationPeriodNs - timeSinceLastNotifiedNs);
                ALOGV("InputBufferManager: Notifications for "
                      "listener @ %p will be postponed.",
                      listener.get());
                ++it;
                continue;
            }

            // If enough time has passed since the last notification to this
            // listener but there are currently no pending notifications, the
            // listener can be removed from mDeathNotifications---there is no
            // need to keep track of the last notification time anymore.
            if (deathNotifications.count == 0) {
                it = mDeathNotifications.erase(it);
                continue;
            }

            // Create the argument for the callback.
            notifications.emplace_back(listener, deathNotifications.count);
            hidl_vec<IComponentListener::RenderedFrame>& renderedFrames =
                    notifications.back().renderedFrames;
            size_t i = 0;
            for (std::pair<const uint64_t, std::vector<size_t>>& p :
                    deathNotifications.indices) {
                uint64_t frameIndex = p.first;
                const std::vector<size_t> &bufferIndices = p.second;
                for (const size_t& bufferIndex : bufferIndices) {
                    IComponentListener::RenderedFrame &renderedFrame
                            = renderedFrames[i++];
                    renderedFrame.slotId = ~bufferIndex;
                    renderedFrame.bufferQueueId = frameIndex;
                    renderedFrame.timestampNs = timeNowNs;
                    ALOGV("InputBufferManager: "
                          "Sending death notification (listener @ %p, "
                          "frameIndex = %llu, bufferIndex = %zu)",
                          listener.get(),
                          static_cast<long long unsigned>(frameIndex),
                          bufferIndex);
                }
            }

            // Clear deathNotifications for this listener and set retry to true
            // so processNotifications will be called again. This will
            // guarantee that a listener with no pending notifications will
            // eventually be removed from mDeathNotifications after
            // kNotificationPeriodNs nanoseconds has passed.
            retry = true;
            deathNotifications.indices.clear();
            deathNotifications.count = 0;
            deathNotifications.lastSentNs = timeNowNs;
            ++it;
        }
    }

    // Call onFramesRendered outside the lock to avoid deadlock.
    for (const Notification& notification : notifications) {
        if (!notification.listener->onFramesRendered(
                notification.renderedFrames).isOk()) {
            // This may trigger if the client has died.
            ALOGD("InputBufferManager: onFramesRendered transaction failed "
                  "(listener @ %p)",
                  notification.listener.get());
        }
    }
    if (retry) {
        ALOGV("InputBufferManager: Pending death notifications"
              "will be sent in %lldns.",
              static_cast<long long>(*timeToRetryNs));
    }
    return retry;
}

void InputBufferManager::main() {
    ALOGV("InputBufferManager: Starting main thread");
    nsecs_t timeToRetryNs;
    while (true) {
        std::unique_lock<std::mutex> lock(mMutex);
        while (mDeathNotifications.empty()) {
            ALOGV("InputBufferManager: Waiting for buffer deaths");
            mOnBufferDestroyed.wait(lock);
        }
        lock.unlock();
        ALOGV("InputBufferManager: Sending buffer death notifications");
        while (processNotifications(&timeToRetryNs)) {
            std::this_thread::sleep_for(
                    std::chrono::nanoseconds(timeToRetryNs));
            ALOGV("InputBufferManager: Sending pending death notifications");
        }
        ALOGV("InputBufferManager: No pending death notifications");
    }
}

InputBufferManager::InputBufferManager()
      : mMainThread(&InputBufferManager::main, this) {
}

InputBufferManager& InputBufferManager::getInstance() {
    static InputBufferManager instance{};
    return instance;
}

}  // namespace utils
}  // namespace V1_0
}  // namespace c2
}  // namespace media
}  // namespace google
}  // namespace hardware
