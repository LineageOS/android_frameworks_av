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

#ifndef CODEC2_HIDL_CLIENT_H
#define CODEC2_HIDL_CLIENT_H

#include <gui/IGraphicBufferProducer.h>
#include <codec2/hidl/1.0/types.h>

#include <C2PlatformSupport.h>
#include <C2Component.h>
#include <C2Buffer.h>
#include <C2Param.h>
#include <C2.h>

#include <hidl/HidlSupport.h>
#include <utils/StrongPointer.h>

#include <functional>
#include <map>
#include <memory>
#include <mutex>

/**
 * This file contains minimal interfaces for the framework to access Codec2.0.
 *
 * Codec2Client is the main class that contains the following inner classes:
 * - Listener
 * - Configurable
 * - Interface
 * - Component
 *
 * Classes in Codec2Client, interfaces in Codec2.0, and  HIDL interfaces are
 * related as follows:
 * - Codec2Client <==> C2ComponentStore <==> IComponentStore
 * - Codec2Client::Listener <==> C2Component::Listener <==> IComponentListener
 * - Codec2Client::Configurable <==> [No equivalent] <==> IConfigurable
 * - Codec2Client::Interface <==> C2ComponentInterface <==> IComponentInterface
 * - Codec2Client::Component <==> C2Component <==> IComponent
 *
 * The entry point is Codec2Client::CreateFromService(), which creates a
 * Codec2Client object. From Codec2Client, Interface and Component objects can
 * be created by calling createComponent() and createInterface().
 *
 * createComponent() takes a Listener object, which must be implemented by the
 * user.
 *
 * At the present, createBlockPool() is the only method that yields a
 * Configurable object. Note, however, that Interface, Component and
 * Codec2Client are all subclasses of Configurable.
 */

// Forward declaration of Codec2.0 HIDL interfaces
namespace android {
namespace hardware {
namespace media {
namespace c2 {
namespace V1_0 {
struct IConfigurable;
struct IComponent;
struct IComponentInterface;
struct IComponentStore;
struct IInputSurface;
struct IInputSurfaceConnection;
} // namespace V1_0
} // namespace c2
} // namespace media
} // namespace hardware
} // namespace android

namespace android {
namespace hardware {
namespace media {
namespace bufferpool {
namespace V2_0 {
struct IClientManager;
} // namespace V2_0
} // namespace bufferpool
} // namespace media
} // namespace hardware
} // namespace android

// Forward declarations of other classes
namespace android {
namespace hardware {
namespace graphics {
namespace bufferqueue {
namespace V1_0 {
struct IGraphicBufferProducer;
} // namespace V1_0
} // namespace bufferqueue
} // namespace graphics
namespace media {
namespace omx {
namespace V1_0 {
struct IGraphicBufferSource;
} // namespace V1_0
} // namespace omx
} // namespace media
} // namespace hardware
} // namespace android

namespace android {

// This class is supposed to be called Codec2Client::Configurable, but forward
// declaration of an inner class is not possible.
struct Codec2ConfigurableClient {

    typedef ::android::hardware::media::c2::V1_0::IConfigurable Base;

    const C2String& getName() const;

    c2_status_t query(
            const std::vector<C2Param*>& stackParams,
            const std::vector<C2Param::Index> &heapParamIndices,
            c2_blocking_t mayBlock,
            std::vector<std::unique_ptr<C2Param>>* const heapParams) const;

    c2_status_t config(
            const std::vector<C2Param*> &params,
            c2_blocking_t mayBlock,
            std::vector<std::unique_ptr<C2SettingResult>>* const failures);

    c2_status_t querySupportedParams(
            std::vector<std::shared_ptr<C2ParamDescriptor>>* const params
            ) const;

    c2_status_t querySupportedValues(
            std::vector<C2FieldSupportedValuesQuery>& fields,
            c2_blocking_t mayBlock) const;

    // base cannot be null.
    Codec2ConfigurableClient(const sp<Base>& base);

protected:
    sp<Base> mBase;
    C2String mName;

    friend struct Codec2Client;
};

struct Codec2Client : public Codec2ConfigurableClient {

    typedef ::android::hardware::media::c2::V1_0::IComponentStore Base;

    struct Listener;

    typedef Codec2ConfigurableClient Configurable;

    struct Component;

    struct Interface;

    struct InputSurface;

    struct InputSurfaceConnection;

    typedef Codec2Client Store;

    std::string getServiceName() const { return mServiceName; }

    c2_status_t createComponent(
            const C2String& name,
            const std::shared_ptr<Listener>& listener,
            std::shared_ptr<Component>* const component);

    c2_status_t createInterface(
            const C2String& name,
            std::shared_ptr<Interface>* const interface);

    c2_status_t createInputSurface(
            std::shared_ptr<InputSurface>* const inputSurface);

    const std::vector<C2Component::Traits>& listComponents() const;

    c2_status_t copyBuffer(
            const std::shared_ptr<C2Buffer>& src,
            const std::shared_ptr<C2Buffer>& dst);

    std::shared_ptr<C2ParamReflector> getParamReflector();

    static std::shared_ptr<Codec2Client> CreateFromService(
            const char* serviceName,
            bool waitForService = true);

    // Try to create a component with a given name from all known
    // IComponentStore services.
    static std::shared_ptr<Component> CreateComponentByName(
            const char* componentName,
            const std::shared_ptr<Listener>& listener,
            std::shared_ptr<Codec2Client>* owner = nullptr);

    // Try to create a component interface with a given name from all known
    // IComponentStore services.
    static std::shared_ptr<Interface> CreateInterfaceByName(
            const char* interfaceName,
            std::shared_ptr<Codec2Client>* owner = nullptr);

    // List traits from all known IComponentStore services.
    static const std::vector<C2Component::Traits>& ListComponents();

    // Create an input surface.
    static std::shared_ptr<InputSurface> CreateInputSurface();

    // base cannot be null.
    Codec2Client(const sp<Base>& base, std::string serviceName);

protected:
    sp<Base> mBase;

    // Finds the first store where the predicate returns OK, and returns the last
    // predicate result. Uses key to remember the last store found, and if cached,
    // it tries that store before trying all stores (one retry).
    static c2_status_t ForAllStores(
            const std::string& key,
            std::function<c2_status_t(const std::shared_ptr<Codec2Client>&)> predicate);

    mutable std::mutex mMutex;
    mutable bool mListed;
    std::string mServiceName;
    mutable std::vector<C2Component::Traits> mTraitsList;

    sp<::android::hardware::media::bufferpool::V2_0::IClientManager>
            mHostPoolManager;
};

struct Codec2Client::Interface : public Codec2Client::Configurable {

    typedef ::android::hardware::media::c2::V1_0::IComponentInterface Base;

    Interface(const sp<Base>& base);

protected:
    sp<Base> mBase;
};

struct Codec2Client::Listener {

    // This is called when the component produces some output.
    //
    // numDiscardedInputBuffers is the number of input buffers contained in
    // workItems that have just become unused. Note that workItems may contain
    // more input buffers than numDiscardedInputBuffers because buffers that
    // have been previously reported by onInputBufferDone() are not counted
    // towards numDiscardedInputBuffers, but may still show up in workItems.
    virtual void onWorkDone(
            const std::weak_ptr<Component>& comp,
            std::list<std::unique_ptr<C2Work>>& workItems,
            size_t numDiscardedInputBuffers) = 0;

    // This is called when the component goes into a tripped state.
    virtual void onTripped(
            const std::weak_ptr<Component>& comp,
            const std::vector<std::shared_ptr<C2SettingResult>>& settingResults
            ) = 0;

    // This is called when the component encounters an error.
    virtual void onError(
            const std::weak_ptr<Component>& comp,
            uint32_t errorCode) = 0;

    // This is called when the process that hosts the component shuts down
    // unexpectedly.
    virtual void onDeath(
            const std::weak_ptr<Component>& comp) = 0;

    // This is called when an input buffer is no longer in use by the codec.
    // Input buffers that have been returned by onWorkDone() or flush() will not
    // trigger a call to this function.
    virtual void onInputBufferDone(
            const std::shared_ptr<C2Buffer>& buffer) = 0;

    // This is called when the component becomes aware of a frame being
    // rendered.
    virtual void onFrameRendered(
            uint64_t bufferQueueId,
            int32_t slotId,
            int64_t timestampNs) = 0;

    virtual ~Listener();

};

struct Codec2Client::Component : public Codec2Client::Configurable {

    typedef ::android::hardware::media::c2::V1_0::IComponent Base;

    c2_status_t createBlockPool(
            C2Allocator::id_t id,
            C2BlockPool::local_id_t* blockPoolId,
            std::shared_ptr<Configurable>* configurable);

    c2_status_t destroyBlockPool(
            C2BlockPool::local_id_t localId);

    c2_status_t queue(
            std::list<std::unique_ptr<C2Work>>* const items);

    c2_status_t flush(
            C2Component::flush_mode_t mode,
            std::list<std::unique_ptr<C2Work>>* const flushedWork);

    c2_status_t drain(C2Component::drain_mode_t mode);

    c2_status_t start();

    c2_status_t stop();

    c2_status_t reset();

    c2_status_t release();

    typedef ::android::
            IGraphicBufferProducer IGraphicBufferProducer;
    typedef IGraphicBufferProducer::
            QueueBufferInput QueueBufferInput;
    typedef IGraphicBufferProducer::
            QueueBufferOutput QueueBufferOutput;

    typedef ::android::hardware::graphics::bufferqueue::V1_0::
            IGraphicBufferProducer HGraphicBufferProducer;
    typedef ::android::hardware::media::omx::V1_0::
            IGraphicBufferSource HGraphicBufferSource;

    // Set the output surface to be used with a blockpool previously created by
    // createBlockPool().
    c2_status_t setOutputSurface(
            C2BlockPool::local_id_t blockPoolId,
            const sp<IGraphicBufferProducer>& surface,
            uint32_t generation);

    // Extract a slot number from of the block, then call
    // IGraphicBufferProducer::queueBuffer().
    //
    // If the output surface has not been set, NO_INIT will be returned.
    //
    // If the block does not come from a bufferqueue-based blockpool,
    // attachBuffer() will be called, followed by queueBuffer().
    //
    // If the block has a bqId that does not match the id of the output surface,
    // DEAD_OBJECT will be returned.
    //
    // If the call to queueBuffer() is successful but the block cannot be
    // associated to the output surface for automatic cancellation upon
    // destruction, UNKNOWN_ERROR will be returned.
    //
    // Otherwise, the return value from queueBuffer() will be returned.
    status_t queueToOutputSurface(
            const C2ConstGraphicBlock& block,
            const QueueBufferInput& input,
            QueueBufferOutput* output);

    // Connect to a given InputSurface.
    c2_status_t connectToInputSurface(
            const std::shared_ptr<InputSurface>& inputSurface,
            std::shared_ptr<InputSurfaceConnection>* connection);

    c2_status_t connectToOmxInputSurface(
            const sp<HGraphicBufferProducer>& producer,
            const sp<HGraphicBufferSource>& source,
            std::shared_ptr<InputSurfaceConnection>* connection);

    c2_status_t disconnectFromInputSurface();

    // base cannot be null.
    Component(const sp<Base>& base);

    ~Component();

protected:
    sp<Base> mBase;

    // Mutex for mInputBuffers and mInputBufferCount.
    mutable std::mutex mInputBuffersMutex;

    // Map: frameIndex -> vector of bufferIndices
    //
    // mInputBuffers[frameIndex][bufferIndex] may be null if the buffer in that
    // slot has been freed.
    mutable std::map<uint64_t, std::vector<std::shared_ptr<C2Buffer>>>
            mInputBuffers;

    // Map: frameIndex -> number of bufferIndices that have not been freed
    //
    // mInputBufferCount[frameIndex] keeps track of the number of non-null
    // elements in mInputBuffers[frameIndex]. When mInputBufferCount[frameIndex]
    // decreases to 0, frameIndex can be removed from both mInputBuffers and
    // mInputBufferCount.
    mutable std::map<uint64_t, size_t> mInputBufferCount;

    ::android::hardware::media::c2::V1_0::utils::DefaultBufferPoolSender
            mBufferPoolSender;

    std::mutex mOutputBufferQueueMutex;
    sp<IGraphicBufferProducer> mOutputIgbp;
    uint64_t mOutputBqId;
    uint32_t mOutputGeneration;

    static c2_status_t setDeathListener(
            const std::shared_ptr<Component>& component,
            const std::shared_ptr<Listener>& listener);
    sp<::android::hardware::hidl_death_recipient> mDeathRecipient;

    friend struct Codec2Client;

    struct HidlListener;
    // Return the number of input buffers that should be discarded.
    size_t handleOnWorkDone(const std::list<std::unique_ptr<C2Work>> &workItems);
    // Remove an input buffer from mInputBuffers and return it.
    std::shared_ptr<C2Buffer> freeInputBuffer(uint64_t frameIndex, size_t bufferIndex);

};

struct Codec2Client::InputSurface : public Codec2Client::Configurable {
public:
    typedef ::android::hardware::media::c2::V1_0::IInputSurface Base;

    typedef ::android::hardware::media::c2::V1_0::IInputSurfaceConnection
            ConnectionBase;

    typedef Codec2Client::InputSurfaceConnection Connection;

    typedef ::android::IGraphicBufferProducer IGraphicBufferProducer;

    sp<IGraphicBufferProducer> getGraphicBufferProducer() const;

    // Return the underlying IInputSurface.
    sp<Base> getHalInterface() const;

    // base cannot be null.
    InputSurface(const sp<Base>& base);

protected:
    sp<Base> mBase;

    sp<IGraphicBufferProducer> mGraphicBufferProducer;

    friend struct Codec2Client;
    friend struct Component;
};

struct Codec2Client::InputSurfaceConnection : public Codec2Client::Configurable {

    typedef ::android::hardware::media::c2::V1_0::IInputSurfaceConnection Base;

    c2_status_t disconnect();

    // base cannot be null.
    InputSurfaceConnection(const sp<Base>& base);

protected:
    sp<Base> mBase;

    friend struct Codec2Client::InputSurface;
};

}  // namespace android

#endif  // CODEC2_HIDL_CLIENT_H

