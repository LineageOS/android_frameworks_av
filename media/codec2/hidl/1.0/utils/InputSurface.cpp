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
#define LOG_TAG "Codec2-InputSurface"
#include <log/log.h>

#include <codec2/hidl/1.0/InputSurface.h>
#include <codec2/hidl/1.0/InputSurfaceConnection.h>

#include <util/C2InterfaceHelper.h>
#include <C2Component.h>
#include <C2Config.h>

#include <memory>

namespace android {
namespace hardware {
namespace media {
namespace c2 {
namespace V1_0 {
namespace utils {

using namespace ::android;

class InputSurface::ConfigurableImpl : public C2InterfaceHelper {
public:
    explicit ConfigurableImpl(
            const std::shared_ptr<C2ReflectorHelper> &helper)
        : C2InterfaceHelper(helper) {

        setDerivedInstance(this);

        addParameter(
                DefineParam(mEos, C2_NAME_INPUT_SURFACE_EOS_TUNING)
                .withDefault(new C2InputSurfaceEosTuning(false))
                .withFields({C2F(mEos, value).oneOf({true, false})})
                .withSetter(EosSetter)
                .build());
    }

    static C2R EosSetter(bool mayBlock, C2P<C2InputSurfaceEosTuning> &me) {
        (void)mayBlock;
        return me.F(me.v.value).validatePossible(me.v.value);
    }

    bool eos() const { return mEos->value; }

private:
    std::shared_ptr<C2InputSurfaceEosTuning> mEos;
};

namespace {

class ConfigurableWrapper : public ConfigurableC2Intf {
public:
    ConfigurableWrapper(
            const std::shared_ptr<InputSurface::ConfigurableImpl> &impl,
            const sp<GraphicBufferSource> &source)
        : ConfigurableC2Intf("input-surface"),
          mImpl(impl),
          mSource(source) {
    }

    ~ConfigurableWrapper() override = default;

    c2_status_t query(
            const std::vector<C2Param::Index> &indices,
            c2_blocking_t mayBlock,
            std::vector<std::unique_ptr<C2Param>>* const params) const override {
        return mImpl->query({}, indices, mayBlock, params);
    }

    c2_status_t config(
            const std::vector<C2Param*> &params,
            c2_blocking_t mayBlock,
            std::vector<std::unique_ptr<C2SettingResult>>* const failures) override {
        c2_status_t err = mImpl->config(params, mayBlock, failures);
        if (mImpl->eos()) {
            sp<GraphicBufferSource> source = mSource.promote();
            if (source == nullptr || source->signalEndOfInputStream() != OK) {
                // TODO: put something in |failures|
                err = C2_BAD_VALUE;
            }
            // TODO: reset eos?
        }
        return err;
    }

    c2_status_t querySupportedParams(
            std::vector<std::shared_ptr<C2ParamDescriptor>>* const params) const override {
        return mImpl->querySupportedParams(params);
    }

    c2_status_t querySupportedValues(
            std::vector<C2FieldSupportedValuesQuery>& fields,
            c2_blocking_t mayBlock) const override {
        return mImpl->querySupportedValues(fields, mayBlock);
    }

private:
    const std::shared_ptr<InputSurface::ConfigurableImpl> mImpl;
    wp<GraphicBufferSource> mSource;
};

}  // namespace


Return<void> InputSurface::connectToComponent(
        const sp<IComponent>& component,
        connectToComponent_cb _hidl_cb) {
    Status status;
    sp<InputSurfaceConnection> conn;
    if (!component) {
        status = Status::BAD_VALUE;
    } else {
        std::shared_ptr<C2Component> comp = mStore->findC2Component(component);
        if (!comp) {
            conn = new InputSurfaceConnection(mSource, component);
        } else {
            conn = new InputSurfaceConnection(mSource, comp);
        }
        if (!conn->init()) {
            conn = nullptr;
            status = Status::BAD_VALUE;
        } else {
            status = Status::OK;
        }
    }
    _hidl_cb(status, conn);
    return Void();
}

Return<sp<IConfigurable>> InputSurface::getConfigurable() {
    return mConfigurable;
}

// Derived methods from IGraphicBufferProducer

Return<void> InputSurface::requestBuffer(
        int32_t slot,
        requestBuffer_cb _hidl_cb) {
    return mBase->requestBuffer(slot, _hidl_cb);
}

Return<int32_t> InputSurface::setMaxDequeuedBufferCount(
        int32_t maxDequeuedBuffers) {
    return mBase->setMaxDequeuedBufferCount(maxDequeuedBuffers);
}

Return<int32_t> InputSurface::setAsyncMode(
        bool async) {
    return mBase->setAsyncMode(async);
}

Return<void> InputSurface::dequeueBuffer(
        uint32_t width,
        uint32_t height,
        PixelFormat format,
        uint32_t usage,
        bool getFrameTimestamps,
        dequeueBuffer_cb _hidl_cb) {
    return mBase->dequeueBuffer(
            width, height, format, usage, getFrameTimestamps, _hidl_cb);
}

Return<int32_t> InputSurface::detachBuffer(
        int32_t slot) {
    return mBase->detachBuffer(slot);
}

Return<void> InputSurface::detachNextBuffer(
        detachNextBuffer_cb _hidl_cb) {
    return mBase->detachNextBuffer(_hidl_cb);
}

Return<void> InputSurface::attachBuffer(
        const AnwBuffer& buffer,
        attachBuffer_cb _hidl_cb) {
    return mBase->attachBuffer(buffer, _hidl_cb);
}

Return<void> InputSurface::queueBuffer(
        int32_t slot,
        const QueueBufferInput& input,
        queueBuffer_cb _hidl_cb) {
    return mBase->queueBuffer(slot, input, _hidl_cb);
}

Return<int32_t> InputSurface::cancelBuffer(
        int32_t slot,
        const hidl_handle& fence) {
    return mBase->cancelBuffer(slot, fence);
}

Return<void> InputSurface::query(
        int32_t what,
        query_cb _hidl_cb) {
    return mBase->query(what, _hidl_cb);
}

Return<void> InputSurface::connect(
        const sp<HProducerListener>& listener,
        int32_t api,
        bool producerControlledByApp,
        connect_cb _hidl_cb) {
    return mBase->connect(listener, api, producerControlledByApp, _hidl_cb);
}

Return<int32_t> InputSurface::disconnect(
        int32_t api,
        DisconnectMode mode) {
    return mBase->disconnect(api, mode);
}

Return<int32_t> InputSurface::setSidebandStream(
        const hidl_handle& stream) {
    return mBase->setSidebandStream(stream);
}

Return<void> InputSurface::allocateBuffers(
        uint32_t width,
        uint32_t height,
        PixelFormat format,
        uint32_t usage) {
    return mBase->allocateBuffers(width, height, format, usage);
}

Return<int32_t> InputSurface::allowAllocation(
        bool allow) {
    return mBase->allowAllocation(allow);
}

Return<int32_t> InputSurface::setGenerationNumber(
        uint32_t generationNumber) {
    return mBase->setGenerationNumber(generationNumber);
}

Return<void> InputSurface::getConsumerName(
        getConsumerName_cb _hidl_cb) {
    return mBase->getConsumerName(_hidl_cb);
}

Return<int32_t> InputSurface::setSharedBufferMode(
        bool sharedBufferMode) {
    return mBase->setSharedBufferMode(sharedBufferMode);
}

Return<int32_t> InputSurface::setAutoRefresh(
        bool autoRefresh) {
    return mBase->setAutoRefresh(autoRefresh);
}

Return<int32_t> InputSurface::setDequeueTimeout(
        int64_t timeoutNs) {
    return mBase->setDequeueTimeout(timeoutNs);
}

Return<void> InputSurface::getLastQueuedBuffer(
        getLastQueuedBuffer_cb _hidl_cb) {
    return mBase->getLastQueuedBuffer(_hidl_cb);
}

Return<void> InputSurface::getFrameTimestamps(
        getFrameTimestamps_cb _hidl_cb) {
    return mBase->getFrameTimestamps(_hidl_cb);
}

Return<void> InputSurface::getUniqueId(
        getUniqueId_cb _hidl_cb) {
    return mBase->getUniqueId(_hidl_cb);
}

// Constructor is exclusive to ComponentStore.
InputSurface::InputSurface(
        const sp<ComponentStore>& store,
        const std::shared_ptr<C2ReflectorHelper>& reflector,
        const sp<HGraphicBufferProducer>& base,
        const sp<GraphicBufferSource>& source) :
    mStore(store),
    mBase(base),
    mSource(source),
    mHelper(std::make_shared<ConfigurableImpl>(reflector)),
    mConfigurable(new CachedConfigurable(
            std::make_unique<ConfigurableWrapper>(mHelper, source))) {

    mConfigurable->init(store.get());
}

}  // namespace utils
}  // namespace V1_0
}  // namespace c2
}  // namespace media
}  // namespace hardware
}  // namespace android

