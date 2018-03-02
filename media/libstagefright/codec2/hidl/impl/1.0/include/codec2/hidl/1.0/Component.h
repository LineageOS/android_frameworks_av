#ifndef VENDOR_GOOGLE_MEDIA_C2_V1_0_COMPONENT_H
#define VENDOR_GOOGLE_MEDIA_C2_V1_0_COMPONENT_H

#include <codec2/hidl/1.0/Configurable.h>

#include <vendor/google/media/c2/1.0/IComponentListener.h>
#include <vendor/google/media/c2/1.0/IComponentStore.h>
#include <vendor/google/media/c2/1.0/IComponent.h>
#include <hidl/MQDescriptor.h>
#include <hidl/Status.h>

#include <C2Component.h>
#include <C2.h>

namespace vendor {
namespace google {
namespace media {
namespace c2 {
namespace V1_0 {
namespace implementation {

using ::android::hardware::hidl_array;
using ::android::hardware::hidl_memory;
using ::android::hardware::hidl_string;
using ::android::hardware::hidl_vec;
using ::android::hardware::Return;
using ::android::hardware::Void;
using ::android::sp;

struct ComponentStore;

struct ComponentInterface : public Configurable<IComponentInterface> {
    ComponentInterface(
            const std::shared_ptr<C2ComponentInterface>& interface,
            const sp<ComponentStore>& store);
    c2_status_t status() const;

protected:
    c2_status_t mInit;
    std::shared_ptr<C2ComponentInterface> mInterface;
    // sp<ComponentStore> mStore; // TODO needed?
};

struct Component : public Configurable<IComponent> {
    Component(
            const std::shared_ptr<C2Component>&,
            const sp<IComponentListener>& listener,
            const sp<ComponentStore>& store);

    // Methods from gIComponent follow.
    virtual Return<Status> queue(const WorkBundle& workBundle) override;
    virtual Return<void> flush(flush_cb _hidl_cb) override;
    virtual Return<Status> drain(bool withEos) override;
    virtual Return<Status> connectToInputSurface(
            const sp<IInputSurface>& surface) override;
    virtual Return<Status> connectToOmxInputSurface(
            const sp<::android::hardware::graphics::bufferqueue::V1_0::
            IGraphicBufferProducer>& producer,
            const sp<::android::hardware::media::omx::V1_0::
            IGraphicBufferSource>& source) override;
    virtual Return<Status> disconnectFromInputSurface() override;
    virtual Return<void> createBlockPool(
            uint32_t allocatorId,
            createBlockPool_cb _hidl_cb) override;
    virtual Return<Status> start() override;
    virtual Return<Status> stop() override;
    virtual Return<Status> reset() override;
    virtual Return<Status> release() override;

protected:
    c2_status_t mInit;
    std::shared_ptr<C2Component> mComponent;
    std::shared_ptr<C2ComponentInterface> mInterface;
    sp<IComponentListener> mListener;
    // sp<ComponentStore> mStore; // TODO needed?
};

}  // namespace implementation
}  // namespace V1_0
}  // namespace c2
}  // namespace media
}  // namespace google
}  // namespace vendor

#endif  // VENDOR_GOOGLE_MEDIA_C2_V1_0_COMPONENT_H
