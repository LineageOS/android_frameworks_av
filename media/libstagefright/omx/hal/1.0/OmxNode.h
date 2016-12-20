#ifndef ANDROID_HARDWARE_MEDIA_OMX_V1_0_OMXNODE_H
#define ANDROID_HARDWARE_MEDIA_OMX_V1_0_OMXNODE_H

#include <android/hardware/media/omx/1.0/IOmxNode.h>
#include <android/hardware/media/omx/1.0/IOmxObserver.h>
#include <hidl/MQDescriptor.h>
#include <hidl/Status.h>

#include <OMXNodeInstance.h>

namespace android {
namespace hardware {
namespace media {
namespace omx {
namespace V1_0 {
namespace implementation {

using ::android::hardware::media::omx::V1_0::CodecBuffer;
using ::android::hardware::media::omx::V1_0::IOmxBufferSource;
using ::android::hardware::media::omx::V1_0::IOmxNode;
using ::android::hardware::media::omx::V1_0::IOmxObserver;
using ::android::hardware::media::omx::V1_0::Message;
using ::android::hardware::media::omx::V1_0::PortMode;
using ::android::hardware::media::omx::V1_0::Status;
using ::android::hidl::base::V1_0::IBase;
using ::android::hardware::hidl_array;
using ::android::hardware::hidl_memory;
using ::android::hardware::hidl_string;
using ::android::hardware::hidl_vec;
using ::android::hardware::Return;
using ::android::hardware::Void;
using ::android::sp;

using ::android::OMXNodeInstance;
using ::android::OmxNodeOwner;

/**
 * Wrapper classes for conversion
 * ==============================
 *
 * Naming convention:
 * - LW = Legacy Wrapper --- It wraps a Treble object inside a legacy object.
 * - TW = Treble Wrapper --- It wraps a legacy object inside a Treble object.
 */

struct OmxNode : public IOmxNode {
    Return<Status> freeNode() override;
    Return<Status> sendCommand(uint32_t cmd, int32_t param) override;
    Return<void> getParameter(uint32_t index, const hidl_vec<uint8_t>& inParams, getParameter_cb _hidl_cb) override;
    Return<Status> setParameter(uint32_t index, const hidl_vec<uint8_t>& params) override;
    Return<void> getConfig(uint32_t index, const hidl_vec<uint8_t>& inConfig, getConfig_cb _hidl_cb) override;
    Return<Status> setConfig(uint32_t index, const hidl_vec<uint8_t>& config) override;
    Return<Status> setPortMode(uint32_t portIndex, PortMode mode) override;
    Return<Status> prepareForAdaptivePlayback(uint32_t portIndex, bool enable, uint32_t maxFrameWidth, uint32_t maxFrameHeight) override;
    Return<void> configureVideoTunnelMode(uint32_t portIndex, bool tunneled, uint32_t audioHwSync, configureVideoTunnelMode_cb _hidl_cb) override;
    Return<void> getGraphicBufferUsage(uint32_t portIndex, getGraphicBufferUsage_cb _hidl_cb) override;
    Return<Status> setInputSurface(const sp<IOmxBufferSource>& bufferSource) override;
    Return<void> allocateSecureBuffer(uint32_t portIndex, uint64_t size, allocateSecureBuffer_cb _hidl_cb) override;
    Return<void> useBuffer(uint32_t portIndex, const CodecBuffer& omxBuffer, useBuffer_cb _hidl_cb) override;
    Return<Status> freeBuffer(uint32_t portIndex, uint32_t buffer) override;
    Return<Status> fillBuffer(uint32_t buffer, const CodecBuffer& omxBuffer, const hidl_handle& fence) override;
    Return<Status> emptyBuffer(uint32_t buffer, const CodecBuffer& omxBuffer, uint32_t flags, uint64_t timestampUs, const hidl_handle& fence) override;
    Return<void> getExtensionIndex(const hidl_string& parameterName, getExtensionIndex_cb _hidl_cb) override;
    Return<Status> dispatchMessage(const Message& msg) override;

    OmxNode(OmxNodeOwner* owner, sp<IOmxObserver> const& observer, char const* name);
protected:
    sp<OMXNodeInstance> mLNode;
};

}  // namespace implementation
}  // namespace V1_0
}  // namespace omx
}  // namespace media
}  // namespace hardware
}  // namespace android

#endif  // ANDROID_HARDWARE_MEDIA_OMX_V1_0_OMXNODE_H
