/*
 * Copyright 2016, The Android Open Source Project
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

#include "Conversion.h"

#include "OmxNode.h"
#include "WOmxObserver.h"

namespace android {
namespace hardware {
namespace media {
namespace omx {
namespace V1_0 {
namespace implementation {

// Methods from ::android::hardware::media::omx::V1_0::IOmxNode follow.
Return<Status> OmxNode::freeNode() {
    // TODO implement
    return ::android::hardware::media::omx::V1_0::Status {};
}

Return<Status> OmxNode::sendCommand(uint32_t cmd, int32_t param) {
    // TODO implement
    return ::android::hardware::media::omx::V1_0::Status {};
}

Return<void> OmxNode::getParameter(uint32_t index, const hidl_vec<uint8_t>& inParams, getParameter_cb _hidl_cb) {
    // TODO implement
    return Void();
}

Return<Status> OmxNode::setParameter(uint32_t index, const hidl_vec<uint8_t>& params) {
    // TODO implement
    return ::android::hardware::media::omx::V1_0::Status {};
}

Return<void> OmxNode::getConfig(uint32_t index, const hidl_vec<uint8_t>& inConfig, getConfig_cb _hidl_cb) {
    // TODO implement
    return Void();
}

Return<Status> OmxNode::setConfig(uint32_t index, const hidl_vec<uint8_t>& config) {
    // TODO implement
    return ::android::hardware::media::omx::V1_0::Status {};
}

Return<Status> OmxNode::setPortMode(uint32_t portIndex, PortMode mode) {
    // TODO implement
    return ::android::hardware::media::omx::V1_0::Status {};
}

Return<Status> OmxNode::prepareForAdaptivePlayback(uint32_t portIndex, bool enable, uint32_t maxFrameWidth, uint32_t maxFrameHeight) {
    // TODO implement
    return ::android::hardware::media::omx::V1_0::Status {};
}

Return<void> OmxNode::configureVideoTunnelMode(uint32_t portIndex, bool tunneled, uint32_t audioHwSync, configureVideoTunnelMode_cb _hidl_cb) {
    // TODO implement
    return Void();
}

Return<void> OmxNode::getGraphicBufferUsage(uint32_t portIndex, getGraphicBufferUsage_cb _hidl_cb) {
    // TODO implement
    return Void();
}

Return<Status> OmxNode::setInputSurface(const sp<IOmxBufferSource>& bufferSource) {
    // TODO implement
    return ::android::hardware::media::omx::V1_0::Status {};
}

Return<void> OmxNode::allocateSecureBuffer(uint32_t portIndex, uint64_t size, allocateSecureBuffer_cb _hidl_cb) {
    // TODO implement
    return Void();
}

Return<void> OmxNode::useBuffer(uint32_t portIndex, const CodecBuffer& omxBuffer, useBuffer_cb _hidl_cb) {
    // TODO implement
    return Void();
}

Return<Status> OmxNode::freeBuffer(uint32_t portIndex, uint32_t buffer) {
    // TODO implement
    return ::android::hardware::media::omx::V1_0::Status {};
}

Return<Status> OmxNode::fillBuffer(uint32_t buffer, const CodecBuffer& omxBuffer, const hidl_handle& fence) {
    // TODO implement
    return ::android::hardware::media::omx::V1_0::Status {};
}

Return<Status> OmxNode::emptyBuffer(uint32_t buffer, const CodecBuffer& omxBuffer, uint32_t flags, uint64_t timestampUs, const hidl_handle& fence) {
    // TODO implement
    return ::android::hardware::media::omx::V1_0::Status {};
}

Return<void> OmxNode::getExtensionIndex(const hidl_string& parameterName, getExtensionIndex_cb _hidl_cb) {
    // TODO implement
    return Void();
}

Return<Status> OmxNode::dispatchMessage(const Message& msg) {
    // TODO implement
    return ::android::hardware::media::omx::V1_0::Status {};
}

OmxNode::OmxNode(OmxNodeOwner* owner, sp<IOmxObserver> const& observer, char const* name) {
    mLNode = new OMXNodeInstance(owner, new LWOmxObserver(observer), name);
}

}  // namespace implementation
}  // namespace V1_0
}  // namespace omx
}  // namespace media
}  // namespace hardware
}  // namespace android
