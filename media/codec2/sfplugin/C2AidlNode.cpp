/*
 * Copyright 2024, The Android Open Source Project
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
#define LOG_TAG "C2AidlNode"
#include <log/log.h>
#include <private/android/AHardwareBufferHelpers.h>

#include <media/stagefright/MediaErrors.h>
#include <media/stagefright/aidlpersistentsurface/wrapper/Conversion.h>

#include "C2NodeImpl.h"
#include "C2AidlNode.h"

namespace android {

using ::aidl::android::media::IAidlBufferSource;
using ::aidl::android::media::IAidlNode;

// Conversion
using ::android::media::aidl_conversion::toAidlStatus;

C2AidlNode::C2AidlNode(const std::shared_ptr<Codec2Client::Component> &comp)
    : mImpl(new C2NodeImpl(comp, true)) {}

// aidl ndk interfaces
::ndk::ScopedAStatus C2AidlNode::freeNode() {
    return toAidlStatus(mImpl->freeNode());
}

::ndk::ScopedAStatus C2AidlNode::getConsumerUsage(int64_t* _aidl_return) {
    uint64_t usage;
    mImpl->getConsumerUsageBits(&usage);
    *_aidl_return = usage;
    return ::ndk::ScopedAStatus::ok();
}

::ndk::ScopedAStatus C2AidlNode::getInputBufferParams(IAidlNode::InputBufferParams* _aidl_return) {
    mImpl->getInputBufferParams(_aidl_return);
    return ::ndk::ScopedAStatus::ok();
}

::ndk::ScopedAStatus C2AidlNode::setConsumerUsage(int64_t usage) {
    mImpl->setConsumerUsageBits(static_cast<uint64_t>(usage));
    return ::ndk::ScopedAStatus::ok();
}

::ndk::ScopedAStatus C2AidlNode::setAdjustTimestampGapUs(int32_t gapUs) {
    mImpl->setAdjustTimestampGapUs(gapUs);
    return ::ndk::ScopedAStatus::ok();
}

::ndk::ScopedAStatus C2AidlNode::setInputSurface(
        const std::shared_ptr<IAidlBufferSource>& bufferSource) {
    return toAidlStatus(mImpl->setAidlInputSurface(bufferSource));
}

::ndk::ScopedAStatus C2AidlNode::submitBuffer(
        int32_t buffer,
        const std::optional<::aidl::android::hardware::HardwareBuffer>& hBuffer,
        int32_t flags, int64_t timestamp, const ::ndk::ScopedFileDescriptor& fence) {
    sp<GraphicBuffer> gBuf;
    AHardwareBuffer *ahwb = nullptr;
    if (hBuffer.has_value()) {
        ahwb = hBuffer.value().get();
    }

    if (ahwb) {
        gBuf = AHardwareBuffer_to_GraphicBuffer(ahwb);
    }
    return toAidlStatus(mImpl->submitBuffer(
            buffer, gBuf, flags, timestamp, ::dup(fence.get())));
}

::ndk::ScopedAStatus C2AidlNode::onDataSpaceChanged(
        int32_t dataSpace,
        int32_t aspects,
        int32_t pixelFormat) {
    // NOTE: legacy codes passed aspects, but they didn't used.
    (void)aspects;

    return toAidlStatus(mImpl->onDataspaceChanged(
            static_cast<uint32_t>(dataSpace),
            static_cast<uint32_t>(pixelFormat)));
}

// cpp interface

std::shared_ptr<IAidlBufferSource> C2AidlNode::getSource() {
    return mImpl->getAidlSource();
}

void C2AidlNode::setFrameSize(uint32_t width, uint32_t height) {
    return mImpl->setFrameSize(width, height);
}

void C2AidlNode::onInputBufferDone(c2_cntr64_t index) {
    return mImpl->onInputBufferDone(index);
}

android_dataspace C2AidlNode::getDataspace() {
    return mImpl->getDataspace();
}

uint32_t C2AidlNode::getPixelFormat() {
    return mImpl->getPixelFormat();
}

void C2AidlNode::setPriority(int priority) {
    return mImpl->setPriority(priority);
}

}  // namespace android
