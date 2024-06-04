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

#pragma once

#include <aidl/android/media/BnAidlNode.h>
#include <codec2/hidl/client.h>

namespace android {

struct C2NodeImpl;

/**
 * Thin Codec2 AIdL encoder HAL wrapper for InputSurface
 */
class C2AidlNode : public ::aidl::android::media::BnAidlNode {
public:
    explicit C2AidlNode(const std::shared_ptr<Codec2Client::Component> &comp);
    ~C2AidlNode() override = default;

    // IAidlNode
    ::ndk::ScopedAStatus freeNode() override;

    ::ndk::ScopedAStatus getConsumerUsage(int64_t *_aidl_return) override;

    ::ndk::ScopedAStatus getInputBufferParams(
            ::aidl::android::media::IAidlNode::InputBufferParams *_aidl_return) override;

    ::ndk::ScopedAStatus setConsumerUsage(int64_t usage) override;

    ::ndk::ScopedAStatus setAdjustTimestampGapUs(int32_t gapUs) override;

    ::ndk::ScopedAStatus setInputSurface(
            const std::shared_ptr<::aidl::android::media::IAidlBufferSource>&
                    bufferSource) override;

    ::ndk::ScopedAStatus submitBuffer(
            int32_t buffer,
            const std::optional<::aidl::android::hardware::HardwareBuffer>& hBuffer,
            int32_t flags,
            int64_t timestampUs,
            const ::ndk::ScopedFileDescriptor& fence) override;

    ::ndk::ScopedAStatus onDataSpaceChanged(
            int dataSpace, int aspects, int pixelFormat) override;

    /**
     * Returns underlying IAidlBufferSource object.
     */
    std::shared_ptr<::aidl::android::media::IAidlBufferSource> getSource();

    /**
     * Configure the frame size.
     */
    void setFrameSize(uint32_t width, uint32_t height);

    /**
     * Notify that the input buffer reference is no longer needed by the component.
     * Clean up if necessary.
     *
     * \param index input work index
     */
    void onInputBufferDone(c2_cntr64_t index);

    /**
     * Notify input buffer is emptied.
     */
    void onInputBufferEmptied();

    /**
     * Returns dataspace information from GraphicBufferSource.
     */
    android_dataspace getDataspace();

    /**
     * Returns dataspace information from GraphicBufferSource.
     */
    uint32_t getPixelFormat();

    /**
     * Sets priority of the queue thread.
     */
    void setPriority(int priority);

private:
    std::shared_ptr<C2NodeImpl> mImpl;
};

}  // namespace android

