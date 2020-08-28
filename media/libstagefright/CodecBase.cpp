/*
 * Copyright 2017, The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

//#define LOG_NDEBUG 0
#define LOG_TAG "CodecBase"

#include <android/hardware/cas/native/1.0/IDescrambler.h>
#include <android/hardware/drm/1.0/types.h>
#include <hidlmemory/FrameworkUtils.h>
#include <mediadrm/ICrypto.h>
#include <media/stagefright/CodecBase.h>
#include <utils/Log.h>

namespace android {

void BufferChannelBase::IMemoryToSharedBuffer(
        const sp<IMemory> &memory,
        int32_t heapSeqNum,
        hardware::drm::V1_0::SharedBuffer *buf) {
    ssize_t offset;
    size_t size;

    sp<hardware::HidlMemory> hidlMemory;
    hidlMemory = hardware::fromHeap(memory->getMemory(&offset, &size));
    buf->bufferId = static_cast<uint32_t>(heapSeqNum);
    buf->offset = offset >= 0 ? offset : 0;
    buf->size = size;
}

} // namespace android
