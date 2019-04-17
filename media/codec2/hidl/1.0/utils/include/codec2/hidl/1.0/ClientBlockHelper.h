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

#ifndef CLIENT_BLOCK_HELPER_H
#define CLIENT_BLOCK_HELPER_H

#include <gui/IGraphicBufferProducer.h>
#include <codec2/hidl/1.0/types.h>
#include <C2Work.h>

namespace android {
namespace hardware {
namespace media {
namespace c2 {
namespace V1_0 {
namespace utils {


// BufferQueue-Based Block Operations
// ==================================

// Create a GraphicBuffer object from a graphic block and attach it to an
// IGraphicBufferProducer.
status_t attachToBufferQueue(const C2ConstGraphicBlock& block,
                             const sp<IGraphicBufferProducer>& igbp,
                             uint32_t generation,
                             int32_t* bqSlot);

// Return false if block does not come from a bufferqueue-based blockpool.
// Otherwise, extract generation, bqId and bqSlot and return true.
bool getBufferQueueAssignment(const C2ConstGraphicBlock& block,
                              uint32_t* generation,
                              uint64_t* bqId,
                              int32_t* bqSlot);

// Assign the given block to a bufferqueue so that when the block is destroyed,
// cancelBuffer() will be called.
//
// If the block does not come from a bufferqueue-based blockpool, this function
// returns false.
//
// If the block already has a bufferqueue assignment that matches the given one,
// the function returns true.
//
// If the block already has a bufferqueue assignment that does not match the
// given one, the block will be reassigned to the given bufferqueue. This
// will call attachBuffer() on the given igbp. The function then returns true on
// success or false on any failure during the operation.
//
// Note: This function should be called after detachBuffer() or dequeueBuffer()
// is called manually.
bool holdBufferQueueBlock(const C2ConstGraphicBlock& block,
                          const sp<IGraphicBufferProducer>& igbp,
                          uint64_t bqId,
                          uint32_t generation);

// Call holdBufferQueueBlock() on input or output blocks in the given workList.
// Since the bufferqueue assignment for input and output buffers can be
// different, this function takes forInput to determine whether the given
// bufferqueue is for input buffers or output buffers. (The default value of
// forInput is false.)
//
// In the (rare) case that both input and output buffers are bufferqueue-based,
// this function must be called twice, once for the input buffers and once for
// the output buffers.
//
// Note: This function should be called after WorkBundle has been received from
// another process.
void holdBufferQueueBlocks(const std::list<std::unique_ptr<C2Work>>& workList,
                           const sp<IGraphicBufferProducer>& igbp,
                           uint64_t bqId,
                           uint32_t generation,
                           bool forInput = false);

}  // namespace utils
}  // namespace V1_0
}  // namespace c2
}  // namespace media
}  // namespace hardware
}  // namespace android

#endif  // CLIENT_BLOCK_HELPER_H
