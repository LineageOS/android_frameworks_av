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

//#define LOG_NDEBUG 0
#define LOG_TAG "Codec2-block_helper"
#include <android-base/logging.h>

#include <android/hardware/graphics/bufferqueue/2.0/IGraphicBufferProducer.h>
#include <codec2/hidl/1.0/ClientBlockHelper.h>
#include <gui/bufferqueue/2.0/B2HGraphicBufferProducer.h>

#include <C2AllocatorGralloc.h>
#include <C2BlockInternal.h>
#include <C2Buffer.h>
#include <C2PlatformSupport.h>

#include <iomanip>

namespace android {
namespace hardware {
namespace media {
namespace c2 {
namespace V1_0 {
namespace utils {

using HGraphicBufferProducer = ::android::hardware::graphics::bufferqueue::
        V2_0::IGraphicBufferProducer;
using B2HGraphicBufferProducer = ::android::hardware::graphics::bufferqueue::
        V2_0::utils::B2HGraphicBufferProducer;

namespace /* unnamed */ {

// Create a GraphicBuffer object from a graphic block.
sp<GraphicBuffer> createGraphicBuffer(const C2ConstGraphicBlock& block) {
    uint32_t width;
    uint32_t height;
    uint32_t format;
    uint64_t usage;
    uint32_t stride;
    uint32_t generation;
    uint64_t bqId;
    int32_t bqSlot;
    _UnwrapNativeCodec2GrallocMetadata(
            block.handle(), &width, &height, &format, &usage,
            &stride, &generation, &bqId, reinterpret_cast<uint32_t*>(&bqSlot));
    native_handle_t *grallocHandle =
            UnwrapNativeCodec2GrallocHandle(block.handle());
    sp<GraphicBuffer> graphicBuffer =
            new GraphicBuffer(grallocHandle,
                              GraphicBuffer::CLONE_HANDLE,
                              width, height, format,
                              1, usage, stride);
    native_handle_delete(grallocHandle);
    return graphicBuffer;
}

template <typename BlockProcessor>
void forEachBlock(C2FrameData& frameData,
                  BlockProcessor process) {
    for (const std::shared_ptr<C2Buffer>& buffer : frameData.buffers) {
        if (buffer) {
            for (const C2ConstGraphicBlock& block :
                    buffer->data().graphicBlocks()) {
                process(block);
            }
        }
    }
}

template <typename BlockProcessor>
void forEachBlock(const std::list<std::unique_ptr<C2Work>>& workList,
                  BlockProcessor process,
                  bool processInput, bool processOutput) {
    for (const std::unique_ptr<C2Work>& work : workList) {
        if (!work) {
            continue;
        }
        if (processInput) {
            forEachBlock(work->input, process);
        }
        if (processOutput) {
            for (const std::unique_ptr<C2Worklet>& worklet : work->worklets) {
                if (worklet) {
                    forEachBlock(worklet->output,
                                 process);
                }
            }
        }
    }
}

sp<HGraphicBufferProducer> getHgbp(const sp<IGraphicBufferProducer>& igbp) {
    sp<HGraphicBufferProducer> hgbp =
            igbp->getHalInterface<HGraphicBufferProducer>();
    return hgbp ? hgbp :
            new B2HGraphicBufferProducer(igbp);
}

} // unnamed namespace

status_t attachToBufferQueue(const C2ConstGraphicBlock& block,
                             const sp<IGraphicBufferProducer>& igbp,
                             uint32_t generation,
                             int32_t* bqSlot) {
    if (!igbp) {
        LOG(WARNING) << "attachToBufferQueue -- null producer.";
        return NO_INIT;
    }

    sp<GraphicBuffer> graphicBuffer = createGraphicBuffer(block);
    graphicBuffer->setGenerationNumber(generation);

    LOG(VERBOSE) << "attachToBufferQueue -- attaching buffer:"
            << " block dimension " << block.width() << "x"
                                   << block.height()
            << ", graphicBuffer dimension " << graphicBuffer->getWidth() << "x"
                                           << graphicBuffer->getHeight()
            << std::hex << std::setfill('0')
            << ", format 0x" << std::setw(8) << graphicBuffer->getPixelFormat()
            << ", usage 0x" << std::setw(16) << graphicBuffer->getUsage()
            << std::dec << std::setfill(' ')
            << ", stride " << graphicBuffer->getStride()
            << ", generation " << graphicBuffer->getGenerationNumber();

    status_t result = igbp->attachBuffer(bqSlot, graphicBuffer);
    if (result != OK) {
        LOG(WARNING) << "attachToBufferQueue -- attachBuffer failed: "
                        "status = " << result << ".";
        return result;
    }
    LOG(VERBOSE) << "attachToBufferQueue -- attachBuffer returned slot #"
                 << *bqSlot << ".";
    return OK;
}

bool getBufferQueueAssignment(const C2ConstGraphicBlock& block,
                              uint32_t* generation,
                              uint64_t* bqId,
                              int32_t* bqSlot) {
    return _C2BlockFactory::GetBufferQueueData(
            _C2BlockFactory::GetGraphicBlockPoolData(block),
            generation, bqId, bqSlot);
}

bool holdBufferQueueBlock(const C2ConstGraphicBlock& block,
                            const sp<IGraphicBufferProducer>& igbp,
                            uint64_t bqId,
                            uint32_t generation) {
    std::shared_ptr<_C2BlockPoolData> data =
            _C2BlockFactory::GetGraphicBlockPoolData(block);
    if (!data) {
        return false;
    }

    uint32_t oldGeneration;
    uint64_t oldId;
    int32_t oldSlot;
    // If the block is not bufferqueue-based, do nothing.
    if (!_C2BlockFactory::GetBufferQueueData(
            data, &oldGeneration, &oldId, &oldSlot) ||
            (oldId == 0)) {
        return false;
    }

    // If the block's bqId is the same as the desired bqId, just hold.
    if ((oldId == bqId) && (oldGeneration == generation)) {
        LOG(VERBOSE) << "holdBufferQueueBlock -- import without attaching:"
                     << " bqId " << oldId
                     << ", bqSlot " << oldSlot
                     << ", generation " << generation
                     << ".";
        _C2BlockFactory::HoldBlockFromBufferQueue(data, getHgbp(igbp));
        return true;
    }

    // Otherwise, attach to the given igbp, which must not be null.
    if (!igbp) {
        return false;
    }

    int32_t bqSlot;
    status_t result = attachToBufferQueue(block, igbp, generation, &bqSlot);

    if (result != OK) {
        LOG(ERROR) << "holdBufferQueueBlock -- fail to attach:"
                   << " target bqId " << bqId
                   << ", generation " << generation
                   << ".";
        return false;
    }

    LOG(VERBOSE) << "holdBufferQueueBlock -- attached:"
                 << " bqId " << bqId
                 << ", bqSlot " << bqSlot
                 << ", generation " << generation
                 << ".";
    _C2BlockFactory::AssignBlockToBufferQueue(
            data, getHgbp(igbp), generation, bqId, bqSlot, true);
    return true;
}

void holdBufferQueueBlocks(const std::list<std::unique_ptr<C2Work>>& workList,
                           const sp<IGraphicBufferProducer>& igbp,
                           uint64_t bqId,
                           uint32_t generation,
                           bool forInput) {
    forEachBlock(workList,
                 std::bind(holdBufferQueueBlock,
                           std::placeholders::_1, igbp, bqId, generation),
                 forInput, !forInput);
}

}  // namespace utils
}  // namespace V1_0
}  // namespace c2
}  // namespace media
}  // namespace hardware
}  // namespace android

