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
#define LOG_TAG "Codec2-BufferTypes"
#include <android-base/logging.h>

#include <codec2/common/BufferTypes.h>

#include <C2AllocatorIon.h>
#include <C2AllocatorGralloc.h>
#include <C2BlockInternal.h>
#include <C2Buffer.h>
#include <C2Component.h>
#include <C2FenceFactory.h>
#include <C2PlatformSupport.h>
#include <C2Work.h>

namespace android {

// C2LinearBlock, vector<C2Param*>, C2Fence -> C2Buffer
bool CreateLinearBuffer(
        std::shared_ptr<C2Buffer>* buffer,
        const std::shared_ptr<C2LinearBlock>& block,
        const std::vector<C2Param*>& meta,
        const C2Fence& fence) {
    // Check the block meta. It should have exactly 1 C2Info:
    // C2Hal_RangeInfo.
    if ((meta.size() != 1) || !meta[0]) {
        LOG(ERROR) << "Invalid C2LinearBlock::meta.";
        return false;
    }
    if (meta[0]->size() != sizeof(C2Hal_RangeInfo)) {
        LOG(ERROR) << "Invalid range info in C2LinearBlock.";
        return false;
    }
    C2Hal_RangeInfo *rangeInfo =
            reinterpret_cast<C2Hal_RangeInfo*>(meta[0]);

    // Create C2Buffer from C2LinearBlock.
    *buffer = C2Buffer::CreateLinearBuffer(block->share(
            rangeInfo->offset, rangeInfo->length,
            fence));
    if (!(*buffer)) {
        LOG(ERROR) << "CreateLinearBuffer failed.";
        return false;
    }
    return true;
}

// C2GraphicBlock, vector<C2Param*>, C2Fence -> C2Buffer
bool CreateGraphicBuffer(
        std::shared_ptr<C2Buffer>* buffer,
        const std::shared_ptr<C2GraphicBlock>& block,
        const std::vector<C2Param*>& meta,
        const C2Fence& fence) {
    // Check the block meta. It should have exactly 1 C2Info:
    // C2Hal_RectInfo.
    if ((meta.size() != 1) || !meta[0]) {
        LOG(ERROR) << "Invalid C2GraphicBlock::meta.";
        return false;
    }
    if (meta[0]->size() != sizeof(C2Hal_RectInfo)) {
        LOG(ERROR) << "Invalid rect info in C2GraphicBlock.";
        return false;
    }
    C2Hal_RectInfo *rectInfo =
            reinterpret_cast<C2Hal_RectInfo*>(meta[0]);

    // Create C2Buffer from C2GraphicBlock.
    *buffer = C2Buffer::CreateGraphicBuffer(block->share(
            C2Rect(rectInfo->width, rectInfo->height).
            at(rectInfo->left, rectInfo->top),
            fence));
    if (!(*buffer)) {
        LOG(ERROR) << "CreateGraphicBuffer failed.";
        return false;
    }
    return true;
}

namespace /* unnamed */ {

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

} // unnamed namespace

bool BeginTransferBufferQueueBlock(const C2ConstGraphicBlock& block) {
    std::shared_ptr<_C2BlockPoolData> data =
            _C2BlockFactory::GetGraphicBlockPoolData(block);
    if (data && _C2BlockFactory::GetBufferQueueData(data)) {
        _C2BlockFactory::BeginTransferBlockToClient(data);
        return true;
    }
    return false;
}

void BeginTransferBufferQueueBlocks(
        const std::list<std::unique_ptr<C2Work>>& workList,
        bool processInput, bool processOutput) {
    forEachBlock(workList, BeginTransferBufferQueueBlock,
                 processInput, processOutput);
}

bool EndTransferBufferQueueBlock(
        const C2ConstGraphicBlock& block,
        bool transfer) {
    std::shared_ptr<_C2BlockPoolData> data =
            _C2BlockFactory::GetGraphicBlockPoolData(block);
    if (data && _C2BlockFactory::GetBufferQueueData(data)) {
        _C2BlockFactory::EndTransferBlockToClient(data, transfer);
        return true;
    }
    return false;
}

void EndTransferBufferQueueBlocks(
        const std::list<std::unique_ptr<C2Work>>& workList,
        bool transfer,
        bool processInput, bool processOutput) {
    forEachBlock(workList,
                 std::bind(EndTransferBufferQueueBlock,
                           std::placeholders::_1, transfer),
                 processInput, processOutput);
}

bool DisplayBufferQueueBlock(const C2ConstGraphicBlock& block) {
    std::shared_ptr<_C2BlockPoolData> data =
            _C2BlockFactory::GetGraphicBlockPoolData(block);
    if (data && _C2BlockFactory::GetBufferQueueData(data)) {
        _C2BlockFactory::DisplayBlockToBufferQueue(data);
        return true;
    }
    return false;
}

}  // namespace android

