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

#ifndef CODEC2_COMMON_BUFFER_TYPES_H
#define CODEC2_COMMON_BUFFER_TYPES_H

#ifndef LOG_TAG
#define LOG_TAG "Codec2-BufferTypes"
#endif
#include <android-base/logging.h>

#include <codec2/common/BufferPoolSender.h>
#include <codec2/common/ParamTypes.h>
#include <media/stagefright/foundation/AUtils.h>

#include <C2AllocatorIon.h>
#include <C2AllocatorGralloc.h>
#include <C2BlockInternal.h>
#include <C2Buffer.h>
#include <C2Component.h>
#include <C2FenceFactory.h>
#include <C2Param.h>
#include <C2ParamDef.h>
#include <C2PlatformSupport.h>
#include <C2Work.h>

#include <algorithm>
#include <functional>
#include <iomanip>
#include <map>

namespace android {

// Types of metadata for Blocks.
struct C2Hal_Range {
    uint32_t offset;
    uint32_t length; // Do not use "size" because the name collides with C2Info::size().
};
typedef C2GlobalParam<C2Info, C2Hal_Range, 0> C2Hal_RangeInfo;

struct C2Hal_Rect {
    uint32_t left;
    uint32_t top;
    uint32_t width;
    uint32_t height;
};
typedef C2GlobalParam<C2Info, C2Hal_Rect, 1> C2Hal_RectInfo;

// Note: The handle is not cloned.
template <typename BaseBlock>
void SetHandle(BaseBlock *baseBlock, const C2Handle *handle);

template <typename BaseBlock>
void SetAHardwareBuffer(BaseBlock *baseBlock, AHardwareBuffer *pBuf);

template <typename BufferPoolTypes, typename BaseBlock>
void SetPooledBlock(
        BaseBlock *baseBlock,
        const typename BufferPoolTypes::BufferStatusMessage &pooledBlock);

template <typename BufferPoolTypes>
bool GetBufferPoolData(
        const std::shared_ptr<const _C2BlockPoolData>& blockPoolData,
        std::shared_ptr<typename BufferPoolTypes::BufferPoolData> *bpData);

// Find or add a HAL BaseBlock object from a given C2Handle* to a list and an
// associated map.
// Note: The handle is not cloned.
template <typename BaseBlock>
bool _addBaseBlock(
        uint32_t* index,
        const C2Handle* handle,
        std::list<BaseBlock>* baseBlocks,
        std::map<const void*, uint32_t>* baseBlockIndices) {
    if (!handle) {
        LOG(ERROR) << "addBaseBlock called on a null C2Handle.";
        return false;
    }
    auto it = baseBlockIndices->find(handle);
    if (it != baseBlockIndices->end()) {
        *index = it->second;
    } else {
        *index = baseBlocks->size();
        baseBlockIndices->emplace(handle, *index);
        baseBlocks->emplace_back();

        BaseBlock &dBaseBlock = baseBlocks->back();
        SetHandle(&dBaseBlock, handle);
    }
    return true;
}

// Find or add a HAL BaseBlock object from a given AHardwareBuffer* to a list and an
// associated map.
template <typename BaseBlock>
bool _addBaseBlock(
        uint32_t* index,
        AHardwareBuffer* pBuf,
        std::list<BaseBlock>* baseBlocks,
        std::map<const void*, uint32_t>* baseBlockIndices) {
    if (!pBuf) {
        LOG(ERROR) << "addBaseBlock called on a null AHardwareBuffer.";
    }
    auto it = baseBlockIndices->find(pBuf);
    if (it != baseBlockIndices->end()) {
        *index = it->second;
    } else {
        *index = baseBlocks->size();
        baseBlockIndices->emplace(pBuf, *index);
        baseBlocks->emplace_back();

        BaseBlock &dBaseBlock = baseBlocks->back();
        SetAHardwareBuffer(&dBaseBlock, pBuf);
    }
    return true;
}

// Find or add a hidl BaseBlock object from a given BufferPoolData to a list and
// an associated map.
template <typename BufferPoolTypes, typename BaseBlock>
bool _addBaseBlock(
        uint32_t* index,
        const std::shared_ptr<typename BufferPoolTypes::BufferPoolData> &bpData,
        BufferPoolSender<BufferPoolTypes>* bufferPoolSender,
        std::list<BaseBlock>* baseBlocks,
        std::map<const void*, uint32_t>* baseBlockIndices) {
    if (!bpData) {
        LOG(ERROR) << "addBaseBlock called on a null BufferPoolData.";
        return false;
    }
    auto it = baseBlockIndices->find(bpData.get());
    if (it != baseBlockIndices->end()) {
        *index = it->second;
    } else {
        *index = baseBlocks->size();
        baseBlockIndices->emplace(bpData.get(), *index);
        baseBlocks->emplace_back();

        BaseBlock &dBaseBlock = baseBlocks->back();

        if (bufferPoolSender) {
            typename BufferPoolTypes::BufferStatusMessage pooledBlock;
            typename BufferPoolTypes::BufferPoolStatus bpStatus =
                bufferPoolSender->send(bpData, &pooledBlock);

            if (bpStatus != BufferPoolTypes::ResultStatus::OK) {
                LOG(ERROR) << "Failed to send buffer with BufferPool. Error: "
                           << static_cast<int32_t>(bpStatus)
                           << ".";
                return false;
            }
            SetPooledBlock<BufferPoolTypes>(&dBaseBlock, pooledBlock);
        }
    }
    return true;
}

template <typename BufferPoolTypes, typename BaseBlock>
bool addBaseBlock(
        uint32_t* index,
        const C2Handle* handle,
        const std::shared_ptr<const _C2BlockPoolData>& blockPoolData,
        BufferPoolSender<BufferPoolTypes>* bufferPoolSender,
        std::list<BaseBlock>* baseBlocks,
        std::map<const void*, uint32_t>* baseBlockIndices) {
    if (!blockPoolData) {
        // No BufferPoolData ==> NATIVE block.
        return _addBaseBlock(
                index, handle,
                baseBlocks, baseBlockIndices);
    }
    switch (blockPoolData->getType()) {
    case _C2BlockPoolData::TYPE_BUFFERPOOL: {
            // BufferPoolData
            std::shared_ptr<typename BufferPoolTypes::BufferPoolData> bpData;
            if (!GetBufferPoolData<BufferPoolTypes>(blockPoolData, &bpData) || !bpData) {
                LOG(ERROR) << "BufferPoolData unavailable in a block.";
                return false;
            }
            return _addBaseBlock(
                    index, bpData,
                    bufferPoolSender, baseBlocks, baseBlockIndices);
        }
    case _C2BlockPoolData::TYPE_BUFFERQUEUE:
        uint32_t gen;
        uint64_t bqId;
        int32_t bqSlot;
        // Update handle if migration happened.
        if (_C2BlockFactory::GetBufferQueueData(
                blockPoolData, &gen, &bqId, &bqSlot)) {
            android::MigrateNativeCodec2GrallocHandle(
                    const_cast<native_handle_t*>(handle), gen, bqId, bqSlot);
        }
        return _addBaseBlock(
                index, handle,
                baseBlocks, baseBlockIndices);
    case _C2BlockPoolData::TYPE_AHWBUFFER:
        AHardwareBuffer *pBuf;
        if (!_C2BlockFactory::GetAHardwareBuffer(blockPoolData, &pBuf)) {
            LOG(ERROR) << "AHardwareBuffer unavailable in a block.";
            return false;
        }
        return _addBaseBlock(
                index, pBuf,
                baseBlocks, baseBlockIndices);
    default:
        LOG(ERROR) << "Unknown C2BlockPoolData type.";
        return false;
    }
}

// C2Fence -> Handle
// Note: File descriptors are not duplicated. The original file descriptor must
// not be closed before the transaction is complete.
template <typename Handle>
bool objcpy(Handle* d, const C2Fence& s) {
    d->setTo(nullptr);
    native_handle_t* handle = _C2FenceFactory::CreateNativeHandle(s);
    if (handle) {
        d->setTo(handle, true /* owns */);
//  } else if (!s.ready()) {
//      // TODO: we should wait for unmarshallable fences but this may not be
//      // the best place for it. We can safely ignore here as at this time
//      // all fences used here are marshallable.
    }
    return true;
}

// C2ConstLinearBlock -> Block
// Note: Native handles are not duplicated. The original handles must not be
// closed before the transaction is complete.
template <typename Block, typename BufferPoolTypes, typename BaseBlock>
bool objcpy(Block* d, const C2ConstLinearBlock& s,
        BufferPoolSender<BufferPoolTypes>* bufferPoolSender,
        std::list<BaseBlock>* baseBlocks,
        std::map<const void*, uint32_t>* baseBlockIndices) {
    std::shared_ptr<const _C2BlockPoolData> bpData =
            _C2BlockFactory::GetLinearBlockPoolData(s);
    if (!addBaseBlock((uint32_t *)&d->index, s.handle(), bpData,
            bufferPoolSender, baseBlocks, baseBlockIndices)) {
        LOG(ERROR) << "Invalid block data in C2ConstLinearBlock.";
        return false;
    }

    // Create the metadata.
    C2Hal_RangeInfo dRangeInfo;
    dRangeInfo.offset = static_cast<uint32_t>(s.offset());
    dRangeInfo.length = static_cast<uint32_t>(s.size());
    if (!_createParamsBlob(&d->meta, std::vector<C2Param*>{ &dRangeInfo })) {
        LOG(ERROR) << "Invalid range info in C2ConstLinearBlock.";
        return false;
    }

    // Copy the fence
    if (!objcpy(&d->fence, s.fence())) {
        LOG(ERROR) << "Invalid C2ConstLinearBlock::fence.";
        return false;
    }
    return true;
}

// C2ConstGraphicBlock -> Block
// Note: Native handles are not duplicated. The original handles must not be
// closed before the transaction is complete.
template <typename Block, typename BufferPoolTypes, typename BaseBlock>
bool objcpy(Block* d, const C2ConstGraphicBlock& s,
        BufferPoolSender<BufferPoolTypes>* bufferPoolSender,
        std::list<BaseBlock>* baseBlocks,
        std::map<const void*, uint32_t>* baseBlockIndices) {
    std::shared_ptr<const _C2BlockPoolData> bpData =
            _C2BlockFactory::GetGraphicBlockPoolData(s);
    if (!addBaseBlock((uint32_t *)&d->index, s.handle(), bpData,
            bufferPoolSender, baseBlocks, baseBlockIndices)) {
        LOG(ERROR) << "Invalid block data in C2ConstGraphicBlock.";
        return false;
    }

    // Create the metadata.
    C2Hal_RectInfo dRectInfo;
    C2Rect sRect = s.crop();
    dRectInfo.left = static_cast<uint32_t>(sRect.left);
    dRectInfo.top = static_cast<uint32_t>(sRect.top);
    dRectInfo.width = static_cast<uint32_t>(sRect.width);
    dRectInfo.height = static_cast<uint32_t>(sRect.height);
    if (!_createParamsBlob(&d->meta, std::vector<C2Param*>{ &dRectInfo })) {
        LOG(ERROR) << "Invalid rect info in C2ConstGraphicBlock.";
        return false;
    }

    // Copy the fence
    if (!objcpy(&d->fence, s.fence())) {
        LOG(ERROR) << "Invalid C2ConstGraphicBlock::fence.";
        return false;
    }
    return true;
}

// C2BufferData -> Buffer
// This function only fills in d->blocks.
template <typename Buffer, typename BufferPoolTypes, typename BaseBlock>
bool objcpy(Buffer* d, const C2BufferData& s,
        BufferPoolSender<BufferPoolTypes>* bufferPoolSender,
        std::list<BaseBlock>* baseBlocks,
        std::map<const void*, uint32_t>* baseBlockIndices) {
    d->blocks.resize(
            s.linearBlocks().size() +
            s.graphicBlocks().size());
    size_t i = 0;
    for (const C2ConstLinearBlock& linearBlock : s.linearBlocks()) {
        auto& dBlock = d->blocks[i++];
        if (!objcpy(
                &dBlock, linearBlock,
                bufferPoolSender, baseBlocks, baseBlockIndices)) {
            LOG(ERROR) << "Invalid C2BufferData::linearBlocks. "
                       << "(Destination index = " << i - 1 << ".)";
            return false;
        }
    }
    for (const C2ConstGraphicBlock& graphicBlock : s.graphicBlocks()) {
        auto& dBlock = d->blocks[i++];
        if (!objcpy(
                &dBlock, graphicBlock,
                bufferPoolSender, baseBlocks, baseBlockIndices)) {
            LOG(ERROR) << "Invalid C2BufferData::graphicBlocks. "
                       << "(Destination index = " << i - 1 << ".)";
            return false;
        }
    }
    return true;
}

// C2Buffer -> Buffer
template <typename Buffer, typename BufferPoolTypes, typename BaseBlock>
bool objcpy(Buffer* d, const C2Buffer& s,
        BufferPoolSender<BufferPoolTypes>* bufferPoolSender,
        std::list<BaseBlock>* baseBlocks,
        std::map<const void*, uint32_t>* baseBlockIndices) {
    if (!_createParamsBlob(&d->info, s.info())) {
        LOG(ERROR) << "Invalid C2Buffer::info.";
        return false;
    }
    if (!objcpy(d, s.data(), bufferPoolSender, baseBlocks, baseBlockIndices)) {
        LOG(ERROR) << "Invalid C2Buffer::data.";
        return false;
    }
    return true;
}

// C2InfoBuffer -> InfoBuffer
template <typename InfoBuffer, typename BufferPoolTypes, typename BaseBlock>
bool objcpy(InfoBuffer* d, const C2InfoBuffer& s,
        BufferPoolSender<BufferPoolTypes>* bufferPoolSender,
        std::list<BaseBlock>* baseBlocks,
        std::map<const void*, uint32_t>* baseBlockIndices) {
    d->index = static_cast<decltype(d->index)>(s.index());
    auto& dBuffer = d->buffer;
    if (!objcpy(&dBuffer, s.data(), bufferPoolSender, baseBlocks, baseBlockIndices)) {
        LOG(ERROR) << "Invalid C2InfoBuffer::data";
        return false;
    }
    return true;
}

// C2FrameData -> FrameData
template <typename FrameData, typename BufferPoolTypes, typename BaseBlock>
bool objcpy(FrameData* d, const C2FrameData& s,
        BufferPoolSender<BufferPoolTypes>* bufferPoolSender,
        std::list<BaseBlock>* baseBlocks,
        std::map<const void*, uint32_t>* baseBlockIndices) {
    d->flags = static_cast<decltype(d->flags)>(s.flags);
    if (!objcpy(&d->ordinal, s.ordinal)) {
        LOG(ERROR) << "Invalid C2FrameData::ordinal.";
        return false;
    }

    d->buffers.resize(s.buffers.size());
    size_t i = 0;
    for (const std::shared_ptr<C2Buffer>& sBuffer : s.buffers) {
        auto& dBuffer = d->buffers[i++];
        if (!sBuffer) {
            // A null (pointer to) C2Buffer corresponds to a Buffer with empty
            // info and blocks.
            auto *dInfo = GetBlob(&dBuffer.info);
            dInfo->resize(0);
            dBuffer.blocks.resize(0);
            continue;
        }
        if (!objcpy(
                &dBuffer, *sBuffer,
                bufferPoolSender, baseBlocks, baseBlockIndices)) {
            LOG(ERROR) << "Invalid C2FrameData::buffers["
                       << i - 1 << "].";
            return false;
        }
    }

    if (!_createParamsBlob(&d->configUpdate, s.configUpdate)) {
        LOG(ERROR) << "Invalid C2FrameData::configUpdate.";
        return false;
    }

    d->infoBuffers.resize(s.infoBuffers.size());
    i = 0;
    for (const C2InfoBuffer& sInfoBuffer : s.infoBuffers) {
        auto& dInfoBuffer = d->infoBuffers[i++];
        if (!objcpy(&dInfoBuffer, sInfoBuffer,
                bufferPoolSender, baseBlocks, baseBlockIndices)) {
            LOG(ERROR) << "Invalid C2FrameData::infoBuffers["
                       << i - 1 << "].";
            return false;
        }
    }

    return true;
}

// std::list<std::unique_ptr<C2Work>> -> WorkBundle
template <typename WorkBundle, typename BufferPoolTypes>
bool objcpy(
        WorkBundle* d,
        const std::list<std::unique_ptr<C2Work>>& s,
        BufferPoolSender<BufferPoolTypes>* bufferPoolSender) {
    // baseBlocks holds a list of BaseBlock objects that Blocks can refer to.
    std::list<typename decltype(d->baseBlocks)::value_type> baseBlocks;

    // baseBlockIndices maps a raw pointer to native_handle_t or BufferPoolData
    // inside baseBlocks to the corresponding index into baseBlocks. The keys
    // (pointers) are used to identify blocks that have the same "base block" in
    // s, a list of C2Work objects. Because baseBlocks will be copied into a
    // hidl_vec eventually, the values of baseBlockIndices are zero-based
    // integer indices instead of list iterators.
    //
    // Note that the pointers can be raw because baseBlockIndices has a shorter
    // lifespan than all of base blocks.
    std::map<const void*, uint32_t> baseBlockIndices;

    d->works.resize(s.size());
    size_t i = 0;
    for (const std::unique_ptr<C2Work>& sWork : s) {
        auto &dWork = d->works[i++];
        if (!sWork) {
            LOG(WARNING) << "Null C2Work encountered.";
            continue;
        }

        // chain info is not in use currently.

        // input
        if (!objcpy(&dWork.input, sWork->input,
                bufferPoolSender, &baseBlocks, &baseBlockIndices)) {
            LOG(ERROR) << "Invalid C2Work::input.";
            return false;
        }

        // worklets
        if (sWork->worklets.size() == 0) {
            LOG(DEBUG) << "Work with no worklets.";
        } else {
            // Parcel the worklets.
            auto &dWorklets = dWork.worklets;
            dWorklets.resize(sWork->worklets.size());
            size_t j = 0;
            for (const std::unique_ptr<C2Worklet>& sWorklet : sWork->worklets)
            {
                if (!sWorklet) {
                    LOG(WARNING) << "Null C2Work::worklets["
                                 << j << "].";
                    continue;
                }
                auto &dWorklet = dWorklets[j++];

                // component id
                dWorklet.componentId = static_cast<uint32_t>(
                        sWorklet->component);

                // tunings
                if (!_createParamsBlob(&dWorklet.tunings, sWorklet->tunings)) {
                    LOG(ERROR) << "Invalid C2Work::worklets["
                               << j - 1 << "]->tunings.";
                    return false;
                }

                // failures
                dWorklet.failures.resize(sWorklet->failures.size());
                size_t k = 0;
                for (const std::unique_ptr<C2SettingResult>& sFailure :
                        sWorklet->failures) {
                    if (!sFailure) {
                        LOG(WARNING) << "Null C2Work::worklets["
                                     << j - 1 << "]->failures["
                                     << k << "].";
                        continue;
                    }
                    if (!objcpy(&dWorklet.failures[k++], *sFailure)) {
                        LOG(ERROR) << "Invalid C2Work::worklets["
                                   << j - 1 << "]->failures["
                                   << k - 1 << "].";
                        return false;
                    }
                }

                // output
                if (!objcpy(&dWorklet.output, sWorklet->output,
                        bufferPoolSender, &baseBlocks, &baseBlockIndices)) {
                    LOG(ERROR) << "Invalid C2Work::worklets["
                               << j - 1 << "]->output.";
                    return false;
                }
            }
        }

        // worklets processed
        dWork.workletsProcessed = sWork->workletsProcessed;

        // result
        SetStatus(&dWork.result, sWork->result);
    }

    // Move std::list<BaseBlock> to vector<BaseBlock>.
    {
        d->baseBlocks.resize(baseBlocks.size());
        size_t i = 0;
        for (auto&& baseBlock : baseBlocks) {
            d->baseBlocks[i++] = std::move(baseBlock);
        }
    }

    return true;
}

struct C2BaseBlock {
    enum type_t {
        LINEAR,
        GRAPHIC,
    };
    type_t type;
    std::shared_ptr<C2LinearBlock> linear;
    std::shared_ptr<C2GraphicBlock> graphic;
};

// Handle -> C2Fence
// Note: File descriptors are not duplicated. The original file descriptor must
// not be closed before the transaction is complete.
template <typename Handle>
bool objcpy(C2Fence* d, const Handle& s) {
    const native_handle_t* handle = s.getNativeHandle();
    *d = _C2FenceFactory::CreateFromNativeHandle(handle);
    return true;
}

// C2LinearBlock, vector<C2Param*>, C2Fence -> C2Buffer
bool CreateLinearBuffer(
        std::shared_ptr<C2Buffer>* buffer,
        const std::shared_ptr<C2LinearBlock>& block,
        const std::vector<C2Param*>& meta,
        const C2Fence& fence);

// C2GraphicBlock, vector<C2Param*>, C2Fence -> C2Buffer
bool CreateGraphicBuffer(
        std::shared_ptr<C2Buffer>* buffer,
        const std::shared_ptr<C2GraphicBlock>& block,
        const std::vector<C2Param*>& meta,
        const C2Fence& fence);

// Buffer -> C2Buffer
// Note: The native handles will be cloned.
template <typename Buffer>
bool objcpy(std::shared_ptr<C2Buffer>* d, const Buffer& s,
        const std::vector<C2BaseBlock>& baseBlocks) {
    *d = nullptr;

    // Currently, a non-null C2Buffer must contain exactly 1 block.
    if (s.blocks.size() == 0) {
        return true;
    } else if (s.blocks.size() != 1) {
        LOG(ERROR) << "Invalid Buffer: "
                      "Currently, a C2Buffer must contain exactly 1 block.";
        return false;
    }

    const auto &sBlock = s.blocks[0];
    if (sBlock.index >= baseBlocks.size()) {
        LOG(ERROR) << "Invalid Buffer::blocks[0].index: "
                      "Array index out of range.";
        return false;
    }
    const C2BaseBlock &baseBlock = baseBlocks[sBlock.index];

    // Parse meta.
    std::vector<C2Param*> sBlockMeta;
    if (!parseParamsBlob(&sBlockMeta, sBlock.meta)) {
        LOG(ERROR) << "Invalid Buffer::blocks[0].meta.";
        return false;
    }

    // Copy fence.
    C2Fence dFence;
    if (!objcpy(&dFence, sBlock.fence)) {
        LOG(ERROR) << "Invalid Buffer::blocks[0].fence.";
        return false;
    }

    // Construct a block.
    switch (baseBlock.type) {
    case C2BaseBlock::LINEAR:
        if (!CreateLinearBuffer(d, baseBlock.linear, sBlockMeta, dFence)) {
            LOG(ERROR) << "Invalid C2BaseBlock::linear.";
            return false;
        }
        break;
    case C2BaseBlock::GRAPHIC:
        if (!CreateGraphicBuffer(d, baseBlock.graphic, sBlockMeta, dFence)) {
            LOG(ERROR) << "Invalid C2BaseBlock::graphic.";
            return false;
        }
        break;
    default:
        LOG(ERROR) << "Invalid C2BaseBlock::type.";
        return false;
    }

    // Parse info
    std::vector<C2Param*> params;
    if (!parseParamsBlob(&params, s.info)) {
        LOG(ERROR) << "Invalid Buffer::info.";
        return false;
    }
    for (C2Param* param : params) {
        if (param == nullptr) {
            LOG(ERROR) << "Null param in Buffer::info.";
            return false;
        }
        std::shared_ptr<C2Param> c2param{
                C2Param::Copy(*param).release()};
        if (!c2param) {
            LOG(ERROR) << "Invalid param in Buffer::info.";
            return false;
        }
        c2_status_t status =
                (*d)->setInfo(std::static_pointer_cast<C2Info>(c2param));
        if (status != C2_OK) {
            LOG(ERROR) << "C2Buffer::setInfo failed.";
            return false;
        }
    }

    return true;
}

// InfoBuffer -> C2InfoBuffer
template <typename InfoBuffer>
bool objcpy(
        std::vector<C2InfoBuffer> *d,
        const InfoBuffer& s,
        const std::vector<C2BaseBlock>& baseBlocks) {

    // Currently, a non-null C2InfoBufer must contain exactly 1 block.
    if (s.buffer.blocks.size() == 0) {
        return true;
    } else if (s.buffer.blocks.size() != 1) {
        LOG(ERROR) << "Invalid InfoBuffer::Buffer "
                      "Currently, a C2InfoBuffer must contain exactly 1 block.";
        return false;
    }

    const auto &sBlock = s.buffer.blocks[0];
    if (sBlock.index >= baseBlocks.size()) {
        LOG(ERROR) << "Invalid InfoBuffer::Buffer::blocks[0].index: "
                      "Array index out of range.";
        return false;
    }
    const C2BaseBlock &baseBlock = baseBlocks[sBlock.index];

    // Parse meta.
    std::vector<C2Param*> sBlockMeta;
    if (!parseParamsBlob(&sBlockMeta, sBlock.meta)) {
        LOG(ERROR) << "Invalid InfoBuffer::Buffer::blocks[0].meta.";
        return false;
    }

    // Copy fence.
    C2Fence dFence;
    if (!objcpy(&dFence, sBlock.fence)) {
        LOG(ERROR) << "Invalid InfoBuffer::Buffer::blocks[0].fence.";
        return false;
    }

    // Construct a block.
    switch (baseBlock.type) {
    case C2BaseBlock::LINEAR:
        if (sBlockMeta.size() == 1 && sBlockMeta[0] != nullptr &&
            sBlockMeta[0]->size() == sizeof(C2Hal_RangeInfo)) {
            C2Hal_RangeInfo *rangeInfo =
                    reinterpret_cast<C2Hal_RangeInfo*>(sBlockMeta[0]);
            d->emplace_back(C2InfoBuffer::CreateLinearBuffer(
                    uint32_t(s.index),
                    baseBlock.linear->share(
                            rangeInfo->offset, rangeInfo->length, dFence)));
            return true;
        }
        LOG(ERROR) << "Invalid Meta for C2BaseBlock::Linear InfoBuffer.";
        break;
    case C2BaseBlock::GRAPHIC:
        // It's not used now
        LOG(ERROR) << "Non-Used C2BaseBlock::type for InfoBuffer.";
        break;
    default:
        LOG(ERROR) << "Invalid C2BaseBlock::type for InfoBuffer.";
        break;
    }

    return false;
}

// FrameData -> C2FrameData
template <typename FrameData>
bool objcpy(C2FrameData* d, const FrameData& s,
        const std::vector<C2BaseBlock>& baseBlocks) {
    d->flags = static_cast<C2FrameData::flags_t>(s.flags);
    if (!objcpy(&d->ordinal, s.ordinal)) {
        LOG(ERROR) << "Invalid FrameData::ordinal.";
        return false;
    }
    d->buffers.clear();
    d->buffers.reserve(s.buffers.size());
    for (const auto& sBuffer : s.buffers) {
        std::shared_ptr<C2Buffer> dBuffer;
        if (!objcpy(&dBuffer, sBuffer, baseBlocks)) {
            LOG(ERROR) << "Invalid FrameData::buffers.";
            return false;
        }
        d->buffers.emplace_back(dBuffer);
    }

    std::vector<C2Param*> params;
    if (!parseParamsBlob(&params, s.configUpdate)) {
        LOG(ERROR) << "Invalid FrameData::configUpdate.";
        return false;
    }
    d->configUpdate.clear();
    for (C2Param* param : params) {
        d->configUpdate.emplace_back(C2Param::Copy(*param));
        if (!d->configUpdate.back()) {
            LOG(ERROR) << "Unexpected error while parsing "
                          "FrameData::configUpdate.";
            return false;
        }
    }

    d->infoBuffers.clear();
    if (s.infoBuffers.size() == 0) {
        // InfoBuffer is optional
        return true;
    }
    d->infoBuffers.reserve(s.infoBuffers.size());
    for (const auto &sInfoBuffer: s.infoBuffers) {
        if (!objcpy(&(d->infoBuffers), sInfoBuffer, baseBlocks)) {
            LOG(ERROR) << "Invalid Framedata::infoBuffers.";
            return false;
        }
    }
    return true;
}

// BaseBlock -> C2BaseBlock
template <typename BaseBlock>
bool objcpy(C2BaseBlock* d, const BaseBlock& s);

// WorkBundle -> std::list<std::unique_ptr<C2Work>>
template <typename WorkBundle>
bool objcpy(std::list<std::unique_ptr<C2Work>>* d, const WorkBundle& s) {
    // Convert BaseBlocks to C2BaseBlocks.
    std::vector<C2BaseBlock> dBaseBlocks(s.baseBlocks.size());
    for (size_t i = 0; i < s.baseBlocks.size(); ++i) {
        if (!objcpy(&dBaseBlocks[i], s.baseBlocks[i])) {
            LOG(ERROR) << "Invalid WorkBundle::baseBlocks["
                       << i << "].";
            return false;
        }
    }

    d->clear();
    for (const auto& sWork : s.works) {
        d->emplace_back(std::make_unique<C2Work>());
        C2Work& dWork = *d->back();

        // chain info is not in use currently.

        // input
        if (!objcpy(&dWork.input, sWork.input, dBaseBlocks)) {
            LOG(ERROR) << "Invalid Work::input.";
            return false;
        }

        // worklet(s)
        dWork.worklets.clear();
        for (const auto& sWorklet : sWork.worklets) {
            std::unique_ptr<C2Worklet> dWorklet = std::make_unique<C2Worklet>();

            // component id
            dWorklet->component = static_cast<c2_node_id_t>(
                    sWorklet.componentId);

            // tunings
            if (!_copyParamsFromBlob(&dWorklet->tunings, sWorklet.tunings)) {
                LOG(ERROR) << "Invalid Worklet::tunings";
                return false;
            }

            // failures
            dWorklet->failures.clear();
            dWorklet->failures.reserve(sWorklet.failures.size());
            for (const auto& sFailure : sWorklet.failures) {
                std::unique_ptr<C2SettingResult> dFailure;
                if (!objcpy(&dFailure, sFailure)) {
                    LOG(ERROR) << "Invalid Worklet::failures.";
                    return false;
                }
                dWorklet->failures.emplace_back(std::move(dFailure));
            }

            // output
            if (!objcpy(&dWorklet->output, sWorklet.output, dBaseBlocks)) {
                LOG(ERROR) << "Invalid Worklet::output.";
                return false;
            }

            dWork.worklets.emplace_back(std::move(dWorklet));
        }

        // workletsProcessed
        dWork.workletsProcessed = sWork.workletsProcessed;

        // result
        dWork.result = GetStatus(sWork.result);
    }

    return true;
}

// BufferQueue-Based Block Operations
// ==================================

// Call before transferring block to other processes.
//
// The given block is ready to transfer to other processes. This will guarantee
// the given block data is not mutated by bufferqueue migration.
bool BeginTransferBufferQueueBlock(const C2ConstGraphicBlock& block);

// Call beginTransferBufferQueueBlock() on blocks in the given workList.
// processInput determines whether input blocks are yielded. processOutput
// works similarly on output blocks. (The default value of processInput is
// false while the default value of processOutput is true. This implies that in
// most cases, only output buffers contain bufferqueue-based blocks.)
void BeginTransferBufferQueueBlocks(
        const std::list<std::unique_ptr<C2Work>>& workList,
        bool processInput = false,
        bool processOutput = true);

// Call after transferring block is finished and make sure that
// beginTransferBufferQueueBlock() is called before.
//
// The transfer of given block is finished. If transfer is successful the given
// block is not owned by process anymore. Since transfer is finished the given
// block data is OK to mutate by bufferqueue migration after this call.
bool EndTransferBufferQueueBlock(const C2ConstGraphicBlock& block,
                                 bool transfer);

// Call endTransferBufferQueueBlock() on blocks in the given workList.
// processInput determines whether input blocks are yielded. processOutput
// works similarly on output blocks. (The default value of processInput is
// false while the default value of processOutput is true. This implies that in
// most cases, only output buffers contain bufferqueue-based blocks.)
void EndTransferBufferQueueBlocks(
        const std::list<std::unique_ptr<C2Work>>& workList,
        bool transfer,
        bool processInput = false,
        bool processOutput = true);

// The given block is ready to be rendered. the given block is not owned by
// process anymore. If migration is in progress, this returns false in order
// not to render.
bool DisplayBufferQueueBlock(const C2ConstGraphicBlock& block);

}  // namespace android

#endif  // CODEC2_COMMON_BUFFER_TYPES_H
