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
#define LOG_TAG "Codec2-AIDL-BufferTypes"
#include <android-base/logging.h>

#include <aidlcommonsupport/NativeHandle.h>
#include <aidl/android/hardware/media/bufferpool2/BufferStatusMessage.h>
#include <bufferpool2/BufferPoolTypes.h>
#include <codec2/aidl/BufferTypes.h>
#include <codec2/common/BufferTypes.h>
#include <cutils/native_handle.h>
#include <media/stagefright/foundation/AUtils.h>

#include <C2AllocatorIon.h>
#include <C2AllocatorGralloc.h>
#include <C2BlockInternal.h>
#include <C2Buffer.h>
#include <C2Component.h>
#include <C2FenceFactory.h>
#include <C2Param.h>
#include <C2PlatformSupport.h>
#include <C2Work.h>

#include <algorithm>
#include <functional>
#include <iomanip>
#include <unordered_map>

#include "ParamTypes-specialization.h"

namespace android {

using ::aidl::android::hardware::media::bufferpool2::BufferPoolData;
using ::aidl::android::hardware::media::bufferpool2::BufferStatusMessage;
using ::aidl::android::hardware::media::bufferpool2::ResultStatus;
using ::aidl::android::hardware::media::bufferpool2::implementation::BufferPoolStatus;
using ::aidl::android::hardware::media::bufferpool2::implementation::ClientManager;
using ::aidl::android::hardware::media::c2::BaseBlock;
using ::aidl::android::hardware::media::c2::utils::BufferPoolTypes;

using AidlNativeHandle = ::aidl::android::hardware::common::NativeHandle;
using AidlHardwareBuffer = ::aidl::android::hardware::HardwareBuffer;

constexpr BaseBlock::Tag NATIVE_BLOCK = BaseBlock::nativeBlock;
constexpr BaseBlock::Tag HWB_BLOCK = BaseBlock::hwbBlock;
constexpr BaseBlock::Tag POOLED_BLOCK = BaseBlock::pooledBlock;

// BaseBlock -> C2BaseBlock
template<>
bool objcpy(C2BaseBlock* d, const BaseBlock& s) {
    switch (s.getTag()) {
    case NATIVE_BLOCK: {
            if (isAidlNativeHandleEmpty(s.get<NATIVE_BLOCK>())) {
                LOG(ERROR) << "Null BaseBlock::nativeBlock handle";
                return false;
            }
            native_handle_t* sHandle =
                    ::android::dupFromAidl(s.get<NATIVE_BLOCK>());
            if (sHandle == nullptr) {
                LOG(ERROR) << "Null BaseBlock::nativeBlock.";
                return false;
            }
            const C2Handle *sC2Handle =
                    reinterpret_cast<const C2Handle*>(sHandle);

            // If successful, the handle is deleted(!) and fds are owned by the block.
            d->linear = _C2BlockFactory::CreateLinearBlock(sC2Handle);
            if (d->linear) {
                d->type = ::android::C2BaseBlock::LINEAR;
                return true;
            }

            // If successful, the handle is deleted(!) and fds are owned by the block.
            d->graphic = _C2BlockFactory::CreateGraphicBlock(sC2Handle);
            if (d->graphic) {
                d->type = ::android::C2BaseBlock::GRAPHIC;
                return true;
            }

            LOG(ERROR) << "Unknown handle type in BaseBlock::nativeBlock.";
            if (sHandle) {
                native_handle_close(sHandle);
                native_handle_delete(sHandle);
            }
            return false;
        }
    case HWB_BLOCK: {
            AHardwareBuffer *pBuf =
                    const_cast<AidlHardwareBuffer&>(
                            s.get<HWB_BLOCK>()).release();
            d->graphic = _C2BlockFactory::CreateGraphicBlock(pBuf);
            if (pBuf) {
                AHardwareBuffer_release(pBuf);
            }
            if (d->graphic) {
                d->type = ::android::C2BaseBlock::GRAPHIC;
                return true;
            }
            LOG(ERROR) << "Improper ahwb in BaseBlock::hwbBlock.";
            return false;
        }
    case POOLED_BLOCK: {
            const BufferStatusMessage &bpMessage = s.get<POOLED_BLOCK>();
            std::shared_ptr<ClientManager> bp = ClientManager::getInstance();
            std::shared_ptr<BufferPoolData> bpData;
            native_handle_t *cHandle;
            BufferPoolStatus bpStatus = bp->receive(
                    bpMessage.connectionId,
                    bpMessage.transactionId,
                    bpMessage.bufferId,
                    bpMessage.timestampUs,
                    &cHandle,
                    &bpData);
            if (bpStatus != ResultStatus::OK) {
                LOG(ERROR) << "Failed to receive buffer from bufferpool -- "
                           << "resultStatus = " << bpStatus << ".";
                return false;
            } else if (!bpData) {
                LOG(ERROR) << "No data in bufferpool transaction.";
                return false;
            }

            // If successful, the handle is deleted(!) and fds are owned by the block.
            d->linear = _C2BlockFactory::CreateLinearBlock(cHandle, bpData);
            if (d->linear) {
                d->type = ::android::C2BaseBlock::LINEAR;
                return true;
            }

            // If successful, the handle is deleted(!) and fds are owned by the block.
            d->graphic = _C2BlockFactory::CreateGraphicBlock(cHandle, bpData);
            if (d->graphic) {
                d->type = ::android::C2BaseBlock::GRAPHIC;
                return true;
            }
            if (cHandle) {
                // Though we got cloned handle, creating block failed.
                native_handle_close(cHandle);
                native_handle_delete(cHandle);
            }

            LOG(ERROR) << "Unknown handle type in BaseBlock::pooledBlock.";
            return false;
        }
    default:
        LOG(ERROR) << "Unrecognized BaseBlock's discriminator with "
                   << "underlying value "
                   << ::android::underlying_value(s.getTag()) << ".";
        return false;
    }
}

// C2Fence -> AidlNativeHandle
template<>
bool objcpy(AidlNativeHandle* d, const C2Fence& s) {
    // fds are not duplicated here
    native_handle_t* handle = _C2FenceFactory::CreateNativeHandle(s);
    if (handle) {
        // |d| copies the fds without duplicating
        *d = makeToAidl(handle);
        // no fds are duplicated, just delete the handle
        // Note: C2Fence still owns the fds and should not be cleared
        // before the transaction is complete.
        native_handle_delete(handle);
//  } else if (!s.ready()) {
//      // TODO: we should wait for unmarshallable fences but this may not be
//      // the best place for it. We can safely ignore here as at this time
//      // all fences used here are marshallable.
    }
    return true;
}

// AidlNativeHandle -> C2Fence
template<>
bool objcpy(C2Fence* d, const AidlNativeHandle& s) {
    // makeFromAidl does not duplicate the fds.
    native_handle_t* handle = makeFromAidl(s);
    // C2Fence duplicates and owns the fds
    *d = _C2FenceFactory::CreateFromNativeHandle(handle);
    if (handle) {
        // |handle| should not be closed here, as the fds are owned by |s|
        native_handle_delete(handle);
    }
    return true;
}

template<>
void SetHandle(BaseBlock *block, const C2Handle *handle) {
    block->set<BaseBlock::nativeBlock>(dupToAidl(handle));
}

template<>
void SetAHardwareBuffer(BaseBlock *block, AHardwareBuffer *ahwb) {
    AHardwareBuffer_acquire(ahwb);
    block->set<HWB_BLOCK>(AidlHardwareBuffer());
    (block->get<HWB_BLOCK>()).reset(ahwb);
}

template<>
void SetPooledBlock<BufferPoolTypes>(
        BaseBlock *baseBlock,
        const typename BufferPoolTypes::BufferStatusMessage &pooledBlock) {
    baseBlock->set<POOLED_BLOCK>(pooledBlock);
}

template<>
bool GetBufferPoolData<BufferPoolTypes>(
        const std::shared_ptr<const _C2BlockPoolData>& blockPoolData,
        std::shared_ptr<typename BufferPoolTypes::BufferPoolData> *bpData) {
    return _C2BlockFactory::GetBufferPoolData(blockPoolData, bpData);
}

}  // namespace android

namespace aidl {
namespace android {
namespace hardware {
namespace media {
namespace c2 {
namespace utils {

namespace bufferpool2 = ::aidl::android::hardware::media::bufferpool2;
namespace bufferpool2_impl = ::aidl::android::hardware::media::bufferpool2::implementation;

// DefaultBufferPoolSender's implementation

DefaultBufferPoolSender::DefaultBufferPoolSender(
        const std::shared_ptr<IClientManager>& receiverManager,
        std::chrono::steady_clock::duration refreshInterval)
    : mReceiverManager(receiverManager),
      mRefreshInterval(refreshInterval) {
}

void DefaultBufferPoolSender::setReceiver(
        const std::shared_ptr<IClientManager>& receiverManager,
        std::chrono::steady_clock::duration refreshInterval) {
    std::lock_guard<std::mutex> lock(mMutex);
    if (mReceiverManager != receiverManager) {
        mReceiverManager = receiverManager;
        mConnections.clear();
    }
    mRefreshInterval = refreshInterval;
}

BufferPoolTypes::BufferPoolStatus DefaultBufferPoolSender::send(
        const std::shared_ptr<bufferpool2::BufferPoolData>& bpData,
        bufferpool2::BufferStatusMessage* bpMessage) {
    int64_t connectionId = bpData->mConnectionId;
    if (connectionId == 0) {
        LOG(WARNING) << "registerSender -- invalid sender connection id (0).";
        return bufferpool2::ResultStatus::CRITICAL_ERROR;
    }
    std::lock_guard<std::mutex> lock(mMutex);
    if (!mReceiverManager) {
        LOG(ERROR) << "No access to receiver's BufferPool.";
        return bufferpool2::ResultStatus::NOT_FOUND;
    }
    if (!mSenderManager) {
        mSenderManager = ClientManager::getInstance();
        if (!mSenderManager) {
            LOG(ERROR) << "Failed to retrieve local BufferPool ClientManager.";
            return bufferpool2::ResultStatus::CRITICAL_ERROR;
        }
    }

    int64_t receiverConnectionId{0};
    auto foundConnection = mConnections.find(connectionId);
    bool isNewConnection = foundConnection == mConnections.end();
    std::chrono::steady_clock::time_point now =
            std::chrono::steady_clock::now();
    if (isNewConnection ||
            (now - foundConnection->second.lastSent > mRefreshInterval)) {
        // Initialize the bufferpool connection.
        bufferpool2_impl::BufferPoolStatus rs =
                mSenderManager->registerSender(mReceiverManager,
                                               connectionId,
                                               &receiverConnectionId,
                                               &isNewConnection);
        if ((rs != bufferpool2::ResultStatus::OK)
                && (rs != bufferpool2::ResultStatus::ALREADY_EXISTS)) {
            LOG(WARNING) << "registerSender -- returned error: "
                         << static_cast<int32_t>(rs)
                         << ".";
            return rs;
        } else if (receiverConnectionId == 0) {
            LOG(WARNING) << "registerSender -- "
                            "invalid receiver connection id (0).";
            return bufferpool2::ResultStatus::CRITICAL_ERROR;
        } else {
            if (foundConnection == mConnections.end()) {
                foundConnection = mConnections.try_emplace(
                        connectionId, receiverConnectionId, now).first;
            } else {
                foundConnection->second.receiverConnectionId = receiverConnectionId;
            }
        }
    } else {
        receiverConnectionId = foundConnection->second.receiverConnectionId;
    }

    uint64_t transactionId;
    int64_t timestampUs;
    bufferpool2_impl::BufferPoolStatus rs = mSenderManager->postSend(
            receiverConnectionId, bpData, &transactionId, &timestampUs);
    if (rs != bufferpool2::ResultStatus::OK) {
        LOG(ERROR) << "ClientManager::postSend -- returned error: "
                   << static_cast<int32_t>(rs)
                   << ".";
        mConnections.erase(foundConnection);
        return rs;
    }
    if (!bpMessage) {
        LOG(ERROR) << "Null output parameter for BufferStatusMessage.";
        mConnections.erase(foundConnection);
        return bufferpool2::ResultStatus::CRITICAL_ERROR;
    }
    bpMessage->connectionId = receiverConnectionId;
    bpMessage->bufferId = bpData->mId;
    bpMessage->transactionId = transactionId;
    bpMessage->timestampUs = timestampUs;
    foundConnection->second.lastSent = now;
    return rs;
}

// std::list<std::unique_ptr<C2Work>> -> WorkBundle
bool ToAidl(
        WorkBundle* d,
        const std::list<std::unique_ptr<C2Work>>& s,
        ::android::BufferPoolSender<BufferPoolTypes>* bufferPoolSender) {
    return ::android::objcpy(d, s, bufferPoolSender);
}

// WorkBundle -> std::list<std::unique_ptr<C2Work>>
bool FromAidl(std::list<std::unique_ptr<C2Work>>* d, const WorkBundle& s) {
    return ::android::objcpy(d, s);
}

void ReturnOutputBlocksToClientIfNeeded(
        const std::list<std::unique_ptr<C2Work>>& workList) {
    for (const std::unique_ptr<C2Work>& work : workList) {
        if (!work) {
            continue;
        }
        for (const std::unique_ptr<C2Worklet>& worklet : work->worklets) {
            if (worklet) {
                for (const std::shared_ptr<C2Buffer>& buffer : worklet->output.buffers) {
                    if (buffer) {
                        for (const C2ConstGraphicBlock& block : buffer->data().graphicBlocks()) {
                            std::shared_ptr<_C2BlockPoolData> poolData =
                                  _C2BlockFactory::GetGraphicBlockPoolData(block);
                            _C2BlockFactory::DisownIgbaBlock(poolData);
                        }
                    }
                }
            }
        }
    }
}

}  // namespace utils
}  // namespace c2
}  // namespace media
}  // namespace hardware
}  // namespace android
}  // namespace aidl

