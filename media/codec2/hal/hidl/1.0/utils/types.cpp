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
#define LOG_TAG "Codec2-types"
#include <android-base/logging.h>

#include <bufferpool/ClientManager.h>
#include <codec2/common/BufferTypes.h>
#include <codec2/common/ParamTypes.h>
#include <codec2/hidl/1.0/types.h>

#include <C2AllocatorIon.h>
#include <C2AllocatorGralloc.h>
#include <C2BlockInternal.h>
#include <C2Buffer.h>
#include <C2Component.h>
#include <C2FenceFactory.h>
#include <C2PlatformSupport.h>
#include <C2Work.h>

namespace android {

using hardware::media::bufferpool::V2_0::implementation::ClientManager;
using hardware::media::c2::V1_0::BaseBlock;
using hardware::media::c2::V1_0::FieldSupportedValues;
using hardware::media::c2::V1_0::PrimitiveValue;
using hardware::media::c2::V1_0::ValueRange;
using hardware::media::c2::V1_0::utils::BufferPoolTypes;
using hardware::hidl_vec;

// C2FieldSupportedValues -> FieldSupportedValues
template<>
bool objcpy(
        FieldSupportedValues *d, const C2FieldSupportedValues &s) {
    switch (s.type) {
    case C2FieldSupportedValues::EMPTY: {
            d->empty(::android::hidl::safe_union::V1_0::Monostate{});
            break;
        }
    case C2FieldSupportedValues::RANGE: {
            ValueRange range{};
            if (!objcpy(&range, s.range)) {
                LOG(ERROR) << "Invalid C2FieldSupportedValues::range.";
                d->range(range);
                return false;
            }
            d->range(range);
            break;
        }
    case C2FieldSupportedValues::VALUES: {
            hidl_vec<PrimitiveValue> values;
            copyVector<uint64_t>(&values, s.values);
            d->values(values);
            break;
        }
    case C2FieldSupportedValues::FLAGS: {
            hidl_vec<PrimitiveValue> flags;
            copyVector<uint64_t>(&flags, s.values);
            d->flags(flags);
            break;
        }
    default:
        LOG(DEBUG) << "Unrecognized C2FieldSupportedValues::type_t "
                   << "with underlying value " << underlying_value(s.type)
                   << ".";
        return false;
    }
    return true;
}

// FieldSupportedValues -> C2FieldSupportedValues
template<>
bool objcpy(
        C2FieldSupportedValues *d, const FieldSupportedValues &s) {
    switch (s.getDiscriminator()) {
    case FieldSupportedValues::hidl_discriminator::empty: {
            d->type = C2FieldSupportedValues::EMPTY;
            break;
        }
    case FieldSupportedValues::hidl_discriminator::range: {
            d->type = C2FieldSupportedValues::RANGE;
            if (!objcpy(&d->range, s.range())) {
                LOG(ERROR) << "Invalid FieldSupportedValues::range.";
                return false;
            }
            d->values.resize(0);
            break;
        }
    case FieldSupportedValues::hidl_discriminator::values: {
            d->type = C2FieldSupportedValues::VALUES;
            copyVector<uint64_t>(&d->values, s.values());
            break;
        }
    case FieldSupportedValues::hidl_discriminator::flags: {
            d->type = C2FieldSupportedValues::FLAGS;
            copyVector<uint64_t>(&d->values, s.flags());
            break;
        }
    default:
        LOG(WARNING) << "Unrecognized FieldSupportedValues::getDiscriminator()";
        return false;
    }
    return true;
}

template<>
bool objcpy(C2BaseBlock* d, const BaseBlock& s) {
    switch (s.getDiscriminator()) {
    case BaseBlock::hidl_discriminator::nativeBlock: {
            if (s.nativeBlock() == nullptr) {
                LOG(ERROR) << "Null BaseBlock::nativeBlock handle";
                return false;
            }
            native_handle_t* sHandle =
                    native_handle_clone(s.nativeBlock());
            if (sHandle == nullptr) {
                LOG(ERROR) << "Null BaseBlock::nativeBlock.";
                return false;
            }
            const C2Handle *sC2Handle =
                    reinterpret_cast<const C2Handle*>(sHandle);

            d->linear = _C2BlockFactory::CreateLinearBlock(sC2Handle);
            if (d->linear) {
                d->type = C2BaseBlock::LINEAR;
                return true;
            }

            d->graphic = _C2BlockFactory::CreateGraphicBlock(sC2Handle);
            if (d->graphic) {
                d->type = C2BaseBlock::GRAPHIC;
                return true;
            }

            LOG(ERROR) << "Unknown handle type in BaseBlock::nativeBlock.";
            if (sHandle) {
                native_handle_close(sHandle);
                native_handle_delete(sHandle);
            }
            return false;
        }
    case BaseBlock::hidl_discriminator::pooledBlock: {
            const BufferPoolTypes::BufferStatusMessage &bpMessage =
                    s.pooledBlock();
            sp<ClientManager> bp = ClientManager::getInstance();
            std::shared_ptr<BufferPoolTypes::BufferPoolData> bpData;
            native_handle_t *cHandle;
            BufferPoolTypes::BufferPoolStatus bpStatus = bp->receive(
                    bpMessage.connectionId,
                    bpMessage.transactionId,
                    bpMessage.bufferId,
                    bpMessage.timestampUs,
                    &cHandle,
                    &bpData);
            if (bpStatus != BufferPoolTypes::ResultStatus::OK) {
                LOG(ERROR) << "Failed to receive buffer from bufferpool -- "
                           << "resultStatus = " << underlying_value(bpStatus)
                           << ".";
                return false;
            } else if (!bpData) {
                LOG(ERROR) << "No data in bufferpool transaction.";
                return false;
            }

            d->linear = _C2BlockFactory::CreateLinearBlock(cHandle, bpData);
            if (d->linear) {
                d->type = C2BaseBlock::LINEAR;
                return true;
            }

            d->graphic = _C2BlockFactory::CreateGraphicBlock(cHandle, bpData);
            if (d->graphic) {
                d->type = C2BaseBlock::GRAPHIC;
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
                   << underlying_value(s.getDiscriminator()) << ".";
        return false;
    }
}

template<>
void SetHandle(BaseBlock *block, const C2Handle *handle) {
    block->nativeBlock(reinterpret_cast<const native_handle_t*>(handle));
}

template<>
void SetPooledBlock<BufferPoolTypes>(
        BaseBlock *baseBlock,
        const typename BufferPoolTypes::BufferStatusMessage &pooledBlock) {
    baseBlock->pooledBlock(pooledBlock);
}

template<>
bool GetBufferPoolData<BufferPoolTypes>(
        const std::shared_ptr<const _C2BlockPoolData>& blockPoolData,
        std::shared_ptr<typename BufferPoolTypes::BufferPoolData> *bpData) {
    return _C2BlockFactory::GetBufferPoolData(blockPoolData, bpData);
}

namespace hardware {
namespace media {
namespace c2 {
namespace V1_0 {
namespace utils {

using ::android::hardware::media::bufferpool::BufferPoolData;
using ::android::hardware::media::bufferpool::V2_0::ResultStatus;
using ::android::hardware::media::bufferpool::V2_0::implementation::
        TransactionId;

const char* asString(Status status, const char* def) {
    return asString(static_cast<c2_status_t>(status), def);
}

// C2FieldSupportedValuesQuery -> FieldSupportedValuesQuery
bool objcpy(
        FieldSupportedValuesQuery* d,
        const C2FieldSupportedValuesQuery& s) {
    return ::android::objcpy(d, nullptr, s);
}

// FieldSupportedValuesQuery -> C2FieldSupportedValuesQuery
bool objcpy(
        C2FieldSupportedValuesQuery* d,
        const FieldSupportedValuesQuery& s) {
    return ::android::objcpy(d, s);
}

// C2FieldSupportedValuesQuery -> FieldSupportedValuesQueryResult
bool objcpy(
        FieldSupportedValuesQueryResult* d,
        const C2FieldSupportedValuesQuery& s) {
    return ::android::objcpy(nullptr, d, s);
}

// FieldSupportedValuesQuery, FieldSupportedValuesQueryResult ->
// C2FieldSupportedValuesQuery
bool objcpy(
        C2FieldSupportedValuesQuery* d,
        const FieldSupportedValuesQuery& sq,
        const FieldSupportedValuesQueryResult& sr) {
    return ::android::objcpy(d, sq, sr);
}

// C2Component::Traits -> IComponentStore::ComponentTraits
bool objcpy(
        IComponentStore::ComponentTraits *d,
        const C2Component::Traits &s) {
    return ::android::objcpy(d, s);
}

// ComponentTraits -> C2Component::Traits, std::unique_ptr<std::vector<std::string>>
bool objcpy(
        C2Component::Traits* d,
        const IComponentStore::ComponentTraits& s) {
    return ::android::objcpy(d, s);
}

// C2SettingResult -> SettingResult
bool objcpy(SettingResult *d, const C2SettingResult &s) {
    return ::android::objcpy(d, s);
}

// SettingResult -> std::unique_ptr<C2SettingResult>
bool objcpy(std::unique_ptr<C2SettingResult> *d, const SettingResult &s) {
    return ::android::objcpy(d, s);
}

// C2ParamDescriptor -> ParamDescriptor
bool objcpy(ParamDescriptor *d, const C2ParamDescriptor &s) {
    return ::android::objcpy(d, s);
}

// ParamDescriptor -> C2ParamDescriptor
bool objcpy(std::shared_ptr<C2ParamDescriptor> *d, const ParamDescriptor &s) {
    return ::android::objcpy(d, s);
}

// C2StructDescriptor -> StructDescriptor
bool objcpy(StructDescriptor *d, const C2StructDescriptor &s) {
    return ::android::objcpy(d, s);
}

// StructDescriptor -> C2StructDescriptor
bool objcpy(std::unique_ptr<C2StructDescriptor> *d, const StructDescriptor &s) {
    return ::android::objcpy(d, s);
}

// DefaultBufferPoolSender's implementation

DefaultBufferPoolSender::DefaultBufferPoolSender(
        const sp<IClientManager>& receiverManager,
        std::chrono::steady_clock::duration refreshInterval)
    : mReceiverManager(receiverManager),
      mRefreshInterval(refreshInterval) {
}

void DefaultBufferPoolSender::setReceiver(
        const sp<IClientManager>& receiverManager,
        std::chrono::steady_clock::duration refreshInterval) {
    std::lock_guard<std::mutex> lock(mMutex);
    if (mReceiverManager != receiverManager) {
        mReceiverManager = receiverManager;
        mConnections.clear();
    }
    mRefreshInterval = refreshInterval;
}

ResultStatus DefaultBufferPoolSender::send(
        const std::shared_ptr<BufferPoolData>& bpData,
        BufferStatusMessage* bpMessage) {
    int64_t connectionId = bpData->mConnectionId;
    if (connectionId == 0) {
        LOG(WARNING) << "registerSender -- invalid sender connection id (0).";
        return ResultStatus::CRITICAL_ERROR;
    }
    std::lock_guard<std::mutex> lock(mMutex);
    if (!mReceiverManager) {
        LOG(ERROR) << "No access to receiver's BufferPool.";
        return ResultStatus::NOT_FOUND;
    }
    if (!mSenderManager) {
        mSenderManager = ClientManager::getInstance();
        if (!mSenderManager) {
            LOG(ERROR) << "Failed to retrieve local BufferPool ClientManager.";
            return ResultStatus::CRITICAL_ERROR;
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
        ResultStatus rs =
                mSenderManager->registerSender(mReceiverManager,
                                               connectionId,
                                               &receiverConnectionId);
        if ((rs != ResultStatus::OK) && (rs != ResultStatus::ALREADY_EXISTS)) {
            LOG(WARNING) << "registerSender -- returned error: "
                         << static_cast<int32_t>(rs)
                         << ".";
            return rs;
        } else if (receiverConnectionId == 0) {
            LOG(WARNING) << "registerSender -- "
                            "invalid receiver connection id (0).";
            return ResultStatus::CRITICAL_ERROR;
        } else {
            if (isNewConnection) {
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
    ResultStatus rs = mSenderManager->postSend(
            receiverConnectionId, bpData, &transactionId, &timestampUs);
    if (rs != ResultStatus::OK) {
        LOG(ERROR) << "ClientManager::postSend -- returned error: "
                   << static_cast<int32_t>(rs)
                   << ".";
        mConnections.erase(foundConnection);
        return rs;
    }
    if (!bpMessage) {
        LOG(ERROR) << "Null output parameter for BufferStatusMessage.";
        mConnections.erase(foundConnection);
        return ResultStatus::CRITICAL_ERROR;
    }
    bpMessage->connectionId = receiverConnectionId;
    bpMessage->bufferId = bpData->mId;
    bpMessage->transactionId = transactionId;
    bpMessage->timestampUs = timestampUs;
    foundConnection->second.lastSent = now;
    return rs;
}

// std::list<std::unique_ptr<C2Work>> -> WorkBundle
bool objcpy(
        WorkBundle* d,
        const std::list<std::unique_ptr<C2Work>>& s,
        BufferPoolSender* bufferPoolSender) {
    return ::android::objcpy(d, s, bufferPoolSender);
}

// WorkBundle -> std::list<std::unique_ptr<C2Work>>
bool objcpy(std::list<std::unique_ptr<C2Work>>* d, const WorkBundle& s) {
    return ::android::objcpy(d, s);
}

// Params -> std::vector<C2Param*>
bool parseParamsBlob(std::vector<C2Param*> *params, const hidl_vec<uint8_t> &blob) {
    return ::android::parseParamsBlob(params, blob);
}

// std::vector<const C2Param*> -> Params
bool createParamsBlob(
        hidl_vec<uint8_t> *blob,
        const std::vector<const C2Param*> &params) {
    return ::android::_createParamsBlob(blob, params);
}

// std::vector<C2Param*> -> Params
bool createParamsBlob(
        hidl_vec<uint8_t> *blob,
        const std::vector<C2Param*> &params) {
    return ::android::_createParamsBlob(blob, params);
}

// std::vector<std::unique_ptr<C2Param>> -> Params
bool createParamsBlob(
        hidl_vec<uint8_t> *blob,
        const std::vector<std::unique_ptr<C2Param>> &params) {
    return ::android::_createParamsBlob(blob, params);
}

// std::vector<std::unique_ptr<C2Tuning>> -> Params
bool createParamsBlob(
        hidl_vec<uint8_t> *blob,
        const std::vector<std::unique_ptr<C2Tuning>> &params) {
    return ::android::_createParamsBlob(blob, params);
}

// std::vector<std::shared_ptr<const C2Info>> -> Params
bool createParamsBlob(
        hidl_vec<uint8_t> *blob,
        const std::vector<std::shared_ptr<const C2Info>> &params) {
    return ::android::_createParamsBlob(blob, params);
}

// Params -> std::vector<std::unique_ptr<C2Param>>
bool copyParamsFromBlob(
        std::vector<std::unique_ptr<C2Param>>* params,
        Params blob) {
    return ::android::_copyParamsFromBlob(params, blob);
}

// Params -> std::vector<std::unique_ptr<C2Tuning>>
bool copyParamsFromBlob(
        std::vector<std::unique_ptr<C2Tuning>>* params,
        Params blob) {
    return ::android::_copyParamsFromBlob(params, blob);
}

// Params -> update std::vector<std::unique_ptr<C2Param>>
bool updateParamsFromBlob(
        const std::vector<C2Param*>& params,
        const Params& blob) {
    return ::android::updateParamsFromBlob(params, blob);
}

// Convert BufferPool ResultStatus to c2_status_t.
c2_status_t toC2Status(ResultStatus rs) {
    switch (rs) {
    case ResultStatus::OK:
        return C2_OK;
    case ResultStatus::NO_MEMORY:
        return C2_NO_MEMORY;
    case ResultStatus::ALREADY_EXISTS:
        return C2_DUPLICATE;
    case ResultStatus::NOT_FOUND:
        return C2_NOT_FOUND;
    case ResultStatus::CRITICAL_ERROR:
        return C2_CORRUPTED;
    default:
        LOG(WARNING) << "Unrecognized BufferPool ResultStatus: "
                     << static_cast<int32_t>(rs) << ".";
        return C2_CORRUPTED;
    }
}

// BufferQueue-Based Block Operations
bool beginTransferBufferQueueBlock(const C2ConstGraphicBlock& block) {
    return ::android::BeginTransferBufferQueueBlock(block);
}

void beginTransferBufferQueueBlocks(
        const std::list<std::unique_ptr<C2Work>>& workList,
        bool processInput,
        bool processOutput) {
    return ::android::BeginTransferBufferQueueBlocks(
            workList, processInput, processOutput);
}

bool endTransferBufferQueueBlock(const C2ConstGraphicBlock& block,
                                 bool transfer) {
    return ::android::EndTransferBufferQueueBlock(block, transfer);
}

void endTransferBufferQueueBlocks(
        const std::list<std::unique_ptr<C2Work>>& workList,
        bool transfer,
        bool processInput,
        bool processOutput) {
    return ::android::EndTransferBufferQueueBlocks(
            workList, transfer, processInput, processOutput);
}

bool displayBufferQueueBlock(const C2ConstGraphicBlock& block) {
    return ::android::DisplayBufferQueueBlock(block);
}

}  // namespace utils
}  // namespace V1_0
}  // namespace c2
}  // namespace media
}  // namespace hardware
}  // namespace android

