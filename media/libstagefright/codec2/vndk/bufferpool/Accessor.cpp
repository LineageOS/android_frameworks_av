/*
 * Copyright (C) 2018 The Android Open Source Project
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

#include "Accessor.h"
#include "AccessorImpl.h"
#include "Connection.h"

namespace android {
namespace hardware {
namespace media {
namespace bufferpool {
namespace V1_0 {
namespace implementation {

// Methods from ::android::hardware::media::bufferpool::V1_0::IAccessor follow.
Return<void> Accessor::connect(connect_cb _hidl_cb) {
    sp<Connection> connection;
    ConnectionId connectionId;
    const QueueDescriptor* fmqDesc;

    ResultStatus status = connect(&connection, &connectionId, &fmqDesc);
    if (status == ResultStatus::OK) {
        _hidl_cb(status, connection, connectionId, *fmqDesc);
    } else {
        _hidl_cb(status, nullptr, -1LL,
                 android::hardware::MQDescriptorSync<BufferStatusMessage>(
                         std::vector<android::hardware::GrantorDescriptor>(),
                         nullptr /* nhandle */, 0 /* size */));
    }
    return Void();
}

Accessor::Accessor(const std::shared_ptr<BufferPoolAllocator> &allocator)
    : mImpl(new Impl(allocator)) {}

Accessor::~Accessor() {
}

bool Accessor::isValid() {
    return (bool)mImpl;
}

ResultStatus Accessor::allocate(
        ConnectionId connectionId,
        const std::vector<uint8_t> &params,
        BufferId *bufferId, const native_handle_t** handle) {
    if (mImpl) {
        return mImpl->allocate(connectionId, params, bufferId, handle);
    }
    return ResultStatus::CRITICAL_ERROR;
}

ResultStatus Accessor::fetch(
        ConnectionId connectionId, TransactionId transactionId,
        BufferId bufferId, const native_handle_t** handle) {
    if (mImpl) {
        return mImpl->fetch(connectionId, transactionId, bufferId, handle);
    }
    return ResultStatus::CRITICAL_ERROR;
}

ResultStatus Accessor::connect(
        sp<Connection> *connection, ConnectionId *pConnectionId,
        const QueueDescriptor** fmqDescPtr) {
    if (mImpl) {
        return mImpl->connect(this, connection, pConnectionId, fmqDescPtr);
    }
    return ResultStatus::CRITICAL_ERROR;
}

ResultStatus Accessor::close(ConnectionId connectionId) {
    if (mImpl) {
        return mImpl->close(connectionId);
    }
    return ResultStatus::CRITICAL_ERROR;
}

//IAccessor* HIDL_FETCH_IAccessor(const char* /* name */) {
//    return new Accessor();
//}

}  // namespace implementation
}  // namespace V1_0
}  // namespace bufferpool
}  // namespace media
}  // namespace hardware
}  // namespace android
