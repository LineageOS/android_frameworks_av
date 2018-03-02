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

#ifndef ANDROID_HARDWARE_MEDIA_BUFFERPOOL_V1_0_ACCESSOR_H
#define ANDROID_HARDWARE_MEDIA_BUFFERPOOL_V1_0_ACCESSOR_H

#include <android/hardware/media/bufferpool/1.0/IAccessor.h>
#include <hidl/MQDescriptor.h>
#include <hidl/Status.h>
#include <BufferPoolTypes.h>
#include "BufferStatus.h"

namespace android {
namespace hardware {
namespace media {
namespace bufferpool {
namespace V1_0 {
namespace implementation {

using ::android::hardware::hidl_array;
using ::android::hardware::hidl_memory;
using ::android::hardware::hidl_string;
using ::android::hardware::hidl_vec;
using ::android::hardware::Return;
using ::android::hardware::Void;
using ::android::sp;

struct Connection;

/**
 * A buffer pool accessor which enables a buffer pool to communicate with buffer
 * pool clients. 1:1 correspondense holds between a buffer pool and an accessor.
 */
struct Accessor : public IAccessor {
    // Methods from ::android::hardware::media::bufferpool::V1_0::IAccessor follow.
    Return<void> connect(connect_cb _hidl_cb) override;

    /**
     * Creates a buffer pool accessor which uses the specified allocator.
     *
     * @param allocator buffer allocator.
     */
    explicit Accessor(const std::shared_ptr<BufferPoolAllocator> &allocator);

    /** Destructs a buffer pool accessor. */
    ~Accessor();

    /** Returns whether the accessor is valid. */
    bool isValid();

    /** Allocates a buffer form a buffer pool.
     *
     * @param connectionId  the connection id of the client.
     * @param params        the allocation parameters.
     * @param bufferId      the id of the allocated buffer.
     * @param handle        the native handle of the allocated buffer.
     *
     * @return OK when a buffer is successfully allocated.
     *         NO_MEMORY when there is no memory.
     *         CRITICAL_ERROR otherwise.
     */
    ResultStatus allocate(
            ConnectionId connectionId,
            const std::vector<uint8_t>& params,
            BufferId *bufferId,
            const native_handle_t** handle);

    /**
     * Fetches a buffer for the specified transaction.
     *
     * @param connectionId  the id of receiving connection(client).
     * @param transactionId the id of the transfer transaction.
     * @param bufferId      the id of the buffer to be fetched.
     * @param handle        the native handle of the fetched buffer.
     *
     * @return OK when a buffer is successfully fetched.
     *         NO_MEMORY when there is no memory.
     *         CRITICAL_ERROR otherwise.
     */
    ResultStatus fetch(
            ConnectionId connectionId,
            TransactionId transactionId,
            BufferId bufferId,
            const native_handle_t** handle);

    /**
     * Makes a connection to the buffer pool. The buffer pool client uses the
     * created connection in order to communicate with the buffer pool. An
     * FMQ for buffer status message is also created for the client.
     *
     * @param connection    created connection
     * @param pConnectionId the id of the created connection
     * @param fmqDescPtr    FMQ descriptor for shared buffer status message
     *                      queue between a buffer pool and the client.
     *
     * @return OK when a connection is successfully made.
     *         NO_MEMORY when there is no memory.
     *         CRITICAL_ERROR otherwise.
     */
    ResultStatus connect(
            sp<Connection> *connection, ConnectionId *pConnectionId,
            const QueueDescriptor** fmqDescPtr);

    /**
     * Closes the specified connection to the client.
     *
     * @param connectionId  the id of the connection.
     *
     * @return OK when the connection is closed.
     *         CRITICAL_ERROR otherwise.
     */
    ResultStatus close(ConnectionId connectionId);

private:
    class Impl;
    std::unique_ptr<Impl> mImpl;
};

// FIXME: most likely delete, this is only for passthrough implementations
// extern "C" IAccessor* HIDL_FETCH_IAccessor(const char* name);

}  // namespace implementation
}  // namespace V1_0
}  // namespace bufferpool
}  // namespace media
}  // namespace hardware
}  // namespace android

#endif  // ANDROID_HARDWARE_MEDIA_BUFFERPOOL_V1_0_ACCESSOR_H
