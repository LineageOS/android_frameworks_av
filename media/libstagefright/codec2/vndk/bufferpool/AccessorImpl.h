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

#ifndef ANDROID_HARDWARE_MEDIA_BUFFERPOOL_V1_0_ACCESSORIMPL_H
#define ANDROID_HARDWARE_MEDIA_BUFFERPOOL_V1_0_ACCESSORIMPL_H

#include <map>
#include <set>
#include "Accessor.h"

namespace android {
namespace hardware {
namespace media {
namespace bufferpool {
namespace V1_0 {
namespace implementation {

struct InternalBuffer;
struct TransactionStatus;

/**
 * An implementation of a buffer pool accessor(or a buffer pool implementation.) */
class Accessor::Impl {
public:
    Impl(const std::shared_ptr<BufferPoolAllocator> &allocator);

    ~Impl();

    ResultStatus connect(
            const sp<Accessor> &accessor, sp<Connection> *connection,
            ConnectionId *pConnectionId, const QueueDescriptor** fmqDescPtr);

    ResultStatus close(ConnectionId connectionId);

    ResultStatus allocate(ConnectionId connectionId,
                          const std::vector<uint8_t>& params,
                          BufferId *bufferId,
                          const native_handle_t** handle);

    ResultStatus fetch(ConnectionId connectionId,
                       TransactionId transactionId,
                       BufferId bufferId,
                       const native_handle_t** handle);

    /** Processes pending buffer status messages */
    void sync();

private:
    // ConnectionId = pid : (timestamp_created + seqId)
    // in order to guarantee uniqueness for each connection
    static uint32_t sSeqId;
    static int32_t sPid;

    const std::shared_ptr<BufferPoolAllocator> mAllocator;

    /**
     * Buffer pool implementation.
     *
     * Handles buffer status messages. Handles buffer allocation/recycling.
     * Handles buffer transfer between buffer pool clients.
     */
    struct BufferPool {
    private:
        std::mutex mMutex;
        int64_t mTimestampUs;
        BufferId mSeq;
        BufferStatusObserver mObserver;

        std::map<ConnectionId, std::set<BufferId>> mUsingBuffers;
        std::map<BufferId, std::set<ConnectionId>> mUsingConnections;

        std::map<ConnectionId, std::set<TransactionId>> mPendingTransactions;
        // Transactions completed before TRANSFER_TO message arrival.
        // Fetch does not occur for the transactions.
        // Only transaction id is kept for the transactions in short duration.
        std::set<TransactionId> mCompletedTransactions;
        // Currently active(pending) transations' status & information.
        std::map<TransactionId, std::unique_ptr<TransactionStatus>>
                mTransactions;

        std::map<BufferId, std::unique_ptr<InternalBuffer>> mBuffers;
        std::set<BufferId> mFreeBuffers;

    public:
        /** Creates a buffer pool. */
        BufferPool();

        /**
         * Processes all pending buffer status messages, and returns the result.
         * Each status message is handled by methods with 'handle' prefix.
         */
        void processStatusMessages();

        /**
         * Handles a buffer being owned by a connection.
         *
         * @param connectionId  the id of the buffer owning connection.
         * @param bufferId      the id of the buffer.
         *
         * @return {@code true} when the buffer is owned,
         *         {@code false} otherwise.
         */
        bool handleOwnBuffer(ConnectionId connectionId, BufferId bufferId);

        /**
         * Handles a buffer being released by a connection.
         *
         * @param connectionId  the id of the buffer owning connection.
         * @param bufferId      the id of the buffer.
         *
         * @return {@code true} when the buffer ownership is released,
         *         {@code false} otherwise.
         */
        bool handleReleaseBuffer(ConnectionId connectionId, BufferId bufferId);

        /**
         * Handles a transfer transaction start message from the sender.
         *
         * @param message   a buffer status message for the transaction.
         *
         * @result {@code true} when transfer_to message is acknowledged,
         *         {@code false} otherwise.
         */
        bool handleTransferTo(const BufferStatusMessage &message);

        /**
         * Handles a transfer transaction being acked by the receiver.
         *
         * @param message   a buffer status message for the transaction.
         *
         * @result {@code true} when transfer_from message is acknowledged,
         *         {@code false} otherwise.
         */
        bool handleTransferFrom(const BufferStatusMessage &message);

        /**
         * Handles a transfer transaction result message from the receiver.
         *
         * @param message   a buffer status message for the transaction.
         *
         * @result {@code true} when the exisitng transaction is finished,
         *         {@code false} otherwise.
         */
        bool handleTransferResult(const BufferStatusMessage &message);

        /**
         * Handles a connection being closed, and returns the result. All the
         * buffers and transactions owned by the connection will be cleaned up.
         * The related FMQ will be cleaned up too.
         *
         * @param connectionId  the id of the connection.
         *
         * @result {@code true} when the connection existed,
         *         {@code false} otherwise.
         */
        bool handleClose(ConnectionId connectionId);

        /**
         * Recycles a existing free buffer if it is possible.
         *
         * @param allocator the buffer allocator
         * @param params    the allocation parameters.
         * @param pId       the id of the recycled buffer.
         * @param handle    the native handle of the recycled buffer.
         *
         * @return {@code true} when a buffer is recycled, {@code false}
         *         otherwise.
         */
        bool getFreeBuffer(
                const std::shared_ptr<BufferPoolAllocator> &allocator,
                const std::vector<uint8_t> &params,
                BufferId *pId, const native_handle_t **handle);

        /**
         * Creates a new buffer.
         *
         * @param allocator the buffer allocator
         * @param params    the allocator parameters
         * @param pId       the buffer id for the newly allocated buffer.
         * @param handle    the native handle for the newly allocated buffer.
         *
         * @return OK when an allocation is successfully allocated.
         *         NO_MEMORY when there is no memory.
         *         CRITICAL_ERROR otherwise.
         */
        ResultStatus getNewBuffer(
                const std::shared_ptr<BufferPoolAllocator> &allocator,
                const std::vector<uint8_t> &params, BufferId *pId,
                const native_handle_t **handle);

        friend class Accessor::Impl;
    } mBufferPool;
};

}  // namespace implementation
}  // namespace V1_0
}  // namespace ufferpool
}  // namespace media
}  // namespace hardware
}  // namespace android

#endif  // ANDROID_HARDWARE_MEDIA_BUFFERPOOL_V1_0_ACCESSORIMPL_H
