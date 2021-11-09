/*
 * Copyright (C) 2021 The Android Open Source Project
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
#define LOG_TAG "BufferpoolUnitTest"
#include <utils/Log.h>

#include <binder/ProcessState.h>
#include <bufferpool/ClientManager.h>
#include <gtest/gtest.h>
#include <hidl/LegacySupport.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unordered_set>
#include <vector>
#include "allocator.h"

using android::hardware::configureRpcThreadpool;
using android::hardware::media::bufferpool::BufferPoolData;
using android::hardware::media::bufferpool::V2_0::IClientManager;
using android::hardware::media::bufferpool::V2_0::ResultStatus;
using android::hardware::media::bufferpool::V2_0::implementation::BufferId;
using android::hardware::media::bufferpool::V2_0::implementation::ClientManager;
using android::hardware::media::bufferpool::V2_0::implementation::ConnectionId;
using android::hardware::media::bufferpool::V2_0::implementation::TransactionId;

using namespace android;

// communication message types between processes.
enum PipeCommand : int32_t {
    INIT,
    TRANSFER,
    STOP,

    INIT_OK,
    INIT_ERROR,
    TRANSFER_OK,
    TRANSFER_ERROR,
    STOP_OK,
    STOP_ERROR,
};

// communication message between processes.
union PipeMessage {
    struct {
        int32_t command;
        int32_t memsetValue;
        BufferId bufferId;
        ConnectionId connectionId;
        TransactionId transactionId;
        int64_t timestampUs;
    } data;
    char array[0];
};

static int32_t kNumIterationCount = 10;

class BufferpoolTest {
  public:
    BufferpoolTest() : mConnectionValid(false), mManager(nullptr), mAllocator(nullptr) {
        mConnectionId = -1;
    }

    ~BufferpoolTest() {
        if (mConnectionValid) {
            mManager->close(mConnectionId);
        }
    }

  protected:
    bool mConnectionValid;
    ConnectionId mConnectionId;

    android::sp<ClientManager> mManager;
    std::shared_ptr<BufferPoolAllocator> mAllocator;

    void setupBufferpoolManager();
};

void BufferpoolTest::setupBufferpoolManager() {
    // retrieving per process bufferpool object sp<ClientManager>
    mManager = ClientManager::getInstance();
    ASSERT_NE(mManager, nullptr) << "unable to get ClientManager\n";

    mAllocator = std::make_shared<TestBufferPoolAllocator>();
    ASSERT_NE(mAllocator, nullptr) << "unable to create TestBufferPoolAllocator\n";

    // set-up local bufferpool connection for sender
    ResultStatus status = mManager->create(mAllocator, &mConnectionId);
    ASSERT_EQ(status, ResultStatus::OK)
            << "unable to set-up local bufferpool connection for sender\n";
    mConnectionValid = true;
}

class BufferpoolUnitTest : public BufferpoolTest, public ::testing::Test {
  public:
    virtual void SetUp() override { setupBufferpoolManager(); }

    virtual void TearDown() override {}
};

class BufferpoolFunctionalityTest : public BufferpoolTest, public ::testing::Test {
  public:
    virtual void SetUp() override {
        mReceiverPid = -1;

        ASSERT_TRUE(pipe(mCommandPipeFds) == 0) << "pipe connection failed for commandPipe\n";
        ASSERT_TRUE(pipe(mResultPipeFds) == 0) << "pipe connection failed for resultPipe\n";

        mReceiverPid = fork();
        ASSERT_TRUE(mReceiverPid >= 0) << "fork failed\n";

        if (mReceiverPid == 0) {
            doReceiver();
            // In order to ignore gtest behaviour, wait for being killed from tearDown
            pause();
        }
        setupBufferpoolManager();
    }

    virtual void TearDown() override {
        if (mReceiverPid > 0) {
            kill(mReceiverPid, SIGKILL);
            int wstatus;
            wait(&wstatus);
        }
    }

  protected:
    pid_t mReceiverPid;
    int mCommandPipeFds[2];
    int mResultPipeFds[2];

    bool sendMessage(int* pipes, const PipeMessage& message) {
        int ret = write(pipes[1], message.array, sizeof(PipeMessage));
        return ret == sizeof(PipeMessage);
    }

    bool receiveMessage(int* pipes, PipeMessage* message) {
        int ret = read(pipes[0], message->array, sizeof(PipeMessage));
        return ret == sizeof(PipeMessage);
    }

    void doReceiver();
};

void BufferpoolFunctionalityTest::doReceiver() {
    // Configures the threadpool used for handling incoming RPC calls in this process.
    configureRpcThreadpool(1 /*threads*/, false /*willJoin*/);
    bool receiverRunning = true;
    while (receiverRunning) {
        PipeMessage message;
        receiveMessage(mCommandPipeFds, &message);
        ResultStatus err = ResultStatus::OK;
        switch (message.data.command) {
            case PipeCommand::INIT: {
                // receiver manager creation
                mManager = ClientManager::getInstance();
                if (!mManager) {
                    message.data.command = PipeCommand::INIT_ERROR;
                    sendMessage(mResultPipeFds, message);
                    return;
                }

                android::status_t status = mManager->registerAsService();
                if (status != android::OK) {
                    message.data.command = PipeCommand::INIT_ERROR;
                    sendMessage(mResultPipeFds, message);
                    return;
                }
                message.data.command = PipeCommand::INIT_OK;
                sendMessage(mResultPipeFds, message);
                break;
            }
            case PipeCommand::TRANSFER: {
                native_handle_t* receiveHandle = nullptr;
                std::shared_ptr<BufferPoolData> receiveBuffer;
                err = mManager->receive(message.data.connectionId, message.data.transactionId,
                                        message.data.bufferId, message.data.timestampUs,
                                        &receiveHandle, &receiveBuffer);
                if (err != ResultStatus::OK) {
                    message.data.command = PipeCommand::TRANSFER_ERROR;
                    sendMessage(mResultPipeFds, message);
                    return;
                }
                if (!TestBufferPoolAllocator::Verify(receiveHandle, message.data.memsetValue)) {
                    message.data.command = PipeCommand::TRANSFER_ERROR;
                    sendMessage(mResultPipeFds, message);
                    return;
                }
                if (receiveHandle) {
                    native_handle_close(receiveHandle);
                    native_handle_delete(receiveHandle);
                }
                receiveHandle = nullptr;
                receiveBuffer.reset();
                message.data.command = PipeCommand::TRANSFER_OK;
                sendMessage(mResultPipeFds, message);
                break;
            }
            case PipeCommand::STOP: {
                err = mManager->close(message.data.connectionId);
                if (err != ResultStatus::OK) {
                    message.data.command = PipeCommand::STOP_ERROR;
                    sendMessage(mResultPipeFds, message);
                    return;
                }
                message.data.command = PipeCommand::STOP_OK;
                sendMessage(mResultPipeFds, message);
                receiverRunning = false;
                break;
            }
            default:
                ALOGE("unknown command. try again");
                break;
        }
    }
}

// Buffer allocation test.
// Check whether each buffer allocation is done successfully with unique buffer id.
TEST_F(BufferpoolUnitTest, AllocateBuffer) {
    std::vector<uint8_t> vecParams;
    getTestAllocatorParams(&vecParams);

    std::vector<std::shared_ptr<BufferPoolData>> buffers{};
    std::vector<native_handle_t*> allocHandle{};
    ResultStatus status;
    for (int i = 0; i < kNumIterationCount; ++i) {
        native_handle_t* handle = nullptr;
        std::shared_ptr<BufferPoolData> buffer{};
        status = mManager->allocate(mConnectionId, vecParams, &handle, &buffer);
        ASSERT_EQ(status, ResultStatus::OK) << "allocate failed for " << i << "iteration";

        buffers.push_back(std::move(buffer));
        if (handle) {
            allocHandle.push_back(std::move(handle));
        }
    }

    for (int i = 0; i < kNumIterationCount; ++i) {
        for (int j = i + 1; j < kNumIterationCount; ++j) {
            ASSERT_TRUE(buffers[i]->mId != buffers[j]->mId) << "allocated buffers are not unique";
        }
    }
    // delete the buffer handles
    for (auto handle : allocHandle) {
        native_handle_close(handle);
        native_handle_delete(handle);
    }
    // clear the vectors
    buffers.clear();
    allocHandle.clear();
}

// Buffer recycle test.
// Check whether de-allocated buffers are recycled.
TEST_F(BufferpoolUnitTest, RecycleBuffer) {
    std::vector<uint8_t> vecParams;
    getTestAllocatorParams(&vecParams);

    ResultStatus status;
    std::vector<BufferId> bid{};
    std::vector<native_handle_t*> allocHandle{};
    for (int i = 0; i < kNumIterationCount; ++i) {
        native_handle_t* handle = nullptr;
        std::shared_ptr<BufferPoolData> buffer;
        status = mManager->allocate(mConnectionId, vecParams, &handle, &buffer);
        ASSERT_EQ(status, ResultStatus::OK) << "allocate failed for " << i << "iteration";

        bid.push_back(buffer->mId);
        if (handle) {
            allocHandle.push_back(std::move(handle));
        }
        buffer.reset();
    }

    std::unordered_set<BufferId> set(bid.begin(), bid.end());
    ASSERT_EQ(set.size(), 1) << "buffers are not recycled properly";

    // delete the buffer handles
    for (auto handle : allocHandle) {
        native_handle_close(handle);
        native_handle_delete(handle);
    }
    allocHandle.clear();
}

// Buffer transfer test between processes.
TEST_F(BufferpoolFunctionalityTest, TransferBuffer) {
    // initialize the receiver
    PipeMessage message;
    message.data.command = PipeCommand::INIT;
    sendMessage(mCommandPipeFds, message);
    ASSERT_TRUE(receiveMessage(mResultPipeFds, &message)) << "receiveMessage failed\n";
    ASSERT_EQ(message.data.command, PipeCommand::INIT_OK) << "receiver init failed";

    android::sp<IClientManager> receiver = IClientManager::getService();
    ASSERT_NE(receiver, nullptr) << "getService failed for receiver\n";

    ConnectionId receiverId;
    ResultStatus status = mManager->registerSender(receiver, mConnectionId, &receiverId);
    ASSERT_EQ(status, ResultStatus::OK)
            << "registerSender failed for connection id " << mConnectionId << "\n";

    std::vector<uint8_t> vecParams;
    getTestAllocatorParams(&vecParams);

    for (int i = 0; i < kNumIterationCount; ++i) {
        native_handle_t* handle = nullptr;
        std::shared_ptr<BufferPoolData> buffer;
        status = mManager->allocate(mConnectionId, vecParams, &handle, &buffer);
        ASSERT_EQ(status, ResultStatus::OK) << "allocate failed for " << i << "iteration";

        ASSERT_TRUE(TestBufferPoolAllocator::Fill(handle, i))
                << "Fill fail for buffer handle " << handle << "\n";

        // send the buffer to the receiver
        int64_t postUs;
        TransactionId transactionId;
        status = mManager->postSend(receiverId, buffer, &transactionId, &postUs);
        ASSERT_EQ(status, ResultStatus::OK)
                << "postSend failed for receiver " << receiverId << "\n";

        // PipeMessage message;
        message.data.command = PipeCommand::TRANSFER;
        message.data.memsetValue = i;
        message.data.bufferId = buffer->mId;
        message.data.connectionId = receiverId;
        message.data.transactionId = transactionId;
        message.data.timestampUs = postUs;
        sendMessage(mCommandPipeFds, message);
        // delete buffer handle
        if (handle) {
            native_handle_close(handle);
            native_handle_delete(handle);
        }
        ASSERT_TRUE(receiveMessage(mResultPipeFds, &message)) << "receiveMessage failed\n";
        ASSERT_EQ(message.data.command, PipeCommand::TRANSFER_OK)
                << "received error during buffer transfer\n";
    }
    message.data.command = PipeCommand::STOP;
    sendMessage(mCommandPipeFds, message);
    ASSERT_TRUE(receiveMessage(mResultPipeFds, &message)) << "receiveMessage failed\n";
    ASSERT_EQ(message.data.command, PipeCommand::STOP_OK)
            << "received error during buffer transfer\n";
}

int main(int argc, char** argv) {
    android::hardware::details::setTrebleTestingOverride(true);
    ::testing::InitGoogleTest(&argc, argv);
    int status = RUN_ALL_TESTS();
    ALOGV("Test result = %d\n", status);
    return status;
}
