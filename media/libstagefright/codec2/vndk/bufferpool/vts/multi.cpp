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

#define LOG_TAG "buffferpool_unit_test"

#include <gtest/gtest.h>

#include <C2AllocatorIon.h>
#include <C2Buffer.h>
#include <C2PlatformSupport.h>
#include <ClientManager.h>
#include <android-base/logging.h>
#include <binder/ProcessState.h>
#include <hidl/HidlSupport.h>
#include <hidl/HidlTransportSupport.h>
#include <hidl/LegacySupport.h>
#include <hidl/Status.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <iostream>
#include <memory>
#include <vector>
#include "allocator.h"

using android::C2AllocatorIon;
using android::C2PlatformAllocatorStore;
using android::hardware::configureRpcThreadpool;
using android::hardware::hidl_handle;
using android::hardware::media::bufferpool::V1_0::IAccessor;
using android::hardware::media::bufferpool::V1_0::IClientManager;
using android::hardware::media::bufferpool::V1_0::ResultStatus;
using android::hardware::media::bufferpool::V1_0::implementation::BufferId;
using android::hardware::media::bufferpool::V1_0::implementation::ClientManager;
using android::hardware::media::bufferpool::V1_0::implementation::ConnectionId;
using android::hardware::media::bufferpool::V1_0::implementation::TransactionId;

namespace {

// communication message types between processes.
enum PipeCommand : int32_t {
    INIT_OK = 0,
    INIT_ERROR,
    SEND,
    RECEIVE_OK,
    RECEIVE_ERROR,
};

// communication message between processes.
union PipeMessage {
    struct  {
        int32_t command;
        BufferId bufferId;
        ConnectionId connectionId;
        TransactionId transactionId;
        int64_t  timestampUs;
    } data;
    char array[0];
};

// media.bufferpool test setup
class BufferpoolMultiTest : public ::testing::Test {
 public:
  virtual void SetUp() override {
    ResultStatus status;
    mReceiverPid = -1;

    ASSERT_TRUE(pipe(mCommandPipeFds) == 0);
    ASSERT_TRUE(pipe(mResultPipeFds) == 0);

    mReceiverPid = fork();
    ASSERT_TRUE(mReceiverPid >= 0);

    if (mReceiverPid == 0) {
       doReceiver();
       return;
    }

    mManager = ClientManager::getInstance();
    ASSERT_NE(mManager, nullptr);

    std::shared_ptr<C2Allocator> allocator =
        std::make_shared<C2AllocatorIon>(C2PlatformAllocatorStore::ION);
    ASSERT_TRUE((bool)allocator);

    mAllocator = std::make_shared<VtsBufferPoolAllocator>(allocator);
    ASSERT_TRUE((bool)mAllocator);

    status = mManager->create(mAllocator, &mConnectionId);
    ASSERT_TRUE(status == ResultStatus::OK);

    status = mManager->getAccessor(mConnectionId, &mAccessor);
    ASSERT_TRUE(status == ResultStatus::OK && (bool)mAccessor);
  }

  virtual void TearDown() override {
      if (mReceiverPid > 0) {
          kill(mReceiverPid, SIGKILL);
          int wstatus;
          wait(&wstatus);
      }
  }

 protected:
  static void description(const std::string& description) {
    RecordProperty("description", description);
  }

  android::sp<ClientManager> mManager;
  android::sp<IAccessor> mAccessor;
  std::shared_ptr<BufferPoolAllocator> mAllocator;
  ConnectionId mConnectionId;
  pid_t mReceiverPid;
  int mCommandPipeFds[2];
  int mResultPipeFds[2];

  bool sendMessage(int *pipes, const PipeMessage &message) {
    int ret = write(pipes[1], message.array, sizeof(PipeMessage));
    return ret == sizeof(PipeMessage);
  }

  bool receiveMessage(int *pipes, PipeMessage *message) {
    int ret = read(pipes[0], message->array, sizeof(PipeMessage));
    return ret == sizeof(PipeMessage);
  }

  void doReceiver() {
    configureRpcThreadpool(1, false);
    PipeMessage message;
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

    receiveMessage(mCommandPipeFds, &message);
    {
      std::shared_ptr<_C2BlockPoolData> rbuffer;
      ResultStatus status = mManager->receive(
          message.data.connectionId, message.data.transactionId,
          message.data.bufferId, message.data.timestampUs, &rbuffer);
      if (status != ResultStatus::OK) {
        message.data.command = PipeCommand::RECEIVE_ERROR;
        sendMessage(mResultPipeFds, message);
        return;
      }
    }
    message.data.command = PipeCommand::RECEIVE_OK;
    sendMessage(mResultPipeFds, message);
    while(1); // An easy way to ignore gtest behaviour.
  }
};

// Buffer transfer test between processes.
TEST_F(BufferpoolMultiTest, TransferBuffer) {
  ResultStatus status;
  PipeMessage message;

  ASSERT_TRUE(receiveMessage(mResultPipeFds, &message));

  android::sp<IClientManager> receiver = IClientManager::getService();
  ConnectionId receiverId;
  ASSERT_TRUE((bool)receiver);

  receiver->registerSender(
      mAccessor, [&status, &receiverId]
      (ResultStatus outStatus, ConnectionId outId) {
        status = outStatus;
        receiverId = outId;
      });
  ASSERT_TRUE(status == ResultStatus::OK);
  {
    std::shared_ptr<_C2BlockPoolData> sbuffer;
    TransactionId transactionId;
    int64_t postUs;
    std::vector<uint8_t> vecParams;

    getVtsAllocatorParams(&vecParams);
    status = mManager->allocate(mConnectionId, vecParams, &sbuffer);
    ASSERT_TRUE(status == ResultStatus::OK);

    status = mManager->postSend(mConnectionId, receiverId, sbuffer,
                               &transactionId, &postUs);
    ASSERT_TRUE(status == ResultStatus::OK);

    message.data.command = PipeCommand::SEND;
    message.data.bufferId = sbuffer->mId;
    message.data.connectionId = receiverId;
    message.data.transactionId = transactionId;
    message.data.timestampUs = postUs;
    sendMessage(mCommandPipeFds, message);
  }
  EXPECT_TRUE(receiveMessage(mResultPipeFds, &message));
}

}  // anonymous namespace

int main(int argc, char** argv) {
  setenv("TREBLE_TESTING_OVERRIDE", "true", true);
  ::testing::InitGoogleTest(&argc, argv);
  int status = RUN_ALL_TESTS();
  LOG(INFO) << "Test result = " << status;
  return status;
}
