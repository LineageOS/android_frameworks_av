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
#include <unistd.h>
#include <iostream>
#include <memory>
#include <vector>
#include "allocator.h"

using android::C2AllocatorIon;
using android::C2PlatformAllocatorStore;
using android::hardware::hidl_handle;
using android::hardware::media::bufferpool::V1_0::IAccessor;
using android::hardware::media::bufferpool::V1_0::ResultStatus;
using android::hardware::media::bufferpool::V1_0::implementation::BufferId;
using android::hardware::media::bufferpool::V1_0::implementation::ClientManager;
using android::hardware::media::bufferpool::V1_0::implementation::ConnectionId;
using android::hardware::media::bufferpool::V1_0::implementation::TransactionId;

namespace {

// Number of iteration for buffer allocation test.
constexpr static int kNumAllocationTest = 3;

// Number of iteration for buffer recycling test.
constexpr static int kNumRecycleTest = 3;

// media.bufferpool test setup
class BufferpoolSingleTest : public ::testing::Test {
 public:
  virtual void SetUp() override {
    ResultStatus status;

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

    ConnectionId& receiverId = mReceiverId;
    mManager->registerSender(
        mAccessor,
        [&status, &receiverId](ResultStatus hidlStatus, ConnectionId hidlId) {
          status = hidlStatus;
          receiverId = hidlId;
        });
    ASSERT_TRUE(status == ResultStatus::ALREADY_EXISTS &&
                receiverId == mConnectionId);
  }

 protected:
  static void description(const std::string& description) {
    RecordProperty("description", description);
  }

  android::sp<ClientManager> mManager;
  android::sp<IAccessor> mAccessor;
  std::shared_ptr<BufferPoolAllocator> mAllocator;
  ConnectionId mConnectionId;
  ConnectionId mReceiverId;

};

// Buffer allocation test.
// Check whether each buffer allocation is done successfully with
// unique buffer id.
TEST_F(BufferpoolSingleTest, AllocateBuffer) {
  ResultStatus status;
  std::vector<uint8_t> vecParams;
  getVtsAllocatorParams(&vecParams);

  std::shared_ptr<_C2BlockPoolData> buffer[kNumAllocationTest];
  for (int i = 0; i < kNumAllocationTest; ++i) {
    status = mManager->allocate(mConnectionId, vecParams, &buffer[i]);
    ASSERT_TRUE(status == ResultStatus::OK);
  }
  for (int i = 0; i < kNumAllocationTest; ++i) {
    for (int j = i + 1; j < kNumAllocationTest; ++j) {
      ASSERT_TRUE(buffer[i]->mId != buffer[j]->mId);
    }
  }
  EXPECT_TRUE(kNumAllocationTest > 1);
}

// Buffer recycle test.
// Check whether de-allocated buffers are recycled.
TEST_F(BufferpoolSingleTest, RecycleBuffer) {
  ResultStatus status;
  std::vector<uint8_t> vecParams;
  getVtsAllocatorParams(&vecParams);

  BufferId bid[kNumRecycleTest];
  for (int i = 0; i < kNumRecycleTest; ++i) {
    std::shared_ptr<_C2BlockPoolData> buffer;
    status = mManager->allocate(mConnectionId, vecParams, &buffer);
    ASSERT_TRUE(status == ResultStatus::OK);
    bid[i] = buffer->mId;
  }
  for (int i = 1; i < kNumRecycleTest; ++i) {
    ASSERT_TRUE(bid[i - 1] == bid[i]);
  }
  EXPECT_TRUE(kNumRecycleTest > 1);
}

// Buffer transfer test.
// Check whether buffer is transferred to another client successfully.
TEST_F(BufferpoolSingleTest, TransferBuffer) {
  ResultStatus status;
  std::vector<uint8_t> vecParams;
  getVtsAllocatorParams(&vecParams);
  std::shared_ptr<_C2BlockPoolData> sbuffer, rbuffer;

  TransactionId transactionId;
  int64_t postUs;

  status = mManager->allocate(mConnectionId, vecParams, &sbuffer);
  ASSERT_TRUE(status == ResultStatus::OK);
  status = mManager->postSend(mConnectionId, mReceiverId, sbuffer,
                              &transactionId, &postUs);
  ASSERT_TRUE(status == ResultStatus::OK);
  status = mManager->receive(mReceiverId, transactionId, sbuffer->mId, postUs,
                             &rbuffer);
  EXPECT_TRUE(status == ResultStatus::OK);
}

}  // anonymous namespace

int main(int argc, char** argv) {
  ::testing::InitGoogleTest(&argc, argv);
  int status = RUN_ALL_TESTS();
  LOG(INFO) << "Test result = " << status;
  return status;
}
