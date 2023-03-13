/*
 * Copyright 2021 The Android Open Source Project
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
#define LOG_TAG "AData_test"

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <utils/RefBase.h>

#include <media/stagefright/foundation/AMessage.h>
#include <media/stagefright/foundation/AHandler.h>
#include <media/stagefright/foundation/ALooper.h>

using namespace android;

using ::testing::InSequence;
using ::testing::NiceMock;

class LooperWithSettableClock : public ALooper {
public:
  LooperWithSettableClock() : mClockUs(0) {}

  void setClockUs(int64_t nowUs) {
    mClockUs = nowUs;
  }

  int64_t getNowUs() override {
    return mClockUs;
  }

private:
  int64_t mClockUs;
};

timespec millis100 = {0, 100L*1000*1000};

class MockHandler : public AHandler {
public:
    MOCK_METHOD(void, onMessageReceived, (const sp<AMessage>&), (override));
};

TEST(AMessage_tests, settersAndGetters) {
  sp<AMessage> m1 = new AMessage();

  m1->setInt32("value", 2);
  m1->setInt32("bar", 3);

  int32_t i32;
  EXPECT_TRUE(m1->findInt32("value", &i32));
  EXPECT_EQ(2, i32);

  EXPECT_TRUE(m1->findInt32("bar", &i32));
  EXPECT_EQ(3, i32);


  m1->setInt64("big", INT64_MAX);
  m1->setInt64("smaller", INT64_MAX - 2);
  m1->setInt64("smallest", 257);

  int64_t i64;
  EXPECT_TRUE(m1->findInt64("big", &i64));
  EXPECT_EQ(INT64_MAX, i64);

  EXPECT_TRUE(m1->findInt64("smaller", &i64));
  EXPECT_EQ(INT64_MAX - 2, i64);

  m1->setSize("size1", 257);
  m1->setSize("size2", 1023);

  size_t sizing;
  EXPECT_TRUE(m1->findSize("size2", &sizing));
  EXPECT_EQ(1023, sizing);
  EXPECT_TRUE(m1->findSize("size1", &sizing));
  EXPECT_EQ(257, sizing);

  m1->setDouble("precise", 10.5);
  m1->setDouble("small", 0.125);

  double d;
  EXPECT_TRUE(m1->findDouble("precise", &d));
  EXPECT_EQ(10.5, d);

  EXPECT_TRUE(m1->findDouble("small", &d));
  EXPECT_EQ(0.125, d);

  // should be unchanged from the top of the test
  EXPECT_TRUE(m1->findInt32("bar", &i32));
  EXPECT_EQ(3, i32);

  EXPECT_FALSE(m1->findInt32("nonesuch", &i32));
  EXPECT_FALSE(m1->findInt64("nonesuch2", &i64));
  // types disagree, not found
  EXPECT_FALSE(m1->findInt32("big", &i32));
  EXPECT_FALSE(m1->findInt32("precise", &i32));

  // integral types should come back true
  EXPECT_TRUE(m1->findAsInt64("big", &i64));
  EXPECT_EQ(INT64_MAX, i64);
  EXPECT_TRUE(m1->findAsInt64("bar", &i64));
  EXPECT_EQ(3, i64);
  EXPECT_FALSE(m1->findAsInt64("precise", &i64));

  // recovers ints, size, and floating point values
  float value;
  EXPECT_TRUE(m1->findAsFloat("value", &value));
  EXPECT_EQ(2, value);
  EXPECT_TRUE(m1->findAsFloat("smallest", &value));
  EXPECT_EQ(257, value);
  EXPECT_TRUE(m1->findAsFloat("size2", &value));
  EXPECT_EQ(1023, value);
  EXPECT_TRUE(m1->findAsFloat("precise", &value));
  EXPECT_EQ(10.5, value);
  EXPECT_TRUE(m1->findAsFloat("small", &value));
  EXPECT_EQ(0.125, value);


  // need to handle still:
  // strings
  // Object
  // Buffer
  // Message (nested)
  //

  // removal
  m1->setInt32("shortlived", 2);
  m1->setInt32("alittlelonger", 2);
  EXPECT_EQ(OK, m1->removeEntryByName("shortlived"));
  EXPECT_EQ(BAD_VALUE, m1->removeEntryByName(nullptr));
  EXPECT_EQ(BAD_INDEX, m1->removeEntryByName("themythicalnonesuch"));
  EXPECT_FALSE(m1->findInt32("shortlived", &i32));
  EXPECT_TRUE(m1->findInt32("alittlelonger", &i32));

  EXPECT_NE(OK, m1->removeEntryByName("notpresent"));
}

TEST(AMessage_tests, deliversMultipleMessagesInOrderImmediately) {
  sp<NiceMock<MockHandler>> mockHandler = new NiceMock<MockHandler>;
  sp<LooperWithSettableClock> looper = new LooperWithSettableClock();
  looper->registerHandler(mockHandler);

  sp<AMessage> msgNow1 = new AMessage(0, mockHandler);
  msgNow1->post();
  sp<AMessage> msgNow2 = new AMessage(0, mockHandler);
  msgNow2->post();

  {
    InSequence inSequence;
    EXPECT_CALL(*mockHandler, onMessageReceived(msgNow1)).Times(1);
    EXPECT_CALL(*mockHandler, onMessageReceived(msgNow2)).Times(1);
  }
  looper->start();
  nanosleep(&millis100, nullptr); // just enough time for the looper thread to run
}

TEST(AMessage_tests, doesNotDeliverDelayedMessageImmediately) {
  sp<NiceMock<MockHandler>> mockHandler = new NiceMock<MockHandler>;
  sp<LooperWithSettableClock> looper = new LooperWithSettableClock();
  looper->registerHandler(mockHandler);

  sp<AMessage> msgNow = new AMessage(0, mockHandler);
  msgNow->post();
  sp<AMessage> msgDelayed = new AMessage(0, mockHandler);
  msgDelayed->post(100);

  EXPECT_CALL(*mockHandler, onMessageReceived(msgNow)).Times(1);
  // note: never called
  EXPECT_CALL(*mockHandler, onMessageReceived(msgDelayed)).Times(0);
  looper->start();
  nanosleep(&millis100, nullptr); // just enough time for the looper thread to run
}

TEST(AMessage_tests, deliversDelayedMessagesInSequence) {
  sp<NiceMock<MockHandler>> mockHandler = new NiceMock<MockHandler>;
  sp<LooperWithSettableClock> looper = new LooperWithSettableClock();
  looper->registerHandler(mockHandler);

  sp<AMessage> msgIn500 = new AMessage(0, mockHandler);
  msgIn500->post(500);
  sp<AMessage> msgNow = new AMessage(0, mockHandler);
  msgNow->post();
  sp<AMessage> msgIn100 = new AMessage(0, mockHandler);
  msgIn100->post(100);
  // not expected to be received
  sp<AMessage> msgIn1000 = new AMessage(0, mockHandler);
  msgIn1000->post(1000);

  looper->setClockUs(500);
  {
    InSequence inSequence;

    EXPECT_CALL(*mockHandler, onMessageReceived(msgNow)).Times(1);
    EXPECT_CALL(*mockHandler, onMessageReceived(msgIn100)).Times(1);
    EXPECT_CALL(*mockHandler, onMessageReceived(msgIn500)).Times(1);
  }
  // note: never called
  EXPECT_CALL(*mockHandler, onMessageReceived(msgIn1000)).Times(0);
  looper->start();
  nanosleep(&millis100, nullptr); // just enough time for the looper thread to run
}

TEST(AMessage_tests, deliversDelayedUniqueMessage) {
  sp<NiceMock<MockHandler>> mockHandler = new NiceMock<MockHandler>;
  sp<LooperWithSettableClock> looper = new LooperWithSettableClock();
  looper->registerHandler(mockHandler);

  sp<AMessage> msg = new AMessage(0, mockHandler);
  msg->postUnique(msg, 50);

  looper->setClockUs(50);
  EXPECT_CALL(*mockHandler, onMessageReceived(msg)).Times(1);
  looper->start();
  nanosleep(&millis100, nullptr); // just enough time for the looper thread to run
}

TEST(AMessage_tests, deliversImmediateUniqueMessage) {
  sp<NiceMock<MockHandler>> mockHandler = new NiceMock<MockHandler>;
  // note: we don't need to set the clock, but we do want a stable clock that doesn't advance
  sp<LooperWithSettableClock> looper = new LooperWithSettableClock();
  looper->registerHandler(mockHandler);

  sp<AMessage> msg = new AMessage(0, mockHandler);
  msg->postUnique(msg, 0);

  EXPECT_CALL(*mockHandler, onMessageReceived(msg)).Times(1);
  looper->start();
  nanosleep(&millis100, nullptr); // just enough time for the looper thread to run
}

TEST(AMessage_tests, doesNotDeliverUniqueMessageAfterRescheduleLater) {
  sp<NiceMock<MockHandler>> mockHandler = new NiceMock<MockHandler>;
  sp<LooperWithSettableClock> looper = new LooperWithSettableClock();
  looper->registerHandler(mockHandler);

  sp<AMessage> msg = new AMessage(0, mockHandler);
  msg->postUnique(msg, 50);
  msg->postUnique(msg, 100); // reschedule for later

  looper->setClockUs(50); // if the message is correctly rescheduled, it should not be delivered
  // Never called because the message was rescheduled to a later point in time
  EXPECT_CALL(*mockHandler, onMessageReceived(msg)).Times(0);
  looper->start();
  nanosleep(&millis100, nullptr); // just enough time for the looper thread to run
}

TEST(AMessage_tests, deliversUniqueMessageAfterRescheduleEarlier) {
  sp<NiceMock<MockHandler>> mockHandler = new NiceMock<MockHandler>;
  sp<LooperWithSettableClock> looper = new LooperWithSettableClock();
  looper->registerHandler(mockHandler);

  sp<AMessage> msg = new AMessage(0, mockHandler);
  msg->postUnique(msg, 100);
  msg->postUnique(msg, 50); // reschedule to fire earlier

  looper->setClockUs(50); // if the message is rescheduled correctly, it should be delivered
  EXPECT_CALL(*mockHandler, onMessageReceived(msg)).Times(1);
  looper->start();
  nanosleep(&millis100, nullptr); // just enough time for the looper thread to run
}

TEST(AMessage_tests, deliversSameMessageTwice) {
  sp<NiceMock<MockHandler>> mockHandler = new NiceMock<MockHandler>;
  sp<LooperWithSettableClock> looper = new LooperWithSettableClock();
  looper->registerHandler(mockHandler);

  sp<AMessage> msg = new AMessage(0, mockHandler);
  msg->post(50);
  msg->post(100);

  looper->setClockUs(100);
  EXPECT_CALL(*mockHandler, onMessageReceived(msg)).Times(2);
  looper->start();
  nanosleep(&millis100, nullptr); // just enough time for the looper thread to run
}

// When messages are posted twice with the same token, it will only be delivered once after being
// rescheduled.
TEST(AMessage_tests, deliversUniqueMessageOnce) {
  sp<NiceMock<MockHandler>> mockHandler = new NiceMock<MockHandler>;
  sp<LooperWithSettableClock> looper = new LooperWithSettableClock();
  looper->registerHandler(mockHandler);

  sp<AMessage> msg1 = new AMessage(0, mockHandler);
  msg1->postUnique(msg1, 50);
  sp<AMessage> msg2 = new AMessage(0, mockHandler);
  msg2->postUnique(msg1, 75); // note, using the same token as msg1

  looper->setClockUs(100);
  EXPECT_CALL(*mockHandler, onMessageReceived(msg1)).Times(0);
  EXPECT_CALL(*mockHandler, onMessageReceived(msg2)).Times(1);
  looper->start();
  nanosleep(&millis100, nullptr); // just enough time for the looper thread to run
}

TEST(AMessage_tests, postUnique_withNullToken_returnsInvalidArgument) {
  sp<NiceMock<MockHandler>> mockHandler = new NiceMock<MockHandler>;
  sp<ALooper> looper = new ALooper();
  looper->registerHandler(mockHandler);

  sp<AMessage> msg = new AMessage(0, mockHandler);
  EXPECT_EQ(msg->postUnique(nullptr, 0), -EINVAL);
}
