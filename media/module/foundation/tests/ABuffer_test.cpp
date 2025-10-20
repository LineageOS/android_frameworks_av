/*
 * Copyright 2025 The Android Open Source Project
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
#define LOG_TAG "ABuffer_test"

#include <gtest/gtest.h>
#include <utils/RefBase.h>

#include <media/stagefright/foundation/ABuffer.h>

namespace android {

class ABufferTest : public ::testing::Test {
};

TEST_F(ABufferTest, CreateAndVerifyTest) {
    size_t capacity = 10;
    // ABuffer with owned placeholder
    sp<ABuffer> buf = new ABuffer(capacity);
    EXPECT_TRUE(buf != nullptr);
    EXPECT_TRUE(buf->base() != nullptr);
    EXPECT_TRUE(buf->data() != nullptr);
    EXPECT_TRUE(buf->capacity() == capacity);
    EXPECT_TRUE(buf->size() == capacity);
    EXPECT_TRUE(buf->offset() == 0);

    // ABuffer with not owned placeholder
    std::unique_ptr<uint8_t[]> charArray(new uint8_t[capacity]);
    sp<ABuffer> copyBuf = new ABuffer(charArray.get(), capacity);
    EXPECT_TRUE(copyBuf != nullptr);
    EXPECT_TRUE(copyBuf->base() == charArray.get());
    EXPECT_TRUE(copyBuf->data() == charArray.get());
    EXPECT_TRUE(copyBuf->capacity() == capacity);
    EXPECT_TRUE(copyBuf->size() == capacity);
    EXPECT_TRUE(copyBuf->offset() == 0);

    // ABuffer without any placeholder.
    sp<ABuffer> nullBuf = new ABuffer(nullptr, 0);
    EXPECT_TRUE(nullBuf != nullptr);
    EXPECT_TRUE(nullBuf->base() == nullptr);
    EXPECT_TRUE(nullBuf->data() == nullptr);
    EXPECT_TRUE(nullBuf->capacity() == 0);
    EXPECT_TRUE(nullBuf->size() == 0);
    EXPECT_TRUE(nullBuf->offset() == 0);
}

TEST_F(ABufferTest, SetRangeTest) {
    size_t capacity = 10;
    size_t offset = 2;
    size_t size = capacity - offset;
    sp<ABuffer> buf = new ABuffer(capacity);
    EXPECT_TRUE(buf != nullptr);
    EXPECT_TRUE(buf->base() != nullptr);
    EXPECT_TRUE(buf->data() != nullptr);
    EXPECT_TRUE(buf->capacity() == capacity);
    EXPECT_TRUE(buf->size() == capacity);
    EXPECT_TRUE(buf->offset() == 0);

    // Set the valid range
    buf->setRange(offset, size);
    EXPECT_TRUE(buf->capacity() == capacity);
    EXPECT_TRUE(buf->size() == size);
    EXPECT_TRUE(buf->offset() == offset);

    // Calling setRange with invalid input will crash the test.
}

TEST_F(ABufferTest, SetRange2Test) {
    size_t capacity = 10;
    size_t offset = 2;
    size_t size = capacity - offset;
    sp<ABuffer> buf = new ABuffer(capacity);
    EXPECT_TRUE(buf != nullptr);
    EXPECT_TRUE(buf->base() != nullptr);
    EXPECT_TRUE(buf->data() != nullptr);
    EXPECT_TRUE(buf->capacity() == capacity);
    EXPECT_TRUE(buf->size() == capacity);
    EXPECT_TRUE(buf->offset() == 0);

    // Set the valid range
    EXPECT_TRUE(buf->setRangeWithStatus(offset, size) == OK);
    EXPECT_TRUE(buf->capacity() == capacity);
    EXPECT_TRUE(buf->size() == size);
    EXPECT_TRUE(buf->offset() == offset);

    // Set the range with invalid arguments ==> size goes beyond capacity.
    EXPECT_TRUE(buf->setRangeWithStatus(offset, size + 1) == BAD_VALUE);

    // Set the range with invalid arguments ==> offset goes beyond capacity.
    EXPECT_TRUE(buf->setRangeWithStatus(offset + capacity, size) == BAD_VALUE);

    // ABuffer without any placeholder.
    sp<ABuffer> nullBuf = new ABuffer(nullptr, capacity);
    EXPECT_TRUE(nullBuf != nullptr);
    EXPECT_TRUE(nullBuf->base() == nullptr);
    EXPECT_TRUE(nullBuf->data() == nullptr);
    EXPECT_TRUE(nullBuf->capacity() == capacity);
    EXPECT_TRUE(nullBuf->size() == capacity);
    EXPECT_TRUE(nullBuf->offset() == 0);

    // Set the range when buffer has no placeholder ==> data/base is nullptr
    EXPECT_TRUE(nullBuf->setRangeWithStatus(offset, size) == NO_MEMORY);
}

} // namespace android
