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

#include <error/expected_utils.h>
#include <gtest/gtest.h>

#define LOG_TAG "Result-test"

namespace android {
namespace foo {

class Value {
  public:
    explicit Value(int i) : mInt(i) {}
    Value(const Value&) = delete;
    Value(Value&&) = default;

    operator int() const { return mInt; }

  private:
    const int mInt;
};

class Status {
  public:
    explicit Status(int i) : mInt(i) {}
    Status(const Status&) = delete;
    Status(Status&&) = default;

    operator int() const { return mInt; }

  private:
    const int mInt;
};

bool errorIsOk(const Status& e) {
    return e == 0;
}

std::string errorToString(const Status& e) {
    std::ostringstream str;
    str << e;
    return str.str();
}

using Result = base::expected<Value, Status>;

}  // namespace foo

namespace {

using foo::Result;
using foo::Status;
using foo::Value;

TEST(Result, ValueOrReturnSuccess) {
    Result result = []() -> Result {
        Value intermediate = VALUE_OR_RETURN(Result(Value(3)));
        return Value(intermediate + 1);
    }();
    ASSERT_TRUE(result.ok());
    EXPECT_EQ(4, result.value());
}

TEST(Result, ValueOrReturnFailure) {
    Result result = []() -> Result {
        Value intermediate = VALUE_OR_RETURN(Result(base::unexpected(Status(2))));
        return Value(intermediate + 1);
    }();
    ASSERT_FALSE(result.ok());
    EXPECT_EQ(2, result.error());
}

TEST(Result, ValueOrReturnStatusSuccess) {
    Status status = []() -> Status {
        Value intermediate = VALUE_OR_RETURN_STATUS(Result(Value(3)));
        (void) intermediate;
        return Status(0);
    }();
    EXPECT_EQ(0, status);
}

TEST(Result, ValueOrReturnStatusFailure) {
    Status status = []() -> Status {
        Value intermediate = VALUE_OR_RETURN_STATUS(Result(base::unexpected(Status(1))));
        (void) intermediate;
        return Status(0);
    }();
    EXPECT_EQ(1, status);
}

TEST(Result, ReturnIfErrorSuccess) {
    Result result = []() -> Result {
        RETURN_IF_ERROR(Status(0));
        return Value(5);
    }();
    ASSERT_TRUE(result.ok());
    EXPECT_EQ(5, result.value());
}

TEST(Result, ReturnIfErrorFailure) {
    Result result = []() -> Result {
        RETURN_IF_ERROR(Status(4));
        return Value(5);
    }();
    ASSERT_FALSE(result.ok());
    EXPECT_EQ(4, result.error());
}

TEST(Result, ReturnStatusIfErrorSuccess) {
    Status status = []() -> Status {
        RETURN_STATUS_IF_ERROR(Status(0));
        return Status(7);
    }();
    EXPECT_EQ(7, status);
}

TEST(Result, ReturnStatusIfErrorFailure) {
    Status status = []() -> Status {
        RETURN_STATUS_IF_ERROR(Status(3));
        return Status(0);
    }();
    EXPECT_EQ(3, status);
}

TEST(Result, ValueOrFatalSuccess) {
    Value value = VALUE_OR_FATAL(Result(Value(7)));
    EXPECT_EQ(7, value);
}

TEST(Result, ValueOrFatalFailure) {
    EXPECT_DEATH(VALUE_OR_FATAL(Result(base::unexpected(Status(3)))), "");
}

TEST(Result, FatalIfErrorSuccess) {
    FATAL_IF_ERROR(Status(0));
}

TEST(Result, FatalIfErrorFailure) {
    EXPECT_DEATH(FATAL_IF_ERROR(Status(3)), "");
}

}  // namespace
}  // namespace android
