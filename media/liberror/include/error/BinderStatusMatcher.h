/*
 * Copyright (C) 2024 The Android Open Source Project
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

#pragma once

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <ostream>

#include <binder/Status.h>

namespace android::error {

class BinderStatusMatcher {
  public:
    using is_gtest_matcher = void;

    explicit BinderStatusMatcher(binder::Status status) : status_(std::move(status)) {}

    static BinderStatusMatcher hasException(binder::Status::Exception ex) {
        return BinderStatusMatcher(binder::Status::fromExceptionCode(ex));
    }

    static BinderStatusMatcher isOk() { return BinderStatusMatcher(binder::Status::ok()); }

    bool MatchAndExplain(const binder::Status& value,
                         ::testing::MatchResultListener* listener) const {
        if (status_.exceptionCode() == value.exceptionCode() &&
            status_.transactionError() == value.transactionError() &&
            status_.serviceSpecificErrorCode() == value.serviceSpecificErrorCode()) {
            return true;
        }
        *listener << "received binder status: " << value;
        return false;
    }

    void DescribeTo(std::ostream* os) const { *os << "contains binder status " << status_; }

    void DescribeNegationTo(std::ostream* os) const {
        *os << "does not contain binder status " << status_;
    }

  private:
    const binder::Status status_;
};
}  // namespace android::error
