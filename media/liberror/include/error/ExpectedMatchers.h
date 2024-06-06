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
#include <type_traits>

namespace android::error {

/**
 * Example Usage:
 * Given a function with signature
 *       Result<T, U> foo()
 * Matchers can be used as follows:
 *       EXPECT_THAT(foo(), IsOkAnd(Eq(T{})));
 *       EXPECT_THAT(foo(), IsErrorAnd(Eq(U{})));
 */
template <typename ExpectedT>
class IsOkAndImpl : public ::testing::MatcherInterface<ExpectedT> {
  public:
    using ValueT = std::remove_reference_t<ExpectedT>::value_type;

    template <typename InnerMatcher>
    explicit IsOkAndImpl(InnerMatcher innerMatcher)
        : inner_matcher_(::testing::SafeMatcherCast<const ValueT&>(
                  std::forward<InnerMatcher>(innerMatcher))) {}

    bool MatchAndExplain(ExpectedT val, ::testing::MatchResultListener* listener) const {
        if (!val.has_value()) {
            *listener << "which has error " << ::testing::PrintToString(val.error());
            return false;
        }
        const auto res = inner_matcher_.MatchAndExplain(val.value(), listener);
        if (!res) {
            *listener << "which has value " << ::testing::PrintToString(val.value());
        }
        return res;
    }

    void DescribeTo(std::ostream* os) const {
        *os << "contains expected value which ";
        inner_matcher_.DescribeTo(os);
    }

    void DescribeNegationTo(std::ostream* os) const {
        *os << "does not contain expected, or contains expected value which ";
        inner_matcher_.DescribeNegationTo(os);
    }

  private:
    ::testing::Matcher<const ValueT&> inner_matcher_;
};

template <typename InnerMatcher>
class IsOkAnd {
  public:
    explicit IsOkAnd(InnerMatcher innerMatcher) : inner_matcher_(std::move(innerMatcher)) {}

    template <typename T>
    operator ::testing::Matcher<T>() const {
        return ::testing::Matcher<T>{new IsOkAndImpl<const T&>(inner_matcher_)};
    }

  private:
    InnerMatcher inner_matcher_;
};

template <typename ExpectedT>
class IsErrorAndImpl : public ::testing::MatcherInterface<ExpectedT> {
  public:
    using ErrorT = typename std::remove_reference_t<ExpectedT>::error_type;

    template <typename InnerMatcher>
    explicit IsErrorAndImpl(InnerMatcher innerMatcher)
        : inner_matcher_(::testing::SafeMatcherCast<const ErrorT&>(
                  std::forward<InnerMatcher>(innerMatcher))) {}

    bool MatchAndExplain(ExpectedT val, ::testing::MatchResultListener* listener) const {
        if (val.has_value()) {
            *listener << "which has value " << ::testing::PrintToString(val.value());
            return false;
        }

        const auto res = inner_matcher_.MatchAndExplain(val.error(), listener);
        if (!res) {
            *listener << "which has error " << ::testing::PrintToString(val.error());
        }
        return res;
    }

    void DescribeTo(std::ostream* os) const {
        *os << "contains error value which ";
        inner_matcher_.DescribeTo(os);
    }

    void DescribeNegationTo(std::ostream* os) const {
        *os << "does not contain error value, or contains error value which ";
        inner_matcher_.DescribeNegationTo(os);
    }

  private:
    ::testing::Matcher<const ErrorT&> inner_matcher_;
};

template <typename InnerMatcher>
class IsErrorAnd {
  public:
    explicit IsErrorAnd(InnerMatcher innerMatcher) : inner_matcher_(std::move(innerMatcher)) {}

    template <typename T>
    operator ::testing::Matcher<T>() const {
        return ::testing::Matcher<T>{new IsErrorAndImpl<const T&>(inner_matcher_)};
    }

  private:
    InnerMatcher inner_matcher_;
};

}  // namespace android::error
