/*
 * Copyright (C) 2022 The Android Open Source Project
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

#include <atomic>
#include <cstdint>
#include <tuple>
#include <type_traits>

#include <log/log.h>

namespace android::mediautils {

// The goal of this class is to detect and accumulate wraparound occurrences on a
// lower sized integer.

// This class assumes that the underlying unsigned type is either incremented or
// decremented by at most the underlying signed type between any two subsequent
// polls (or construction). This is well-defined as the modular nature of
// unsigned arithmetic ensures that every new value maps 1-1 to an
// increment/decrement over the same sized signed type. It also ensures that our
// counter will be equivalent mod the size of the integer even if the underlying
// type is modified outside of this range.
//
// For convenience, this class is thread compatible. Additionally, it is safe
// as long as there is only one writer.
template <typename Integral = uint32_t, typename AccumulatingType = uint64_t>
class ExtendedAccumulator {
    static_assert(sizeof(Integral) < sizeof(AccumulatingType),
                  "Accumulating type should be larger than underlying type");
    static_assert(std::is_integral_v<Integral> && std::is_unsigned_v<Integral>,
                  "Wraparound behavior is only well-defiend for unsigned ints");
    static_assert(std::is_integral_v<AccumulatingType>);

  public:
    enum class Wrap {
        Normal = 0,
        Underflow = 1,
        Overflow = 2,
    };

    using UnsignedInt = Integral;
    using SignedInt = std::make_signed_t<UnsignedInt>;

    explicit ExtendedAccumulator(AccumulatingType initial = 0) : mAccumulated(initial) {}

    // Returns a pair of the calculated change on the accumulating value, and a
    // Wrap type representing the type of wraparound (if any) which occurred.
    std::pair<SignedInt, Wrap> poll(UnsignedInt value) {
        auto acc = mAccumulated.load(std::memory_order_relaxed);
        const auto bottom_bits = static_cast<UnsignedInt>(acc);
        std::pair<SignedInt, Wrap> res = {0, Wrap::Normal};
        const bool overflow = __builtin_sub_overflow(value, bottom_bits, &res.first);

        if (overflow) {
            res.second = (res.first > 0) ? Wrap::Overflow : Wrap::Underflow;
        }

        const bool acc_overflow = __builtin_add_overflow(acc, res.first, &acc);
        // If our *accumulating* type overflows or underflows (depending on its
        // signedness), we should abort.
        if (acc_overflow) LOG_ALWAYS_FATAL("Unexpected overflow/underflow in %s", __func__);

        mAccumulated.store(acc, std::memory_order_relaxed);
        return res;
    }

    AccumulatingType getValue() const { return mAccumulated.load(std::memory_order_relaxed); }

  private:
    // Invariant - the bottom underlying bits of accumulated are the same as the
    // last value provided to poll.
    std::atomic<AccumulatingType> mAccumulated;
};

}  // namespace android::mediautils
