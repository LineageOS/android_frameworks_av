/*
 * Copyright 2016 The Android Open Source Project
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
#define LOG_TAG "TypeTraits_test"

#include <gtest/gtest.h>

#include <media/stagefright/foundation/TypeTraits.h>

namespace android {

class TypeTraitsTest : public ::testing::Test {
protected:
    enum A { };
    enum UA : uint32_t { };
    enum IA : int32_t { };
};

// =========== basic sanity tests for type-support templates
TEST_F(TypeTraitsTest, StaticTests) {
    static_assert(!std::is_integral<A>::value, "enums should not be integral");
    static_assert(!std::is_integral<UA>::value, "enums should not be integral");
    static_assert(!std::is_integral<IA>::value, "enums should not be integral");
    static_assert(is_integral_or_enum<A>::value, "enums should be integral_or_enum");
    static_assert(is_integral_or_enum<UA>::value, "enums should be integral_or_enum");
    static_assert(is_integral_or_enum<IA>::value, "enums should be integral_or_enum");
    static_assert(is_integral_or_enum<int>::value, "ints should be integral_or_enum");
    static_assert(is_integral_or_enum<unsigned>::value, "unsigned ints should be integral_or_enum");
    static_assert(!is_integral_or_enum<float>::value, "floats should not be integral_or_enum");

    static_assert(!std::is_unsigned<UA>::value,
                  "unsigned enums should not be unsigned");
    static_assert(!std::is_unsigned<IA>::value,
                  "unsigned enums should not be unsigned");
    static_assert(std::is_unsigned<typename std::underlying_type<UA>::type>::value,
                  "underlying type of unsigned enums should be unsigned");
    static_assert(!std::is_unsigned<typename std::underlying_type<IA>::type>::value,
                  "underlying type of unsigned enums should be unsigned");
    static_assert(is_unsigned_integral<UA>::value,
                  "unsigned enums should be unsigned_integral");
    static_assert(!is_unsigned_integral<IA>::value,
                  "signed enums should not be unsigned_integral");
    static_assert(is_unsigned_integral<unsigned>::value,
                  "unsigned ints should be unsigned_integral");
    static_assert(!is_unsigned_integral<int>::value,
                  "ints should not be unsigned_integral");
    static_assert(!is_unsigned_integral<float>::value,
                  "floats should not be unsigned_integral");

    static_assert(!std::is_signed<UA>::value,
                  "unsigned enums should not be signed");
    static_assert(!std::is_signed<IA>::value,
                  "unsigned enums should not be signed");
    static_assert(!std::is_signed<typename std::underlying_type<UA>::type>::value,
                  "underlying type of unsigned enums should be signed");
    static_assert(std::is_signed<typename std::underlying_type<IA>::type>::value,
                  "underlying type of unsigned enums should be signed");
    static_assert(!is_signed_integral<UA>::value,
                  "unsigned enums should not be signed_integral");
    static_assert(is_signed_integral<IA>::value,
                  "signed enums should be signed_integral");
    static_assert(!is_signed_integral<unsigned>::value,
                  "unsigned ints should not be signed_integral");
    static_assert(is_signed_integral<int>::value,
                  "ints should be signed_integral");
    static_assert(!is_signed_integral<float>::value,
                  "floats should not be signed_integral");

    static_assert(std::is_same<uint64_t, typename underlying_integral_type<uint64_t>::type>::value,
                  "underlying integral type of uint64_t should be uint64_t");
    static_assert(std::is_same<uint32_t, typename underlying_integral_type<UA>::type>::value,
                  "underlying integral type of uint32_t based enums should be uint32_t");
    static_assert(std::is_same<int64_t, typename underlying_integral_type<int64_t>::type>::value,
                  "underlying integral type of int64_t should be int64_t");
    static_assert(std::is_same<int32_t, typename underlying_integral_type<IA>::type>::value,
                  "underlying integral type of int32_t based enums should be int32_t");
    //typedef underlying_integral_type<float>::type no_type;
    static_assert(std::is_same<void, typename underlying_integral_type<float, void>::type>::value,
                  "underlying integral type of float cannot be specified");
}

} // namespace android
