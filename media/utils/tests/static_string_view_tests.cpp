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

#define LOG_TAG "StaticStringViewTests"

#include <mediautils/StaticStringView.h>

#include <gtest/gtest.h>
#include <log/log.h>

using namespace android::mediautils;

template <auto& T, class = void>
struct CanCreate : std::false_type {};

template <auto& T>
struct CanCreate<T, typename std::void_t<decltype(StaticStringView::create<T>)>> : std::true_type {
};

static constexpr std::array<char, 2> global = {'a', 'b'};

TEST(StaticStringViewTests, CreateTicket) {
    // This will always fail due to template param binding rules
    // const std::array<char,2> nonstatic = {'a', 'b'};
    // static_assert(can_assign<nonstatic>::value == false);
    static std::array<char, 2> nonconst = {'a', 'b'};
    static constexpr std::array<int, 2> nonchar = {1, 2};
    static constexpr size_t nonarray = 2;

    static_assert(CanCreate<nonconst>::value == false);
    static_assert(CanCreate<nonarray>::value == false);
    static_assert(CanCreate<nonchar>::value == false);

    static constexpr std::array<char, 2> scoped = {'a', 'b'};
    constexpr StaticStringView Ticket1 = StaticStringView::create<global>();
    constexpr StaticStringView Ticket2 = StaticStringView::create<scoped>();
    const StaticStringView Ticket3 = StaticStringView::create<scoped>();
    EXPECT_EQ(Ticket3, Ticket2);
    EXPECT_EQ(Ticket1.getStringView(), Ticket2.getStringView());
    EXPECT_EQ(std::string_view{"ab"}, Ticket1.getStringView());
}
TEST(StaticStringViewTests, CompileTimeConvert) {
    static constexpr std::array<char, 4> converted = StaticStringView::toStdArray("test");
    constexpr StaticStringView ticket = StaticStringView::create<converted>();
    EXPECT_EQ(ticket, std::string_view{"test"});
    // Unchecked constexpr construction
    static const std::array<char, 5> converted2 = StaticStringView::toStdArray("test2");
    constexpr auto ticket2 = StaticStringView::create<converted2, false>();
    EXPECT_EQ(ticket2, std::string_view{"test2"});
    constexpr char stack_array[4] = {'a', 'b', 'c', '\0'};
    static constexpr auto converted3 = StaticStringView::toStdArray(stack_array);
    constexpr auto ticket3 = StaticStringView::create<converted3>();
    EXPECT_EQ(ticket3, std::string_view{"abc"});
}

TEST(StaticStringViewTests, CompileTimeConcat) {
    // temporaries should not be static to prevent odr use
    constexpr std::array<char, 3> arr1 = {'a', 'b', 'c'};
    constexpr std::array<char, 4> arr2 = {'d', 'e', 'f', 'g'};
    static constexpr std::array<char, 7> res = StaticStringView::concatArray(arr1, arr2);
    static constexpr std::array<char, 7> expected = {'a', 'b', 'c', 'd', 'e', 'f', 'g'};
    EXPECT_EQ(res, expected);
}

TEST(StaticStringViewTests, StringViewForwarding) {
    static constexpr auto converted = StaticStringView::toStdArray("test");
    constexpr auto ticket = StaticStringView::create<converted>();
    EXPECT_EQ(ticket.length(), ticket.getStringView().length());
    EXPECT_TRUE(ticket == ticket.getStringView());
    EXPECT_TRUE(ticket == ticket);
    EXPECT_TRUE(ticket.getStringView() == ticket);
    EXPECT_TRUE(ticket > "abc");
    EXPECT_TRUE("abc" < ticket);
}
