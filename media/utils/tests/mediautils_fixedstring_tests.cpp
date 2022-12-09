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

#define LOG_TAG "mediautils_fixedstring_tests"

#include <mediautils/FixedString.h>

#include <gtest/gtest.h>
#include <utils/Log.h>

using namespace android::mediautils;

TEST(mediautils_fixedstring_tests, ctor) {
    FixedString<8> s0("abcde");

    ASSERT_FALSE(s0.empty());
    ASSERT_EQ(8U, s0.capacity());

    ASSERT_EQ(5U, s0.size());
    ASSERT_EQ(3U, s0.remaining());
    ASSERT_EQ(0, strcmp(s0.c_str(), "abcde"));

    ASSERT_EQ(0, strcmp(s0.data(), "abcde"));

    // overflow
    FixedString<8> s1("abcdefghijk");
    ASSERT_EQ(8U, s1.size());
    ASSERT_TRUE(s1.full());
    ASSERT_EQ(0U, s1.remaining());
    ASSERT_EQ(0, strcmp(s1.c_str(), "abcdefgh"));

    // overflow
    FixedString<8> s2(std::string("abcdefghijk"));
    ASSERT_TRUE(s2.full());

    ASSERT_EQ(8U, s2.size());
    ASSERT_EQ(0, strcmp(s2.c_str(), "abcdefgh"));

    // complex
    ASSERT_EQ(s1, s2);
    ASSERT_EQ(FixedString<12>().append(s1), s2);
    ASSERT_NE(s1, "bcd");

    // string and stringview
    ASSERT_EQ(s1.asString(), s1.asStringView());

    FixedString30 s3;
    s3 = std::string("abcd");
    ASSERT_EQ(s3, "abcd");

    s3.clear();
    ASSERT_EQ(s3, "");
    ASSERT_NE(s3, "abcd");
    ASSERT_EQ(0U, s3.size());
}

TEST(mediautils_fixedstring_tests, append) {
    FixedString<8> s0;
    ASSERT_EQ(0U, s0.size());
    ASSERT_EQ(0, strcmp(s0.c_str(), ""));
    ASSERT_TRUE(s0.empty());
    ASSERT_FALSE(s0.full());

    s0.append("abc");
    ASSERT_EQ(3U, s0.size());
    ASSERT_EQ(0, strcmp(s0.c_str(), "abc"));

    s0.append(std::string("d"));
    ASSERT_EQ(4U, s0.size());
    ASSERT_EQ(0, strcmp(s0.c_str(), "abcd"));

    // overflow
    s0.append("efghijk");
    ASSERT_EQ(8U, s0.size());
    ASSERT_EQ(0, strcmp(s0.c_str(), "abcdefgh"));
    ASSERT_TRUE(s0.full());

    // concatenated
    ASSERT_EQ(FixedString62("abcd"),
            FixedString<8>("ab").append("c").append(FixedString<8>("d")));
    ASSERT_EQ(FixedString<12>("a").append(FixedString<12>("b")), "ab");
}

TEST(mediautils_fixedstring_tests, plus_equals) {
    FixedString<8> s0;
    ASSERT_EQ(0U, s0.size());
    ASSERT_EQ(0, strcmp(s0.c_str(), ""));

    s0 += "abc";
    s0 += "def";
    ASSERT_EQ(s0, "abcdef");
}

TEST(mediautils_fixedstring_tests, stream_operator) {
    FixedString<8> s0('a');

    s0 << 'b' << "c" << "d" << '\n';
    ASSERT_EQ(s0, "abcd\n");
}

TEST(mediautils_fixedstring_tests, examples) {
    FixedString30 s1(std::string("a"));
    s1 << "bc" << 'd' << '\n';
    s1 += "hello";

    ASSERT_EQ(s1, "abcd\nhello");

    FixedString30 s2;
    for (const auto &c : s1.asStringView()) {
        s2.append(c);
    };
    ASSERT_EQ(s1, s2);

    FixedString30 s3(std::move(s1));
}

// Ensure type alias works fine as well.
using FixedString1024 = FixedString<1024>;

TEST(mediautils_fixedstring_tests, copy) {
    FixedString1024 s0("abc");
    FixedString62 s1(s0);

    ASSERT_EQ(3U, s1.size());
    ASSERT_EQ(0, strcmp(s1.c_str(), "abc"));
    ASSERT_EQ(s0, s1);

    FixedString<1024> s2(s1);
    ASSERT_EQ(3U, s2.size());
    ASSERT_EQ(0, strcmp(s2.c_str(), "abc"));
    ASSERT_EQ(s2, "abc");
    ASSERT_NE(s2, "def");
    ASSERT_EQ(s2, std::string("abc"));
    ASSERT_NE(s2, std::string("def"));
    ASSERT_EQ(s1, s2);
    ASSERT_EQ(s0, s2);
    ASSERT_EQ(s2, FixedString62(FixedString1024("abc")));
}
