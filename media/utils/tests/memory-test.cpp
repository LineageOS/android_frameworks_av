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

#include <gtest/gtest.h>
#include <mediautils/memory.h>

namespace android {
namespace {

TEST(UniqueMallocedPtr, Void) {
    unique_malloced_ptr<void> p(std::malloc(10));
}

TEST(UniqueMallocedPtr, Char) {
    unique_malloced_ptr<char> p(reinterpret_cast<char*>(std::malloc(10)));
}

TEST(UniqueMallocedPtr, Null) {
    unique_malloced_ptr<char> p(nullptr);
}

TEST(UniqueMallocedPtr, Default) {
    unique_malloced_ptr<char> p;
}

}  // namespace
}  // namespace android
