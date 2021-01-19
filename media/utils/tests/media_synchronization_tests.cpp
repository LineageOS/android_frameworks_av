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

#define LOG_TAG "media_synchronization_tests"

#include <mediautils/Synchronization.h>

#include <gtest/gtest.h>
#include <utils/Log.h>

using namespace android;
using namespace android::mediautils;

// Simple Test Class
template <typename T>
class MyObject : public RefBase {
    T value_;
  public:
    MyObject(const T& value) : value_(value) {}
    MyObject(const MyObject<T>& mo) : value_(mo.get()) {}
    T get() const { return value_; }
    void set(const T& value) { value_ = value; }
};

TEST(media_synchronization_tests, atomic_wp) {
  sp<MyObject<int>> refobj = new MyObject<int>(20);
  atomic_wp<MyObject<int>> wpobj = refobj;

  // we can promote.
  ASSERT_EQ(20, wpobj.load().promote()->get());

  // same underlying object for sp and atomic_wp.
  ASSERT_EQ(refobj.get(), wpobj.load().promote().get());

  // behavior is consistent with same underlying object.
  wpobj.load().promote()->set(10);
  ASSERT_EQ(10, refobj->get());
  refobj->set(5);
  ASSERT_EQ(5, wpobj.load().promote()->get());

  // we can clear our weak ptr.
  wpobj = nullptr;
  ASSERT_EQ(nullptr, wpobj.load().promote());

  // didn't affect our original obj.
  ASSERT_NE(nullptr, refobj.get());
}

TEST(media_synchronization_tests, atomic_sp) {
  sp<MyObject<int>> refobj = new MyObject<int>(20);
  atomic_sp<MyObject<int>> spobj = refobj;

  // same underlying object for sp and atomic_sp.
  ASSERT_EQ(refobj.get(), spobj.load().get());

  // behavior is consistent with same underlying object.
  ASSERT_EQ(20, spobj.load()->get());
  spobj.load()->set(10);
  ASSERT_EQ(10, refobj->get());
  refobj->set(5);
  ASSERT_EQ(5, spobj.load()->get());

  // we can clear spobj.
  spobj = nullptr;
  ASSERT_EQ(nullptr, spobj.load().get());

  // didn't affect our original obj.
  ASSERT_NE(nullptr, refobj.get());
}
