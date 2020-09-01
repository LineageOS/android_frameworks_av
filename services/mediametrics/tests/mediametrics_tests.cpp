/*
 * Copyright (C) 2019 The Android Open Source Project
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

#define LOG_TAG "mediametrics_tests"
#include <utils/Log.h>

#include "MediaMetricsService.h"

#include <stdio.h>
#include <unordered_set>

#include <gtest/gtest.h>
#include <media/MediaMetricsItem.h>
#include <system/audio.h>

#include "AudioTypes.h"
#include "StringUtils.h"

using namespace android;

static size_t countNewlines(const char *s) {
    size_t count = 0;
    while ((s = strchr(s, '\n')) != nullptr) {
        ++s;
        ++count;
    }
    return count;
}

template <typename M>
ssize_t countDuplicates(const M& map) {
    std::unordered_set<typename M::mapped_type> s;
    for (const auto &m : map) {
        s.emplace(m.second);
    }
    return map.size() - s.size();
}

TEST(mediametrics_tests, startsWith) {
  std::string s("test");
  ASSERT_EQ(true, android::mediametrics::startsWith(s, "te"));
  ASSERT_EQ(true, android::mediametrics::startsWith(s, std::string("tes")));
  ASSERT_EQ(false, android::mediametrics::startsWith(s, "ts"));
  ASSERT_EQ(false, android::mediametrics::startsWith(s, std::string("est")));
}

TEST(mediametrics_tests, defer) {
  bool check = false;
  {
      android::mediametrics::Defer defer([&] { check = true; });
      ASSERT_EQ(false, check);
  }
  ASSERT_EQ(true, check);
}

TEST(mediametrics_tests, shared_ptr_wrap) {
  // Test shared pointer wrap with simple access
  android::mediametrics::SharedPtrWrap<std::string> s("123");
  ASSERT_EQ('1', s->at(0));
  ASSERT_EQ('2', s->at(1));
  s->push_back('4');
  ASSERT_EQ('4', s->at(3));

  const android::mediametrics::SharedPtrWrap<std::string> s2("345");
  ASSERT_EQ('3', s2->operator[](0));  // s2[0] == '3'
  // we allow modification through a const shared pointer wrap
  // for compatibility with shared_ptr.
  s2->push_back('6');
  ASSERT_EQ('6', s2->operator[](3));  // s2[3] == '6'

  android::mediametrics::SharedPtrWrap<std::string> s3("");
  s3.set(std::make_shared<std::string>("abc"));
  ASSERT_EQ('b', s3->operator[](1)); // s2[1] = 'b';

  // Use Thunk to check whether the destructor was called prematurely
  // when setting the shared ptr wrap in the middle of a method.

  class Thunk {
    std::function<void(int)> mF;
    const int mFinal;

    public:
      explicit Thunk(decltype(mF) f, int final) : mF(std::move(f)), mFinal(final) {}
      ~Thunk() { mF(mFinal); }
      void thunk(int value) { mF(value); }
  };

  int counter = 0;
  android::mediametrics::SharedPtrWrap<Thunk> s4(
    [&](int value) {
      s4.set(std::make_shared<Thunk>([](int){}, 0)); // recursively set s4 while in s4.
      ++counter;
      ASSERT_EQ(value, counter);  // on thunk() value is 1, on destructor this is 2.
    }, 2);

  // This will fail if the shared ptr wrap doesn't hold a ref count during method access.
  s4->thunk(1);
}

TEST(mediametrics_tests, lock_wrap) {
  // Test lock wrap with simple access
  android::mediametrics::LockWrap<std::string> s("123");
  ASSERT_EQ('1', s->at(0));
  ASSERT_EQ('2', s->at(1));
  s->push_back('4');
  ASSERT_EQ('4', s->at(3));

  const android::mediametrics::LockWrap<std::string> s2("345");
  ASSERT_EQ('3', s2->operator[](0));  // s2[0] == '3'
  // note: we can't modify s2 due to const, s2->push_back('6');

  android::mediametrics::LockWrap<std::string> s3("");
  s3->operator=("abc");
  ASSERT_EQ('b', s3->operator[](1)); // s2[1] = 'b';

  // Check that we can recursively hold lock.
  android::mediametrics::LockWrap<std::vector<int>> v{std::initializer_list<int>{1, 2}};
  v->push_back(3);
  v->push_back(4);
  ASSERT_EQ(1, v->operator[](0));
  ASSERT_EQ(2, v->operator[](1));
  ASSERT_EQ(3, v->operator[](2));
  ASSERT_EQ(4, v->operator[](3));
  // The end of the full expression here requires recursive depth of 4.
  ASSERT_EQ(10, v->operator[](0) + v->operator[](1) + v->operator[](2) + v->operator[](3));

  // Mikhail's note: a non-recursive lock implementation could be used if one obtains
  // the LockedPointer helper object like this and directly hold the lock through RAII,
  // though it is trickier in use.
  //
  // We include an example here for completeness.
  {
    auto l = v.operator->();
    ASSERT_EQ(10, l->operator[](0) + l->operator[](1) + l->operator[](2) + l->operator[](3));
  }

  // Use Thunk to check whether we have the lock when calling a method through LockWrap.

  class Thunk {
    std::function<void()> mF;

    public:
      explicit Thunk(decltype(mF) f) : mF(std::move(f)) {}
      void thunk() { mF(); }
  };

  android::mediametrics::LockWrap<Thunk> s4([&]{
    ASSERT_EQ((size_t)1, s4.getRecursionDepth()); // we must be locked when thunk() is called.
  });

  ASSERT_EQ((size_t)0, s4.getRecursionDepth());
  // This will fail if we are not locked during method access.
  s4->thunk();
  ASSERT_EQ((size_t)0, s4.getRecursionDepth());
}

TEST(mediametrics_tests, lock_wrap_multithread) {
  class Accumulator {
    int32_t value_ = 0;
  public:
    void add(int32_t incr) {
      const int32_t temp = value_;
      sleep(0);  // yield
      value_ = temp + incr;
    }
    int32_t get() { return value_; }
  };

  android::mediametrics::LockWrap<Accumulator> a{}; // locked accumulator succeeds
  // auto a = std::make_shared<Accumulator>(); // this fails, only 50% adds atomic.

  constexpr size_t THREADS = 100;
  constexpr size_t ITERATIONS = 10;
  constexpr int32_t INCREMENT = 1;

  std::vector<std::future<void>> threads(THREADS);
  for (size_t i = 0; i < THREADS; ++i) {
    threads.push_back(std::async(std::launch::async, [&] {
        for (size_t j = 0; j < ITERATIONS; ++j) {
          a->add(INCREMENT);
        }
      }));
  }
  threads.clear();

  // If the add operations are not atomic, value will be smaller than expected.
  ASSERT_EQ(INCREMENT * THREADS * ITERATIONS, (size_t)a->get());
}

TEST(mediametrics_tests, instantiate) {
  sp mediaMetrics = new MediaMetricsService();
  status_t status;

  // random keys ignored when empty
  std::unique_ptr<mediametrics::Item> random_key(mediametrics::Item::create("random_key"));
  status = mediaMetrics->submit(random_key.get());
  ASSERT_EQ(PERMISSION_DENIED, status);

  // random keys ignored with data
  random_key->setInt32("foo", 10);
  status = mediaMetrics->submit(random_key.get());
  ASSERT_EQ(PERMISSION_DENIED, status);

  // known keys ignored if empty
  std::unique_ptr<mediametrics::Item> audiotrack_key(mediametrics::Item::create("audiotrack"));
  status = mediaMetrics->submit(audiotrack_key.get());
  ASSERT_EQ(BAD_VALUE, status);

  // known keys not ignored if not empty
  audiotrack_key->addInt32("foo", 10);
  status = mediaMetrics->submit(audiotrack_key.get());
  ASSERT_EQ(NO_ERROR, status);


  /*
  // fluent style that goes directly to mediametrics
  ASSERT_EQ(true, mediametrics::Item("audiorecord")
                     .setInt32("value", 2)
                     .addInt32("bar", 1)
                     .addInt32("value", 3)
                     .selfrecord());
  */

  mediaMetrics->dump(fileno(stdout), {} /* args */);
}

TEST(mediametrics_tests, package_installer_check) {
  ASSERT_EQ(false, MediaMetricsService::useUidForPackage(
      "abcd", "installer"));  // ok, package name has no dot.
  ASSERT_EQ(false, MediaMetricsService::useUidForPackage(
      "android.com", "installer"));  // ok, package name starts with android

  ASSERT_EQ(false, MediaMetricsService::useUidForPackage(
      "abc.def", "com.android.foo"));  // ok, installer name starts with com.android
  ASSERT_EQ(false, MediaMetricsService::useUidForPackage(
      "123.456", "com.google.bar"));  // ok, installer name starts with com.google
  ASSERT_EQ(false, MediaMetricsService::useUidForPackage(
      "r2.d2", "preload"));  // ok, installer name is preload

  ASSERT_EQ(true, MediaMetricsService::useUidForPackage(
      "abc.def", "installer"));  // unknown installer
  ASSERT_EQ(true, MediaMetricsService::useUidForPackage(
      "123.456", "installer")); // unknown installer
  ASSERT_EQ(true, MediaMetricsService::useUidForPackage(
      "r2.d2", "preload23"));  // unknown installer

  ASSERT_EQ(true, MediaMetricsService::useUidForPackage(
      "com.android.foo", "abc.def"));  // unknown installer
  ASSERT_EQ(true, MediaMetricsService::useUidForPackage(
      "com.google.bar", "123.456"));  // unknown installer
}

TEST(mediametrics_tests, item_manipulation) {
  mediametrics::Item item("audiorecord");

  item.setInt32("value", 2).addInt32("bar", 3).addInt32("value", 4);

  int32_t i32;
  ASSERT_TRUE(item.getInt32("value", &i32));
  ASSERT_EQ(6, i32);

  ASSERT_TRUE(item.getInt32("bar", &i32));
  ASSERT_EQ(3, i32);

  item.setInt64("big", INT64_MAX).setInt64("smaller", INT64_MAX - 1).addInt64("smaller", -2);

  int64_t i64;
  ASSERT_TRUE(item.getInt64("big", &i64));
  ASSERT_EQ(INT64_MAX, i64);

  ASSERT_TRUE(item.getInt64("smaller", &i64));
  ASSERT_EQ(INT64_MAX - 3, i64);

  item.setDouble("precise", 10.5).setDouble("small", 0.125).addDouble("precise", 0.25);

  double d;
  ASSERT_TRUE(item.getDouble("precise", &d));
  ASSERT_EQ(10.75, d);

  ASSERT_TRUE(item.getDouble("small", &d));
  ASSERT_EQ(0.125, d);

  char *s;
  item.setCString("name", "Frank").setCString("mother", "June").setCString("mother", "July");
  ASSERT_TRUE(item.getCString("name", &s));
  ASSERT_EQ(0, strcmp(s, "Frank"));
  free(s);

  ASSERT_TRUE(item.getCString("mother", &s));
  ASSERT_EQ(0, strcmp(s, "July"));  // "July" overwrites "June"
  free(s);

  item.setRate("burgersPerHour", 5, 2);
  int64_t b, h;
  ASSERT_TRUE(item.getRate("burgersPerHour", &b, &h, &d));
  ASSERT_EQ(5, b);
  ASSERT_EQ(2, h);
  ASSERT_EQ(2.5, d);

  item.addRate("burgersPerHour", 4, 2);
  ASSERT_TRUE(item.getRate("burgersPerHour", &b, &h, &d));
  ASSERT_EQ(9, b);
  ASSERT_EQ(4, h);
  ASSERT_EQ(2.25, d);

  printf("item: %s\n", item.toString().c_str());
  fflush(stdout);

  sp mediaMetrics = new MediaMetricsService();
  status_t status = mediaMetrics->submit(&item);
  ASSERT_EQ(NO_ERROR, status);
  mediaMetrics->dump(fileno(stdout), {} /* args */);
}

TEST(mediametrics_tests, superbig_item) {
  mediametrics::Item item("TheBigOne");
  constexpr size_t count = 10000;

  for (size_t i = 0; i < count; ++i) {
    item.setInt32(std::to_string(i).c_str(), i);
  }
  for (size_t i = 0; i < count; ++i) {
    int32_t i32;
    ASSERT_TRUE(item.getInt32(std::to_string(i).c_str(), &i32));
    ASSERT_EQ((int32_t)i, i32);
  }
}

TEST(mediametrics_tests, superbig_item_removal) {
  mediametrics::Item item("TheOddBigOne");
  constexpr size_t count = 10000;

  for (size_t i = 0; i < count; ++i) {
    item.setInt32(std::to_string(i).c_str(), i);
  }
  for (size_t i = 0; i < count; i += 2) {
    item.filter(std::to_string(i).c_str()); // filter out all the evens.
  }
  for (size_t i = 0; i < count; ++i) {
    int32_t i32;
    if (i & 1) { // check to see that only the odds are left.
        ASSERT_TRUE(item.getInt32(std::to_string(i).c_str(), &i32));
        ASSERT_EQ((int32_t)i, i32);
    } else {
        ASSERT_FALSE(item.getInt32(std::to_string(i).c_str(), &i32));
    }
  }
}

TEST(mediametrics_tests, superbig_item_removal2) {
  mediametrics::Item item("TheOne");
  constexpr size_t count = 10000;

  for (size_t i = 0; i < count; ++i) {
    item.setInt32(std::to_string(i).c_str(), i);
  }
  static const char *attrs[] = { "1", };
  item.filterNot(1, attrs);

  for (size_t i = 0; i < count; ++i) {
    int32_t i32;
    if (i == 1) { // check to see that there is only one
        ASSERT_TRUE(item.getInt32(std::to_string(i).c_str(), &i32));
        ASSERT_EQ((int32_t)i, i32);
    } else {
        ASSERT_FALSE(item.getInt32(std::to_string(i).c_str(), &i32));
    }
  }
}

TEST(mediametrics_tests, item_transmutation) {
  mediametrics::Item item("Alchemist's Stone");

  item.setInt64("convert", 123);
  int64_t i64;
  ASSERT_TRUE(item.getInt64("convert", &i64));
  ASSERT_EQ(123, i64);

  item.addInt32("convert", 2);     // changes type of 'convert' from i64 to i32 (and re-init).
  ASSERT_FALSE(item.getInt64("convert", &i64));  // should be false, no value in i64.

  int32_t i32;
  ASSERT_TRUE(item.getInt32("convert", &i32));   // check it is i32 and 2 (123 is discarded).
  ASSERT_EQ(2, i32);
}

TEST(mediametrics_tests, item_binderization) {
  mediametrics::Item item;
  item.setInt32("i32", 1)
      .setInt64("i64", 2)
      .setDouble("double", 3.1)
      .setCString("string", "abc")
      .setRate("rate", 11, 12);

  Parcel p;
  item.writeToParcel(&p);

  p.setDataPosition(0); // rewind for reading
  mediametrics::Item item2;
  item2.readFromParcel(p);

  ASSERT_EQ(item, item2);
}

TEST(mediametrics_tests, item_byteserialization) {
  mediametrics::Item item;
  item.setInt32("i32", 1)
      .setInt64("i64", 2)
      .setDouble("double", 3.1)
      .setCString("string", "abc")
      .setRate("rate", 11, 12);

  char *data;
  size_t length;
  ASSERT_EQ(0, item.writeToByteString(&data, &length));
  ASSERT_GT(length, (size_t)0);

  mediametrics::Item item2;
  item2.readFromByteString(data, length);

  printf("item: %s\n", item.toString().c_str());
  printf("item2: %s\n", item2.toString().c_str());
  ASSERT_EQ(item, item2);

  free(data);
}

TEST(mediametrics_tests, item_iteration) {
  mediametrics::Item item;
  item.setInt32("i32", 1)
      .setInt64("i64", 2)
      .setDouble("double", 3.125)
      .setCString("string", "abc")
      .setRate("rate", 11, 12);

  int mask = 0;
  for (auto &prop : item) {
      const char *name = prop.getName();
      if (!strcmp(name, "i32")) {
          int32_t i32;
          ASSERT_TRUE(prop.get(&i32));
          ASSERT_EQ(1, i32);
          ASSERT_EQ(1, std::get<int32_t>(prop.get()));
          mask |= 1;
      } else if (!strcmp(name, "i64")) {
          int64_t i64;
          ASSERT_TRUE(prop.get(&i64));
          ASSERT_EQ(2, i64);
          ASSERT_EQ(2, std::get<int64_t>(prop.get()));
          mask |= 2;
      } else if (!strcmp(name, "double")) {
          double d;
          ASSERT_TRUE(prop.get(&d));
          ASSERT_EQ(3.125, d);
          ASSERT_EQ(3.125, std::get<double>(prop.get()));
          mask |= 4;
      } else if (!strcmp(name, "string")) {
          std::string s;
          ASSERT_TRUE(prop.get(&s));
          ASSERT_EQ("abc", s);
          ASSERT_EQ(s, std::get<std::string>(prop.get()));
          mask |= 8;
      } else if (!strcmp(name, "rate")) {
          std::pair<int64_t, int64_t> r;
          ASSERT_TRUE(prop.get(&r));
          ASSERT_EQ(11, r.first);
          ASSERT_EQ(12, r.second);
          ASSERT_EQ(r, std::get<decltype(r)>(prop.get()));
          mask |= 16;
      } else {
          FAIL();
      }
  }
  ASSERT_EQ(31, mask);
}

TEST(mediametrics_tests, item_expansion) {
  mediametrics::LogItem<1> item("I");
  item.set("i32", (int32_t)1)
      .set("i64", (int64_t)2)
      .set("double", (double)3.125)
      .set("string", "abcdefghijklmnopqrstuvwxyz")
      .set("rate", std::pair<int64_t, int64_t>(11, 12));
  ASSERT_TRUE(item.updateHeader());

  mediametrics::Item item2;
  item2.readFromByteString(item.getBuffer(), item.getLength());
  ASSERT_EQ((pid_t)-1, item2.getPid());
  ASSERT_EQ((uid_t)-1, item2.getUid());
  int mask = 0;
  for (auto &prop : item2) {
      const char *name = prop.getName();
      if (!strcmp(name, "i32")) {
          int32_t i32;
          ASSERT_TRUE(prop.get(&i32));
          ASSERT_EQ(1, i32);
          mask |= 1;
      } else if (!strcmp(name, "i64")) {
          int64_t i64;
          ASSERT_TRUE(prop.get(&i64));
          ASSERT_EQ(2, i64);
          mask |= 2;
      } else if (!strcmp(name, "double")) {
          double d;
          ASSERT_TRUE(prop.get(&d));
          ASSERT_EQ(3.125, d);
          mask |= 4;
      } else if (!strcmp(name, "string")) {
          std::string s;
          ASSERT_TRUE(prop.get(&s));
          ASSERT_EQ("abcdefghijklmnopqrstuvwxyz", s);
          mask |= 8;
      } else if (!strcmp(name, "rate")) {
          std::pair<int64_t, int64_t> r;
          ASSERT_TRUE(prop.get(&r));
          ASSERT_EQ(11, r.first);
          ASSERT_EQ(12, r.second);
          mask |= 16;
      } else {
          FAIL();
      }
  }
  ASSERT_EQ(31, mask);
}

TEST(mediametrics_tests, item_expansion2) {
  mediametrics::LogItem<1> item("Bigly");
  item.setPid(123)
      .setUid(456);
  constexpr size_t count = 10000;

  for (size_t i = 0; i < count; ++i) {
    // printf("recording %zu, %p, len:%zu of %zu  remaining:%zu \n", i, item.getBuffer(), item.getLength(), item.getCapacity(), item.getRemaining());
    item.set(std::to_string(i).c_str(), (int32_t)i);
  }
  ASSERT_TRUE(item.updateHeader());

  mediametrics::Item item2;
  printf("begin buffer:%p  length:%zu\n", item.getBuffer(), item.getLength());
  fflush(stdout);
  item2.readFromByteString(item.getBuffer(), item.getLength());

  ASSERT_EQ((pid_t)123, item2.getPid());
  ASSERT_EQ((uid_t)456, item2.getUid());
  for (size_t i = 0; i < count; ++i) {
    int32_t i32;
    ASSERT_TRUE(item2.getInt32(std::to_string(i).c_str(), &i32));
    ASSERT_EQ((int32_t)i, i32);
  }
}

TEST(mediametrics_tests, time_machine_storage) {
  auto item = std::make_shared<mediametrics::Item>("Key");
  (*item).set("i32", (int32_t)1)
      .set("i64", (int64_t)2)
      .set("double", (double)3.125)
      .set("string", "abcdefghijklmnopqrstuvwxyz")
      .set("rate", std::pair<int64_t, int64_t>(11, 12));

  // Let's put the item in
  android::mediametrics::TimeMachine timeMachine;
  ASSERT_EQ(NO_ERROR, timeMachine.put(item, true));

  // Can we read the values?
  int32_t i32;
  ASSERT_EQ(NO_ERROR, timeMachine.get("Key", "i32", &i32, -1));
  ASSERT_EQ(1, i32);

  int64_t i64;
  ASSERT_EQ(NO_ERROR, timeMachine.get("Key", "i64", &i64, -1));
  ASSERT_EQ(2, i64);

  double d;
  ASSERT_EQ(NO_ERROR, timeMachine.get("Key", "double", &d, -1));
  ASSERT_EQ(3.125, d);

  std::string s;
  ASSERT_EQ(NO_ERROR, timeMachine.get("Key", "string", &s, -1));
  ASSERT_EQ("abcdefghijklmnopqrstuvwxyz", s);

  // Using fully qualified name?
  i32 = 0;
  ASSERT_EQ(NO_ERROR, timeMachine.get("Key.i32", &i32, -1));
  ASSERT_EQ(1, i32);

  i64 = 0;
  ASSERT_EQ(NO_ERROR, timeMachine.get("Key.i64", &i64, -1));
  ASSERT_EQ(2, i64);

  d = 0.;
  ASSERT_EQ(NO_ERROR, timeMachine.get("Key.double", &d, -1));
  ASSERT_EQ(3.125, d);

  s.clear();
  ASSERT_EQ(NO_ERROR, timeMachine.get("Key.string", &s, -1));
  ASSERT_EQ("abcdefghijklmnopqrstuvwxyz", s);
}

TEST(mediametrics_tests, time_machine_remote_key) {
  auto item = std::make_shared<mediametrics::Item>("Key1");
  (*item).set("one", (int32_t)1)
         .set("two", (int32_t)2);

  android::mediametrics::TimeMachine timeMachine;
  ASSERT_EQ(NO_ERROR, timeMachine.put(item, true));

  auto item2 = std::make_shared<mediametrics::Item>("Key2");
  (*item2).set("three", (int32_t)3)
         .set("[Key1]four", (int32_t)4)   // affects Key1
         .set("[Key1]five", (int32_t)5);  // affects key1

  ASSERT_EQ(NO_ERROR, timeMachine.put(item2, true));

  auto item3 = std::make_shared<mediametrics::Item>("Key2");
  (*item3).set("six", (int32_t)6)
         .set("[Key1]seven", (int32_t)7);   // affects Key1

  ASSERT_EQ(NO_ERROR, timeMachine.put(item3, false)); // remote keys not allowed.

  // Can we read the values?
  int32_t i32;
  ASSERT_EQ(NO_ERROR, timeMachine.get("Key1.one", &i32, -1));
  ASSERT_EQ(1, i32);

  ASSERT_EQ(NO_ERROR, timeMachine.get("Key1.two", &i32, -1));
  ASSERT_EQ(2, i32);

  ASSERT_EQ(BAD_VALUE, timeMachine.get("Key1.three", &i32, -1));

  ASSERT_EQ(NO_ERROR, timeMachine.get("Key2.three", &i32, -1));
  ASSERT_EQ(3, i32);

  ASSERT_EQ(NO_ERROR, timeMachine.get("Key1.four", &i32, -1));
  ASSERT_EQ(4, i32);

  ASSERT_EQ(BAD_VALUE, timeMachine.get("Key2.four", &i32, -1));

  ASSERT_EQ(NO_ERROR, timeMachine.get("Key1.five", &i32, -1));
  ASSERT_EQ(5, i32);

  ASSERT_EQ(BAD_VALUE, timeMachine.get("Key2.five", &i32, -1));

  ASSERT_EQ(NO_ERROR, timeMachine.get("Key2.six", &i32, -1));
  ASSERT_EQ(6, i32);

  ASSERT_EQ(BAD_VALUE, timeMachine.get("Key2.seven", &i32, -1));
}

TEST(mediametrics_tests, time_machine_gc) {
  auto item = std::make_shared<mediametrics::Item>("Key1");
  (*item).set("one", (int32_t)1)
         .set("two", (int32_t)2)
         .setTimestamp(10);

  android::mediametrics::TimeMachine timeMachine(1, 2); // keep at most 2 keys.

  ASSERT_EQ((size_t)0, timeMachine.size());

  ASSERT_EQ(NO_ERROR, timeMachine.put(item, true));

  ASSERT_EQ((size_t)1, timeMachine.size());

  auto item2 = std::make_shared<mediametrics::Item>("Key2");
  (*item2).set("three", (int32_t)3)
         .set("[Key1]three", (int32_t)3)
         .setTimestamp(11);

  ASSERT_EQ(NO_ERROR, timeMachine.put(item2, true));
  ASSERT_EQ((size_t)2, timeMachine.size());

  //printf("Before\n%s\n\n", timeMachine.dump().c_str());

  auto item3 = std::make_shared<mediametrics::Item>("Key3");
  (*item3).set("six", (int32_t)6)
          .set("[Key1]four", (int32_t)4)   // affects Key1
          .set("[Key1]five", (int32_t)5)   // affects key1
          .setTimestamp(12);

  ASSERT_EQ(NO_ERROR, timeMachine.put(item3, true));

  ASSERT_EQ((size_t)2, timeMachine.size());

  // Can we read the values?
  int32_t i32;
  ASSERT_EQ(BAD_VALUE, timeMachine.get("Key1.one", &i32, -1));
  ASSERT_EQ(BAD_VALUE, timeMachine.get("Key1.two", &i32, -1));
  ASSERT_EQ(BAD_VALUE, timeMachine.get("Key1.three", &i32, -1));
  ASSERT_EQ(BAD_VALUE, timeMachine.get("Key1.four", &i32, -1));
  ASSERT_EQ(BAD_VALUE, timeMachine.get("Key1.five", &i32, -1));

  ASSERT_EQ(NO_ERROR, timeMachine.get("Key2.three", &i32, -1));
  ASSERT_EQ(3, i32);

  ASSERT_EQ(NO_ERROR, timeMachine.get("Key3.six", &i32, -1));
  ASSERT_EQ(6, i32);

  printf("After\n%s\n", timeMachine.dump().first.c_str());
}

TEST(mediametrics_tests, transaction_log_gc) {
  auto item = std::make_shared<mediametrics::Item>("Key1");
  (*item).set("one", (int32_t)1)
         .set("two", (int32_t)2)
         .setTimestamp(10);

  android::mediametrics::TransactionLog transactionLog(1, 2); // keep at most 2 items
  ASSERT_EQ((size_t)0, transactionLog.size());

  ASSERT_EQ(NO_ERROR, transactionLog.put(item));
  ASSERT_EQ((size_t)1, transactionLog.size());

  auto item2 = std::make_shared<mediametrics::Item>("Key2");
  (*item2).set("three", (int32_t)3)
         .set("[Key1]three", (int32_t)3)
         .setTimestamp(11);

  ASSERT_EQ(NO_ERROR, transactionLog.put(item2));
  ASSERT_EQ((size_t)2, transactionLog.size());

  auto item3 = std::make_shared<mediametrics::Item>("Key3");
  (*item3).set("six", (int32_t)6)
          .set("[Key1]four", (int32_t)4)   // affects Key1
          .set("[Key1]five", (int32_t)5)   // affects key1
          .setTimestamp(12);

  ASSERT_EQ(NO_ERROR, transactionLog.put(item3));
  ASSERT_EQ((size_t)2, transactionLog.size());
}

TEST(mediametrics_tests, analytics_actions) {
  mediametrics::AnalyticsActions analyticsActions;
  bool action1 = false;
  bool action2 = false;
  bool action3 = false;
  bool action4 = false;

  // check to see whether various actions have been matched.
  analyticsActions.addAction(
      "audio.flinger.event",
      std::string("AudioFlinger"),
      std::make_shared<mediametrics::AnalyticsActions::Function>(
          [&](const std::shared_ptr<const android::mediametrics::Item> &) {
            action1 = true;
          }));

  analyticsActions.addAction(
      "audio.*.event",
      std::string("AudioFlinger"),
      std::make_shared<mediametrics::AnalyticsActions::Function>(
          [&](const std::shared_ptr<const android::mediametrics::Item> &) {
            action2 = true;
          }));

  analyticsActions.addAction("audio.fl*n*g*r.event",
      std::string("AudioFlinger"),
      std::make_shared<mediametrics::AnalyticsActions::Function>(
          [&](const std::shared_ptr<const android::mediametrics::Item> &) {
            action3 = true;
          }));

  analyticsActions.addAction("audio.fl*gn*r.event",
      std::string("AudioFlinger"),
      std::make_shared<mediametrics::AnalyticsActions::Function>(
          [&](const std::shared_ptr<const android::mediametrics::Item> &) {
            action4 = true;
          }));

  // make a test item
  auto item = std::make_shared<mediametrics::Item>("audio.flinger");
  (*item).set("event", "AudioFlinger");

  // get the actions and execute them
  auto actions = analyticsActions.getActionsForItem(item);
  for (const auto& action : actions) {
    action->operator()(item);
  }

  // The following should match.
  ASSERT_EQ(true, action1);
  ASSERT_EQ(true, action2);
  ASSERT_EQ(true, action3);
  ASSERT_EQ(false, action4); // audio.fl*gn*r != audio.flinger
}

TEST(mediametrics_tests, audio_analytics_permission) {
  auto item = std::make_shared<mediametrics::Item>("audio.1");
  (*item).set("one", (int32_t)1)
         .set("two", (int32_t)2)
         .setTimestamp(10);

  auto item2 = std::make_shared<mediametrics::Item>("audio.1");
  (*item2).set("three", (int32_t)3)
         .setTimestamp(11);

  auto item3 = std::make_shared<mediametrics::Item>("audio.2");
  (*item3).set("four", (int32_t)4)
          .setTimestamp(12);

  android::mediametrics::AudioAnalytics audioAnalytics;

  // untrusted entities cannot create a new key.
  ASSERT_EQ(PERMISSION_DENIED, audioAnalytics.submit(item, false /* isTrusted */));
  ASSERT_EQ(PERMISSION_DENIED, audioAnalytics.submit(item2, false /* isTrusted */));

  // TODO: Verify contents of AudioAnalytics.
  // Currently there is no getter API in AudioAnalytics besides dump.
  ASSERT_EQ(11, audioAnalytics.dump(1000).second /* lines */);

  ASSERT_EQ(NO_ERROR, audioAnalytics.submit(item, true /* isTrusted */));
  // untrusted entities can add to an existing key
  ASSERT_EQ(NO_ERROR, audioAnalytics.submit(item2, false /* isTrusted */));

  // Check that we have some info in the dump.
  ASSERT_LT(9, audioAnalytics.dump(1000).second /* lines */);
}

TEST(mediametrics_tests, audio_analytics_permission2) {
  constexpr int32_t transactionUid = 1010; // arbitrary
  auto item = std::make_shared<mediametrics::Item>("audio.1");
  (*item).set("one", (int32_t)1)
         .set("two", (int32_t)2)
         .set(AMEDIAMETRICS_PROP_ALLOWUID, transactionUid)
         .setTimestamp(10);

  // item2 submitted untrusted
  auto item2 = std::make_shared<mediametrics::Item>("audio.1");
  (*item2).set("three", (int32_t)3)
         .setUid(transactionUid)
         .setTimestamp(11);

  auto item3 = std::make_shared<mediametrics::Item>("audio.2");
  (*item3).set("four", (int32_t)4)
          .setTimestamp(12);

  android::mediametrics::AudioAnalytics audioAnalytics;

  // untrusted entities cannot create a new key.
  ASSERT_EQ(PERMISSION_DENIED, audioAnalytics.submit(item, false /* isTrusted */));
  ASSERT_EQ(PERMISSION_DENIED, audioAnalytics.submit(item2, false /* isTrusted */));

  // TODO: Verify contents of AudioAnalytics.
  // Currently there is no getter API in AudioAnalytics besides dump.
  ASSERT_EQ(11, audioAnalytics.dump(1000).second /* lines */);

  ASSERT_EQ(NO_ERROR, audioAnalytics.submit(item, true /* isTrusted */));
  // untrusted entities can add to an existing key
  ASSERT_EQ(NO_ERROR, audioAnalytics.submit(item2, false /* isTrusted */));

  // Check that we have some info in the dump.
  ASSERT_LT(9, audioAnalytics.dump(1000).second /* lines */);
}

TEST(mediametrics_tests, audio_analytics_dump) {
  auto item = std::make_shared<mediametrics::Item>("audio.1");
  (*item).set("one", (int32_t)1)
         .set("two", (int32_t)2)
         .setTimestamp(10);

  auto item2 = std::make_shared<mediametrics::Item>("audio.1");
  (*item2).set("three", (int32_t)3)
         .setTimestamp(11);

  auto item3 = std::make_shared<mediametrics::Item>("audio.2");
  (*item3).set("four", (int32_t)4)
          .setTimestamp(12);

  android::mediametrics::AudioAnalytics audioAnalytics;

  ASSERT_EQ(NO_ERROR, audioAnalytics.submit(item, true /* isTrusted */));
  // untrusted entities can add to an existing key
  ASSERT_EQ(NO_ERROR, audioAnalytics.submit(item2, false /* isTrusted */));
  ASSERT_EQ(NO_ERROR, audioAnalytics.submit(item3, true /* isTrusted */));

  // find out how many lines we have.
  auto [string, lines] = audioAnalytics.dump(1000);
  ASSERT_EQ(lines, (int32_t) countNewlines(string.c_str()));

  printf("AudioAnalytics: %s", string.c_str());
  // ensure that dump operates over those lines.
  for (int32_t ll = 0; ll < lines; ++ll) {
      auto [s, l] = audioAnalytics.dump(ll);
      ASSERT_EQ(ll, l);
      ASSERT_EQ(ll, (int32_t) countNewlines(s.c_str()));
  }
}

TEST(mediametrics_tests, device_parsing) {
    auto devaddr = android::mediametrics::stringutils::getDeviceAddressPairs("(DEVICE, )");
    ASSERT_EQ((size_t)1, devaddr.size());
    ASSERT_EQ("DEVICE", devaddr[0].first);
    ASSERT_EQ("", devaddr[0].second);

    devaddr = android::mediametrics::stringutils::getDeviceAddressPairs(
            "(DEVICE1, A)|(D, ADDRB)");
    ASSERT_EQ((size_t)2, devaddr.size());
    ASSERT_EQ("DEVICE1", devaddr[0].first);
    ASSERT_EQ("A", devaddr[0].second);
    ASSERT_EQ("D", devaddr[1].first);
    ASSERT_EQ("ADDRB", devaddr[1].second);

    devaddr = android::mediametrics::stringutils::getDeviceAddressPairs(
            "(A,B)|(C,D)");
    ASSERT_EQ((size_t)2, devaddr.size());
    ASSERT_EQ("A", devaddr[0].first);
    ASSERT_EQ("B", devaddr[0].second);
    ASSERT_EQ("C", devaddr[1].first);
    ASSERT_EQ("D", devaddr[1].second);

    devaddr = android::mediametrics::stringutils::getDeviceAddressPairs(
            "  ( A1 , B )  | ( C , D2 )  ");
    ASSERT_EQ((size_t)2, devaddr.size());
    ASSERT_EQ("A1", devaddr[0].first);
    ASSERT_EQ("B", devaddr[0].second);
    ASSERT_EQ("C", devaddr[1].first);
    ASSERT_EQ("D2", devaddr[1].second);
}

TEST(mediametrics_tests, timed_action) {
    android::mediametrics::TimedAction timedAction;
    std::atomic_int value1 = 0;

    timedAction.postIn(std::chrono::seconds(0), [&value1] { ++value1; });
    timedAction.postIn(std::chrono::seconds(1000), [&value1] { ++value1; });
    usleep(100000);
    ASSERT_EQ(1, value1);
    ASSERT_EQ((size_t)1, timedAction.size());
}

// Ensure we don't introduce unexpected duplicates into our maps.
TEST(mediametrics_tests, audio_types_tables) {
    using namespace android::mediametrics::types;

    ASSERT_EQ(0, countDuplicates(getAudioCallerNameMap()));
    ASSERT_EQ(2, countDuplicates(getAudioDeviceInMap()));  // has dups
    ASSERT_EQ(1, countDuplicates(getAudioDeviceOutMap())); // has dups
    ASSERT_EQ(0, countDuplicates(getAudioThreadTypeMap()));
    ASSERT_EQ(0, countDuplicates(getAudioTrackTraitsMap()));
}

// Check our string validation (before logging to statsd).
// This variant checks the logged, possibly shortened string.
TEST(mediametrics_tests, audio_types_string) {
    using namespace android::mediametrics::types;

    ASSERT_EQ("java", (lookup<CALLER_NAME, std::string>)("java"));
    ASSERT_EQ("", (lookup<CALLER_NAME, std::string>)("random"));

    ASSERT_EQ("SPEECH", (lookup<CONTENT_TYPE, std::string>)("AUDIO_CONTENT_TYPE_SPEECH"));
    ASSERT_EQ("", (lookup<CONTENT_TYPE, std::string>)("random"));

    ASSERT_EQ("FLAC", (lookup<ENCODING, std::string>)("AUDIO_FORMAT_FLAC"));
    ASSERT_EQ("", (lookup<ENCODING, std::string>)("random"));

    ASSERT_EQ("USB_DEVICE", (lookup<INPUT_DEVICE, std::string>)("AUDIO_DEVICE_IN_USB_DEVICE"));
    ASSERT_EQ("BUILTIN_MIC|WIRED_HEADSET", (lookup<INPUT_DEVICE, std::string>)(
            "AUDIO_DEVICE_IN_BUILTIN_MIC|AUDIO_DEVICE_IN_WIRED_HEADSET"));
    ASSERT_EQ("", (lookup<INPUT_DEVICE, std::string>)("random"));

    ASSERT_EQ("RAW", (lookup<INPUT_FLAG, std::string>)("AUDIO_INPUT_FLAG_RAW"));
    ASSERT_EQ("HW_AV_SYNC|VOIP_TX", (lookup<INPUT_FLAG, std::string>)(
            "AUDIO_INPUT_FLAG_HW_AV_SYNC|AUDIO_INPUT_FLAG_VOIP_TX"));
    ASSERT_EQ("", (lookup<INPUT_FLAG, std::string>)("random"));

    ASSERT_EQ("BLUETOOTH_SCO_CARKIT",
            (lookup<OUTPUT_DEVICE, std::string>)("AUDIO_DEVICE_OUT_BLUETOOTH_SCO_CARKIT"));
    ASSERT_EQ("SPEAKER|HDMI", (lookup<OUTPUT_DEVICE, std::string>)(
            "AUDIO_DEVICE_OUT_SPEAKER|AUDIO_DEVICE_OUT_HDMI"));
    ASSERT_EQ("", (lookup<OUTPUT_DEVICE, std::string>)("random"));

    ASSERT_EQ("PRIMARY", (lookup<OUTPUT_FLAG, std::string>)("AUDIO_OUTPUT_FLAG_PRIMARY"));
    ASSERT_EQ("DEEP_BUFFER|NON_BLOCKING", (lookup<OUTPUT_FLAG, std::string>)(
            "AUDIO_OUTPUT_FLAG_DEEP_BUFFER|AUDIO_OUTPUT_FLAG_NON_BLOCKING"));
    ASSERT_EQ("", (lookup<OUTPUT_FLAG, std::string>)("random"));

    ASSERT_EQ("MIC", (lookup<SOURCE_TYPE, std::string>)("AUDIO_SOURCE_MIC"));
    ASSERT_EQ("", (lookup<SOURCE_TYPE, std::string>)("random"));

    ASSERT_EQ("TTS", (lookup<STREAM_TYPE, std::string>)("AUDIO_STREAM_TTS"));
    ASSERT_EQ("", (lookup<STREAM_TYPE, std::string>)("random"));

    ASSERT_EQ("DIRECT", (lookup<THREAD_TYPE, std::string>)("DIRECT"));
    ASSERT_EQ("", (lookup<THREAD_TYPE, std::string>)("random"));

    ASSERT_EQ("static", (lookup<TRACK_TRAITS, std::string>)("static"));
    ASSERT_EQ("", (lookup<TRACK_TRAITS, std::string>)("random"));

    ASSERT_EQ("VOICE_COMMUNICATION",
            (lookup<USAGE, std::string>)("AUDIO_USAGE_VOICE_COMMUNICATION"));
    ASSERT_EQ("", (lookup<USAGE, std::string>)("random"));
}

// Check our string validation (before logging to statsd).
// This variant checks integral value logging.
TEST(mediametrics_tests, audio_types_integer) {
    using namespace android::mediametrics::types;

    ASSERT_EQ(2, (lookup<CALLER_NAME, int32_t>)("java"));
    ASSERT_EQ(0, (lookup<CALLER_NAME, int32_t>)("random")); // 0 == unknown

    ASSERT_EQ((int32_t)AUDIO_CONTENT_TYPE_SPEECH,
            (lookup<CONTENT_TYPE, int32_t>)("AUDIO_CONTENT_TYPE_SPEECH"));
    ASSERT_EQ((int32_t)AUDIO_CONTENT_TYPE_UNKNOWN, (lookup<CONTENT_TYPE, int32_t>)("random"));

    ASSERT_EQ((int32_t)AUDIO_FORMAT_FLAC, (lookup<ENCODING, int32_t>)("AUDIO_FORMAT_FLAC"));
    ASSERT_EQ((int32_t)AUDIO_FORMAT_INVALID, (lookup<ENCODING, int32_t>)("random"));

    ASSERT_EQ(getAudioDeviceInMap().at("AUDIO_DEVICE_IN_USB_DEVICE"),
            (lookup<INPUT_DEVICE, int64_t>)("AUDIO_DEVICE_IN_USB_DEVICE"));
    ASSERT_EQ(getAudioDeviceInMap().at("AUDIO_DEVICE_IN_BUILTIN_MIC")
            | getAudioDeviceInMap().at("AUDIO_DEVICE_IN_WIRED_HEADSET"),
            (lookup<INPUT_DEVICE, int64_t>)(
            "AUDIO_DEVICE_IN_BUILTIN_MIC|AUDIO_DEVICE_IN_WIRED_HEADSET"));
    ASSERT_EQ(0, (lookup<INPUT_DEVICE, int64_t>)("random"));

    ASSERT_EQ((int32_t)AUDIO_INPUT_FLAG_RAW,
            (lookup<INPUT_FLAG, int32_t>)("AUDIO_INPUT_FLAG_RAW"));
    ASSERT_EQ((int32_t)AUDIO_INPUT_FLAG_HW_AV_SYNC
            | (int32_t)AUDIO_INPUT_FLAG_VOIP_TX,
            (lookup<INPUT_FLAG, int32_t>)(
            "AUDIO_INPUT_FLAG_HW_AV_SYNC|AUDIO_INPUT_FLAG_VOIP_TX"));
    ASSERT_EQ(0, (lookup<INPUT_FLAG, int32_t>)("random"));

    ASSERT_EQ(getAudioDeviceOutMap().at("AUDIO_DEVICE_OUT_BLUETOOTH_SCO_CARKIT"),
            (lookup<OUTPUT_DEVICE, int64_t>)("AUDIO_DEVICE_OUT_BLUETOOTH_SCO_CARKIT"));
    ASSERT_EQ(getAudioDeviceOutMap().at("AUDIO_DEVICE_OUT_SPEAKER")
            | getAudioDeviceOutMap().at("AUDIO_DEVICE_OUT_HDMI"),
            (lookup<OUTPUT_DEVICE, int64_t>)(
            "AUDIO_DEVICE_OUT_SPEAKER|AUDIO_DEVICE_OUT_HDMI"));
    ASSERT_EQ(0, (lookup<OUTPUT_DEVICE, int64_t>)("random"));

    ASSERT_EQ((int32_t)AUDIO_OUTPUT_FLAG_PRIMARY,
            (lookup<OUTPUT_FLAG, int32_t>)("AUDIO_OUTPUT_FLAG_PRIMARY"));
    ASSERT_EQ((int32_t)AUDIO_OUTPUT_FLAG_DEEP_BUFFER | (int32_t)AUDIO_OUTPUT_FLAG_NON_BLOCKING,
            (lookup<OUTPUT_FLAG, int32_t>)(
            "AUDIO_OUTPUT_FLAG_DEEP_BUFFER|AUDIO_OUTPUT_FLAG_NON_BLOCKING"));
    ASSERT_EQ(0, (lookup<OUTPUT_FLAG, int32_t>)("random"));

    ASSERT_EQ((int32_t)AUDIO_SOURCE_MIC, (lookup<SOURCE_TYPE, int32_t>)("AUDIO_SOURCE_MIC"));
    ASSERT_EQ((int32_t)AUDIO_SOURCE_DEFAULT, (lookup<SOURCE_TYPE, int32_t>)("random"));

    ASSERT_EQ((int32_t)AUDIO_STREAM_TTS, (lookup<STREAM_TYPE, int32_t>)("AUDIO_STREAM_TTS"));
    ASSERT_EQ((int32_t)AUDIO_STREAM_DEFAULT, (lookup<STREAM_TYPE, int32_t>)("random"));

    ASSERT_EQ(1, (lookup<THREAD_TYPE, int32_t>)("DIRECT"));
    ASSERT_EQ(-1, (lookup<THREAD_TYPE, int32_t>)("random"));

    ASSERT_EQ(getAudioTrackTraitsMap().at("static"), (lookup<TRACK_TRAITS, int32_t>)("static"));
    ASSERT_EQ(0, (lookup<TRACK_TRAITS, int32_t>)("random"));

    ASSERT_EQ((int32_t)AUDIO_USAGE_VOICE_COMMUNICATION,
            (lookup<USAGE, int32_t>)("AUDIO_USAGE_VOICE_COMMUNICATION"));
    ASSERT_EQ((int32_t)AUDIO_USAGE_UNKNOWN, (lookup<USAGE, int32_t>)("random"));
}

#if 0
// Stress test code for garbage collection, you need to enable AID_SHELL as trusted to run
// in MediaMetricsService.cpp.
//
// TODO: Make a dedicated stress test.
//
TEST(mediametrics_tests, gc_same_key) {
  // random keys ignored when empty
  for (int i = 0; i < 10000000; ++i) {
      std::unique_ptr<mediametrics::Item> test_key(mediametrics::Item::create("audio.zzz.123"));
      test_key->set("event#", "hello");
      test_key->set("value",  (int)10);
      test_key->selfrecord();
  }
  //mediaMetrics->dump(fileno(stdout), {} /* args */);
}
#endif
