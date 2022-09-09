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

#include <mediautils/ThreadSnapshot.h>
#include <mediautils/TidWrapper.h>

#define LOG_TAG "media_threadsnapshot_tests"

#include <gtest/gtest.h>
#include <utils/Log.h>

#include <chrono>
#include <thread>

using namespace android;
using namespace android::mediautils;

// Disables false-positives from base::Split()
//
// See mismatched sanitized libraries here:
// https://github.com/google/sanitizers/wiki/AddressSanitizerContainerOverflow
extern "C" const char* __asan_default_options() {
  return "detect_container_overflow=0";
}

TEST(media_threadsnapshot_tests, basic) {
  using namespace std::chrono_literals;

  ThreadSnapshot threadSnapshot(getThreadIdWrapper());

  threadSnapshot.onBegin();

  std::string snapshot1 = threadSnapshot.toString();

  std::this_thread::sleep_for(100ms);

  threadSnapshot.onEnd();

  std::string snapshot2 = threadSnapshot.toString();

  // Either we can't get a snapshot, or they must be different when taken when thread is running.
  if (snapshot1.empty()) {
    ASSERT_TRUE(snapshot2.empty());
  } else {
    ASSERT_FALSE(snapshot2.empty());
    ASSERT_NE(snapshot1, snapshot2);
  }
}
