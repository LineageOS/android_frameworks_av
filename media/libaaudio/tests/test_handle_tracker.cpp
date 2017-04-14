/*
 * Copyright (C) 2016 The Android Open Source Project
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

// Unit tests for AAudio Handle Tracker

#include <stdlib.h>
#include <math.h>

#include <gtest/gtest.h>

#include <aaudio/AAudio.h>
#include "utility/HandleTracker.h"

// Test adding one address.
TEST(test_handle_tracker, aaudio_handle_tracker) {
    const int MAX_HANDLES = 4;
    HandleTracker tracker(MAX_HANDLES);
    handle_tracker_type_t type = 3; // arbitrary generic type
    int data; // something that has an address we can use
    handle_tracker_address_t found;

    // repeat the test several times to see if it breaks
    const int SEVERAL = 5; // arbitrary
    for (int i = 0; i < SEVERAL; i++) {
        // should fail to find a bogus handle
        found = tracker.get(type, 0);  // bad handle
        EXPECT_EQ(nullptr, found);

        // create a valid handle and use it to lookup the object again
        aaudio_handle_t dataHandle = tracker.put(type, &data);
        ASSERT_TRUE(dataHandle > 0);
        found = tracker.get(type, dataHandle);
        EXPECT_EQ(&data, found);
        found = tracker.get(type, 0); // bad handle
        EXPECT_EQ(nullptr, found);

        // wrong type
        found = tracker.get(type+1, dataHandle);
        EXPECT_EQ(nullptr, found);

        // remove from storage
        found = tracker.remove(type, dataHandle);
        EXPECT_EQ(&data, found);
        // should fail the second time
        found = tracker.remove(type, dataHandle);
        EXPECT_EQ(nullptr, found);
    }
}

// Test filling the tracker.
TEST(test_handle_tracker, aaudio_full_up) {
    const int MAX_HANDLES = 5;
    HandleTracker tracker(MAX_HANDLES);
    handle_tracker_type_t type = 4; // arbitrary generic type
    int data[MAX_HANDLES];
    aaudio_handle_t handles[MAX_HANDLES];
    handle_tracker_address_t found;

    // repeat the test several times to see if it breaks
    const int SEVERAL = 5; // arbitrary
    for (int i = 0; i < SEVERAL; i++) {
        for (int i = 0; i < MAX_HANDLES; i++) {
            // add a handle
            handles[i] = tracker.put(type, &data[i]);
            ASSERT_TRUE(handles[i] > 0);
            found = tracker.get(type, handles[i]);
            EXPECT_EQ(&data[i], found);
        }

        // Now that it is full, try to add one more.
        aaudio_handle_t handle = tracker.put(type, &data[0]);
        EXPECT_TRUE(handle < 0);

        for (int i = 0; i < MAX_HANDLES; i++) {
            // look up each handle
            found = tracker.get(type, handles[i]);
            EXPECT_EQ(&data[i], found);
        }

        // remove one from storage
        found = tracker.remove(type, handles[2]);
        EXPECT_EQ(&data[2], found);
        // now try to look up the same handle and fail
        found = tracker.get(type, handles[2]);
        EXPECT_EQ(nullptr, found);

        // add that same one back
        handle = tracker.put(type, &data[2]);
        ASSERT_TRUE(handle > 0);
        found = tracker.get(type, handle);
        EXPECT_EQ(&data[2], found);
        // now use a stale handle again with a valid index and fail
        found = tracker.get(type, handles[2]);
        EXPECT_EQ(nullptr, found);

        // remove them all
        handles[2] = handle;
        for (int i = 0; i < MAX_HANDLES; i++) {
            // look up each handle
            found = tracker.remove(type, handles[i]);
            EXPECT_EQ(&data[i], found);
        }
    }
}
