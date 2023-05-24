/*
 * Copyright (C) 2023 The Android Open Source Project
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

// #define LOG_NDEBUG 0
#define LOG_TAG "synchronizedrecordstate_tests"

#include "../SynchronizedRecordState.h"

#include <gtest/gtest.h>

using namespace android;
using namespace android::audioflinger;

namespace {

TEST(SynchronizedRecordStateTests, Basic) {
    struct Cookie : public RefBase {};

    // These variables are set by trigger().
    bool triggered = false;
    wp<SyncEvent> param;

    constexpr auto type = AudioSystem::SYNC_EVENT_PRESENTATION_COMPLETE;
    constexpr auto triggerSession = audio_session_t(10);
    constexpr auto listenerSession = audio_session_t(11);
    const SyncEventCallback callback =
            [&](const wp<SyncEvent>& event) {
                triggered = true;
                param = event;
            };
    const auto cookie = sp<Cookie>::make();

    // Check timeout.
    SynchronizedRecordState recordState(48000 /* sampleRate */);
    auto syncEvent = sp<SyncEvent>::make(
            type,
            triggerSession,
            listenerSession,
            callback,
            cookie);
    recordState.startRecording(syncEvent);
    recordState.updateRecordFrames(2);
    ASSERT_FALSE(triggered);
    ASSERT_EQ(0, recordState.updateRecordFrames(1'000'000'000));
    ASSERT_FALSE(triggered);
    ASSERT_TRUE(syncEvent->isCancelled());

    // Check count down after track is complete.
    syncEvent = sp<SyncEvent>::make(
                type,
                triggerSession,
                listenerSession,
                callback,
                cookie);
    recordState.startRecording(syncEvent);
    recordState.onPlaybackFinished(syncEvent, 10);
    ASSERT_EQ(1, recordState.updateRecordFrames(9));
    ASSERT_FALSE(triggered);
    ASSERT_EQ(0, recordState.updateRecordFrames(2));
    ASSERT_FALSE(triggered);
    ASSERT_TRUE(syncEvent->isCancelled());
}

}
