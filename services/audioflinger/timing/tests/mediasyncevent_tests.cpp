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
#define LOG_TAG "mediasyncevent_tests"

#include "../SyncEvent.h"

#include <gtest/gtest.h>

using namespace android;
using namespace android::audioflinger;

namespace {

TEST(MediaSyncEventTests, Basic) {
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

    // Since the callback uses a weak pointer to this,
    // don't allocate on the stack.
    auto syncEvent = sp<SyncEvent>::make(
            type,
            triggerSession,
            listenerSession,
            callback,
            cookie);

    ASSERT_EQ(type, syncEvent->type());
    ASSERT_EQ(triggerSession, syncEvent->triggerSession());
    ASSERT_EQ(listenerSession, syncEvent->listenerSession());
    ASSERT_EQ(cookie, syncEvent->cookie());
    ASSERT_FALSE(triggered);

    syncEvent->trigger();
    ASSERT_TRUE(triggered);
    ASSERT_EQ(param, syncEvent);

    ASSERT_FALSE(syncEvent->isCancelled());
    syncEvent->cancel();
    ASSERT_TRUE(syncEvent->isCancelled());
}

} // namespace
