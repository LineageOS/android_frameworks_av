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
#pragma once

#include <utils/Mutex.h>
#include <utils/RefBase.h>

#include "ClearKeyTypes.h"
#include "Session.h"

namespace clearkeydrm {

class SessionLibrary {
  public:
    static SessionLibrary* get();

    ::android::sp<Session> createSession();

    ::android::sp<Session> findSession(const std::vector<uint8_t>& sessionId);

    void destroySession(const ::android::sp<Session>& session);

    size_t numOpenSessions() const { return mSessions.size(); }

  private:
    CLEARKEY_DISALLOW_COPY_AND_ASSIGN(SessionLibrary);

    SessionLibrary() : mNextSessionId(1) {}

    static ::android::Mutex sSingletonLock;
    static SessionLibrary* sSingleton;

    ::android::Mutex mSessionsLock;
    uint32_t mNextSessionId;
    std::map<std::vector<uint8_t>, ::android::sp<Session>> mSessions;
};

}  // namespace clearkeydrm
