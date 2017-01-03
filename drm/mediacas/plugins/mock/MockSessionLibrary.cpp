/*
 * Copyright (C) 2017 The Android Open Source Project
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

//#define LOG_NDEBUG 0
#define LOG_TAG "MockSessionLibrary"

#include <utils/Log.h>
#include <utils/String8.h>
#include "MockSessionLibrary.h"

namespace android {

Mutex MockSessionLibrary::sSingletonLock;
MockSessionLibrary* MockSessionLibrary::sSingleton = NULL;

inline bool operator < (
        const SessionInfo& lhs,
        const SessionInfo& rhs) {
    if (lhs.plugin < rhs.plugin) return true;
    else if (lhs.plugin > rhs.plugin) return false;

    if (lhs.program_number < rhs.program_number) return true;
    else if (lhs.program_number > rhs.program_number) return false;

    return lhs.elementary_PID < rhs.elementary_PID;
}

void MockCasSession::setSessionInfo(const SessionInfo &info) {
    mSessionInfo = info;
}

const SessionInfo& MockCasSession::getSessionInfo() const {
    return mSessionInfo;
}

MockSessionLibrary* MockSessionLibrary::get() {
    Mutex::Autolock lock(sSingletonLock);

    if (sSingleton == NULL) {
        ALOGD("Instantiating Session Library Singleton.");
        sSingleton = new MockSessionLibrary();
    }

    return sSingleton;
}

MockSessionLibrary::MockSessionLibrary() : mNextSessionId(1) {}

status_t MockSessionLibrary::addSession(
        CasPlugin *plugin,
        uint16_t program_number,
        uint16_t elementary_PID,
        CasSessionId *sessionId) {
    Mutex::Autolock lock(mSessionsLock);

    SessionInfo info = {plugin, program_number, elementary_PID};
    ssize_t index = mSessionInfoToIDMap.indexOfKey(info);
    if (index >= 0) {
        ALOGW("Session already exists: program_number=%u, elementary_PID=%u",
                program_number, elementary_PID);
        *sessionId = mSessionInfoToIDMap[index];
        return OK;
    }

    sp<MockCasSession> session = new MockCasSession();
    session->setSessionInfo(info);

    uint8_t *byteArray = (uint8_t *) &mNextSessionId;
    sessionId->push_back(byteArray[3]);
    sessionId->push_back(byteArray[2]);
    sessionId->push_back(byteArray[1]);
    sessionId->push_back(byteArray[0]);
    mNextSessionId++;

    mSessionInfoToIDMap.add(info, *sessionId);
    mIDToSessionMap.add(*sessionId, session);
    return OK;
}

sp<MockCasSession> MockSessionLibrary::findSession(
        const CasSessionId& sessionId) {
    Mutex::Autolock lock(mSessionsLock);

    ssize_t index = mIDToSessionMap.indexOfKey(sessionId);
    if (index < 0) {
        return NULL;
    }
    return mIDToSessionMap.valueFor(sessionId);
}

void MockSessionLibrary::destroySession(const CasSessionId& sessionId) {
    Mutex::Autolock lock(mSessionsLock);

    ssize_t index = mIDToSessionMap.indexOfKey(sessionId);
    if (index < 0) {
        return;
    }

    sp<MockCasSession> session = mIDToSessionMap.valueAt(index);
    mSessionInfoToIDMap.removeItem(session->getSessionInfo());
    mIDToSessionMap.removeItemsAt(index);
}

void MockSessionLibrary::destroyPlugin(CasPlugin *plugin) {
    Mutex::Autolock lock(mSessionsLock);

    for (ssize_t index = mSessionInfoToIDMap.size() - 1; index >= 0; index--) {
        const SessionInfo &info = mSessionInfoToIDMap.keyAt(index);
        if (info.plugin == plugin) {
            const CasSessionId &id = mSessionInfoToIDMap.valueAt(index);
            mIDToSessionMap.removeItem(id);
            mSessionInfoToIDMap.removeItemsAt(index);
        }
    }
}

} // namespace android
