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

#pragma once

namespace android {

class SyncEvent;

typedef void (*sync_event_callback_t)(const wp<SyncEvent>& event) ;

class SyncEvent : public RefBase {
public:
    SyncEvent(AudioSystem::sync_event_t type,
              audio_session_t triggerSession,
              audio_session_t listenerSession,
              sync_event_callback_t callBack,
              const wp<RefBase>& cookie)
    : mType(type), mTriggerSession(triggerSession), mListenerSession(listenerSession),
      mCallback(callBack), mCookie(cookie)
    {}

    virtual ~SyncEvent() {}

    void trigger() {
        Mutex::Autolock _l(mLock);
        if (mCallback) mCallback(wp<SyncEvent>(this));
    }
    bool isCancelled() const { Mutex::Autolock _l(mLock); return (mCallback == NULL); }
    void cancel() { Mutex::Autolock _l(mLock); mCallback = NULL; }
    AudioSystem::sync_event_t type() const { return mType; }
    audio_session_t triggerSession() const { return mTriggerSession; }
    audio_session_t listenerSession() const { return mListenerSession; }
    wp<RefBase> cookie() const { return mCookie; }

private:
      const AudioSystem::sync_event_t mType;
      const audio_session_t mTriggerSession;
      const audio_session_t mListenerSession;
      sync_event_callback_t mCallback;
      const wp<RefBase> mCookie;
      mutable Mutex mLock;
};

} // namespace android
