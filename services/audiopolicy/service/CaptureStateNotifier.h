/*
 * Copyright (C) 2020 The Android Open Source Project
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

#include <mutex>
#include <binder/IBinder.h>
#include <utils/StrongPointer.h>

namespace android {
namespace media {
// Must be pre-declared, or else there isn't a good way to generate a header
// library.
class ICaptureStateListener;
}

// A utility for managing capture state change notifications.
//
// We are making some strong assumptions, for the sake of simplicity:
// - There is no way to explicitly unregister listeners. The only way for a
//   listener to unregister is by dying.
// - There's only at most one listener at a given time. Attempting to register
//   a second listener will cause a crash.
// - This class isn't really meant to ever be destroyed. We expose a destructor
//   because it is convenient to use this class as a global instance or a member
//   of another class, but it will crash if destroyed while a listener is
//   registered.
//
// All of these assumptions can be lifted if there is ever a need.
//
// This class is thread-safe.
class CaptureStateNotifier {
public:
    // Ctor.
    // Accepts the initial active state.
    explicit CaptureStateNotifier(bool initialActive);

    // Register a listener to be notified of state changes.
    // The current state is returned and from that point on any change will be
    // notified of.
    bool RegisterListener(const sp<media::ICaptureStateListener>& listener);

    // Change the current capture state.
    // Active means "actively capturing".
    void setCaptureState(bool active);

    // Dtor. Do not actually call at runtime. Will cause a crash if a listener
    // is registered.
    ~CaptureStateNotifier();

private:
    std::mutex mMutex;
    sp<media::ICaptureStateListener> mListener;
    sp<IBinder::DeathRecipient> mDeathRecipient;
    bool mActive;

    class DeathRecipient;

    void binderDied();
};

}  // namespace android
