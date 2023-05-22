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

#include "SyncEvent.h"

#pragma push_macro("LOG_TAG")
#undef LOG_TAG
#define LOG_TAG "SynchronizedRecordState"

namespace android::audioflinger {

class SynchronizedRecordState {
public:
    explicit SynchronizedRecordState(uint32_t sampleRate)
        : mSampleRate(sampleRate)
        {}

    void clear() {
        std::lock_guard lg(mLock);
        clear_l();
    }

    // Called by the RecordThread when recording is starting.
    void startRecording(const sp<SyncEvent>& event) {
        std::lock_guard lg(mLock);
        mSyncStartEvent = event;
        // Sync event can be cancelled by the trigger session if the track is not in a
        // compatible state in which case we start record immediately
        if (mSyncStartEvent->isCancelled()) {
            clear_l();
        } else {
            mFramesToDrop = -(ssize_t)
                ((AudioSystem::kSyncRecordStartTimeOutMs * mSampleRate) / 1000);
        }
    }

    // Invoked by SyncEvent callback.
    void onPlaybackFinished(const sp<SyncEvent>& event, size_t framesToDrop = 1) {
        std::lock_guard lg(mLock);
        if (event == mSyncStartEvent) {
            mFramesToDrop = framesToDrop;  // compute this
            ALOGV("%s: framesToDrop:%zd", __func__, mFramesToDrop);
        }
    }

    // Returns the current FramesToDrop counter
    //
    //   if <0 waiting (drop the frames)
    //   if >0 draining (drop the frames)
    //    else if ==0 proceed to record.
    ssize_t updateRecordFrames(size_t frames) {
        std::lock_guard lg(mLock);
        if (mFramesToDrop > 0) {
            // we've been triggered, we count down for start delay
            ALOGV("%s: trigger countdown %zd by %zu frames", __func__, mFramesToDrop, frames);
            mFramesToDrop -= (ssize_t)frames;
            if (mFramesToDrop <= 0) clear_l();
        } else if (mFramesToDrop < 0) {
            // we're waiting to be triggered.
            // ALOGD("%s: timeout countup %zd with %zu frames", __func__, mFramesToDrop, frames);
            mFramesToDrop += (ssize_t)frames;
            if (mFramesToDrop >= 0 || !mSyncStartEvent || mSyncStartEvent->isCancelled()) {
                ALOGW("Synced record %s, trigger session %d",
                        (mFramesToDrop >= 0) ? "timed out" : "cancelled",
                        (mSyncStartEvent) ? mSyncStartEvent->triggerSession()
                                          : AUDIO_SESSION_NONE);
                 clear_l();
            }
        }
        return mFramesToDrop;
    }

private:
    const uint32_t mSampleRate;

    std::mutex mLock;
    // number of captured frames to drop after the start sync event has been received.
    // when < 0, maximum frames to drop before starting capture even if sync event is
    // not received
    ssize_t mFramesToDrop GUARDED_BY(mLock) = 0;

    // sync event triggering actual audio capture. Frames read before this event will
    // be dropped and therefore not read by the application.
    sp<SyncEvent> mSyncStartEvent GUARDED_BY(mLock);

    void clear_l() REQUIRES(mLock) {
        if (mSyncStartEvent) {
            mSyncStartEvent->cancel();
            mSyncStartEvent.clear();
        }
        mFramesToDrop = 0;
    }
};

} // namespace android::audioflinger

#pragma pop_macro("LOG_TAG")
