/*
 * Copyright 2021 The Android Open Source Project
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

#ifndef PLAYBACK_DURATION_ACCUMULATOR_H_

namespace android {

// Accumulates playback duration by processing render times of individual frames and by ignoring
// frames rendered during inactive playbacks such as seeking, pausing, or re-buffering.
class PlaybackDurationAccumulator {
private:
    // Controls the maximum delta between render times before considering the playback is not
    // active and has stalled.
    static const int64_t MAX_PRESENTATION_DURATION_NS = 500 * 1000 * 1000;

public:
    PlaybackDurationAccumulator() {
        mPlaybackDurationNs = 0;
        mPreviousRenderTimeNs = 0;
    }

    // Process a render time expressed in nanoseconds.
    void onFrameRendered(int64_t newRenderTimeNs) {
        // If we detect wrap-around or out of order frames, just ignore the duration for this
        // and the next frame.
        if (newRenderTimeNs < mPreviousRenderTimeNs) {
            mPreviousRenderTimeNs = 0;
        }
        if (mPreviousRenderTimeNs > 0) {
            int64_t presentationDurationNs = newRenderTimeNs - mPreviousRenderTimeNs;
            if (presentationDurationNs < MAX_PRESENTATION_DURATION_NS) {
                mPlaybackDurationNs += presentationDurationNs;
            }
        }
        mPreviousRenderTimeNs = newRenderTimeNs;
    }

    int64_t getDurationInSeconds() {
        return mPlaybackDurationNs / 1000 / 1000 / 1000; // Nanoseconds to seconds.
    }

private:
    // The playback duration accumulated so far.
    int64_t mPlaybackDurationNs;
    // The previous render time used to compute the next presentation duration.
    int64_t mPreviousRenderTimeNs;
};

} // android

#endif // PLAYBACK_DURATION_ACCUMULATOR_H_

