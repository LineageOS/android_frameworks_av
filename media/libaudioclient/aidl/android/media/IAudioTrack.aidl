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

package android.media;

import android.media.AudioTimestampInternal;
import android.media.SharedFileRegion;
import android.media.VolumeShaperConfiguration;
import android.media.VolumeShaperOperation;
import android.media.VolumeShaperState;
import android.media.audio.common.AudioDualMonoMode;
import android.media.audio.common.AudioPlaybackRate;

/**
 * Unless otherwise noted, methods returning int expect it to be interpreted as a status_t.
 *
 * {@hide}
 */
interface IAudioTrack {
    /** Get this track's control block */
    @nullable SharedFileRegion getCblk();

    /**
     * After it's created the track is not active. Call start() to
     * make it active.
     */
    int start();

    /**
     * Stop a track. If set, the callback will cease being called and
     * obtainBuffer will return an error. Buffers that are already released
     * will continue to be processed, unless/until flush() is called.
     */
    void stop();

    /**
     * Flush a stopped or paused track. All pending/released buffers are discarded.
     * This function has no effect if the track is not stopped or paused.
     */
    void flush();

    /**
     * Pause a track. If set, the callback will cease being called and
     * obtainBuffer will return an error. Buffers that are already released
     * will continue to be processed, unless/until flush() is called.
     */
    void pause();

    /**
     * Attach track auxiliary output to specified effect. Use effectId = 0
     * to detach track from effect.
     */
    int attachAuxEffect(int effectId);

    /** Send parameters to the audio hardware. */
    int setParameters(@utf8InCpp String keyValuePairs);

    /** Selects the presentation (if available). */
    int selectPresentation(int presentationId, int programId);

    /** Return NO_ERROR if timestamp is valid. */
    int getTimestamp(out AudioTimestampInternal timestamp);

    /** Signal the playback thread for a change in control block. */
    void signal();

    /** Sets the volume shaper. Returns the volume shaper status. */
    int applyVolumeShaper(in VolumeShaperConfiguration configuration,
                          in VolumeShaperOperation operation);

    /** Gets the volume shaper state. */
    @nullable VolumeShaperState getVolumeShaperState(int id);

    /**
     * Returns DualMonoMode setting associated with this AudioTrack.
     */
    AudioDualMonoMode getDualMonoMode();

    /**
     * Sets DualMonoMode setting.
     */
    void setDualMonoMode(in AudioDualMonoMode mode);

    /**
     * Returns the AudioDescriptionMixLevel.
     */
    float getAudioDescriptionMixLevel();

    /**
     * Sets the AudioDescriptionMixLevel.
     */
    void setAudioDescriptionMixLevel(float leveldB);

    /**
     * Returns the AudioPlaybackRate.
     */
    AudioPlaybackRate getPlaybackRateParameters();

    /**
     * Sets the AudioPlaybackRate.
     */
    void setPlaybackRateParameters(in AudioPlaybackRate playbackRate);
}
