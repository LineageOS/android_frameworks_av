/*
 * Copyright (C) 2025 The Android Open Source Project
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

import android.media.AudioClient;
import android.media.TimerQueueHandle;
import android.media.audio.common.AudioAttributes;
import android.media.audio.common.AudioPlaybackRate;
import android.media.MmapBufferInfo;

/**
 * The IMmapStream interface is the binder interface to control a stream in MMAP mode.
 *
 * @hide
 */
interface IMmapStream {
    /**
     * Creates the mmap buffer used for audio samples transfer.
     * Must be called before any other method after opening the stream or entering standby.
     *
     * @param minSizeFrames minimum buffer size requested. The actual buffer
     *        size returned in struct audio_mmap_buffer_info can be larger.
     * @return A MmapBufferInfo struct with the mmap buffer information.
     */
    MmapBufferInfo createMmapBuffer(in int minSizeFrames);

    parcelable MmapStreamPosition {
        /** The timestamp of the position in nanoseconds. */
        long timeNanos;
        /** The position in frames. */
        // TODO(b/430107775) convert to 64b.  See MmapExternalPosition.aidl.
        int positionFrames;
    }
    /**
     * Read current read/write position in the mmap buffer with associated time stamp.
     *
     * @return A MmapStreamPosition struct with the mmap read/write position.
     */
    MmapStreamPosition getMmapPosition();

    parcelable MmapObservablePosition {
        /** The timestamp of the position in nanoseconds. */
        long timeNanos;
        /** The position in frames. */
        long positionFrames;
    }
    /**
     * Get a recent count of the number of audio frames presented/received to/from an
     * external observer.
     *
     * @return A MmapObservablePosition struct with
     *     position count of presented audio frames and
     *     timeNanos associated clock time
     */
    MmapObservablePosition getObservablePosition();

    /**
     * Start a stream operating in mmap mode.
     * createMmapBuffer() must be called before calling start()
     *
     * @param client a AudioClient struct describing the client starting on this stream.
     * @param attr audio attributes provided by the client.
     * @param portId to be used
     * @return a unique handle for this instance. Used with stop().
     */
    int start(in AudioClient client, in @nullable AudioAttributes attr, in int portId);

    /**
     * Stop a stream operating in mmap mode.
     * Must be called after start()
     *
     * @param handle unique handle allocated by start().
     */
    void stop(in int handle);

    /**
     * Put a stream operating in mmap mode into standby.
     * Must be called after createMmapBuffer(). Cannot be called if any client is active,
     * i.e. started but not stopped.
     * It is recommended to place a mmap stream into standby as often as possible when
     * no client is active to save power.
     */
    void standby();

    /**
     * Report when data being written to a playback buffer. Currently, this is used by mmap
     * playback thread for sound dose computation.
     *
     * TODO(b/430293936) Optimize the call interface to avoid passing buffer.
     *
     * @param buffer a byte buffer of the data, whose length is
     *        frame size multiplied by frame count.
     */
    void reportData(in byte[] buffer);

    /**
     * Notify the stream is currently draining.
     *
     * @param wakeUpNanos the timestamp in boottime nanoseconds that the client must be waken up.
     * @param allowSoftWakeUp allow the service side to wake up the client even if it is not the
     *                        requested time. This allows service side to smartly select wake up
     *                        time instead of waiting for the exact wake up time.
     * @param handle the handle to identify the task in TimerQueue at service side. Use this handle
     *               to remove the wake up task if the wake up task is no longer needed.
     */
    void drain(long wakeUpNanos, boolean allowSoftWakeUp, out TimerQueueHandle handle);

    /**
     * Notify the stream is active.
     *
     * @param handle the handle to identify the wake up task in TimerQueue at service side.
                     It is used by service side to remove wake up task.
     */
    void activate(in TimerQueueHandle handle);

    void setPlaybackParameters(in AudioPlaybackRate rate);

    void getPlaybackParameters(out AudioPlaybackRate rate);
}
