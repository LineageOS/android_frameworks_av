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

/**
 * The MmapBufferInfo parcelable is used to return the mmap buffer information from
 * IMmapStream.createMmapBuffer().
 *
 * @hide
 */
parcelable MmapBufferInfo {
    /** A parcel file descriptor associated with the shared memory region for
        the audio data. */
    ParcelFileDescriptor sharedFd;
    /** The total size of the buffer in frames. */
    int bufferSizeFrames;
    /** The burst size in frames. */
    int burstSizeFrames;
    /** flags see enum audio_mmap_buffer_flag. */
    int flags;
}
