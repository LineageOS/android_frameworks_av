/*
 * Copyright (C) 2024 The Android Open Source Project
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

import android.os.ParcelFileDescriptor;

/**
 * Binder interface for controlling and handling IAidlGraphicBufferSource
 * from the process which owns IAidlNode.
 *
 * In order to support Persistent InputSurface and/or MediaRecorder
 */
interface IAidlBufferSource {
    /**
     * This is called when IAidlGraphicBufferSource can start handing buffers.
     * If we already have buffers of data sitting in the BufferQueue,
     * this will send them to the codec.
     */
    void onStart();

    /**
     * This is called when IAidlGraphicBufferSource indicaters that
     * the codec is meant to return all buffers back to the client for them
     * to be freed. Do NOT submit any more buffers to the component.
     */
    void onStop();

    /**
     * This is called when IAidlGraphicBufferSource indicates that
     * we are shutting down.
     */
    void onRelease();

    /**
     * A "codec buffer", i.e. a buffer that can be used to pass data into
     * the encoder, has been allocated.
     */
    void onInputBufferAdded(int bufferID);

    /**
     * If we have a BQ buffer available,
     * fill it with a new frame of data; otherwise, just mark it as available.
     *
     * fence contains the fence's fd that the callee should wait on before
     * using the buffer (or pass on to the user of the buffer, if the user supports
     * fences). Callee takes ownership of the fence fd even if it fails.
     */
    void onInputBufferEmptied(int bufferID, in @nullable ParcelFileDescriptor fence);
}

