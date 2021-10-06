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

package aaudio;

import aaudio.Endpoint;
import aaudio.IAAudioClient;
import aaudio.StreamParameters;
import aaudio.StreamRequest;

interface IAAudioService {
    /**
     * Register an object to receive audio input/output change and track notifications.
     * For a given calling pid, AAudio service disregards any registrations after the first.
     * Thus the IAAudioClient must be a singleton per process.
     */
    void registerClient(IAAudioClient client);

    /**
     * @param request info needed to create the stream
     * @param paramsOut contains information about the created stream
     * @return handle to the stream or a negative error
     */
    int openStream(in StreamRequest request,
                   out StreamParameters paramsOut);

    int closeStream(int streamHandle);

    /*
     * Get an immutable description of the in-memory queues
     * used to communicate with the underlying HAL or Service.
     */
    int getStreamDescription(int streamHandle, out Endpoint endpoint);

    /**
     * Start the flow of data.
     * This is asynchronous. When complete, the service will send a STARTED event.
     */
    int startStream(int streamHandle);

    /**
     * Stop the flow of data such that start() can resume without loss of data.
     * This is asynchronous. When complete, the service will send a PAUSED event.
     */
    int pauseStream(int streamHandle);

    /**
     * Stop the flow of data such that the data currently in the buffer is played.
     * This is asynchronous. When complete, the service will send a STOPPED event.
     */
    int stopStream(int streamHandle);

    /**
     *  Discard any data held by the underlying HAL or Service.
     * This is asynchronous. When complete, the service will send a FLUSHED event.
     */
    int flushStream(int streamHandle);

    /**
     * Manage the specified thread as a low latency audio thread.
     */
    int registerAudioThread(int streamHandle,
                            int clientThreadId,
                            long periodNanoseconds);

    int unregisterAudioThread(int streamHandle,
                              int clientThreadId);
}
