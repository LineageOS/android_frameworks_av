/*
 * Copyright 2016 The Android Open Source Project
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

#ifndef ANDROID_BINDING_AUDIO_ENDPOINT_PARCELABLE_H
#define ANDROID_BINDING_AUDIO_ENDPOINT_PARCELABLE_H

#include <stdint.h>

//#include <sys/mman.h>
#include <aaudio/Endpoint.h>
#include <android-base/unique_fd.h>

#include "binding/AAudioServiceDefinitions.h"
#include "binding/RingBufferParcelable.h"

using android::status_t;

namespace aaudio {

/**
 * Container for information about the message queues plus
 * general stream information needed by AAudio clients.
 * It contains no addresses, just sizes, offsets and file descriptors for
 * shared memory that can be passed through Binder.
 */
class AudioEndpointParcelable {
public:
    AudioEndpointParcelable() = default;

    // Ctor/assignment from a parcelable representation.
    // Since the parcelable object owns unique FDs (for shared memory blocks), move semantics are
    // provided to avoid the need to dupe.
    explicit AudioEndpointParcelable(Endpoint&& parcelable);
    AudioEndpointParcelable& operator=(Endpoint&& parcelable);

    /**
     * Add the file descriptor to the table.
     * @return index in table or negative error
     */
    int32_t addFileDescriptor(const android::base::unique_fd& fd, int32_t sizeInBytes);

    /**
     * Close current data file descriptor. The duplicated file descriptor will be close.
     */
    void closeDataFileDescriptor();

    /**
     * Update current data file descriptor with given endpoint parcelable.
     * @param endpointParcelable an endpoint parcelable that contains new data file
     *                           descriptor information
     * @return AAUDIO_OK if the data file descriptor updates successfully.
     *         AAUDIO_ERROR_OUT_OF_RANGE if there is not enough space for the shared memory.
     */
    aaudio_result_t updateDataFileDescriptor(AudioEndpointParcelable* endpointParcelable);

    aaudio_result_t resolve(EndpointDescriptor *descriptor);
    aaudio_result_t resolveDataQueue(RingBufferDescriptor *descriptor);

    aaudio_result_t close();

    void dump();

    // Extract a parcelable representation of this object.
    // Since our shared memory objects own a unique FD, move semantics are provided to avoid the
    // need to dupe.
    Endpoint parcelable()&&;

public: // TODO add getters
    // Set capacityInFrames to zero if Queue is unused.
    RingBufferParcelable    mUpMessageQueueParcelable;   // server to client
    RingBufferParcelable    mDownMessageQueueParcelable; // to server
    RingBufferParcelable    mUpDataQueueParcelable;      // eg. record, could share same queue
    RingBufferParcelable    mDownDataQueueParcelable;    // eg. playback

private:
    // Return the first available shared memory position. Return -1 if all shared memories are
    // in use.
    int32_t getNextAvailableSharedMemoryPosition() const;

    SharedMemoryParcelable  mSharedMemories[MAX_SHARED_MEMORIES];
};

} /* namespace aaudio */

#endif //ANDROID_BINDING_AUDIO_ENDPOINT_PARCELABLE_H
