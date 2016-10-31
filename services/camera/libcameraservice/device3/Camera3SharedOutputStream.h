/*
 * Copyright (C) 2016 The Android Open Source Project
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

#ifndef ANDROID_SERVERS_CAMERA3_SHARED_OUTPUT_STREAM_H
#define ANDROID_SERVERS_CAMERA3_SHARED_OUTPUT_STREAM_H

#include "Camera3StreamSplitter.h"
#include "Camera3OutputStream.h"

namespace android {

namespace camera3 {

class Camera3SharedOutputStream :
        public Camera3OutputStream {
public:
    /**
     * Set up a stream for formats that have 2 dimensions, with multiple
     * surfaces. A valid stream set id needs to be set to support buffer
     * sharing between multiple streams.
     */
    Camera3SharedOutputStream(int id, const std::vector<sp<Surface>>& surfaces,
            bool hasDeferredSurface, uint32_t width, uint32_t height, int format,
            uint32_t consumerUsage, android_dataspace dataSpace,
            camera3_stream_rotation_t rotation, nsecs_t timestampOffset,
            int setId = CAMERA3_STREAM_SET_ID_INVALID);

    virtual ~Camera3SharedOutputStream();

    virtual status_t notifyRequestedSurfaces(uint32_t frame_number,
            const std::vector<size_t>& surface_ids);

    virtual bool isConsumerConfigurationDeferred(size_t surface_id) const;

    virtual status_t setConsumer(sp<Surface> consumer);

private:
    // Surfaces passed in constructor from app
    std::vector<sp<Surface> > mSurfaces;

    /**
     * The Camera3StreamSplitter object this stream uses for stream
     * sharing.
     */
    sp<Camera3StreamSplitter> mStreamSplitter;

    /**
     * Initialize stream splitter.
     */
    status_t connectStreamSplitterLocked();

    virtual status_t configureQueueLocked();

    virtual status_t disconnectLocked();

    virtual status_t getEndpointUsage(uint32_t *usage) const;

    bool mDeferred;

}; // class Camera3SharedOutputStream

} // namespace camera3

} // namespace android

#endif // ANDROID_SERVERS_CAMERA3_SHARED_OUTPUT_STREAM_H
