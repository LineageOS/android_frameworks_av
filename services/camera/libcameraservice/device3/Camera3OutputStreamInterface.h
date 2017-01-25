/*
 * Copyright (C) 2013 The Android Open Source Project
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

#ifndef ANDROID_SERVERS_CAMERA3_OUTPUT_STREAM_INTERFACE_H
#define ANDROID_SERVERS_CAMERA3_OUTPUT_STREAM_INTERFACE_H

#include "Camera3StreamInterface.h"

namespace android {

namespace camera3 {

/**
 * An interface for managing a single stream of output data from the camera
 * device.
 */
class Camera3OutputStreamInterface : public virtual Camera3StreamInterface {
  public:
    /**
     * Set the transform on the output stream; one of the
     * HAL_TRANSFORM_* / NATIVE_WINDOW_TRANSFORM_* constants.
     */
    virtual status_t setTransform(int transform) = 0;

    /**
     * Return if this output stream is for video encoding.
     */
    virtual bool isVideoStream() const = 0;

    /**
     * Return if the consumer configuration of this stream is deferred.
     */
    virtual bool isConsumerConfigurationDeferred(size_t surface_id = 0) const = 0;

    /**
     * Set the consumer surfaces to the output stream.
     */
    virtual status_t setConsumers(const std::vector<sp<Surface>>& consumers) = 0;

    /**
     * Detach an unused buffer from the stream.
     *
     * buffer must be non-null; fenceFd may null, and if it is non-null, but
     * there is no valid fence associated with the detached buffer, it will be
     * set to -1.
     *
     */
    virtual status_t detachBuffer(sp<GraphicBuffer>* buffer, int* fenceFd) = 0;

    /**
     * Notify which surfaces are requested for a particular frame number.
     *
     * Mulitple surfaces could share the same output stream, but a request may
     * be only for a subset of surfaces. In this case, the
     * Camera3OutputStreamInterface object needs to manage the output surfaces on
     * a per request basis.
     *
     * If there is only one surface for this output stream, calling this
     * function is a no-op.
     */
    virtual status_t notifyRequestedSurfaces(uint32_t frame_number,
            const std::vector<size_t>& surface_ids) = 0;
};

} // namespace camera3

} // namespace android

#endif
