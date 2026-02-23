/*
 * Copyright (C) 2016-2018 The Android Open Source Project
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

#include <array>

#include "Flags.h"

#include "Camera3OutputStream.h"

#if USE_NEW_STREAM_SPLITTER
#include "Camera3StreamSplitter.h"
#else
#include "deprecated/DeprecatedCamera3StreamSplitter.h"
#endif  // USE_NEW_STREAM_SPLITTER

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
    Camera3SharedOutputStream(int id, const std::vector<SurfaceHolder>& surfaces,
            uint32_t width, uint32_t height, int format,
            uint64_t consumerUsage, android_dataspace dataSpace,
            camera_stream_rotation_t rotation, nsecs_t timestampOffset,
            const std::string& physicalCameraId,
            const std::unordered_set<int32_t> &sensorPixelModesUsed, IPCTransport transport,
            int setId, bool useHalBufManager, int64_t dynamicProfile, int64_t streamUseCase,
            bool deviceTimeBaseIsRealtime, int timestampBase,
            int32_t colorSpace, bool useReadoutTimestamp);

    virtual ~Camera3SharedOutputStream();

    void setHalBufferManager(bool enabled) override;

    virtual status_t notifyBufferReleased(ANativeWindowBuffer *buffer);

    virtual bool isConsumerConfigurationDeferred(size_t surface_id) const;

    virtual status_t setConsumers(const std::vector<SurfaceHolder>& consumers);

    virtual ssize_t getSurfaceId(const sp<Surface> &surface);

    /**
     * Query the unique surface IDs of current surfaceIds.
     * When passing unique surface IDs in returnBuffer(), if the
     * surfaceId has been removed from the stream, the output corresponding to
     * the unique surface ID will be ignored and not delivered to client.
     */
    virtual status_t getUniqueSurfaceIds(const std::vector<size_t>& surfaceIds,
            /*out*/std::vector<size_t>* outUniqueIds) override;

    virtual status_t updateStream(const std::vector<SurfaceHolder> &outputSurfaces,
            const std::vector<OutputStreamInfo> &outputInfo,
            const std::vector<size_t> &removedSurfaceIds,
            KeyedVector<sp<Surface>, size_t> *outputMap/*out*/);

    virtual status_t updateInternalStream(
            KeyedVector<sp<Surface>, size_t> * /*outputMap out*/) override {
        return INVALID_OPERATION;
    }

    virtual bool getOfflineProcessingSupport() const {
        // As per Camera spec. shared streams currently do not support
        // offline mode.
        return false;
    }

    virtual status_t  setTransform(int transform, int surfaceId);

    /**
     * Query the mirror mode of specific output surface id.
     */
    virtual int getSurfaceMirrorMode(size_t surfaceId) override;

private:

    static const size_t kMaxOutputs = 4;

    // Whether HAL is in control for buffer management. Surface sharing behavior
    // depends on this flag.
    bool mUseHalBufManager;

    // Struct of an output SurfaceHolder, transform, and its unique ID
    struct SurfaceHolderUniqueId {
        SurfaceHolder mSurfaceHolder;
        int mTransform = -1;
        size_t mId = -1;

        SurfaceHolderUniqueId() = default;
        SurfaceHolderUniqueId(size_t id) : mId(id) {}
        SurfaceHolderUniqueId(const SurfaceHolder& holder, size_t id) :
                mSurfaceHolder(holder), mId(id) {}
    };

    // Map surfaceId -> SurfaceHolderUniqueId
    std::array<SurfaceHolderUniqueId, kMaxOutputs> mSurfaceUniqueIds;

    size_t mNextUniqueSurfaceId = 0;

    ssize_t getNextSurfaceIdLocked();

    status_t revertPartialUpdateLocked(const KeyedVector<size_t, SurfaceHolder> &removedSurfaces,
            const KeyedVector<sp<Surface>, size_t> &attachedSurfaces);

    /**
     * The Camera3StreamSplitter object this stream uses for stream
     * sharing.
     */
#if USE_NEW_STREAM_SPLITTER
    sp<Camera3StreamSplitter> mStreamSplitter;
#else
    sp<DeprecatedCamera3StreamSplitter> mStreamSplitter;
#endif  // USE_NEW_STREAM_SPLITTER
    /**
     * Initialize stream splitter.
     */
    status_t connectStreamSplitterLocked();

    /**
     * Attach the output buffer to stream splitter.
     * When camera service is doing buffer management, this method will be called
     * before the buffer is handed out to HAL in request thread.
     * When HAL is doing buffer management, this method will be called when
     * the buffer is returned from HAL in hwbinder callback thread.
     */
    status_t attachBufferToSplitterLocked(ANativeWindowBuffer* anb,
            const std::vector<size_t>& surface_ids);

    /**
     * Internal Camera3Stream interface
     */
    virtual status_t getBufferLocked(camera_stream_buffer *buffer,
            const std::vector<size_t>& surface_ids);

    virtual status_t queueBufferToConsumer(sp<ANativeWindow>& consumer,
            ANativeWindowBuffer* buffer, int anwReleaseFence,
            const std::vector<size_t>& uniqueSurfaceIds);

    virtual status_t configureQueueLocked();

    virtual status_t disconnectLocked(bool force = false);

    virtual status_t getEndpointUsage(uint64_t *usage);

}; // class Camera3SharedOutputStream

} // namespace camera3

} // namespace android

#endif // ANDROID_SERVERS_CAMERA3_SHARED_OUTPUT_STREAM_H
