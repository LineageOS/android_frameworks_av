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

#include "Camera3SharedOutputStream.h"

namespace android {

namespace camera3 {

Camera3SharedOutputStream::Camera3SharedOutputStream(int id,
        const std::vector<sp<Surface>>& surfaces,
        bool hasDeferredSurface,
        uint32_t width, uint32_t height, int format,
        uint32_t consumerUsage, android_dataspace dataSpace,
        camera3_stream_rotation_t rotation,
        nsecs_t timestampOffset, int setId) :
        Camera3OutputStream(id, CAMERA3_STREAM_OUTPUT, width, height,
                            format, dataSpace, rotation, consumerUsage,
                            timestampOffset, setId),
        mSurfaces(surfaces),
        mDeferred(hasDeferredSurface) {
}

Camera3SharedOutputStream::~Camera3SharedOutputStream() {
    disconnectLocked();
}

status_t Camera3SharedOutputStream::connectStreamSplitterLocked() {
    status_t res = OK;

    mStreamSplitter = new Camera3StreamSplitter();

    uint32_t usage;
    getEndpointUsage(&usage);

    res = mStreamSplitter->connect(mSurfaces, usage, camera3_stream::max_buffers, mConsumer);
    if (res != OK) {
        ALOGE("%s: Failed to connect to stream splitter: %s(%d)",
                __FUNCTION__, strerror(-res), res);
        return res;
    }

    return res;
}

status_t Camera3SharedOutputStream::notifyRequestedSurfaces(uint32_t /*frame_number*/,
        const std::vector<size_t>& surface_ids) {
    Mutex::Autolock l(mLock);
    status_t res = OK;

    if (mStreamSplitter != nullptr) {
        res = mStreamSplitter->notifyRequestedSurfaces(surface_ids);
    }

    return res;
}

bool Camera3SharedOutputStream::isConsumerConfigurationDeferred(size_t surface_id) const {
    Mutex::Autolock l(mLock);
    return (mDeferred && surface_id >= mSurfaces.size());
}

status_t Camera3SharedOutputStream::setConsumer(sp<Surface> surface) {
    if (surface == nullptr) {
        ALOGE("%s: it's illegal to set a null consumer surface!", __FUNCTION__);
        return INVALID_OPERATION;
    }

    if (!mDeferred) {
        ALOGE("%s: Current stream isn't deferred!", __FUNCTION__);
        return INVALID_OPERATION;
    }

    mSurfaces.push_back(surface);

    return mStreamSplitter->addOutput(surface, camera3_stream::max_buffers);
}

status_t Camera3SharedOutputStream::configureQueueLocked() {
    status_t res;

    if ((res = Camera3IOStreamBase::configureQueueLocked()) != OK) {
        return res;
    }

    res = connectStreamSplitterLocked();
    if (res != OK) {
        ALOGE("Cannot connect to stream splitter: %s(%d)", strerror(-res), res);
        return res;
    }

    res = configureConsumerQueueLocked();
    if (res != OK) {
        ALOGE("Failed to configureConsumerQueueLocked: %s(%d)", strerror(-res), res);
        return res;
    }

    return OK;
}

status_t Camera3SharedOutputStream::disconnectLocked() {
    status_t res;
    res = Camera3OutputStream::disconnectLocked();

    if (mStreamSplitter != nullptr) {
        mStreamSplitter->disconnect();
    }

    return res;
}

status_t Camera3SharedOutputStream::getEndpointUsage(uint32_t *usage) const {

    status_t res;
    uint32_t u = 0;

    if (mConsumer == nullptr) {
        // Called before shared buffer queue is constructed.
        *usage = getPresetConsumerUsage();

        for (auto surface : mSurfaces) {
            if (surface != nullptr) {
                res = getEndpointUsageForSurface(&u, surface);
                *usage |= u;
            }
        }
    } else {
        // Called after shared buffer queue is constructed.
        res = getEndpointUsageForSurface(&u, mConsumer);
        *usage |= u;
    }

    return res;
}

} // namespace camera3

} // namespace android
