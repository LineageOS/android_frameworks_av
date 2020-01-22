/*
 * Copyright (C) 2019 The Android Open Source Project
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

#ifndef ANDROID_SERVERS_CAMERA_CAMERAOFFLINESESSIONBASE_H
#define ANDROID_SERVERS_CAMERA_CAMERAOFFLINESESSIONBASE_H

#include <utils/RefBase.h>
#include <utils/String8.h>
#include <utils/Timers.h>

#include "camera/CaptureResult.h"

namespace android {

/**
 * Abstract class for HAL notification listeners
 */
class NotificationListener : public virtual RefBase {
  public:
    // The set of notifications is a merge of the notifications required for
    // API1 and API2.

    // Required for API 1 and 2
    virtual void notifyError(int32_t errorCode,
                             const CaptureResultExtras &resultExtras) = 0;

    // Required only for API2
    virtual void notifyIdle() = 0;
    virtual void notifyShutter(const CaptureResultExtras &resultExtras,
            nsecs_t timestamp) = 0;
    virtual void notifyPrepared(int streamId) = 0;
    virtual void notifyRequestQueueEmpty() = 0;

    // Required only for API1
    virtual void notifyAutoFocus(uint8_t newState, int triggerId) = 0;
    virtual void notifyAutoExposure(uint8_t newState, int triggerId) = 0;
    virtual void notifyAutoWhitebalance(uint8_t newState,
            int triggerId) = 0;
    virtual void notifyRepeatingRequestError(long lastFrameNumber) = 0;
  protected:
    virtual ~NotificationListener() {}
};

class CameraOfflineSessionBase : public virtual RefBase {
  public:
    virtual ~CameraOfflineSessionBase();

    virtual status_t initialize(
            wp<NotificationListener> listener) = 0;

    // The session's original camera ID
    virtual const String8& getId() const = 0;

    virtual status_t disconnect() = 0;

    virtual status_t dump(int fd) = 0;

    /**
     * Capture result passing
     */
    virtual status_t waitForNextFrame(nsecs_t timeout) = 0;

    virtual status_t getNextResult(CaptureResult *frame) = 0;

    // TODO: notification passing path
}; // class CameraOfflineSessionBase

} // namespace android

#endif
