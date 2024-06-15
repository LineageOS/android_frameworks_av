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

//#define LOG_NDEBUG 0
#define LOG_TAG "ACameraCaptureSession"

#include "ACameraCaptureSession.h"

using namespace android;

ACameraCaptureSession::~ACameraCaptureSession() {
    ALOGV("~ACameraCaptureSession: %p notify device end of life", this);
#ifdef __ANDROID_VNDK__
    std::shared_ptr<acam::CameraDevice> dev = getDevicePtr();
#else
    sp<acam::CameraDevice> dev = getDeviceSp();
#endif
    if (dev != nullptr && !dev->isClosed()) {
        dev->lockDeviceForSessionOps();
        {
            Mutex::Autolock _l(mSessionLock);
            dev->notifySessionEndOfLifeLocked(this);
        }
        dev->unlockDevice();
    }
    // Fire onClosed callback
    if (mUserSessionCallback.onClosed != nullptr) {
        (*mUserSessionCallback.onClosed)(mUserSessionCallback.context, this);
    }
    ALOGV("~ACameraCaptureSession: %p is deleted", this);
}

void
ACameraCaptureSession::closeByApp() {
    {
        Mutex::Autolock _l(mSessionLock);
        if (mClosedByApp) {
            // Do not close twice
            return;
        }
        mClosedByApp = true;
    }

#ifdef __ANDROID_VNDK__
    std::shared_ptr<acam::CameraDevice> dev = getDevicePtr();
#else
    sp<acam::CameraDevice> dev = getDeviceSp();
#endif
    if (dev != nullptr) {
        dev->lockDeviceForSessionOps();
    }

    {
        Mutex::Autolock _l(mSessionLock);

        if (!mIsClosed && dev != nullptr) {
            camera_status_t ret = dev->stopRepeatingLocked();
            if (ret != ACAMERA_OK) {
                ALOGE("Stop repeating request failed while closing session %p", this);
            }
        }
        mIsClosed = true;
    }

    if (dev != nullptr) {
        dev->unlockDevice();
    }
    this->decStrong((void*) ACameraDevice_createCaptureSession);
}

camera_status_t
ACameraCaptureSession::stopRepeating() {
#ifdef __ANDROID_VNDK__
    std::shared_ptr<acam::CameraDevice> dev = getDevicePtr();
#else
    sp<acam::CameraDevice> dev = getDeviceSp();
#endif
    if (dev == nullptr) {
        ALOGE("Error: Device associated with session %p has been closed!", this);
        return ACAMERA_ERROR_SESSION_CLOSED;
    }

    camera_status_t ret;
    dev->lockDeviceForSessionOps();
    {
        Mutex::Autolock _l(mSessionLock);
        ret = dev->stopRepeatingLocked();
    }
    dev->unlockDevice();
    return ret;
}

camera_status_t
ACameraCaptureSession::abortCaptures() {
#ifdef __ANDROID_VNDK__
    std::shared_ptr<acam::CameraDevice> dev = getDevicePtr();
#else
    sp<acam::CameraDevice> dev = getDeviceSp();
#endif
    if (dev == nullptr) {
        ALOGE("Error: Device associated with session %p has been closed!", this);
        return ACAMERA_ERROR_SESSION_CLOSED;
    }

    camera_status_t ret;
    dev->lockDeviceForSessionOps();
    {
        Mutex::Autolock _l(mSessionLock);
        ret = dev->flushLocked(this);
    }
    dev->unlockDevice();
    return ret;
}

camera_status_t ACameraCaptureSession::updateOutputConfiguration(ACaptureSessionOutput *output) {
#ifdef __ANDROID_VNDK__
    std::shared_ptr<acam::CameraDevice> dev = getDevicePtr();
#else
    sp<acam::CameraDevice> dev = getDeviceSp();
#endif
    if (dev == nullptr) {
        ALOGE("Error: Device associated with session %p has been closed!", this);
        return ACAMERA_ERROR_SESSION_CLOSED;
    }

    camera_status_t ret;
    dev->lockDeviceForSessionOps();
    {
        Mutex::Autolock _l(mSessionLock);
        ret = dev->updateOutputConfigurationLocked(output);
    }
    dev->unlockDevice();
    return ret;
}

camera_status_t ACameraCaptureSession::prepare(ANativeWindow* window) {
#ifdef __ANDROID_VNDK__
    std::shared_ptr<acam::CameraDevice> dev = getDevicePtr();
#else
    sp<acam::CameraDevice> dev = getDeviceSp();
#endif
    if (dev == nullptr) {
        ALOGE("Error: Device associated with session %p has been closed!", this);
        return ACAMERA_ERROR_SESSION_CLOSED;
    }

    camera_status_t ret;
    dev->lockDeviceForSessionOps();
    {
        Mutex::Autolock _l(mSessionLock);
        ret = dev->prepareLocked(window);
    }
    dev->unlockDevice();
    return ret;
}

ACameraDevice*
ACameraCaptureSession::getDevice() {
    Mutex::Autolock _l(mSessionLock);
#ifdef __ANDROID_VNDK__
    std::shared_ptr<acam::CameraDevice> dev = getDevicePtr();
#else
    sp<acam::CameraDevice> dev = getDeviceSp();
#endif
    if (dev == nullptr) {
        ALOGE("Error: Device associated with session %p has been closed!", this);
        return nullptr;
    }
    return dev->getWrapper();
}

void
ACameraCaptureSession::closeByDevice() {
    Mutex::Autolock _l(mSessionLock);
    mIsClosed = true;
}

#ifdef __ANDROID_VNDK__
std::shared_ptr<acam::CameraDevice>
ACameraCaptureSession::getDevicePtr() {
    std::shared_ptr<acam::CameraDevice> device = mDevice.lock();
    if (device == nullptr || device->isClosed()) {
        ALOGW("Device is closed but session %d is not notified", mId);
        return nullptr;
    }
    return device;
}
#else
sp<acam::CameraDevice>
ACameraCaptureSession::getDeviceSp() {
    sp<acam::CameraDevice> device = mDevice.promote();
    if (device == nullptr || device->isClosed()) {
        ALOGW("Device is closed but session %d is not notified", mId);
        return nullptr;
    }
    return device;
}
#endif
