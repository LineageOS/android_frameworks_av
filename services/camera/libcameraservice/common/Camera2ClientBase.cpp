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

#define LOG_TAG "Camera2ClientBase"
#define ATRACE_TAG ATRACE_TAG_CAMERA
//#define LOG_NDEBUG 0

#include <inttypes.h>

#include <utils/Log.h>
#include <utils/Trace.h>

#include <cutils/properties.h>
#include <gui/Surface.h>
#include <gui/Surface.h>

#include <camera/CameraSessionStats.h>
#include <camera/StringUtils.h>

#include "common/Camera2ClientBase.h"

#include "api2/CameraDeviceClient.h"

#include "device3/Camera3Device.h"
#include "device3/aidl/AidlCamera3Device.h"
#include "device3/hidl/HidlCamera3Device.h"
#include "utils/CameraThreadState.h"

namespace android {

using namespace camera2;

// Interface used by CameraService

template <typename TClientBase>
Camera2ClientBase<TClientBase>::Camera2ClientBase(
        const sp<CameraService>& cameraService,
        const sp<TCamCallbacks>& remoteCallback,
        std::shared_ptr<CameraServiceProxyWrapper> cameraServiceProxyWrapper,
        const std::string& clientPackageName,
        bool systemNativeClient,
        const std::optional<std::string>& clientFeatureId,
        const std::string& cameraId,
        int api1CameraId,
        int cameraFacing,
        int sensorOrientation,
        int clientPid,
        uid_t clientUid,
        int servicePid,
        bool overrideForPerfClass,
        bool overrideToPortrait,
        bool legacyClient):
        TClientBase(cameraService, remoteCallback, clientPackageName, systemNativeClient,
                clientFeatureId, cameraId, api1CameraId, cameraFacing, sensorOrientation, clientPid,
                clientUid, servicePid, overrideToPortrait),
        mSharedCameraCallbacks(remoteCallback),
        mCameraServiceProxyWrapper(cameraServiceProxyWrapper),
        mDeviceActive(false), mApi1CameraId(api1CameraId)
{
    ALOGI("Camera %s: Opened. Client: %s (PID %d, UID %d)", cameraId.c_str(),
            clientPackageName.c_str(), clientPid, clientUid);

    mInitialClientPid = clientPid;
    mOverrideForPerfClass = overrideForPerfClass;
    mLegacyClient = legacyClient;
}

template <typename TClientBase>
status_t Camera2ClientBase<TClientBase>::checkPid(const char* checkLocation)
        const {

    int callingPid = CameraThreadState::getCallingPid();
    if (callingPid == TClientBase::mClientPid) return NO_ERROR;

    ALOGE("%s: attempt to use a locked camera from a different process"
            " (old pid %d, new pid %d)", checkLocation, TClientBase::mClientPid, callingPid);
    return PERMISSION_DENIED;
}

template <typename TClientBase>
status_t Camera2ClientBase<TClientBase>::initialize(sp<CameraProviderManager> manager,
        const std::string& monitorTags) {
    return initializeImpl(manager, monitorTags);
}

template <typename TClientBase>
template <typename TProviderPtr>
status_t Camera2ClientBase<TClientBase>::initializeImpl(TProviderPtr providerPtr,
        const std::string& monitorTags) {
    ATRACE_CALL();
    ALOGV("%s: Initializing client for camera %s", __FUNCTION__,
          TClientBase::mCameraIdStr.c_str());
    status_t res;

    IPCTransport providerTransport = IPCTransport::INVALID;
    res = providerPtr->getCameraIdIPCTransport(TClientBase::mCameraIdStr,
            &providerTransport);
    if (res != OK) {
        return res;
    }
    switch (providerTransport) {
        case IPCTransport::HIDL:
            mDevice =
                    new HidlCamera3Device(mCameraServiceProxyWrapper,
                            TClientBase::mCameraIdStr, mOverrideForPerfClass,
                            TClientBase::mOverrideToPortrait, mLegacyClient);
            break;
        case IPCTransport::AIDL:
            mDevice =
                    new AidlCamera3Device(mCameraServiceProxyWrapper,
                            TClientBase::mCameraIdStr, mOverrideForPerfClass,
                            TClientBase::mOverrideToPortrait, mLegacyClient);
             break;
        default:
            ALOGE("%s Invalid transport for camera id %s", __FUNCTION__,
                    TClientBase::mCameraIdStr.c_str());
            return NO_INIT;
    }
    if (mDevice == NULL) {
        ALOGE("%s: Camera %s: No device connected",
                __FUNCTION__, TClientBase::mCameraIdStr.c_str());
        return NO_INIT;
    }

    res = mDevice->initialize(providerPtr, monitorTags);
    if (res != OK) {
        ALOGE("%s: Camera %s: unable to initialize device: %s (%d)",
                __FUNCTION__, TClientBase::mCameraIdStr.c_str(), strerror(-res), res);
        return res;
    }

    // Verify ops permissions
    res = TClientBase::startCameraOps();
    if (res != OK) {
        TClientBase::finishCameraOps();
        return res;
    }

    wp<NotificationListener> weakThis(this);
    res = mDevice->setNotifyCallback(weakThis);
    if (res != OK) {
        ALOGE("%s: Camera %s: Unable to set notify callback: %s (%d)",
                __FUNCTION__, TClientBase::mCameraIdStr.c_str(), strerror(-res), res);
        return res;
    }

    /** Start watchdog thread */
    mCameraServiceWatchdog = new CameraServiceWatchdog(TClientBase::mCameraIdStr,
            mCameraServiceProxyWrapper);
    res = mCameraServiceWatchdog->run("Camera2ClientBaseWatchdog");
    if (res != OK) {
        ALOGE("%s: Unable to start camera service watchdog thread: %s (%d)",
                __FUNCTION__, strerror(-res), res);
        return res;
    }

    return OK;
}

template <typename TClientBase>
Camera2ClientBase<TClientBase>::~Camera2ClientBase() {
    ATRACE_CALL();

    TClientBase::mDestructionStarted = true;

    disconnect();

    if (mCameraServiceWatchdog != NULL) {
        mCameraServiceWatchdog->requestExit();
        mCameraServiceWatchdog.clear();
    }

    ALOGI("%s: Client object's dtor for Camera Id %s completed. Client was: %s (PID %d, UID %u)",
            __FUNCTION__, TClientBase::mCameraIdStr.c_str(),
            TClientBase::mClientPackageName.c_str(),
            mInitialClientPid, TClientBase::mClientUid);
}

template <typename TClientBase>
status_t Camera2ClientBase<TClientBase>::dumpClient(int fd,
                                              const Vector<String16>& args) {
    std::string result;
    result += fmt::sprintf("Camera2ClientBase[%s] (%p) PID: %d, dump:\n",
            TClientBase::mCameraIdStr.c_str(),
            (TClientBase::getRemoteCallback() != NULL ?
                    (void *)IInterface::asBinder(TClientBase::getRemoteCallback()).get() : NULL),
            TClientBase::mClientPid);
    result += "  State: ";

    write(fd, result.c_str(), result.size());
    // TODO: print dynamic/request section from most recent requests

    return dumpDevice(fd, args);
}

template <typename TClientBase>
status_t Camera2ClientBase<TClientBase>::startWatchingTags(const std::string &tags, int out) {
  sp<CameraDeviceBase> device = mDevice;
  if (!device) {
    dprintf(out, "  Device is detached");
    return OK;
  }

  return device->startWatchingTags(tags);
}

template <typename TClientBase>
status_t Camera2ClientBase<TClientBase>::stopWatchingTags(int out) {
  sp<CameraDeviceBase> device = mDevice;
  if (!device) {
    dprintf(out, "  Device is detached");
    return OK;
  }

  return device->stopWatchingTags();
}

template <typename TClientBase>
status_t Camera2ClientBase<TClientBase>::dumpWatchedEventsToVector(std::vector<std::string> &out) {
    sp<CameraDeviceBase> device = mDevice;
    if (!device) {
        // Nothing to dump if the device is detached
        return OK;
    }
    return device->dumpWatchedEventsToVector(out);
}

template <typename TClientBase>
status_t Camera2ClientBase<TClientBase>::dumpDevice(
                                                int fd,
                                                const Vector<String16>& args) {
    std::string result;

    result = "  Device dump:\n";
    write(fd, result.c_str(), result.size());

    sp<CameraDeviceBase> device = mDevice;
    if (!device.get()) {
        result = "  *** Device is detached\n";
        write(fd, result.c_str(), result.size());
        return NO_ERROR;
    }

    status_t res = device->dump(fd, args);
    if (res != OK) {
        result = fmt::sprintf("   Error dumping device: %s (%d)",
                strerror(-res), res);
        write(fd, result.c_str(), result.size());
    }

    return NO_ERROR;
}

// ICameraClient2BaseUser interface

template <typename TClientBase>
binder::Status Camera2ClientBase<TClientBase>::disconnect() {
    if (mCameraServiceWatchdog != nullptr && mDevice != nullptr) {
        // Timer for the disconnect call should be greater than getExpectedInFlightDuration
        // since this duration is used to error handle methods in the disconnect sequence
        // thus allowing existing error handling methods to execute first
        uint64_t maxExpectedDuration =
                ns2ms(mDevice->getExpectedInFlightDuration() + kBufferTimeDisconnectNs);

        // Initialization from hal succeeded, time disconnect.
        return mCameraServiceWatchdog->WATCH_CUSTOM_TIMER(disconnectImpl(),
                maxExpectedDuration / kCycleLengthMs, kCycleLengthMs);
    }
    return disconnectImpl();
}

template <typename TClientBase>
binder::Status Camera2ClientBase<TClientBase>::disconnectImpl() {
    ATRACE_CALL();
    ALOGD("Camera %s: start to disconnect", TClientBase::mCameraIdStr.c_str());
    Mutex::Autolock icl(mBinderSerializationLock);

    ALOGD("Camera %s: serializationLock acquired", TClientBase::mCameraIdStr.c_str());
    binder::Status res = binder::Status::ok();
    // Allow both client and the media server to disconnect at all times
    int callingPid = CameraThreadState::getCallingPid();
    if (callingPid != TClientBase::mClientPid &&
        callingPid != TClientBase::mServicePid) return res;

    ALOGD("Camera %s: Shutting down", TClientBase::mCameraIdStr.c_str());

    // Before detaching the device, cache the info from current open session.
    // The disconnected check avoids duplication of info and also prevents
    // deadlock while acquiring service lock in cacheDump.
    if (!TClientBase::mDisconnected) {
        ALOGD("Camera %s: start to cacheDump", TClientBase::mCameraIdStr.c_str());
        Camera2ClientBase::getCameraService()->cacheDump();
    }

    detachDevice();

    CameraService::BasicClient::disconnect();

    ALOGV("Camera %s: Shut down complete", TClientBase::mCameraIdStr.c_str());

    return res;
}

template <typename TClientBase>
void Camera2ClientBase<TClientBase>::detachDevice() {
    if (mDevice == 0) return;
    mDevice->disconnect();

    ALOGV("Camera %s: Detach complete", TClientBase::mCameraIdStr.c_str());
}

template <typename TClientBase>
status_t Camera2ClientBase<TClientBase>::connect(
        const sp<TCamCallbacks>& client) {
    ATRACE_CALL();
    ALOGV("%s: E", __FUNCTION__);
    Mutex::Autolock icl(mBinderSerializationLock);

    if (TClientBase::mClientPid != 0 &&
        CameraThreadState::getCallingPid() != TClientBase::mClientPid) {

        ALOGE("%s: Camera %s: Connection attempt from pid %d; "
                "current locked to pid %d",
                __FUNCTION__,
                TClientBase::mCameraIdStr.c_str(),
                CameraThreadState::getCallingPid(),
                TClientBase::mClientPid);
        return BAD_VALUE;
    }

    TClientBase::mClientPid = CameraThreadState::getCallingPid();

    TClientBase::mRemoteCallback = client;
    mSharedCameraCallbacks = client;

    return OK;
}

/** Device-related methods */

template <typename TClientBase>
void Camera2ClientBase<TClientBase>::notifyError(
        int32_t errorCode,
        const CaptureResultExtras& resultExtras) {
    ALOGE("Error condition %d reported by HAL, requestId %" PRId32, errorCode,
          resultExtras.requestId);
}

template <typename TClientBase>
void Camera2ClientBase<TClientBase>::notifyPhysicalCameraChange(const std::string &physicalId) {
    // We're only interested in this notification if overrideToPortrait is turned on.
    if (!TClientBase::mOverrideToPortrait) {
        return;
    }

    auto physicalCameraMetadata = mDevice->infoPhysical(physicalId);
    auto orientationEntry = physicalCameraMetadata.find(ANDROID_SENSOR_ORIENTATION);

    if (orientationEntry.count == 1) {
        int orientation = orientationEntry.data.i32[0];
        int rotateAndCropMode = ANDROID_SCALER_ROTATE_AND_CROP_NONE;

        if (orientation == 0 || orientation == 180) {
            rotateAndCropMode = ANDROID_SCALER_ROTATE_AND_CROP_90;
        }

        static_cast<TClientBase *>(this)->setRotateAndCropOverride(rotateAndCropMode,
                                                                   /*fromHal*/ true);
    }
}

template <typename TClientBase>
status_t Camera2ClientBase<TClientBase>::notifyActive(float maxPreviewFps) {
    if (!mDeviceActive) {
        status_t res = TClientBase::startCameraStreamingOps();
        if (res != OK) {
            ALOGE("%s: Camera %s: Error starting camera streaming ops: %d", __FUNCTION__,
                    TClientBase::mCameraIdStr.c_str(), res);
            return res;
        }
        mCameraServiceProxyWrapper->logActive(TClientBase::mCameraIdStr, maxPreviewFps);
    }
    mDeviceActive = true;

    ALOGV("Camera device is now active");
    return OK;
}

template <typename TClientBase>
void Camera2ClientBase<TClientBase>::notifyIdleWithUserTag(
        int64_t requestCount, int64_t resultErrorCount, bool deviceError,
        const std::vector<hardware::CameraStreamStats>& streamStats,
        const std::string& userTag, int videoStabilizationMode) {
    if (mDeviceActive) {
        status_t res = TClientBase::finishCameraStreamingOps();
        if (res != OK) {
            ALOGE("%s: Camera %s: Error finishing streaming ops: %d", __FUNCTION__,
                    TClientBase::mCameraIdStr.c_str(), res);
        }
        mCameraServiceProxyWrapper->logIdle(TClientBase::mCameraIdStr,
                requestCount, resultErrorCount, deviceError, userTag, videoStabilizationMode,
                streamStats);
    }
    mDeviceActive = false;

    ALOGV("Camera device is now idle");
}

template <typename TClientBase>
void Camera2ClientBase<TClientBase>::notifyShutter(
                [[maybe_unused]] const CaptureResultExtras& resultExtras,
                [[maybe_unused]] nsecs_t timestamp) {
    ALOGV("%s: Shutter notification for request id %" PRId32 " at time %" PRId64,
            __FUNCTION__, resultExtras.requestId, timestamp);
}

template <typename TClientBase>
void Camera2ClientBase<TClientBase>::notifyAutoFocus([[maybe_unused]] uint8_t newState,
                                                     [[maybe_unused]] int triggerId) {
    ALOGV("%s: Autofocus state now %d, last trigger %d",
          __FUNCTION__, newState, triggerId);

}

template <typename TClientBase>
void Camera2ClientBase<TClientBase>::notifyAutoExposure([[maybe_unused]] uint8_t newState,
                                                        [[maybe_unused]] int triggerId) {
    ALOGV("%s: Autoexposure state now %d, last trigger %d",
            __FUNCTION__, newState, triggerId);
}

template <typename TClientBase>
void Camera2ClientBase<TClientBase>::notifyAutoWhitebalance(
                [[maybe_unused]] uint8_t newState,
                [[maybe_unused]] int triggerId) {
    ALOGV("%s: Auto-whitebalance state now %d, last trigger %d",
            __FUNCTION__, newState, triggerId);
}

template <typename TClientBase>
void Camera2ClientBase<TClientBase>::notifyPrepared([[maybe_unused]] int streamId) {
    ALOGV("%s: Stream %d now prepared",
            __FUNCTION__, streamId);
}

template <typename TClientBase>
void Camera2ClientBase<TClientBase>::notifyRequestQueueEmpty() {

    ALOGV("%s: Request queue now empty", __FUNCTION__);
}

template <typename TClientBase>
void Camera2ClientBase<TClientBase>::notifyRepeatingRequestError(
            [[maybe_unused]] long lastFrameNumber) {
    ALOGV("%s: Repeating request was stopped. Last frame number is %ld",
            __FUNCTION__, lastFrameNumber);
}

template <typename TClientBase>
int Camera2ClientBase<TClientBase>::getCameraId() const {
    return mApi1CameraId;
}

template <typename TClientBase>
const sp<CameraDeviceBase>& Camera2ClientBase<TClientBase>::getCameraDevice() {
    return mDevice;
}

template <typename TClientBase>
const sp<CameraService>& Camera2ClientBase<TClientBase>::getCameraService() {
    return TClientBase::sCameraService;
}

template <typename TClientBase>
Camera2ClientBase<TClientBase>::SharedCameraCallbacks::Lock::Lock(
        SharedCameraCallbacks &client) :

        mRemoteCallback(client.mRemoteCallback),
        mSharedClient(client) {

    mSharedClient.mRemoteCallbackLock.lock();
}

template <typename TClientBase>
Camera2ClientBase<TClientBase>::SharedCameraCallbacks::Lock::~Lock() {
    mSharedClient.mRemoteCallbackLock.unlock();
}

template <typename TClientBase>
Camera2ClientBase<TClientBase>::SharedCameraCallbacks::SharedCameraCallbacks(
        const sp<TCamCallbacks>&client) :

        mRemoteCallback(client) {
}

template <typename TClientBase>
typename Camera2ClientBase<TClientBase>::SharedCameraCallbacks&
Camera2ClientBase<TClientBase>::SharedCameraCallbacks::operator=(
        const sp<TCamCallbacks>&client) {

    Mutex::Autolock l(mRemoteCallbackLock);
    mRemoteCallback = client;
    return *this;
}

template <typename TClientBase>
void Camera2ClientBase<TClientBase>::SharedCameraCallbacks::clear() {
    Mutex::Autolock l(mRemoteCallbackLock);
    mRemoteCallback.clear();
}

template <typename TClientBase>
status_t Camera2ClientBase<TClientBase>::injectCamera(const std::string& injectedCamId,
        sp<CameraProviderManager> manager) {
    return mDevice->injectCamera(injectedCamId, manager);
}

template <typename TClientBase>
status_t Camera2ClientBase<TClientBase>::stopInjection() {
    return mDevice->stopInjection();
}

template class Camera2ClientBase<CameraService::Client>;
template class Camera2ClientBase<CameraDeviceClientBase>;

} // namespace android
