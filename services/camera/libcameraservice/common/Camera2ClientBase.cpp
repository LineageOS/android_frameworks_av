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
#include <gui/BufferItem.h>
#include <gui/BufferItemConsumer.h>
#include <gui/Surface.h>

#include <android/hardware/ICameraService.h>
#include <android/content/res/CameraCompatibilityInfo.h>
#include <camera/CameraSessionStats.h>
#include <camera/StringUtils.h>
#include <com_android_window_flags.h>
#include <com_android_internal_camera_flags.h>

#include "common/Camera2ClientBase.h"

#include "api2/CameraDeviceClient.h"

#include "device3/Camera3Device.h"
#include "device3/aidl/AidlCamera3Device.h"
#include "device3/hidl/HidlCamera3Device.h"
#include "device3/aidl/AidlCamera3SharedDevice.h"

namespace android {

using namespace camera2;

namespace wm_flags = com::android::window::flags;
namespace flags = com::android::internal::camera::flags;

// Interface used by CameraService

template <typename TClientBase>
Camera2ClientBase<TClientBase>::Camera2ClientBase(
        const sp<CameraService>& cameraService, const sp<TCamCallbacks>& remoteCallback,
        std::shared_ptr<CameraServiceProxyWrapper> cameraServiceProxyWrapper,
        std::shared_ptr<AttributionAndPermissionUtils> attributionAndPermissionUtils,
        const AttributionSourceState& clientAttribution, int callingPid, bool systemNativeClient,
        const std::string& cameraId, int api1CameraId, int cameraFacing, int sensorOrientation,
        int servicePid, bool overrideForPerfClass, const CameraCompatibilityInfo& compatInfo,
        bool sharedMode, bool isVendorClient, bool legacyClient)
    : TClientBase(cameraService, remoteCallback, attributionAndPermissionUtils, clientAttribution,
                  callingPid, systemNativeClient, cameraId, api1CameraId, cameraFacing,
                  sensorOrientation, servicePid, compatInfo, sharedMode),
      mSharedCameraCallbacks(remoteCallback),
      mCameraServiceProxyWrapper(cameraServiceProxyWrapper),
      mDeviceActive(false),
      mApi1CameraId(api1CameraId) {
    ALOGV("Camera %s: Opened. Client: %s (PID %d, UID %d)", cameraId.c_str(),
          TClientBase::getPackageName().c_str(), TClientBase::mCallingPid,
          TClientBase::getClientUid());

    mInitialClientPid = TClientBase::mCallingPid;
    mOverrideForPerfClass = overrideForPerfClass;
    mLegacyClient = legacyClient;
    mIsVendorClient = isVendorClient;
}

template <typename TClientBase>
status_t Camera2ClientBase<TClientBase>::checkPid(const char* checkLocation)
        const {

    int callingPid = TClientBase::getCallingPid();
    if (callingPid == TClientBase::mCallingPid) return NO_ERROR;

    ALOGE("%s: attempt to use a locked camera from a different process"
            " (old pid %d, new pid %d)", checkLocation, TClientBase::mCallingPid, callingPid);
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
                            TClientBase::mAttributionAndPermissionUtils,
                            TClientBase::mCameraIdStr, mOverrideForPerfClass,
                            TClientBase::mCompatInfo, mIsVendorClient,
                            mLegacyClient);
            break;
        case IPCTransport::AIDL:
            if (flags::camera_multi_client() && TClientBase::mSharedMode) {
                mDevice = AidlCamera3SharedDevice::getInstance(mCameraServiceProxyWrapper,
                            TClientBase::mAttributionAndPermissionUtils,
                            TClientBase::mCameraIdStr, mOverrideForPerfClass,
                            TClientBase::mCompatInfo, mIsVendorClient,
                            mLegacyClient);
            } else {
                mDevice =
                    new AidlCamera3Device(mCameraServiceProxyWrapper,
                            TClientBase::mAttributionAndPermissionUtils,
                            TClientBase::mCameraIdStr, mOverrideForPerfClass,
                            TClientBase::mCompatInfo, mIsVendorClient,
                            mLegacyClient);
            }
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

    // Notify camera opening (check op if check_full_attribution_source_chain flag is off).
    res = TClientBase::notifyCameraOpening();
    if (res != OK) {
        TClientBase::notifyCameraClosing();
        return res;
    }

    res = mDevice->initialize(providerPtr, monitorTags);
    if (res != OK) {
        ALOGE("%s: Camera %s: unable to initialize device: %s (%d)",
                __FUNCTION__, TClientBase::mCameraIdStr.c_str(), strerror(-res), res);
        TClientBase::notifyCameraClosing();
        return res;
    }

    wp<NotificationListener> weakThis(this);
    res = mDevice->setNotifyCallback(weakThis);
    if (res != OK) {
        ALOGE("%s: Camera %s: Unable to set notify callback: %s (%d)",
                __FUNCTION__, TClientBase::mCameraIdStr.c_str(), strerror(-res), res);
        return res;
    }

    return OK;
}

template <typename TClientBase>
Camera2ClientBase<TClientBase>::~Camera2ClientBase() {
    ATRACE_CALL();

    if (!flags::camera_multi_client() || !TClientBase::mDisconnected) {
        TClientBase::mDestructionStarted = true;
        disconnect();
    }

    ALOGV("%s: Client object's dtor for Camera Id %s completed. Client was: %s (PID %d, UID %u)",
          __FUNCTION__, TClientBase::mCameraIdStr.c_str(), TClientBase::getPackageName().c_str(),
          mInitialClientPid, TClientBase::getClientUid());
}

template <typename TClientBase>
status_t Camera2ClientBase<TClientBase>::dumpClient(int fd,
                                              const Vector<String16>& args,
                                              bool /*ignoreResult*/) {
    std::string result;
    result += fmt::sprintf("Camera2ClientBase[%s] (%p) PID: %d, dump:\n",
            TClientBase::mCameraIdStr.c_str(),
            (TClientBase::getRemoteCallback() != NULL ?
                    (void *)IInterface::asBinder(TClientBase::getRemoteCallback()).get() : NULL),
            TClientBase::mCallingPid);
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

   if (!flags::camera_multi_client() || !TClientBase::mDisconnected) {
       return disconnectImpl();
   }
   return binder::Status::ok();
}

template <typename TClientBase>
binder::Status Camera2ClientBase<TClientBase>::disconnectImpl() {
    ATRACE_CALL();
    ALOGV("Camera %s: start to disconnect", TClientBase::mCameraIdStr.c_str());
    Mutex::Autolock icl(mBinderSerializationLock);

    ALOGV("Camera %s: serializationLock acquired", TClientBase::mCameraIdStr.c_str());
    binder::Status res = binder::Status::ok();
    // Allow both client and the media server to disconnect at all times
    int callingPid = TClientBase::getCallingPid();
    if (callingPid != TClientBase::mCallingPid &&
        callingPid != TClientBase::mServicePid) return res;

    ALOGD("Camera %s: Shutting down", TClientBase::mCameraIdStr.c_str());

    // Before detaching the device, cache the info from current open session.
    // The disconnected check avoids duplication of info and also prevents
    // deadlock while acquiring service lock in cacheDump.
    if (!TClientBase::mDisconnected) {
        ALOGV("Camera %s: start to cacheDump", TClientBase::mCameraIdStr.c_str());
        Camera2ClientBase::getCameraService()->cacheDump(TClientBase::mCameraIdStr);
    }

    detachDevice();

    CameraService::BasicClient::disconnect();

    ALOGV("Camera %s: Shut down complete", TClientBase::mCameraIdStr.c_str());

    return res;
}

template <typename TClientBase>
void Camera2ClientBase<TClientBase>::detachDevice() {
    if (mDevice == 0) return;
    if (flags::camera_multi_client() && TClientBase::mSharedMode) {
        mDevice->disconnectClient(TClientBase::getClientCallingPid());
    } else {
        mDevice->disconnect();
    }

    ALOGV("Camera %s: Detach complete", TClientBase::mCameraIdStr.c_str());
}

template <typename TClientBase>
status_t Camera2ClientBase<TClientBase>::connect(
        const sp<TCamCallbacks>& client) {
    ATRACE_CALL();
    ALOGV("%s: E", __FUNCTION__);
    Mutex::Autolock icl(mBinderSerializationLock);

    if (TClientBase::mCallingPid != 0 &&
        TClientBase::getCallingPid() != TClientBase::mCallingPid) {

        ALOGE("%s: Camera %s: Connection attempt from pid %d; "
                "current locked to pid %d",
                __FUNCTION__,
                TClientBase::mCameraIdStr.c_str(),
                TClientBase::getCallingPid(),
                TClientBase::mCallingPid);
        return BAD_VALUE;
    }

    TClientBase::mCallingPid = TClientBase::getCallingPid();

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
void Camera2ClientBase<TClientBase>::notifyClientSharedAccessPriorityChanged(bool primaryClient) {
    ALOGV("%s Camera %s access priorities changed for client %d primaryClient=%d", __FUNCTION__,
            TClientBase::mCameraIdStr.c_str(), TClientBase::getClientUid(), primaryClient);
}

template <typename TClientBase>
void Camera2ClientBase<TClientBase>::notifyPhysicalCameraChange(const std::string &physicalId) {
    using android::hardware::ICameraService;
    // We're only interested in this notification if compatInfo is turned on.
    if (!TClientBase::mCompatInfo.shouldRotateAndCrop()
        && !TClientBase::mCompatInfo.shouldOverrideSensorOrientation()) {
        return;
    }

    auto physicalCameraMetadata = mDevice->infoPhysical(physicalId);
    auto orientationEntry = physicalCameraMetadata.find(ANDROID_SENSOR_ORIENTATION);

    if (orientationEntry.count == 1) {
        int rotateAndCropMode = ANDROID_SCALER_ROTATE_AND_CROP_NONE;
        std::optional<ui::Rotation> rotateAndCropRotation = TClientBase::mCompatInfo
                .getRotateAndCropRotation();
        if (rotateAndCropRotation.has_value() && rotateAndCropRotation.value() == ui::ROTATION_90) {
            rotateAndCropMode = ANDROID_SCALER_ROTATE_AND_CROP_90;
        } else if (rotateAndCropRotation.has_value() && rotateAndCropRotation.value() ==
                ui::ROTATION_270) {
            rotateAndCropMode = ANDROID_SCALER_ROTATE_AND_CROP_270;
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
        std::pair<int32_t, int32_t> mostRequestedFpsRange,
        const std::vector<hardware::CameraStreamStats>& streamStats,
        const std::string& userTag, int videoStabilizationMode, bool usedUltraWide,
        bool usedZoomOverride) {
    if (mDeviceActive) {
        status_t res = TClientBase::finishCameraStreamingOps();
        if (res != OK) {
            ALOGE("%s: Camera %s: Error finishing streaming ops: %d", __FUNCTION__,
                    TClientBase::mCameraIdStr.c_str(), res);
        }
        mCameraServiceProxyWrapper->logIdle(TClientBase::mCameraIdStr,
                requestCount, resultErrorCount, deviceError, userTag, videoStabilizationMode,
                usedUltraWide, usedZoomOverride, mostRequestedFpsRange, streamStats);
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

template <typename TClientBase>
status_t Camera2ClientBase<TClientBase>::injectSessionParams(
    const CameraMetadata& sessionParams) {
    return mDevice->injectSessionParams(sessionParams);
}

template class Camera2ClientBase<CameraService::Client>;
template class Camera2ClientBase<CameraDeviceClientBase>;

} // namespace android
