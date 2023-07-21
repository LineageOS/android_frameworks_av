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

package android.hardware;

import android.hardware.ICamera;
import android.hardware.ICameraClient;
import android.hardware.camera2.ICameraDeviceUser;
import android.hardware.camera2.ICameraDeviceCallbacks;
import android.hardware.camera2.ICameraInjectionCallback;
import android.hardware.camera2.ICameraInjectionSession;
import android.hardware.camera2.params.VendorTagDescriptor;
import android.hardware.camera2.params.VendorTagDescriptorCache;
import android.hardware.camera2.utils.ConcurrentCameraIdCombination;
import android.hardware.camera2.utils.CameraIdAndSessionConfiguration;
import android.hardware.camera2.impl.CameraMetadataNative;
import android.hardware.ICameraServiceListener;
import android.hardware.CameraInfo;
import android.hardware.CameraIdRemapping;
import android.hardware.CameraStatus;
import android.hardware.CameraExtensionSessionStats;

/**
 * Binder interface for the native camera service running in mediaserver.
 *
 * @hide
 */
interface ICameraService
{
    /**
     * All camera service and device Binder calls may return a
     * ServiceSpecificException with the following error codes
     */
    const int ERROR_PERMISSION_DENIED = 1;
    const int ERROR_ALREADY_EXISTS = 2;
    const int ERROR_ILLEGAL_ARGUMENT = 3;
    const int ERROR_DISCONNECTED = 4;
    const int ERROR_TIMED_OUT = 5;
    const int ERROR_DISABLED = 6;
    const int ERROR_CAMERA_IN_USE = 7;
    const int ERROR_MAX_CAMERAS_IN_USE = 8;
    const int ERROR_DEPRECATED_HAL = 9;
    const int ERROR_INVALID_OPERATION = 10;

    /**
     * Types for getNumberOfCameras
     */
    const int CAMERA_TYPE_BACKWARD_COMPATIBLE = 0;
    const int CAMERA_TYPE_ALL = 1;

    /**
     * Return the number of camera devices available in the system
     */
    int getNumberOfCameras(int type);

    /**
     * Fetch basic camera information for a camera device
     */
    CameraInfo getCameraInfo(int cameraId, boolean overrideToPortrait);

    /**
     * Default UID/PID values for non-privileged callers of
     * connect() and connectDevice()
     */
    const int USE_CALLING_UID = -1;
    const int USE_CALLING_PID = -1;

    /**
     * Open a camera device through the old camera API
     */
    ICamera connect(ICameraClient client,
            int cameraId,
            @utf8InCpp String opPackageName,
            int clientUid, int clientPid,
            int targetSdkVersion,
            boolean overrideToPortrait,
            boolean forceSlowJpegMode);

    /**
     * Open a camera device through the new camera API
     * Only supported for device HAL versions >= 3.2
     */
    ICameraDeviceUser connectDevice(ICameraDeviceCallbacks callbacks,
            @utf8InCpp String cameraId,
            @utf8InCpp String opPackageName,
            @nullable @utf8InCpp String featureId,
            int clientUid, int oomScoreOffset,
            int targetSdkVersion,
            boolean overrideToPortrait);

    /**
     * Add listener for changes to camera device and flashlight state.
     *
     * Also returns the set of currently-known camera IDs and state of each device.
     * Adding a listener will trigger the torch status listener to fire for all
     * devices that have a flash unit.
     */
    CameraStatus[] addListener(ICameraServiceListener listener);

    /**
     * Get a list of combinations of camera ids which support concurrent streaming.
     *
     */
    ConcurrentCameraIdCombination[] getConcurrentCameraIds();

    /**
      * Check whether a particular set of session configurations are concurrently supported by the
      * corresponding camera ids.
      *
      * @param sessions the set of camera id and session configuration pairs to be queried.
      * @param targetSdkVersion the target sdk level of the application calling this function.
      * @return true  - the set of concurrent camera id and stream combinations is supported.
      *         false - the set of concurrent camera id and stream combinations is not supported
      *                 OR the method was called with a set of camera ids not returned by
      *                 getConcurrentCameraIds().
      */
    boolean isConcurrentSessionConfigurationSupported(
            in CameraIdAndSessionConfiguration[] sessions,
            int targetSdkVersion);

    /**
     * Remap Camera Ids in the CameraService.
     *
     * Once this is in effect, all binder calls in the ICameraService that
     * use logicalCameraId should consult remapping state to arrive at the
     * correct cameraId to perform the operation on.
     *
     * Note: Before the new cameraIdRemapping state is applied, the previous
     * state is cleared.
     *
     * @param cameraIdRemapping the camera ids to remap. Sending an unpopulated
     *        cameraIdRemapping object will result in clearing of any previous
     *        cameraIdRemapping state in the camera service.
     */
    void remapCameraIds(in CameraIdRemapping cameraIdRemapping);

    /**
     * Remove listener for changes to camera device and flashlight state.
     */
    void removeListener(ICameraServiceListener listener);

    /**
     * Read the static camera metadata for a camera device.
     * Only supported for device HAL versions >= 3.2
     */
    CameraMetadataNative getCameraCharacteristics(@utf8InCpp String cameraId, int targetSdkVersion,
            boolean overrideToPortrait);

    /**
     * Read in the vendor tag descriptors from the camera module HAL.
     * Intended to be used by the native code of CameraMetadataNative to correctly
     * interpret camera metadata with vendor tags.
     */
    VendorTagDescriptor getCameraVendorTagDescriptor();

    /**
     * Retrieve the vendor tag descriptor cache which can have multiple vendor
     * providers.
     * Intended to be used by the native code of CameraMetadataNative to correctly
     * interpret camera metadata with vendor tags.
     */
    VendorTagDescriptorCache getCameraVendorTagCache();

    /**
     * Read the legacy camera1 parameters into a String
     */
    @utf8InCpp String getLegacyParameters(int cameraId);

    /**
     * apiVersion constants for supportsCameraApi
     */
    const int API_VERSION_1 = 1;
    const int API_VERSION_2 = 2;

    // Determines if a particular API version is supported directly for a cameraId.
    boolean supportsCameraApi(@utf8InCpp String cameraId, int apiVersion);
    // Determines if a cameraId is a hidden physical camera of a logical multi-camera.
    boolean isHiddenPhysicalCamera(@utf8InCpp String cameraId);
    // Inject the external camera to replace the internal camera session.
    ICameraInjectionSession injectCamera(@utf8InCpp String packageName, @utf8InCpp String internalCamId,
            @utf8InCpp String externalCamId, in ICameraInjectionCallback CameraInjectionCallback);

    void setTorchMode(@utf8InCpp String cameraId, boolean enabled, IBinder clientBinder);

    // Change the brightness level of the flash unit associated with cameraId to strengthLevel.
    // If the torch is in OFF state and strengthLevel > 0 then the torch will also be turned ON.
    void turnOnTorchWithStrengthLevel(@utf8InCpp String cameraId, int strengthLevel, IBinder clientBinder);

    // Get the brightness level of the flash unit associated with cameraId.
    int getTorchStrengthLevel(@utf8InCpp String cameraId);

    /**
     * Notify the camera service of a system event.  Should only be called from system_server.
     *
     * Callers require the android.permission.CAMERA_SEND_SYSTEM_EVENTS permission.
     */
    const int EVENT_NONE = 0;
    const int EVENT_USER_SWITCHED = 1; // The argument is the set of new foreground user IDs.
    const int EVENT_USB_DEVICE_ATTACHED = 2; // The argument is the deviceId and vendorId
    const int EVENT_USB_DEVICE_DETACHED = 3; // The argument is the deviceId and vendorId
    oneway void notifySystemEvent(int eventId, in int[] args);

    /**
     * Notify the camera service of a display configuration change.
     *
     * Callers require the android.permission.CAMERA_SEND_SYSTEM_EVENTS permission.
     */
    oneway void notifyDisplayConfigurationChange();

    /**
     * Notify the camera service of a device physical status change. May only be called from
     * a privileged process.
     *
     * newState is a bitfield consisting of DEVICE_STATE_* values combined together. Valid state
     * combinations are device-specific. At device startup, the camera service will assume the device
     * state is NORMAL until otherwise notified.
     *
     * Callers require the android.permission.CAMERA_SEND_SYSTEM_EVENTS permission.
     */
    oneway void notifyDeviceStateChange(long newState);

    /**
     * Report Extension specific metrics to camera service for logging. This should only be called
     * by CameraExtensionSession to log extension metrics. All calls after the first must set
     * CameraExtensionSessionStats.key to the value returned by this function.
     *
     * Each subsequent call fully overwrites the existing CameraExtensionSessionStats for the
     * current session, so the caller is responsible for keeping the stats complete.
     *
     * Due to cameraservice and cameraservice_proxy architecture, there is no guarantee that
     * {@code stats} will be logged immediately (or at all). CameraService will log whatever
     * extension stats it has at the time of camera session closing which may be before the app
     * process receives a session/device closed callback; so CameraExtensionSession
     * should send metrics to the cameraservice preriodically, and cameraservice must handle calls
     * to this function from sessions that have not been logged yet and from sessions that have
     * already been closed.
     *
     * @return the key that must be used to report updates to previously reported stats.
     */
    @utf8InCpp String reportExtensionSessionStats(in CameraExtensionSessionStats stats);

    // Bitfield constants for notifyDeviceStateChange
    // All bits >= 32 are for custom vendor states
    // Written as ints since AIDL does not support long constants.
    const int DEVICE_STATE_NORMAL = 0;
    const int DEVICE_STATE_BACK_COVERED = 1;
    const int DEVICE_STATE_FRONT_COVERED = 2;
    const int DEVICE_STATE_FOLDED = 4;
    const int DEVICE_STATE_LAST_FRAMEWORK_BIT = 0x80000000; // 1 << 31;

}
