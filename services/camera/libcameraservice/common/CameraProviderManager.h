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

#ifndef ANDROID_SERVERS_CAMERA_CAMERAPROVIDER_H
#define ANDROID_SERVERS_CAMERA_CAMERAPROVIDER_H

#include <vector>
#include <unordered_map>
#include <unordered_set>
#include <set>
#include <string>
#include <mutex>
#include <future>

#include <camera/camera2/ConcurrentCamera.h>
#include <camera/CameraParameters2.h>
#include <camera/CameraMetadata.h>
#include <camera/CameraBase.h>
#include <utils/Condition.h>
#include <utils/Errors.h>
#include <android/hardware/ICameraService.h>
#include <utils/IPCTransport.h>
#include <utils/SessionConfigurationUtils.h>
#include <aidl/android/hardware/camera/provider/ICameraProvider.h>
#include <android/hardware/camera/common/1.0/types.h>
#include <android/hardware/camera/provider/2.5/ICameraProvider.h>
#include <android/hardware/camera/provider/2.6/ICameraProviderCallback.h>
#include <android/hardware/camera/provider/2.6/ICameraProvider.h>
#include <android/hardware/camera/provider/2.7/ICameraProvider.h>
#include <android/hardware/camera/device/3.7/types.h>
#include <android/hidl/manager/1.0/IServiceNotification.h>
#include <binder/IServiceManager.h>
#include <camera/VendorTagDescriptor.h>

namespace android {

using hardware::camera2::utils::CameraIdAndSessionConfiguration;

enum class CameraDeviceStatus : uint32_t {
  NOT_PRESENT = 0,
  PRESENT = 1,
  ENUMERATING = 2
};

enum class TorchModeStatus : uint32_t {
  NOT_AVAILABLE = 0,
  AVAILABLE_OFF = 1,
  AVAILABLE_ON = 2
};

struct CameraResourceCost {
  uint32_t resourceCost;
  std::vector<std::string> conflictingDevices;
};

enum SystemCameraKind {
   /**
    * These camera devices are visible to all apps and system components alike
    */
   PUBLIC = 0,

   /**
    * These camera devices are visible only to processes having the
    * android.permission.SYSTEM_CAMERA permission. They are not exposed to 3P
    * apps.
    */
   SYSTEM_ONLY_CAMERA,

   /**
    * These camera devices are visible only to HAL clients (that try to connect
    * on a hwbinder thread).
    */
   HIDDEN_SECURE_CAMERA
};

#define CAMERA_DEVICE_API_VERSION_1_0 HARDWARE_DEVICE_API_VERSION(1, 0)
#define CAMERA_DEVICE_API_VERSION_3_0 HARDWARE_DEVICE_API_VERSION(3, 0)
#define CAMERA_DEVICE_API_VERSION_3_1 HARDWARE_DEVICE_API_VERSION(3, 1)
#define CAMERA_DEVICE_API_VERSION_3_2 HARDWARE_DEVICE_API_VERSION(3, 2)
#define CAMERA_DEVICE_API_VERSION_3_3 HARDWARE_DEVICE_API_VERSION(3, 3)
#define CAMERA_DEVICE_API_VERSION_3_4 HARDWARE_DEVICE_API_VERSION(3, 4)
#define CAMERA_DEVICE_API_VERSION_3_5 HARDWARE_DEVICE_API_VERSION(3, 5)
#define CAMERA_DEVICE_API_VERSION_3_6 HARDWARE_DEVICE_API_VERSION(3, 6)
#define CAMERA_DEVICE_API_VERSION_3_7 HARDWARE_DEVICE_API_VERSION(3, 7)

/**
 * The vendor tag descriptor class that takes HIDL/AIDL vendor tag information as
 * input. Not part of VendorTagDescriptor class because that class is used
 * in AIDL generated sources which don't have access to AIDL / HIDL headers.
 */
class IdlVendorTagDescriptor : public VendorTagDescriptor {
public:
    /**
     * Create a VendorTagDescriptor object from the HIDL/AIDL VendorTagSection
     * vector.
     *
     * Returns OK on success, or a negative error code.
     */
    template <class VendorTagSectionVectorType, class VendorTagSectionType>
    static status_t createDescriptorFromIdl(
            const VendorTagSectionVectorType& vts,
            /*out*/
            sp<VendorTagDescriptor>& descriptor);
};

/**
 * A manager for all camera providers available on an Android device.
 *
 * Responsible for enumerating providers and the individual camera devices
 * they export, both at startup and as providers and devices are added/removed.
 *
 * Provides methods for requesting information about individual devices and for
 * opening them for active use.
 *
 */
class CameraProviderManager : virtual public hidl::manager::V1_0::IServiceNotification,
        public virtual IServiceManager::LocalRegistrationCallback {
public:
    // needs to be made friend strict since HidlProviderInfo needs to inherit
    // from CameraProviderManager::ProviderInfo which isn't a public member.
    friend struct HidlProviderInfo;
    friend struct AidlProviderInfo;
    ~CameraProviderManager();

    // Tiny proxy for the static methods in a HIDL interface that communicate with the hardware
    // service manager, to be replacable in unit tests with a fake.
    struct HidlServiceInteractionProxy {
        virtual bool registerForNotifications(
                const std::string &serviceName,
                const sp<hidl::manager::V1_0::IServiceNotification>
                &notification) = 0;
        // Will not wait for service to start if it's not already running
        virtual sp<hardware::camera::provider::V2_4::ICameraProvider> tryGetService(
                const std::string &serviceName) = 0;
        // Will block for service if it exists but isn't running
        virtual sp<hardware::camera::provider::V2_4::ICameraProvider> getService(
                const std::string &serviceName) = 0;
        virtual hardware::hidl_vec<hardware::hidl_string> listServices() = 0;
        virtual ~HidlServiceInteractionProxy() {}
    };

    // Standard use case - call into the normal generated static methods which invoke
    // the real hardware service manager
    struct HidlServiceInteractionProxyImpl : public HidlServiceInteractionProxy {
        virtual bool registerForNotifications(
                const std::string &serviceName,
                const sp<hidl::manager::V1_0::IServiceNotification>
                &notification) override {
            return hardware::camera::provider::V2_4::ICameraProvider::registerForNotifications(
                    serviceName, notification);
        }
        virtual sp<hardware::camera::provider::V2_4::ICameraProvider> tryGetService(
                const std::string &serviceName) override {
            return hardware::camera::provider::V2_4::ICameraProvider::tryGetService(serviceName);
        }
        virtual sp<hardware::camera::provider::V2_4::ICameraProvider> getService(
                const std::string &serviceName) override {
            return hardware::camera::provider::V2_4::ICameraProvider::getService(serviceName);
        }

        virtual hardware::hidl_vec<hardware::hidl_string> listServices() override;
    };

    /**
     * Listener interface for device/torch status changes
     */
    struct StatusListener : virtual public RefBase {
        ~StatusListener() {}

        virtual void onDeviceStatusChanged(const String8 &cameraId,
                CameraDeviceStatus newStatus) = 0;
        virtual void onDeviceStatusChanged(const String8 &cameraId,
                const String8 &physicalCameraId,
                CameraDeviceStatus newStatus) = 0;
        virtual void onTorchStatusChanged(const String8 &cameraId,
                TorchModeStatus newStatus,
                SystemCameraKind kind) = 0;
        virtual void onTorchStatusChanged(const String8 &cameraId,
                TorchModeStatus newStatus) = 0;
        virtual void onNewProviderRegistered() = 0;
    };

    /**
     * Represents the mode a camera device is currently in
     */
    enum class DeviceMode {
        TORCH,
        CAMERA
    };

    /**
     * Initialize the manager and give it a status listener; optionally accepts a service
     * interaction proxy.
     *
     * The default proxy communicates via the hardware service manager; alternate proxies can be
     * used for testing. The lifetime of the proxy must exceed the lifetime of the manager.
     */
    status_t initialize(wp<StatusListener> listener,
            HidlServiceInteractionProxy *hidlProxy = &sHidlServiceInteractionProxy);

    status_t getCameraIdIPCTransport(const std::string &id,
            IPCTransport *providerTransport) const;

    /**
     * Retrieve the total number of available cameras.
     * This value may change dynamically as cameras are added or removed.
     */
    std::pair<int, int> getCameraCount() const;

    std::vector<std::string> getCameraDeviceIds() const;

    /**
     * Retrieve the number of API1 compatible cameras; these are internal and
     * backwards-compatible. This is the set of cameras that will be
     * accessible via the old camera API.
     * The return value may change dynamically due to external camera hotplug.
     */
    std::vector<std::string> getAPI1CompatibleCameraDeviceIds() const;

    /**
     * Return true if a device with a given ID has a flash unit. Returns false
     * for devices that are unknown.
     */
    bool hasFlashUnit(const std::string &id) const;

    /**
     * Return true if the camera device has native zoom ratio support.
     */
    bool supportNativeZoomRatio(const std::string &id) const;

    /**
     * Return the resource cost of this camera device
     */
    status_t getResourceCost(const std::string &id,
            CameraResourceCost* cost) const;

    /**
     * Return the old camera API camera info
     */
    status_t getCameraInfo(const std::string &id,
            hardware::CameraInfo* info) const;

    /**
     * Return API2 camera characteristics - returns NAME_NOT_FOUND if a device ID does
     * not have a v3 or newer HAL version.
     */
    status_t getCameraCharacteristics(const std::string &id,
            bool overrideForPerfClass, CameraMetadata* characteristics) const;

    status_t isConcurrentSessionConfigurationSupported(
            const std::vector<hardware::camera2::utils::CameraIdAndSessionConfiguration>
                    &cameraIdsAndSessionConfigs,
            const std::set<std::string>& perfClassPrimaryCameraIds,
            int targetSdkVersion, bool *isSupported);

    std::vector<std::unordered_set<std::string>> getConcurrentCameraIds() const;
    /**
     * Check for device support of specific stream combination.
     */
    status_t isSessionConfigurationSupported(const std::string& id,
            const SessionConfiguration &configuration,
            bool overrideForPerfClass, camera3::metadataGetter getMetadata,
            bool *status /*out*/) const;

    /**
     * Return the highest supported device interface version for this ID
     */
    status_t getHighestSupportedVersion(const std::string &id,
            hardware::hidl_version *v, IPCTransport *transport);

    /**
     * Check if a given camera device support setTorchMode API.
     */
    bool supportSetTorchMode(const std::string &id) const;

    /**
     * Check if torch strength update should be skipped or not.
     */
    bool shouldSkipTorchStrengthUpdate(const std::string &id, int32_t torchStrength) const;

    /**
     * Return the default torch strength level if the torch strength control
     * feature is supported.
     */
    int32_t getTorchDefaultStrengthLevel(const std::string &id) const;

    /**
     * Turn on or off the flashlight on a given camera device.
     * May fail if the device does not support this API, is in active use, or if the device
     * doesn't exist, etc.
     */
    status_t setTorchMode(const std::string &id, bool enabled);

    /**
     * Change the brightness level of the flash unit associated with the cameraId and
     * set it to the value in torchStrength.
     * If the torch is OFF and torchStrength > 0, the torch will be turned ON with the
     * specified strength level. If the torch is ON, only the brightness level will be
     * changed.
     *
     * This operation will fail if the device does not have flash unit, has flash unit
     * but does not support this API, torchStrength is invalid or if the device doesn't
     * exist etc.
     */
    status_t turnOnTorchWithStrengthLevel(const std::string &id, int32_t torchStrength);

    /**
     * Return the torch strength level of this camera device.
     */
    status_t getTorchStrengthLevel(const std::string &id, int32_t* torchStrength);

    /**
     * Setup vendor tags for all registered providers
     */
    status_t setUpVendorTags();

    /**
     * Inform registered providers about a device state change, such as folding or unfolding
     */
    status_t notifyDeviceStateChange(int64_t newState);

    status_t openAidlSession(const std::string &id,
        const std::shared_ptr<
                aidl::android::hardware::camera::device::ICameraDeviceCallback>& callback,
        /*out*/
        std::shared_ptr<aidl::android::hardware::camera::device::ICameraDeviceSession> *session);

    status_t openAidlInjectionSession(const std::string &id,
        const std::shared_ptr<
                aidl::android::hardware::camera::device::ICameraDeviceCallback>& callback,
        /*out*/
        std::shared_ptr<aidl::android::hardware::camera::device::ICameraInjectionSession> *session);

    /**
     * Open an active session to a camera device.
     *
     * This fully powers on the camera device hardware, and returns a handle to a
     * session to be used for hardware configuration and operation.
     */
    status_t openHidlSession(const std::string &id,
            const sp<hardware::camera::device::V3_2::ICameraDeviceCallback>& callback,
            /*out*/
            sp<hardware::camera::device::V3_2::ICameraDeviceSession> *session);

    /**
     * Notify that the camera or torch is no longer being used by a camera client
     */
    void removeRef(DeviceMode usageType, const std::string &cameraId);

    /**
     * IServiceNotification::onRegistration
     * Invoked by the hardware service manager when a new camera provider is registered
     */
    virtual hardware::Return<void> onRegistration(const hardware::hidl_string& fqName,
            const hardware::hidl_string& name,
            bool preexisting) override;

    // LocalRegistrationCallback::onServiceRegistration
    virtual void onServiceRegistration(const String16& name, const sp<IBinder> &binder) override;

    /**
     * Dump out information about available providers and devices
     */
    status_t dump(int fd, const Vector<String16>& args);

    /**
     * Conversion methods between HAL Status and status_t and strings
     */
    static status_t mapToStatusT(const hardware::camera::common::V1_0::Status& s);
    static const char* statusToString(const hardware::camera::common::V1_0::Status& s);

    /*
     * Return provider type for a specific device.
     */
    metadata_vendor_id_t getProviderTagIdLocked(const std::string& id) const;

    /*
     * Check if a camera is a logical camera. And if yes, return
     * the physical camera ids.
     */
    bool isLogicalCamera(const std::string& id, std::vector<std::string>* physicalCameraIds);

    status_t getSystemCameraKind(const std::string& id, SystemCameraKind *kind) const;
    bool isHiddenPhysicalCamera(const std::string& cameraId) const;

    status_t filterSmallJpegSizes(const std::string& cameraId);

    status_t notifyUsbDeviceEvent(int32_t eventId, const std::string &usbDeviceId);

    static const float kDepthARTolerance;
private:
    // All private members, unless otherwise noted, expect mInterfaceMutex to be locked before use
    mutable std::mutex mInterfaceMutex;

    wp<StatusListener> mListener;
    HidlServiceInteractionProxy* mHidlServiceProxy;

    // Current overall Android device physical status
    int64_t mDeviceState;

    // mProviderLifecycleLock is locked during onRegistration and removeProvider
    mutable std::mutex mProviderLifecycleLock;

    static HidlServiceInteractionProxyImpl sHidlServiceInteractionProxy;

    struct HalCameraProvider {
      // Empty parent struct for storing either aidl / hidl camera provider reference
      HalCameraProvider(const char *descriptor) : mDescriptor(descriptor) { };
      virtual ~HalCameraProvider() {};
      std::string mDescriptor;
    };

    struct HidlHalCameraProvider : public HalCameraProvider {
        HidlHalCameraProvider(
                const sp<hardware::camera::provider::V2_4::ICameraProvider> &provider,
                const char *descriptor) :
                HalCameraProvider(descriptor), mCameraProvider(provider) { };
     private:
        sp<hardware::camera::provider::V2_4::ICameraProvider> mCameraProvider;
    };

    struct AidlHalCameraProvider : public HalCameraProvider {
        AidlHalCameraProvider(
                const std::shared_ptr<
                        aidl::android::hardware::camera::provider::ICameraProvider> &provider,
                const char *descriptor) :
                HalCameraProvider(descriptor), mCameraProvider(provider) { };
     private:
        std::shared_ptr<aidl::android::hardware::camera::provider::ICameraProvider> mCameraProvider;
    };


    // Mapping from CameraDevice IDs to CameraProviders. This map is used to keep the
    // ICameraProvider alive while it is in use by the camera with the given ID for camera
    // capabilities
    std::unordered_map<std::string, std::shared_ptr<HalCameraProvider>>
            mCameraProviderByCameraId;

    // Mapping from CameraDevice IDs to CameraProviders. This map is used to keep the
    // ICameraProvider alive while it is in use by the camera with the given ID for torch
    // capabilities
    std::unordered_map<std::string, std::shared_ptr<HalCameraProvider>>
            mTorchProviderByCameraId;

    // Lock for accessing mCameraProviderByCameraId and mTorchProviderByCameraId
    std::mutex mProviderInterfaceMapLock;
    struct ProviderInfo : public virtual RefBase {
        friend struct HidlProviderInfo;
        friend struct AidlProviderInfo;
        const std::string mProviderName;
        const std::string mProviderInstance;
        const metadata_vendor_id_t mProviderTagid;
        int32_t mMinorVersion;
        sp<VendorTagDescriptor> mVendorTagDescriptor;
        bool mSetTorchModeSupported;
        bool mIsRemote;

        ProviderInfo(const std::string &providerName, const std::string &providerInstance,
                CameraProviderManager *manager);
        ~ProviderInfo();

        virtual IPCTransport getIPCTransport() = 0;

        const std::string& getType() const;

        status_t dump(int fd, const Vector<String16>& args) const;

        void initializeProviderInfoCommon(const std::vector<std::string> &devices);
        /**
         * Setup vendor tags for this provider
         */
        virtual status_t setUpVendorTags() = 0;

        /**
         * Notify provider about top-level device physical state changes
         *
         * Note that 'mInterfaceMutex' should not be held when calling this method.
         * It is possible for camera providers to add/remove devices and try to
         * acquire it.
         */
        virtual status_t notifyDeviceStateChange(int64_t newDeviceState) = 0;

        virtual bool successfullyStartedProviderInterface() = 0;

        virtual int64_t getDeviceState() = 0;

        std::vector<std::unordered_set<std::string>> getConcurrentCameraIdCombinations();

        /**
         * Notify 'DeviceInfo' instanced about top-level device physical state changes
         *
         * Note that 'mInterfaceMutex' should be held when calling this method.
         */
        void notifyDeviceInfoStateChangeLocked(int64_t newDeviceState);

        /**
         * Query the camera provider for concurrent stream configuration support
         */
        virtual status_t isConcurrentSessionConfigurationSupported(
                    const std::vector<CameraIdAndSessionConfiguration> &cameraIdsAndSessionConfigs,
                    const std::set<std::string>& perfClassPrimaryCameraIds,
                    int targetSdkVersion, bool *isSupported) = 0;

        /**
         * Remove all devices associated with this provider and notify listeners
         * with NOT_PRESENT state.
         */
        void removeAllDevices();

        /**
         * Provider is an external lazy HAL
         */
        bool isExternalLazyHAL() const;

        // Basic device information, common to all camera devices
        struct DeviceInfo {
            const std::string mName;  // Full instance name
            const std::string mId;    // ID section of full name
            //Both hidl and aidl DeviceInfos. Aidl deviceInfos get {3, 8} to
            //start off.
            const hardware::hidl_version mVersion;
            const metadata_vendor_id_t mProviderTagid;
            bool mIsLogicalCamera;
            std::vector<std::string> mPhysicalIds;
            hardware::CameraInfo mInfo;
            SystemCameraKind mSystemCameraKind = SystemCameraKind::PUBLIC;

            const CameraResourceCost mResourceCost;

            CameraDeviceStatus mStatus;

            wp<ProviderInfo> mParentProvider;
            // Torch strength default, maximum levels if the torch strength control
            // feature is supported.
            int32_t mTorchStrengthLevel;
            int32_t mTorchMaximumStrengthLevel;
            int32_t mTorchDefaultStrengthLevel;

            // Wait for lazy HALs to confirm device availability
            static const nsecs_t kDeviceAvailableTimeout = 2000e6; // 2000 ms
            Mutex     mDeviceAvailableLock;
            Condition mDeviceAvailableSignal;
            bool mIsDeviceAvailable = true;

            bool hasFlashUnit() const { return mHasFlashUnit; }
            bool supportNativeZoomRatio() const { return mSupportNativeZoomRatio; }
            virtual status_t setTorchMode(bool enabled) = 0;
            virtual status_t turnOnTorchWithStrengthLevel(int32_t torchStrength) = 0;
            virtual status_t getTorchStrengthLevel(int32_t *torchStrength) = 0;
            virtual status_t getCameraInfo(hardware::CameraInfo *info) const = 0;
            virtual bool isAPI1Compatible() const = 0;
            virtual status_t dumpState(int fd) = 0;
            virtual status_t getCameraCharacteristics(bool overrideForPerfClass,
                    CameraMetadata *characteristics) const {
                (void) overrideForPerfClass;
                (void) characteristics;
                return INVALID_OPERATION;
            }
            virtual status_t getPhysicalCameraCharacteristics(const std::string& physicalCameraId,
                    CameraMetadata *characteristics) const {
                (void) physicalCameraId;
                (void) characteristics;
                return INVALID_OPERATION;
            }

            virtual status_t isSessionConfigurationSupported(
                    const SessionConfiguration &/*configuration*/,
                    bool /*overrideForPerfClass*/,
                    camera3::metadataGetter /*getMetadata*/,
                    bool * /*status*/) {
                return INVALID_OPERATION;
            }
            virtual status_t filterSmallJpegSizes() = 0;
            virtual void notifyDeviceStateChange(int64_t /*newState*/) {}

            DeviceInfo(const std::string& name, const metadata_vendor_id_t tagId,
                    const std::string &id, const hardware::hidl_version& version,
                    const std::vector<std::string>& publicCameraIds,
                    const CameraResourceCost& resourceCost,
                    sp<ProviderInfo> parentProvider) :
                    mName(name), mId(id), mVersion(version), mProviderTagid(tagId),
                    mIsLogicalCamera(false), mResourceCost(resourceCost),
                    mStatus(CameraDeviceStatus::PRESENT),
                    mParentProvider(parentProvider), mTorchStrengthLevel(0),
                    mTorchMaximumStrengthLevel(0), mTorchDefaultStrengthLevel(0),
                    mHasFlashUnit(false), mSupportNativeZoomRatio(false),
                    mPublicCameraIds(publicCameraIds) {}
            virtual ~DeviceInfo() {}
        protected:

            bool mHasFlashUnit; // const after constructor
            bool mSupportNativeZoomRatio; // const after constructor
            const std::vector<std::string>& mPublicCameraIds;
        };
        std::vector<std::unique_ptr<DeviceInfo>> mDevices;
        std::unordered_set<std::string> mUniqueCameraIds;
        int mUniqueDeviceCount;
        std::vector<std::string> mUniqueAPI1CompatibleCameraIds;
        // The initial public camera IDs published by the camera provider.
        // Currently logical multi-camera is not supported for hot-plug camera.
        // And we use this list to keep track of initial public camera IDs
        // advertised by the provider, and to distinguish against "hidden"
        // physical camera IDs.
        std::vector<std::string> mProviderPublicCameraIds;

        // HALv3-specific camera fields, including the actual device interface
        struct DeviceInfo3 : public DeviceInfo {

            virtual status_t setTorchMode(bool enabled) = 0;
            virtual status_t turnOnTorchWithStrengthLevel(int32_t torchStrength) = 0;
            virtual status_t getTorchStrengthLevel(int32_t *torchStrength) = 0;
            virtual status_t getCameraInfo(hardware::CameraInfo *info) const override;
            virtual bool isAPI1Compatible() const override;
            virtual status_t dumpState(int fd) = 0;
            virtual status_t getCameraCharacteristics(
                    bool overrideForPerfClass,
                    CameraMetadata *characteristics) const override;
            virtual status_t getPhysicalCameraCharacteristics(const std::string& physicalCameraId,
                    CameraMetadata *characteristics) const override;
            virtual status_t isSessionConfigurationSupported(
                    const SessionConfiguration &configuration, bool /*overrideForPerfClass*/,
                    camera3::metadataGetter /*getMetadata*/,
                    bool *status /*out*/) = 0;
            virtual status_t filterSmallJpegSizes() override;
            virtual void notifyDeviceStateChange(
                        int64_t newState) override;

            DeviceInfo3(const std::string& name, const metadata_vendor_id_t tagId,
                    const std::string &id, uint16_t minorVersion,
                    const CameraResourceCost& resourceCost,
                    sp<ProviderInfo> parentProvider,
                    const std::vector<std::string>& publicCameraIds);
            virtual ~DeviceInfo3() {};
        protected:
            // Modified by derived transport specific (hidl / aidl) class
            CameraMetadata mCameraCharacteristics;
            // Map device states to sensor orientations
            std::unordered_map<int64_t, int32_t> mDeviceStateOrientationMap;
            // A copy of mCameraCharacteristics without performance class
            // override
            std::unique_ptr<CameraMetadata> mCameraCharNoPCOverride;
            // Only contains characteristics for hidden physical cameras,
            // not for public physical cameras.
            std::unordered_map<std::string, CameraMetadata> mPhysicalCameraCharacteristics;
            void queryPhysicalCameraIds();
            SystemCameraKind getSystemCameraKind();
            status_t fixupMonochromeTags();
            status_t fixupTorchStrengthTags();
            status_t addDynamicDepthTags(bool maxResolution = false);
            status_t deriveHeicTags(bool maxResolution = false);
            status_t addRotateCropTags();
            status_t addPreCorrectionActiveArraySize();
            status_t addReadoutTimestampTag(bool readoutTimestampSupported = true);

            static void getSupportedSizes(const CameraMetadata& ch, uint32_t tag,
                    android_pixel_format_t format,
                    std::vector<std::tuple<size_t, size_t>> *sizes /*out*/);
            static void getSupportedDurations( const CameraMetadata& ch, uint32_t tag,
                    android_pixel_format_t format,
                    const std::vector<std::tuple<size_t, size_t>>& sizes,
                    std::vector<int64_t> *durations/*out*/);
            static void getSupportedDynamicDepthDurations(
                    const std::vector<int64_t>& depthDurations,
                    const std::vector<int64_t>& blobDurations,
                    std::vector<int64_t> *dynamicDepthDurations /*out*/);
            static void getSupportedDynamicDepthSizes(
                    const std::vector<std::tuple<size_t, size_t>>& blobSizes,
                    const std::vector<std::tuple<size_t, size_t>>& depthSizes,
                    std::vector<std::tuple<size_t, size_t>> *dynamicDepthSizes /*out*/,
                    std::vector<std::tuple<size_t, size_t>> *internalDepthSizes /*out*/);
            status_t removeAvailableKeys(CameraMetadata& c, const std::vector<uint32_t>& keys,
                    uint32_t keyTag);
            status_t fillHeicStreamCombinations(std::vector<int32_t>* outputs,
                    std::vector<int64_t>* durations,
                    std::vector<int64_t>* stallDurations,
                    const camera_metadata_entry& halStreamConfigs,
                    const camera_metadata_entry& halStreamDurations);
        };
    protected:
        std::string mType;
        uint32_t mId;

        std::mutex mLock;

        CameraProviderManager *mManager;

        struct CameraStatusInfoT {
            bool isPhysicalCameraStatus = false;
            std::string cameraId;
            std::string physicalCameraId;
            CameraDeviceStatus status;
            CameraStatusInfoT(bool isForPhysicalCamera, const std::string& id,
                    const std::string& physicalId,
                    CameraDeviceStatus s) :
                    isPhysicalCameraStatus(isForPhysicalCamera), cameraId(id),
                    physicalCameraId(physicalId), status(s) {}
        };

        // Lock to synchronize between initialize() and camera status callbacks
        std::mutex mInitLock;
        bool mInitialized = false;
        std::vector<CameraStatusInfoT> mCachedStatus;
        // End of scope for mInitLock

        std::future<void> mInitialStatusCallbackFuture;

        std::unique_ptr<ProviderInfo::DeviceInfo>
        virtual initializeDeviceInfo(
                const std::string &name, const metadata_vendor_id_t tagId,
                const std::string &id, uint16_t minorVersion) = 0;

        virtual status_t reCacheConcurrentStreamingCameraIdsLocked() = 0;

        void notifyInitialStatusChange(sp<StatusListener> listener,
                std::unique_ptr<std::vector<CameraStatusInfoT>> cachedStatus);

        std::vector<std::unordered_set<std::string>> mConcurrentCameraIdCombinations;

        // Parse provider instance name for type and id
        static status_t parseProviderName(const std::string& name,
                std::string *type, uint32_t *id);

        // Parse device instance name for device version, type, and id.
        static status_t parseDeviceName(const std::string& name,
                uint16_t *major, uint16_t *minor, std::string *type, std::string *id);

        // Generate vendor tag id
        static metadata_vendor_id_t generateVendorTagId(const std::string &name);

        status_t addDevice(
                const std::string& name, CameraDeviceStatus initialStatus,
                /*out*/ std::string* parsedId);

        void cameraDeviceStatusChangeInternal(const std::string& cameraDeviceName,
                CameraDeviceStatus newStatus);

        status_t cameraDeviceStatusChangeLocked(
                std::string* id, const std::string& cameraDeviceName,
                CameraDeviceStatus newStatus);

        void physicalCameraDeviceStatusChangeInternal(const std::string& cameraDeviceName,
                const std::string& physicalCameraDeviceName,
                CameraDeviceStatus newStatus);

      status_t physicalCameraDeviceStatusChangeLocked(
            std::string* id, std::string* physicalId,
            const std::string& cameraDeviceName,
            const std::string& physicalCameraDeviceName,
            CameraDeviceStatus newStatus);

        void torchModeStatusChangeInternal(const std::string& cameraDeviceName,
                TorchModeStatus newStatus);

        void removeDevice(std::string id);

    };

    template <class ProviderInfoType, class HalCameraProviderType>
    status_t setTorchModeT(sp<ProviderInfo> &parentProvider,
            std::shared_ptr<HalCameraProvider> *halCameraProvider);

    // Try to get hidl provider services declared. Expects mInterfaceMutex to be
    // locked. Also registers for hidl provider service notifications.
    status_t tryToInitAndAddHidlProvidersLocked(HidlServiceInteractionProxy *hidlProxy);

    // Try to get aidl provider services declared. Expects mInterfaceMutex to be
    // locked. Also registers for aidl provider service notifications.
    status_t tryToAddAidlProvidersLocked();

    /**
     * Save the ICameraProvider while it is being used by a camera or torch client
     */
    void saveRef(DeviceMode usageType, const std::string &cameraId,
            std::shared_ptr<HalCameraProvider> provider);

    // Utility to find a DeviceInfo by ID; pointer is only valid while mInterfaceMutex is held
    // and the calling code doesn't mutate the list of providers or their lists of devices.
    // No guarantees on the order of traversal
    ProviderInfo::DeviceInfo* findDeviceInfoLocked(const std::string& id) const;

    // Map external providers to USB devices in order to handle USB hotplug
    // events for lazy HALs
    std::pair<std::vector<std::string>, sp<ProviderInfo>>
        mExternalUsbDevicesForProvider;
    sp<ProviderInfo> startExternalLazyProvider() const;

    status_t addHidlProviderLocked(const std::string& newProvider, bool preexisting = false);

    status_t addAidlProviderLocked(const std::string& newProvider);

    status_t tryToInitializeHidlProviderLocked(const std::string& providerName,
            const sp<ProviderInfo>& providerInfo);

    status_t tryToInitializeAidlProviderLocked(const std::string& providerName,
            const sp<ProviderInfo>& providerInfo);

    bool isLogicalCameraLocked(const std::string& id, std::vector<std::string>* physicalCameraIds);

    // No method corresponding to the same provider / member belonging to the
    // same provider should be used after this method is called since it'll lead
    // to invalid memory access (especially since this is called by ProviderInfo methods on hal
    // service death).
    status_t removeProvider(const std::string& provider);
    sp<StatusListener> getStatusListener() const;

    bool isValidDeviceLocked(const std::string &id, uint16_t majorVersion,
            IPCTransport transport) const;

    size_t mProviderInstanceId = 0;
    std::vector<sp<ProviderInfo>> mProviders;
    // Provider names of AIDL providers with retrieved binders.
    std::set<std::string> mAidlProviderWithBinders;

    static const char* deviceStatusToString(
        const hardware::camera::common::V1_0::CameraDeviceStatus&);
    static const char* torchStatusToString(
        const hardware::camera::common::V1_0::TorchModeStatus&);

    status_t getCameraCharacteristicsLocked(const std::string &id, bool overrideForPerfClass,
            CameraMetadata* characteristics) const;
    void filterLogicalCameraIdsLocked(std::vector<std::string>& deviceIds) const;

    status_t getSystemCameraKindLocked(const std::string& id, SystemCameraKind *kind) const;
    std::pair<bool, ProviderInfo::DeviceInfo *> isHiddenPhysicalCameraInternal(
            const std::string& cameraId) const;

    void collectDeviceIdsLocked(const std::vector<std::string> deviceIds,
            std::vector<std::string>& normalDeviceIds,
            std::vector<std::string>& systemCameraDeviceIds) const;

    status_t usbDeviceDetached(const std::string &usbDeviceId);
    ndk::ScopedAStatus onAidlRegistration(const std::string& in_name,
            const ::ndk::SpAIBinder& in_binder);
};

} // namespace android

#endif
