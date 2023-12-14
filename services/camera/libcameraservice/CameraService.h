/*
 * Copyright (C) 2008 The Android Open Source Project
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

#ifndef ANDROID_SERVERS_CAMERA_CAMERASERVICE_H
#define ANDROID_SERVERS_CAMERA_CAMERASERVICE_H

#include <android/hardware/BnCameraService.h>
#include <android/hardware/BnSensorPrivacyListener.h>
#include <android/hardware/ICameraServiceListener.h>
#include <android/hardware/CameraIdRemapping.h>
#include <android/hardware/camera2/BnCameraInjectionSession.h>
#include <android/hardware/camera2/ICameraInjectionCallback.h>

#include <cutils/multiuser.h>
#include <utils/Vector.h>
#include <utils/KeyedVector.h>
#include <binder/ActivityManager.h>
#include <binder/AppOpsManager.h>
#include <binder/BinderService.h>
#include <binder/IServiceManager.h>
#include <binder/IActivityManager.h>
#include <binder/IAppOpsCallback.h>
#include <binder/IUidObserver.h>
#include <hardware/camera.h>
#include <sensorprivacy/SensorPrivacyManager.h>

#include <android/hardware/camera/common/1.0/types.h>

#include <camera/VendorTagDescriptor.h>
#include <camera/CaptureResult.h>
#include <camera/CameraParameters.h>
#include <camera/camera2/ConcurrentCamera.h>

#include "CameraFlashlight.h"

#include "common/CameraProviderManager.h"
#include "media/RingBuffer.h"
#include "utils/AutoConditionLock.h"
#include "utils/ClientManager.h"
#include "utils/IPCTransport.h"
#include "utils/CameraServiceProxyWrapper.h"

#include <set>
#include <string>
#include <list>
#include <map>
#include <memory>
#include <optional>
#include <utility>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace android {

extern volatile int32_t gLogLevel;

class MemoryHeapBase;
class MediaPlayer;

class CameraService :
    public BinderService<CameraService>,
    public virtual ::android::hardware::BnCameraService,
    public virtual IBinder::DeathRecipient,
    public virtual CameraProviderManager::StatusListener,
    public virtual IServiceManager::LocalRegistrationCallback
{
    friend class BinderService<CameraService>;
    friend class CameraOfflineSessionClient;
public:
    class Client;
    class BasicClient;
    class OfflineClient;

    // The effective API level.  The Camera2 API running in LEGACY mode counts as API_1.
    enum apiLevel {
        API_1 = 1,
        API_2 = 2
    };

    // 3 second busy timeout when other clients are connecting
    static const nsecs_t DEFAULT_CONNECT_TIMEOUT_NS = 3000000000;

    // 1 second busy timeout when other clients are disconnecting
    static const nsecs_t DEFAULT_DISCONNECT_TIMEOUT_NS = 1000000000;

    // Default number of messages to store in eviction log
    static const size_t DEFAULT_EVENT_LOG_LENGTH = 100;

    // Event log ID
    static const int SN_EVENT_LOG_ID = 0x534e4554;

    // Register camera service
    static void instantiate();

    // Implementation of BinderService<T>
    static char const* getServiceName() { return "media.camera"; }

    // Implementation of IServiceManager::LocalRegistrationCallback
    virtual void onServiceRegistration(const String16& name, const sp<IBinder>& binder) override;

                        // Non-null arguments for cameraServiceProxyWrapper should be provided for
                        // testing purposes only.
                        CameraService(std::shared_ptr<CameraServiceProxyWrapper>
                                cameraServiceProxyWrapper = nullptr);
    virtual             ~CameraService();

    /////////////////////////////////////////////////////////////////////
    // HAL Callbacks - implements CameraProviderManager::StatusListener

    virtual void        onDeviceStatusChanged(const std::string &cameraId,
            CameraDeviceStatus newHalStatus) override;
    virtual void        onDeviceStatusChanged(const std::string &cameraId,
            const std::string &physicalCameraId,
            CameraDeviceStatus newHalStatus) override;
    // This method may hold CameraProviderManager::mInterfaceMutex as a part
    // of calling getSystemCameraKind() internally. Care should be taken not to
    // directly / indirectly call this from callers who also hold
    // mInterfaceMutex.
    virtual void        onTorchStatusChanged(const std::string& cameraId,
            TorchModeStatus newStatus) override;
    // Does not hold CameraProviderManager::mInterfaceMutex.
    virtual void        onTorchStatusChanged(const std::string& cameraId,
            TorchModeStatus newStatus,
            SystemCameraKind kind) override;
    virtual void        onNewProviderRegistered() override;

    /////////////////////////////////////////////////////////////////////
    // ICameraService
    // IMPORTANT: All binder calls that deal with logicalCameraId should use
    // resolveCameraId(logicalCameraId) to arrive at the correct cameraId to
    // perform the operation on (in case of Id Remapping).
    virtual binder::Status     getNumberOfCameras(int32_t type, int32_t* numCameras);

    virtual binder::Status     getCameraInfo(int cameraId, bool overrideToPortrait,
            hardware::CameraInfo* cameraInfo) override;
    virtual binder::Status     getCameraCharacteristics(const std::string& cameraId,
            int targetSdkVersion, bool overrideToPortrait, CameraMetadata* cameraInfo) override;
    virtual binder::Status     getCameraVendorTagDescriptor(
            /*out*/
            hardware::camera2::params::VendorTagDescriptor* desc);
    virtual binder::Status     getCameraVendorTagCache(
            /*out*/
            hardware::camera2::params::VendorTagDescriptorCache* cache);

    virtual binder::Status     connect(const sp<hardware::ICameraClient>& cameraClient,
            int32_t cameraId, const std::string& clientPackageName,
            int32_t clientUid, int clientPid, int targetSdkVersion,
            bool overrideToPortrait, bool forceSlowJpegMode,
            /*out*/
            sp<hardware::ICamera>* device) override;

    virtual binder::Status     connectDevice(
            const sp<hardware::camera2::ICameraDeviceCallbacks>& cameraCb,
            const std::string& cameraId,
            const std::string& clientPackageName, const std::optional<std::string>& clientFeatureId,
            int32_t clientUid, int scoreOffset, int targetSdkVersion, bool overrideToPortrait,
            /*out*/
            sp<hardware::camera2::ICameraDeviceUser>* device);

    virtual binder::Status    addListener(const sp<hardware::ICameraServiceListener>& listener,
            /*out*/
            std::vector<hardware::CameraStatus>* cameraStatuses);
    virtual binder::Status    removeListener(
            const sp<hardware::ICameraServiceListener>& listener);

    virtual binder::Status getConcurrentCameraIds(
        /*out*/
        std::vector<hardware::camera2::utils::ConcurrentCameraIdCombination>* concurrentCameraIds);

    virtual binder::Status isConcurrentSessionConfigurationSupported(
        const std::vector<hardware::camera2::utils::CameraIdAndSessionConfiguration>& sessions,
        int targetSdkVersion, /*out*/bool* supported);

    virtual binder::Status    getLegacyParameters(
            int32_t cameraId,
            /*out*/
            std::string* parameters);

    virtual binder::Status    setTorchMode(const std::string& cameraId, bool enabled,
            const sp<IBinder>& clientBinder);

    virtual binder::Status    turnOnTorchWithStrengthLevel(const std::string& cameraId,
            int32_t torchStrength, const sp<IBinder>& clientBinder);

    virtual binder::Status    getTorchStrengthLevel(const std::string& cameraId,
            int32_t* torchStrength);

    virtual binder::Status    notifySystemEvent(int32_t eventId,
            const std::vector<int32_t>& args);

    virtual binder::Status    notifyDeviceStateChange(int64_t newState);

    virtual binder::Status    notifyDisplayConfigurationChange();

    // OK = supports api of that version, -EOPNOTSUPP = does not support
    virtual binder::Status    supportsCameraApi(
            const std::string& cameraId, int32_t apiVersion,
            /*out*/
            bool *isSupported);

    virtual binder::Status    isHiddenPhysicalCamera(
            const std::string& cameraId,
            /*out*/
            bool *isSupported);

    virtual binder::Status injectCamera(
            const std::string& packageName, const std::string& internalCamId,
            const std::string& externalCamId,
            const sp<hardware::camera2::ICameraInjectionCallback>& callback,
            /*out*/
            sp<hardware::camera2::ICameraInjectionSession>* cameraInjectionSession);

    virtual binder::Status reportExtensionSessionStats(
            const hardware::CameraExtensionSessionStats& stats, std::string* sessionKey /*out*/);

    virtual binder::Status remapCameraIds(const hardware::CameraIdRemapping&
        cameraIdRemapping);

    // Extra permissions checks
    virtual status_t    onTransact(uint32_t code, const Parcel& data,
                                   Parcel* reply, uint32_t flags);

    virtual status_t    dump(int fd, const Vector<String16>& args);

    virtual status_t    shellCommand(int in, int out, int err, const Vector<String16>& args);

    binder::Status      addListenerHelper(const sp<hardware::ICameraServiceListener>& listener,
            /*out*/
            std::vector<hardware::CameraStatus>* cameraStatuses, bool isVendor = false,
            bool isProcessLocalTest = false);

    // Monitored UIDs availability notification
    void                notifyMonitoredUids();
    void                notifyMonitoredUids(const std::unordered_set<uid_t> &notifyUidSet);

    // Stores current open session device info in temp file.
    void cacheDump();

    // Register an offline client for a given active camera id
    status_t addOfflineClient(const std::string &cameraId, sp<BasicClient> offlineClient);

    /////////////////////////////////////////////////////////////////////
    // Client functionality

    enum sound_kind {
        SOUND_SHUTTER = 0,
        SOUND_RECORDING_START = 1,
        SOUND_RECORDING_STOP = 2,
        NUM_SOUNDS
    };

    void                playSound(sound_kind kind);
    void                loadSoundLocked(sound_kind kind);
    void                decreaseSoundRef();
    void                increaseSoundRef();

    /////////////////////////////////////////////////////////////////////
    // CameraDeviceFactory functionality
    std::pair<int, IPCTransport>    getDeviceVersion(const std::string& cameraId,
            bool overrideToPortrait, int* portraitRotation,
            int* facing = nullptr, int* orientation = nullptr);

    /////////////////////////////////////////////////////////////////////
    // Methods to be used in CameraService class tests only
    //
    // CameraService class test method only - clear static variables in the
    // cameraserver process, which otherwise might affect multiple test runs.
    void                clearCachedVariables();

    // Add test listener, linkToDeath won't be called since this is for process
    // local testing.
    binder::Status    addListenerTest(const sp<hardware::ICameraServiceListener>& listener,
            /*out*/
            std::vector<hardware::CameraStatus>* cameraStatuses);

    /////////////////////////////////////////////////////////////////////
    // Shared utilities
    static binder::Status filterGetInfoErrorCode(status_t err);

    /////////////////////////////////////////////////////////////////////
    // CameraClient functionality

    class BasicClient : public virtual RefBase {
    friend class CameraService;
    public:
        virtual status_t       initialize(sp<CameraProviderManager> manager,
                const std::string& monitorTags) = 0;
        virtual binder::Status disconnect();

        // because we can't virtually inherit IInterface, which breaks
        // virtual inheritance
        virtual sp<IBinder>    asBinderWrapper() = 0;

        // Return the remote callback binder object (e.g. ICameraDeviceCallbacks)
        sp<IBinder>            getRemote() {
            return mRemoteBinder;
        }

        bool getOverrideToPortrait() const {
            return mOverrideToPortrait;
        }

        // Disallows dumping over binder interface
        virtual status_t dump(int fd, const Vector<String16>& args);
        // Internal dump method to be called by CameraService
        virtual status_t dumpClient(int fd, const Vector<String16>& args) = 0;

        virtual status_t startWatchingTags(const std::string &tags, int outFd);
        virtual status_t stopWatchingTags(int outFd);
        virtual status_t dumpWatchedEventsToVector(std::vector<std::string> &out);

        // Return the package name for this client
        virtual std::string getPackageName() const;

        // Return the camera facing for this client
        virtual int getCameraFacing() const;

        // Return the camera orientation for this client
        virtual int getCameraOrientation() const;

        // Notify client about a fatal error
        virtual void notifyError(int32_t errorCode,
                const CaptureResultExtras& resultExtras) = 0;

        // Get the UID of the application client using this
        virtual uid_t getClientUid() const;

        // Get the PID of the application client using this
        virtual int getClientPid() const;

        // Check what API level is used for this client. This is used to determine which
        // superclass this can be cast to.
        virtual bool canCastToApiClient(apiLevel level) const;

        // Block the client form using the camera
        virtual void block();

        // set audio restriction from client
        // Will call into camera service and hold mServiceLock
        virtual status_t setAudioRestriction(int32_t mode);

        // Get current global audio restriction setting
        // Will call into camera service and hold mServiceLock
        virtual int32_t getServiceAudioRestriction() const;

        // Get current audio restriction setting for this client
        virtual int32_t getAudioRestriction() const;

        static bool isValidAudioRestriction(int32_t mode);

        // Override rotate-and-crop AUTO behavior
        virtual status_t setRotateAndCropOverride(uint8_t rotateAndCrop, bool fromHal = false) = 0;

        // Override autoframing AUTO behaviour
        virtual status_t setAutoframingOverride(uint8_t autoframingValue) = 0;

        // Whether the client supports camera muting (black only output)
        virtual bool supportsCameraMute() = 0;

        // Set/reset camera mute
        virtual status_t setCameraMute(bool enabled) = 0;

        // Set Camera service watchdog
        virtual status_t setCameraServiceWatchdog(bool enabled) = 0;

        // Set stream use case overrides
        virtual void setStreamUseCaseOverrides(
                const std::vector<int64_t>& useCaseOverrides) = 0;

        // Clear stream use case overrides
        virtual void clearStreamUseCaseOverrides() = 0;

        // Whether the client supports camera zoom override
        virtual bool supportsZoomOverride() = 0;

        // Set/reset zoom override
        virtual status_t setZoomOverride(int32_t zoomOverride) = 0;

        // The injection camera session to replace the internal camera
        // session.
        virtual status_t injectCamera(const std::string& injectedCamId,
                sp<CameraProviderManager> manager) = 0;

        // Stop the injection camera and restore to internal camera session.
        virtual status_t stopInjection() = 0;

    protected:
        BasicClient(const sp<CameraService>& cameraService,
                const sp<IBinder>& remoteCallback,
                const std::string& clientPackageName,
                bool nativeClient,
                const std::optional<std::string>& clientFeatureId,
                const std::string& cameraIdStr,
                int cameraFacing,
                int sensorOrientation,
                int clientPid,
                uid_t clientUid,
                int servicePid,
                bool overrideToPortrait);

        virtual ~BasicClient();

        // the instance is in the middle of destruction. When this is set,
        // the instance should not be accessed from callback.
        // CameraService's mClientLock should be acquired to access this.
        // - subclasses should set this to true in their destructors.
        bool                            mDestructionStarted;

        // these are initialized in the constructor.
        static sp<CameraService>        sCameraService;
        const std::string               mCameraIdStr;
        const int                       mCameraFacing;
        const int                       mOrientation;
        std::string                     mClientPackageName;
        bool                            mSystemNativeClient;
        std::optional<std::string>      mClientFeatureId;
        pid_t                           mClientPid;
        const uid_t                     mClientUid;
        const pid_t                     mServicePid;
        bool                            mDisconnected;
        bool                            mUidIsTrusted;
        bool                            mOverrideToPortrait;

        mutable Mutex                   mAudioRestrictionLock;
        int32_t                         mAudioRestriction;

        // - The app-side Binder interface to receive callbacks from us
        sp<IBinder>                     mRemoteBinder;   // immutable after constructor

        // Permissions management methods for camera lifecycle

        // Notify rest of system/apps about camera opening, and check appops
        virtual status_t                startCameraOps();
        // Notify rest of system/apps about camera starting to stream data, and confirm appops
        virtual status_t                startCameraStreamingOps();
        // Notify rest of system/apps about camera stopping streaming data
        virtual status_t                finishCameraStreamingOps();
        // Notify rest of system/apps about camera closing
        virtual status_t                finishCameraOps();
        // Handle errors for start/checkOps
        virtual status_t                handleAppOpMode(int32_t mode);
        // Just notify camera appops to trigger unblocking dialog if sensor
        // privacy is enabled and camera mute is not supported
        virtual status_t                noteAppOp();

        std::unique_ptr<AppOpsManager>  mAppOpsManager = nullptr;

        class OpsCallback : public BnAppOpsCallback {
        public:
            explicit OpsCallback(wp<BasicClient> client);
            virtual void opChanged(int32_t op, const String16& packageName);

        private:
            wp<BasicClient> mClient;

        }; // class OpsCallback

        sp<OpsCallback> mOpsCallback;
        // Track whether checkOps was called successfully, to avoid
        // finishing what we didn't start, on camera open.
        bool            mOpsActive;
        // Track whether startOps was called successfully on start of
        // camera streaming.
        bool            mOpsStreaming;

        // IAppOpsCallback interface, indirected through opListener
        virtual void opChanged(int32_t op, const String16& packageName);
    }; // class BasicClient

    class Client : public hardware::BnCamera, public BasicClient
    {
    public:
        typedef hardware::ICameraClient TCamCallbacks;

        // ICamera interface (see ICamera for details)
        virtual binder::Status disconnect();
        virtual status_t      connect(const sp<hardware::ICameraClient>& client) = 0;
        virtual status_t      lock() = 0;
        virtual status_t      unlock() = 0;
        virtual status_t      setPreviewTarget(const sp<IGraphicBufferProducer>& bufferProducer)=0;
        virtual void          setPreviewCallbackFlag(int flag) = 0;
        virtual status_t      setPreviewCallbackTarget(
                const sp<IGraphicBufferProducer>& callbackProducer) = 0;
        virtual status_t      startPreview() = 0;
        virtual void          stopPreview() = 0;
        virtual bool          previewEnabled() = 0;
        virtual status_t      setVideoBufferMode(int32_t videoBufferMode) = 0;
        virtual status_t      startRecording() = 0;
        virtual void          stopRecording() = 0;
        virtual bool          recordingEnabled() = 0;
        virtual void          releaseRecordingFrame(const sp<IMemory>& mem) = 0;
        virtual status_t      autoFocus() = 0;
        virtual status_t      cancelAutoFocus() = 0;
        virtual status_t      takePicture(int msgType) = 0;
        virtual status_t      setParameters(const String8& params) = 0;
        virtual String8       getParameters() const = 0;
        virtual status_t      sendCommand(int32_t cmd, int32_t arg1, int32_t arg2) = 0;
        virtual status_t      setVideoTarget(const sp<IGraphicBufferProducer>& bufferProducer) = 0;

        // Interface used by CameraService
        Client(const sp<CameraService>& cameraService,
                const sp<hardware::ICameraClient>& cameraClient,
                const std::string& clientPackageName,
                bool systemNativeClient,
                const std::optional<std::string>& clientFeatureId,
                const std::string& cameraIdStr,
                int api1CameraId,
                int cameraFacing,
                int sensorOrientation,
                int clientPid,
                uid_t clientUid,
                int servicePid,
                bool overrideToPortrait);
        ~Client();

        // return our camera client
        const sp<hardware::ICameraClient>&    getRemoteCallback() {
            return mRemoteCallback;
        }

        virtual sp<IBinder> asBinderWrapper() {
            return asBinder(this);
        }

        virtual void         notifyError(int32_t errorCode,
                                         const CaptureResultExtras& resultExtras);

        // Check what API level is used for this client. This is used to determine which
        // superclass this can be cast to.
        virtual bool canCastToApiClient(apiLevel level) const;

        void setImageDumpMask(int /*mask*/) { }
    protected:
        // Initialized in constructor

        // - The app-side Binder interface to receive callbacks from us
        sp<hardware::ICameraClient>               mRemoteCallback;

        int mCameraId;  // All API1 clients use integer camera IDs
    }; // class Client

    /**
     * A listener class that implements the LISTENER interface for use with a ClientManager, and
     * implements the following methods:
     *    void onClientRemoved(const ClientDescriptor<KEY, VALUE>& descriptor);
     *    void onClientAdded(const ClientDescriptor<KEY, VALUE>& descriptor);
     */
    class ClientEventListener {
    public:
        void onClientAdded(const resource_policy::ClientDescriptor<std::string,
                sp<CameraService::BasicClient>>& descriptor);
        void onClientRemoved(const resource_policy::ClientDescriptor<std::string,
                sp<CameraService::BasicClient>>& descriptor);
    }; // class ClientEventListener

    typedef std::shared_ptr<resource_policy::ClientDescriptor<std::string,
            sp<CameraService::BasicClient>>> DescriptorPtr;

    /**
     * A container class for managing active camera clients that are using HAL devices.  Active
     * clients are represented by ClientDescriptor objects that contain strong pointers to the
     * actual BasicClient subclass binder interface implementation.
     *
     * This class manages the eviction behavior for the camera clients.  See the parent class
     * implementation in utils/ClientManager for the specifics of this behavior.
     */
    class CameraClientManager : public resource_policy::ClientManager<std::string,
            sp<CameraService::BasicClient>, ClientEventListener> {
    public:
        CameraClientManager();
        virtual ~CameraClientManager();

        /**
         * Return a strong pointer to the active BasicClient for this camera ID, or an empty
         * if none exists.
         */
        sp<CameraService::BasicClient> getCameraClient(const std::string& id) const;

        /**
         * Return a string describing the current state.
         */
        std::string toString() const;

        /**
         * Make a ClientDescriptor object wrapping the given BasicClient strong pointer.
         */
        static DescriptorPtr makeClientDescriptor(const std::string& key,
                const sp<BasicClient>& value, int32_t cost,
                const std::set<std::string>& conflictingKeys, int32_t score,
                int32_t ownerId, int32_t state, int oomScoreOffset, bool systemNativeClient);

        /**
         * Make a ClientDescriptor object wrapping the given BasicClient strong pointer with
         * values intialized from a prior ClientDescriptor.
         */
        static DescriptorPtr makeClientDescriptor(const sp<BasicClient>& value,
                const CameraService::DescriptorPtr& partial, int oomScoreOffset,
                bool systemNativeClient);

    }; // class CameraClientManager

    int32_t updateAudioRestriction();
    int32_t updateAudioRestrictionLocked();

private:

    // TODO: b/263304156 update this to make use of a death callback for more
    // robust/fault tolerant logging
    static const sp<IActivityManager>& getActivityManager() {
        static const char* kActivityService = "activity";
        static const auto activityManager = []() -> sp<IActivityManager> {
            const sp<IServiceManager> sm(defaultServiceManager());
            if (sm != nullptr) {
                 return interface_cast<IActivityManager>(sm->checkService(String16(kActivityService)));
            }
            return nullptr;
        }();
        return activityManager;
    }

    /**
     * Typesafe version of device status, containing both the HAL-layer and the service interface-
     * layer values.
     */
    enum class StatusInternal : int32_t {
        NOT_PRESENT = static_cast<int32_t>(CameraDeviceStatus::NOT_PRESENT),
        PRESENT = static_cast<int32_t>(CameraDeviceStatus::PRESENT),
        ENUMERATING = static_cast<int32_t>(CameraDeviceStatus::ENUMERATING),
        NOT_AVAILABLE = static_cast<int32_t>(hardware::ICameraServiceListener::STATUS_NOT_AVAILABLE),
        UNKNOWN = static_cast<int32_t>(hardware::ICameraServiceListener::STATUS_UNKNOWN)
    };

    friend int32_t format_as(StatusInternal s);

    /**
     * Container class for the state of each logical camera device, including: ID, status, and
     * dependencies on other devices.  The mapping of camera ID -> state saved in mCameraStates
     * represents the camera devices advertised by the HAL (and any USB devices, when we add
     * those).
     *
     * This container does NOT represent an active camera client.  These are represented using
     * the ClientDescriptors stored in mActiveClientManager.
     */
    class CameraState {
    public:

        /**
         * Make a new CameraState and set the ID, cost, and conflicting devices using the values
         * returned in the HAL's camera_info struct for each device.
         */
        CameraState(const std::string& id, int cost, const std::set<std::string>& conflicting,
                SystemCameraKind deviceKind, const std::vector<std::string>& physicalCameras);
        virtual ~CameraState();

        /**
         * Return the status for this device.
         *
         * This method acquires mStatusLock.
         */
        StatusInternal getStatus() const;

        /**
         * This function updates the status for this camera device, unless the given status
         * is in the given list of rejected status states, and execute the function passed in
         * with a signature onStatusUpdateLocked(const std::string&, int32_t)
         * if the status has changed.
         *
         * This method is idempotent, and will not result in the function passed to
         * onStatusUpdateLocked being called more than once for the same arguments.
         * This method aquires mStatusLock.
         */
        template<class Func>
        void updateStatus(StatusInternal status,
                const std::string& cameraId,
                std::initializer_list<StatusInternal> rejectSourceStates,
                Func onStatusUpdatedLocked);

        /**
         * Return the last set CameraParameters object generated from the information returned by
         * the HAL for this device (or an empty CameraParameters object if none has been set).
         */
        CameraParameters getShimParams() const;

        /**
         * Set the CameraParameters for this device.
         */
        void setShimParams(const CameraParameters& params);

        /**
         * Return the resource_cost advertised by the HAL for this device.
         */
        int getCost() const;

        /**
         * Return a set of the IDs of conflicting devices advertised by the HAL for this device.
         */
        std::set<std::string> getConflicting() const;

        /**
         * Return the kind (SystemCameraKind) of this camera device.
         */
        SystemCameraKind getSystemCameraKind() const;

        /**
         * Return whether this camera is a logical multi-camera and has a
         * particular physical sub-camera.
         */
        bool containsPhysicalCamera(const std::string& physicalCameraId) const;

        /**
         * Add/Remove the unavailable physical camera ID.
         */
        bool addUnavailablePhysicalId(const std::string& physicalId);
        bool removeUnavailablePhysicalId(const std::string& physicalId);

        /**
         * Set and get client package name.
         */
        void setClientPackage(const std::string& clientPackage);
        std::string getClientPackage() const;

        /**
         * Return the unavailable physical ids for this device.
         *
         * This method acquires mStatusLock.
         */
        std::vector<std::string> getUnavailablePhysicalIds() const;
    private:
        const std::string mId;
        StatusInternal mStatus; // protected by mStatusLock
        const int mCost;
        std::set<std::string> mConflicting;
        std::set<std::string> mUnavailablePhysicalIds;
        std::string mClientPackage;
        mutable Mutex mStatusLock;
        CameraParameters mShimParams;
        const SystemCameraKind mSystemCameraKind;
        const std::vector<std::string> mPhysicalCameras; // Empty if not a logical multi-camera
    }; // class CameraState

    // Observer for UID lifecycle enforcing that UIDs in idle
    // state cannot use the camera to protect user privacy.
    class UidPolicy :
        public BnUidObserver,
        public virtual IBinder::DeathRecipient,
        public virtual IServiceManager::LocalRegistrationCallback {
    public:
        explicit UidPolicy(sp<CameraService> service)
                : mRegistered(false), mService(service) {}

        void registerSelf();
        void unregisterSelf();

        bool isUidActive(uid_t uid, const std::string &callingPackage);
        int32_t getProcState(uid_t uid);

        // IUidObserver
        void onUidGone(uid_t uid, bool disabled) override;
        void onUidActive(uid_t uid) override;
        void onUidIdle(uid_t uid, bool disabled) override;
        void onUidStateChanged(uid_t uid, int32_t procState, int64_t procStateSeq,
                int32_t capability) override;
        void onUidProcAdjChanged(uid_t uid, int adj) override;

        void addOverrideUid(uid_t uid, const std::string &callingPackage, bool active);
        void removeOverrideUid(uid_t uid, const std::string &callingPackage);

        void registerMonitorUid(uid_t uid, bool openCamera);
        void unregisterMonitorUid(uid_t uid, bool closeCamera);

        // Implementation of IServiceManager::LocalRegistrationCallback
        virtual void onServiceRegistration(const String16& name,
                        const sp<IBinder>& binder) override;
        // IBinder::DeathRecipient implementation
        virtual void binderDied(const wp<IBinder> &who);
    private:
        bool isUidActiveLocked(uid_t uid, const std::string &callingPackage);
        int32_t getProcStateLocked(uid_t uid);
        void updateOverrideUid(uid_t uid, const std::string &callingPackage, bool active,
                bool insert);
        void registerWithActivityManager();

        struct MonitoredUid {
            int32_t procState;
            int32_t procAdj;
            bool hasCamera;
            size_t refCount;
        };

        Mutex mUidLock;
        bool mRegistered;
        ActivityManager mAm;
        wp<CameraService> mService;
        std::unordered_set<uid_t> mActiveUids;
        // Monitored uid map
        std::unordered_map<uid_t, MonitoredUid> mMonitoredUids;
        std::unordered_map<uid_t, bool> mOverrideUids;
        sp<IBinder> mObserverToken;
    }; // class UidPolicy

    // If sensor privacy is enabled then all apps, including those that are active, should be
    // prevented from accessing the camera.
    class SensorPrivacyPolicy : public hardware::BnSensorPrivacyListener,
            public virtual IBinder::DeathRecipient,
            public virtual IServiceManager::LocalRegistrationCallback {
        public:
            explicit SensorPrivacyPolicy(wp<CameraService> service)
                    : mService(service), mSensorPrivacyEnabled(false), mRegistered(false) {}

            void registerSelf();
            void unregisterSelf();

            bool isSensorPrivacyEnabled();
            bool isCameraPrivacyEnabled();

            binder::Status onSensorPrivacyChanged(int toggleType, int sensor,
                                                  bool enabled);

            // Implementation of IServiceManager::LocalRegistrationCallback
            virtual void onServiceRegistration(const String16& name,
                                               const sp<IBinder>& binder) override;
            // IBinder::DeathRecipient implementation
            virtual void binderDied(const wp<IBinder> &who);

        private:
            SensorPrivacyManager mSpm;
            wp<CameraService> mService;
            Mutex mSensorPrivacyLock;
            bool mSensorPrivacyEnabled;
            bool mRegistered;

            bool hasCameraPrivacyFeature();
            void registerWithSensorPrivacyManager();
    };

    sp<UidPolicy> mUidPolicy;

    sp<SensorPrivacyPolicy> mSensorPrivacyPolicy;

    std::shared_ptr<CameraServiceProxyWrapper> mCameraServiceProxyWrapper;

    // Delay-load the Camera HAL module
    virtual void onFirstRef();

    // Eumerate all camera providers in the system
    status_t enumerateProviders();

    // Add/remove a new camera to camera and torch state lists or remove an unplugged one
    // Caller must not hold mServiceLock
    void addStates(const std::string& id);
    void removeStates(const std::string& id);

    // Check if we can connect, before we acquire the service lock.
    // The returned originalClientPid is the PID of the original process that wants to connect to
    // camera.
    // The returned clientPid is the PID of the client that directly connects to camera.
    // originalClientPid and clientPid are usually the same except when the application uses
    // mediaserver to connect to camera (using MediaRecorder to connect to camera). In that case,
    // clientPid is the PID of mediaserver and originalClientPid is the PID of the application.
    binder::Status validateConnectLocked(const std::string& cameraId, const std::string& clientName,
            /*inout*/int& clientUid, /*inout*/int& clientPid, /*out*/int& originalClientPid) const;
    binder::Status validateClientPermissionsLocked(const std::string& cameraId,
            const std::string& clientName, /*inout*/int& clientUid, /*inout*/int& clientPid,
            /*out*/int& originalClientPid) const;

    // Handle active client evictions, and update service state.
    // Only call with with mServiceLock held.
    status_t handleEvictionsLocked(const std::string& cameraId, int clientPid,
        apiLevel effectiveApiLevel, const sp<IBinder>& remoteCallback,
        const std::string& packageName, int scoreOffset, bool systemNativeClient,
        /*out*/
        sp<BasicClient>* client,
        std::shared_ptr<resource_policy::ClientDescriptor<std::string, sp<BasicClient>>>* partial);

    // Should an operation attempt on a cameraId be rejected ? (this can happen
    // under various conditions. For example if a camera device is advertised as
    // system only or hidden secure camera, amongst possible others.
    bool shouldRejectSystemCameraConnection(const std::string& cameraId) const;

    // Should a device status update be skipped for a particular camera device ? (this can happen
    // under various conditions. For example if a camera device is advertised as
    // system only or hidden secure camera, amongst possible others.
    static bool shouldSkipStatusUpdates(SystemCameraKind systemCameraKind, bool isVendorListener,
            int clientPid, int clientUid);

    // Gets the kind of camera device (i.e public, hidden secure or system only)
    // getSystemCameraKind() needs mInterfaceMutex which might lead to deadlocks
    // if held along with mStatusListenerLock (depending on lock ordering, b/141756275), it is
    // recommended that we don't call this function with mStatusListenerLock held.
    status_t getSystemCameraKind(const std::string& cameraId, SystemCameraKind *kind) const;

    // Update the set of API1Compatible camera devices without including system
    // cameras and secure cameras. This is used for hiding system only cameras
    // from clients using camera1 api and not having android.permission.SYSTEM_CAMERA.
    // This function expects @param normalDeviceIds, to have normalDeviceIds
    // sorted in alpha-numeric order.
    void filterAPI1SystemCameraLocked(const std::vector<std::string> &normalDeviceIds);

    // In some cases the calling code has no access to the package it runs under.
    // For example, NDK camera API.
    // In this case we will get the packages for the calling UID and pick the first one
    // for attributing the app op. This will work correctly for runtime permissions
    // as for legacy apps we will toggle the app op for all packages in the UID.
    // The caveat is that the operation may be attributed to the wrong package and
    // stats based on app ops may be slightly off.
    std::string getPackageNameFromUid(int clientUid);

    // Single implementation shared between the various connect calls
    template<class CALLBACK, class CLIENT>
    binder::Status connectHelper(const sp<CALLBACK>& cameraCb, const std::string& cameraId,
            int api1CameraId, const std::string& clientPackageNameMaybe, bool systemNativeClient,
            const std::optional<std::string>& clientFeatureId, int clientUid, int clientPid,
            apiLevel effectiveApiLevel, bool shimUpdateOnly, int scoreOffset, int targetSdkVersion,
            bool overrideToPortrait, bool forceSlowJpegMode, const std::string& originalCameraId,
            /*out*/sp<CLIENT>& device);

    // Lock guarding camera service state
    Mutex               mServiceLock;

    // Condition to use with mServiceLock, used to handle simultaneous connect calls from clients
    std::shared_ptr<WaitableMutexWrapper> mServiceLockWrapper;

    // Return NO_ERROR if the device with a give ID can be connected to
    status_t checkIfDeviceIsUsable(const std::string& cameraId) const;

    // Container for managing currently active application-layer clients
    CameraClientManager mActiveClientManager;

    // Adds client logs during open session to the file pointed by fd.
    void dumpOpenSessionClientLogs(int fd, const Vector<String16>& args,
            const std::string& cameraId);

    // Adds client logs during closed session to the file pointed by fd.
    void dumpClosedSessionClientLogs(int fd, const std::string& cameraId);

    // Mapping from camera ID -> state for each device, map is protected by mCameraStatesLock
    std::map<std::string, std::shared_ptr<CameraState>> mCameraStates;

    // Mutex guarding mCameraStates map
    mutable Mutex mCameraStatesLock;

    /**
     * Mapping from packageName -> {cameraIdToReplace -> newCameraIdtoUse}.
     *
     * This specifies that for packageName, for every binder operation targeting
     * cameraIdToReplace, use newCameraIdToUse instead.
     */
    typedef std::map<std::string, std::map<std::string, std::string>> TCameraIdRemapping;
    TCameraIdRemapping mCameraIdRemapping{};
    /** Mutex guarding mCameraIdRemapping. */
    Mutex mCameraIdRemappingLock;

    /** Parses cameraIdRemapping parcelable into the native cameraIdRemappingMap. */
    binder::Status parseCameraIdRemapping(
            const hardware::CameraIdRemapping& cameraIdRemapping,
            /* out */ TCameraIdRemapping* cameraIdRemappingMap);

    /**
     * Resolve the (potentially remapped) camera Id to use for packageName.
     *
     * This returns the Camera Id to use in case inputCameraId was remapped to a
     * different Id for the given packageName. Otherwise, it returns the inputCameraId.
     *
     * If the packageName is not provided, it will be inferred from the clientUid.
     */
    std::string resolveCameraId(
            const std::string& inputCameraId,
            int clientUid,
            const std::string& packageName = "");

    /**
     * Updates the state of mCameraIdRemapping, while disconnecting active clients as necessary.
     */
    void remapCameraIds(const TCameraIdRemapping& cameraIdRemapping);

    /**
     * Finds the Camera Ids that were remapped to the inputCameraId for the given client.
     */
    std::vector<std::string> findOriginalIdsForRemappedCameraId(
        const std::string& inputCameraId, int clientUid);

    // Circular buffer for storing event logging for dumps
    RingBuffer<std::string> mEventLog;
    Mutex mLogLock;

    // set of client package names to watch. if this set contains 'all', then all clients will
    // be watched. Access should be guarded by mLogLock
    std::set<std::string> mWatchedClientPackages;
    // cache of last monitored tags dump immediately before the client disconnects. If a client
    // re-connects, its entry is not updated until it disconnects again. Access should be guarded
    // by mLogLock
    std::map<std::string, std::string> mWatchedClientsDumpCache;

    // The last monitored tags set by client
    std::string mMonitorTags;

    // Currently allowed user IDs
    std::set<userid_t> mAllowedUsers;

    /**
     * Get the camera state for a given camera id.
     *
     * This acquires mCameraStatesLock.
     */
    std::shared_ptr<CameraService::CameraState> getCameraState(const std::string& cameraId) const;

    /**
     * Evict client who's remote binder has died.  Returns true if this client was in the active
     * list and was disconnected.
     *
     * This method acquires mServiceLock.
     */
    bool evictClientIdByRemote(const wp<IBinder>& cameraClient);

    /**
     * Remove the given client from the active clients list; does not disconnect the client.
     *
     * This method acquires mServiceLock.
     */
    void removeByClient(const BasicClient* client);

    /**
     * Add new client to active clients list after conflicting clients have disconnected using the
     * values set in the partial descriptor passed in to construct the actual client descriptor.
     * This is typically called at the end of a connect call.
     *
     * This method must be called with mServiceLock held.
     */
    void finishConnectLocked(const sp<BasicClient>& client, const DescriptorPtr& desc,
            int oomScoreOffset, bool systemNativeClient);

    /**
     * Returns the underlying camera Id string mapped to a camera id int
     * Empty string is returned when the cameraIdInt is invalid.
     */
    std::string cameraIdIntToStr(int cameraIdInt);

    /**
     * Returns the underlying camera Id string mapped to a camera id int
     * Empty string is returned when the cameraIdInt is invalid.
     */
    std::string cameraIdIntToStrLocked(int cameraIdInt);

    /**
     * Remove a single client corresponding to the given camera id from the list of active clients.
     * If none exists, return an empty strongpointer.
     *
     * This method must be called with mServiceLock held.
     */
    sp<CameraService::BasicClient> removeClientLocked(const std::string& cameraId);

    /**
     * Handle a notification that the current device user has changed.
     */
    void doUserSwitch(const std::vector<int32_t>& newUserIds);

    /**
     * Add an event log message.
     */
    void logEvent(const std::string &event);

    /**
     * Add an event log message that a client has been disconnected.
     */
    void logDisconnected(const std::string &cameraId, int clientPid,
            const std::string &clientPackage);

    /**
     * Add an event log message that a client has been disconnected from offline device.
     */
    void logDisconnectedOffline(const std::string &cameraId, int clientPid,
            const std::string &clientPackage);

    /**
     * Add an event log message that an offline client has been connected.
     */
    void logConnectedOffline(const std::string &cameraId, int clientPid,
            const std::string &clientPackage);

    /**
     * Add an event log message that a client has been connected.
     */
    void logConnected(const std::string &cameraId, int clientPid, const std::string &clientPackage);

    /**
     * Add an event log message that a client's connect attempt has been rejected.
     */
    void logRejected(const std::string &cameraId, int clientPid, const std::string &clientPackage,
            const std::string &reason);

    /**
     * Add an event log message when a client calls setTorchMode succesfully.
     */
    void logTorchEvent(const std::string &cameraId, const std::string &torchState, int clientPid);

    /**
     * Add an event log message that the current device user has been switched.
     */
    void logUserSwitch(const std::set<userid_t>& oldUserIds,
        const std::set<userid_t>& newUserIds);

    /**
     * Add an event log message that a device has been removed by the HAL
     */
    void logDeviceRemoved(const std::string &cameraId, const std::string &reason);

    /**
     * Add an event log message that a device has been added by the HAL
     */
    void logDeviceAdded(const std::string &cameraId, const std::string &reason);

    /**
     * Add an event log message that a client has unexpectedly died.
     */
    void logClientDied(int clientPid, const std::string &reason);

    /**
     * Add a event log message that a serious service-level error has occured
     * The errorCode should be one of the Android Errors
     */
    void logServiceError(const std::string &msg, int errorCode);

    /**
     * Dump the event log to an FD
     */
    void dumpEventLog(int fd);

    void cacheClientTagDumpIfNeeded(const std::string &cameraId, BasicClient *client);

    /**
     * This method will acquire mServiceLock
     */
    void updateCameraNumAndIds();

    /**
     * Filter camera characteristics for S Performance class primary cameras.
     * mServiceLock should be locked.
     */
    void filterSPerfClassCharacteristicsLocked();

    // File descriptor to temp file used for caching previous open
    // session dumpsys info.
    int mMemFd;

    // Number of camera devices (excluding hidden secure cameras)
    int                 mNumberOfCameras;
    // Number of camera devices (excluding hidden secure cameras and
    // system cameras)
    int                 mNumberOfCamerasWithoutSystemCamera;

    std::vector<std::string> mNormalDeviceIds;
    std::vector<std::string> mNormalDeviceIdsWithoutSystemCamera;
    std::set<std::string> mPerfClassPrimaryCameraIds;

    // sounds
    sp<MediaPlayer>     newMediaPlayer(const char *file);

    Mutex               mSoundLock;
    sp<MediaPlayer>     mSoundPlayer[NUM_SOUNDS];
    int                 mSoundRef;  // reference count (release all MediaPlayer when 0)

    // Basic flag on whether the camera subsystem is in a usable state
    bool                mInitialized;

    sp<CameraProviderManager> mCameraProviderManager;

    class ServiceListener : public virtual IBinder::DeathRecipient {
        public:
            ServiceListener(sp<CameraService> parent, sp<hardware::ICameraServiceListener> listener,
                    int uid, int pid, bool isVendorClient, bool openCloseCallbackAllowed)
                    : mParent(parent), mListener(listener), mListenerUid(uid), mListenerPid(pid),
                      mIsVendorListener(isVendorClient),
                      mOpenCloseCallbackAllowed(openCloseCallbackAllowed) { }

            status_t initialize(bool isProcessLocalTest) {
                if (isProcessLocalTest) {
                    return OK;
                }
                return IInterface::asBinder(mListener)->linkToDeath(this);
            }

            template<typename... args_t>
            void handleBinderStatus(const binder::Status &ret, const char *logOnError,
                    args_t... args) {
                if (!ret.isOk() &&
                        (ret.exceptionCode() != binder::Status::Exception::EX_TRANSACTION_FAILED
                        || !mLastTransactFailed)) {
                    ALOGE(logOnError, args...);
                }

                // If the transaction failed, the process may have died (or other things, see
                // b/28321379). Mute consecutive errors from this listener to avoid log spam.
                if (ret.exceptionCode() == binder::Status::Exception::EX_TRANSACTION_FAILED) {
                    if (!mLastTransactFailed) {
                        ALOGE("%s: Muting similar errors from listener %d:%d", __FUNCTION__,
                                mListenerUid, mListenerPid);
                    }
                    mLastTransactFailed = true;
                } else {
                    // Reset mLastTransactFailed when binder becomes healthy again.
                    mLastTransactFailed = false;
                }
            }

            virtual void binderDied(const wp<IBinder> &/*who*/) {
                auto parent = mParent.promote();
                if (parent.get() != nullptr) {
                    parent->removeListener(mListener);
                }
            }

            int getListenerUid() { return mListenerUid; }
            int getListenerPid() { return mListenerPid; }
            sp<hardware::ICameraServiceListener> getListener() { return mListener; }
            bool isVendorListener() { return mIsVendorListener; }
            bool isOpenCloseCallbackAllowed() { return mOpenCloseCallbackAllowed; }

        private:
            wp<CameraService> mParent;
            sp<hardware::ICameraServiceListener> mListener;
            int mListenerUid = -1;
            int mListenerPid = -1;
            bool mIsVendorListener = false;
            bool mOpenCloseCallbackAllowed = false;

            // Flag for preventing log spam when binder becomes unhealthy
            bool mLastTransactFailed = false;
    };

    // Guarded by mStatusListenerMutex
    std::vector<sp<ServiceListener>> mListenerList;

    Mutex       mStatusListenerLock;

    /**
     * Update the status for the given camera id (if that device exists), and broadcast the
     * status update to all current ICameraServiceListeners if the status has changed.  Any
     * statuses in rejectedSourceStates will be ignored.
     *
     * This method must be idempotent.
     * This method acquires mStatusLock and mStatusListenerLock.
     */
    void updateStatus(StatusInternal status,
            const std::string& cameraId,
            std::initializer_list<StatusInternal>
                rejectedSourceStates);
    void updateStatus(StatusInternal status,
            const std::string& cameraId);

    /**
     * Update the opened/closed status of the given camera id.
     *
     * This method acqiures mStatusListenerLock.
     */
    void updateOpenCloseStatus(const std::string& cameraId, bool open,
            const std::string& packageName);

    // flashlight control
    sp<CameraFlashlight> mFlashlight;
    // guard mTorchStatusMap
    Mutex                mTorchStatusMutex;
    // guard mTorchClientMap
    Mutex                mTorchClientMapMutex;
    // guard mTorchUidMap
    Mutex                mTorchUidMapMutex;
    // camera id -> torch status
    KeyedVector<std::string, TorchModeStatus>
            mTorchStatusMap;
    // camera id -> torch client binder
    // only store the last client that turns on each camera's torch mode
    KeyedVector<std::string, sp<IBinder>> mTorchClientMap;
    // camera id -> [incoming uid, current uid] pair
    std::map<std::string, std::pair<int, int>> mTorchUidMap;

    // check and handle if torch client's process has died
    void handleTorchClientBinderDied(const wp<IBinder> &who);

    // handle torch mode status change and invoke callbacks. mTorchStatusMutex
    // should be locked.
    void onTorchStatusChangedLocked(const std::string& cameraId,
            TorchModeStatus newStatus,
            SystemCameraKind systemCameraKind);

    // get a camera's torch status. mTorchStatusMutex should be locked.
    status_t getTorchStatusLocked(const std::string &cameraId,
             TorchModeStatus *status) const;

    // set a camera's torch status. mTorchStatusMutex should be locked.
    status_t setTorchStatusLocked(const std::string &cameraId,
            TorchModeStatus status);

    // notify physical camera status when the physical camera is public.
    // Expects mStatusListenerLock to be locked.
    void notifyPhysicalCameraStatusLocked(int32_t status, const std::string& physicalCameraId,
            const std::list<std::string>& logicalCameraIds, SystemCameraKind deviceKind);

    // get list of logical cameras which are backed by physicalCameraId
    std::list<std::string> getLogicalCameras(const std::string& physicalCameraId);


    // IBinder::DeathRecipient implementation
    virtual void        binderDied(const wp<IBinder> &who);

    /**
     * Initialize and cache the metadata used by the HAL1 shim for a given cameraId.
     *
     * Sets Status to a service-specific error on failure
     */
    binder::Status      initializeShimMetadata(int cameraId);

    /**
     * Get the cached CameraParameters for the camera. If they haven't been
     * cached yet, then initialize them for the first time.
     *
     * Sets Status to a service-specific error on failure
     */
    binder::Status      getLegacyParametersLazy(int cameraId, /*out*/CameraParameters* parameters);

    // Blocks all clients from the UID
    void blockClientsForUid(uid_t uid);

    // Blocks all active clients.
    void blockAllClients();

    // Overrides the UID state as if it is idle
    status_t handleSetUidState(const Vector<String16>& args, int err);

    // Clears the override for the UID state
    status_t handleResetUidState(const Vector<String16>& args, int err);

    // Gets the UID state
    status_t handleGetUidState(const Vector<String16>& args, int out, int err);

    // Set the rotate-and-crop AUTO override behavior
    status_t handleSetRotateAndCrop(const Vector<String16>& args);

    // Get the rotate-and-crop AUTO override behavior
    status_t handleGetRotateAndCrop(int out);

    // Set the autoframing AUTO override behaviour.
    status_t handleSetAutoframing(const Vector<String16>& args);

    // Get the autoframing AUTO override behaviour
    status_t handleGetAutoframing(int out);

    // Set the mask for image dump to disk
    status_t handleSetImageDumpMask(const Vector<String16>& args);

    // Get the mask for image dump to disk
    status_t handleGetImageDumpMask(int out);

    // Set the camera mute state
    status_t handleSetCameraMute(const Vector<String16>& args);

    // Set the stream use case overrides
    status_t handleSetStreamUseCaseOverrides(const Vector<String16>& args);

    // Clear the stream use case overrides
    void handleClearStreamUseCaseOverrides();

    // Set or clear the zoom override flag
    status_t handleSetZoomOverride(const Vector<String16>& args);

    // Set Camera Id remapping using 'cmd'
    status_t handleCameraIdRemapping(const Vector<String16>& args, int errFd);

    // Handle 'watch' command as passed through 'cmd'
    status_t handleWatchCommand(const Vector<String16> &args, int inFd, int outFd);

    // Set the camera service watchdog
    status_t handleSetCameraServiceWatchdog(const Vector<String16>& args);

    // Enable tag monitoring of the given tags in provided clients
    status_t startWatchingTags(const Vector<String16> &args, int outFd);

    // Disable tag monitoring
    status_t stopWatchingTags(int outFd);

    // Clears mWatchedClientsDumpCache
    status_t clearCachedMonitoredTagDumps(int outFd);

    // Print events of monitored tags in all cached and attached clients
    status_t printWatchedTags(int outFd);

    // Print events of monitored tags in all attached clients as they are captured. New events are
    // fetched every `refreshMillis` ms
    // NOTE: This function does not terminate until user passes '\n' to inFd.
    status_t printWatchedTagsUntilInterrupt(const Vector<String16> &args, int inFd, int outFd);

    // Parses comma separated clients list and adds them to mWatchedClientPackages.
    // Does not acquire mLogLock before modifying mWatchedClientPackages. It is the caller's
    // responsibility to acquire mLogLock before calling this function.
    void parseClientsToWatchLocked(const std::string &clients);

    // Prints the shell command help
    status_t printHelp(int out);

    // Returns true if client should monitor tags based on the contents of mWatchedClientPackages.
    // Acquires mLogLock before querying mWatchedClientPackages.
    bool isClientWatched(const BasicClient *client);

    // Returns true if client should monitor tags based on the contents of mWatchedClientPackages.
    // Does not acquire mLogLock before querying mWatchedClientPackages. It is the caller's
    // responsibility to acquire mLogLock before calling this functions.
    bool isClientWatchedLocked(const BasicClient *client);

    /**
     * Get the current system time as a formatted string.
     */
    static std::string getFormattedCurrentTime();

    static binder::Status makeClient(
            const sp<CameraService>& cameraService, const sp<IInterface>& cameraCb,
            const std::string& packageName, bool systemNativeClient,
            const std::optional<std::string>& featureId, const std::string& cameraId, int api1CameraId,
            int facing, int sensorOrientation, int clientPid, uid_t clientUid, int servicePid,
            std::pair<int, IPCTransport> deviceVersionAndIPCTransport, apiLevel effectiveApiLevel,
            bool overrideForPerfClass, bool overrideToPortrait, bool forceSlowJpegMode,
            const std::string& originalCameraId,
            /*out*/ sp<BasicClient>* client);

    static std::string toString(std::set<userid_t> intSet);
    static int32_t mapToInterface(TorchModeStatus status);
    static StatusInternal mapToInternal(CameraDeviceStatus status);
    static int32_t mapToInterface(StatusInternal status);


    void broadcastTorchModeStatus(const std::string& cameraId,
            TorchModeStatus status, SystemCameraKind systemCameraKind);

    void broadcastTorchStrengthLevel(const std::string& cameraId, int32_t newTorchStrengthLevel);

    void disconnectClient(const std::string& id, sp<BasicClient> clientToDisconnect);

    // Regular online and offline devices must not be in conflict at camera service layer.
    // Use separate keys for offline devices.
    static const std::string kOfflineDevice;

    // Sentinel value to be stored in `mWatchedClientsPackages` to indicate that all clients should
    // be watched.
    static const std::string kWatchAllClientsFlag;

    // TODO: right now each BasicClient holds one AppOpsManager instance.
    // We can refactor the code so all of clients share this instance
    AppOpsManager mAppOps;

    // Aggreated audio restriction mode for all camera clients
    int32_t mAudioRestriction;

    // Current override cmd rotate-and-crop mode; AUTO means no override
    uint8_t mOverrideRotateAndCropMode = ANDROID_SCALER_ROTATE_AND_CROP_AUTO;

    // Current autoframing mode
    uint8_t mOverrideAutoframingMode = ANDROID_CONTROL_AUTOFRAMING_AUTO;

    // Current image dump mask
    uint8_t mImageDumpMask = 0;

    // Current camera mute mode
    bool mOverrideCameraMuteMode = false;

    // Camera Service watchdog flag
    bool mCameraServiceWatchdogEnabled = true;

    // Current stream use case overrides
    std::vector<int64_t> mStreamUseCaseOverrides;

    // Current zoom override value
    int32_t mZoomOverrideValue = -1;

    /**
     * A listener class that implements the IBinder::DeathRecipient interface
     * for use to call back the error state injected by the external camera, and
     * camera service can kill the injection when binder signals process death.
     */
    class InjectionStatusListener : public virtual IBinder::DeathRecipient {
        public:
            InjectionStatusListener(sp<CameraService> parent) : mParent(parent) {}

            void addListener(const sp<hardware::camera2::ICameraInjectionCallback>& callback);
            void removeListener();
            void notifyInjectionError(const std::string &injectedCamId, status_t err);

            // IBinder::DeathRecipient implementation
            virtual void binderDied(const wp<IBinder>& who);

        private:
            Mutex mListenerLock;
            wp<CameraService> mParent;
            sp<hardware::camera2::ICameraInjectionCallback> mCameraInjectionCallback;
    };

    sp<InjectionStatusListener> mInjectionStatusListener;

    /**
     * A class that implements the hardware::camera2::BnCameraInjectionSession interface
     */
    class CameraInjectionSession : public hardware::camera2::BnCameraInjectionSession {
        public:
            CameraInjectionSession(sp<CameraService> parent) : mParent(parent) {}
            virtual ~CameraInjectionSession() {}
            binder::Status stopInjection() override;

        private:
            Mutex mInjectionSessionLock;
            wp<CameraService> mParent;
    };

    // When injecting the camera, it will check whether the injecting camera status is unavailable.
    // If it is, the disconnect function will be called to to prevent camera access on the device.
    status_t checkIfInjectionCameraIsPresent(const std::string& externalCamId,
            sp<BasicClient> clientSp);

    void clearInjectionParameters();

    // This is the existing camera id being replaced.
    std::string mInjectionInternalCamId;
    // This is the external camera Id replacing the internalId.
    std::string mInjectionExternalCamId;
    bool mInjectionInitPending = false;
    // Guard mInjectionInternalCamId and mInjectionInitPending.
    Mutex mInjectionParametersLock;

    // Track the folded/unfoled device state. 0 == UNFOLDED, 4 == FOLDED
    int64_t mDeviceState;

    void updateTorchUidMapLocked(const std::string& cameraId, int uid);
};

} // namespace android

#endif
