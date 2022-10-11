/*
 * Copyright (C) 2013-2018 The Android Open Source Project
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

#ifndef ANDROID_SERVERS_CAMERA_PHOTOGRAPHY_CAMERADEVICECLIENT_H
#define ANDROID_SERVERS_CAMERA_PHOTOGRAPHY_CAMERADEVICECLIENT_H

#include <android/hardware/camera2/BnCameraDeviceUser.h>
#include <android/hardware/camera2/ICameraDeviceCallbacks.h>
#include <camera/camera2/OutputConfiguration.h>
#include <camera/camera2/SessionConfiguration.h>
#include <camera/camera2/SubmitInfo.h>
#include <gui/Flags.h>  // remove with WB_LIBCAMERASERVICE_WITH_DEPENDENCIES
#include <stop_token>
#include <string>
#include <unordered_map>

#include <fmq/AidlMessageQueueCpp.h>

#include "CameraOfflineSessionClient.h"
#include "CameraService.h"
#include "binder/Status.h"
#include "common/FrameProcessorBase.h"
#include "common/Camera2ClientBase.h"
#include "CompositeStream.h"
#include "utils/CameraServiceProxyWrapper.h"
#include "utils/SessionConfigurationUtils.h"

using android::camera3::OutputStreamInfo;
using android::camera3::CompositeStream;

namespace android {

#if WB_LIBCAMERASERVICE_WITH_DEPENDENCIES
typedef uint64_t SurfaceKey;
#else
typedef sp<IBinder> SurfaceKey;
#endif

struct CameraDeviceClientBase :
         public CameraService::BasicClient,
         public hardware::camera2::BnCameraDeviceUser
{
    typedef hardware::camera2::ICameraDeviceCallbacks TCamCallbacks;

    const sp<hardware::camera2::ICameraDeviceCallbacks>& getRemoteCallback() {
        return mRemoteCallback;
    }

protected:
    CameraDeviceClientBase(
            const sp<CameraService>& cameraService,
            const sp<hardware::camera2::ICameraDeviceCallbacks>& remoteCallback,
            std::shared_ptr<AttributionAndPermissionUtils> attributionAndPermissionUtils,
            const AttributionSourceState& clientAttribution, int callingPid,
            bool systemNativeClient, const std::string& cameraId, int api1CameraId,
            int cameraFacing, int sensorOrientation, int servicePid,
            const CameraCompatibilityInfo& compatInfo, bool sharedMode);

    sp<hardware::camera2::ICameraDeviceCallbacks> mRemoteCallback;
};

/**
 * Implements the binder ICameraDeviceUser API,
 * meant for HAL3-public implementation of
 * android.hardware.photography.CameraDevice
 */
class CameraDeviceClient :
        public Camera2ClientBase<CameraDeviceClientBase>,
        public camera2::FrameProcessorBase::FilteredListener
{
public:
    /**
     * ICameraDeviceUser interface (see ICameraDeviceUser for details)
     */

    // Note that the callee gets a copy of the metadata.
    virtual binder::Status submitRequest(
            const hardware::camera2::CaptureRequest& request,
            bool streaming = false,
            /*out*/
            hardware::camera2::utils::SubmitInfo *submitInfo = nullptr) override;
    // List of requests are copied.
    virtual binder::Status submitRequestList(
            const std::vector<hardware::camera2::CaptureRequest>& requests,
            bool streaming = false,
            /*out*/
            hardware::camera2::utils::SubmitInfo *submitInfo = nullptr) override;
    virtual binder::Status cancelRequest(int requestId,
            /*out*/
            int64_t* lastFrameNumber = NULL) override;
    virtual binder::Status startStreaming(
            const std::vector<int>& streamIds,
            const std::vector<int>& surfaceIds,
            /*out*/
            hardware::camera2::utils::SubmitInfo *submitInfo = nullptr) override;

    virtual binder::Status beginConfigure() override;

    virtual binder::Status endConfigure(int operatingMode,
            const hardware::camera2::impl::CameraMetadataNative& sessionParams,
            int64_t startTimeMs,
            /*out*/
            std::vector<int>* offlineStreamIds) override;

    // Verify specific session configuration.
    virtual binder::Status isSessionConfigurationSupported(
            const SessionConfiguration& sessionConfiguration,
            /*out*/
            bool* streamStatus) override;

    // Returns -EBUSY if device is not idle or in error state
    virtual binder::Status deleteStream(int streamId) override;

    virtual binder::Status configureStreams(
            const hardware::camera2::utils::SessionConfigurationAndStreamIds&
                    sessionConfigurationAndStreamIds,
            /*out*/
            hardware::camera2::utils::OutputAndInputStreamIds*
                    outputAndInputStreamIds) override;

    virtual binder::Status createStream(
            const hardware::camera2::params::OutputConfiguration &outputConfiguration,
            /*out*/
            int32_t* newStreamId = NULL) override;

    // Create an input stream of width, height, and format.
    virtual binder::Status createInputStream(int width, int height, int format,
            bool isMultiResolution,
            /*out*/
            int32_t* newStreamId = NULL) override;

    // Get the buffer producer of the input stream
    virtual binder::Status getInputSurface(
            /*out*/
            view::Surface *inputSurface) override;

    // Create a request object from a template.
    virtual binder::Status createDefaultRequest(int templateId,
            /*out*/
            hardware::camera2::impl::CameraMetadataNative* request) override;

    // Get the static metadata for the camera
    // -- Caller owns the newly allocated metadata
    virtual binder::Status getCameraInfo(
            /*out*/
            hardware::camera2::impl::CameraMetadataNative* cameraCharacteristics) override;

    // Wait until all the submitted requests have finished processing
    virtual binder::Status waitUntilIdle() override;

    // Flush all active and pending requests as fast as possible
    virtual binder::Status flush(
            /*out*/
            int64_t* lastFrameNumber = NULL) override;

    // Prepare stream by preallocating its buffers
    virtual binder::Status prepare(int32_t streamId) override;

    // Tear down stream resources by freeing its unused buffers
    virtual binder::Status tearDown(int32_t streamId) override;

    // Prepare stream by preallocating up to maxCount of its buffers
    virtual binder::Status prepare2(int32_t maxCount, int32_t streamId) override;

    // Update an output configuration
    virtual binder::Status updateOutputConfiguration(int streamId,
            const hardware::camera2::params::OutputConfiguration &outputConfiguration) override;

    // Finalize the output configurations with surfaces not added before.
    virtual binder::Status finalizeOutputConfigurations(int32_t streamId,
            const hardware::camera2::params::OutputConfiguration &outputConfiguration) override;

    virtual binder::Status setCameraAudioRestriction(AudioRestriction mode) override;

    virtual binder::Status getCaptureResultMetadataQueue(
          android::hardware::common::fmq::MQDescriptor<
          int8_t, android::hardware::common::fmq::SynchronizedReadWrite>*
          aidl_return) override;

    virtual binder::Status getGlobalAudioRestriction(/*out*/AudioRestriction* outMode) override;

    virtual binder::Status switchToOffline(
            const sp<hardware::camera2::ICameraDeviceCallbacks>& cameraCb,
            const std::vector<int>& offlineOutputIds,
            /*out*/
            sp<hardware::camera2::ICameraOfflineSession>* session) override;

    virtual binder::Status isPrimaryClient(/*out*/bool* isPrimary) override;

    virtual binder::Status updateOutputConfigurations(
            const std::vector<int32_t>& streamIds,
            const std::vector<OutputConfiguration>& configurations) override;

    // Locked versions of beginConfigure(), createStreams(), deleteStreams() and endConfigure().
    // These methods expect mBinderSerializationLock lock to be held by the caller.
    binder::Status beginConfigureLocked() ;

    binder::Status createStreamLocked(
            const hardware::camera2::params::OutputConfiguration &outputConfiguration,
            /*out*/
            int32_t* newStreamId);

    binder::Status createInputStreamLocked(int width, int height, int format,
            bool isMultiResolution,
            /*out*/
            int32_t* newStreamId);

    binder::Status deleteStreamLocked(int streamId);

    binder::Status endConfigureLocked(int operatingMode,
            const hardware::camera2::impl::CameraMetadataNative& sessionParams,
            int64_t startTimeMs,
            /*out*/
            std::vector<int>* offlineStreamIds);

    void cleanUpStreamsLocked(const std::vector<int32_t>& newOutputStreamIds,
                              int32_t newInputStreamId);

    /**
     * Interface used by CameraService
     */

    CameraDeviceClient(const sp<CameraService>& cameraService,
                       const sp<hardware::camera2::ICameraDeviceCallbacks>& remoteCallback,
                       std::shared_ptr<CameraServiceProxyWrapper> cameraServiceProxyWrapper,
                       std::shared_ptr<AttributionAndPermissionUtils> attributionAndPermissionUtils,
                       const AttributionSourceState& clientAttribution, int callingPid,
                       bool clientPackageOverride, const std::string& cameraId, int cameraFacing,
                       int sensorOrientation, int servicePid, bool overrideForPerfClass,
                       const CameraCompatibilityInfo& compatInfo,
                       const std::string& originalCameraId, bool sharedMode, bool isVendorClient);
    virtual ~CameraDeviceClient();

    virtual status_t      initialize(sp<CameraProviderManager> manager,
            const std::string& monitorTags) override;

    virtual status_t      setRotateAndCropOverride(uint8_t rotateAndCrop,
            bool fromHal = false) override;

    virtual status_t      setAutoframingOverride(uint8_t autoframingValue) override;

    virtual bool          supportsCameraMute();
    virtual status_t      setCameraMute(bool enabled);

    virtual bool          supportsZoomOverride() override;
    virtual status_t      setZoomOverride(int32_t zoomOverride) override;

    virtual status_t      dump(int fd, const Vector<String16>& args);

    virtual status_t      dumpClient(int fd, const Vector<String16>& args, bool ignoreResult);

    virtual status_t      startWatchingTags(const std::string &tags, int out);
    virtual status_t      stopWatchingTags(int out);
    virtual status_t      dumpWatchedEventsToVector(std::vector<std::string> &out);

    virtual status_t      setCameraServiceWatchdog(bool enabled);

    virtual void          setStreamUseCaseOverrides(const std::vector<int64_t>& useCaseOverrides);
    virtual void          clearStreamUseCaseOverrides() override;

    /**
     * Device listener interface
     */

    virtual void notifyIdle(int64_t requestCount, int64_t resultErrorCount, bool deviceError,
                            std::pair<int32_t, int32_t> mostRequestedFpsRange,
                            const std::vector<hardware::CameraStreamStats>& streamStats,
                            int32_t errorState);
    virtual void notifyError(int32_t errorCode,
                             const CaptureResultExtras& resultExtras);
    virtual void notifyShutter(const CaptureResultExtras& resultExtras, nsecs_t timestamp);
    virtual void notifyPrepared(int streamId);
    virtual void notifyRequestQueueEmpty();
    virtual void notifyRepeatingRequestError(long lastFrameNumber);
    virtual void notifyClientSharedAccessPriorityChanged(bool primaryClient);

    void setImageDumpMask(int mask) { if (mDevice != nullptr) mDevice->setImageDumpMask(mask); }
    /**
     * Interface used by independent components of CameraDeviceClient.
     */
protected:
    /** FilteredListener implementation **/

    size_t writeResultMetadataIntoResultQueue(const CameraMetadata &result);
    std::vector<PhysicalCaptureResultInfo> convertToFMQ(
            const std::vector<PhysicalCaptureResultInfo> &physicalResults);
    virtual void          onResultAvailable(const CaptureResult& result);
    virtual void          detachDevice();

    bool supportsUltraHighResolutionCapture(const std::string &cameraId);

    bool isSensorPixelModeConsistent(const std::list<int> &streamIdList,
            const CameraMetadata &settings);

    const CameraMetadata &getStaticInfo(const std::string &cameraId);

private:
    using MetadataQueue = AidlMessageQueueCpp<
            int8_t, android::hardware::common::fmq::SynchronizedReadWrite>;
    using CameraMetadataInfo = android::hardware::camera2::CameraMetadataInfo;
    status_t CreateMetadataQueue(
            std::unique_ptr<MetadataQueue>* metadata_queue, size_t size_bytes);
    // StreamSurfaceId encapsulates streamId + surfaceId for a particular surface.
    // streamId specifies the index of the stream the surface belongs to, and the
    // surfaceId specifies the index of the surface within the stream. (one stream
    // could contain multiple surfaces.)
    class StreamSurfaceId final {
    public:
        StreamSurfaceId() {
            mStreamId = -1;
            mSurfaceId = -1;
        }
        StreamSurfaceId(int32_t streamId, int32_t surfaceId) {
            mStreamId = streamId;
            mSurfaceId = surfaceId;
        }
        int32_t streamId() const {
            return mStreamId;
        }
        int32_t surfaceId() const {
            return mSurfaceId;
        }

    private:
        int32_t mStreamId;
        int32_t mSurfaceId;

    }; // class StreamSurfaceId

private:
    /** ICameraDeviceUser interface-related private members */

    /** Preview callback related members */
    sp<camera2::FrameProcessorBase> mFrameProcessor;

    std::vector<int32_t> mSupportedPhysicalRequestKeys;

    template<typename TProviderPtr>
    status_t      initializeImpl(TProviderPtr providerPtr, const std::string& monitorTags);

    /** Utility members */
    binder::Status checkPidStatus(const char* checkLocation);
    bool enforceRequestPermissions(CameraMetadata& metadata);

    // Update an output configuration
    binder::Status updateOutputConfigurationLocked(int streamId,
            const hardware::camera2::params::OutputConfiguration &outputConfiguration,
            bool replaceSurface = false, int64_t* lastFrameNumber = nullptr);

    // Create an output stream with surface deferred for future.
    binder::Status createDeferredSurfaceStreamLocked(
            const hardware::camera2::params::OutputConfiguration &outputConfiguration,
            bool isShared,
            int* newStreamId = NULL);

    // Utility method to insert the surface into SurfaceMap
    binder::Status insertSurfaceLocked(const ParcelableSurfaceType& surface,
            /*out*/SurfaceMap* surfaceMap, /*out*/Vector<int32_t>* streamIds,
            /*out*/int32_t*  currentStreamId);

    // A ParcelableSurfaceType can be either a view::Surface or IGBP.
    // We use this type of surface when we need to be able to have a parcelable data type.
    // view::Surface has helper functions to make converting between a regular Surface and a
    // view::Surface easy.
    status_t getSurfaceKey(ParcelableSurfaceType surface, SurfaceKey* out) const;
    // Surface only
    status_t getSurfaceKey(sp<Surface> surface, SurfaceKey* out) const;

    void updateCompositeOutputsLocked(int streamId, SurfaceKey surfaceKey,
            const sp<CompositeStream>& compositeStream, bool deferredCompositeStream,
            bool noNewOutputs);
    void findCompositeStream(int streamId, sp<CompositeStream> *compositeStream /*out*/,
            bool *deferredStream /*out*/);

    bool matchSharedStreamingRequest(int reqId);
    bool matchSharedCaptureRequest(int reqId);
    void markClientActive();
    void markClientIdle();

    // IGraphicsBufferProducer binder -> Stream ID + Surface ID for output streams
    KeyedVector<SurfaceKey, StreamSurfaceId> mStreamMap;

    // Stream ID -> OutputConfiguration. Used for looking up Surface by stream/surface index
    KeyedVector<int32_t, hardware::camera2::params::OutputConfiguration> mConfiguredOutputs;

    // Dynamic range profile id -> Supported dynamic profiles bitmap within an single capture
    // request
    std::unordered_map<int64_t, int64_t> mDynamicProfileMap;

    struct InputStreamConfiguration {
        bool configured;
        int32_t width;
        int32_t height;
        int32_t format;
        int32_t id;
    } mInputStream;

    // Streaming request ID
    int32_t mStreamingRequestId;
    Mutex mStreamingRequestIdLock;
    std::pair<int32_t, int32_t> mSharedStreamingRequest;
    std::map<int32_t, int32_t> mSharedRequestMap;
    int64_t mStreamingRequestLastFrameNumber;
    static const int32_t REQUEST_ID_NONE = -1;

    int32_t mRequestIdCounter;
    bool mPrivilegedClient;

    // Metadata queue to write the result metadata to.
    std::unique_ptr<MetadataQueue> mResultMetadataQueue;

    std::vector<std::string> mPhysicalCameraIds;

    // The list of output streams whose surfaces are deferred. We have to track them separately
    // as there are no surfaces available and can not be put into mStreamMap. Once the deferred
    // Surface is configured, the stream id will be moved to mStreamMap.
    Vector<int32_t> mDeferredStreams;

    // stream ID -> outputStreamInfo mapping
    std::unordered_map<int32_t, OutputStreamInfo> mStreamInfoMap;

    // map high resolution camera id (logical / physical) -> list of stream ids configured
    std::unordered_map<std::string, std::unordered_set<int>> mHighResolutionCameraIdToStreamIdSet;

    // set of high resolution camera id (logical / physical)
    std::unordered_set<std::string> mHighResolutionSensors;

    // Synchronize access to 'mCompositeStreamMap' and 'mDeferredCompositeMap'
    Mutex mCompositeLock;
    KeyedVector<SurfaceKey, sp<CompositeStream>> mCompositeStreamMap;

    // Map stream ids to deferred composite streams
    std::unordered_map<int, sp<CompositeStream>> mDeferredCompositeMap;

    sp<CameraProviderManager> mProviderManager;

    // Override the camera characteristics for performance class primary cameras.
    bool mOverrideForPerfClass;

    // Various fields used to collect session statistics
    struct RunningSessionStats {
        // The string representation of object passed into CaptureRequest.setTag.
        std::string mUserTag;
        // The last set video stabilization mode
        int mVideoStabilizationMode = -1;
        // Whether a zoom_ratio < 1.0 has been used during this session
        bool mUsedUltraWide = false;
        // Whether a zoom settings override has been used during this session
        bool mUsedSettingsOverrideZoom = false;
    } mRunningSessionStats;

    // This only exists in case of camera ID Remapping.
    const std::string mOriginalCameraId;

    bool mIsVendorClient = false;
};

}; // namespace android

#endif
