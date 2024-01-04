/*
 * Copyright (C) 2018 The Android Open Source Project
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
#ifndef _ACAMERA_DEVICE_H
#define _ACAMERA_DEVICE_H

#include "ACameraMetadata.h"
#include "utils.h"

#include <aidl/android/frameworks/cameraservice/common/Status.h>
#include <aidl/android/frameworks/cameraservice/device/BnCameraDeviceCallback.h>
#include <aidl/android/frameworks/cameraservice/device/CaptureResultExtras.h>
#include <aidl/android/frameworks/cameraservice/device/ErrorCode.h>
#include <aidl/android/frameworks/cameraservice/device/CaptureMetadataInfo.h>
#include <aidl/android/frameworks/cameraservice/device/ICameraDeviceUser.h>
#include <aidl/android/frameworks/cameraservice/device/PhysicalCameraSettings.h>
#include <aidl/android/frameworks/cameraservice/device/PhysicalCaptureResultInfo.h>
#include <aidl/android/frameworks/cameraservice/device/StreamConfigurationMode.h>
#include <aidl/android/frameworks/cameraservice/device/SubmitInfo.h>
#include <aidl/android/frameworks/cameraservice/service/CameraStatusAndId.h>
#include <atomic>
#include <camera/NdkCameraCaptureSession.h>
#include <camera/NdkCameraManager.h>
#include <fmq/AidlMessageQueue.h>
#include <fmq/MessageQueue.h>
#include <map>
#include <media/stagefright/foundation/AHandler.h>
#include <media/stagefright/foundation/ALooper.h>
#include <media/stagefright/foundation/AMessage.h>
#include <memory>
#include <set>
#include <utility>
#include <utils/List.h>
#include <utils/Mutex.h>
#include <utils/StrongPointer.h>
#include <utils/Vector.h>
#include <vector>

namespace android {
namespace acam {

using ::aidl::android::frameworks::cameraservice::common::Status;
using ::aidl::android::frameworks::cameraservice::device::BnCameraDeviceCallback;
using ::aidl::android::frameworks::cameraservice::device::CaptureResultExtras;
using ::aidl::android::frameworks::cameraservice::device::ErrorCode;
using ::aidl::android::frameworks::cameraservice::device::CaptureMetadataInfo;
using ::aidl::android::frameworks::cameraservice::device::ICameraDeviceCallback;
using ::aidl::android::frameworks::cameraservice::device::ICameraDeviceUser;
using ::aidl::android::frameworks::cameraservice::device::OutputConfiguration;
using ::aidl::android::frameworks::cameraservice::device::PhysicalCameraSettings;
using ::aidl::android::frameworks::cameraservice::device::PhysicalCaptureResultInfo;
using ::aidl::android::frameworks::cameraservice::device::StreamConfigurationMode;
using ::aidl::android::frameworks::cameraservice::device::SubmitInfo;
using ::aidl::android::frameworks::cameraservice::service::CameraStatusAndId;
using ::aidl::android::hardware::common::fmq::SynchronizedReadWrite;
using ::android::AidlMessageQueue;


using ResultMetadataQueue = AidlMessageQueue<int8_t, SynchronizedReadWrite>;
using RequestMetadataQueue = AidlMessageQueue<int8_t, SynchronizedReadWrite>;

using utils::CaptureRequest;

// Wrap ACameraCaptureFailure so it can be ref-counted
struct CameraCaptureFailure : public RefBase, public ACameraCaptureFailure { };

// Wrap PhysicalCaptureResultInfo so that it can be ref-counted
struct PhysicalCaptureResultInfoLocal {
    std::string physicalCameraId;
    CameraMetadata physicalMetadata;
};

struct ACameraPhysicalCaptureResultInfo: public RefBase {
    ACameraPhysicalCaptureResultInfo(const std::vector<PhysicalCaptureResultInfoLocal>& info,
            int64_t frameNumber) :
        mPhysicalResultInfo(info), mFrameNumber(frameNumber) {}

    std::vector<PhysicalCaptureResultInfoLocal> mPhysicalResultInfo;
    int64_t mFrameNumber;
};

class CameraDevice final : public std::enable_shared_from_this<CameraDevice> {
  public:
    CameraDevice(const char* id, ACameraDevice_StateCallbacks* cb,
                  sp<ACameraMetadata> chars,
                  ACameraDevice* wrapper);
    ~CameraDevice();

    // Called to initialize fields that require shared_ptr to `this`
    void init();

    inline const char* getId() const { return mCameraId.c_str(); }

    camera_status_t createCaptureRequest(
            ACameraDevice_request_template templateId,
            const ACameraIdList* physicalCameraIdList,
            ACaptureRequest** request) const;

    camera_status_t createCaptureSession(
            const ACaptureSessionOutputContainer*       outputs,
            const ACaptureRequest* sessionParameters,
            const ACameraCaptureSession_stateCallbacks* callbacks,
            /*out*/ACameraCaptureSession** session);

    camera_status_t isSessionConfigurationSupported(
            const ACaptureSessionOutputContainer* sessionOutputContainer) const;

    // Callbacks from camera service
    class ServiceCallback : public BnCameraDeviceCallback {
      public:
        explicit ServiceCallback(std::weak_ptr<CameraDevice> device) :
              mDevice(std::move(device)) {}

        ndk::ScopedAStatus onDeviceError(ErrorCode in_errorCode,
                                         const CaptureResultExtras& in_resultExtras) override;
        ndk::ScopedAStatus onDeviceIdle() override;

        ndk::ScopedAStatus onCaptureStarted(const CaptureResultExtras& in_resultExtras,
                                            int64_t in_timestamp) override;
        ndk::ScopedAStatus onPrepared(int32_t in_streamId) override;
        ndk::ScopedAStatus onRepeatingRequestError(int64_t in_lastFrameNumber,
                                                   int32_t in_repeatingRequestId) override;
        ndk::ScopedAStatus onResultReceived(const CaptureMetadataInfo& in_result,
                                            const CaptureResultExtras& in_resultExtras,
                                            const std::vector<PhysicalCaptureResultInfo>&
                                                    in_physicalCaptureResultInfos) override;

      private:
        camera_status_t readOneResultMetadata(const CaptureMetadataInfo& captureMetadataInfo,
                ResultMetadataQueue* metadataQueue, CameraMetadata* metadata);
        const std::weak_ptr<CameraDevice> mDevice;
    };
    inline std::shared_ptr<BnCameraDeviceCallback> getServiceCallback() {
        return mServiceCallback;
    };

    // Camera device is only functional after remote being set
    void setRemoteDevice(std::shared_ptr<ICameraDeviceUser> remote);

    bool setDeviceMetadataQueues();
    inline ACameraDevice* getWrapper() const { return mWrapper; };

    // Stop the looper thread and unregister the handler
    void stopLooperAndDisconnect();

  private:
    friend ACameraCaptureSession;
    friend ACameraDevice;

    camera_status_t checkCameraClosedOrErrorLocked() const;

    // device goes into fatal error state after this
    void setCameraDeviceErrorLocked(camera_status_t error);

    void disconnectLocked(sp<ACameraCaptureSession>& session); // disconnect from camera service

    camera_status_t stopRepeatingLocked();

    camera_status_t flushLocked(ACameraCaptureSession*);

    camera_status_t waitUntilIdleLocked();

    template<class T>
    camera_status_t captureLocked(sp<ACameraCaptureSession> session,
            /*optional*/T* cbs,
            int numRequests, ACaptureRequest** requests,
            /*optional*/int* captureSequenceId);

    template<class T>
    camera_status_t setRepeatingRequestsLocked(sp<ACameraCaptureSession> session,
            /*optional*/T* cbs,
            int numRequests, ACaptureRequest** requests,
            /*optional*/int* captureSequenceId);

    template<class T>
    camera_status_t submitRequestsLocked(
            sp<ACameraCaptureSession> session,
            /*optional*/T* cbs,
            int numRequests, ACaptureRequest** requests,
            /*out*/int* captureSequenceId,
            bool isRepeating);

    void addRequestSettingsMetadata(ACaptureRequest *aCaptureRequest, sp<CaptureRequest> &req);

    camera_status_t updateOutputConfigurationLocked(ACaptureSessionOutput *output);

    camera_status_t prepareLocked(ANativeWindow *window);

    // Since this writes to ICameraDeviceUser's fmq, clients must take care that:
    //   a) This function is called serially.
    //   b) This function is called in accordance with ICameraDeviceUser.submitRequestList,
    //      otherwise, the wrong capture request might have the wrong settings
    //      metadata associated with it.
    camera_status_t allocateCaptureRequestLocked(
            const ACaptureRequest* request, sp<CaptureRequest>& outReq);
    void allocateOneCaptureRequestMetadata(
            PhysicalCameraSettings& cameraSettings,
            const std::string& id, const sp<ACameraMetadata>& metadata);

    static ACaptureRequest* allocateACaptureRequest(sp<CaptureRequest>& req, const char* deviceId);
    static void freeACaptureRequest(ACaptureRequest*);

    // only For session to hold device lock
    // Always grab device lock before grabbing session lock
    void lockDeviceForSessionOps() const { mDeviceLock.lock(); };
    void unlockDevice() const { mDeviceLock.unlock(); };

    // For capture session to notify its end of life
    void notifySessionEndOfLifeLocked(ACameraCaptureSession* session);

    camera_status_t configureStreamsLocked(const ACaptureSessionOutputContainer* outputs,
           const ACaptureRequest* sessionParameters, nsecs_t startTimeNs);

    // Input message will be posted and cleared after this returns
    void postSessionMsgAndCleanup(sp<AMessage>& msg);

    mutable Mutex mDeviceLock;
    const std::string mCameraId;                          // Camera ID
    const ACameraDevice_StateCallbacks mAppCallbacks; // Callback to app
    const sp<ACameraMetadata> mChars;    // Camera characteristics
    std::shared_ptr<ServiceCallback> mServiceCallback;
    ACameraDevice* mWrapper;

    // stream id -> pair of (ACameraWindowType* from application, OutputConfiguration used for
    // camera service)
    std::map<int, std::pair<ANativeWindow *, OutputConfiguration>> mConfiguredOutputs;

    // TODO: maybe a bool will suffice for synchronous implementation?
    std::atomic_bool mClosing;
    inline bool isClosed() { return mClosing; }

    bool mInError = false;
    camera_status_t mError = ACAMERA_OK;
    void onCaptureErrorLocked(
            ErrorCode errorCode,
            const CaptureResultExtras& resultExtras);

    bool mIdle = true;
    // This will avoid a busy session being deleted before it's back to idle state
    sp<ACameraCaptureSession> mBusySession;

    std::shared_ptr<ICameraDeviceUser> mRemote;

    // Looper thread to handle callback to app
    sp<ALooper> mCbLooper;
    // definition of handler and message
    enum {
        // Device state callbacks
        kWhatOnDisconnected,   // onDisconnected
        kWhatOnError,          // onError
        // Session state callbacks
        kWhatSessionStateCb,   // onReady, onActive
        // Capture callbacks
        kWhatCaptureStart,     // onCaptureStarted
        kWhatCaptureStart2,     // onCaptureStarted2
        kWhatCaptureResult,    // onCaptureProgressed, onCaptureCompleted
        kWhatLogicalCaptureResult, // onLogicalCameraCaptureCompleted
        kWhatCaptureFail,      // onCaptureFailed
        kWhatLogicalCaptureFail, // onLogicalCameraCaptureFailed
        kWhatCaptureSeqEnd,    // onCaptureSequenceCompleted
        kWhatCaptureSeqAbort,  // onCaptureSequenceAborted
        kWhatCaptureBufferLost, // onCaptureBufferLost
        kWhatPreparedCb, // onPrepared
        // Internal cleanup
        kWhatCleanUpSessions   // Cleanup cached sp<ACameraCaptureSession>
    };
    static const char* kContextKey;
    static const char* kDeviceKey;
    static const char* kErrorCodeKey;
    static const char* kCallbackFpKey;
    static const char* kSessionSpKey;
    static const char* kCaptureRequestKey;
    static const char* kTimeStampKey;
    static const char* kCaptureResultKey;
    static const char* kPhysicalCaptureResultKey;
    static const char* kCaptureFailureKey;
    static const char* kSequenceIdKey;
    static const char* kFrameNumberKey;
    static const char* kAnwKey;
    static const char* kFailingPhysicalCameraId;

    class CallbackHandler : public AHandler {
      public:
        explicit CallbackHandler(const char *id);
        void onMessageReceived(const sp<AMessage> &msg) override;

      private:
        std::string mId;
        // This handler will cache all capture session sp until kWhatCleanUpSessions
        // is processed. This is used to guarantee the last session reference is always
        // being removed in callback thread without holding camera device lock
        std::vector<sp<ACameraCaptureSession>> mCachedSessions;
    };
    sp<CallbackHandler> mHandler;

    /***********************************
     * Capture session related members *
     ***********************************/
    // The current active session
    wp<ACameraCaptureSession> mCurrentSession;
    bool mFlushing = false;

    int mNextSessionId = 0;
    // TODO: might need another looper/handler to handle callbacks from service

    static const int REQUEST_ID_NONE = -1;
    int mRepeatingSequenceId = REQUEST_ID_NONE;

    // sequence id -> last frame number map
    std::map<int32_t, int64_t> mSequenceLastFrameNumberMap;

    struct CallbackHolder {
        CallbackHolder(sp<ACameraCaptureSession>          session,
                       std::vector<sp<CaptureRequest>>   requests,
                       bool                               isRepeating,
                       ACameraCaptureSession_captureCallbacks* cbs);
        CallbackHolder(sp<ACameraCaptureSession>          session,
                       std::vector<sp<CaptureRequest>>   requests,
                       bool                               isRepeating,
                       ACameraCaptureSession_logicalCamera_captureCallbacks* lcbs);
        CallbackHolder(sp<ACameraCaptureSession>          session,
                       std::vector<sp<CaptureRequest> >  requests,
                       bool                               isRepeating,
                       ACameraCaptureSession_captureCallbacksV2* cbs);
        CallbackHolder(sp<ACameraCaptureSession>          session,
                       std::vector<sp<CaptureRequest> >  requests,
                       bool                               isRepeating,
                       ACameraCaptureSession_logicalCamera_captureCallbacksV2* lcbs);
        void clearCallbacks() {
            mContext = nullptr;
            mOnCaptureStarted = nullptr;
            mOnCaptureStarted2 = nullptr;
            mOnCaptureProgressed = nullptr;
            mOnCaptureCompleted = nullptr;
            mOnLogicalCameraCaptureCompleted = nullptr;
            mOnLogicalCameraCaptureFailed = nullptr;
            mOnCaptureFailed = nullptr;
            mOnCaptureSequenceCompleted = nullptr;
            mOnCaptureSequenceAborted = nullptr;
            mOnCaptureBufferLost = nullptr;
        }

        template <class T>
        void initCaptureCallbacksV2(T* cbs) {
            clearCallbacks();
            if (cbs != nullptr) {
                mContext = cbs->context;
                mOnCaptureStarted2 = cbs->onCaptureStarted;
                mOnCaptureProgressed = cbs->onCaptureProgressed;
                mOnCaptureSequenceCompleted = cbs->onCaptureSequenceCompleted;
                mOnCaptureSequenceAborted = cbs->onCaptureSequenceAborted;
                mOnCaptureBufferLost = cbs->onCaptureBufferLost;
            }
        }

        template <class T>
        void initCaptureCallbacks(T* cbs) {
            clearCallbacks();
            if (cbs != nullptr) {
                mContext = cbs->context;
                mOnCaptureStarted = cbs->onCaptureStarted;
                mOnCaptureProgressed = cbs->onCaptureProgressed;
                mOnCaptureSequenceCompleted = cbs->onCaptureSequenceCompleted;
                mOnCaptureSequenceAborted = cbs->onCaptureSequenceAborted;
                mOnCaptureBufferLost = cbs->onCaptureBufferLost;
            }
        }

        sp<ACameraCaptureSession>   mSession;
        std::vector<sp<CaptureRequest>>  mRequests;
        const bool                  mIsRepeating;
        const bool                  mIs2Callback;
        const bool                  mIsLogicalCameraCallback;

        void*                       mContext;
        ACameraCaptureSession_captureCallback_start mOnCaptureStarted;
        ACameraCaptureSession_captureCallback_startV2 mOnCaptureStarted2;
        ACameraCaptureSession_captureCallback_result mOnCaptureProgressed;
        ACameraCaptureSession_captureCallback_result mOnCaptureCompleted;
        ACameraCaptureSession_logicalCamera_captureCallback_result mOnLogicalCameraCaptureCompleted;
        ACameraCaptureSession_logicalCamera_captureCallback_failed mOnLogicalCameraCaptureFailed;
        ACameraCaptureSession_captureCallback_failed mOnCaptureFailed;
        ACameraCaptureSession_captureCallback_sequenceEnd mOnCaptureSequenceCompleted;
        ACameraCaptureSession_captureCallback_sequenceAbort mOnCaptureSequenceAborted;
        ACameraCaptureSession_captureCallback_bufferLost mOnCaptureBufferLost;
    };
    // sequence id -> callbacks map
    std::map<int, CallbackHolder> mSequenceCallbackMap;

    static const int64_t NO_FRAMES_CAPTURED = -1;
    class FrameNumberTracker {
      public:
        // TODO: Called in onResultReceived and onCaptureErrorLocked
        void updateTracker(int64_t frameNumber, bool isError);
        inline int64_t getCompletedFrameNumber() { return mCompletedFrameNumber; }
      private:
        void update();
        void updateCompletedFrameNumber(int64_t frameNumber);

        int64_t mCompletedFrameNumber = NO_FRAMES_CAPTURED;
        List<int64_t> mSkippedFrameNumbers;
        std::set<int64_t> mFutureErrorSet;
    };
    FrameNumberTracker mFrameNumberTracker;

    void checkRepeatingSequenceCompleteLocked(const int sequenceId, const int64_t lastFrameNumber);
    void checkAndFireSequenceCompleteLocked();

    // Misc variables
    int32_t mShadingMapSize[2];   // const after constructor
    int32_t mPartialResultCount;  // const after constructor
    std::shared_ptr<RequestMetadataQueue> mCaptureRequestMetadataQueue = nullptr;
    std::shared_ptr<ResultMetadataQueue> mCaptureResultMetadataQueue = nullptr;
};

} // namespace acam;
} // namespace android;

/**
 * ACameraDevice opaque struct definition
 * Leave outside of android namespace because it's NDK struct
 */
struct ACameraDevice {
    ACameraDevice(const char* id, ACameraDevice_StateCallbacks* cb,
                  sp<ACameraMetadata> chars) :
            mDevice(std::make_shared<android::acam::CameraDevice>(id, cb,
                                                                std::move(chars), this)) {
        mDevice->init();
    }

    ~ACameraDevice();
    /*******************
     * NDK public APIs *
     *******************/
    inline const char* getId() const { return mDevice->getId(); }

    camera_status_t createCaptureRequest(
            ACameraDevice_request_template templateId,
            const ACameraIdList* physicalCameraIdList,
            ACaptureRequest** request) const {
        return mDevice->createCaptureRequest(templateId, physicalCameraIdList, request);
    }

    camera_status_t createCaptureSession(
            const ACaptureSessionOutputContainer*       outputs,
            const ACaptureRequest* sessionParameters,
            const ACameraCaptureSession_stateCallbacks* callbacks,
            /*out*/ACameraCaptureSession** session) {
        return mDevice->createCaptureSession(outputs, sessionParameters, callbacks, session);
    }

    camera_status_t isSessionConfigurationSupported(
            const ACaptureSessionOutputContainer* sessionOutputContainer) const {
        return mDevice->isSessionConfigurationSupported(sessionOutputContainer);
    }

    /***********************
     * Device interal APIs *
     ***********************/
    inline std::shared_ptr<android::acam::BnCameraDeviceCallback> getServiceCallback() {
        return mDevice->getServiceCallback();
    };

    // Camera device is only functional after remote being set
    inline void setRemoteDevice(std::shared_ptr<
            ::aidl::android::frameworks::cameraservice::device::ICameraDeviceUser> remote) {
        mDevice->setRemoteDevice(remote);
    }
    inline bool setDeviceMetadataQueues() {
        return mDevice->setDeviceMetadataQueues();
    }
  private:
    std::shared_ptr<android::acam::CameraDevice> mDevice;
};

#endif // _ACAMERA_DEVICE_H
