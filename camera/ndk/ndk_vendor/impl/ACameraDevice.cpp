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

//#define LOG_NDEBUG 0
#define LOG_TAG "ACameraDeviceVendor"

#include "ACameraCaptureSession.h"
#include "ACameraMetadata.h"
#include "ACaptureRequest.h"
#include "ndk_vendor/impl/ACameraDevice.h"
#include "utils.h"
#include <CameraMetadata.h>
#include <aidl/android/frameworks/cameraservice/device/CameraMetadata.h>
#include <aidl/android/frameworks/cameraservice/device/OutputConfiguration.h>
#include <aidl/android/frameworks/cameraservice/device/SessionConfiguration.h>
#include <android/native_window_aidl.h>
#include <inttypes.h>
#include <map>
#include <utility>
#include <vector>

#define CHECK_TRANSACTION_AND_RET(ret, callName)                                            \
    if (!remoteRet.isOk()) {                                                                \
        if (remoteRet.getExceptionCode() != EX_SERVICE_SPECIFIC) {                          \
            ALOGE("%s: Transaction error during %s call %d", __FUNCTION__, callName,        \
                                ret.getExceptionCode());                                    \
            return ACAMERA_ERROR_UNKNOWN;                                                   \
        } else {                                                                            \
            Status errStatus = static_cast<Status>(remoteRet.getServiceSpecificError());    \
            std::string errorMsg =                                                          \
                    aidl::android::frameworks::cameraservice::common::toString(errStatus);  \
            ALOGE("%s: %s call failed: %s", __FUNCTION__, callName, errorMsg.c_str());      \
            return utils::convertFromAidl(errStatus);                                       \
        }                                                                                   \
    }

using namespace android;

ACameraDevice::~ACameraDevice() {
    mDevice->stopLooperAndDisconnect();
}

namespace android {
namespace acam {

using AidlCameraMetadata = ::aidl::android::frameworks::cameraservice::device::CameraMetadata;
using ::aidl::android::frameworks::cameraservice::device::OutputConfiguration;
using ::aidl::android::frameworks::cameraservice::device::SessionConfiguration;
using ::aidl::android::view::Surface;
using ::ndk::ScopedAStatus;

// Static member definitions
const char* CameraDevice::kContextKey        = "Context";
const char* CameraDevice::kDeviceKey         = "Device";
const char* CameraDevice::kErrorCodeKey      = "ErrorCode";
const char* CameraDevice::kCallbackFpKey     = "Callback";
const char* CameraDevice::kSessionSpKey      = "SessionSp";
const char* CameraDevice::kCaptureRequestKey = "CaptureRequest";
const char* CameraDevice::kTimeStampKey      = "TimeStamp";
const char* CameraDevice::kCaptureResultKey  = "CaptureResult";
const char* CameraDevice::kPhysicalCaptureResultKey = "PhysicalCaptureResult";
const char* CameraDevice::kCaptureFailureKey = "CaptureFailure";
const char* CameraDevice::kSequenceIdKey     = "SequenceId";
const char* CameraDevice::kFrameNumberKey    = "FrameNumber";
const char* CameraDevice::kAnwKey            = "Anw";
const char* CameraDevice::kFailingPhysicalCameraId= "FailingPhysicalCameraId";

/**
 * CameraDevice Implementation
 */
CameraDevice::CameraDevice(
        const char* id,
        ACameraDevice_StateCallbacks* cb,
        sp<ACameraMetadata> chars,
        ACameraDevice* wrapper) :
        mCameraId(id),
        mAppCallbacks(*cb),
        mChars(std::move(chars)),
        mWrapper(wrapper),
        mInError(false),
        mError(ACAMERA_OK),
        mIdle(true),
        mCurrentSession(nullptr) {
    mClosing = false;
    // Setup looper thread to perfrom device callbacks to app
    mCbLooper = new ALooper;
    mCbLooper->setName("C2N-dev-looper");
    status_t err = mCbLooper->start(
            /*runOnCallingThread*/false,
            /*canCallJava*/       true,
            PRIORITY_DEFAULT);
    if (err != OK) {
        ALOGE("%s: Unable to start camera device callback looper: %s (%d)",
                __FUNCTION__, strerror(-err), err);
        setCameraDeviceErrorLocked(ACAMERA_ERROR_CAMERA_DEVICE);
    }
    mHandler = new CallbackHandler(id);
    mCbLooper->registerHandler(mHandler);

    const CameraMetadata& metadata = mChars->getInternalData();
    camera_metadata_ro_entry entry = metadata.find(ANDROID_REQUEST_PARTIAL_RESULT_COUNT);
    if (entry.count != 1) {
        ALOGW("%s: bad count %zu for partial result count", __FUNCTION__, entry.count);
        mPartialResultCount = 1;
    } else {
        mPartialResultCount = entry.data.i32[0];
    }

    entry = metadata.find(ANDROID_LENS_INFO_SHADING_MAP_SIZE);
    if (entry.count != 2) {
        ALOGW("%s: bad count %zu for shading map size", __FUNCTION__, entry.count);
        mShadingMapSize[0] = 0;
        mShadingMapSize[1] = 0;
    } else {
        mShadingMapSize[0] = entry.data.i32[0];
        mShadingMapSize[1] = entry.data.i32[1];
    }
}

CameraDevice::~CameraDevice() { }

void CameraDevice::init() {
    mServiceCallback = ndk::SharedRefBase::make<ServiceCallback>(weak_from_this());
}

void CameraDevice::postSessionMsgAndCleanup(sp<AMessage>& msg) {
    msg->post();
    msg.clear();
    sp<AMessage> cleanupMsg = new AMessage(kWhatCleanUpSessions, mHandler);
    cleanupMsg->post();
}

// TODO: cached created request?
camera_status_t CameraDevice::createCaptureRequest(
        ACameraDevice_request_template templateId,
        const ACameraIdList* physicalCameraIdList,
        ACaptureRequest** request) const {
    Mutex::Autolock _l(mDeviceLock);
    camera_status_t ret = checkCameraClosedOrErrorLocked();
    if (ret != ACAMERA_OK) {
        return ret;
    }
    if (mRemote == nullptr) {
        return ACAMERA_ERROR_CAMERA_DISCONNECTED;
    }

    AidlCameraMetadata aidlMetadata;
    ScopedAStatus remoteRet = mRemote->createDefaultRequest(
            utils::convertToAidl(templateId), &aidlMetadata);
    CHECK_TRANSACTION_AND_RET(remoteRet, "createDefaultRequest()")

    camera_metadata_t* rawRequest;
    utils::cloneFromAidl(aidlMetadata, &rawRequest);
    ACaptureRequest* outReq = new ACaptureRequest();
    outReq->settings = new ACameraMetadata(rawRequest, ACameraMetadata::ACM_REQUEST);
    if (physicalCameraIdList != nullptr) {
        for (auto i = 0; i < physicalCameraIdList->numCameras; i++) {
            outReq->physicalSettings.emplace(physicalCameraIdList->cameraIds[i],
                    new ACameraMetadata(*(outReq->settings)));
        }
    }
    outReq->targets  = new ACameraOutputTargets();
    *request = outReq;
    return ACAMERA_OK;
}

camera_status_t CameraDevice::createCaptureSession(
        const ACaptureSessionOutputContainer* outputs,
        const ACaptureRequest* sessionParameters,
        const ACameraCaptureSession_stateCallbacks* callbacks,
        /*out*/ACameraCaptureSession** session) {
    nsecs_t startTimeNs = systemTime();
    sp<ACameraCaptureSession> currentSession = mCurrentSession.promote();
    Mutex::Autolock _l(mDeviceLock);
    camera_status_t ret = checkCameraClosedOrErrorLocked();
    if (ret != ACAMERA_OK) {
        return ret;
    }

    if (currentSession != nullptr) {
        currentSession->closeByDevice();
        stopRepeatingLocked();
    }

    // Create new session
    ret = configureStreamsLocked(outputs, sessionParameters, startTimeNs);
    if (ret != ACAMERA_OK) {
        ALOGE("Fail to create new session. cannot configure streams");
        return ret;
    }

    ACameraCaptureSession* newSession = new ACameraCaptureSession(
            mNextSessionId++, outputs, callbacks, weak_from_this());

    // set new session as current session
    newSession->incStrong((void *) ACameraDevice_createCaptureSession);
    mCurrentSession = newSession;
    mFlushing = false;
    *session = newSession;
    return ACAMERA_OK;
}

camera_status_t CameraDevice::isSessionConfigurationSupported(
        const ACaptureSessionOutputContainer* sessionOutputContainer) const {
    Mutex::Autolock _l(mDeviceLock);
    camera_status_t ret = checkCameraClosedOrErrorLocked();
    if (ret != ACAMERA_OK) {
        return ret;
    }

    SessionConfiguration sessionConfig;
    sessionConfig.inputWidth = 0;
    sessionConfig.inputHeight = 0;
    sessionConfig.inputFormat = -1;
    sessionConfig.operationMode = StreamConfigurationMode::NORMAL_MODE;
    sessionConfig.outputStreams.resize(sessionOutputContainer->mOutputs.size());
    size_t index = 0;
    for (const auto& output : sessionOutputContainer->mOutputs) {
        OutputConfiguration& outputStream = sessionConfig.outputStreams[index];
        outputStream.rotation = utils::convertToAidl(output.mRotation);
        outputStream.windowGroupId = -1;
        auto& surfaces = outputStream.surfaces;
        surfaces.reserve(output.mSharedWindows.size() + 1);
        surfaces.emplace_back(output.mWindow);
        outputStream.physicalCameraId = output.mPhysicalCameraId;
        index++;
    }

    bool configSupported = false;
    ScopedAStatus remoteRet = mRemote->isSessionConfigurationSupported(
            sessionConfig, &configSupported);
    CHECK_TRANSACTION_AND_RET(remoteRet, "isSessionConfigurationSupported()")
    return configSupported ? ACAMERA_OK : ACAMERA_ERROR_STREAM_CONFIGURE_FAIL;
}

static void addMetadataToPhysicalCameraSettings(const CameraMetadata *metadata,
        const std::string &cameraId, PhysicalCameraSettings *physicalCameraSettings) {
    const camera_metadata_t* cameraMetadata = metadata->getAndLock();
    AidlCameraMetadata aidlCameraMetadata;
    utils::convertToAidl(cameraMetadata, &aidlCameraMetadata);
    metadata->unlock(cameraMetadata);
    physicalCameraSettings->settings.set<CaptureMetadataInfo::metadata>(
            std::move(aidlCameraMetadata));
    physicalCameraSettings->id = cameraId;
}

void CameraDevice::addRequestSettingsMetadata(ACaptureRequest *aCaptureRequest,
        sp<CaptureRequest> &req) {
    req->mPhysicalCameraSettings.resize(1 + aCaptureRequest->physicalSettings.size());
    addMetadataToPhysicalCameraSettings(
            &(aCaptureRequest->settings->getInternalData()),
            getId(),&(req->mPhysicalCameraSettings[0]));
    size_t i = 1;
    for (auto &physicalSetting : aCaptureRequest->physicalSettings) {
        addMetadataToPhysicalCameraSettings(&(physicalSetting.second->getInternalData()),
                physicalSetting.first, &(req->mPhysicalCameraSettings[i]));
        i++;
    }
}

camera_status_t CameraDevice::updateOutputConfigurationLocked(ACaptureSessionOutput *output) {
    camera_status_t ret = checkCameraClosedOrErrorLocked();
    if (ret != ACAMERA_OK) {
        return ret;
    }

    if (output == nullptr) {
        return ACAMERA_ERROR_INVALID_PARAMETER;
    }

    if (!output->mIsShared) {
        ALOGE("Error output configuration is not shared");
        return ACAMERA_ERROR_INVALID_OPERATION;
    }

    int32_t streamId = -1;
    for (auto& kvPair : mConfiguredOutputs) {
        if (kvPair.second.first == output->mWindow) {
            streamId = kvPair.first;
            break;
        }
    }
    if (streamId < 0) {
        ALOGE("Error: Invalid output configuration");
        return ACAMERA_ERROR_INVALID_PARAMETER;
    }

    OutputConfiguration outConfig;
    outConfig.rotation = utils::convertToAidl(output->mRotation);
    auto& surfaces = outConfig.surfaces;
    surfaces.reserve(output->mSharedWindows.size() + 1);
    surfaces.emplace_back(output->mWindow);
    outConfig.physicalCameraId = output->mPhysicalCameraId;
    for (auto& anw : output->mSharedWindows) {
        surfaces.emplace_back(anw);
    }

    auto remoteRet = mRemote->updateOutputConfiguration(streamId,
                                                        outConfig);

    if (!remoteRet.isOk()) {
        if (remoteRet.getExceptionCode() == EX_SERVICE_SPECIFIC) {
            Status st = static_cast<Status>(remoteRet.getServiceSpecificError());
            switch (st) {
                case Status::NO_ERROR:
                    break;
                case Status::INVALID_OPERATION:
                    ALOGE("Camera device %s invalid operation", getId());
                    return ACAMERA_ERROR_INVALID_OPERATION;
                case Status::ALREADY_EXISTS:
                    ALOGE("Camera device %s output surface already exists", getId());
                    return ACAMERA_ERROR_INVALID_PARAMETER;
                case Status::ILLEGAL_ARGUMENT:
                    ALOGE("Camera device %s invalid input argument", getId());
                    return ACAMERA_ERROR_INVALID_PARAMETER;
                default:
                    ALOGE("Camera device %s failed to add shared output", getId());
                    return ACAMERA_ERROR_UNKNOWN;
            }
        } else {
            ALOGE("%s: Transaction error in updating OutputConfiguration: %d", __FUNCTION__,
                remoteRet.getExceptionCode());
            return ACAMERA_ERROR_UNKNOWN;
        }
    }

    mConfiguredOutputs[streamId] = std::make_pair(output->mWindow,
                                        std::move(outConfig));
    return ACAMERA_OK;
}

camera_status_t CameraDevice::prepareLocked(ANativeWindow *window) {
    camera_status_t ret = checkCameraClosedOrErrorLocked();
    if (ret != ACAMERA_OK) {
        return ret;
    }

    if (window == nullptr) {
        return ACAMERA_ERROR_INVALID_PARAMETER;
    }

    int32_t streamId = -1;
    for (auto& kvPair : mConfiguredOutputs) {
        if (window == kvPair.second.first) {
            streamId = kvPair.first;
            break;
        }
    }
    if (streamId < 0) {
        ALOGE("Error: Invalid output configuration");
        return ACAMERA_ERROR_INVALID_PARAMETER;
    }

    auto remoteRet = mRemote->prepare(streamId);
    CHECK_TRANSACTION_AND_RET(remoteRet, "prepare()")
    return ACAMERA_OK;
}

camera_status_t CameraDevice::allocateCaptureRequestLocked(
        const ACaptureRequest* request, /*out*/sp<CaptureRequest> &outReq) {
    sp<CaptureRequest> req(new CaptureRequest());
    req->mCaptureRequest.physicalCameraSettings.resize(1 + request->physicalSettings.size());

    size_t index = 0;
    allocateOneCaptureRequestMetadata(
            req->mCaptureRequest.physicalCameraSettings[index++],
            mCameraId, request->settings);

    for (auto& physicalEntry : request->physicalSettings) {
        allocateOneCaptureRequestMetadata(
                req->mCaptureRequest.physicalCameraSettings[index++],
                physicalEntry.first, physicalEntry.second);
    }

    std::vector<int32_t> requestStreamIdxList;
    std::vector<int32_t> requestSurfaceIdxList;

    for (auto& outputTarget : request->targets->mOutputs) {
        ANativeWindow *anw = outputTarget.mWindow;
        bool found = false;
        req->mSurfaceList.push_back(anw);
        // lookup stream/surface ID
        for (const auto& kvPair : mConfiguredOutputs) {
            int streamId = kvPair.first;
            const OutputConfiguration& outConfig = kvPair.second.second;
            const auto& surfaces = outConfig.surfaces;
            for (int surfaceId = 0; surfaceId < (int) surfaces.size(); surfaceId++) {
                // If two window handles point to the same native window,
                // they have the same surfaces.
                auto& surface = surfaces[surfaceId];
                if (anw == surface.get()) {
                    found = true;
                    requestStreamIdxList.push_back(streamId);
                    requestSurfaceIdxList.push_back(surfaceId);
                    break;
                }
            }
            if (found) {
                break;
            }
        }
        if (!found) {
            ALOGE("Unconfigured output target %p in capture request!", anw);
            return ACAMERA_ERROR_INVALID_PARAMETER;
        }
    }
    req->mCaptureRequest.streamAndWindowIds.resize(requestStreamIdxList.size());
    for (int i = 0; i < requestStreamIdxList.size(); i++) {
        req->mCaptureRequest.streamAndWindowIds[i].streamId = requestStreamIdxList[i];
        req->mCaptureRequest.streamAndWindowIds[i].windowId = requestSurfaceIdxList[i];
    }
    outReq = req;
    return ACAMERA_OK;
}

void CameraDevice::allocateOneCaptureRequestMetadata(
        PhysicalCameraSettings& cameraSettings,
        const std::string& id, const sp<ACameraMetadata>& metadata) {
    cameraSettings.id = id;

    if (metadata == nullptr) {
        return;
    }

    const camera_metadata_t* cameraMetadata = metadata->getInternalData().getAndLock();
    AidlCameraMetadata aidlCameraMetadata;
    utils::convertToAidl(cameraMetadata, &aidlCameraMetadata);
    metadata->getInternalData().unlock(cameraMetadata);

    if (aidlCameraMetadata.metadata.data() != nullptr &&
        mCaptureRequestMetadataQueue != nullptr &&
        mCaptureRequestMetadataQueue->write(
                reinterpret_cast<const int8_t*>(aidlCameraMetadata.metadata.data()),
                aidlCameraMetadata.metadata.size())) {
        cameraSettings.settings.set<CaptureMetadataInfo::fmqMetadataSize>(
                aidlCameraMetadata.metadata.size());
    } else {
        ALOGE("Fmq write capture result failed, falling back to hwbinder");
        cameraSettings.settings.set<CaptureMetadataInfo::metadata>(std::move(aidlCameraMetadata));
    }
}


ACaptureRequest* CameraDevice::allocateACaptureRequest(sp<CaptureRequest>& req,
                                                       const char* deviceId) {
    ACaptureRequest* pRequest = new ACaptureRequest();
    for (size_t i = 0; i < req->mPhysicalCameraSettings.size(); i++) {
        const std::string& id = req->mPhysicalCameraSettings[i].id;
        camera_metadata_t* clone;
        AidlCameraMetadata& aidlCameraMetadata = req->mPhysicalCameraSettings[i].settings
                                                         .get<CaptureMetadataInfo::metadata>();
        utils::cloneFromAidl(aidlCameraMetadata, &clone);

        if (id == deviceId) {
            pRequest->settings = new ACameraMetadata(clone, ACameraMetadata::ACM_REQUEST);
        } else {
            pRequest->physicalSettings[req->mPhysicalCameraSettings[i].id] =
                    new ACameraMetadata(clone, ACameraMetadata::ACM_REQUEST);
        }
    }
    pRequest->targets = new ACameraOutputTargets();
    for (size_t i = 0; i < req->mSurfaceList.size(); i++) {
        ANativeWindow *anw = req->mSurfaceList[i];
        ACameraOutputTarget outputTarget(anw);
        pRequest->targets->mOutputs.insert(std::move(outputTarget));
    }
    return pRequest;
}

void CameraDevice::freeACaptureRequest(ACaptureRequest* req) {
    if (req == nullptr) {
        return;
    }
    req->settings.clear();
    delete req->targets;
    delete req;
}

void
CameraDevice::notifySessionEndOfLifeLocked(ACameraCaptureSession* session) {
    if (isClosed()) {
        // Device is closing already. do nothing
        return;
    }

    if (mCurrentSession != session) {
        // Session has been replaced by other session or device is closed
        return;
    }
    mCurrentSession = nullptr;

    // Should not happen
    if (!session->mIsClosed) {
        ALOGE("Error: unclosed session %p reaches end of life!", session);
        setCameraDeviceErrorLocked(ACAMERA_ERROR_CAMERA_DEVICE);
        return;
    }

    // No new session, un-configure now
    // Note: The un-configuration of session won't be accounted for session
    // latency because a stream configuration with 0 streams won't ever become
    // active.
    nsecs_t startTimeNs = systemTime();
    camera_status_t ret = configureStreamsLocked(nullptr, nullptr, startTimeNs);
    if (ret != ACAMERA_OK) {
        ALOGE("Unconfigure stream failed. Device might still be configured! ret %d", ret);
    }
}

void
CameraDevice::disconnectLocked(sp<ACameraCaptureSession>& session) {
    if (mClosing.exchange(true)) {
        // Already closing, just return
        ALOGW("Camera device %s is already closing.", getId());
        return;
    }

    if (mRemote != nullptr) {
        ALOGD("%s: binder disconnect reached", __FUNCTION__);
        auto ret = mRemote->disconnect();
        if (!ret.isOk()) {
            ALOGE("%s: Transaction error while disconnecting device %d", __FUNCTION__,
                  ret.getExceptionCode());
        }
    }
    mRemote = nullptr;

    if (session != nullptr) {
        session->closeByDevice();
    }
}

camera_status_t CameraDevice::stopRepeatingLocked() {
    camera_status_t ret = checkCameraClosedOrErrorLocked();
    if (ret != ACAMERA_OK) {
        ALOGE("Camera %s stop repeating failed! ret %d", getId(), ret);
        return ret;
    }
    if (mRepeatingSequenceId != REQUEST_ID_NONE) {
        int repeatingSequenceId = mRepeatingSequenceId;
        mRepeatingSequenceId = REQUEST_ID_NONE;

        int64_t lastFrameNumber;
        ScopedAStatus remoteRet = mRemote->cancelRepeatingRequest(&lastFrameNumber);
        CHECK_TRANSACTION_AND_RET(remoteRet, "cancelRepeatingRequest()");
        checkRepeatingSequenceCompleteLocked(repeatingSequenceId, lastFrameNumber);
    }
    return ACAMERA_OK;
}

camera_status_t CameraDevice::flushLocked(ACameraCaptureSession* session) {
    camera_status_t ret = checkCameraClosedOrErrorLocked();
    if (ret != ACAMERA_OK) {
        ALOGE("Camera %s abort captures failed! ret %d", getId(), ret);
        return ret;
    }

    // This should never happen because creating a new session will close
    // previous one and thus reject any API call from previous session.
    // But still good to check here in case something unexpected happen.
    if (mCurrentSession != session) {
        ALOGE("Camera %s session %p is not current active session!", getId(), session);
        return ACAMERA_ERROR_INVALID_OPERATION;
    }

    if (mFlushing) {
        ALOGW("Camera %s is already aborting captures", getId());
        return ACAMERA_OK;
    }

    mFlushing = true;

    // Send onActive callback to guarantee there is always active->ready transition
    sp<AMessage> msg = new AMessage(kWhatSessionStateCb, mHandler);
    msg->setPointer(kContextKey, session->mUserSessionCallback.context);
    msg->setObject(kSessionSpKey, session);
    msg->setPointer(kCallbackFpKey, (void*) session->mUserSessionCallback.onActive);
    postSessionMsgAndCleanup(msg);

    // If device is already idling, send callback and exit early
    if (mIdle) {
        sp<AMessage> msg = new AMessage(kWhatSessionStateCb, mHandler);
        msg->setPointer(kContextKey, session->mUserSessionCallback.context);
        msg->setObject(kSessionSpKey, session);
        msg->setPointer(kCallbackFpKey, (void*) session->mUserSessionCallback.onReady);
        postSessionMsgAndCleanup(msg);
        mFlushing = false;
        return ACAMERA_OK;
    }

    int64_t lastFrameNumber;
    ScopedAStatus remoteRet = mRemote->flush(&lastFrameNumber);
    CHECK_TRANSACTION_AND_RET(remoteRet, "flush()")
    if (mRepeatingSequenceId != REQUEST_ID_NONE) {
        checkRepeatingSequenceCompleteLocked(mRepeatingSequenceId, lastFrameNumber);
    }
    return ACAMERA_OK;
}

camera_status_t CameraDevice::waitUntilIdleLocked() {
    camera_status_t ret = checkCameraClosedOrErrorLocked();
    if (ret != ACAMERA_OK) {
        ALOGE("Wait until camera %s idle failed! ret %d", getId(), ret);
        return ret;
    }

    if (mRepeatingSequenceId != REQUEST_ID_NONE) {
        ALOGE("Camera device %s won't go to idle when there is repeating request!", getId());
        return ACAMERA_ERROR_INVALID_OPERATION;
    }

    auto remoteRet = mRemote->waitUntilIdle();
    CHECK_TRANSACTION_AND_RET(remoteRet, "waitUntilIdle()")
    return ACAMERA_OK;
}

camera_status_t CameraDevice::configureStreamsLocked(const ACaptureSessionOutputContainer* outputs,
                                                     const ACaptureRequest* sessionParameters,
                                                     nsecs_t startTimeNs) {
    ACaptureSessionOutputContainer emptyOutput;
    if (outputs == nullptr) {
        outputs = &emptyOutput;
    }

    camera_status_t ret = checkCameraClosedOrErrorLocked();
    if (ret != ACAMERA_OK) {
        return ret;
    }

    std::map<ANativeWindow *, OutputConfiguration> windowToConfig;
    for (const auto& outConfig : outputs->mOutputs) {
        ANativeWindow *anw = outConfig.mWindow;
        OutputConfiguration outConfigInsert;
        outConfigInsert.rotation = utils::convertToAidl(outConfig.mRotation);
        outConfigInsert.windowGroupId = -1;
        auto& surfaces = outConfigInsert.surfaces;
        surfaces.reserve(outConfig.mSharedWindows.size() + 1);
        surfaces.emplace_back(anw);
        outConfigInsert.physicalCameraId = outConfig.mPhysicalCameraId;
        windowToConfig.insert({anw, std::move(outConfigInsert)});
    }

    std::set<ANativeWindow *> addSet;
    for (auto& kvPair : windowToConfig) {
        addSet.insert(kvPair.first);
    }

    std::vector<int32_t> deleteList;

    // Determine which streams need to be created, which to be deleted
    for (auto& kvPair : mConfiguredOutputs) {
        int32_t streamId = kvPair.first;
        auto& outputPair = kvPair.second;
        auto& anw = outputPair.first;
        auto& configuredOutput = outputPair.second;

        auto itr = windowToConfig.find(anw);
        if (itr != windowToConfig.end() && (itr->second) == configuredOutput) {
            deleteList.push_back(streamId);
        } else {
            addSet.erase(anw);
        }
    }

    ret = stopRepeatingLocked();
    if (ret != ACAMERA_OK) {
        ALOGE("Camera device %s stop repeating failed, ret %d", getId(), ret);
        return ret;
    }

    ret = waitUntilIdleLocked();
    if (ret != ACAMERA_OK) {
        ALOGE("Camera device %s wait until idle failed, ret %d", getId(), ret);
        return ret;
    }

    // Send onReady to previous session
    // CurrentSession will be updated after configureStreamLocked, so here
    // mCurrentSession is the session to be replaced by a new session
    if (!mIdle && mCurrentSession != nullptr) {
        if (mBusySession != mCurrentSession) {
            ALOGE("Current session != busy session");
            setCameraDeviceErrorLocked(ACAMERA_ERROR_CAMERA_DEVICE);
            return ACAMERA_ERROR_CAMERA_DEVICE;
        }
        sp<AMessage> msg = new AMessage(kWhatSessionStateCb, mHandler);
        msg->setPointer(kContextKey, mBusySession->mUserSessionCallback.context);
        msg->setObject(kSessionSpKey, mBusySession);
        msg->setPointer(kCallbackFpKey, (void*) mBusySession->mUserSessionCallback.onReady);
        mBusySession.clear();
        postSessionMsgAndCleanup(msg);
    }
    mIdle = true;

    auto remoteRet = mRemote->beginConfigure();
    CHECK_TRANSACTION_AND_RET(remoteRet, "beginConfigure()")

    // delete to-be-deleted streams
    for (auto streamId : deleteList) {
        remoteRet = mRemote->deleteStream(streamId);
        CHECK_TRANSACTION_AND_RET(remoteRet, "deleteStream()")
        mConfiguredOutputs.erase(streamId);
    }

    // add new streams
    for (const auto &anw : addSet) {
        int32_t streamId;
        auto itr = windowToConfig.find(anw);
        remoteRet = mRemote->createStream(itr->second, &streamId);
        CHECK_TRANSACTION_AND_RET(remoteRet, "createStream()")
        mConfiguredOutputs.insert(std::make_pair(streamId,
                                                 std::make_pair(anw,
                                                                std::move(itr->second))));
        windowToConfig.erase(itr);
    }

    AidlCameraMetadata aidlParams;
    if ((sessionParameters != nullptr) && (sessionParameters->settings != nullptr)) {
        const CameraMetadata &params = sessionParameters->settings->getInternalData();
        const camera_metadata_t* paramsMetadata = params.getAndLock();
        utils::convertToAidl(paramsMetadata, &aidlParams);
        params.unlock(paramsMetadata);
    }
    remoteRet = mRemote->endConfigure(StreamConfigurationMode::NORMAL_MODE,
                                      aidlParams, startTimeNs);
    CHECK_TRANSACTION_AND_RET(remoteRet, "endConfigure()")
    return ACAMERA_OK;
}

void CameraDevice::setRemoteDevice(std::shared_ptr<ICameraDeviceUser> remote) {
    Mutex::Autolock _l(mDeviceLock);
    mRemote = std::move(remote);
}

bool CameraDevice::setDeviceMetadataQueues() {
        if (mRemote == nullptr) {
          ALOGE("mRemote must not be null while trying to fetch metadata queues");
          return false;
        }
        std::shared_ptr<RequestMetadataQueue> &reqQueue = mCaptureRequestMetadataQueue;
        MQDescriptor<int8_t, SynchronizedReadWrite> reqMqDescriptor;
        ScopedAStatus ret = mRemote->getCaptureRequestMetadataQueue(&reqMqDescriptor);
        if (!ret.isOk()) {
            ALOGE("Transaction error trying to get capture request metadata queue");
            return false;
        }
        reqQueue = std::make_shared<RequestMetadataQueue>(reqMqDescriptor);
        if (!reqQueue->isValid() || reqQueue->availableToWrite() <= 0) {
            ALOGE("Empty fmq from cameraserver");
            reqQueue = nullptr;
        }

        MQDescriptor<int8_t, SynchronizedReadWrite> resMqDescriptor;
        std::shared_ptr<ResultMetadataQueue> &resQueue = mCaptureResultMetadataQueue;
        ret = mRemote->getCaptureResultMetadataQueue(&resMqDescriptor);
        if (!ret.isOk()) {
            ALOGE("Transaction error trying to get capture result metadata queue");
            return false;
        }
        resQueue = std::make_shared<ResultMetadataQueue>(resMqDescriptor);
        if (!resQueue->isValid() || resQueue->availableToWrite() <= 0) {
            ALOGE("Empty fmq from cameraserver");
        }

        return true;
}

camera_status_t CameraDevice::checkCameraClosedOrErrorLocked() const {
    if (mRemote == nullptr) {
        ALOGE("%s: camera device already closed", __FUNCTION__);
        return ACAMERA_ERROR_CAMERA_DISCONNECTED;
    }
    if (mInError) { // triggered by onDeviceError
        ALOGE("%s: camera device has encountered a serious error: %d", __FUNCTION__, mError);
        return mError;
    }
    return ACAMERA_OK;
}

void CameraDevice::setCameraDeviceErrorLocked(camera_status_t error) {
    mInError = true;
    mError = error;
}

void CameraDevice::FrameNumberTracker::updateTracker(int64_t frameNumber, bool isError) {
    ALOGV("updateTracker frame %" PRId64 " isError %d", frameNumber, isError);
    if (isError) {
        mFutureErrorSet.insert(frameNumber);
    } else if (frameNumber <= mCompletedFrameNumber) {
        ALOGE("Frame number %" PRId64 " decreased! current fn %" PRId64,
                frameNumber, mCompletedFrameNumber);
        return;
    } else {
        if (frameNumber != mCompletedFrameNumber + 1) {
            ALOGE("Frame number out of order. Expect %" PRId64 " but get %" PRId64,
                    mCompletedFrameNumber + 1, frameNumber);
            // Do not assert as in java implementation
        }
        mCompletedFrameNumber = frameNumber;
    }
    update();
}

void CameraDevice::FrameNumberTracker::update() {
    for (auto it = mFutureErrorSet.begin(); it != mFutureErrorSet.end();) {
        int64_t errorFrameNumber = *it;
        if (errorFrameNumber == mCompletedFrameNumber + 1) {
            mCompletedFrameNumber++;
            it = mFutureErrorSet.erase(it);
        } else if (errorFrameNumber <= mCompletedFrameNumber) {
            // This should not happen, but deal with it anyway
            ALOGE("Completd frame number passed through current frame number!");
            // erase the old error since it's no longer useful
            it = mFutureErrorSet.erase(it);
        } else {
            // Normal requests hasn't catched up error frames, just break
            break;
        }
    }
    ALOGV("Update complete frame %" PRId64, mCompletedFrameNumber);
}

void CameraDevice::onCaptureErrorLocked(ErrorCode errorCode,
                                        const CaptureResultExtras& resultExtras) {
    int sequenceId = resultExtras.requestId;
    int64_t frameNumber = resultExtras.frameNumber;
    int32_t burstId = resultExtras.burstId;
    auto it = mSequenceCallbackMap.find(sequenceId);
    if (it == mSequenceCallbackMap.end()) {
        ALOGE("%s: Error: capture sequence index %d not found!",
                __FUNCTION__, sequenceId);
        setCameraDeviceErrorLocked(ACAMERA_ERROR_CAMERA_SERVICE);
        return;
    }

    CallbackHolder cbh = it->second;
    sp<ACameraCaptureSession> session = cbh.mSession;
    if ((size_t) burstId >= cbh.mRequests.size()) {
        ALOGE("%s: Error: request index %d out of bound (size %zu)",
                __FUNCTION__, burstId, cbh.mRequests.size());
        setCameraDeviceErrorLocked(ACAMERA_ERROR_CAMERA_SERVICE);
        return;
    }
    sp<CaptureRequest> request = cbh.mRequests[burstId];

    // Handle buffer error
    if (errorCode == ErrorCode::CAMERA_BUFFER) {
        int32_t streamId = resultExtras.errorStreamId;
        ACameraCaptureSession_captureCallback_bufferLost onBufferLost =
                cbh.mOnCaptureBufferLost;
        auto outputPairIt = mConfiguredOutputs.find(streamId);
        if (outputPairIt == mConfiguredOutputs.end()) {
            ALOGE("%s: Error: stream id %d does not exist", __FUNCTION__, streamId);
            setCameraDeviceErrorLocked(ACAMERA_ERROR_CAMERA_SERVICE);
            return;
        }

        // Get the surfaces corresponding to the error stream id, go through
        // them and try to match the surfaces in the corresponding
        // CaptureRequest.
        const auto& errorSurfaces =
                outputPairIt->second.second.surfaces;
        for (const auto& errorSurface : errorSurfaces) {
            for (const auto &requestStreamAndWindowId :
                        request->mCaptureRequest.streamAndWindowIds) {
                // Go through the surfaces in the capture request and see which
                // ones match the surfaces in the error stream.
                int32_t requestWindowId = requestStreamAndWindowId.windowId;
                auto requestSurfacePairIt =
                        mConfiguredOutputs.find(requestStreamAndWindowId.streamId);
                if (requestSurfacePairIt == mConfiguredOutputs.end()) {
                    ALOGE("%s: Error: request stream id %d does not exist", __FUNCTION__,
                              requestStreamAndWindowId.streamId);
                    setCameraDeviceErrorLocked(ACAMERA_ERROR_CAMERA_SERVICE);
                    return;
                }

                const auto &requestSurfaces = requestSurfacePairIt->second.second.surfaces;
                auto& requestSurface = requestSurfaces[requestWindowId];

                if (requestSurface == errorSurface) {
                    const ANativeWindow *anw = requestSurface.get();
                    ALOGV("Camera %s Lost output buffer for ANW %p frame %" PRId64,
                            getId(), anw, frameNumber);

                    sp<AMessage> msg = new AMessage(kWhatCaptureBufferLost, mHandler);
                    msg->setPointer(kContextKey, cbh.mContext);
                    msg->setObject(kSessionSpKey, session);
                    msg->setPointer(kCallbackFpKey, (void*) onBufferLost);
                    msg->setObject(kCaptureRequestKey, request);
                    msg->setPointer(kAnwKey, (void*) anw);
                    msg->setInt64(kFrameNumberKey, frameNumber);
                    postSessionMsgAndCleanup(msg);
                }
            }
        }
    } else { // Handle other capture failures
        // Fire capture failure callback if there is one registered
        ACameraCaptureSession_captureCallback_failed onError = cbh.mOnCaptureFailed;
        sp<CameraCaptureFailure> failure(new CameraCaptureFailure());
        failure->frameNumber = frameNumber;
        // TODO: refine this when implementing flush
        failure->reason      = CAPTURE_FAILURE_REASON_ERROR;
        failure->sequenceId  = sequenceId;
        failure->wasImageCaptured = (errorCode == ErrorCode::CAMERA_RESULT);

        sp<AMessage> msg = new AMessage(cbh.mIsLogicalCameraCallback ? kWhatLogicalCaptureFail
                                                                     : kWhatCaptureFail,
                                        mHandler);
        msg->setPointer(kContextKey, cbh.mContext);
        msg->setObject(kSessionSpKey, session);
        if (cbh.mIsLogicalCameraCallback) {
            if (!resultExtras.errorPhysicalCameraId.empty()) {
                msg->setString(kFailingPhysicalCameraId,
                               resultExtras.errorPhysicalCameraId.c_str(),
                               resultExtras.errorPhysicalCameraId.size());
            }
            msg->setPointer(kCallbackFpKey, (void*) cbh.mOnLogicalCameraCaptureFailed);
        } else {
            msg->setPointer(kCallbackFpKey, (void*) onError);
        }
        msg->setObject(kCaptureRequestKey, request);
        msg->setObject(kCaptureFailureKey, failure);
        postSessionMsgAndCleanup(msg);

        // Update tracker
        mFrameNumberTracker.updateTracker(frameNumber, /*isError*/true);
        checkAndFireSequenceCompleteLocked();
    }
}

CameraDevice::CallbackHandler::CallbackHandler(const char *id) : mId(id) { }

void CameraDevice::CallbackHandler::onMessageReceived(
        const sp<AMessage> &msg) {
    switch (msg->what()) {
        case kWhatOnDisconnected:
        case kWhatOnError:
        case kWhatSessionStateCb:
        case kWhatCaptureStart:
        case kWhatCaptureStart2:
        case kWhatCaptureResult:
        case kWhatLogicalCaptureResult:
        case kWhatCaptureFail:
        case kWhatLogicalCaptureFail:
        case kWhatCaptureSeqEnd:
        case kWhatCaptureSeqAbort:
        case kWhatCaptureBufferLost:
        case kWhatPreparedCb:
            ALOGV("%s: Received msg %d", __FUNCTION__, msg->what());
            break;
        case kWhatCleanUpSessions:
            mCachedSessions.clear();
            return;
        default:
            ALOGE("%s:Error: unknown device callback %d", __FUNCTION__, msg->what());
            return;
    }
    // Check the common part of all message
    void* context;
    bool found = msg->findPointer(kContextKey, &context);
    if (!found) {
        ALOGE("%s: Cannot find callback context!", __FUNCTION__);
        return;
    }
    switch (msg->what()) {
        case kWhatOnDisconnected:
        {
            ACameraDevice* dev;
            found = msg->findPointer(kDeviceKey, (void**) &dev);
            if (!found || dev == nullptr) {
                ALOGE("%s: Cannot find device pointer!", __FUNCTION__);
                return;
            }
            ACameraDevice_StateCallback onDisconnected;
            found = msg->findPointer(kCallbackFpKey, (void**) &onDisconnected);
            if (!found) {
                ALOGE("%s: Cannot find onDisconnected!", __FUNCTION__);
                return;
            }
            if (onDisconnected == nullptr) {
                return;
            }
            (*onDisconnected)(context, dev);
            break;
        }
        case kWhatOnError:
        {
            ACameraDevice* dev;
            found = msg->findPointer(kDeviceKey, (void**) &dev);
            if (!found || dev == nullptr) {
                ALOGE("%s: Cannot find device pointer!", __FUNCTION__);
                return;
            }
            ACameraDevice_ErrorStateCallback onError;
            found = msg->findPointer(kCallbackFpKey, (void**) &onError);
            if (!found) {
                ALOGE("%s: Cannot find onError!", __FUNCTION__);
                return;
            }
            int errorCode;
            found = msg->findInt32(kErrorCodeKey, &errorCode);
            if (!found) {
                ALOGE("%s: Cannot find error code!", __FUNCTION__);
                return;
            }
            if (onError == nullptr) {
                return;
            }
            (*onError)(context, dev, errorCode);
            break;
        }
        case kWhatSessionStateCb:
        case kWhatCaptureStart:
        case kWhatCaptureStart2:
        case kWhatCaptureResult:
        case kWhatLogicalCaptureResult:
        case kWhatCaptureFail:
        case kWhatLogicalCaptureFail:
        case kWhatCaptureSeqEnd:
        case kWhatCaptureSeqAbort:
        case kWhatCaptureBufferLost:
        case kWhatPreparedCb:
        {
            sp<RefBase> obj;
            found = msg->findObject(kSessionSpKey, &obj);
            if (!found || obj == nullptr) {
                ALOGE("%s: Cannot find session pointer!", __FUNCTION__);
                return;
            }
            sp<ACameraCaptureSession> session(static_cast<ACameraCaptureSession*>(obj.get()));
            mCachedSessions.push_back(session);
            sp<CaptureRequest> requestSp = nullptr;
            const char *id_cstr = mId.c_str();
            switch (msg->what()) {
                case kWhatCaptureStart:
                case kWhatCaptureStart2:
                case kWhatCaptureResult:
                case kWhatLogicalCaptureResult:
                case kWhatCaptureFail:
                case kWhatLogicalCaptureFail:
                case kWhatCaptureBufferLost:
                    found = msg->findObject(kCaptureRequestKey, &obj);
                    if (!found) {
                        ALOGE("%s: Cannot find capture request!", __FUNCTION__);
                        return;
                    }
                    requestSp = static_cast<CaptureRequest*>(obj.get());
                    break;
            }

            switch (msg->what()) {
                case kWhatSessionStateCb:
                {
                    ACameraCaptureSession_stateCallback onState;
                    found = msg->findPointer(kCallbackFpKey, (void**) &onState);
                    if (!found) {
                        ALOGE("%s: Cannot find state callback!", __FUNCTION__);
                        return;
                    }
                    if (onState == nullptr) {
                        return;
                    }
                    (*onState)(context, session.get());
                    break;
                }
                case kWhatPreparedCb:
                {
                    ACameraCaptureSession_prepareCallback onWindowPrepared;
                    found = msg->findPointer(kCallbackFpKey, (void**) &onWindowPrepared);
                    if (!found) {
                        ALOGE("%s: Cannot find state callback!", __FUNCTION__);
                        return;
                    }
                    if (onWindowPrepared == nullptr) {
                        return;
                    }
                    ANativeWindow* anw;
                    found = msg->findPointer(kAnwKey, (void**) &anw);
                    if (!found) {
                        ALOGE("%s: Cannot find ANativeWindow: %d!", __FUNCTION__, __LINE__);
                        return;
                    }
                    (*onWindowPrepared)(context, anw, session.get());
                    break;
                }
                case kWhatCaptureStart:
                {
                    ACameraCaptureSession_captureCallback_start onStart;
                    found = msg->findPointer(kCallbackFpKey, (void**) &onStart);
                    if (!found) {
                        ALOGE("%s: Cannot find capture start callback!", __FUNCTION__);
                        return;
                    }
                    if (onStart == nullptr) {
                        return;
                    }
                    int64_t timestamp;
                    found = msg->findInt64(kTimeStampKey, &timestamp);
                    if (!found) {
                        ALOGE("%s: Cannot find timestamp!", __FUNCTION__);
                        return;
                    }
                    ACaptureRequest* request = allocateACaptureRequest(requestSp, id_cstr);
                    (*onStart)(context, session.get(), request, timestamp);
                    freeACaptureRequest(request);
                    break;
                }
                case kWhatCaptureStart2:
                {
                    ACameraCaptureSession_captureCallback_startV2 onStart2;
                    found = msg->findPointer(kCallbackFpKey, (void**) &onStart2);
                    if (!found) {
                        ALOGE("%s: Cannot find capture startV2 callback!", __FUNCTION__);
                        return;
                    }
                    if (onStart2 == nullptr) {
                        return;
                    }
                    int64_t timestamp;
                    found = msg->findInt64(kTimeStampKey, &timestamp);
                    if (!found) {
                        ALOGE("%s: Cannot find timestamp!", __FUNCTION__);
                        return;
                    }
                    int64_t frameNumber;
                    found = msg->findInt64(kFrameNumberKey, &frameNumber);
                    if (!found) {
                        ALOGE("%s: Cannot find frame number!", __FUNCTION__);
                        return;
                    }

                    ACaptureRequest* request = allocateACaptureRequest(requestSp, id_cstr);
                    (*onStart2)(context, session.get(), request, timestamp, frameNumber);
                    freeACaptureRequest(request);
                    break;
                }
                case kWhatCaptureResult:
                {
                    ACameraCaptureSession_captureCallback_result onResult;
                    found = msg->findPointer(kCallbackFpKey, (void**) &onResult);
                    if (!found) {
                        ALOGE("%s: Cannot find capture result callback!", __FUNCTION__);
                        return;
                    }
                    if (onResult == nullptr) {
                        return;
                    }

                    found = msg->findObject(kCaptureResultKey, &obj);
                    if (!found) {
                        ALOGE("%s: Cannot find capture result!", __FUNCTION__);
                        return;
                    }
                    sp<ACameraMetadata> result(static_cast<ACameraMetadata*>(obj.get()));
                    ACaptureRequest* request = allocateACaptureRequest(requestSp, id_cstr);
                    (*onResult)(context, session.get(), request, result.get());
                    freeACaptureRequest(request);
                    break;
                }
                case kWhatLogicalCaptureResult:
                {
                    ACameraCaptureSession_logicalCamera_captureCallback_result onResult;
                    found = msg->findPointer(kCallbackFpKey, (void**) &onResult);
                    if (!found) {
                        ALOGE("%s: Cannot find capture result callback!", __FUNCTION__);
                        return;
                    }
                    if (onResult == nullptr) {
                        return;
                    }

                    found = msg->findObject(kCaptureResultKey, &obj);
                    if (!found) {
                        ALOGE("%s: Cannot find capture result!", __FUNCTION__);
                        return;
                    }
                    sp<ACameraMetadata> result(static_cast<ACameraMetadata*>(obj.get()));

                    found = msg->findObject(kPhysicalCaptureResultKey, &obj);
                    if (!found) {
                        ALOGE("%s: Cannot find physical capture result!", __FUNCTION__);
                        return;
                    }
                    sp<ACameraPhysicalCaptureResultInfo> physicalResult(
                            static_cast<ACameraPhysicalCaptureResultInfo*>(obj.get()));
                    std::vector<PhysicalCaptureResultInfoLocal>& physicalResultInfo =
                            physicalResult->mPhysicalResultInfo;

                    std::vector<std::string> physicalCameraIds;
                    std::vector<sp<ACameraMetadata>> physicalMetadataCopy;
                    for (size_t i = 0; i < physicalResultInfo.size(); i++) {
                        physicalCameraIds.push_back(physicalResultInfo[i].physicalCameraId);

                        CameraMetadata clone = physicalResultInfo[i].physicalMetadata;
                        clone.update(ANDROID_SYNC_FRAME_NUMBER,
                                &physicalResult->mFrameNumber, /*data_count*/1);
                        sp<ACameraMetadata> metadata =
                                new ACameraMetadata(clone.release(),
                                                    ACameraMetadata::ACM_RESULT);
                        physicalMetadataCopy.push_back(metadata);
                    }
                    std::vector<const char*> physicalCameraIdPtrs;
                    std::vector<const ACameraMetadata*> physicalMetadataCopyPtrs;
                    for (size_t i = 0; i < physicalResultInfo.size(); i++) {
                        physicalCameraIdPtrs.push_back(physicalCameraIds[i].c_str());
                        physicalMetadataCopyPtrs.push_back(physicalMetadataCopy[i].get());
                    }

                    ACaptureRequest* request = allocateACaptureRequest(requestSp, id_cstr);
                    (*onResult)(context, session.get(), request, result.get(),
                            physicalResultInfo.size(), physicalCameraIdPtrs.data(),
                            physicalMetadataCopyPtrs.data());
                    freeACaptureRequest(request);
                    break;
                }

                case kWhatCaptureFail:
                {
                    ACameraCaptureSession_captureCallback_failed onFail;
                    found = msg->findPointer(kCallbackFpKey, (void**) &onFail);
                    if (!found) {
                        ALOGE("%s: Cannot find capture fail callback!", __FUNCTION__);
                        return;
                    }
                    if (onFail == nullptr) {
                        return;
                    }

                    found = msg->findObject(kCaptureFailureKey, &obj);
                    if (!found) {
                        ALOGE("%s: Cannot find capture failure!", __FUNCTION__);
                        return;
                    }
                    sp<CameraCaptureFailure> failureSp(
                            static_cast<CameraCaptureFailure*>(obj.get()));
                    ACameraCaptureFailure* failure =
                            static_cast<ACameraCaptureFailure*>(failureSp.get());
                    ACaptureRequest* request = allocateACaptureRequest(requestSp, id_cstr);
                    (*onFail)(context, session.get(), request, failure);
                    freeACaptureRequest(request);
                    break;
                }
                case kWhatLogicalCaptureFail:
                {
                    ACameraCaptureSession_logicalCamera_captureCallback_failed onFail;
                    found = msg->findPointer(kCallbackFpKey, (void**) &onFail);
                    if (!found) {
                        ALOGE("%s: Cannot find capture fail callback!", __FUNCTION__);
                        return;
                    }
                    if (onFail == nullptr) {
                        return;
                    }

                    found = msg->findObject(kCaptureFailureKey, &obj);
                    if (!found) {
                        ALOGE("%s: Cannot find capture failure!", __FUNCTION__);
                        return;
                    }
                    sp<CameraCaptureFailure> failureSp(
                            static_cast<CameraCaptureFailure*>(obj.get()));
                    ALogicalCameraCaptureFailure failure;
                    AString physicalCameraId;
                    found = msg->findString(kFailingPhysicalCameraId, &physicalCameraId);
                    if (found && !physicalCameraId.empty()) {
                        failure.physicalCameraId = physicalCameraId.c_str();
                    } else {
                        failure.physicalCameraId = nullptr;
                    }
                    failure.captureFailure = *failureSp;
                    ACaptureRequest* request = allocateACaptureRequest(requestSp, id_cstr);
                    (*onFail)(context, session.get(), request, &failure);
                    freeACaptureRequest(request);
                    break;
                }
                case kWhatCaptureSeqEnd:
                {
                    ACameraCaptureSession_captureCallback_sequenceEnd onSeqEnd;
                    found = msg->findPointer(kCallbackFpKey, (void**) &onSeqEnd);
                    if (!found) {
                        ALOGE("%s: Cannot find sequence end callback!", __FUNCTION__);
                        return;
                    }
                    if (onSeqEnd == nullptr) {
                        return;
                    }
                    int seqId;
                    found = msg->findInt32(kSequenceIdKey, &seqId);
                    if (!found) {
                        ALOGE("%s: Cannot find frame number!", __FUNCTION__);
                        return;
                    }
                    int64_t frameNumber;
                    found = msg->findInt64(kFrameNumberKey, &frameNumber);
                    if (!found) {
                        ALOGE("%s: Cannot find frame number!", __FUNCTION__);
                        return;
                    }
                    (*onSeqEnd)(context, session.get(), seqId, frameNumber);
                    break;
                }
                case kWhatCaptureSeqAbort:
                {
                    ACameraCaptureSession_captureCallback_sequenceAbort onSeqAbort;
                    found = msg->findPointer(kCallbackFpKey, (void**) &onSeqAbort);
                    if (!found) {
                        ALOGE("%s: Cannot find sequence end callback!", __FUNCTION__);
                        return;
                    }
                    if (onSeqAbort == nullptr) {
                        return;
                    }
                    int seqId;
                    found = msg->findInt32(kSequenceIdKey, &seqId);
                    if (!found) {
                        ALOGE("%s: Cannot find frame number!", __FUNCTION__);
                        return;
                    }
                    (*onSeqAbort)(context, session.get(), seqId);
                    break;
                }
                case kWhatCaptureBufferLost:
                {
                    ACameraCaptureSession_captureCallback_bufferLost onBufferLost;
                    found = msg->findPointer(kCallbackFpKey, (void**) &onBufferLost);
                    if (!found) {
                        ALOGE("%s: Cannot find buffer lost callback!", __FUNCTION__);
                        return;
                    }
                    if (onBufferLost == nullptr) {
                        return;
                    }

                    ANativeWindow* anw;
                    found = msg->findPointer(kAnwKey, (void**) &anw);
                    if (!found) {
                        ALOGE("%s: Cannot find ANativeWindow!", __FUNCTION__);
                        return;
                    }

                    int64_t frameNumber;
                    found = msg->findInt64(kFrameNumberKey, &frameNumber);
                    if (!found) {
                        ALOGE("%s: Cannot find frame number!", __FUNCTION__);
                        return;
                    }

                    ACaptureRequest* request = allocateACaptureRequest(requestSp, id_cstr);
                    (*onBufferLost)(context, session.get(), request, anw, frameNumber);
                    freeACaptureRequest(request);
                    break;
                }
            }
            break;
        }
    }
}

CameraDevice::CallbackHolder::CallbackHolder(
        sp<ACameraCaptureSession>          session,
        std::vector<sp<CaptureRequest>>  requests,
        bool                               isRepeating,
        ACameraCaptureSession_captureCallbacks* cbs) :
        mSession(std::move(session)), mRequests(std::move(requests)),
        mIsRepeating(isRepeating),
        mIs2Callback(false),
        mIsLogicalCameraCallback(false) {
    initCaptureCallbacks(cbs);

    if (cbs != nullptr) {
        mOnCaptureCompleted = cbs->onCaptureCompleted;
        mOnCaptureFailed = cbs->onCaptureFailed;
    }
}

CameraDevice::CallbackHolder::CallbackHolder(
        sp<ACameraCaptureSession>          session,
        std::vector<sp<CaptureRequest>>  requests,
        bool                               isRepeating,
        ACameraCaptureSession_logicalCamera_captureCallbacks* lcbs) :
        mSession(std::move(session)), mRequests(std::move(requests)),
        mIsRepeating(isRepeating),
        mIs2Callback(false),
        mIsLogicalCameraCallback(true) {
    initCaptureCallbacks(lcbs);

    if (lcbs != nullptr) {
        mOnLogicalCameraCaptureCompleted = lcbs->onLogicalCameraCaptureCompleted;
        mOnLogicalCameraCaptureFailed = lcbs->onLogicalCameraCaptureFailed;
    }
}

CameraDevice::CallbackHolder::CallbackHolder(
        sp<ACameraCaptureSession>          session,
        std::vector<sp<CaptureRequest>>  requests,
        bool                               isRepeating,
        ACameraCaptureSession_captureCallbacksV2* cbs) :
        mSession(std::move(session)), mRequests(std::move(requests)),
        mIsRepeating(isRepeating),
        mIs2Callback(true),
        mIsLogicalCameraCallback(false) {
    initCaptureCallbacksV2(cbs);

    if (cbs != nullptr) {
        mOnCaptureCompleted = cbs->onCaptureCompleted;
        mOnCaptureFailed = cbs->onCaptureFailed;
    }
}

CameraDevice::CallbackHolder::CallbackHolder(
        sp<ACameraCaptureSession>          session,
        std::vector<sp<CaptureRequest>>  requests,
        bool                               isRepeating,
        ACameraCaptureSession_logicalCamera_captureCallbacksV2* lcbs) :
        mSession(std::move(session)), mRequests(std::move(requests)),
        mIsRepeating(isRepeating),
        mIs2Callback(true),
        mIsLogicalCameraCallback(true) {
    initCaptureCallbacksV2(lcbs);

    if (lcbs != nullptr) {
        mOnLogicalCameraCaptureCompleted = lcbs->onLogicalCameraCaptureCompleted;
        mOnLogicalCameraCaptureFailed = lcbs->onLogicalCameraCaptureFailed;
    }
}

void
CameraDevice::checkRepeatingSequenceCompleteLocked(
    const int sequenceId, const int64_t lastFrameNumber) {
    ALOGV("Repeating seqId %d lastFrameNumer %" PRId64, sequenceId, lastFrameNumber);
    if (lastFrameNumber == NO_FRAMES_CAPTURED) {
        if (mSequenceCallbackMap.count(sequenceId) == 0) {
            ALOGW("No callback found for sequenceId %d", sequenceId);
            return;
        }
        // remove callback holder from callback map
        auto cbIt = mSequenceCallbackMap.find(sequenceId);
        CallbackHolder cbh = cbIt->second;
        mSequenceCallbackMap.erase(cbIt);
        // send seq aborted callback
        sp<AMessage> msg = new AMessage(kWhatCaptureSeqAbort, mHandler);
        msg->setPointer(kContextKey, cbh.mContext);
        msg->setObject(kSessionSpKey, cbh.mSession);
        msg->setPointer(kCallbackFpKey, (void*) cbh.mOnCaptureSequenceAborted);
        msg->setInt32(kSequenceIdKey, sequenceId);
        postSessionMsgAndCleanup(msg);
    } else {
        // Use mSequenceLastFrameNumberMap to track
        mSequenceLastFrameNumberMap.insert(std::make_pair(sequenceId, lastFrameNumber));

        // Last frame might have arrived. Check now
        checkAndFireSequenceCompleteLocked();
    }
}

void
CameraDevice::checkAndFireSequenceCompleteLocked() {
    int64_t completedFrameNumber = mFrameNumberTracker.getCompletedFrameNumber();
    auto it = mSequenceLastFrameNumberMap.begin();
    while (it != mSequenceLastFrameNumberMap.end()) {
        int sequenceId = it->first;
        int64_t lastFrameNumber = it->second;
        bool seqCompleted = false;
        bool hasCallback  = true;

        if (mRemote == nullptr) {
            ALOGW("Camera %s closed while checking sequence complete", getId());
            return;
        }

        // Check if there is callback for this sequence
        // This should not happen because we always register callback (with nullptr inside)
        if (mSequenceCallbackMap.count(sequenceId) == 0) {
            ALOGW("No callback found for sequenceId %d", sequenceId);
            hasCallback = false;
        }

        if (lastFrameNumber <= completedFrameNumber) {
            ALOGV("seq %d reached last frame %" PRId64 ", completed %" PRId64,
                  sequenceId, lastFrameNumber, completedFrameNumber);
            seqCompleted = true;
        }

        if (seqCompleted && hasCallback) {
            // remove callback holder from callback map
            auto cbIt = mSequenceCallbackMap.find(sequenceId);
            CallbackHolder cbh = cbIt->second;
            mSequenceCallbackMap.erase(cbIt);
            // send seq complete callback
            sp<AMessage> msg = new AMessage(kWhatCaptureSeqEnd, mHandler);
            msg->setPointer(kContextKey, cbh.mContext);
            msg->setObject(kSessionSpKey, cbh.mSession);
            msg->setPointer(kCallbackFpKey, (void*) cbh.mOnCaptureSequenceCompleted);
            msg->setInt32(kSequenceIdKey, sequenceId);
            msg->setInt64(kFrameNumberKey, lastFrameNumber);

            // Clear the session sp before we send out the message
            // This will guarantee the rare case where the message is processed
            // before cbh goes out of scope and causing we call the session
            // destructor while holding device lock
            cbh.mSession.clear();

            postSessionMsgAndCleanup(msg);
        }

        // No need to track sequence complete if there is no callback registered
        if (seqCompleted || !hasCallback) {
            it = mSequenceLastFrameNumberMap.erase(it);
        } else {
            ++it;
        }
    }
}

void CameraDevice::stopLooperAndDisconnect() {
    Mutex::Autolock _l(mDeviceLock);
    sp<ACameraCaptureSession> session = mCurrentSession.promote();
    if (!isClosed()) {
        disconnectLocked(session);
    }
    mCurrentSession = nullptr;
    if (mCbLooper != nullptr) {
      mCbLooper->unregisterHandler(mHandler->id());
      mCbLooper->stop();
    }
    mCbLooper.clear();
    mHandler.clear();
}

/**
  * Camera service callback implementation
  */
ScopedAStatus CameraDevice::ServiceCallback::onDeviceError(
        ErrorCode errorCode, const CaptureResultExtras& resultExtras) {
    ALOGD("Device error received, code %d, frame number %" PRId64 ", request ID %d, subseq ID %d"
            " physical camera ID %s", errorCode, resultExtras.frameNumber, resultExtras.requestId,
            resultExtras.burstId, resultExtras.errorPhysicalCameraId.c_str());

    std::shared_ptr<CameraDevice> dev = mDevice.lock();
    if (dev == nullptr) {
        return ScopedAStatus::ok(); // device has been closed
    }

    sp<ACameraCaptureSession> session = dev->mCurrentSession.promote();
    Mutex::Autolock _l(dev->mDeviceLock);
    if (dev->mRemote == nullptr) {
        return ScopedAStatus::ok(); // device has been closed
    }
    switch (errorCode) {
        case ErrorCode::CAMERA_DISCONNECTED:
        {
            // Camera is disconnected, close the session and expect no more callbacks
            if (session != nullptr) {
                session->closeByDevice();
            }
            dev->mCurrentSession = nullptr;
            sp<AMessage> msg = new AMessage(kWhatOnDisconnected, dev->mHandler);
            msg->setPointer(kContextKey, dev->mAppCallbacks.context);
            msg->setPointer(kDeviceKey, (void*) dev->getWrapper());
            msg->setPointer(kCallbackFpKey, (void*) dev->mAppCallbacks.onDisconnected);
            msg->post();
            break;
        }
        default:
            ALOGE("Unknown error from camera device: %d", errorCode);
            [[fallthrough]];
        case ErrorCode::CAMERA_DEVICE:
        case ErrorCode::CAMERA_SERVICE:
        {
            int32_t errorVal = ::ERROR_CAMERA_DEVICE;
            // We keep this switch since this block might be encountered with
            // more than just 2 states. The default fallthrough could have us
            // handling more unmatched error cases.
            switch (errorCode) {
                case ErrorCode::CAMERA_DEVICE:
                    dev->setCameraDeviceErrorLocked(ACAMERA_ERROR_CAMERA_DEVICE);
                    break;
                case ErrorCode::CAMERA_SERVICE:
                    dev->setCameraDeviceErrorLocked(ACAMERA_ERROR_CAMERA_SERVICE);
                    errorVal = ::ERROR_CAMERA_SERVICE;
                    break;
                default:
                    dev->setCameraDeviceErrorLocked(ACAMERA_ERROR_UNKNOWN);
                    break;
            }
            sp<AMessage> msg = new AMessage(kWhatOnError, dev->mHandler);
            msg->setPointer(kContextKey, dev->mAppCallbacks.context);
            msg->setPointer(kDeviceKey, (void*) dev->getWrapper());
            msg->setPointer(kCallbackFpKey, (void*) dev->mAppCallbacks.onError);
            msg->setInt32(kErrorCodeKey, errorVal);
            msg->post();
            break;
        }
        case ErrorCode::CAMERA_REQUEST:
        case ErrorCode::CAMERA_RESULT:
        case ErrorCode::CAMERA_BUFFER:
            dev->onCaptureErrorLocked(errorCode, resultExtras);
            break;
    }
    return ScopedAStatus::ok();
}

ScopedAStatus CameraDevice::ServiceCallback::onDeviceIdle() {
    ALOGV("Camera is now idle");

    std::shared_ptr<CameraDevice> dev = mDevice.lock();
    if (dev == nullptr) {
        return ScopedAStatus::ok(); // device has been closed
    }

    Mutex::Autolock _l(dev->mDeviceLock);
    if (dev->isClosed() || dev->mRemote == nullptr) {
        return ScopedAStatus::ok();
    }

    if (dev->mIdle) {
        // Already in idle state. Possibly other thread did waitUntilIdle
        return ScopedAStatus::ok();
    }

    if (dev->mCurrentSession != nullptr) {
        ALOGE("onDeviceIdle sending state cb");
        if (dev->mBusySession != dev->mCurrentSession) {
            ALOGE("Current session != busy session");
            dev->setCameraDeviceErrorLocked(ACAMERA_ERROR_CAMERA_DEVICE);
            return ScopedAStatus::ok();
        }

        sp<AMessage> msg = new AMessage(kWhatSessionStateCb, dev->mHandler);
        msg->setPointer(kContextKey, dev->mBusySession->mUserSessionCallback.context);
        msg->setObject(kSessionSpKey, dev->mBusySession);
        msg->setPointer(kCallbackFpKey,
                        (void*) dev->mBusySession->mUserSessionCallback.onReady);
        // Make sure we clear the sp first so the session destructor can
        // only happen on handler thread (where we don't hold device/session lock)
        dev->mBusySession.clear();
        dev->postSessionMsgAndCleanup(msg);
    }
    dev->mIdle = true;
    dev->mFlushing = false;
    return ScopedAStatus::ok();
}



ndk::ScopedAStatus CameraDevice::ServiceCallback::onCaptureStarted(
        const CaptureResultExtras& resultExtras, int64_t timestamp) {
    std::shared_ptr<CameraDevice> dev = mDevice.lock();
    if (dev == nullptr) {
        return ScopedAStatus::ok(); // device has been closed
    }
    Mutex::Autolock _l(dev->mDeviceLock);
    if (dev->isClosed() || dev->mRemote == nullptr) {
        return ScopedAStatus::ok();
    }

    int32_t sequenceId = resultExtras.requestId;
    int32_t burstId = resultExtras.burstId;
    int64_t frameNumber = resultExtras.frameNumber;

    auto it = dev->mSequenceCallbackMap.find(sequenceId);
    if (it != dev->mSequenceCallbackMap.end()) {
        CallbackHolder &cbh = it->second;
        ACameraCaptureSession_captureCallback_start onStart = cbh.mOnCaptureStarted;
        ACameraCaptureSession_captureCallback_startV2 onStart2 = cbh.mOnCaptureStarted2;
        bool v2Callback = cbh.mIs2Callback;
        sp<ACameraCaptureSession> session = cbh.mSession;
        if ((size_t) burstId >= cbh.mRequests.size()) {
            ALOGE("%s: Error: request index %d out of bound (size %zu)",
                    __FUNCTION__, burstId, cbh.mRequests.size());
            dev->setCameraDeviceErrorLocked(ACAMERA_ERROR_CAMERA_SERVICE);
        }
        sp<CaptureRequest> request = cbh.mRequests[burstId];
        ALOGE("%s: request = %p", __FUNCTION__, request.get());
        sp<AMessage> msg = nullptr;
        if (v2Callback) {
            msg = new AMessage(kWhatCaptureStart2, dev->mHandler);
            msg->setPointer(kCallbackFpKey, (void*) onStart2);
        } else {
            msg = new AMessage(kWhatCaptureStart, dev->mHandler);
            msg->setPointer(kCallbackFpKey, (void*) onStart);
        }
        msg->setPointer(kContextKey, cbh.mContext);
        msg->setObject(kSessionSpKey, session);
        msg->setObject(kCaptureRequestKey, request);
        msg->setInt64(kTimeStampKey, timestamp);
        msg->setInt64(kFrameNumberKey, frameNumber);
        dev->postSessionMsgAndCleanup(msg);
    }
    return ScopedAStatus::ok();
}

ScopedAStatus CameraDevice::ServiceCallback::onResultReceived(
        const CaptureMetadataInfo& resultMetadata,
        const CaptureResultExtras& resultExtras,
        const std::vector<PhysicalCaptureResultInfo>& physicalResultInfos) {

    std::shared_ptr<CameraDevice> dev = mDevice.lock();
    if (dev == nullptr) {
        return ScopedAStatus::ok(); // device has been closed
    }
    int32_t sequenceId = resultExtras.requestId;
    int64_t frameNumber = resultExtras.frameNumber;
    int32_t burstId = resultExtras.burstId;
    bool isPartialResult = (resultExtras.partialResultCount < dev->mPartialResultCount);

    if (!isPartialResult) {
        ALOGV("SeqId %d frame %" PRId64 " result arrive.", sequenceId, frameNumber);
    }

    Mutex::Autolock _l(dev->mDeviceLock);
    if (dev->mRemote == nullptr) {
        return ScopedAStatus::ok(); // device has been disconnected
    }

    if (dev->isClosed()) {
        if (!isPartialResult) {
            dev->mFrameNumberTracker.updateTracker(frameNumber, /*isError*/false);
        }
        // early return to avoid callback sent to closed devices
        return ScopedAStatus::ok();
    }

    CameraMetadata metadataCopy;
    camera_status_t status = readOneResultMetadata(resultMetadata,
            dev->mCaptureResultMetadataQueue.get(), &metadataCopy);
    if (status != ACAMERA_OK) {
        ALOGE("%s: result metadata couldn't be converted", __FUNCTION__);
        return ScopedAStatus::ok();
    }

    metadataCopy.update(ANDROID_LENS_INFO_SHADING_MAP_SIZE, dev->mShadingMapSize,
                        /* data_count= */ 2);
    metadataCopy.update(ANDROID_SYNC_FRAME_NUMBER, &frameNumber, /* data_count= */1);

    auto it = dev->mSequenceCallbackMap.find(sequenceId);
    if (it != dev->mSequenceCallbackMap.end()) {
        CallbackHolder cbh = (*it).second;
        sp<ACameraCaptureSession> session = cbh.mSession;
        if ((size_t) burstId >= cbh.mRequests.size()) {
            ALOGE("%s: Error: request index %d out of bound (size %zu)",
                    __FUNCTION__, burstId, cbh.mRequests.size());
            dev->setCameraDeviceErrorLocked(ACAMERA_ERROR_CAMERA_SERVICE);
        }
        sp<CaptureRequest> request = cbh.mRequests[burstId];
        sp<ACameraMetadata> result(new ACameraMetadata(
                metadataCopy.release(), ACameraMetadata::ACM_RESULT));

        std::vector<PhysicalCaptureResultInfoLocal> localPhysicalResult;
        localPhysicalResult.resize(physicalResultInfos.size());
        for (size_t i = 0; i < physicalResultInfos.size(); i++) {
            localPhysicalResult[i].physicalCameraId = physicalResultInfos[i].physicalCameraId;
            status = readOneResultMetadata(physicalResultInfos[i].physicalCameraMetadata,
                    dev->mCaptureResultMetadataQueue.get(),
                    &localPhysicalResult[i].physicalMetadata);
            if (status != ACAMERA_OK) {
                ALOGE("%s: physical camera result metadata couldn't be converted", __FUNCTION__);
                return ScopedAStatus::ok();
            }
        }
        sp<ACameraPhysicalCaptureResultInfo> physicalResult(
                new ACameraPhysicalCaptureResultInfo(localPhysicalResult, frameNumber));

        sp<AMessage> msg = new AMessage(
                cbh.mIsLogicalCameraCallback ? kWhatLogicalCaptureResult : kWhatCaptureResult,
                dev->mHandler);
        msg->setPointer(kContextKey, cbh.mContext);
        msg->setObject(kSessionSpKey, session);
        msg->setObject(kCaptureRequestKey, request);
        msg->setObject(kCaptureResultKey, result);
        if (isPartialResult) {
            msg->setPointer(kCallbackFpKey,
                    (void *)cbh.mOnCaptureProgressed);
        } else if (cbh.mIsLogicalCameraCallback) {
            msg->setPointer(kCallbackFpKey,
                    (void *)cbh.mOnLogicalCameraCaptureCompleted);
            msg->setObject(kPhysicalCaptureResultKey, physicalResult);
        } else {
            msg->setPointer(kCallbackFpKey,
                    (void *)cbh.mOnCaptureCompleted);
        }
        dev->postSessionMsgAndCleanup(msg);
    }

    if (!isPartialResult) {
        dev->mFrameNumberTracker.updateTracker(frameNumber, /*isError*/false);
        dev->checkAndFireSequenceCompleteLocked();
    }

    return ScopedAStatus::ok();
}

ScopedAStatus CameraDevice::ServiceCallback::onRepeatingRequestError(int64_t lastFrameNumber,
                                                                     int32_t stoppedSequenceId) {
    std::shared_ptr<CameraDevice> dev = mDevice.lock();
    if (dev == nullptr) {
        return ScopedAStatus::ok(); // device has been closed
    }

    Mutex::Autolock _l(dev->mDeviceLock);

    int repeatingSequenceId = dev->mRepeatingSequenceId;
    if (stoppedSequenceId == repeatingSequenceId) {
        dev->mRepeatingSequenceId = REQUEST_ID_NONE;
    }

    dev->checkRepeatingSequenceCompleteLocked(repeatingSequenceId, lastFrameNumber);

    return ScopedAStatus::ok();
}

ScopedAStatus CameraDevice::ServiceCallback::onPrepared(int32_t streamId) {
    ALOGV("%s: callback for stream id %d", __FUNCTION__, streamId);
    std::shared_ptr<CameraDevice> dev = mDevice.lock();
    if (dev == nullptr) {
        return ScopedAStatus::ok();
    }
    Mutex::Autolock _l(dev->mDeviceLock);
    if (dev->isClosed() || dev->mRemote == nullptr) {
        return ScopedAStatus::ok();
    }
    auto it = dev->mConfiguredOutputs.find(streamId);
    if (it == dev->mConfiguredOutputs.end()) {
        ALOGE("%s: stream id %d does not exist", __FUNCTION__ , streamId);
        return ScopedAStatus::ok();
    }
    sp<ACameraCaptureSession> session = dev->mCurrentSession.promote();
    if (session == nullptr) {
        ALOGE("%s: Session is dead already", __FUNCTION__ );
        return ScopedAStatus::ok();
    }
    // We've found the window corresponding to the surface id.
    const ANativeWindow *anw = it->second.first;
    sp<AMessage> msg = new AMessage(kWhatPreparedCb, dev->mHandler);
    msg->setPointer(kContextKey, session->mPreparedCb.context);
    msg->setPointer(kAnwKey, (void *)anw);
    msg->setObject(kSessionSpKey, session);
    msg->setPointer(kCallbackFpKey, (void *)session->mPreparedCb.onWindowPrepared);
    dev->postSessionMsgAndCleanup(msg);
    return ScopedAStatus::ok();
}

camera_status_t CameraDevice::ServiceCallback::readOneResultMetadata(
        const CaptureMetadataInfo& captureMetadataInfo, ResultMetadataQueue* metadataQueue,
        CameraMetadata* metadata) {
    if (metadataQueue == nullptr || metadata == nullptr) {
        return ACAMERA_ERROR_INVALID_PARAMETER;
    }
    bool converted;
    AidlCameraMetadata aidlCameraMetadata;
    std::vector<uint8_t>& metadataVec = aidlCameraMetadata.metadata;
    camera_metadata_t* clonedMetadata;
    if (captureMetadataInfo.getTag() == CaptureMetadataInfo::fmqMetadataSize) {
        int64_t size = captureMetadataInfo.get<CaptureMetadataInfo::fmqMetadataSize>();
        metadataVec.resize(size);
        bool read = metadataQueue->read(reinterpret_cast<int8_t*>(metadataVec.data()), size);
        if (!read) {
            ALOGE("%s capture request settings could't be read from fmq", __FUNCTION__);
            return ACAMERA_ERROR_UNKNOWN;
        }
        // TODO: Do we actually need to clone here ?
        converted = utils::cloneFromAidl(aidlCameraMetadata, &clonedMetadata);
    } else {
        const AidlCameraMetadata &embeddedMetadata =
                captureMetadataInfo.get<CaptureMetadataInfo::metadata>();
        converted = utils::cloneFromAidl(embeddedMetadata, &clonedMetadata);
    }

    if (converted) {
        *metadata = CameraMetadata(clonedMetadata);
        return ACAMERA_OK;
    }

    return ACAMERA_ERROR_UNKNOWN;
}

} // namespace acam
} // namespace android
