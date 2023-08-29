/******************************************************************************
 *
 * Copyright (C) 2021 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 *****************************************************************************
 * Originally developed and contributed by Ittiam Systems Pvt. Ltd, Bangalore
 */

#define LOG_TAG "CameraServiceFuzzer"
//#define LOG_NDEBUG 0

#include <AudioFlinger.h>
#include <CameraService.h>
#include <ISchedulingPolicyService.h>
#include <MediaPlayerService.h>
#include <android-base/logging.h>
#include <android/hardware/BnCameraServiceListener.h>
#include <android/hardware/ICameraServiceListener.h>
#include <android/hardware/camera2/BnCameraDeviceCallbacks.h>
#include <android/hardware/camera2/ICameraDeviceUser.h>
#include <binder/IActivityManager.h>
#include <binder/IAppOpsService.h>
#include <camera/camera2/OutputConfiguration.h>
#include <device3/Camera3StreamInterface.h>
#include <fakeservicemanager/FakeServiceManager.h>
#include <fuzzbinder/random_binder.h>
#include <gui/BufferItemConsumer.h>
#include <gui/IGraphicBufferProducer.h>
#include <gui/Surface.h>
#include <gui/SurfaceComposerClient.h>
#include <media/IAudioFlinger.h>
#include <private/android_filesystem_config.h>
#include "fuzzer/FuzzedDataProvider.h"

using namespace android;
using namespace hardware;
using namespace std;

const int32_t kPreviewThreshold = 8;
const int32_t kNumRequestsTested = 8;
const nsecs_t kPreviewTimeout = 5000000000;  // .5 [s.]
const nsecs_t kEventTimeout = 10000000000;   // 1 [s.]
const size_t kMaxNumLines = USHRT_MAX;
const size_t kMinArgs = 1;
const size_t kMaxArgs = 5;
const int32_t kCamType[] = {hardware::ICameraService::CAMERA_TYPE_BACKWARD_COMPATIBLE,
                            hardware::ICameraService::CAMERA_TYPE_ALL};
const int kCameraApiVersion[] = {android::CameraService::API_VERSION_1,
                                 android::CameraService::API_VERSION_2};
const uint8_t kSensorPixelModes[] = {ANDROID_SENSOR_PIXEL_MODE_DEFAULT,
        ANDROID_SENSOR_PIXEL_MODE_MAXIMUM_RESOLUTION};
const int32_t kRequestTemplates[] = {
    hardware::camera2::ICameraDeviceUser::TEMPLATE_PREVIEW,
    hardware::camera2::ICameraDeviceUser::TEMPLATE_STILL_CAPTURE,
    hardware::camera2::ICameraDeviceUser::TEMPLATE_RECORD,
    hardware::camera2::ICameraDeviceUser::TEMPLATE_VIDEO_SNAPSHOT,
    hardware::camera2::ICameraDeviceUser::TEMPLATE_MANUAL,
    hardware::camera2::ICameraDeviceUser::TEMPLATE_ZERO_SHUTTER_LAG
};

const int32_t kRotations[] = {
    camera3::CAMERA_STREAM_ROTATION_0,
    camera3::CAMERA_STREAM_ROTATION_90,
    camera3::CAMERA_STREAM_ROTATION_270
};

const int kLayerMetadata[] = {
    0x00100000 /*GRALLOC_USAGE_RENDERSCRIPT*/, 0x00000003 /*GRALLOC_USAGE_SW_READ_OFTEN*/,
    0x00000100 /*GRALLOC_USAGE_HW_TEXTURE*/,   0x00000800 /*GRALLOC_USAGE_HW_COMPOSER*/,
    0x00000200 /*GRALLOC_USAGE_HW_RENDER*/,    0x00010000 /*GRALLOC_USAGE_HW_VIDEO_ENCODER*/};
const int kCameraMsg[] = {0x001 /*CAMERA_MSG_ERROR*/,
                          0x002 /*CAMERA_MSG_SHUTTER*/,
                          0x004 /*CAMERA_MSG_FOCUS*/,
                          0x008 /*CAMERA_MSG_ZOOM*/,
                          0x010 /*CAMERA_MSG_PREVIEW_FRAME*/,
                          0x020 /*CAMERA_MSG_VIDEO_FRAME */,
                          0x040 /*CAMERA_MSG_POSTVIEW_FRAME*/,
                          0x080 /*CAMERA_MSG_RAW_IMAGE */,
                          0x100 /*CAMERA_MSG_COMPRESSED_IMAGE*/,
                          0x200 /*CAMERA_MSG_RAW_IMAGE_NOTIFY*/,
                          0x400 /*CAMERA_MSG_PREVIEW_METADATA*/,
                          0x800 /*CAMERA_MSG_FOCUS_MOVE*/};
const int32_t kEventId[] = {ICameraService::EVENT_USER_SWITCHED, ICameraService::EVENT_NONE};
const android::CameraService::sound_kind kSoundKind[] = {
    android::CameraService::SOUND_SHUTTER, android::CameraService::SOUND_RECORDING_START,
    android::CameraService::SOUND_RECORDING_STOP};
const String16 kShellCmd[] = {String16("set-uid-state"),       String16("reset-uid-state"),
                              String16("get-uid-state"),       String16("set-rotate-and-crop"),
                              String16("get-rotate-and-crop"), String16("help")};
const size_t kNumLayerMetaData = size(kLayerMetadata);
const size_t kNumCameraMsg = size(kCameraMsg);
const size_t kNumSoundKind = size(kSoundKind);
const size_t kNumShellCmd = size(kShellCmd);
static std::once_flag gSmOnce;
sp<FakeServiceManager> gFakeServiceManager;

void addService(const String16& serviceName, const sp<FakeServiceManager>& fakeServiceManager,
                FuzzedDataProvider* fdp) {
    sp<IBinder> binder = getRandomBinder(fdp);
    if (!binder) {
        return;
    }

    CHECK_EQ(NO_ERROR, fakeServiceManager->addService(serviceName, binder));
    return;
}

class FuzzerActivityManager : public BnInterface<IActivityManager> {
  public:
    int32_t openContentUri(const String16& /*stringUri*/) override { return 0; }

    status_t registerUidObserver(const sp<IUidObserver>& /*observer*/, const int32_t /*event*/,
                                 const int32_t /*cutpoint*/,
                                 const String16& /*callingPackage*/) override {
        return OK;
    }

    status_t unregisterUidObserver(const sp<IUidObserver>& /*observer*/) override { return OK; }

    status_t registerUidObserverForUids(const sp<IUidObserver>& /*observer*/,
                                        const int32_t /*event*/, const int32_t /*cutpoint*/,
                                        const String16& /*callingPackage*/,
                                        const int32_t* /*uids[]*/, size_t /*nUids*/,
                                        /*out*/ sp<IBinder>& /*observerToken*/) override {
        return OK;
    }

    status_t addUidToObserver(const sp<IBinder>& /*observerToken*/,
                              const String16& /*callingPackage*/, int32_t /*uid*/) override {
        return OK;
    }

    status_t removeUidFromObserver(const sp<IBinder>& /*observerToken*/,
                                   const String16& /*callingPackage*/, int32_t /*uid*/) override {
        return OK;
    }

    bool isUidActive(const uid_t /*uid*/, const String16& /*callingPackage*/) override {
        return true;
    }

    int32_t getUidProcessState(const uid_t /*uid*/, const String16& /*callingPackage*/) override {
        return ActivityManager::PROCESS_STATE_UNKNOWN;
    }

    status_t checkPermission(const String16& /*permission*/, const pid_t /*pid*/,
                             const uid_t /*uid*/, int32_t* /*outResult*/) override {
        return NO_ERROR;
    }

    status_t logFgsApiBegin(int32_t /*apiType*/, int32_t /*appUid*/, int32_t /*appPid*/) override {
        return OK;
    }
    status_t logFgsApiEnd(int32_t /*apiType*/, int32_t /*appUid*/, int32_t /*appPid*/) override {
        return OK;
    }
    status_t logFgsApiStateChanged(int32_t /*apiType*/, int32_t /*state*/, int32_t /*appUid*/,
                                   int32_t /*appPid*/) override {
        return OK;
    }
};

class FuzzerSensorPrivacyManager : public BnInterface<hardware::ISensorPrivacyManager> {
  public:
    binder::Status supportsSensorToggle(int32_t /*toggleType*/, int32_t /*sensor*/,
                                        bool* /*_aidl_return*/) override {
        return binder::Status::fromStatusT(UNKNOWN_TRANSACTION);
    }
    binder::Status addSensorPrivacyListener(
            const sp<hardware::ISensorPrivacyListener>& /*listener*/) override {
        return binder::Status::fromStatusT(::android::UNKNOWN_TRANSACTION);
    }
    binder::Status addToggleSensorPrivacyListener(
            const sp<hardware::ISensorPrivacyListener>& /*listener*/) override {
        return binder::Status::fromStatusT(UNKNOWN_TRANSACTION);
    }
    binder::Status removeSensorPrivacyListener(
            const sp<hardware::ISensorPrivacyListener>& /*listener*/) override {
        return binder::Status::fromStatusT(::android::UNKNOWN_TRANSACTION);
    }
    binder::Status removeToggleSensorPrivacyListener(
            const sp<hardware::ISensorPrivacyListener>& /*listener*/) override {
        return binder::Status::fromStatusT(::android::UNKNOWN_TRANSACTION);
    }
    binder::Status isSensorPrivacyEnabled(bool* /*_aidl_return*/) override {
        return binder::Status::fromStatusT(UNKNOWN_TRANSACTION);
    }
    binder::Status isCombinedToggleSensorPrivacyEnabled(int32_t /*sensor*/,
                                                        bool* /*_aidl_return*/) override {
        return binder::Status::fromStatusT(UNKNOWN_TRANSACTION);
    }
    binder::Status isToggleSensorPrivacyEnabled(int32_t /*toggleType*/, int32_t /*sensor*/,
                                                bool* /*_aidl_return*/) override {
        return binder::Status::fromStatusT(UNKNOWN_TRANSACTION);
    }
    binder::Status setSensorPrivacy(bool /*enable*/) override {
        return binder::Status::fromStatusT(UNKNOWN_TRANSACTION);
    }
    binder::Status setToggleSensorPrivacy(int32_t /*userId*/, int32_t /*source*/,
                                          int32_t /*sensor*/, bool /*enable*/) override {
        return binder::Status::fromStatusT(UNKNOWN_TRANSACTION);
    }
    binder::Status setToggleSensorPrivacyForProfileGroup(int32_t /*userId*/, int32_t /*source*/,
                                                         int32_t /*sensor*/,
                                                         bool /*enable*/) override {
        return binder::Status::fromStatusT(UNKNOWN_TRANSACTION);
    }
};

class FuzzAppOpsService : public BnAppOpsService {
  public:
    int32_t checkOperation(int32_t /*code*/, int32_t /*uid*/,
                           const String16& /*packageName*/) override {
        return 0;
    }

    int32_t noteOperation(int32_t /*code*/, int32_t /*uid*/, const String16& /*packageName*/,
                          const std::optional<String16>& /*attributionTag*/,
                          bool /*shouldCollectAsyncNotedOp*/, const String16& /*message*/,
                          bool /*shouldCollectMessage*/) override {
        return 0;
    }

    void startWatchingModeWithFlags(int32_t /*op*/, const String16& /*packageName*/,
                                    int32_t /*flags*/,
                                    const sp<IAppOpsCallback>& /*callback*/) override {
        return;
    }

    int32_t startOperation(const sp<IBinder>& /*token*/, int32_t /*code*/, int32_t /*uid*/,
                           const String16& /*packageName*/,
                           const std::optional<String16>& /*attributionTag*/,
                           bool /*startIfModeDefault*/, bool /*shouldCollectAsyncNotedOp*/,
                           const String16& /*message*/, bool /*shouldCollectMessage*/) override {
        return 0;
    }

    void finishOperation(const sp<IBinder>& /*token*/, int32_t /*code*/, int32_t /*uid*/,
                         const String16& /*packageName*/,
                         const std::optional<String16>& /*attributionTag*/) override {
        return;
    }

    void startWatchingMode(int32_t /*op*/, const String16& /*packageName*/,
                           const sp<IAppOpsCallback>& /*callback*/) override {
        return;
    }

    void stopWatchingMode(const sp<IAppOpsCallback>& /*callback*/) override { return; }

    int32_t permissionToOpCode(const String16& /*permission*/) override { return 0; }

    int32_t checkAudioOperation(int32_t /*code*/, int32_t /*usage*/, int32_t /*uid*/,
                                const String16& /*packageName*/) override {
        return 0;
    }

    void setCameraAudioRestriction(int32_t /*mode*/) override { return; }

    bool shouldCollectNotes(int32_t /*opCode*/) override { return true; }
};

class CameraFuzzer : public ::android::hardware::BnCameraClient {
   public:
    CameraFuzzer(sp<CameraService> cs, std::shared_ptr<FuzzedDataProvider> fp) :
          mCameraService(cs), mFuzzedDataProvider(fp) {};
    ~CameraFuzzer() { deInit(); }
    void process();
    void deInit();

   private:
    sp<CameraService> mCameraService = nullptr;
    std::shared_ptr<FuzzedDataProvider> mFuzzedDataProvider = nullptr;
    sp<SurfaceComposerClient> mComposerClient = nullptr;
    int32_t mNumCameras = 0;
    size_t mPreviewBufferCount = 0;
    bool mAutoFocusMessage = false;
    bool mSnapshotNotification = false;
    bool mRecordingNotification = false;
    mutable Mutex mPreviewLock;
    mutable Condition mPreviewCondition;
    mutable Mutex mAutoFocusLock;
    mutable Condition mAutoFocusCondition;
    mutable Mutex mSnapshotLock;
    mutable Condition mSnapshotCondition;
    mutable Mutex mRecordingLock;
    mutable Condition mRecordingCondition;

    void getNumCameras();
    void getCameraInformation(int32_t cameraId);
    void invokeCameraAPIs();
    void invokeCameraSound();
    void invokeDump();
    void invokeShellCommand();
    void invokeNotifyCalls();
    void invokeTorchAPIs(int32_t cameraId);

    // CameraClient interface
    void notifyCallback(int32_t msgType, int32_t, int32_t) override;
    void dataCallback(int32_t msgType, const sp<IMemory> &, camera_frame_metadata_t *) override;
    void dataCallbackTimestamp(nsecs_t, int32_t, const sp<IMemory> &) override{};
    void recordingFrameHandleCallbackTimestamp(nsecs_t, native_handle_t *) override{};
    void recordingFrameHandleCallbackTimestampBatch(
        const std::vector<nsecs_t> &, const std::vector<native_handle_t *> &) override{};
    status_t waitForPreviewStart();
    status_t waitForEvent(Mutex &mutex, Condition &condition, bool &flag);
};

void CameraFuzzer::notifyCallback(int32_t msgType, int32_t, int32_t) {
    if (CAMERA_MSG_FOCUS == msgType) {
        Mutex::Autolock l(mAutoFocusLock);
        mAutoFocusMessage = true;
        mAutoFocusCondition.broadcast();
    }
};

void CameraFuzzer::dataCallback(int32_t msgType, const sp<IMemory> & /*data*/,
                                camera_frame_metadata_t *) {
    switch (msgType) {
        case CAMERA_MSG_PREVIEW_FRAME: {
            Mutex::Autolock l(mPreviewLock);
            ++mPreviewBufferCount;
            mPreviewCondition.broadcast();
            mRecordingNotification = true;
            mRecordingCondition.broadcast();
            break;
        }
        case CAMERA_MSG_COMPRESSED_IMAGE: {
            Mutex::Autolock l(mSnapshotLock);
            mSnapshotNotification = true;
            mSnapshotCondition.broadcast();
            break;
        }
        default:
            break;
    }
};

status_t CameraFuzzer::waitForPreviewStart() {
    status_t rc = NO_ERROR;
    Mutex::Autolock l(mPreviewLock);
    mPreviewBufferCount = 0;

    while (mPreviewBufferCount < kPreviewThreshold) {
        rc = mPreviewCondition.waitRelative(mPreviewLock, kPreviewTimeout);
        if (NO_ERROR != rc) {
            break;
        }
    }

    return rc;
}

status_t CameraFuzzer::waitForEvent(Mutex &mutex, Condition &condition, bool &flag) {
    status_t rc = NO_ERROR;
    Mutex::Autolock l(mutex);
    flag = false;

    while (!flag) {
        rc = condition.waitRelative(mutex, kEventTimeout);
        if (NO_ERROR != rc) {
            break;
        }
    }

    return rc;
}

void CameraFuzzer::deInit() {
    if (mComposerClient) {
        mComposerClient->dispose();
    }
}

void CameraFuzzer::getNumCameras() {
    bool shouldPassInvalidCamType = mFuzzedDataProvider->ConsumeBool();
    int32_t camType;
    if (shouldPassInvalidCamType) {
        camType = mFuzzedDataProvider->ConsumeIntegral<int32_t>();
    } else {
        camType = kCamType[mFuzzedDataProvider->ConsumeBool()];
    }
    mCameraService->getNumberOfCameras(camType, &mNumCameras);
}

void CameraFuzzer::getCameraInformation(int32_t cameraId) {
    std::string cameraIdStr = std::to_string(cameraId);
    bool isSupported = false;
    mCameraService->supportsCameraApi(
        cameraIdStr, kCameraApiVersion[mFuzzedDataProvider->ConsumeBool()], &isSupported);
    mCameraService->isHiddenPhysicalCamera(cameraIdStr, &isSupported);

    std::string parameters;
    mCameraService->getLegacyParameters(cameraId, &parameters);

    std::vector<hardware::camera2::utils::ConcurrentCameraIdCombination> concurrentCameraIds;
    mCameraService->getConcurrentCameraIds(&concurrentCameraIds);

    hardware::camera2::params::VendorTagDescriptorCache cache;
    mCameraService->getCameraVendorTagCache(&cache);

    CameraInfo cameraInfo;
    mCameraService->getCameraInfo(cameraId, /*overrideToPortrait*/false, &cameraInfo);

    CameraMetadata metadata;
    mCameraService->getCameraCharacteristics(cameraIdStr,
            /*targetSdkVersion*/__ANDROID_API_FUTURE__, /*overrideToPortrait*/false, &metadata);
}

void CameraFuzzer::invokeCameraSound() {
    mCameraService->increaseSoundRef();
    mCameraService->decreaseSoundRef();
    bool shouldPassInvalidPlaySound = mFuzzedDataProvider->ConsumeBool();
    bool shouldPassInvalidLockSound = mFuzzedDataProvider->ConsumeBool();
    android::CameraService::sound_kind playSound, lockSound;
    if (shouldPassInvalidPlaySound) {
        playSound = static_cast<android::CameraService::sound_kind>(
            mFuzzedDataProvider->ConsumeIntegral<size_t>());
    } else {
        playSound =
            kSoundKind[mFuzzedDataProvider->ConsumeIntegralInRange<size_t>(0, kNumSoundKind - 1)];
    }

    if (shouldPassInvalidLockSound) {
        lockSound = static_cast<android::CameraService::sound_kind>(
            mFuzzedDataProvider->ConsumeIntegral<size_t>());
    } else {
        lockSound =
            kSoundKind[mFuzzedDataProvider->ConsumeIntegralInRange<size_t>(0, kNumSoundKind - 1)];
    }
    mCameraService->playSound(playSound);
    mCameraService->loadSoundLocked(lockSound);
}

void CameraFuzzer::invokeDump() {
    Vector<String16> args;
    size_t numberOfLines = mFuzzedDataProvider->ConsumeIntegralInRange<size_t>(0, kMaxNumLines);
    for (size_t lineIdx = 0; lineIdx < numberOfLines; ++lineIdx) {
        args.add(static_cast<String16>(mFuzzedDataProvider->ConsumeRandomLengthString().c_str()));
    }
    const char *fileName = "logDumpFile";
    int fd = memfd_create(fileName, MFD_ALLOW_SEALING);
    mCameraService->dump(fd, args);
    close(fd);
}

void CameraFuzzer::invokeShellCommand() {
    int in = mFuzzedDataProvider->ConsumeIntegral<int>();
    int out = mFuzzedDataProvider->ConsumeIntegral<int>();
    int err = mFuzzedDataProvider->ConsumeIntegral<int>();
    Vector<String16> args;
    size_t numArgs = mFuzzedDataProvider->ConsumeIntegralInRange<size_t>(kMinArgs, kMaxArgs);
    for (size_t argsIdx = 0; argsIdx < numArgs; ++argsIdx) {
        bool shouldPassInvalidCommand = mFuzzedDataProvider->ConsumeBool();
        if (shouldPassInvalidCommand) {
            args.add(
                static_cast<String16>(mFuzzedDataProvider->ConsumeRandomLengthString().c_str()));
        } else {
            args.add(kShellCmd[mFuzzedDataProvider->ConsumeIntegralInRange<size_t>(
                0, kNumShellCmd - 1)]);
        }
    }
    mCameraService->shellCommand(in, out, err, args);
}

void CameraFuzzer::invokeNotifyCalls() {
    mCameraService->notifyMonitoredUids();
    int64_t newState = mFuzzedDataProvider->ConsumeIntegral<int64_t>();
    mCameraService->notifyDeviceStateChange(newState);
    std::vector<int32_t> args;
    size_t numArgs = mFuzzedDataProvider->ConsumeIntegralInRange<size_t>(kMinArgs, kMaxArgs);
    for (size_t argsIdx = 0; argsIdx < numArgs; ++argsIdx) {
        args.push_back(mFuzzedDataProvider->ConsumeIntegral<int32_t>());
    }
    bool shouldPassInvalidEvent = mFuzzedDataProvider->ConsumeBool();
    int32_t eventId;
    if (shouldPassInvalidEvent) {
        eventId = mFuzzedDataProvider->ConsumeIntegral<int32_t>();
    } else {
        eventId = kEventId[mFuzzedDataProvider->ConsumeBool()];
    }
    mCameraService->notifySystemEvent(eventId, args);
}

void CameraFuzzer::invokeTorchAPIs(int32_t cameraId) {
    std::string cameraIdStr = std::to_string(cameraId);
    sp<IBinder> binder = new BBinder;

    mCameraService->setTorchMode(cameraIdStr, true, binder);
    ALOGV("Turned torch on.");
    int32_t torchStrength = rand() % 5 + 1;
    ALOGV("Changing torch strength level to %d", torchStrength);
    mCameraService->turnOnTorchWithStrengthLevel(cameraIdStr, torchStrength, binder);
    mCameraService->setTorchMode(cameraIdStr, false, binder);
    ALOGV("Turned torch off.");
}

void CameraFuzzer::invokeCameraAPIs() {
    /** In order to avoid the timeout issue caused due to multiple iteration of loops, the 'for'
     * loops are removed and the 'cameraId', 'pictureSize' and 'videoSize' are derived using the
     * FuzzedDataProvider from the available cameras and vectors of 'pictureSizes' and 'videoSizes'
     */
    int32_t cameraId = mFuzzedDataProvider->ConsumeIntegralInRange<int32_t>(0, mNumCameras - 1);
    getCameraInformation(cameraId);
    invokeTorchAPIs(cameraId);

    ::android::binder::Status rc;
    sp<ICamera> cameraDevice;

    rc = mCameraService->connect(this, cameraId, std::string(),
                                 android::CameraService::USE_CALLING_UID,
                                 android::CameraService::USE_CALLING_PID,
                                 /*targetSdkVersion*/ __ANDROID_API_FUTURE__,
                                 /*overrideToPortrait*/true, /*forceSlowJpegMode*/false,
                                 &cameraDevice);
    if (!rc.isOk()) {
        // camera not connected
        return;
    }
    if (cameraDevice) {
        sp<Surface> previewSurface;
        sp<SurfaceControl> surfaceControl;
        CameraParameters params(cameraDevice->getParameters());
        String8 focusModes(params.get(CameraParameters::KEY_SUPPORTED_FOCUS_MODES));
        bool isAFSupported = false;
        const char* focusMode = nullptr;

        if (focusModes.contains(CameraParameters::FOCUS_MODE_AUTO)) {
            isAFSupported = true;
        } else if (focusModes.contains(CameraParameters::FOCUS_MODE_CONTINUOUS_PICTURE)) {
            isAFSupported = true;
            focusMode = CameraParameters::FOCUS_MODE_CONTINUOUS_PICTURE;
        } else if (focusModes.contains(CameraParameters::FOCUS_MODE_CONTINUOUS_VIDEO)) {
            isAFSupported = true;
            focusMode = CameraParameters::FOCUS_MODE_CONTINUOUS_VIDEO;
        } else if (focusModes.contains(CameraParameters::FOCUS_MODE_MACRO)) {
            isAFSupported = true;
            focusMode = CameraParameters::FOCUS_MODE_MACRO;
        }
        if (nullptr != focusMode) {
            params.set(CameraParameters::KEY_FOCUS_MODE, focusMode);
            cameraDevice->setParameters(params.flatten());
        }
        int previewWidth, previewHeight;
        params.getPreviewSize(&previewWidth, &previewHeight);

        mComposerClient = new SurfaceComposerClient;
        mComposerClient->initCheck();

        bool shouldPassInvalidLayerMetaData = mFuzzedDataProvider->ConsumeBool();
        int layerMetaData;
        if (shouldPassInvalidLayerMetaData) {
            layerMetaData = mFuzzedDataProvider->ConsumeIntegral<int>();
        } else {
            layerMetaData = kLayerMetadata[mFuzzedDataProvider->ConsumeIntegralInRange<size_t>(
                    0, kNumLayerMetaData - 1)];
        }
        surfaceControl = mComposerClient->createSurface(
                String8("Test Surface"), previewWidth, previewHeight,
                CameraParameters::previewFormatToEnum(params.getPreviewFormat()), layerMetaData);

        if (surfaceControl.get()) {
            SurfaceComposerClient::Transaction{}
                    .setLayer(surfaceControl, 0x7fffffff)
                    .show(surfaceControl)
                    .apply();

            previewSurface = surfaceControl->getSurface();
            if (previewSurface.get()) {
                cameraDevice->setPreviewTarget(previewSurface->getIGraphicBufferProducer());
            }
        }
        cameraDevice->setPreviewCallbackFlag(CAMERA_FRAME_CALLBACK_FLAG_CAMCORDER);

        Vector<Size> pictureSizes;
        params.getSupportedPictureSizes(pictureSizes);

        if (pictureSizes.size()) {
            Size pictureSize = pictureSizes[mFuzzedDataProvider->ConsumeIntegralInRange<size_t>(
                    0, pictureSizes.size() - 1)];
            params.setPictureSize(pictureSize.width, pictureSize.height);
            cameraDevice->setParameters(params.flatten());
            cameraDevice->startPreview();
            waitForPreviewStart();
            cameraDevice->autoFocus();
            waitForEvent(mAutoFocusLock, mAutoFocusCondition, mAutoFocusMessage);
            bool shouldPassInvalidCameraMsg = mFuzzedDataProvider->ConsumeBool();
            int msgType;
            if (shouldPassInvalidCameraMsg) {
                msgType = mFuzzedDataProvider->ConsumeIntegral<int>();
            } else {
                msgType = kCameraMsg[mFuzzedDataProvider->ConsumeIntegralInRange<size_t>(
                        0, kNumCameraMsg - 1)];
            }
            cameraDevice->takePicture(msgType);

            waitForEvent(mSnapshotLock, mSnapshotCondition, mSnapshotNotification);
            cameraDevice->stopPreview();
        }

        Vector<Size> videoSizes;
        params.getSupportedVideoSizes(videoSizes);

        if (videoSizes.size()) {
            Size videoSize = videoSizes[mFuzzedDataProvider->ConsumeIntegralInRange<size_t>(
                    0, videoSizes.size() - 1)];
            params.setVideoSize(videoSize.width, videoSize.height);

            cameraDevice->setParameters(params.flatten());
            cameraDevice->startPreview();
            waitForPreviewStart();
            cameraDevice->setVideoBufferMode(
                    android::hardware::BnCamera::VIDEO_BUFFER_MODE_BUFFER_QUEUE);
            sp<SurfaceControl> surfaceControlVideo = mComposerClient->createSurface(
                    String8("Test Surface Video"), previewWidth, previewHeight,
                    CameraParameters::previewFormatToEnum(params.getPreviewFormat()),
                    layerMetaData);
            if (surfaceControlVideo.get()) {
                SurfaceComposerClient::Transaction{}
                        .setLayer(surfaceControlVideo, 0x7fffffff)
                        .show(surfaceControlVideo)
                        .apply();
                sp<Surface> previewSurfaceVideo = surfaceControlVideo->getSurface();
                if (previewSurfaceVideo.get()) {
                    cameraDevice->setVideoTarget(previewSurfaceVideo->getIGraphicBufferProducer());
                }
            }
            cameraDevice->stopPreview();
            cameraDevice->startRecording();
            waitForEvent(mRecordingLock, mRecordingCondition, mRecordingNotification);
            cameraDevice->stopRecording();
        }
        cameraDevice->disconnect();
    }
}

void CameraFuzzer::process() {
    getNumCameras();
    invokeCameraSound();
    if (mNumCameras > 0) {
        invokeCameraAPIs();
    }
    invokeDump();
    invokeShellCommand();
    invokeNotifyCalls();
}

class TestCameraServiceListener : public hardware::BnCameraServiceListener {
public:
    virtual ~TestCameraServiceListener() {};

    virtual binder::Status onStatusChanged(int32_t, const std::string&) {
        return binder::Status::ok();
    };

    virtual binder::Status onPhysicalCameraStatusChanged(int32_t /*status*/,
            const std::string& /*cameraId*/, const std::string& /*physicalCameraId*/) {
        // No op
        return binder::Status::ok();
    };

    virtual binder::Status onTorchStatusChanged(int32_t /*status*/,
            const std::string& /*cameraId*/) {
        return binder::Status::ok();
    };

    virtual binder::Status onCameraAccessPrioritiesChanged() {
        // No op
        return binder::Status::ok();
    }

    virtual binder::Status onCameraOpened(const std::string& /*cameraId*/,
            const std::string& /*clientPackageName*/) {
        // No op
        return binder::Status::ok();
    }

    virtual binder::Status onCameraClosed(const std::string& /*cameraId*/) {
        // No op
        return binder::Status::ok();
    }

    virtual binder::Status onTorchStrengthLevelChanged(const std::string& /*cameraId*/,
            int32_t /*torchStrength*/) {
        // No op
        return binder::Status::ok();
    }
};

class TestCameraDeviceCallbacks : public hardware::camera2::BnCameraDeviceCallbacks {
public:
    TestCameraDeviceCallbacks() {}

    virtual ~TestCameraDeviceCallbacks() {}

    virtual binder::Status onDeviceError(int /*errorCode*/,
            const CaptureResultExtras& /*resultExtras*/) {
        return binder::Status::ok();
    }

    virtual binder::Status onDeviceIdle() {
        return binder::Status::ok();
    }

    virtual binder::Status onCaptureStarted(const CaptureResultExtras& /*resultExtras*/,
            int64_t /*timestamp*/) {
        return binder::Status::ok();
    }

    virtual binder::Status onResultReceived(const CameraMetadata& /*metadata*/,
            const CaptureResultExtras& /*resultExtras*/,
            const std::vector<PhysicalCaptureResultInfo>& /*physicalResultInfos*/) {
        return binder::Status::ok();
    }

    virtual binder::Status onPrepared(int /*streamId*/) {
        return binder::Status::ok();
    }

    virtual binder::Status onRepeatingRequestError(
            int64_t /*lastFrameNumber*/, int32_t /*stoppedSequenceId*/) {
        return binder::Status::ok();
    }

    virtual binder::Status onRequestQueueEmpty() {
        return binder::Status::ok();
    }
};

class Camera2Fuzzer {
   public:
    Camera2Fuzzer(sp<CameraService> cs, std::shared_ptr<FuzzedDataProvider> fp) :
          mCameraService(cs), mFuzzedDataProvider(fp) { };
    ~Camera2Fuzzer() {}
    void process();
   private:
    sp<CameraService> mCameraService = nullptr;
    std::shared_ptr<FuzzedDataProvider> mFuzzedDataProvider = nullptr;
};

void Camera2Fuzzer::process() {
    sp<TestCameraServiceListener> listener = new TestCameraServiceListener();
    std::vector<hardware::CameraStatus> statuses;
    mCameraService->addListenerTest(listener, &statuses);
    for (auto s : statuses) {
        sp<TestCameraDeviceCallbacks> callbacks(new TestCameraDeviceCallbacks());
        sp<hardware::camera2::ICameraDeviceUser> device;
        mCameraService->connectDevice(callbacks, s.cameraId, std::string(), {},
                android::CameraService::USE_CALLING_UID, 0/*oomScoreDiff*/,
                /*targetSdkVersion*/__ANDROID_API_FUTURE__, /*overrideToPortrait*/true,
                &device);
        if (device == nullptr) {
            continue;
        }
        device->beginConfigure();
        sp<IGraphicBufferProducer> gbProducer;
        sp<IGraphicBufferConsumer> gbConsumer;
        BufferQueue::createBufferQueue(&gbProducer, &gbConsumer);
        sp<BufferItemConsumer> opaqueConsumer = new BufferItemConsumer(gbConsumer,
                GRALLOC_USAGE_SW_READ_NEVER, /*maxImages*/8, /*controlledByApp*/true);
        opaqueConsumer->setName(String8("Roger"));

        // Set to VGA dimension for default, as that is guaranteed to be present
        gbConsumer->setDefaultBufferSize(640, 480);
        gbConsumer->setDefaultBufferFormat(HAL_PIXEL_FORMAT_IMPLEMENTATION_DEFINED);

        sp<Surface> surface(new Surface(gbProducer, /*controlledByApp*/false));

        std::string noPhysicalId;
        size_t rotations = sizeof(kRotations) / sizeof(int32_t) - 1;
        OutputConfiguration output(gbProducer,
                kRotations[mFuzzedDataProvider->ConsumeIntegralInRange<size_t>(0, rotations)],
                noPhysicalId);
        int streamId;
        device->createStream(output, &streamId);
        CameraMetadata sessionParams;
        std::vector<int> offlineStreamIds;
        device->endConfigure(/*isConstrainedHighSpeed*/ mFuzzedDataProvider->ConsumeBool(),
                sessionParams, ns2ms(systemTime()), &offlineStreamIds);

        CameraMetadata requestTemplate;
        size_t requestTemplatesSize =  sizeof(kRequestTemplates) /sizeof(int32_t)  - 1;
        device->createDefaultRequest(kRequestTemplates[
                mFuzzedDataProvider->ConsumeIntegralInRange<size_t>(0, requestTemplatesSize)],
                /*out*/&requestTemplate);
        hardware::camera2::CaptureRequest request;
        request.mSurfaceList.add(surface);
        request.mIsReprocess = false;
        hardware::camera2::utils::SubmitInfo info;
        for (int i = 0; i < kNumRequestsTested; i++) {
            uint8_t sensorPixelMode =
                    kSensorPixelModes[mFuzzedDataProvider->ConsumeBool() ? 1 : 0];
            requestTemplate.update(ANDROID_SENSOR_PIXEL_MODE, &sensorPixelMode, 1);
            request.mPhysicalCameraSettings.clear();
            request.mPhysicalCameraSettings.push_back({s.cameraId, requestTemplate});
            device->submitRequest(request, /*streaming*/false, /*out*/&info);
            ALOGV("%s : camera id %s submit request id %d",__FUNCTION__, s.cameraId.c_str(),
                    info.mRequestId);
        }
        device->disconnect();
    }
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 1) {
        return 0;
    }
    setuid(AID_CAMERASERVER);
    std::shared_ptr<FuzzedDataProvider> fp = std::make_shared<FuzzedDataProvider>(data, size);

    std::call_once(gSmOnce, [&] {
        /* Create a FakeServiceManager instance and add required services */
        gFakeServiceManager = sp<FakeServiceManager>::make();
        setDefaultServiceManager(gFakeServiceManager);
    });
    gFakeServiceManager->clear();

    for (const char* service :
         {"sensor_privacy", "permission", "media.camera.proxy", "batterystats", "media.metrics",
          "media.extractor", "drm.drmManager", "permission_checker"}) {
        addService(String16(service), gFakeServiceManager, fp.get());
    }

    const auto audioFlinger = sp<AudioFlinger>::make();
    const auto afAdapter = sp<AudioFlingerServerAdapter>::make(audioFlinger);

    CHECK_EQ(NO_ERROR,
             gFakeServiceManager->addService(
                     String16(IAudioFlinger::DEFAULT_SERVICE_NAME), IInterface::asBinder(afAdapter),
                     false /* allowIsolated */, IServiceManager::DUMP_FLAG_PRIORITY_DEFAULT));

    sp<FuzzerActivityManager> am = new FuzzerActivityManager();
    CHECK_EQ(NO_ERROR,
             gFakeServiceManager->addService(String16("activity"), IInterface::asBinder(am)));

    sp<FuzzerSensorPrivacyManager> sensorPrivacyManager = new FuzzerSensorPrivacyManager();
    CHECK_EQ(NO_ERROR, gFakeServiceManager->addService(String16("sensor_privacy"),
                                                       IInterface::asBinder(sensorPrivacyManager)));

    sp<FuzzAppOpsService> appops = new FuzzAppOpsService();
    CHECK_EQ(NO_ERROR,
             gFakeServiceManager->addService(String16("appops"), IInterface::asBinder(appops)));

    MediaPlayerService::instantiate();

    sp<CameraService> cs = new CameraService();
    cs->clearCachedVariables();
    sp<CameraFuzzer> camerafuzzer = new CameraFuzzer(cs, fp);
    if (!camerafuzzer) {
        return 0;
    }
    camerafuzzer->process();
    Camera2Fuzzer camera2fuzzer(cs, fp);
    camera2fuzzer.process();
    return 0;
}
