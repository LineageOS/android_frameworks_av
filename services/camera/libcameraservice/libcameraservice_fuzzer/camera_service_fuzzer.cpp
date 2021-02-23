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

#include <CameraService.h>
#include <android/hardware/ICameraServiceListener.h>
#include <gui/Surface.h>
#include <gui/SurfaceComposerClient.h>
#include <private/android_filesystem_config.h>
#include "fuzzer/FuzzedDataProvider.h"

using namespace android;
using namespace hardware;
using namespace std;

const int32_t kPreviewThreshold = 8;
const nsecs_t kPreviewTimeout = 5000000000;  // .5 [s.]
const nsecs_t kEventTimeout = 10000000000;   // 1 [s.]
const size_t kMaxNumLines = USHRT_MAX;
const size_t kMinArgs = 1;
const size_t kMaxArgs = 5;
const int32_t kCamType[] = {hardware::ICameraService::CAMERA_TYPE_BACKWARD_COMPATIBLE,
                            hardware::ICameraService::CAMERA_TYPE_ALL};
const int kCameraApiVersion[] = {android::CameraService::API_VERSION_1,
                                 android::CameraService::API_VERSION_2};
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

class CameraFuzzer : public ::android::hardware::BnCameraClient {
   public:
    CameraFuzzer() = default;
    ~CameraFuzzer() { deInit(); }
    bool init();
    void process(const uint8_t *data, size_t size);
    void deInit();

   private:
    FuzzedDataProvider *mFuzzedDataProvider = nullptr;
    sp<CameraService> mCameraService = nullptr;
    sp<SurfaceComposerClient> mComposerClient = nullptr;
    int32_t mNumCameras = 0;
    size_t mPreviewBufferCount = 0;
    bool mAutoFocusMessage = false;
    bool mSnapshotNotification = false;
    mutable Mutex mPreviewLock;
    mutable Condition mPreviewCondition;
    mutable Mutex mAutoFocusLock;
    mutable Condition mAutoFocusCondition;
    mutable Mutex mSnapshotLock;
    mutable Condition mSnapshotCondition;

    void getNumCameras();
    void getCameraInformation(int32_t cameraId);
    void invokeCameraAPIs();
    void invokeCameraSound();
    void invokeDump();
    void invokeShellCommand();
    void invokeNotifyCalls();

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

bool CameraFuzzer::init() {
    setuid(AID_MEDIA);
    mCameraService = new CameraService();
    if (mCameraService) {
        return true;
    }
    return false;
}

void CameraFuzzer::deInit() {
    if (mCameraService) {
        mCameraService = nullptr;
    }
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
    String16 cameraIdStr = String16(String8::format("%d", cameraId));
    bool isSupported = false;
    mCameraService->supportsCameraApi(
        cameraIdStr, kCameraApiVersion[mFuzzedDataProvider->ConsumeBool()], &isSupported);
    mCameraService->isHiddenPhysicalCamera(cameraIdStr, &isSupported);

    String16 parameters;
    mCameraService->getLegacyParameters(cameraId, &parameters);

    std::vector<hardware::camera2::utils::ConcurrentCameraIdCombination> concurrentCameraIds;
    mCameraService->getConcurrentCameraIds(&concurrentCameraIds);

    hardware::camera2::params::VendorTagDescriptorCache cache;
    mCameraService->getCameraVendorTagCache(&cache);

    CameraInfo cameraInfo;
    mCameraService->getCameraInfo(cameraId, &cameraInfo);

    CameraMetadata metadata;
    mCameraService->getCameraCharacteristics(cameraIdStr, &metadata);
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

void CameraFuzzer::invokeCameraAPIs() {
    for (int32_t cameraId = 0; cameraId < mNumCameras; ++cameraId) {
        getCameraInformation(cameraId);

        const String16 opPackageName("com.fuzzer.poc");
        ::android::binder::Status rc;
        sp<ICamera> cameraDevice;

        rc = mCameraService->connect(this, cameraId, opPackageName, AID_MEDIA, AID_ROOT,
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
            const char *focusMode = nullptr;

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

            if (surfaceControl.get() != nullptr) {
                SurfaceComposerClient::Transaction{}
                    .setLayer(surfaceControl, 0x7fffffff)
                    .show(surfaceControl)
                    .apply();

                previewSurface = surfaceControl->getSurface();
                cameraDevice->setPreviewTarget(previewSurface->getIGraphicBufferProducer());
            }
            cameraDevice->setPreviewCallbackFlag(CAMERA_FRAME_CALLBACK_FLAG_CAMCORDER);

            Vector<Size> pictureSizes;
            params.getSupportedPictureSizes(pictureSizes);

            for (size_t i = 0; i < pictureSizes.size(); ++i) {
                params.setPictureSize(pictureSizes[i].width, pictureSizes[i].height);
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
            }

            Vector<Size> videoSizes;
            params.getSupportedVideoSizes(videoSizes);

            for (size_t i = 0; i < videoSizes.size(); ++i) {
                params.setVideoSize(videoSizes[i].width, videoSizes[i].height);

                cameraDevice->setParameters(params.flatten());
                cameraDevice->startPreview();
                waitForPreviewStart();
                cameraDevice->setVideoBufferMode(
                    android::hardware::BnCamera::VIDEO_BUFFER_MODE_BUFFER_QUEUE);
                cameraDevice->setVideoTarget(previewSurface->getIGraphicBufferProducer());
                cameraDevice->startRecording();
                cameraDevice->stopRecording();
            }
            cameraDevice->stopPreview();
            cameraDevice->disconnect();
        }
    }
}

void CameraFuzzer::process(const uint8_t *data, size_t size) {
    mFuzzedDataProvider = new FuzzedDataProvider(data, size);
    getNumCameras();
    invokeCameraSound();
    if (mNumCameras > 0) {
        invokeCameraAPIs();
    }
    invokeDump();
    invokeShellCommand();
    invokeNotifyCalls();
    delete mFuzzedDataProvider;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 1) {
        return 0;
    }
    sp<CameraFuzzer> camerafuzzer = new CameraFuzzer();
    if (!camerafuzzer) {
        return 0;
    }
    if (camerafuzzer->init()) {
        camerafuzzer->process(data, size);
    }
    return 0;
}
