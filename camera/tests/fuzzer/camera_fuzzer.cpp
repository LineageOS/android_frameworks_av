/*
 * Copyright (C) 2022 The Android Open Source Project
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

#include <Camera.h>
#include <CameraParameters.h>
#include <binder/MemoryDealer.h>
#include <fuzzer/FuzzedDataProvider.h>
#include <gui/Surface.h>
#include <gui/SurfaceComposerClient.h>
#include "camera2common.h"

using namespace std;
using namespace android;
using namespace android::hardware;

constexpr int32_t kFrameRateMin = 1;
constexpr int32_t kFrameRateMax = 1000;
constexpr int32_t kNumMin = 0;
constexpr int32_t kNumMax = 1024;
constexpr int32_t kMemoryDealerSize = 1000;
constexpr int8_t kMinElements = 1;
constexpr int8_t kMaxElements = 10;

constexpr int32_t kValidCMD[] = {CAMERA_CMD_START_SMOOTH_ZOOM,
                                 CAMERA_CMD_STOP_SMOOTH_ZOOM,
                                 CAMERA_CMD_SET_DISPLAY_ORIENTATION,
                                 CAMERA_CMD_ENABLE_SHUTTER_SOUND,
                                 CAMERA_CMD_PLAY_RECORDING_SOUND,
                                 CAMERA_CMD_START_FACE_DETECTION,
                                 CAMERA_CMD_STOP_FACE_DETECTION,
                                 CAMERA_CMD_ENABLE_FOCUS_MOVE_MSG,
                                 CAMERA_CMD_PING,
                                 CAMERA_CMD_SET_VIDEO_BUFFER_COUNT,
                                 CAMERA_CMD_SET_VIDEO_FORMAT};

constexpr int32_t kValidVideoBufferMode[] = {ICamera::VIDEO_BUFFER_MODE_DATA_CALLBACK_YUV,
                                             ICamera::VIDEO_BUFFER_MODE_DATA_CALLBACK_METADATA,
                                             ICamera::VIDEO_BUFFER_MODE_BUFFER_QUEUE};

constexpr int32_t kValidPreviewCallbackFlag[] = {
        CAMERA_FRAME_CALLBACK_FLAG_ENABLE_MASK,    CAMERA_FRAME_CALLBACK_FLAG_ONE_SHOT_MASK,
        CAMERA_FRAME_CALLBACK_FLAG_COPY_OUT_MASK,  CAMERA_FRAME_CALLBACK_FLAG_NOOP,
        CAMERA_FRAME_CALLBACK_FLAG_CAMCORDER,      CAMERA_FRAME_CALLBACK_FLAG_CAMERA,
        CAMERA_FRAME_CALLBACK_FLAG_BARCODE_SCANNER};

class TestCameraListener : public CameraListener {
  public:
    virtual ~TestCameraListener() = default;

    void notify(int32_t /*msgType*/, int32_t /*ext1*/, int32_t /*ext2*/) override { return; };
    void postData(int32_t /*msgType*/, const sp<IMemory>& /*dataPtr*/,
                  camera_frame_metadata_t* /*metadata*/) override {
        return;
    };
    void postDataTimestamp(nsecs_t /*timestamp*/, int32_t /*msgType*/,
                           const sp<IMemory>& /*dataPtr*/) override {
        return;
    };
    void postRecordingFrameHandleTimestamp(nsecs_t /*timestamp*/,
                                           native_handle_t* /*handle*/) override {
        return;
    };
    void postRecordingFrameHandleTimestampBatch(
            const std::vector<nsecs_t>& /*timestamps*/,
            const std::vector<native_handle_t*>& /*handles*/) override {
        return;
    };
};

class CameraFuzzer : public ::android::hardware::BnCameraClient {
  public:
    void process(const uint8_t* data, size_t size);

  private:
    bool initCamera();
    void invokeCamera();
    void invokeSetParameters();
    native_handle_t* createNativeHandle();
    sp<Camera> mCamera = nullptr;
    FuzzedDataProvider* mFDP = nullptr;

    // CameraClient interface
    void notifyCallback(int32_t, int32_t, int32_t) override { return; };
    void dataCallback(int32_t, const sp<IMemory>&, camera_frame_metadata_t*) override { return; };
    void dataCallbackTimestamp(nsecs_t, int32_t, const sp<IMemory>&) override { return; };
    void recordingFrameHandleCallbackTimestamp(nsecs_t, native_handle_t*) override { return; };
    void recordingFrameHandleCallbackTimestampBatch(const std::vector<nsecs_t>&,
                                                    const std::vector<native_handle_t*>&) override {
        return;
    };
};

native_handle_t* CameraFuzzer::createNativeHandle() {
    int32_t numFds = mFDP->ConsumeIntegralInRange<int32_t>(kMinElements, kMaxElements);
    int32_t numInts = mFDP->ConsumeIntegralInRange<int32_t>(kNumMin, kNumMax);
    native_handle_t* handle = native_handle_create(numFds, numInts);
    for (int32_t i = 0; i < numFds; ++i) {
        std::string filename = mFDP->ConsumeRandomLengthString(kMaxBytes);
        int32_t fd = open(filename.c_str(), O_RDWR | O_CREAT | O_TRUNC);
        handle->data[i] = fd;
    }
    return handle;
}

bool CameraFuzzer::initCamera() {
    ProcessState::self()->startThreadPool();
    sp<IServiceManager> sm = defaultServiceManager();
    sp<IBinder> binder = sm->getService(String16("media.camera"));
    sp<ICameraService> cameraService = nullptr;
    cameraService = interface_cast<ICameraService>(binder);
    sp<ICamera> cameraDevice = nullptr;
    if (mFDP->ConsumeBool()) {
        cameraService->connect(this, mFDP->ConsumeIntegral<int32_t>() /* cameraId */, "CAMERAFUZZ",
                               hardware::ICameraService::USE_CALLING_UID,
                               hardware::ICameraService::USE_CALLING_PID,
                               /*targetSdkVersion*/ __ANDROID_API_FUTURE__,
                               /*overrideToPortrait*/ false, /*forceSlowJpegMode*/ false,
                               &cameraDevice);
    } else {
        cameraService->connect(this, mFDP->ConsumeIntegral<int32_t>() /* cameraId */,
                               mFDP->ConsumeRandomLengthString(kMaxBytes).c_str(),
                               mFDP->ConsumeIntegral<int8_t>() /* clientUid */,
                               mFDP->ConsumeIntegral<int8_t>() /* clientPid */,
                               /*targetSdkVersion*/ mFDP->ConsumeIntegral<int32_t>(),
                               /*overrideToPortrait*/ mFDP->ConsumeBool(),
                               /*forceSlowJpegMode*/ mFDP->ConsumeBool(), &cameraDevice);
    }

    mCamera = Camera::create(cameraDevice);
    if (!mCamera) {
        return false;
    }
    return true;
}

void CameraFuzzer::invokeSetParameters() {
    String8 s = mCamera->getParameters();
    CameraParameters params(s);
    int32_t width = mFDP->ConsumeIntegral<int32_t>();
    int32_t height = mFDP->ConsumeIntegral<int32_t>();
    params.setVideoSize(width, height);
    int32_t frameRate = mFDP->ConsumeIntegralInRange<int32_t>(kFrameRateMin, kFrameRateMax);
    params.setPreviewFrameRate(frameRate);
    mCamera->setParameters(params.flatten());
}

void CameraFuzzer::invokeCamera() {
    if (!initCamera()) {
        return;
    }

    int32_t cameraId = mFDP->ConsumeIntegral<int32_t>();
    Camera::getNumberOfCameras();
    CameraInfo cameraInfo;
    cameraInfo.facing = mFDP->ConsumeBool() ? mFDP->PickValueInArray(kValidFacing)
                                            : mFDP->ConsumeIntegral<int32_t>();
    cameraInfo.orientation = mFDP->ConsumeBool() ? mFDP->PickValueInArray(kValidOrientation)
                                                 : mFDP->ConsumeIntegral<int32_t>();
    Camera::getCameraInfo(cameraId, /*overrideToPortrait*/false, &cameraInfo);
    mCamera->reconnect();

    sp<SurfaceComposerClient> composerClient = new SurfaceComposerClient;
    sp<SurfaceControl> surfaceControl = nullptr;
    if (mFDP->ConsumeBool()) {
        surfaceControl = composerClient->createSurface(String8("FUZZSURFACE"), 1280, 800,
                                                       HAL_PIXEL_FORMAT_YV12);
    } else {
        surfaceControl = composerClient->createSurface(
                static_cast<String8>(mFDP->ConsumeRandomLengthString(kMaxBytes).c_str()) /* name */,
                mFDP->ConsumeIntegral<uint32_t>() /* width */,
                mFDP->ConsumeIntegral<uint32_t>() /* height */,
                mFDP->ConsumeIntegral<int32_t>() /* format */,
                mFDP->ConsumeIntegral<int32_t>() /* flags */);
    }

    if (mFDP->ConsumeBool()) {
        invokeSetParameters();
    }
    sp<Surface> surface = nullptr;
    if (surfaceControl) {
        surface = surfaceControl->getSurface();
    }
    sp<MemoryDealer> memoryDealer = nullptr;
    sp<IMemory> iMem = nullptr;
    sp<CameraListener> cameraListener = nullptr;

    while (mFDP->remaining_bytes()) {
        auto callCameraAPIs = mFDP->PickValueInArray<const std::function<void()>>({
                [&]() {
                    if (surfaceControl) {
                        mCamera->setPreviewTarget(surface->getIGraphicBufferProducer());
                    }
                },
                [&]() {
                    if (surfaceControl) {
                        mCamera->startPreview();
                    }
                },
                [&]() {
                    if (surfaceControl) {
                        mCamera->stopPreview();
                    }
                },
                [&]() {
                    if (surfaceControl) {
                        mCamera->stopPreview();
                    }
                },
                [&]() {
                    if (surfaceControl) {
                        mCamera->previewEnabled();
                    }
                },
                [&]() {
                    if (surfaceControl) {
                        mCamera->startRecording();
                    }
                },
                [&]() {
                    if (surfaceControl) {
                        mCamera->stopRecording();
                    }
                },
                [&]() { mCamera->lock(); },
                [&]() { mCamera->unlock(); },
                [&]() { mCamera->autoFocus(); },
                [&]() { mCamera->cancelAutoFocus(); },
                [&]() {
                    int32_t msgType = mFDP->ConsumeIntegral<int32_t>();
                    mCamera->takePicture(msgType);
                },
                [&]() {
                    int32_t cmd;
                    cmd = mFDP->ConsumeBool() ? mFDP->PickValueInArray(kValidCMD)
                                              : mFDP->ConsumeIntegral<int32_t>();
                    int32_t arg1 = mFDP->ConsumeIntegral<int32_t>();
                    int32_t arg2 = mFDP->ConsumeIntegral<int32_t>();
                    mCamera->sendCommand(cmd, arg1, arg2);
                },
                [&]() {
                    int32_t videoBufferMode =
                            mFDP->ConsumeBool() ? mFDP->PickValueInArray(kValidVideoBufferMode)
                                                : mFDP->ConsumeIntegral<int32_t>();
                    mCamera->setVideoBufferMode(videoBufferMode);
                },
                [&]() {
                    if (surfaceControl) {
                        mCamera->setVideoTarget(surface->getIGraphicBufferProducer());
                    }
                },
                [&]() {
                    cameraListener = sp<TestCameraListener>::make();
                    mCamera->setListener(cameraListener);
                },
                [&]() {
                    int32_t previewCallbackFlag;
                    previewCallbackFlag =
                            mFDP->ConsumeBool() ? mFDP->PickValueInArray(kValidPreviewCallbackFlag)
                                                : mFDP->ConsumeIntegral<int32_t>();
                    mCamera->setPreviewCallbackFlags(previewCallbackFlag);
                },
                [&]() {
                    if (surfaceControl) {
                        mCamera->setPreviewCallbackTarget(surface->getIGraphicBufferProducer());
                    }
                },
                [&]() { mCamera->getRecordingProxy(); },
                [&]() {
                    int32_t mode = mFDP->ConsumeIntegral<int32_t>();
                    mCamera->setAudioRestriction(mode);
                },
                [&]() { mCamera->getGlobalAudioRestriction(); },
                [&]() { mCamera->recordingEnabled(); },
                [&]() {
                    memoryDealer = new MemoryDealer(kMemoryDealerSize);
                    iMem = memoryDealer->allocate(kMemoryDealerSize);
                },
                [&]() {
                    int32_t msgTypeNC = mFDP->ConsumeIntegral<int32_t>();
                    int32_t ext = mFDP->ConsumeIntegral<int32_t>();
                    int32_t ext2 = mFDP->ConsumeIntegral<int32_t>();
                    mCamera->notifyCallback(msgTypeNC, ext, ext2);
                },
                [&]() {
                    int32_t msgTypeNC = mFDP->ConsumeIntegral<int32_t>();
                    int64_t timestamp = mFDP->ConsumeIntegral<int64_t>();
                    mCamera->dataCallbackTimestamp(timestamp, msgTypeNC, iMem);
                },
                [&]() {
                    int64_t timestamp = mFDP->ConsumeIntegral<int64_t>();
                    native_handle_t* handle = createNativeHandle();
                    mCamera->recordingFrameHandleCallbackTimestamp(timestamp, handle);
                },
                [&]() {
                    native_handle_t* handle = createNativeHandle();
                    mCamera->releaseRecordingFrameHandle(handle);
                },
                [&]() { mCamera->releaseRecordingFrame(iMem); },
                [&]() {
                    std::vector<native_handle_t*> handles;
                    for (int8_t i = 0;
                         i < mFDP->ConsumeIntegralInRange<int8_t>(kMinElements, kMaxElements);
                         ++i) {
                        native_handle_t* handle = createNativeHandle();
                        handles.push_back(handle);
                    }
                    mCamera->releaseRecordingFrameHandleBatch(handles);
                },
                [&]() {
                    std::vector<native_handle_t*> handles;
                    for (int8_t i = 0;
                         i < mFDP->ConsumeIntegralInRange<int8_t>(kMinElements, kMaxElements);
                         ++i) {
                        native_handle_t* handle = createNativeHandle();
                        handles.push_back(handle);
                    }
                    std::vector<nsecs_t> timestamps;
                    for (int8_t i = 0;
                         i < mFDP->ConsumeIntegralInRange<int8_t>(kMinElements, kMaxElements);
                         ++i) {
                        timestamps.push_back(mFDP->ConsumeIntegral<int64_t>());
                    }
                    mCamera->recordingFrameHandleCallbackTimestampBatch(timestamps, handles);
                },
        });
        callCameraAPIs();
    }
}

void CameraFuzzer::process(const uint8_t* data, size_t size) {
    mFDP = new FuzzedDataProvider(data, size);
    invokeCamera();
    delete mFDP;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    sp<CameraFuzzer> cameraFuzzer = new CameraFuzzer();
    cameraFuzzer->process(data, size);
    cameraFuzzer.clear();
    return 0;
}
