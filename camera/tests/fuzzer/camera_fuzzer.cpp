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
#include <CameraBase.h>
#include <CameraMetadata.h>
#include <CameraParameters.h>
#include <CameraUtils.h>
#include <VendorTagDescriptor.h>
#include <binder/IMemory.h>
#include <binder/MemoryDealer.h>
#include <fuzzer/FuzzedDataProvider.h>
#include <gui/IGraphicBufferProducer.h>
#include <gui/Surface.h>
#include <gui/SurfaceComposerClient.h>
#include <utils/Log.h>
#include "camera2common.h"
#include <android/hardware/ICameraService.h>

using namespace std;
using namespace android;
using namespace android::hardware;

constexpr int32_t kFrameRateMin = 1;
constexpr int32_t kFrameRateMax = 120;
constexpr int32_t kCamIdMin = 0;
constexpr int32_t kCamIdMax = 1;
constexpr int32_t kNumMin = 0;
constexpr int32_t kNumMax = 1024;
constexpr int32_t kMemoryDealerSize = 1000;
constexpr int32_t kRangeMin = 0;
constexpr int32_t kRangeMax = 1000;
constexpr int32_t kSizeMin = 0;
constexpr int32_t kSizeMax = 1000;

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

constexpr int32_t kValidFacing[] = {android::hardware::CAMERA_FACING_BACK,
                                    android::hardware::CAMERA_FACING_FRONT};

constexpr int32_t kValidOrientation[] = {0, 90, 180, 270};

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
    ~CameraFuzzer() {
        delete mCameraMetadata;
        mComposerClient.clear();
        mSurfaceControl.clear();
        mSurface.clear();
        mCamera.clear();
        mMemoryDealer.clear();
        mIMem.clear();
        mCameraListener.clear();
        mCameraService.clear();
    }

  private:
    bool initCamera();
    void initCameraMetadata();
    void invokeCamera();
    void invokeCameraUtils();
    void invokeCameraBase();
    void invokeCameraMetadata();
    void invokeSetParameters();
    sp<Camera> mCamera = nullptr;
    CameraMetadata* mCameraMetadata = nullptr;
    sp<SurfaceComposerClient> mComposerClient = nullptr;
    sp<SurfaceControl> mSurfaceControl = nullptr;
    sp<Surface> mSurface = nullptr;
    sp<MemoryDealer> mMemoryDealer = nullptr;
    sp<IMemory> mIMem = nullptr;
    sp<TestCameraListener> mCameraListener = nullptr;
    sp<ICameraService> mCameraService = nullptr;
    sp<ICamera> cameraDevice = nullptr;
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

bool CameraFuzzer::initCamera() {
    ProcessState::self()->startThreadPool();
    sp<IServiceManager> sm = defaultServiceManager();
    sp<IBinder> binder = sm->getService(String16("media.camera"));
    mCameraService = interface_cast<ICameraService>(binder);
    mCameraService->connect(this, mFDP->ConsumeIntegral<int32_t>() /* cameraId */,
                            "CAMERAFUZZ", hardware::ICameraService::USE_CALLING_UID,
                            hardware::ICameraService::USE_CALLING_PID,
                            /*targetSdkVersion*/ __ANDROID_API_FUTURE__,
                            /*overrideToPortrait*/false, /*forceSlowJpegMode*/false, &cameraDevice);
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

    int32_t cameraId = mFDP->ConsumeIntegralInRange<int32_t>(kCamIdMin, kCamIdMax);
    Camera::getNumberOfCameras();
    CameraInfo cameraInfo;
    cameraInfo.facing = mFDP->ConsumeBool() ? mFDP->PickValueInArray(kValidFacing)
                                            : mFDP->ConsumeIntegral<int>();
    cameraInfo.orientation = mFDP->ConsumeBool() ? mFDP->PickValueInArray(kValidOrientation)
                                                 : mFDP->ConsumeIntegral<int>();
    Camera::getCameraInfo(cameraId, /*overrideToPortrait*/false, &cameraInfo);
    mCamera->reconnect();

    mComposerClient = new SurfaceComposerClient;
    mSurfaceControl = mComposerClient->createSurface(
            static_cast<String8>(mFDP->ConsumeRandomLengthString().c_str()) /* name */,
            mFDP->ConsumeIntegral<uint32_t>() /* width */,
            mFDP->ConsumeIntegral<uint32_t>() /* height */,
            mFDP->ConsumeIntegral<int32_t>() /* format */,
            mFDP->ConsumeIntegral<int32_t>() /* flags */);
    if (mSurfaceControl) {
        mSurface = mSurfaceControl->getSurface();
        mCamera->setPreviewTarget(mSurface->getIGraphicBufferProducer());
        mCamera->startPreview();
        mCamera->stopPreview();
        mCamera->previewEnabled();
        mCamera->startRecording();
        mCamera->stopRecording();
    }

    mCamera->lock();
    mCamera->unlock();
    mCamera->autoFocus();
    mCamera->cancelAutoFocus();

    int32_t msgType = mFDP->ConsumeIntegral<int32_t>();
    mCamera->takePicture(msgType);
    invokeSetParameters();
    int32_t cmd;
    if (mFDP->ConsumeBool()) {
        cmd = mFDP->PickValueInArray(kValidCMD);
    } else {
        cmd = mFDP->ConsumeIntegral<int32_t>();
    }
    int32_t arg1 = mFDP->ConsumeIntegral<int32_t>();
    int32_t arg2 = mFDP->ConsumeIntegral<int32_t>();
    mCamera->sendCommand(cmd, arg1, arg2);

    int32_t videoBufferMode = mFDP->PickValueInArray(kValidVideoBufferMode);
    mCamera->setVideoBufferMode(videoBufferMode);
    if (mSurfaceControl) {
        mSurface = mSurfaceControl->getSurface();
        mCamera->setVideoTarget(mSurface->getIGraphicBufferProducer());
    }
    mCameraListener = sp<TestCameraListener>::make();
    mCamera->setListener(mCameraListener);
    int32_t previewCallbackFlag;
    if (mFDP->ConsumeBool()) {
        previewCallbackFlag = mFDP->PickValueInArray(kValidPreviewCallbackFlag);
    } else {
        previewCallbackFlag = mFDP->ConsumeIntegral<int32_t>();
    }
    mCamera->setPreviewCallbackFlags(previewCallbackFlag);
    if (mSurfaceControl) {
        mSurface = mSurfaceControl->getSurface();
        mCamera->setPreviewCallbackTarget(mSurface->getIGraphicBufferProducer());
    }

    mCamera->getRecordingProxy();
    int32_t mode = mFDP->ConsumeIntegral<int32_t>();
    mCamera->setAudioRestriction(mode);
    mCamera->getGlobalAudioRestriction();
    mCamera->recordingEnabled();

    mMemoryDealer = new MemoryDealer(kMemoryDealerSize);
    mIMem = mMemoryDealer->allocate(kMemoryDealerSize);
    mCamera->releaseRecordingFrame(mIMem);

    int32_t numFds = mFDP->ConsumeIntegralInRange<int32_t>(kNumMin, kNumMax);
    int32_t numInts = mFDP->ConsumeIntegralInRange<int32_t>(kNumMin, kNumMax);
    native_handle_t* handle = native_handle_create(numFds, numInts);
    mCamera->releaseRecordingFrameHandle(handle);

    int32_t msgTypeNC = mFDP->ConsumeIntegral<int32_t>();
    int32_t ext = mFDP->ConsumeIntegral<int32_t>();
    int32_t ext2 = mFDP->ConsumeIntegral<int32_t>();
    mCamera->notifyCallback(msgTypeNC, ext, ext2);

    int64_t timestamp = mFDP->ConsumeIntegral<int64_t>();
    mCamera->dataCallbackTimestamp(timestamp, msgTypeNC, mIMem);
    mCamera->recordingFrameHandleCallbackTimestamp(timestamp, handle);
}

void CameraFuzzer::invokeCameraUtils() {
    CameraMetadata staticMetadata;
    int32_t orientVal = mFDP->ConsumeBool() ? mFDP->PickValueInArray(kValidOrientation)
                                            : mFDP->ConsumeIntegral<int32_t>();
    uint8_t facingVal = mFDP->ConsumeBool() ? mFDP->PickValueInArray(kValidFacing)
                                            : mFDP->ConsumeIntegral<uint8_t>();
    staticMetadata.update(ANDROID_SENSOR_ORIENTATION, &orientVal, 1);
    staticMetadata.update(ANDROID_LENS_FACING, &facingVal, 1);
    int32_t transform = 0;
    CameraUtils::getRotationTransform(
            staticMetadata, mFDP->ConsumeIntegral<int32_t>() /* mirrorMode */, &transform /*out*/);
    CameraUtils::isCameraServiceDisabled();
}

void CameraFuzzer::invokeCameraBase() {
    CameraInfo cameraInfo;
    cameraInfo.facing = mFDP->ConsumeBool() ? mFDP->PickValueInArray(kValidFacing)
                                            : mFDP->ConsumeIntegral<int>();
    cameraInfo.orientation = mFDP->ConsumeBool() ? mFDP->PickValueInArray(kValidOrientation)
                                                 : mFDP->ConsumeIntegral<int>();
    invokeReadWriteParcel<CameraInfo>(&cameraInfo);

    CameraStatus* cameraStatus = nullptr;

    if (mFDP->ConsumeBool()) {
        cameraStatus = new CameraStatus();
    } else {
        string cid = mFDP->ConsumeRandomLengthString();
        int32_t status = mFDP->ConsumeIntegral<int32_t>();
        size_t unavailSubIdsSize = mFDP->ConsumeIntegralInRange<size_t>(kSizeMin, kSizeMax);
        vector<std::string> unavailSubIds;
        for (size_t idx = 0; idx < unavailSubIdsSize; ++idx) {
            string subId = mFDP->ConsumeRandomLengthString();
            unavailSubIds.push_back(subId);
        }
        string clientPackage = mFDP->ConsumeRandomLengthString();
        cameraStatus = new CameraStatus(cid, status, unavailSubIds, clientPackage);
    }

    invokeReadWriteParcel<CameraStatus>(cameraStatus);
    delete cameraStatus;
}

void CameraFuzzer::initCameraMetadata() {
    if (mFDP->ConsumeBool()) {
        mCameraMetadata = new CameraMetadata();
    } else {
        size_t entryCapacity = mFDP->ConsumeIntegralInRange<size_t>(kSizeMin, kSizeMax);
        size_t dataCapacity = mFDP->ConsumeIntegralInRange<size_t>(kSizeMin, kSizeMax);
        mCameraMetadata = new CameraMetadata(entryCapacity, dataCapacity);
    }
}

void CameraFuzzer::invokeCameraMetadata() {
    initCameraMetadata();

    const camera_metadata_t* metadataBuffer = nullptr;
    if (mFDP->ConsumeBool()) {
        metadataBuffer = mCameraMetadata->getAndLock();
    }

    mCameraMetadata->entryCount();
    mCameraMetadata->isEmpty();
    mCameraMetadata->bufferSize();
    mCameraMetadata->sort();

    uint32_t tag = mFDP->ConsumeIntegral<uint32_t>();
    uint8_t dataUint8 = mFDP->ConsumeIntegral<uint8_t>();
    int32_t dataInt32 = mFDP->ConsumeIntegral<int32_t>();
    int64_t dataInt64 = mFDP->ConsumeIntegral<int64_t>();
    float dataFloat = mFDP->ConsumeFloatingPoint<float>();
    double dataDouble = mFDP->ConsumeFloatingPoint<double>();
    camera_metadata_rational dataRational;
    dataRational.numerator = mFDP->ConsumeIntegral<int32_t>();
    dataRational.denominator = mFDP->ConsumeIntegral<int32_t>();
    string dataStr = mFDP->ConsumeRandomLengthString();
    String8 dataString(dataStr.c_str());
    size_t data_count = 1;
    mCameraMetadata->update(tag, &dataUint8, data_count);
    mCameraMetadata->update(tag, &dataInt32, data_count);
    mCameraMetadata->update(tag, &dataFloat, data_count);
    mCameraMetadata->update(tag, &dataInt64, data_count);
    mCameraMetadata->update(tag, &dataRational, data_count);
    mCameraMetadata->update(tag, &dataDouble, data_count);
    mCameraMetadata->update(tag, dataString);

    uint32_t tagExists = mFDP->ConsumeBool() ? tag : mFDP->ConsumeIntegral<uint32_t>();
    mCameraMetadata->exists(tagExists);

    uint32_t tagFind = mFDP->ConsumeBool() ? tag : mFDP->ConsumeIntegral<uint32_t>();
    mCameraMetadata->find(tagFind);

    uint32_t tagErase = mFDP->ConsumeBool() ? tag : mFDP->ConsumeIntegral<uint32_t>();
    mCameraMetadata->erase(tagErase);

    mCameraMetadata->unlock(metadataBuffer);
    std::vector<int32_t> tagsRemoved;
    uint64_t vendorId = mFDP->ConsumeIntegral<uint64_t>();
    mCameraMetadata->removePermissionEntries(vendorId, &tagsRemoved);

    string name = mFDP->ConsumeRandomLengthString();
    VendorTagDescriptor vTags;
    uint32_t tagName = mFDP->ConsumeIntegral<uint32_t>();
    mCameraMetadata->getTagFromName(name.c_str(), &vTags, &tagName);

    invokeReadWriteNullParcel<CameraMetadata>(mCameraMetadata);
    invokeReadWriteParcel<CameraMetadata>(mCameraMetadata);

    int32_t fd = open("/dev/null", O_CLOEXEC | O_RDWR | O_CREAT);
    int32_t verbosity = mFDP->ConsumeIntegralInRange<int32_t>(kRangeMin, kRangeMax);
    int32_t indentation = mFDP->ConsumeIntegralInRange<int32_t>(kRangeMin, kRangeMax);
    mCameraMetadata->dump(fd, verbosity, indentation);

    CameraMetadata metadataCopy(mCameraMetadata->release());
    CameraMetadata otherCameraMetadata;
    mCameraMetadata->swap(otherCameraMetadata);
    close(fd);
}

void CameraFuzzer::process(const uint8_t* data, size_t size) {
    mFDP = new FuzzedDataProvider(data, size);
    invokeCamera();
    invokeCameraUtils();
    invokeCameraBase();
    invokeCameraMetadata();
    delete mFDP;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    sp<CameraFuzzer> cameraFuzzer = new CameraFuzzer();
    cameraFuzzer->process(data, size);
    cameraFuzzer.clear();
    return 0;
}
