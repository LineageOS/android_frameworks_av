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

#include <CameraParameters.h>
#include <CameraParameters2.h>
#include <fcntl.h>
#include <fuzzer/FuzzedDataProvider.h>
#include <utils/String16.h>
#include <camera/StringUtils.h>

using namespace std;
using namespace android;

string kValidFormats[] = {
        CameraParameters::PIXEL_FORMAT_YUV422SP,      CameraParameters::PIXEL_FORMAT_YUV420SP,
        CameraParameters::PIXEL_FORMAT_YUV422I,       CameraParameters::PIXEL_FORMAT_YUV420P,
        CameraParameters::PIXEL_FORMAT_RGB565,        CameraParameters::PIXEL_FORMAT_RGBA8888,
        CameraParameters::PIXEL_FORMAT_JPEG,          CameraParameters::PIXEL_FORMAT_BAYER_RGGB,
        CameraParameters::PIXEL_FORMAT_ANDROID_OPAQUE};

class CameraParametersFuzzer {
  public:
    void process(const uint8_t* data, size_t size);
    ~CameraParametersFuzzer() {
        delete mCameraParameters;
        delete mCameraParameters2;
    }

  private:
    void invokeCameraParameters();
    template <class type>
    void initCameraParameters(type** obj);
    template <class type>
    void cameraParametersCommon(type* obj);
    CameraParameters* mCameraParameters = nullptr;
    CameraParameters2* mCameraParameters2 = nullptr;
    FuzzedDataProvider* mFDP = nullptr;
};

template <class type>
void CameraParametersFuzzer::initCameraParameters(type** obj) {
    if (mFDP->ConsumeBool()) {
        *obj = new type();
    } else {
        string params;
        if (mFDP->ConsumeBool()) {
            int32_t width = mFDP->ConsumeIntegral<int32_t>();
            int32_t height = mFDP->ConsumeIntegral<int32_t>();
            int32_t minFps = mFDP->ConsumeIntegral<int32_t>();
            int32_t maxFps = mFDP->ConsumeIntegral<int32_t>();
            params = CameraParameters::KEY_SUPPORTED_VIDEO_SIZES;
            params += '=' + to_string(width) + 'x' + to_string(height) + ';';
            if (mFDP->ConsumeBool()) {
                params += CameraParameters::KEY_PREVIEW_FPS_RANGE;
                params += '=' + to_string(minFps) + ',' + to_string(maxFps) + ';';
            }
            if (mFDP->ConsumeBool()) {
                params += CameraParameters::KEY_SUPPORTED_PICTURE_SIZES;
                params += '=' + to_string(width) + 'x' + to_string(height) + ';';
            }
            if (mFDP->ConsumeBool()) {
                params += CameraParameters::KEY_SUPPORTED_PREVIEW_FORMATS;
                params += '=' + mFDP->PickValueInArray(kValidFormats) + ';';
            }
        } else {
            params = mFDP->ConsumeRandomLengthString();
        }
        *obj = new type(toString8(params));
    }
}

template <class type>
void CameraParametersFuzzer::cameraParametersCommon(type* obj) {
    Vector<Size> supportedPreviewSizes;
    obj->getSupportedPreviewSizes(supportedPreviewSizes);
    int32_t previewWidth = mFDP->ConsumeIntegral<int32_t>();
    int32_t previewHeight = mFDP->ConsumeIntegral<int32_t>();
    obj->setPreviewSize(previewWidth, previewHeight);
    obj->getPreviewSize(&previewWidth, &previewHeight);

    Vector<Size> supportedVideoSizes;
    obj->getSupportedVideoSizes(supportedVideoSizes);
    if (supportedVideoSizes.size() != 0) {
        int32_t videoWidth, videoHeight, preferredVideoWidth, preferredVideoHeight;
        if (mFDP->ConsumeBool()) {
            int32_t idx = mFDP->ConsumeIntegralInRange<int32_t>(0, supportedVideoSizes.size() - 1);
            obj->setVideoSize(supportedVideoSizes[idx].width, supportedVideoSizes[idx].height);
        } else {
            videoWidth = mFDP->ConsumeIntegral<int32_t>();
            videoHeight = mFDP->ConsumeIntegral<int32_t>();
            obj->setVideoSize(videoWidth, videoHeight);
        }
        obj->getVideoSize(&videoWidth, &videoHeight);
        obj->getPreferredPreviewSizeForVideo(&preferredVideoWidth, &preferredVideoHeight);
    }

    int32_t fps = mFDP->ConsumeIntegral<int32_t>();
    obj->setPreviewFrameRate(fps);
    obj->getPreviewFrameRate();
    string previewFormat = mFDP->ConsumeBool() ? mFDP->PickValueInArray(kValidFormats)
                                               : mFDP->ConsumeRandomLengthString();
    obj->setPreviewFormat(previewFormat.c_str());

    int32_t pictureWidth = mFDP->ConsumeIntegral<int32_t>();
    int32_t pictureHeight = mFDP->ConsumeIntegral<int32_t>();
    Vector<Size> supportedPictureSizes;
    obj->setPictureSize(pictureWidth, pictureHeight);
    obj->getPictureSize(&pictureWidth, &pictureHeight);
    obj->getSupportedPictureSizes(supportedPictureSizes);
    string pictureFormat = mFDP->ConsumeBool() ? mFDP->PickValueInArray(kValidFormats)
                                               : mFDP->ConsumeRandomLengthString();
    obj->setPictureFormat(pictureFormat.c_str());
    obj->getPictureFormat();

    if (mFDP->ConsumeBool()) {
        obj->dump();
    } else {
        int32_t fd = open("/dev/null", O_CLOEXEC | O_RDWR | O_CREAT);
        Vector<String16> args = {};
        obj->dump(fd, args);
        close(fd);
    }
}

void CameraParametersFuzzer::invokeCameraParameters() {
    initCameraParameters<CameraParameters>(&mCameraParameters);
    cameraParametersCommon<CameraParameters>(mCameraParameters);
    initCameraParameters<CameraParameters2>(&mCameraParameters2);
    cameraParametersCommon<CameraParameters2>(mCameraParameters2);

    int32_t minFPS, maxFPS;
    mCameraParameters->getPreviewFpsRange(&minFPS, &maxFPS);
    string format = mFDP->ConsumeBool() ? mFDP->PickValueInArray(kValidFormats)
                                        : mFDP->ConsumeRandomLengthString();
    mCameraParameters->previewFormatToEnum(format.c_str());
    mCameraParameters->isEmpty();
    Vector<int32_t> formats;
    mCameraParameters->getSupportedPreviewFormats(formats);
}

void CameraParametersFuzzer::process(const uint8_t* data, size_t size) {
    mFDP = new FuzzedDataProvider(data, size);
    invokeCameraParameters();
    delete mFDP;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    CameraParametersFuzzer cameraParametersFuzzer;
    cameraParametersFuzzer.process(data, size);
    return 0;
}
