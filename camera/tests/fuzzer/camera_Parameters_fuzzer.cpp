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
#include <camera/StringUtils.h>
#include <fcntl.h>
#include <fuzzer/FuzzedDataProvider.h>
#include <utils/String16.h>
#include <camera/StringUtils.h>

#include <functional>

using namespace std;
using namespace android;

constexpr int8_t kMaxBytes = 20;

string kValidFormats[] = {
        CameraParameters::PIXEL_FORMAT_YUV422SP,      CameraParameters::PIXEL_FORMAT_YUV420SP,
        CameraParameters::PIXEL_FORMAT_YUV422I,       CameraParameters::PIXEL_FORMAT_YUV420P,
        CameraParameters::PIXEL_FORMAT_RGB565,        CameraParameters::PIXEL_FORMAT_RGBA8888,
        CameraParameters::PIXEL_FORMAT_JPEG,          CameraParameters::PIXEL_FORMAT_BAYER_RGGB,
        CameraParameters::PIXEL_FORMAT_ANDROID_OPAQUE};

class CameraParametersFuzzer {
  public:
    void process(const uint8_t* data, size_t size);

  private:
    void invokeCameraParameters();
    template <class type>
    void initCameraParameters(unique_ptr<type>& obj);
    template <class type>
    void callCameraParametersAPIs(unique_ptr<type>& obj);
    unique_ptr<CameraParameters> mCameraParameters;
    unique_ptr<CameraParameters2> mCameraParameters2;
    FuzzedDataProvider* mFDP = nullptr;
};

template <class type>
void CameraParametersFuzzer::initCameraParameters(unique_ptr<type>& obj) {
    if (mFDP->ConsumeBool()) {
        obj = make_unique<type>();
    } else {
        string params;
        if (mFDP->ConsumeBool()) {
            int32_t width = mFDP->ConsumeIntegral<int32_t>();
            int32_t height = mFDP->ConsumeIntegral<int32_t>();
            int32_t minFps = mFDP->ConsumeIntegral<int32_t>();
            int32_t maxFps = mFDP->ConsumeIntegral<int32_t>();
            params = mFDP->ConsumeBool() ? mFDP->ConsumeRandomLengthString(kMaxBytes).c_str()
                                         : CameraParameters::KEY_SUPPORTED_VIDEO_SIZES;
            params += '=' + to_string(width) + 'x' + to_string(height) + ';';
            if (mFDP->ConsumeBool()) {
                params += mFDP->ConsumeBool() ? mFDP->ConsumeRandomLengthString(kMaxBytes).c_str()
                                              : CameraParameters::KEY_PREVIEW_FPS_RANGE;
                params += '=' + to_string(minFps) + ',' + to_string(maxFps) + ';';
            }
            if (mFDP->ConsumeBool()) {
                params += mFDP->ConsumeBool() ? mFDP->ConsumeRandomLengthString(kMaxBytes).c_str()
                                              : CameraParameters::KEY_SUPPORTED_PICTURE_SIZES;
                params += '=' + to_string(width) + 'x' + to_string(height) + ';';
            }
            if (mFDP->ConsumeBool()) {
                params += mFDP->ConsumeBool() ? mFDP->ConsumeRandomLengthString(kMaxBytes).c_str()
                                              : CameraParameters::KEY_SUPPORTED_PREVIEW_FORMATS;
                params += '=' +
                          (mFDP->ConsumeBool() ? mFDP->ConsumeRandomLengthString(kMaxBytes).c_str()
                                               : mFDP->PickValueInArray(kValidFormats)) + ';';
            }
        } else {
            params = mFDP->ConsumeRandomLengthString(kMaxBytes);
        }
        obj = make_unique<type>(toString8(params));
    }
}

template <class type>
void CameraParametersFuzzer::callCameraParametersAPIs(unique_ptr<type>& obj) {
    Vector<Size> supportedVideoSizes;
    while (mFDP->remaining_bytes()) {
        auto callCameraUtilsAPIs = mFDP->PickValueInArray<const std::function<void()>>({
                [&]() {
                    Vector<Size> supportedPreviewSizes;
                    obj->getSupportedPreviewSizes(supportedPreviewSizes);
                },
                [&]() {
                    int32_t previewWidth = mFDP->ConsumeIntegral<int32_t>();
                    int32_t previewHeight = mFDP->ConsumeIntegral<int32_t>();
                    obj->setPreviewSize(previewWidth, previewHeight);
                },
                [&]() {
                    int32_t previewWidth, previewHeight;
                    obj->getPreviewSize(&previewWidth, &previewHeight);
                },
                [&]() { obj->getSupportedVideoSizes(supportedVideoSizes); },
                [&]() {
                    int32_t videoWidth, videoHeight;
                    if (supportedVideoSizes.size()) {
                        int32_t idx = mFDP->ConsumeIntegralInRange<int32_t>(
                                0, supportedVideoSizes.size() - 1);
                        videoWidth = mFDP->ConsumeBool() ? supportedVideoSizes[idx].width
                                                         : mFDP->ConsumeIntegral<int32_t>();
                        videoHeight = mFDP->ConsumeBool() ? supportedVideoSizes[idx].height
                                                          : mFDP->ConsumeIntegral<int32_t>();
                        obj->setVideoSize(videoWidth, videoHeight);
                    }
                },
                [&]() {
                    int32_t videoWidth, videoHeight;
                    obj->getVideoSize(&videoWidth, &videoHeight);
                },
                [&]() {
                    int32_t preferredVideoWidth, preferredVideoHeight;
                    obj->getPreferredPreviewSizeForVideo(&preferredVideoWidth,
                                                         &preferredVideoHeight);
                },
                [&]() {
                    int32_t fps = mFDP->ConsumeIntegral<int32_t>();
                    obj->setPreviewFrameRate(fps);
                },
                [&]() { obj->getPreviewFrameRate(); },
                [&]() {
                    string previewFormat = mFDP->ConsumeBool()
                                                   ? mFDP->PickValueInArray(kValidFormats)
                                                   : mFDP->ConsumeRandomLengthString(kMaxBytes);
                    obj->setPreviewFormat(previewFormat.c_str());
                },
                [&]() {
                    int32_t pictureWidth = mFDP->ConsumeIntegral<int32_t>();
                    int32_t pictureHeight = mFDP->ConsumeIntegral<int32_t>();
                    obj->setPictureSize(pictureWidth, pictureHeight);
                },
                [&]() {
                    int32_t pictureWidth, pictureHeight;
                    obj->getPictureSize(&pictureWidth, &pictureHeight);
                },
                [&]() {
                    Vector<Size> supportedPictureSizes;
                    obj->getSupportedPictureSizes(supportedPictureSizes);
                },
                [&]() {
                    string pictureFormat = mFDP->ConsumeBool()
                                                   ? mFDP->PickValueInArray(kValidFormats)
                                                   : mFDP->ConsumeRandomLengthString(kMaxBytes);
                    obj->setPictureFormat(pictureFormat.c_str());
                },
                [&]() { obj->getPictureFormat(); },
                [&]() {
                    if (mFDP->ConsumeBool()) {
                        obj->dump();
                    } else {
                        int32_t fd = open("/dev/null", O_CLOEXEC | O_RDWR | O_CREAT);
                        Vector<String16> args = {};
                        obj->dump(fd, args);
                        close(fd);
                    }
                },
                [&]() { obj->flatten(); },
                [&]() {
                    string key = mFDP->ConsumeRandomLengthString(kMaxBytes);
                    float value = mFDP->ConsumeFloatingPoint<float>();
                    obj->setFloat(key.c_str(), value);
                },
                [&]() {
                    string key = mFDP->ConsumeRandomLengthString(kMaxBytes);
                    obj->getFloat(key.c_str());
                },
                [&]() { obj->getPreviewFormat(); },
                [&]() {
                    string key = mFDP->ConsumeRandomLengthString(kMaxBytes);
                    obj->remove(key.c_str());
                },
                [&]() {
                    if (std::is_same_v<type, CameraParameters>) {
                        string format = mFDP->ConsumeBool()
                                                ? mFDP->ConsumeRandomLengthString(kMaxBytes)
                                                : mFDP->PickValueInArray(kValidFormats);
                        mCameraParameters->previewFormatToEnum(format.c_str());
                    }
                },
                [&]() {
                    if (std::is_same_v<type, CameraParameters>) {
                        mCameraParameters->isEmpty();
                    }
                },
                [&]() {
                    if (std::is_same_v<type, CameraParameters>) {
                        Vector<int32_t> formats;
                        mCameraParameters->getSupportedPreviewFormats(formats);
                    }
                },
                [&]() {
                    if (std::is_same_v<type, CameraParameters2>) {
                        string key1 = mFDP->ConsumeRandomLengthString(kMaxBytes);
                        string key2 = mFDP->ConsumeRandomLengthString(kMaxBytes);
                        int32_t order;
                        mCameraParameters2->compareSetOrder(key1.c_str(), key2.c_str(), &order);
                    }
                },
                [&]() {
                    if (std::is_same_v<type, CameraParameters2>) {
                        int32_t minFps = mFDP->ConsumeIntegral<int32_t>();
                        int32_t maxFps = mFDP->ConsumeIntegral<int32_t>();
                        mCameraParameters2->setPreviewFpsRange(minFps, maxFps);
                    }
                },
        });
        callCameraUtilsAPIs();
    }
}

void CameraParametersFuzzer::invokeCameraParameters() {
    if (mFDP->ConsumeBool()) {
        initCameraParameters<CameraParameters>(mCameraParameters);
        callCameraParametersAPIs(mCameraParameters);
    } else {
        initCameraParameters<CameraParameters2>(mCameraParameters2);
        callCameraParametersAPIs(mCameraParameters2);
    }
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
