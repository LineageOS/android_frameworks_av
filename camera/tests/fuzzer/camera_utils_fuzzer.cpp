/*
 * Copyright (C) 2023 The Android Open Source Project
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

#include <CameraBase.h>
#include <CameraUtils.h>
#include "camera2common.h"

using namespace std;
using namespace android;
using namespace android::hardware;

constexpr int8_t kMaxLoopIterations = 20;
constexpr int32_t kSizeMin = 0;
constexpr int32_t kSizeMax = 1000;

class CameraUtilsFuzzer {
  public:
    void process(const uint8_t* data, size_t size);

  private:
    void invokeCameraUtils();
    void invokeCameraBase();
    FuzzedDataProvider* mFDP = nullptr;
};

void CameraUtilsFuzzer::invokeCameraUtils() {
    int8_t count = kMaxLoopIterations;
    while (--count > 0) {
        int32_t transform = 0;
        auto callCameraUtilsAPIs = mFDP->PickValueInArray<const std::function<void()>>({
                [&]() {
                    CameraMetadata staticMetadata;
                    if (mFDP->ConsumeBool()) {
                        int32_t orientVal = mFDP->ConsumeBool()
                                                    ? mFDP->PickValueInArray(kValidOrientation)
                                                    : mFDP->ConsumeIntegral<int32_t>();
                        uint8_t facingVal = mFDP->ConsumeBool()
                                                    ? mFDP->PickValueInArray(kValidFacing)
                                                    : mFDP->ConsumeIntegral<uint8_t>();
                        staticMetadata.update(ANDROID_SENSOR_ORIENTATION, &orientVal, 1);
                        staticMetadata.update(ANDROID_LENS_FACING, &facingVal, 1);
                    } else {
                        std::vector<int32_t> orientVal;
                        for (int8_t i = 0;
                             i <= mFDP->ConsumeIntegralInRange<int32_t>(kMinCapacity, kMaxCapacity);
                             ++i) {
                            orientVal.push_back(mFDP->ConsumeIntegral<int32_t>());
                        }
                        std::vector<uint8_t> facingVal = mFDP->ConsumeBytes<uint8_t>(kMaxBytes);
                        /**
                         * Resizing vector to a size between 1 to 1000 so that vector is not empty.
                         */
                        orientVal.resize(0, mFDP->ConsumeIntegralInRange<int32_t>(kMinCapacity,
                                                                                  kMaxCapacity));
                        facingVal.resize(0, mFDP->ConsumeIntegralInRange<int32_t>(kMinCapacity,
                                                                                  kMaxCapacity));
                        staticMetadata.update(ANDROID_SENSOR_ORIENTATION, orientVal.data(),
                                              orientVal.size());
                        staticMetadata.update(ANDROID_LENS_FACING, facingVal.data(),
                                              facingVal.size());
                    }

                    CameraUtils::getRotationTransform(
                            staticMetadata, mFDP->ConsumeIntegral<int32_t>() /* mirrorMode */,
                            &transform /*out*/);
                },
                [&]() { CameraUtils::isCameraServiceDisabled(); },
        });
        callCameraUtilsAPIs();
    }
}

void CameraUtilsFuzzer::invokeCameraBase() {
    int8_t count = kMaxLoopIterations;
    while (--count > 0) {
        CameraInfo cameraInfo;
        cameraInfo.facing = mFDP->ConsumeBool() ? mFDP->PickValueInArray(kValidFacing)
                                                : mFDP->ConsumeIntegral<int>();
        cameraInfo.orientation = mFDP->ConsumeBool() ? mFDP->PickValueInArray(kValidOrientation)
                                                     : mFDP->ConsumeIntegral<int>();
        if (mFDP->ConsumeBool()) {
            invokeReadWriteParcel<CameraInfo>(&cameraInfo);
        } else {
            invokeNewReadWriteParcel<CameraInfo>(&cameraInfo, *mFDP);
        }

        CameraStatus* cameraStatus = nullptr;

        if (mFDP->ConsumeBool()) {
            cameraStatus = new CameraStatus();
        } else {
            string id = mFDP->ConsumeRandomLengthString(kMaxBytes);
            int32_t status = mFDP->ConsumeIntegral<int32_t>();
            size_t unavailSubIdsSize = mFDP->ConsumeIntegralInRange<size_t>(kSizeMin, kSizeMax);
            vector<string> unavailSubIds;
            for (size_t idx = 0; idx < unavailSubIdsSize; ++idx) {
                string unavailSubId = mFDP->ConsumeRandomLengthString(kMaxBytes);
                unavailSubIds.push_back(unavailSubId);
            }
            string clientPackage = mFDP->ConsumeRandomLengthString(kMaxBytes);

            cameraStatus = new CameraStatus(id, status, unavailSubIds, clientPackage,
                                            kDefaultDeviceId);
        }

        if (mFDP->ConsumeBool()) {
            invokeReadWriteParcel<CameraStatus>(cameraStatus);
        } else {
            invokeNewReadWriteParcel<CameraStatus>(cameraStatus, *mFDP);
        }
        delete cameraStatus;
    }
}

void CameraUtilsFuzzer::process(const uint8_t* data, size_t size) {
    mFDP = new FuzzedDataProvider(data, size);
    if (mFDP->ConsumeBool()) {
        invokeCameraUtils();
    } else {
        invokeCameraBase();
    }
    delete mFDP;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    CameraUtilsFuzzer cameraUtilsFuzzer;
    cameraUtilsFuzzer.process(data, size);
    return 0;
}
