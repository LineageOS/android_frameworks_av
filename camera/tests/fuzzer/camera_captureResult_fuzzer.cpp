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

#include <CaptureResult.h>
#include <fuzzer/FuzzedDataProvider.h>
#include "camera2common.h"

using namespace std;
using namespace android;
using namespace android::hardware::camera2::impl;

constexpr int32_t kSizeMin = 0;
constexpr int32_t kSizeMax = 1000;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    FuzzedDataProvider fdp = FuzzedDataProvider(data, size);
    PhysicalCaptureResultInfo* physicalCaptureResultInfo = nullptr;

    if (fdp.ConsumeBool()) {
        physicalCaptureResultInfo = new PhysicalCaptureResultInfo();
    } else {
        string cameraId = fdp.ConsumeRandomLengthString();
        CameraMetadata cameraMetadata = CameraMetadata();
        physicalCaptureResultInfo = new PhysicalCaptureResultInfo(cameraId, cameraMetadata);
    }

    invokeReadWriteParcel<PhysicalCaptureResultInfo>(physicalCaptureResultInfo);

    CaptureResult* captureResult = new CaptureResult();

    if (fdp.ConsumeBool()) {
        captureResult->mMetadata = CameraMetadata();
    }
    if (fdp.ConsumeBool()) {
        captureResult->mResultExtras = CaptureResultExtras();
        captureResult->mResultExtras.errorPhysicalCameraId = fdp.ConsumeRandomLengthString();
        captureResult->mResultExtras.isValid();
        invokeReadWriteNullParcel<CaptureResultExtras>(&(captureResult->mResultExtras));
    }
    if (fdp.ConsumeBool()) {
        size_t physicalMetadatasSize = fdp.ConsumeIntegralInRange<size_t>(kSizeMin, kSizeMax);
        for (size_t idx = 0; idx < physicalMetadatasSize; ++idx) {
            captureResult->mPhysicalMetadatas.push_back(PhysicalCaptureResultInfo());
        }
    }

    invokeReadWriteNullParcel<CaptureResult>(captureResult);
    invokeReadWriteParcel<CaptureResult>(captureResult);
    CaptureResult captureResult2(*captureResult);
    CaptureResult captureResult3(std::move(captureResult2));

    delete captureResult;
    delete physicalCaptureResultInfo;
    return 0;
}
