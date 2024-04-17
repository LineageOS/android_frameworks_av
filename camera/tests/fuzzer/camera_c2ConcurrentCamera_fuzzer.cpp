/*
 * Copyright (C) 2021 The Android Open Source Project
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

#include <camera2/ConcurrentCamera.h>
#include <CameraUtils.h>
#include <fuzzer/FuzzedDataProvider.h>
#include "camera2common.h"

using namespace std;
using namespace android;
using namespace android::hardware::camera2::utils;

constexpr int32_t kRangeMin = 0;
constexpr int32_t kRangeMax = 1000;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    FuzzedDataProvider fdp = FuzzedDataProvider(data, size);
    ConcurrentCameraIdCombination camIdCombination;

    if (fdp.ConsumeBool()) {
        size_t concurrentCameraIdSize = fdp.ConsumeIntegralInRange<size_t>(kRangeMin, kRangeMax);
        for (size_t idx = 0; idx < concurrentCameraIdSize; ++idx) {
            string concurrentCameraId = fdp.ConsumeRandomLengthString();
            camIdCombination.mConcurrentCameraIdDeviceIdPairs.push_back(
                    {concurrentCameraId, kDefaultDeviceId});
        }
    }

    invokeReadWriteNullParcel<ConcurrentCameraIdCombination>(&camIdCombination);
    invokeReadWriteParcel<ConcurrentCameraIdCombination>(&camIdCombination);

    CameraIdAndSessionConfiguration camIdAndSessionConfig;

    if (fdp.ConsumeBool()) {
        camIdAndSessionConfig.mCameraId = fdp.ConsumeRandomLengthString();
        if (fdp.ConsumeBool()) {
            camIdAndSessionConfig.mSessionConfiguration = SessionConfiguration();
        } else {
            int32_t inputWidth = fdp.ConsumeIntegral<int32_t>();
            int32_t inputHeight = fdp.ConsumeIntegral<int32_t>();
            int32_t inputFormat = fdp.ConsumeIntegral<int32_t>();
            int32_t operatingMode = fdp.ConsumeIntegral<int32_t>();
            camIdAndSessionConfig.mSessionConfiguration =
                    SessionConfiguration(inputWidth, inputHeight, inputFormat, operatingMode);
        }
    }

    invokeReadWriteNullParcel<CameraIdAndSessionConfiguration>(&camIdAndSessionConfig);
    invokeReadWriteParcel<CameraIdAndSessionConfiguration>(&camIdAndSessionConfig);
    return 0;
}
