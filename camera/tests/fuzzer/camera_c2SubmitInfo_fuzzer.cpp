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

#include <camera2/SubmitInfo.h>
#include <fuzzer/FuzzedDataProvider.h>
#include "camera2common.h"

using namespace std;
using namespace android;
using namespace android::hardware::camera2::utils;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    FuzzedDataProvider fdp = FuzzedDataProvider(data, size);
    SubmitInfo submitInfo;
    submitInfo.mRequestId = fdp.ConsumeIntegral<int32_t>();
    submitInfo.mLastFrameNumber = fdp.ConsumeIntegral<int64_t>();
    if (fdp.ConsumeBool()) {
        invokeReadWriteParcel<SubmitInfo>(&submitInfo);
    } else {
        invokeNewReadWriteParcel<SubmitInfo>(&submitInfo, fdp);
    }
    return 0;
}
