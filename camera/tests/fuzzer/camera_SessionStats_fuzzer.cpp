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

#include <CameraSessionStats.h>
#include <binder/Parcel.h>
#include <fuzzer/FuzzedDataProvider.h>
#include <camera/StringUtils.h>
#include "camera2common.h"

using namespace std;
using namespace android;
using namespace android::hardware;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    FuzzedDataProvider fdp = FuzzedDataProvider(data, size);
    CameraStreamStats* cameraStreamStats = nullptr;
    Parcel parcelCamStreamStats;

    if (fdp.ConsumeBool()) {
        cameraStreamStats = new CameraStreamStats();
    } else {
        int32_t width = fdp.ConsumeIntegral<int32_t>();
        if (fdp.ConsumeBool()) {
            parcelCamStreamStats.writeInt32(width);
        }
        int32_t height = fdp.ConsumeIntegral<int32_t>();
        if (fdp.ConsumeBool()) {
            parcelCamStreamStats.writeInt32(height);
        }
        int32_t format = fdp.ConsumeIntegral<int32_t>();
        if (fdp.ConsumeBool()) {
            parcelCamStreamStats.writeInt32(format);
        }
        float maxPreviewFps = fdp.ConsumeFloatingPoint<float>();
        if (fdp.ConsumeBool()) {
            parcelCamStreamStats.writeFloat(maxPreviewFps);
        }
        int32_t dataSpace = fdp.ConsumeIntegral<int32_t>();
        if (fdp.ConsumeBool()) {
            parcelCamStreamStats.writeInt32(dataSpace);
        }
        int64_t usage = fdp.ConsumeIntegral<int64_t>();
        if (fdp.ConsumeBool()) {
            parcelCamStreamStats.writeInt64(usage);
        }
        int64_t requestCount = fdp.ConsumeIntegral<int64_t>();
        if (fdp.ConsumeBool()) {
            parcelCamStreamStats.writeInt64(requestCount);
        }
        int64_t errorCount = fdp.ConsumeIntegral<int64_t>();
        if (fdp.ConsumeBool()) {
            parcelCamStreamStats.writeInt64(errorCount);
        }
        int32_t maxHalBuffers = fdp.ConsumeIntegral<int32_t>();
        if (fdp.ConsumeBool()) {
            parcelCamStreamStats.writeInt32(maxHalBuffers);
        }
        int32_t maxAppBuffers = fdp.ConsumeIntegral<int32_t>();
        if (fdp.ConsumeBool()) {
            parcelCamStreamStats.writeInt32(maxAppBuffers);
        }
        int32_t dynamicRangeProfile = fdp.ConsumeIntegral<int32_t>();
        if (fdp.ConsumeBool()) {
            parcelCamStreamStats.writeInt32(dynamicRangeProfile);
        }
        int32_t streamUseCase = fdp.ConsumeIntegral<int32_t>();
        if (fdp.ConsumeBool()) {
            parcelCamStreamStats.writeInt32(streamUseCase);
        }
        int32_t colorSpace = fdp.ConsumeIntegral<int32_t>();
        if (fdp.ConsumeBool()) {
            parcelCamStreamStats.writeInt32(colorSpace);
        }

        cameraStreamStats = new CameraStreamStats(width, height, format, maxPreviewFps, dataSpace,
                                                  usage, maxHalBuffers, maxAppBuffers,
                                                  dynamicRangeProfile, streamUseCase, colorSpace);
    }

    parcelCamStreamStats.setDataPosition(0);
    cameraStreamStats->readFromParcel(&parcelCamStreamStats);
    invokeReadWriteNullParcel<CameraStreamStats>(cameraStreamStats);
    invokeReadWriteParcel<CameraStreamStats>(cameraStreamStats);

    CameraSessionStats* cameraSessionStats = nullptr;
    Parcel parcelCamSessionStats;

    if (fdp.ConsumeBool()) {
        cameraSessionStats = new CameraSessionStats();
    } else {
        string cameraId = fdp.ConsumeRandomLengthString();
        if (fdp.ConsumeBool()) {
            parcelCamSessionStats.writeString16(toString16(cameraId));
        }
        int32_t facing = fdp.ConsumeIntegral<int32_t>();
        if (fdp.ConsumeBool()) {
            parcelCamSessionStats.writeInt32(facing);
        }
        int32_t newCameraState = fdp.ConsumeIntegral<int32_t>();
        if (fdp.ConsumeBool()) {
            parcelCamSessionStats.writeInt32(newCameraState);
        }
        string clientName = fdp.ConsumeRandomLengthString();
        if (fdp.ConsumeBool()) {
            parcelCamSessionStats.writeString16(toString16(clientName));
        }
        int32_t apiLevel = fdp.ConsumeIntegral<int32_t>();
        if (fdp.ConsumeBool()) {
            parcelCamSessionStats.writeInt32(apiLevel);
        }
        bool isNdk = fdp.ConsumeBool();
        if (fdp.ConsumeBool()) {
            parcelCamSessionStats.writeBool(isNdk);
        }
        int32_t latencyMs = fdp.ConsumeIntegral<int32_t>();
        if (fdp.ConsumeBool()) {
            parcelCamSessionStats.writeInt32(latencyMs);
        }

        int64_t logId = fdp.ConsumeIntegral<int64_t>();
        if (fdp.ConsumeBool()) {
            parcelCamSessionStats.writeInt64(logId);
        }

        cameraSessionStats = new CameraSessionStats(cameraId, facing, newCameraState, clientName,
                                                    apiLevel, isNdk, latencyMs, logId);
    }

    if (fdp.ConsumeBool()) {
        int32_t internalReconfigure = fdp.ConsumeIntegral<int32_t>();
        parcelCamSessionStats.writeInt32(internalReconfigure);
    }

    if (fdp.ConsumeBool()) {
        int64_t requestCount = fdp.ConsumeIntegral<int64_t>();
        parcelCamSessionStats.writeInt64(requestCount);
    }

    if (fdp.ConsumeBool()) {
        int64_t resultErrorCount = fdp.ConsumeIntegral<int64_t>();
        parcelCamSessionStats.writeInt64(resultErrorCount);
    }

    if (fdp.ConsumeBool()) {
        bool deviceError = fdp.ConsumeBool();
        parcelCamSessionStats.writeBool(deviceError);
    }

    parcelCamSessionStats.setDataPosition(0);
    cameraSessionStats->readFromParcel(&parcelCamSessionStats);
    invokeReadWriteNullParcel<CameraSessionStats>(cameraSessionStats);
    invokeReadWriteParcel<CameraSessionStats>(cameraSessionStats);

    delete cameraStreamStats;
    delete cameraSessionStats;
    return 0;
}
