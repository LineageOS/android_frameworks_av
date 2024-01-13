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

#include <CameraMetadata.h>
#include <camera/StringUtils.h>
#include <camera2/CaptureRequest.h>
#include <fuzzer/FuzzedDataProvider.h>
#include <gui/Surface.h>
#include <gui/SurfaceComposerClient.h>
#include <gui/view/Surface.h>
#include "camera2common.h"

using namespace std;
using namespace android;

constexpr int32_t kNonZeroRangeMin = 0;
constexpr int32_t kRangeMax = 1000;
constexpr int32_t kSizeMin = 1;
constexpr int32_t kSizeMax = 1000;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    FuzzedDataProvider fdp = FuzzedDataProvider(data, size);

    sp<CaptureRequest> captureRequest = new CaptureRequest();
    Parcel parcelCamCaptureReq;

    size_t physicalCameraSettingsSize =
            fdp.ConsumeIntegralInRange<size_t>(kNonZeroRangeMin, kRangeMax);
    if (fdp.ConsumeBool()) {
        parcelCamCaptureReq.writeInt32(physicalCameraSettingsSize);
    }

    for (size_t idx = 0; idx < physicalCameraSettingsSize; ++idx) {
        string id = fdp.ConsumeRandomLengthString(kMaxBytes);
        if (fdp.ConsumeBool()) {
            parcelCamCaptureReq.writeString16(toString16(id));
        }
        CameraMetadata cameraMetadata;
        if (fdp.ConsumeBool()) {
            cameraMetadata = CameraMetadata();
        } else {
            size_t entryCapacity = fdp.ConsumeIntegralInRange<size_t>(kNonZeroRangeMin, kRangeMax);
            size_t dataCapacity = fdp.ConsumeIntegralInRange<size_t>(kNonZeroRangeMin, kRangeMax);
            cameraMetadata = CameraMetadata(entryCapacity, dataCapacity);
        }
        captureRequest->mPhysicalCameraSettings.push_back({id, cameraMetadata});
        if (fdp.ConsumeBool()) {
            cameraMetadata.writeToParcel(&parcelCamCaptureReq);
        }
    }

    captureRequest->mIsReprocess = fdp.ConsumeBool();
    if (fdp.ConsumeBool()) {
        parcelCamCaptureReq.writeInt32(captureRequest->mIsReprocess);
    }

    captureRequest->mSurfaceConverted = fdp.ConsumeBool();
    if (fdp.ConsumeBool() && captureRequest->mSurfaceConverted) {
        // 0-sized array
        parcelCamCaptureReq.writeInt32(0);
    }

    if (!captureRequest->mSurfaceConverted) {
        size_t surfaceListSize = fdp.ConsumeIntegralInRange<size_t>(kSizeMin, kSizeMax);
        if (fdp.ConsumeBool()) {
            parcelCamCaptureReq.writeInt32(surfaceListSize);
        }
        for (size_t idx = 0; idx < surfaceListSize; ++idx) {
            sp<SurfaceComposerClient> composerClient = new SurfaceComposerClient;
            sp<SurfaceControl> surfaceControl = composerClient->createSurface(
                    static_cast<String8>(fdp.ConsumeRandomLengthString().c_str()) /* name */,
                    fdp.ConsumeIntegral<uint32_t>() /* width */,
                    fdp.ConsumeIntegral<uint32_t>() /* height */,
                    fdp.ConsumeIntegral<int32_t>() /* format */,
                    fdp.ConsumeIntegral<int32_t>() /* flags */);
            if (surfaceControl) {
                sp<Surface> surface = surfaceControl->getSurface();
                captureRequest->mSurfaceList.push_back(surface);
                if (fdp.ConsumeBool()) {
                    view::Surface surfaceShim;
                    surfaceShim.name = String16((fdp.ConsumeRandomLengthString()).c_str());
                    surfaceShim.graphicBufferProducer = surface->getIGraphicBufferProducer();
                    surfaceShim.writeToParcel(&parcelCamCaptureReq);
                }
                surface.clear();
            }
            composerClient.clear();
            surfaceControl.clear();
        }
    }

    size_t indexListSize = fdp.ConsumeIntegralInRange<size_t>(kSizeMin, kSizeMax);
    if (fdp.ConsumeBool()) {
        parcelCamCaptureReq.writeInt32(indexListSize);
    }

    for (size_t idx = 0; idx < indexListSize; ++idx) {
        int32_t streamIdx = fdp.ConsumeIntegral<int32_t>();
        int32_t surfaceIdx = fdp.ConsumeIntegral<int32_t>();
        captureRequest->mStreamIdxList.push_back(streamIdx);
        captureRequest->mSurfaceIdxList.push_back(surfaceIdx);
        if (fdp.ConsumeBool()) {
            parcelCamCaptureReq.writeInt32(streamIdx);
        }
        if (fdp.ConsumeBool()) {
            parcelCamCaptureReq.writeInt32(surfaceIdx);
        }
    }

    if (fdp.ConsumeBool()) {
        invokeReadWriteParcelsp<CaptureRequest>(captureRequest);
    } else {
        invokeNewReadWriteParcelsp<CaptureRequest>(captureRequest, fdp);
    }
    invokeReadWriteNullParcelsp<CaptureRequest>(captureRequest);
    parcelCamCaptureReq.setDataPosition(0);
    captureRequest->readFromParcel(&parcelCamCaptureReq);
    captureRequest.clear();
    return 0;
}
