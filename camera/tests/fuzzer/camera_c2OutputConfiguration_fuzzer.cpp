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

#include <camera2/OutputConfiguration.h>
#include <camera2/SessionConfiguration.h>
#include <fuzzer/FuzzedDataProvider.h>
#include <gui/IGraphicBufferProducer.h>
#include <gui/Surface.h>
#include <gui/SurfaceComposerClient.h>
#include "camera2common.h"

using namespace std;
using namespace android;
using namespace android::hardware::camera2::params;

constexpr int32_t kSizeMin = 0;
constexpr int32_t kSizeMax = 1000;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    FuzzedDataProvider fdp = FuzzedDataProvider(data, size);

    OutputConfiguration* outputConfiguration = nullptr;

    if (fdp.ConsumeBool()) {
        outputConfiguration = new OutputConfiguration();
    } else {
        int32_t rotation = fdp.ConsumeIntegral<int32_t>();
        string physicalCameraId = fdp.ConsumeRandomLengthString();
        int32_t surfaceSetID = fdp.ConsumeIntegral<int32_t>();
        bool isShared = fdp.ConsumeBool();

        if (fdp.ConsumeBool()) {
            sp<IGraphicBufferProducer> iGBP = nullptr;
            sp<SurfaceComposerClient> composerClient = new SurfaceComposerClient;
            sp<SurfaceControl> surfaceControl = composerClient->createSurface(
                    static_cast<String8>(fdp.ConsumeRandomLengthString().c_str()) /* name */,
                    fdp.ConsumeIntegral<uint32_t>() /* width */,
                    fdp.ConsumeIntegral<uint32_t>() /* height */,
                    fdp.ConsumeIntegral<int32_t>() /* format */,
                    fdp.ConsumeIntegral<int32_t>() /* flags */);
            if (surfaceControl) {
                sp<Surface> surface = surfaceControl->getSurface();
                iGBP = surface->getIGraphicBufferProducer();
            }
            outputConfiguration = new OutputConfiguration(iGBP, rotation, physicalCameraId,
                                                          surfaceSetID, isShared);
            iGBP.clear();
            composerClient.clear();
            surfaceControl.clear();
        } else {
            size_t iGBPSize = fdp.ConsumeIntegralInRange<size_t>(kSizeMin, kSizeMax);
            vector<sp<IGraphicBufferProducer>> iGBPs;
            for (size_t idx = 0; idx < iGBPSize; ++idx) {
                sp<IGraphicBufferProducer> iGBP = nullptr;
                sp<SurfaceComposerClient> composerClient = new SurfaceComposerClient;
                sp<SurfaceControl> surfaceControl = composerClient->createSurface(
                        static_cast<String8>(fdp.ConsumeRandomLengthString().c_str()) /* name */,
                        fdp.ConsumeIntegral<uint32_t>() /* width */,
                        fdp.ConsumeIntegral<uint32_t>() /* height */,
                        fdp.ConsumeIntegral<int32_t>() /* format */,
                        fdp.ConsumeIntegral<int32_t>() /* flags */);
                if (surfaceControl) {
                    sp<Surface> surface = surfaceControl->getSurface();
                    iGBP = surface->getIGraphicBufferProducer();
                    iGBPs.push_back(iGBP);
                }
                iGBP.clear();
                composerClient.clear();
                surfaceControl.clear();
            }
            outputConfiguration = new OutputConfiguration(iGBPs, rotation, physicalCameraId,
                                                          surfaceSetID, isShared);
        }
    }

    outputConfiguration->getRotation();
    outputConfiguration->getSurfaceSetID();
    outputConfiguration->getSurfaceType();
    outputConfiguration->getWidth();
    outputConfiguration->getHeight();
    outputConfiguration->isDeferred();
    outputConfiguration->isShared();
    outputConfiguration->getPhysicalCameraId();

    OutputConfiguration outputConfiguration2;
    outputConfiguration->gbpsEqual(outputConfiguration2);
    outputConfiguration->sensorPixelModesUsedEqual(outputConfiguration2);
    outputConfiguration->gbpsLessThan(outputConfiguration2);
    outputConfiguration->sensorPixelModesUsedLessThan(outputConfiguration2);
    outputConfiguration->getGraphicBufferProducers();
    sp<IGraphicBufferProducer> gbp;
    outputConfiguration->addGraphicProducer(gbp);
    invokeReadWriteNullParcel<OutputConfiguration>(outputConfiguration);
    invokeReadWriteParcel<OutputConfiguration>(outputConfiguration);
    delete outputConfiguration;
    return 0;
}
