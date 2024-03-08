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

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    FuzzedDataProvider fdp = FuzzedDataProvider(data, size);

    SessionConfiguration* sessionConfiguration = nullptr;

    if (fdp.ConsumeBool()) {
        sessionConfiguration = new SessionConfiguration();
    } else {
        int32_t inputWidth = fdp.ConsumeIntegral<int32_t>();
        int32_t inputHeight = fdp.ConsumeIntegral<int32_t>();
        int32_t inputFormat = fdp.ConsumeIntegral<int32_t>();
        int32_t operatingMode = fdp.ConsumeIntegral<int32_t>();
        sessionConfiguration =
                new SessionConfiguration(inputWidth, inputHeight, inputFormat, operatingMode);
    }

    sessionConfiguration->getInputWidth();
    sessionConfiguration->getInputHeight();
    sessionConfiguration->getInputFormat();
    sessionConfiguration->getOperatingMode();

    OutputConfiguration* outputConfiguration = nullptr;

    if (fdp.ConsumeBool()) {
        outputConfiguration = new OutputConfiguration();
        sessionConfiguration->addOutputConfiguration(*outputConfiguration);
    } else {
        sp<IGraphicBufferProducer> iGBP = nullptr;
        sp<SurfaceComposerClient> composerClient = new SurfaceComposerClient;
        sp<SurfaceControl> surfaceControl = composerClient->createSurface(
                static_cast<String8>(fdp.ConsumeRandomLengthString().c_str()),
                fdp.ConsumeIntegral<uint32_t>(), fdp.ConsumeIntegral<uint32_t>(),
                fdp.ConsumeIntegral<int32_t>(), fdp.ConsumeIntegral<int32_t>());
        if (surfaceControl) {
            sp<Surface> surface = surfaceControl->getSurface();
            iGBP = surface->getIGraphicBufferProducer();
            surface.clear();
        }
        int32_t rotation = fdp.ConsumeIntegral<int32_t>();
        string physicalCameraId = fdp.ConsumeRandomLengthString();
        int32_t surfaceSetID = fdp.ConsumeIntegral<int32_t>();
        bool isShared = fdp.ConsumeBool();
        outputConfiguration =
                new OutputConfiguration(iGBP, rotation, physicalCameraId, surfaceSetID, isShared);
        sessionConfiguration->addOutputConfiguration(*outputConfiguration);
    }

    sessionConfiguration->getOutputConfigurations();
    SessionConfiguration sessionConfiguration2;
    sessionConfiguration->outputsEqual(sessionConfiguration2);
    sessionConfiguration->outputsLessThan(sessionConfiguration2);
    sessionConfiguration->inputIsMultiResolution();

    invokeReadWriteNullParcel<SessionConfiguration>(sessionConfiguration);
    invokeReadWriteParcel<SessionConfiguration>(sessionConfiguration);

    delete sessionConfiguration;
    delete outputConfiguration;
    return 0;
}
