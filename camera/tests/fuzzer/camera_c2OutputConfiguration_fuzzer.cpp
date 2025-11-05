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
#include <gui/Surface.h>
#include <gui/Flags.h>  // remove with WB_LIBCAMERASERVICE_WITH_DEPENDENCIES
#include <gui/SurfaceComposerClient.h>
#include "camera2common.h"

using namespace std;
using namespace android;
using namespace android::hardware::camera2::params;

constexpr int8_t kMaxLoopIterations = 100;
constexpr int32_t kSizeMin = 0;
constexpr int32_t kSizeMax = 1000;

class C2OutputConfigurationFuzzer {
  public:
    void process(const uint8_t* data, size_t size);

  private:
    void invokeC2OutputConfigFuzzer();
    unique_ptr<OutputConfiguration> getC2OutputConfig();
    sp<SurfaceType> createSurface();
    FuzzedDataProvider* mFDP = nullptr;
};

sp<SurfaceType> C2OutputConfigurationFuzzer::createSurface() {
    sp<SurfaceComposerClient> composerClient = new SurfaceComposerClient;
    sp<SurfaceControl> surfaceControl = composerClient->createSurface(
            static_cast<String8>(mFDP->ConsumeRandomLengthString(kMaxBytes).c_str()) /* name */,
            mFDP->ConsumeIntegral<uint32_t>() /* width */,
            mFDP->ConsumeIntegral<uint32_t>() /* height */,
            mFDP->ConsumeIntegral<int32_t>() /* format */,
            mFDP->ConsumeIntegral<int32_t>() /* flags */);
    if (surfaceControl) {
        sp<Surface> surface = surfaceControl->getSurface();
        return flagtools::surfaceToSurfaceType(surface);
    } else {
        return nullptr;
    }
}

unique_ptr<OutputConfiguration> C2OutputConfigurationFuzzer::getC2OutputConfig() {
    unique_ptr<OutputConfiguration> outputConfiguration = nullptr;
    auto selectOutputConfigurationConstructor =
            mFDP->PickValueInArray<const std::function<void()>>({
                    [&]() { outputConfiguration = make_unique<OutputConfiguration>(); },

                    [&]() {
                        int32_t rotation = mFDP->ConsumeIntegral<int32_t>();
                        string physicalCameraId = mFDP->ConsumeRandomLengthString(kMaxBytes);
                        int32_t surfaceSetID = mFDP->ConsumeIntegral<int32_t>();
                        bool isShared = mFDP->ConsumeBool();
                        sp<SurfaceType> surface = createSurface();
                        ParcelableSurfaceType pSurface =
                            flagtools::convertSurfaceTypeToParcelable(surface);
                        outputConfiguration = make_unique<OutputConfiguration>(
                                pSurface, rotation, physicalCameraId, surfaceSetID, isShared);
                    },

                    [&]() {
                        int32_t rotation = mFDP->ConsumeIntegral<int32_t>();
                        string physicalCameraId = mFDP->ConsumeRandomLengthString(kMaxBytes);
                        int32_t surfaceSetID = mFDP->ConsumeIntegral<int32_t>();
                        bool isShared = mFDP->ConsumeBool();
                        size_t surfaceSize =
                                mFDP->ConsumeIntegralInRange<size_t>(kSizeMin, kSizeMax);
                        vector<ParcelableSurfaceType> surfaces;
                        for (size_t idx = 0; idx < surfaceSize; ++idx) {
                            sp<SurfaceType> surface = createSurface();
                            ParcelableSurfaceType pSurface =
                                flagtools::convertSurfaceTypeToParcelable(surface);
                            surfaces.push_back(pSurface);
                        }
                        outputConfiguration = make_unique<OutputConfiguration>(
                                surfaces, rotation, physicalCameraId, surfaceSetID, isShared);
                    },
            });
    selectOutputConfigurationConstructor();
    return outputConfiguration;
}

void C2OutputConfigurationFuzzer::invokeC2OutputConfigFuzzer() {
    unique_ptr<OutputConfiguration> outputConfiguration = getC2OutputConfig();
    int8_t count = kMaxLoopIterations;
    while (--count > 0) {
    unique_ptr<OutputConfiguration> outputConfiguration2 = getC2OutputConfig();
        auto callC2OutputConfAPIs = mFDP->PickValueInArray<const std::function<void()>>({
                [&]() { outputConfiguration->getRotation(); },
                [&]() { outputConfiguration->getSurfaceSetID(); },
                [&]() { outputConfiguration->getSurfaceType(); },
                [&]() { outputConfiguration->getWidth(); },
                [&]() { outputConfiguration->getHeight(); },
                [&]() { outputConfiguration->isDeferred(); },
                [&]() { outputConfiguration->isShared(); },
                [&]() { outputConfiguration->getPhysicalCameraId(); },
                [&]() { outputConfiguration->surfacesEqual(*outputConfiguration2); },
                [&]() { outputConfiguration->sensorPixelModesUsedEqual(*outputConfiguration2); },
                [&]() { outputConfiguration->surfacesLessThan(*outputConfiguration2); },
                [&]() { outputConfiguration->sensorPixelModesUsedLessThan(*outputConfiguration2); },
                [&]() { outputConfiguration->getSurfaces(); },
                [&]() {
                    sp<SurfaceType> surface = createSurface();
                    ParcelableSurfaceType pSurface =
                        flagtools::convertSurfaceTypeToParcelable(surface);
                    outputConfiguration->addSurface(pSurface);
                },
                [&]() { outputConfiguration->getMultiResMode(); },
                [&]() { outputConfiguration->getColorSpace(); },
                [&]() { outputConfiguration->getStreamUseCase(); },
                [&]() { outputConfiguration->getTimestampBase(); },
                [&]() {
                    sp<SurfaceType> surface = createSurface();
                    ParcelableSurfaceType pSurface =
                        flagtools::convertSurfaceTypeToParcelable(surface);
                    outputConfiguration->getMirrorMode(pSurface);
                },
                [&]() { outputConfiguration->useReadoutTimestamp(); },
        });
        callC2OutputConfAPIs();
    }
    // Not keeping invokeReadWrite() APIs in while loop to avoid possible OOM.
    invokeReadWriteNullParcel<OutputConfiguration>(outputConfiguration.get());
    if (mFDP->ConsumeBool()) {
        invokeReadWriteParcel<OutputConfiguration>(outputConfiguration.get());
    } else {
        invokeNewReadWriteParcel<OutputConfiguration>(outputConfiguration.get(), *mFDP);
    }
}

void C2OutputConfigurationFuzzer::process(const uint8_t* data, size_t size) {
    mFDP = new FuzzedDataProvider(data, size);
    invokeC2OutputConfigFuzzer();
    delete mFDP;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    C2OutputConfigurationFuzzer c2OutputConfigurationFuzzer;
    c2OutputConfigurationFuzzer.process(data, size);
    return 0;
}
