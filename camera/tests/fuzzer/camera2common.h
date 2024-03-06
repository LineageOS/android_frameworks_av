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
#ifndef CAMERA2COMMON_H
#define CAMERA2COMMON_H

#include <CameraSessionStats.h>
#include <android-base/logging.h>
#include <binder/IServiceManager.h>
#include <binder/Parcel.h>
#include <fuzzbinder/random_binder.h>
#include <fuzzbinder/random_fd.h>
#include <fuzzbinder/random_parcel.h>
#include <fuzzer/FuzzedDataProvider.h>
#include <utils/String16.h>

using namespace android;

const std::string kFetchCameraService = "media.camera";

constexpr int8_t kMinIterations = 0;
constexpr int8_t kMaxIterations = 20;
constexpr int8_t kMinExtraFDs = 0;
constexpr int8_t kMinExtraBinder = 0;
constexpr int32_t kMaxFDs = 1000;
constexpr int32_t kMinBytes = 0;
constexpr int32_t kMaxBytes = 20;
constexpr int32_t kMinCapacity = 1;
constexpr int32_t kMaxCapacity = 1000;

const int32_t kValidFacing[] = {android::hardware::CameraSessionStats::CAMERA_FACING_BACK,
                                android::hardware::CameraSessionStats::CAMERA_FACING_FRONT};
const int32_t kValidOrientation[] = {0, 90, 180, 270};

void randomizeParcel(Parcel* parcel, FuzzedDataProvider& provider) {
    sp<IServiceManager> sm = defaultServiceManager();
    sp<IBinder> binder = sm->getService(String16(kFetchCameraService.c_str()));
    RandomParcelOptions options{
            .extraBinders = {binder},
            .extraFds = {},
    };

    auto retFds = parcel->debugReadAllFileDescriptors();
    for (size_t i = 0; i < retFds.size(); ++i) {
        options.extraFds.push_back(base::unique_fd(dup(retFds[i])));
    }
    int8_t iterations = provider.ConsumeIntegralInRange<int8_t>(kMinIterations, kMaxIterations);
    while (--iterations >= 0) {
        auto fillFunc = provider.PickValueInArray<const std::function<void()>>({
                // write data
                [&]() {
                    size_t toWrite = provider.ConsumeIntegralInRange<size_t>(kMinBytes, kMaxBytes);
                    std::vector<uint8_t> data = provider.ConsumeBytes<uint8_t>(toWrite);
                    CHECK(OK == parcel->write(data.data(), data.size()));
                },
                // write FD
                [&]() {
                    if (options.extraFds.size() > 0 && provider.ConsumeBool()) {
                        const base::unique_fd& fd =
                                options.extraFds.at(provider.ConsumeIntegralInRange<size_t>(
                                        kMinExtraFDs, options.extraFds.size() - 1));
                        CHECK(OK == parcel->writeFileDescriptor(fd.get(), false /*takeOwnership*/));
                    } else {
                        // b/260119717 - Adding more FDs can eventually lead to FD limit exhaustion
                        if (options.extraFds.size() > kMaxFDs) {
                            return;
                        }

                        std::vector<base::unique_fd> fds = getRandomFds(&provider);
                        CHECK(OK == parcel->writeFileDescriptor(fds.begin()->release(),
                                                                true /*takeOwnership*/));

                        options.extraFds.insert(options.extraFds.end(),
                                                std::make_move_iterator(fds.begin() + 1),
                                                std::make_move_iterator(fds.end()));
                    }
                },
                // write binder
                [&]() {
                    sp<IBinder> binder;
                    if (options.extraBinders.size() > 0 && provider.ConsumeBool()) {
                        binder = options.extraBinders.at(provider.ConsumeIntegralInRange<size_t>(
                                kMinExtraBinder, options.extraBinders.size() - 1));
                    } else {
                        binder = getRandomBinder(&provider);
                    }
                    CHECK(OK == parcel->writeStrongBinder(binder));
                },
        });
        fillFunc();
    }
}

template <class type>
void invokeReadWriteNullParcel(type* obj) {
    Parcel* parcelNull = nullptr;
    obj->writeToParcel(parcelNull);
    obj->readFromParcel(parcelNull);
}

template <class type>
void invokeReadWriteNullParcelsp(sp<type> obj) {
    Parcel* parcelNull = nullptr;
    obj->writeToParcel(parcelNull);
    obj->readFromParcel(parcelNull);
}

template <class type>
void invokeReadWriteParcel(type* obj) {
    Parcel* parcel = new Parcel();
    obj->writeToParcel(parcel);
    parcel->setDataPosition(0);
    obj->readFromParcel(parcel);
    delete parcel;
}

template <class type>
void invokeReadWriteParcelsp(sp<type> obj) {
    Parcel* parcel = new Parcel();
    obj->writeToParcel(parcel);
    parcel->setDataPosition(0);
    obj->readFromParcel(parcel);
    delete parcel;
}

template <class type>
void invokeNewReadWriteParcel(type* obj, FuzzedDataProvider& provider) {
    Parcel* parcel = new Parcel();
    obj->writeToParcel(parcel);
    randomizeParcel(parcel, provider);
    parcel->setDataPosition(0);
    obj->readFromParcel(parcel);
    delete parcel;
}

template <class type>
void invokeNewReadWriteParcelsp(sp<type> obj, FuzzedDataProvider& provider) {
    Parcel* parcel = new Parcel();
    obj->writeToParcel(parcel);
    randomizeParcel(parcel, provider);
    parcel->setDataPosition(0);
    obj->readFromParcel(parcel);
    delete parcel;
}

#endif  // CAMERA2COMMON_H
