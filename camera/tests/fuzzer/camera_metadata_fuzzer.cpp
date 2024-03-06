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
#include "camera2common.h"

using namespace std;
using namespace android;
using namespace android::hardware;

constexpr int32_t kSizeMin = 0;
constexpr int32_t kSizeMax = 1000;
constexpr int32_t kMinMetadataCapacity = 0;
constexpr int32_t kMaxMetadataCapacity = 1000;
constexpr int32_t kRangeMin = 0;
constexpr int32_t kRangeMax = 1000;

class CameraMetadataFuzzer {
  public:
    void process(const uint8_t* data, size_t size);

  private:
    void initCameraMetadata();
    void invokeCameraMetadata();
    CameraMetadata* mCameraMetadata = nullptr;
    FuzzedDataProvider* mFDP = nullptr;
    camera_metadata* mMetaBuffer = nullptr;
    bool mMetadataLocked = false;
    template <typename T>
    void callCameraMetadataUpdate(size_t dataCount, T data) {
        uint32_t tag = mFDP->ConsumeIntegral<uint32_t>();
        mCameraMetadata->update(tag, &data, dataCount);
    }
};

void CameraMetadataFuzzer::initCameraMetadata() {
    auto selectMetadataConstructor = mFDP->PickValueInArray<const std::function<void()>>({
            [&]() {
                mMetaBuffer = allocate_camera_metadata(
                        mFDP->ConsumeIntegralInRange<size_t>(
                                kMinMetadataCapacity, kMaxMetadataCapacity) /* entry_capacity */,
                        mFDP->ConsumeIntegralInRange<size_t>(
                                kMinMetadataCapacity, kMaxMetadataCapacity) /* data_capacity */);
                mCameraMetadata = new CameraMetadata(mMetaBuffer);
            },
            [&]() {
                mCameraMetadata = new CameraMetadata();
            },
            [&]() {
                size_t entryCapacity = mFDP->ConsumeIntegralInRange<size_t>(kSizeMin, kSizeMax);
                size_t dataCapacity = mFDP->ConsumeIntegralInRange<size_t>(kSizeMin, kSizeMax);
                mCameraMetadata = new CameraMetadata(entryCapacity, dataCapacity);
            },
    });
    selectMetadataConstructor();
}
void CameraMetadataFuzzer::invokeCameraMetadata() {
    initCameraMetadata();

    const camera_metadata_t* metadataBuffer = nullptr;
    mMetadataLocked = mFDP->ConsumeBool();
    if (mMetadataLocked) {
        metadataBuffer = mCameraMetadata->getAndLock();
    }

    size_t dataCount = 1;
    while (mFDP->remaining_bytes()) {
        auto callMetadataAPIs = mFDP->PickValueInArray<const std::function<void()>>({

                [&]() { mCameraMetadata->entryCount(); },
                [&]() { mCameraMetadata->isEmpty(); },
                [&]() { mCameraMetadata->bufferSize(); },
                [&]() { mCameraMetadata->sort(); },
                [&]() {
                    uint8_t dataUint8 = mFDP->ConsumeIntegral<uint8_t>();
                    callCameraMetadataUpdate(dataCount, dataUint8);
                },
                [&]() {
                    int32_t dataInt32 = mFDP->ConsumeIntegral<int32_t>();
                    callCameraMetadataUpdate(dataCount, dataInt32);
                },
                [&]() {
                    int64_t dataInt64 = mFDP->ConsumeIntegral<int64_t>();
                    callCameraMetadataUpdate(dataCount, dataInt64);
                },
                [&]() {
                    float dataFloat = mFDP->ConsumeFloatingPoint<float>();
                    callCameraMetadataUpdate(dataCount, dataFloat);
                },
                [&]() {
                    double dataDouble = mFDP->ConsumeFloatingPoint<double>();
                    callCameraMetadataUpdate(dataCount, dataDouble);
                },
                [&]() {
                    camera_metadata_rational dataRational;
                    dataRational.numerator = mFDP->ConsumeIntegral<int32_t>();
                    dataRational.denominator = mFDP->ConsumeIntegral<int32_t>();
                    callCameraMetadataUpdate(dataCount, dataRational);
                },
                [&]() {
                    uint32_t tag = mFDP->ConsumeIntegral<uint32_t>();
                    string dataStr = mFDP->ConsumeRandomLengthString(kMaxBytes);
                    String8 dataString(dataStr.c_str());
                    mCameraMetadata->update(tag, dataString);
                },
                [&]() {
                    uint32_t tag = mFDP->ConsumeIntegral<uint32_t>();
                    uint32_t tagExists =
                            mFDP->ConsumeBool() ? tag : mFDP->ConsumeIntegral<uint32_t>();
                    mCameraMetadata->exists(tagExists);
                },
                [&]() {
                    uint32_t tag = mFDP->ConsumeIntegral<uint32_t>();
                    uint32_t tagFind =
                            mFDP->ConsumeBool() ? tag : mFDP->ConsumeIntegral<uint32_t>();
                    mCameraMetadata->find(tagFind);
                },
                [&]() {
                    uint32_t tag = mFDP->ConsumeIntegral<uint32_t>();
                    uint32_t tagErase =
                            mFDP->ConsumeBool() ? tag : mFDP->ConsumeIntegral<uint32_t>();
                    mCameraMetadata->erase(tagErase);
                },
                [&]() { mCameraMetadata->unlock(metadataBuffer); },
                [&]() {
                    std::vector<int32_t> tagsRemoved;
                    uint64_t vendorId = mFDP->ConsumeIntegral<uint64_t>();
                    mCameraMetadata->removePermissionEntries(vendorId, &tagsRemoved);
                },
                [&]() {
                    string name = mFDP->ConsumeRandomLengthString(kMaxBytes);
                    VendorTagDescriptor vTags;
                    uint32_t tagName = mFDP->ConsumeIntegral<uint32_t>();
                    mCameraMetadata->getTagFromName(name.c_str(), &vTags, &tagName);
                },
                [&]() {
                    int32_t fd = open("/dev/null", O_CLOEXEC | O_RDWR | O_CREAT);
                    int32_t verbosity = mFDP->ConsumeIntegralInRange<int32_t>(kRangeMin, kRangeMax);
                    int32_t indentation =
                            mFDP->ConsumeIntegralInRange<int32_t>(kRangeMin, kRangeMax);
                    mCameraMetadata->dump(fd, verbosity, indentation);
                    close(fd);
                },
                [&]() { CameraMetadata metadataCopy(mCameraMetadata->release()); },
                [&]() {
                    if (mFDP->ConsumeBool()) {
                        CameraMetadata otherCameraMetadata;
                        mCameraMetadata->swap(otherCameraMetadata);
                    } else {
                        std::vector<int8_t> entryCapacityVector =
                                mFDP->ConsumeBytes<int8_t>(kMaxBytes);
                        /**
                         * Resizing vector to a size between 1 to 1000 so that vector is not empty.
                         */
                        entryCapacityVector.resize(0, mFDP->ConsumeIntegralInRange<int32_t>(
                                                              kMinCapacity, kMaxCapacity));
                        CameraMetadata otherCameraMetadata(entryCapacityVector.size());
                        mCameraMetadata->swap(otherCameraMetadata);
                    }
                },
                [&]() {
                    if (!mMetadataLocked) {
                        camera_metadata* metaBuffer = allocate_camera_metadata(
                                mFDP->ConsumeIntegralInRange<size_t>(
                                        kMinMetadataCapacity,
                                        kMaxMetadataCapacity) /* entry_capacity */,
                                mFDP->ConsumeIntegralInRange<size_t>(
                                        kMinMetadataCapacity,
                                        kMaxMetadataCapacity) /* data_capacity */);
                        mCameraMetadata->acquire(metaBuffer);
                    }
                },
                [&]() {
                    if (!mMetadataLocked) {
                        camera_metadata* metaBuffer = allocate_camera_metadata(
                                mFDP->ConsumeIntegralInRange<size_t>(
                                        kMinMetadataCapacity,
                                        kMaxMetadataCapacity) /* entry_capacity */,
                                mFDP->ConsumeIntegralInRange<size_t>(
                                        kMinMetadataCapacity,
                                        kMaxMetadataCapacity) /* data_capacity */);
                        mCameraMetadata->append(metaBuffer);
                        free_camera_metadata(metaBuffer);
                    }
                },
        });
        callMetadataAPIs();

        // Not keeping invokeReadWrite() APIs in while loop to avoid possible OOM.
        invokeReadWriteNullParcel<CameraMetadata>(mCameraMetadata);
        if (mFDP->ConsumeBool()) {
            invokeReadWriteParcel<CameraMetadata>(mCameraMetadata);
        } else {
            invokeNewReadWriteParcel<CameraMetadata>(mCameraMetadata, *mFDP);
        }
    }
    delete mCameraMetadata;
}

void CameraMetadataFuzzer::process(const uint8_t* data, size_t size) {
    mFDP = new FuzzedDataProvider(data, size);
    invokeCameraMetadata();
    delete mFDP;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    CameraMetadataFuzzer cameraMetadataFuzzer;
    cameraMetadataFuzzer.process(data, size);
    return 0;
}
