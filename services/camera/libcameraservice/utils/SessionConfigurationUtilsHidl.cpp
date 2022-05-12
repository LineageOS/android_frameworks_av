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

#include <cutils/properties.h>

#include "SessionConfigurationUtils.h"
#include "SessionConfigurationUtilsHidl.h"

#include "../CameraService.h"
#include "device3/aidl/AidlCamera3Device.h"
#include "device3/hidl/HidlCamera3Device.h"
#include "device3/Camera3OutputStream.h"

using android::camera3::OutputStreamInfo;
using android::hardware::camera2::ICameraDeviceUser;
using android::hardware::camera::metadata::V3_6::CameraMetadataEnumAndroidSensorPixelMode;
using android::hardware::camera::metadata::V3_8::CameraMetadataEnumAndroidRequestAvailableDynamicRangeProfilesMap;
using android::hardware::camera::metadata::V3_8::CameraMetadataEnumAndroidScalerAvailableStreamUseCases;

namespace android {
namespace camera3 {

namespace SessionConfigurationUtils {

status_t
convertAidlToHidl38StreamCombination(
        const aidl::android::hardware::camera::device::StreamConfiguration &aidl,
        hardware::camera::device::V3_8::StreamConfiguration &hidl) {
    hidl.operationMode =
        static_cast<hardware::camera::device::V3_2::StreamConfigurationMode>(aidl.operationMode);
    if (aidl.streamConfigCounter < 0) {
        return BAD_VALUE;
    }
    hidl.streamConfigCounter = static_cast<uint32_t>(aidl.streamConfigCounter);
    hidl.multiResolutionInputImage = aidl.multiResolutionInputImage;
    hidl.sessionParams = aidl.sessionParams.metadata;
    hidl.streams.resize(aidl.streams.size());
    size_t i = 0;
    for (const auto &stream : aidl.streams) {
        //hidlv3_8
        hidl.streams[i].dynamicRangeProfile =
                static_cast<
                        CameraMetadataEnumAndroidRequestAvailableDynamicRangeProfilesMap>
                                (stream.dynamicRangeProfile);
        hidl.streams[i].useCase =
                static_cast<
                        CameraMetadataEnumAndroidScalerAvailableStreamUseCases>
                                (stream.useCase);

        // hidl v3_7
        hidl.streams[i].v3_7.groupId = stream.groupId;
        hidl.streams[i].v3_7.sensorPixelModesUsed.resize(stream.sensorPixelModesUsed.size());
        size_t j = 0;
        for (const auto &mode : stream.sensorPixelModesUsed) {
            hidl.streams[i].v3_7.sensorPixelModesUsed[j] =
                    static_cast<CameraMetadataEnumAndroidSensorPixelMode>(mode);
            j++;
        }

        //hidl v3_4
        hidl.streams[i].v3_7.v3_4.physicalCameraId = stream.physicalCameraId;

        if (stream.bufferSize < 0) {
            return BAD_VALUE;
        }
        hidl.streams[i].v3_7.v3_4.bufferSize = static_cast<uint32_t>(stream.bufferSize);

        // hild v3_2
        hidl.streams[i].v3_7.v3_4.v3_2.id = stream.id;
        hidl.streams[i].v3_7.v3_4.v3_2.format =
                static_cast<hardware::graphics::common::V1_0::PixelFormat>(stream.format);

        if (stream.width < 0 || stream.height < 0) {
            return BAD_VALUE;
        }
        hidl.streams[i].v3_7.v3_4.v3_2.width = static_cast<uint32_t>(stream.width);
        hidl.streams[i].v3_7.v3_4.v3_2.height = static_cast<uint32_t>(stream.height);
        hidl.streams[i].v3_7.v3_4.v3_2.usage =
                static_cast<hardware::camera::device::V3_2::BufferUsageFlags>(stream.usage);
        hidl.streams[i].v3_7.v3_4.v3_2.streamType =
                static_cast<hardware::camera::device::V3_2::StreamType>(stream.streamType);
        hidl.streams[i].v3_7.v3_4.v3_2.dataSpace =
                static_cast<hardware::camera::device::V3_2::DataspaceFlags>(stream.dataSpace);
        hidl.streams[i].v3_7.v3_4.v3_2.rotation =
                static_cast<hardware::camera::device::V3_2::StreamRotation>(stream.rotation);
        i++;
    }
    return OK;
}

void mapStreamInfo(const OutputStreamInfo &streamInfo,
            camera3::camera_stream_rotation_t rotation, String8 physicalId,
            int32_t groupId, hardware::camera::device::V3_8::Stream *stream /*out*/) {
    if (stream == nullptr) {
        return;
    }

    stream->v3_7.v3_4.v3_2.streamType = hardware::camera::device::V3_2::StreamType::OUTPUT;
    stream->v3_7.v3_4.v3_2.width = streamInfo.width;
    stream->v3_7.v3_4.v3_2.height = streamInfo.height;
    stream->v3_7.v3_4.v3_2.format = HidlCamera3Device::mapToPixelFormat(streamInfo.format);
    auto u = streamInfo.consumerUsage;
    camera3::Camera3OutputStream::applyZSLUsageQuirk(streamInfo.format, &u);
    stream->v3_7.v3_4.v3_2.usage = HidlCamera3Device::mapToConsumerUsage(u);
    stream->v3_7.v3_4.v3_2.dataSpace = HidlCamera3Device::mapToHidlDataspace(streamInfo.dataSpace);
    stream->v3_7.v3_4.v3_2.rotation = HidlCamera3Device::mapToStreamRotation(rotation);
    stream->v3_7.v3_4.v3_2.id = -1; // Invalid stream id
    stream->v3_7.v3_4.physicalCameraId = std::string(physicalId.string());
    stream->v3_7.v3_4.bufferSize = 0;
    stream->v3_7.groupId = groupId;
    stream->v3_7.sensorPixelModesUsed.resize(streamInfo.sensorPixelModesUsed.size());

    size_t idx = 0;
    for (auto mode : streamInfo.sensorPixelModesUsed) {
        stream->v3_7.sensorPixelModesUsed[idx++] =
                static_cast<CameraMetadataEnumAndroidSensorPixelMode>(mode);
    }
    stream->dynamicRangeProfile =
        static_cast<CameraMetadataEnumAndroidRequestAvailableDynamicRangeProfilesMap> (
                streamInfo.dynamicRangeProfile);
    stream->useCase = static_cast<CameraMetadataEnumAndroidScalerAvailableStreamUseCases>(
            streamInfo.streamUseCase);
}

binder::Status
convertToHALStreamCombination(
        const SessionConfiguration& sessionConfiguration,
        const String8 &logicalCameraId, const CameraMetadata &deviceInfo,
        metadataGetter getMetadata, const std::vector<std::string> &physicalCameraIds,
        hardware::camera::device::V3_8::StreamConfiguration &streamConfiguration,
        bool overrideForPerfClass, bool *earlyExit) {
    aidl::android::hardware::camera::device::StreamConfiguration aidlStreamConfiguration;
    auto ret = convertToHALStreamCombination(sessionConfiguration, logicalCameraId, deviceInfo,
            getMetadata, physicalCameraIds, aidlStreamConfiguration, overrideForPerfClass,
            earlyExit);
    if (!ret.isOk()) {
        return ret;
    }
    if (earlyExit != nullptr && *earlyExit) {
        return binder::Status::ok();
    }

    if (convertAidlToHidl38StreamCombination(aidlStreamConfiguration, streamConfiguration) != OK) {
        return STATUS_ERROR(CameraService::ERROR_ILLEGAL_ARGUMENT,
                "Invalid AIDL->HIDL3.8 conversion");
    }

    return binder::Status::ok();
}

bool convertHALStreamCombinationFromV38ToV37(
        hardware::camera::device::V3_7::StreamConfiguration &streamConfigV37,
        const hardware::camera::device::V3_8::StreamConfiguration &streamConfigV38) {
    streamConfigV37.streams.resize(streamConfigV38.streams.size());
    for (size_t i = 0; i < streamConfigV38.streams.size(); i++) {
        if (static_cast<int64_t>(streamConfigV38.streams[i].dynamicRangeProfile) !=
                ANDROID_REQUEST_AVAILABLE_DYNAMIC_RANGE_PROFILES_MAP_STANDARD) {
            // ICameraDevice older than 3.8 doesn't support 10-bit dynamic range profiles
            // image
            return false;
        }
        if (static_cast<int64_t>(streamConfigV38.streams[i].useCase) !=
                ANDROID_SCALER_AVAILABLE_STREAM_USE_CASES_DEFAULT) {
            // ICameraDevice older than 3.8 doesn't support stream use case
            return false;
        }
        streamConfigV37.streams[i] = streamConfigV38.streams[i].v3_7;
    }
    streamConfigV37.operationMode = streamConfigV38.operationMode;
    streamConfigV37.sessionParams = streamConfigV38.sessionParams;

    return true;
}

bool convertHALStreamCombinationFromV37ToV34(
        hardware::camera::device::V3_4::StreamConfiguration &streamConfigV34,
        const hardware::camera::device::V3_7::StreamConfiguration &streamConfigV37) {
    if (streamConfigV37.multiResolutionInputImage) {
        // ICameraDevice older than 3.7 doesn't support multi-resolution input image.
        return false;
    }

    streamConfigV34.streams.resize(streamConfigV37.streams.size());
    for (size_t i = 0; i < streamConfigV37.streams.size(); i++) {
        if (streamConfigV37.streams[i].groupId != -1) {
            // ICameraDevice older than 3.7 doesn't support multi-resolution output
            // image
            return false;
        }
        streamConfigV34.streams[i] = streamConfigV37.streams[i].v3_4;
    }
    streamConfigV34.operationMode = streamConfigV37.operationMode;
    streamConfigV34.sessionParams = streamConfigV37.sessionParams;

    return true;
}

} // namespace SessionConfigurationUtils
} // namespace camera3
} // namespace android
