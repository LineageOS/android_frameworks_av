/*
 * Copyright (C) 2020 The Android Open Source Project
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
#ifndef ANDROID_SERVERS_CAMERA_SESSION_CONFIGURATION_UTILS_H
#define ANDROID_SERVERS_CAMERA_SESSION_CONFIGURATION_UTILS_H

#include <android/hardware/camera2/BnCameraDeviceUser.h>
#include <android/hardware/camera2/ICameraDeviceCallbacks.h>
#include <camera/camera2/OutputConfiguration.h>
#include <camera/camera2/SessionConfiguration.h>
#include <camera/camera2/SubmitInfo.h>
#include <android/hardware/camera/device/3.4/ICameraDeviceSession.h>

#include <hardware/camera3.h>
#include <device3/Camera3StreamInterface.h>

#include <stdint.h>

namespace android {

typedef std::function<CameraMetadata (const String8 &)> metadataGetter;

class SessionConfigurationUtils {
public:

    static int64_t euclidDistSquare(int32_t x0, int32_t y0, int32_t x1, int32_t y1);

    // Find the closest dimensions for a given format in available stream configurations with
    // a width <= ROUNDING_WIDTH_CAP
    static bool roundBufferDimensionNearest(int32_t width, int32_t height, int32_t format,
            android_dataspace dataSpace, const CameraMetadata& info,
            /*out*/int32_t* outWidth, /*out*/int32_t* outHeight);

    //check if format is not custom format
    static bool isPublicFormat(int32_t format);

    // Create a Surface from an IGraphicBufferProducer. Returns error if
    // IGraphicBufferProducer's property doesn't match with streamInfo
    static binder::Status createSurfaceFromGbp(
        camera3::OutputStreamInfo& streamInfo, bool isStreamInfoValid,
        sp<Surface>& surface, const sp<IGraphicBufferProducer>& gbp,
        const String8 &cameraId, const CameraMetadata &physicalCameraMetadata);

    static void mapStreamInfo(const camera3::OutputStreamInfo &streamInfo,
            camera3_stream_rotation_t rotation, String8 physicalId,
            hardware::camera::device::V3_4::Stream *stream /*out*/);

    // Check that the physicalCameraId passed in is spported by the camera
    // device.
    static binder::Status checkPhysicalCameraId(
        const std::vector<std::string> &physicalCameraIds, const String8 &physicalCameraId,
        const String8 &logicalCameraId);

    static binder::Status checkSurfaceType(size_t numBufferProducers,
        bool deferredConsumer, int surfaceType);

    static binder::Status checkOperatingMode(int operatingMode,
        const CameraMetadata &staticInfo, const String8 &cameraId);

    // utility function to convert AIDL SessionConfiguration to HIDL
    // streamConfiguration. Also checks for validity of SessionConfiguration and
    // returns a non-ok binder::Status if the passed in session configuration
    // isn't valid.
    static binder::Status
    convertToHALStreamCombination(const SessionConfiguration& sessionConfiguration,
            const String8 &cameraId, const CameraMetadata &deviceInfo,
            metadataGetter getMetadata, const std::vector<std::string> &physicalCameraIds,
            hardware::camera::device::V3_4::StreamConfiguration &streamConfiguration,
            bool *earlyExit);

    static const int32_t MAX_SURFACES_PER_STREAM = 4;

    static const int32_t ROUNDING_WIDTH_CAP = 1920;
};

} // android
#endif
