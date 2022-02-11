/*
 * Copyright (C) 2014 The Android Open Source Project
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

#define LOG_TAG "CameraUtils"
//#define LOG_NDEBUG 0

#include <camera/CameraUtils.h>
#include <camera/camera2/OutputConfiguration.h>
#include <media/hardware/HardwareAPI.h>

#include <android-base/properties.h>
#include <system/window.h>
#include <system/graphics.h>

#include <utils/Log.h>

namespace android {

const char *kCameraServiceDisabledProperty = "config.disable_cameraservice";

status_t CameraUtils::getRotationTransform(const CameraMetadata& staticInfo,
        int mirrorMode, /*out*/int32_t* transform) {
    ALOGV("%s", __FUNCTION__);

    if (transform == NULL) {
        ALOGW("%s: null transform", __FUNCTION__);
        return BAD_VALUE;
    }

    *transform = 0;

    camera_metadata_ro_entry_t entry = staticInfo.find(ANDROID_SENSOR_ORIENTATION);
    if (entry.count == 0) {
        ALOGE("%s: Can't find android.sensor.orientation in static metadata!", __FUNCTION__);
        return INVALID_OPERATION;
    }

    camera_metadata_ro_entry_t entryFacing = staticInfo.find(ANDROID_LENS_FACING);
    if (entryFacing.count == 0) {
        ALOGE("%s: Can't find android.lens.facing in static metadata!", __FUNCTION__);
        return INVALID_OPERATION;
    }

    int32_t& flags = *transform;

    int32_t mirror = 0;
    if (mirrorMode == OutputConfiguration::MIRROR_MODE_AUTO &&
            entryFacing.data.u8[0] == ANDROID_LENS_FACING_FRONT) {
        mirror = NATIVE_WINDOW_TRANSFORM_FLIP_H;
    } else if (mirrorMode == OutputConfiguration::MIRROR_MODE_H) {
        mirror = NATIVE_WINDOW_TRANSFORM_FLIP_H;
    } else if (mirrorMode == OutputConfiguration::MIRROR_MODE_V) {
        mirror = NATIVE_WINDOW_TRANSFORM_FLIP_V;
    }

    int orientation = entry.data.i32[0];
    if (mirror == 0) {
        switch (orientation) {
            case 0:
                flags = 0;
                break;
            case 90:
                flags = NATIVE_WINDOW_TRANSFORM_ROT_90;
                break;
            case 180:
                flags = NATIVE_WINDOW_TRANSFORM_ROT_180;
                break;
            case 270:
                flags = NATIVE_WINDOW_TRANSFORM_ROT_270;
                break;
            default:
                ALOGE("%s: Invalid HAL android.sensor.orientation value: %d",
                      __FUNCTION__, orientation);
                return INVALID_OPERATION;
        }
    } else {
        // - Front camera needs to be horizontally flipped for mirror-like behavior.
        // - Application-specified mirroring needs to be applied.
        // Note: Flips are applied before rotates; using XOR here as some of these flags are
        // composed in terms of other flip/rotation flags, and are not bitwise-ORable.
        switch (orientation) {
            case 0:
                flags = mirror;
                break;
            case 90:
                flags = mirror ^
                        NATIVE_WINDOW_TRANSFORM_ROT_270;
                break;
            case 180:
                flags = mirror ^
                        NATIVE_WINDOW_TRANSFORM_ROT_180;
                break;
            case 270:
                flags = mirror ^
                        NATIVE_WINDOW_TRANSFORM_ROT_90;
                break;
            default:
                ALOGE("%s: Invalid HAL android.sensor.orientation value: %d",
                      __FUNCTION__, orientation);
                return INVALID_OPERATION;
        }

    }

    /**
     * This magic flag makes surfaceflinger un-rotate the buffers
     * to counter the extra global device UI rotation whenever the user
     * physically rotates the device.
     *
     * By doing this, the camera buffer always ends up aligned
     * with the physical camera for a "see through" effect.
     *
     * In essence, the buffer only gets rotated during preview use-cases.
     * The user is still responsible to re-create streams of the proper
     * aspect ratio, or the preview will end up looking non-uniformly
     * stretched.
     */
    flags |= NATIVE_WINDOW_TRANSFORM_INVERSE_DISPLAY;

    ALOGV("%s: final transform = 0x%x", __FUNCTION__, flags);

    return OK;
}

bool CameraUtils::isCameraServiceDisabled() {
    return base::GetBoolProperty(kCameraServiceDisabledProperty, false);
}

} /* namespace android */
