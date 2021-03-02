/*
 * Copyright (C) 2019 The Android Open Source Project
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

#define LOG_TAG "Camera3-ZoomRatioMapper"
//#define LOG_NDEBUG 0

#include <algorithm>

#include "device3/ZoomRatioMapper.h"

namespace android {

namespace camera3 {


status_t ZoomRatioMapper::initZoomRatioInTemplate(CameraMetadata *request) {
    camera_metadata_entry_t entry;
    entry = request->find(ANDROID_CONTROL_ZOOM_RATIO);
    float defaultZoomRatio = 1.0f;
    if (entry.count == 0) {
        return request->update(ANDROID_CONTROL_ZOOM_RATIO, &defaultZoomRatio, 1);
    }
    return OK;
}

status_t ZoomRatioMapper::overrideZoomRatioTags(
        CameraMetadata* deviceInfo, bool* supportNativeZoomRatio) {
    if (deviceInfo == nullptr || supportNativeZoomRatio == nullptr) {
        return BAD_VALUE;
    }

    camera_metadata_entry_t entry;
    entry = deviceInfo->find(ANDROID_CONTROL_ZOOM_RATIO_RANGE);
    if (entry.count != 2 && entry.count != 0) return BAD_VALUE;

    // Hal has zoom ratio support
    if (entry.count == 2) {
        *supportNativeZoomRatio = true;
        return OK;
    }

    // Hal has no zoom ratio support
    *supportNativeZoomRatio = false;

    entry = deviceInfo->find(ANDROID_SCALER_AVAILABLE_MAX_DIGITAL_ZOOM);
    if (entry.count != 1) {
        ALOGI("%s: Camera device doesn't support SCALER_AVAILABLE_MAX_DIGITAL_ZOOM key!",
                __FUNCTION__);
        return OK;
    }

    float zoomRange[] = {1.0f, entry.data.f[0]};
    status_t res = deviceInfo->update(ANDROID_CONTROL_ZOOM_RATIO_RANGE, zoomRange, 2);
    if (res != OK) {
        ALOGE("%s: Failed to update CONTROL_ZOOM_RATIO_RANGE key: %s (%d)",
                __FUNCTION__, strerror(-res), res);
        return res;
    }

    std::vector<int32_t> requestKeys;
    entry = deviceInfo->find(ANDROID_REQUEST_AVAILABLE_REQUEST_KEYS);
    if (entry.count > 0) {
        requestKeys.insert(requestKeys.end(), entry.data.i32, entry.data.i32 + entry.count);
    }
    requestKeys.push_back(ANDROID_CONTROL_ZOOM_RATIO);
    res = deviceInfo->update(ANDROID_REQUEST_AVAILABLE_REQUEST_KEYS,
            requestKeys.data(), requestKeys.size());
    if (res != OK) {
        ALOGE("%s: Failed to update REQUEST_AVAILABLE_REQUEST_KEYS: %s (%d)",
                __FUNCTION__, strerror(-res), res);
        return res;
    }

    std::vector<int32_t> resultKeys;
    entry = deviceInfo->find(ANDROID_REQUEST_AVAILABLE_RESULT_KEYS);
    if (entry.count > 0) {
        resultKeys.insert(resultKeys.end(), entry.data.i32, entry.data.i32 + entry.count);
    }
    resultKeys.push_back(ANDROID_CONTROL_ZOOM_RATIO);
    res = deviceInfo->update(ANDROID_REQUEST_AVAILABLE_RESULT_KEYS,
            resultKeys.data(), resultKeys.size());
    if (res != OK) {
        ALOGE("%s: Failed to update REQUEST_AVAILABLE_RESULT_KEYS: %s (%d)",
                __FUNCTION__, strerror(-res), res);
        return res;
    }

    std::vector<int32_t> charKeys;
    entry = deviceInfo->find(ANDROID_REQUEST_AVAILABLE_CHARACTERISTICS_KEYS);
    if (entry.count > 0) {
        charKeys.insert(charKeys.end(), entry.data.i32, entry.data.i32 + entry.count);
    }
    charKeys.push_back(ANDROID_CONTROL_ZOOM_RATIO_RANGE);
    res = deviceInfo->update(ANDROID_REQUEST_AVAILABLE_CHARACTERISTICS_KEYS,
            charKeys.data(), charKeys.size());
    if (res != OK) {
        ALOGE("%s: Failed to update REQUEST_AVAILABLE_CHARACTERISTICS_KEYS: %s (%d)",
                __FUNCTION__, strerror(-res), res);
        return res;
    }

    return OK;
}

ZoomRatioMapper::ZoomRatioMapper(const CameraMetadata* deviceInfo,
        bool supportNativeZoomRatio, bool usePrecorrectArray) {
    camera_metadata_ro_entry_t entry;

    entry = deviceInfo->find(ANDROID_SENSOR_INFO_PRE_CORRECTION_ACTIVE_ARRAY_SIZE);
    if (entry.count != 4) return;
    int32_t arrayW = entry.data.i32[2];
    int32_t arrayH = entry.data.i32[3];

    entry = deviceInfo->find(ANDROID_SENSOR_INFO_ACTIVE_ARRAY_SIZE);
    if (entry.count != 4) return;
    int32_t activeW = entry.data.i32[2];
    int32_t activeH = entry.data.i32[3];

    if (usePrecorrectArray) {
        mArrayWidth = arrayW;
        mArrayHeight = arrayH;
    } else {
        mArrayWidth = activeW;
        mArrayHeight = activeH;
    }
    mHalSupportsZoomRatio = supportNativeZoomRatio;

    ALOGV("%s: array size: %d x %d, mHalSupportsZoomRatio %d",
            __FUNCTION__, mArrayWidth, mArrayHeight, mHalSupportsZoomRatio);
    mIsValid = true;
}

status_t ZoomRatioMapper::updateCaptureRequest(CameraMetadata* request) {
    if (!mIsValid) return INVALID_OPERATION;

    status_t res = OK;
    bool zoomRatioIs1 = true;
    camera_metadata_entry_t entry;

    entry = request->find(ANDROID_CONTROL_ZOOM_RATIO);
    if (entry.count == 1 && entry.data.f[0] != 1.0f) {
        zoomRatioIs1 = false;

        // If cropRegion is windowboxing, override it with activeArray
        camera_metadata_entry_t cropRegionEntry = request->find(ANDROID_SCALER_CROP_REGION);
        if (cropRegionEntry.count == 4) {
            int cropWidth = cropRegionEntry.data.i32[2];
            int cropHeight = cropRegionEntry.data.i32[3];
            if (cropWidth < mArrayWidth && cropHeight < mArrayHeight) {
                cropRegionEntry.data.i32[0] = 0;
                cropRegionEntry.data.i32[1] = 0;
                cropRegionEntry.data.i32[2] = mArrayWidth;
                cropRegionEntry.data.i32[3] = mArrayHeight;
            }
        }
    }

    if (mHalSupportsZoomRatio && zoomRatioIs1) {
        res = separateZoomFromCropLocked(request, false/*isResult*/);
    } else if (!mHalSupportsZoomRatio && !zoomRatioIs1) {
        res = combineZoomAndCropLocked(request, false/*isResult*/);
    }

    // If CONTROL_ZOOM_RATIO is in request, but HAL doesn't support
    // CONTROL_ZOOM_RATIO, remove it from the request.
    if (!mHalSupportsZoomRatio && entry.count == 1) {
        request->erase(ANDROID_CONTROL_ZOOM_RATIO);
    }

    return res;
}

status_t ZoomRatioMapper::updateCaptureResult(CameraMetadata* result, bool requestedZoomRatioIs1) {
    if (!mIsValid) return INVALID_OPERATION;

    status_t res = OK;

    if (mHalSupportsZoomRatio && requestedZoomRatioIs1) {
        res = combineZoomAndCropLocked(result, true/*isResult*/);
    } else if (!mHalSupportsZoomRatio && !requestedZoomRatioIs1) {
        res = separateZoomFromCropLocked(result, true/*isResult*/);
    } else {
        camera_metadata_entry_t entry = result->find(ANDROID_CONTROL_ZOOM_RATIO);
        if (entry.count == 0) {
            float zoomRatio1x = 1.0f;
            result->update(ANDROID_CONTROL_ZOOM_RATIO, &zoomRatio1x, 1);
        }
    }

    return res;
}

float ZoomRatioMapper::deriveZoomRatio(const CameraMetadata* metadata) {
    float zoomRatio = 1.0;

    camera_metadata_ro_entry_t entry;
    entry = metadata->find(ANDROID_SCALER_CROP_REGION);
    if (entry.count != 4) return zoomRatio;

    // Center of the preCorrection/active size
    float arrayCenterX = mArrayWidth / 2.0;
    float arrayCenterY = mArrayHeight / 2.0;

    // Re-map crop region to coordinate system centered to (arrayCenterX,
    // arrayCenterY).
    float cropRegionLeft = arrayCenterX - entry.data.i32[0] ;
    float cropRegionTop = arrayCenterY - entry.data.i32[1];
    float cropRegionRight = entry.data.i32[0] + entry.data.i32[2] - arrayCenterX;
    float cropRegionBottom = entry.data.i32[1] + entry.data.i32[3] - arrayCenterY;

    // Calculate the scaling factor for left, top, bottom, right
    float zoomRatioLeft = std::max(mArrayWidth / (2 * cropRegionLeft), 1.0f);
    float zoomRatioTop = std::max(mArrayHeight / (2 * cropRegionTop), 1.0f);
    float zoomRatioRight = std::max(mArrayWidth / (2 * cropRegionRight), 1.0f);
    float zoomRatioBottom = std::max(mArrayHeight / (2 * cropRegionBottom), 1.0f);

    // Use minimum scaling factor to handle letterboxing or pillarboxing
    zoomRatio = std::min(std::min(zoomRatioLeft, zoomRatioRight),
            std::min(zoomRatioTop, zoomRatioBottom));

    ALOGV("%s: derived zoomRatio is %f", __FUNCTION__, zoomRatio);
    return zoomRatio;
}

status_t ZoomRatioMapper::separateZoomFromCropLocked(CameraMetadata* metadata, bool isResult) {
    status_t res;
    float zoomRatio = deriveZoomRatio(metadata);

    // Update zoomRatio metadata tag
    res = metadata->update(ANDROID_CONTROL_ZOOM_RATIO, &zoomRatio, 1);
    if (res != OK) {
        ALOGE("%s: Failed to update ANDROID_CONTROL_ZOOM_RATIO: %s(%d)",
                __FUNCTION__, strerror(-res), res);
        return res;
    }

    // Scale regions using zoomRatio
    camera_metadata_entry_t entry;
    for (auto region : kMeteringRegionsToCorrect) {
        entry = metadata->find(region);
        for (size_t j = 0; j < entry.count; j += 5) {
            int32_t weight = entry.data.i32[j + 4];
            if (weight == 0) {
                continue;
            }
            // Top left (inclusive)
            scaleCoordinates(entry.data.i32 + j, 1, zoomRatio, true /*clamp*/);
            // Bottom right (exclusive): Use adjacent inclusive pixel to
            // calculate.
            entry.data.i32[j+2] -= 1;
            entry.data.i32[j+3] -= 1;
            scaleCoordinates(entry.data.i32 + j + 2, 1, zoomRatio, true /*clamp*/);
            entry.data.i32[j+2] += 1;
            entry.data.i32[j+3] += 1;
        }
    }

    for (auto rect : kRectsToCorrect) {
        entry = metadata->find(rect);
        scaleRects(entry.data.i32, entry.count / 4, zoomRatio);
    }

    if (isResult) {
        for (auto pts : kResultPointsToCorrectNoClamp) {
            entry = metadata->find(pts);
            scaleCoordinates(entry.data.i32, entry.count / 2, zoomRatio, false /*clamp*/);
        }
    }

    return OK;
}

status_t ZoomRatioMapper::combineZoomAndCropLocked(CameraMetadata* metadata, bool isResult) {
    float zoomRatio = 1.0f;
    camera_metadata_entry_t entry;
    entry = metadata->find(ANDROID_CONTROL_ZOOM_RATIO);
    if (entry.count == 1) {
        zoomRatio = entry.data.f[0];
    }

    // Unscale regions with zoomRatio
    status_t res;
    for (auto region : kMeteringRegionsToCorrect) {
        entry = metadata->find(region);
        for (size_t j = 0; j < entry.count; j += 5) {
            int32_t weight = entry.data.i32[j + 4];
            if (weight == 0) {
                continue;
            }
            // Top-left (inclusive)
            scaleCoordinates(entry.data.i32 + j, 1, 1.0 / zoomRatio, true /*clamp*/);
            // Bottom-right (exclusive): Use adjacent inclusive pixel to
            // calculate.
            entry.data.i32[j+2] -= 1;
            entry.data.i32[j+3] -= 1;
            scaleCoordinates(entry.data.i32 + j + 2, 1, 1.0 / zoomRatio, true /*clamp*/);
            entry.data.i32[j+2] += 1;
            entry.data.i32[j+3] += 1;
        }
    }
    for (auto rect : kRectsToCorrect) {
        entry = metadata->find(rect);
        scaleRects(entry.data.i32, entry.count / 4, 1.0 / zoomRatio);
    }
    if (isResult) {
        for (auto pts : kResultPointsToCorrectNoClamp) {
            entry = metadata->find(pts);
            scaleCoordinates(entry.data.i32, entry.count / 2, 1.0 / zoomRatio, false /*clamp*/);
        }
    }

    zoomRatio = 1.0;
    res = metadata->update(ANDROID_CONTROL_ZOOM_RATIO, &zoomRatio, 1);
    if (res != OK) {
        return res;
    }

    return OK;
}

void ZoomRatioMapper::scaleCoordinates(int32_t* coordPairs, int coordCount,
        float scaleRatio, bool clamp) {
    // A pixel's coordinate is represented by the position of its top-left corner.
    // To avoid the rounding error, we use the coordinate for the center of the
    // pixel instead:
    // 1. First shift the coordinate system half pixel both horizontally and
    // vertically, so that [x, y] is the center of the pixel, not the top-left corner.
    // 2. Do zoom operation to scale the coordinate relative to the center of
    // the active array (shifted by 0.5 pixel as well).
    // 3. Shift the coordinate system back by directly using the pixel center
    // coordinate.
    for (int i = 0; i < coordCount * 2; i += 2) {
        float x = coordPairs[i];
        float y = coordPairs[i + 1];
        float xCentered = x - (mArrayWidth - 2) / 2;
        float yCentered = y - (mArrayHeight - 2) / 2;
        float scaledX = xCentered * scaleRatio;
        float scaledY = yCentered * scaleRatio;
        scaledX += (mArrayWidth - 2) / 2;
        scaledY += (mArrayHeight - 2) / 2;
        coordPairs[i] = static_cast<int32_t>(std::round(scaledX));
        coordPairs[i+1] = static_cast<int32_t>(std::round(scaledY));
        // Clamp to within activeArray/preCorrectionActiveArray
        if (clamp) {
            int32_t right = mArrayWidth - 1;
            int32_t bottom = mArrayHeight - 1;
            coordPairs[i] =
                    std::min(right, std::max(0, coordPairs[i]));
            coordPairs[i+1] =
                    std::min(bottom, std::max(0, coordPairs[i+1]));
        }
        ALOGV("%s: coordinates: %d, %d", __FUNCTION__, coordPairs[i], coordPairs[i+1]);
    }
}

void ZoomRatioMapper::scaleRects(int32_t* rects, int rectCount,
        float scaleRatio) {
    for (int i = 0; i < rectCount * 4; i += 4) {
        // Map from (l, t, width, height) to (l, t, l+width-1, t+height-1),
        // where both top-left and bottom-right are inclusive.
        int32_t coords[4] = {
            rects[i],
            rects[i + 1],
            rects[i] + rects[i + 2] - 1,
            rects[i + 1] + rects[i + 3] - 1
        };

        // top-left
        scaleCoordinates(coords, 1, scaleRatio, true /*clamp*/);
        // bottom-right
        scaleCoordinates(coords+2, 1, scaleRatio, true /*clamp*/);

        // Map back to (l, t, width, height)
        rects[i] = coords[0];
        rects[i + 1] = coords[1];
        rects[i + 2] = coords[2] - coords[0] + 1;
        rects[i + 3] = coords[3] - coords[1] + 1;
    }
}

} // namespace camera3

} // namespace android
