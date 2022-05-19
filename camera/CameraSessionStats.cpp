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

// #define LOG_NDEBUG 0
#define LOG_TAG "CameraSessionStats"
#include <utils/Log.h>
#include <utils/String16.h>

#include <camera/CameraSessionStats.h>

#include <binder/Parcel.h>

namespace android {
namespace hardware {

status_t CameraStreamStats::readFromParcel(const android::Parcel* parcel) {
    if (parcel == NULL) {
        ALOGE("%s: Null parcel", __FUNCTION__);
        return BAD_VALUE;
    }

    status_t err = OK;

    int width = 0;
    if ((err = parcel->readInt32(&width)) != OK) {
        ALOGE("%s: Failed to read width from parcel", __FUNCTION__);
        return err;
    }

    int height = 0;
    if ((err = parcel->readInt32(&height)) != OK) {
        ALOGE("%s: Failed to read height from parcel", __FUNCTION__);
        return err;
    }

    int format = 0;
    if ((err = parcel->readInt32(&format)) != OK) {
        ALOGE("%s: Failed to read format from parcel", __FUNCTION__);
        return err;
    }

    float maxPreviewFps = 0;
    if ((err = parcel->readFloat(&maxPreviewFps)) != OK) {
        ALOGE("%s: Failed to read maxPreviewFps from parcel", __FUNCTION__);
        return err;
    }

    int dataSpace = 0;
    if ((err = parcel->readInt32(&dataSpace)) != OK) {
        ALOGE("%s: Failed to read dataSpace from parcel", __FUNCTION__);
        return err;
    }

    int64_t usage = 0;
    if ((err = parcel->readInt64(&usage)) != OK) {
        ALOGE("%s: Failed to read usage from parcel", __FUNCTION__);
        return err;
    }

    int64_t requestCount = 0;
    if ((err = parcel->readInt64(&requestCount)) != OK) {
        ALOGE("%s: Failed to read request count from parcel", __FUNCTION__);
        return err;
    }

    int64_t errorCount = 0;
    if ((err = parcel->readInt64(&errorCount)) != OK) {
        ALOGE("%s: Failed to read error count from parcel", __FUNCTION__);
        return err;
    }

    int startLatencyMs = 0;
    if ((err = parcel->readInt32(&startLatencyMs)) != OK) {
        ALOGE("%s: Failed to read start latency from parcel", __FUNCTION__);
        return err;
    }

    int maxHalBuffers = 0;
    if ((err = parcel->readInt32(&maxHalBuffers)) != OK) {
        ALOGE("%s: Failed to read max Hal buffers from parcel", __FUNCTION__);
        return err;
    }

    int maxAppBuffers = 0;
    if ((err = parcel->readInt32(&maxAppBuffers)) != OK) {
        ALOGE("%s: Failed to read max app buffers from parcel", __FUNCTION__);
        return err;
    }

    int histogramType = HISTOGRAM_TYPE_UNKNOWN;
    if ((err = parcel->readInt32(&histogramType)) != OK) {
        ALOGE("%s: Failed to read histogram type from parcel", __FUNCTION__);
        return err;
    }

    std::vector<float> histogramBins;
    if ((err = parcel->readFloatVector(&histogramBins)) != OK) {
        ALOGE("%s: Failed to read histogram bins from parcel", __FUNCTION__);
        return err;
    }

    std::vector<int64_t> histogramCounts;
    if ((err = parcel->readInt64Vector(&histogramCounts)) != OK) {
        ALOGE("%s: Failed to read histogram counts from parcel", __FUNCTION__);
        return err;
    }

    int64_t dynamicRangeProfile = ANDROID_REQUEST_AVAILABLE_DYNAMIC_RANGE_PROFILES_MAP_STANDARD;
    if ((err = parcel->readInt64(&dynamicRangeProfile)) != OK) {
        ALOGE("%s: Failed to read dynamic range profile type from parcel", __FUNCTION__);
        return err;
    }

    int64_t streamUseCase = ANDROID_SCALER_AVAILABLE_STREAM_USE_CASES_DEFAULT;
    if ((err = parcel->readInt64(&streamUseCase)) != OK) {
        ALOGE("%s: Failed to read stream use case from parcel", __FUNCTION__);
        return err;
    }

    mWidth = width;
    mHeight = height;
    mFormat = format;
    mMaxPreviewFps = maxPreviewFps;
    mDataSpace = dataSpace;
    mUsage = usage;
    mRequestCount = requestCount;
    mErrorCount = errorCount;
    mStartLatencyMs = startLatencyMs;
    mMaxHalBuffers = maxHalBuffers;
    mMaxAppBuffers = maxAppBuffers;
    mHistogramType = histogramType;
    mHistogramBins = std::move(histogramBins);
    mHistogramCounts = std::move(histogramCounts);
    mDynamicRangeProfile = dynamicRangeProfile;
    mStreamUseCase = streamUseCase;

    return OK;
}

status_t CameraStreamStats::writeToParcel(android::Parcel* parcel) const {
    if (parcel == NULL) {
        ALOGE("%s: Null parcel", __FUNCTION__);
        return BAD_VALUE;
    }

    status_t err = OK;

    if ((err = parcel->writeInt32(mWidth)) != OK) {
        ALOGE("%s: Failed to write stream width!", __FUNCTION__);
        return err;
    }

    if ((err = parcel->writeInt32(mHeight)) != OK) {
        ALOGE("%s: Failed to write stream height!", __FUNCTION__);
        return err;
    }

    if ((err = parcel->writeInt32(mFormat)) != OK) {
        ALOGE("%s: Failed to write stream format!", __FUNCTION__);
        return err;
    }

    if ((err = parcel->writeFloat(mMaxPreviewFps)) != OK) {
        ALOGE("%s: Failed to write stream maxPreviewFps!", __FUNCTION__);
        return err;
    }

    if ((err = parcel->writeInt32(mDataSpace)) != OK) {
        ALOGE("%s: Failed to write stream dataSpace!", __FUNCTION__);
        return err;
    }

    if ((err = parcel->writeInt64(mUsage)) != OK) {
        ALOGE("%s: Failed to write stream usage!", __FUNCTION__);
        return err;
    }

    if ((err = parcel->writeInt64(mRequestCount)) != OK) {
        ALOGE("%s: Failed to write stream request count!", __FUNCTION__);
        return err;
    }

    if ((err = parcel->writeInt64(mErrorCount)) != OK) {
        ALOGE("%s: Failed to write stream error count!", __FUNCTION__);
        return err;
    }

    if ((err = parcel->writeInt32(mStartLatencyMs)) != OK) {
        ALOGE("%s: Failed to write stream start latency!", __FUNCTION__);
        return err;
    }

    if ((err = parcel->writeInt32(mMaxHalBuffers)) != OK) {
        ALOGE("%s: Failed to write max hal buffers", __FUNCTION__);
        return err;
    }

    if ((err = parcel->writeInt32(mMaxAppBuffers)) != OK) {
        ALOGE("%s: Failed to write max app buffers", __FUNCTION__);
        return err;
    }

    if ((err = parcel->writeInt32(mHistogramType)) != OK) {
        ALOGE("%s: Failed to write histogram type", __FUNCTION__);
        return err;
    }

    if ((err = parcel->writeFloatVector(mHistogramBins)) != OK) {
        ALOGE("%s: Failed to write histogram bins!", __FUNCTION__);
        return err;
    }

    if ((err = parcel->writeInt64Vector(mHistogramCounts)) != OK) {
        ALOGE("%s: Failed to write histogram counts!", __FUNCTION__);
        return err;
    }

    if ((err = parcel->writeInt64(mDynamicRangeProfile)) != OK) {
        ALOGE("%s: Failed to write dynamic range profile type", __FUNCTION__);
        return err;
    }

    if ((err = parcel->writeInt64(mStreamUseCase)) != OK) {
        ALOGE("%s: Failed to write stream use case!", __FUNCTION__);
        return err;
    }

    return OK;
}

const int CameraSessionStats::CAMERA_STATE_OPEN = 0;
const int CameraSessionStats::CAMERA_STATE_ACTIVE = 1;
const int CameraSessionStats::CAMERA_STATE_IDLE = 2;
const int CameraSessionStats::CAMERA_STATE_CLOSED = 3;

const int CameraSessionStats::CAMERA_FACING_BACK = 0;
const int CameraSessionStats::CAMERA_FACING_FRONT = 1;
const int CameraSessionStats::CAMERA_FACING_EXTERNAL = 2;

const int CameraSessionStats::CAMERA_API_LEVEL_1 = 1;
const int CameraSessionStats::CAMERA_API_LEVEL_2 = 2;

CameraSessionStats::CameraSessionStats() :
        mFacing(CAMERA_FACING_BACK),
        mNewCameraState(CAMERA_STATE_CLOSED),
        mApiLevel(0),
        mIsNdk(false),
        mLatencyMs(-1),
        mMaxPreviewFps(0),
        mSessionType(0),
        mInternalReconfigure(0),
        mRequestCount(0),
        mResultErrorCount(0),
        mDeviceError(false),
        mVideoStabilizationMode(-1) {}

CameraSessionStats::CameraSessionStats(const String16& cameraId,
        int facing, int newCameraState, const String16& clientName,
        int apiLevel, bool isNdk, int32_t latencyMs) :
                mCameraId(cameraId),
                mFacing(facing),
                mNewCameraState(newCameraState),
                mClientName(clientName),
                mApiLevel(apiLevel),
                mIsNdk(isNdk),
                mLatencyMs(latencyMs),
                mMaxPreviewFps(0),
                mSessionType(0),
                mInternalReconfigure(0),
                mRequestCount(0),
                mResultErrorCount(0),
                mDeviceError(0),
                mVideoStabilizationMode(-1) {}

status_t CameraSessionStats::readFromParcel(const android::Parcel* parcel) {
    if (parcel == NULL) {
        ALOGE("%s: Null parcel", __FUNCTION__);
        return BAD_VALUE;
    }

    status_t err = OK;

    String16 id;
    if ((err = parcel->readString16(&id)) != OK) {
        ALOGE("%s: Failed to read camera id!", __FUNCTION__);
        return BAD_VALUE;
    }

    int facing = 0;
    if ((err = parcel->readInt32(&facing)) != OK) {
        ALOGE("%s: Failed to read camera facing from parcel", __FUNCTION__);
        return err;
    }

    int32_t newCameraState;
    if ((err = parcel->readInt32(&newCameraState)) != OK) {
        ALOGE("%s: Failed to read new camera state from parcel", __FUNCTION__);
        return err;
    }

    String16 clientName;
    if ((err = parcel->readString16(&clientName)) != OK) {
        ALOGE("%s: Failed to read client name!", __FUNCTION__);
        return BAD_VALUE;
    }

    int32_t apiLevel;
    if ((err = parcel->readInt32(&apiLevel)) != OK) {
        ALOGE("%s: Failed to read api level from parcel", __FUNCTION__);
        return err;
    }

    bool isNdk;
    if ((err = parcel->readBool(&isNdk)) != OK) {
        ALOGE("%s: Failed to read isNdk flag from parcel", __FUNCTION__);
        return err;
    }

    int32_t latencyMs;
    if ((err = parcel->readInt32(&latencyMs)) != OK) {
        ALOGE("%s: Failed to read latencyMs from parcel", __FUNCTION__);
        return err;
    }

    float maxPreviewFps;
    if ((err = parcel->readFloat(&maxPreviewFps)) != OK) {
        ALOGE("%s: Failed to read maxPreviewFps from parcel", __FUNCTION__);
        return err;
    }

    int32_t sessionType;
    if ((err = parcel->readInt32(&sessionType)) != OK) {
        ALOGE("%s: Failed to read session type from parcel", __FUNCTION__);
        return err;
    }

    int32_t internalReconfigure;
    if ((err = parcel->readInt32(&internalReconfigure)) != OK) {
        ALOGE("%s: Failed to read internal reconfigure count from parcel", __FUNCTION__);
        return err;
    }

    int64_t requestCount;
    if ((err = parcel->readInt64(&requestCount)) != OK) {
        ALOGE("%s: Failed to read request count from parcel", __FUNCTION__);
        return err;
    }

    int64_t resultErrorCount;
    if ((err = parcel->readInt64(&resultErrorCount)) != OK) {
        ALOGE("%s: Failed to read result error count from parcel", __FUNCTION__);
        return err;
    }

    bool deviceError;
    if ((err = parcel->readBool(&deviceError)) != OK) {
        ALOGE("%s: Failed to read device error flag from parcel", __FUNCTION__);
        return err;
    }

    std::vector<CameraStreamStats> streamStats;
    if ((err = parcel->readParcelableVector(&streamStats)) != OK) {
        ALOGE("%s: Failed to read stream state from parcel", __FUNCTION__);
        return err;
    }

    String16 userTag;
    if ((err = parcel->readString16(&userTag)) != OK) {
        ALOGE("%s: Failed to read user tag!", __FUNCTION__);
        return BAD_VALUE;
    }

    int32_t videoStabilizationMode;
    if ((err = parcel->readInt32(&videoStabilizationMode)) != OK) {
        ALOGE("%s: Failed to read video stabilization mode from parcel", __FUNCTION__);
        return err;
    }

    mCameraId = id;
    mFacing = facing;
    mNewCameraState = newCameraState;
    mClientName = clientName;
    mApiLevel = apiLevel;
    mIsNdk = isNdk;
    mLatencyMs = latencyMs;
    mMaxPreviewFps = maxPreviewFps;
    mSessionType = sessionType;
    mInternalReconfigure = internalReconfigure;
    mRequestCount = requestCount;
    mResultErrorCount = resultErrorCount;
    mDeviceError = deviceError;
    mStreamStats = std::move(streamStats);
    mUserTag = userTag;
    mVideoStabilizationMode = videoStabilizationMode;

    return OK;
}

status_t CameraSessionStats::writeToParcel(android::Parcel* parcel) const {
    if (parcel == NULL) {
        ALOGE("%s: Null parcel", __FUNCTION__);
        return BAD_VALUE;
    }

    status_t err = OK;

    if ((err = parcel->writeString16(mCameraId)) != OK) {
        ALOGE("%s: Failed to write camera id!", __FUNCTION__);
        return err;
    }

    if ((err = parcel->writeInt32(mFacing)) != OK) {
        ALOGE("%s: Failed to write camera facing!", __FUNCTION__);
        return err;
    }

    if ((err = parcel->writeInt32(mNewCameraState)) != OK) {
        ALOGE("%s: Failed to write new camera state!", __FUNCTION__);
        return err;
    }

    if ((err = parcel->writeString16(mClientName)) != OK) {
        ALOGE("%s: Failed to write client name!", __FUNCTION__);
        return err;
    }

    if ((err = parcel->writeInt32(mApiLevel)) != OK) {
        ALOGE("%s: Failed to write api level!", __FUNCTION__);
        return err;
    }

    if ((err = parcel->writeBool(mIsNdk)) != OK) {
        ALOGE("%s: Failed to write isNdk flag!", __FUNCTION__);
        return err;
    }

    if ((err = parcel->writeInt32(mLatencyMs)) != OK) {
        ALOGE("%s: Failed to write latency in Ms!", __FUNCTION__);
        return err;
    }

    if ((err = parcel->writeFloat(mMaxPreviewFps)) != OK) {
        ALOGE("%s: Failed to write maxPreviewFps!", __FUNCTION__);
        return err;
    }

    if ((err = parcel->writeInt32(mSessionType)) != OK) {
        ALOGE("%s: Failed to write session type!", __FUNCTION__);
        return err;
    }

    if ((err = parcel->writeInt32(mInternalReconfigure)) != OK) {
        ALOGE("%s: Failed to write internal reconfigure count!", __FUNCTION__);
        return err;
    }

    if ((err = parcel->writeInt64(mRequestCount)) != OK) {
        ALOGE("%s: Failed to write request count!", __FUNCTION__);
        return err;
    }

    if ((err = parcel->writeInt64(mResultErrorCount)) != OK) {
        ALOGE("%s: Failed to write result error count!", __FUNCTION__);
        return err;
    }

    if ((err = parcel->writeBool(mDeviceError)) != OK) {
        ALOGE("%s: Failed to write device error flag!", __FUNCTION__);
        return err;
    }

    if ((err = parcel->writeParcelableVector(mStreamStats)) != OK) {
        ALOGE("%s: Failed to write stream states!", __FUNCTION__);
        return err;
    }

    if ((err = parcel->writeString16(mUserTag)) != OK) {
        ALOGE("%s: Failed to write user tag!", __FUNCTION__);
        return err;
    }

    if ((err = parcel->writeInt32(mVideoStabilizationMode)) != OK) {
        ALOGE("%s: Failed to write video stabilization mode!", __FUNCTION__);
        return err;
    }
    return OK;
}

} // namespace hardware
} // namesmpace android
