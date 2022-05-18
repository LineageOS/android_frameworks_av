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

#ifndef ANDROID_HARDWARE_CAMERA_SERVICE_SESSION_STATS_H
#define ANDROID_HARDWARE_CAMERA_SERVICE_SESSION_STATS_H

#include <binder/Parcelable.h>

#include <camera/CameraMetadata.h>

namespace android {
namespace hardware {

/**
 * Camera stream info and statistics
 */
class CameraStreamStats : public android::Parcelable {
public:
    enum HistogramType {
        HISTOGRAM_TYPE_UNKNOWN = 0,
        HISTOGRAM_TYPE_CAPTURE_LATENCY = 1,
    };

    int mWidth;
    int mHeight;
    int mFormat;
    float mMaxPreviewFps;
    int mDataSpace;
    int64_t mUsage;

    // The number of requested buffers
    int64_t mRequestCount;
    // The number of buffer errors
    int64_t mErrorCount;

    // The capture latency of 1st request for this stream
    int32_t mStartLatencyMs;

    // Buffer count info
    int mMaxHalBuffers;
    int mMaxAppBuffers;

    // Histogram type. So far only capture latency histogram is supported.
    int mHistogramType;
    // The bounary values separating adjacent histogram bins.
    // A vector of {h1, h2, h3} represents bins of [0, h1), [h1, h2), [h2, h3),
    // and [h3, infinity)
    std::vector<float> mHistogramBins;
    // The counts for all histogram bins.
    // size(mHistogramBins) + 1 = size(mHistogramCounts)
    std::vector<int64_t> mHistogramCounts;

    // Dynamic range profile
    int64_t mDynamicRangeProfile;
    // Stream use case
    int64_t mStreamUseCase;

    CameraStreamStats() :
            mWidth(0), mHeight(0), mFormat(0), mMaxPreviewFps(0), mDataSpace(0), mUsage(0),
            mRequestCount(0), mErrorCount(0), mStartLatencyMs(0),
            mMaxHalBuffers(0), mMaxAppBuffers(0), mHistogramType(HISTOGRAM_TYPE_UNKNOWN),
            mDynamicRangeProfile(ANDROID_REQUEST_AVAILABLE_DYNAMIC_RANGE_PROFILES_MAP_STANDARD),
            mStreamUseCase(ANDROID_SCALER_AVAILABLE_STREAM_USE_CASES_DEFAULT) {}
    CameraStreamStats(int width, int height, int format, float maxPreviewFps, int dataSpace,
            int64_t usage, int maxHalBuffers, int maxAppBuffers, int dynamicRangeProfile,
            int streamUseCase)
            : mWidth(width), mHeight(height), mFormat(format), mMaxPreviewFps(maxPreviewFps),
              mDataSpace(dataSpace), mUsage(usage), mRequestCount(0), mErrorCount(0),
              mStartLatencyMs(0), mMaxHalBuffers(maxHalBuffers), mMaxAppBuffers(maxAppBuffers),
              mHistogramType(HISTOGRAM_TYPE_UNKNOWN),
              mDynamicRangeProfile(dynamicRangeProfile),
              mStreamUseCase(streamUseCase) {}

    virtual status_t readFromParcel(const android::Parcel* parcel) override;
    virtual status_t writeToParcel(android::Parcel* parcel) const override;
};

/**
 * Camera session statistics
 *
 * This includes session wide info and stream statistics.
 */
class CameraSessionStats : public android::Parcelable {
public:
    /**
     * Values for notifyCameraState newCameraState
     */
    static const int CAMERA_STATE_OPEN;
    static const int CAMERA_STATE_ACTIVE;
    static const int CAMERA_STATE_IDLE;
    static const int CAMERA_STATE_CLOSED;

    /**
     * Values for notifyCameraState facing
     */
    static const int CAMERA_FACING_BACK;
    static const int CAMERA_FACING_FRONT;
    static const int CAMERA_FACING_EXTERNAL;

    /**
     * Values for notifyCameraState api level
     */
    static const int CAMERA_API_LEVEL_1;
    static const int CAMERA_API_LEVEL_2;

    String16 mCameraId;
    int mFacing;
    int mNewCameraState;
    String16 mClientName;
    int mApiLevel;
    bool mIsNdk;
    // latency in ms for camera open, close, or session creation.
    int mLatencyMs;
    float mMaxPreviewFps;

    // Session info and statistics
    int mSessionType;
    int mInternalReconfigure;
    // The number of capture requests
    int64_t mRequestCount;
    // The number of result error
    int64_t mResultErrorCount;
    // Whether the device runs into an error state
    bool mDeviceError;
    std::vector<CameraStreamStats> mStreamStats;
    String16 mUserTag;
    int mVideoStabilizationMode;

    // Constructors
    CameraSessionStats();
    CameraSessionStats(const String16& cameraId, int facing, int newCameraState,
            const String16& clientName, int apiLevel, bool isNdk, int32_t latencyMs);

    virtual status_t readFromParcel(const android::Parcel* parcel) override;
    virtual status_t writeToParcel(android::Parcel* parcel) const override;
};

}; // namespace hardware
}; // namespace android

#endif // ANDROID_HARDWARE_CAMERA_SERVICE_SESSION_STATS_H
