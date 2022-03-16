/*
 * Copyright (C) 2015-2018 The Android Open Source Project
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

#ifndef ANDROID_HARDWARE_CAMERA2_OUTPUTCONFIGURATION_H
#define ANDROID_HARDWARE_CAMERA2_OUTPUTCONFIGURATION_H

#include <gui/IGraphicBufferProducer.h>
#include <binder/Parcelable.h>

namespace android {

class Surface;

namespace hardware {
namespace camera2 {
namespace params {

class OutputConfiguration : public android::Parcelable {
public:

    static const int INVALID_ROTATION;
    static const int INVALID_SET_ID;
    enum SurfaceType{
        SURFACE_TYPE_UNKNOWN = -1,
        SURFACE_TYPE_SURFACE_VIEW = 0,
        SURFACE_TYPE_SURFACE_TEXTURE = 1
    };
    enum TimestampBaseType {
        TIMESTAMP_BASE_DEFAULT = 0,
        TIMESTAMP_BASE_SENSOR = 1,
        TIMESTAMP_BASE_MONOTONIC = 2,
        TIMESTAMP_BASE_REALTIME = 3,
        TIMESTAMP_BASE_CHOREOGRAPHER_SYNCED = 4
    };
    enum MirrorModeType {
        MIRROR_MODE_AUTO = 0,
        MIRROR_MODE_NONE = 1,
        MIRROR_MODE_H = 2,
        MIRROR_MODE_V = 3,
    };

    const std::vector<sp<IGraphicBufferProducer>>& getGraphicBufferProducers() const;
    int                        getRotation() const;
    int                        getSurfaceSetID() const;
    int                        getSurfaceType() const;
    int                        getWidth() const;
    int                        getHeight() const;
    int64_t                    getDynamicRangeProfile() const;
    bool                       isDeferred() const;
    bool                       isShared() const;
    String16                   getPhysicalCameraId() const;
    bool                       isMultiResolution() const;
    int64_t                    getStreamUseCase() const;
    int                        getTimestampBase() const;
    int                        getMirrorMode() const;

    // set of sensor pixel mode resolutions allowed {MAX_RESOLUTION, DEFAULT_MODE};
    const std::vector<int32_t>&            getSensorPixelModesUsed() const;
    /**
     * Keep impl up-to-date with OutputConfiguration.java in frameworks/base
     */
    virtual status_t           writeToParcel(android::Parcel* parcel) const override;

    virtual status_t           readFromParcel(const android::Parcel* parcel) override;

    // getGraphicBufferProducer will be NULL
    // getRotation will be INVALID_ROTATION
    // getSurfaceSetID will be INVALID_SET_ID
    OutputConfiguration();

    // getGraphicBufferProducer will be NULL if error occurred
    // getRotation will be INVALID_ROTATION if error occurred
    // getSurfaceSetID will be INVALID_SET_ID if error occurred
    OutputConfiguration(const android::Parcel& parcel);

    OutputConfiguration(sp<IGraphicBufferProducer>& gbp, int rotation,
            const String16& physicalCameraId,
            int surfaceSetID = INVALID_SET_ID, bool isShared = false);

    OutputConfiguration(const std::vector<sp<IGraphicBufferProducer>>& gbps,
                        int rotation, const String16& physicalCameraId,
                        int surfaceSetID = INVALID_SET_ID,
                        int surfaceType = OutputConfiguration::SURFACE_TYPE_UNKNOWN, int width = 0,
                        int height = 0, bool isShared = false);

    bool operator == (const OutputConfiguration& other) const {
        return ( mRotation == other.mRotation &&
                mSurfaceSetID == other.mSurfaceSetID &&
                mSurfaceType == other.mSurfaceType &&
                mWidth == other.mWidth &&
                mHeight == other.mHeight &&
                mIsDeferred == other.mIsDeferred &&
                mIsShared == other.mIsShared &&
                gbpsEqual(other) &&
                mPhysicalCameraId == other.mPhysicalCameraId &&
                mIsMultiResolution == other.mIsMultiResolution &&
                sensorPixelModesUsedEqual(other) &&
                mDynamicRangeProfile == other.mDynamicRangeProfile &&
                mStreamUseCase == other.mStreamUseCase &&
                mTimestampBase == other.mTimestampBase &&
                mMirrorMode == other.mMirrorMode);
    }
    bool operator != (const OutputConfiguration& other) const {
        return !(*this == other);
    }
    bool operator < (const OutputConfiguration& other) const {
        if (*this == other) return false;
        if (mSurfaceSetID != other.mSurfaceSetID) {
            return mSurfaceSetID < other.mSurfaceSetID;
        }
        if (mSurfaceType != other.mSurfaceType) {
            return mSurfaceType < other.mSurfaceType;
        }
        if (mWidth != other.mWidth) {
            return mWidth < other.mWidth;
        }
        if (mHeight != other.mHeight) {
            return mHeight < other.mHeight;
        }
        if (mRotation != other.mRotation) {
            return mRotation < other.mRotation;
        }
        if (mIsDeferred != other.mIsDeferred) {
            return mIsDeferred < other.mIsDeferred;
        }
        if (mIsShared != other.mIsShared) {
            return mIsShared < other.mIsShared;
        }
        if (mPhysicalCameraId != other.mPhysicalCameraId) {
            return mPhysicalCameraId < other.mPhysicalCameraId;
        }
        if (mIsMultiResolution != other.mIsMultiResolution) {
            return mIsMultiResolution < other.mIsMultiResolution;
        }
        if (!sensorPixelModesUsedEqual(other)) {
            return sensorPixelModesUsedLessThan(other);
        }
        if (mDynamicRangeProfile != other.mDynamicRangeProfile) {
            return mDynamicRangeProfile < other.mDynamicRangeProfile;
        }
        if (mStreamUseCase != other.mStreamUseCase) {
            return mStreamUseCase < other.mStreamUseCase;
        }
        if (mTimestampBase != other.mTimestampBase) {
            return mTimestampBase < other.mTimestampBase;
        }
        if (mMirrorMode != other.mMirrorMode) {
            return mMirrorMode < other.mMirrorMode;
        }
        return gbpsLessThan(other);
    }

    bool operator > (const OutputConfiguration& other) const {
        return (*this != other && !(*this < other));
    }

    bool gbpsEqual(const OutputConfiguration& other) const;
    bool sensorPixelModesUsedEqual(const OutputConfiguration& other) const;
    bool sensorPixelModesUsedLessThan(const OutputConfiguration& other) const;
    bool gbpsLessThan(const OutputConfiguration& other) const;
    void addGraphicProducer(sp<IGraphicBufferProducer> gbp) {mGbps.push_back(gbp);}
private:
    std::vector<sp<IGraphicBufferProducer>> mGbps;
    int                        mRotation;
    int                        mSurfaceSetID;
    int                        mSurfaceType;
    int                        mWidth;
    int                        mHeight;
    bool                       mIsDeferred;
    bool                       mIsShared;
    String16                   mPhysicalCameraId;
    bool                       mIsMultiResolution;
    std::vector<int32_t>       mSensorPixelModesUsed;
    int64_t                    mDynamicRangeProfile;
    int64_t                    mStreamUseCase;
    int                        mTimestampBase;
    int                        mMirrorMode;
};
} // namespace params
} // namespace camera2
} // namespace hardware


using hardware::camera2::params::OutputConfiguration;

}; // namespace android

#endif
