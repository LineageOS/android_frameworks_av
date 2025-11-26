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

#include <string>
#include "system/graphics-base-v1.0.h"

#include <gui/Flags.h>  // remove with WB_LIBCAMERASERVICE_WITH_DEPENDENCIES
#if WB_LIBCAMERASERVICE_WITH_DEPENDENCIES
#include <gui/view/Surface.h>
#else
#include <gui/IGraphicBufferProducer.h>
#endif
#include <binder/Parcelable.h>

namespace android {

class Surface;

namespace hardware {
namespace camera2 {
namespace params {

class OutputConfiguration : public android::Parcelable {
public:

    static const int ROTATION_0;
    static const int INVALID_ROTATION;
    static const int INVALID_SET_ID;
    enum SurfaceType {
        SURFACE_TYPE_UNKNOWN = -1,
        SURFACE_TYPE_SURFACE_VIEW = 0,
        SURFACE_TYPE_SURFACE_TEXTURE = 1,
        SURFACE_TYPE_MEDIA_RECORDER = 2,
        SURFACE_TYPE_MEDIA_CODEC = 3,
        SURFACE_TYPE_IMAGE_READER = 4
    };
    enum TimestampBaseType {
        TIMESTAMP_BASE_DEFAULT = 0,
        TIMESTAMP_BASE_SENSOR = 1,
        TIMESTAMP_BASE_MONOTONIC = 2,
        TIMESTAMP_BASE_REALTIME = 3,
        TIMESTAMP_BASE_CHOREOGRAPHER_SYNCED = 4,
        TIMESTAMP_BASE_MAX = TIMESTAMP_BASE_CHOREOGRAPHER_SYNCED,
    };
    enum MirrorModeType {
        MIRROR_MODE_AUTO = 0,
        MIRROR_MODE_NONE = 1,
        MIRROR_MODE_H = 2,
        MIRROR_MODE_V = 3,
    };
    enum MultiResolutionModeType {
        MULTI_RES_OFF = 0,
        MULTI_RES_ON = 1,
        MULTI_RES_ON_CONCURRENT = 2,
    };

    const std::vector<ParcelableSurfaceType>& getSurfaces() const;
    int                        getRotation() const;
    int                        getSurfaceSetID() const;
    int                        getSurfaceType() const;
    int                        getWidth() const;
    int                        getHeight() const;
    int64_t                    getDynamicRangeProfile() const;
    int32_t                    getColorSpace() const;
    bool                       isDeferred() const;
    bool                       isShared() const;
    std::string                getPhysicalCameraId() const;
    int                        getMultiResMode() const;
    int64_t                    getStreamUseCase() const;
    int                        getTimestampBase() const;
    int                        getMirrorMode(ParcelableSurfaceType surface) const;
    int                        getMirrorMode() const;
    bool                       useReadoutTimestamp() const;
    int                        getFormat() const;
    int                        getDataspace() const;
    int64_t                    getUsage() const;
    bool                       isComplete() const;

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

    OutputConfiguration(ParcelableSurfaceType& surface, int rotation,
            const std::string& physicalCameraId,
            int surfaceSetID = INVALID_SET_ID, bool isShared = false);

    OutputConfiguration(const std::vector<ParcelableSurfaceType>& surfaces,
                        int rotation, const std::string& physicalCameraId,
                        int surfaceSetID = INVALID_SET_ID,
                        int surfaceType = SURFACE_TYPE_UNKNOWN, int width = 0,
                        int height = 0, bool isShared = false,
                        int format = HAL_PIXEL_FORMAT_IMPLEMENTATION_DEFINED,
                        int dataspace = 0);

    OutputConfiguration(int surfaceType, int width, int height, int format, int32_t colorSpace,
            int mirrorMode, bool useReadoutTimestamp,int timestampBase, int dataspace,
            int64_t usage, int64_t streamusecase, std::string physicalCamId);

    bool operator == (const OutputConfiguration& other) const {
        return ( mRotation == other.mRotation &&
                mSurfaceSetID == other.mSurfaceSetID &&
                mSurfaceType == other.mSurfaceType &&
                mWidth == other.mWidth &&
                mHeight == other.mHeight &&
                mIsDeferred == other.mIsDeferred &&
                mIsShared == other.mIsShared &&
                surfacesEqual(other) &&
                mPhysicalCameraId == other.mPhysicalCameraId &&
                mMultiResMode == other.mMultiResMode &&
                sensorPixelModesUsedEqual(other) &&
                mDynamicRangeProfile == other.mDynamicRangeProfile &&
                mColorSpace == other.mColorSpace &&
                mStreamUseCase == other.mStreamUseCase &&
                mTimestampBase == other.mTimestampBase &&
                mMirrorMode == other.mMirrorMode &&
                mirrorModesEqual(other) &&
                mUseReadoutTimestamp == other.mUseReadoutTimestamp &&
                mFormat == other.mFormat &&
                mDataspace == other.mDataspace &&
                mUsage == other.mUsage);
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
        if (mMultiResMode != other.mMultiResMode) {
            return mMultiResMode < other.mMultiResMode;
        }
        if (!sensorPixelModesUsedEqual(other)) {
            return sensorPixelModesUsedLessThan(other);
        }
        if (mDynamicRangeProfile != other.mDynamicRangeProfile) {
            return mDynamicRangeProfile < other.mDynamicRangeProfile;
        }
        if (mColorSpace != other.mColorSpace) {
            return mColorSpace < other.mColorSpace;
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
        if (!mirrorModesEqual(other)) {
            return mirrorModesLessThan(other);
        }
        if (mUseReadoutTimestamp != other.mUseReadoutTimestamp) {
            return mUseReadoutTimestamp < other.mUseReadoutTimestamp;
        }
        if (mFormat != other.mFormat) {
            return mFormat < other.mFormat;
        }
        if (mDataspace != other.mDataspace) {
            return mDataspace < other.mDataspace;
        }
        if (mUsage != other.mUsage) {
            return mUsage < other.mUsage;
        }
        return surfacesLessThan(other);
    }

    bool operator > (const OutputConfiguration& other) const {
        return (*this != other && !(*this < other));
    }

    bool surfacesEqual(const OutputConfiguration& other) const;
    bool sensorPixelModesUsedEqual(const OutputConfiguration& other) const;
    bool sensorPixelModesUsedLessThan(const OutputConfiguration& other) const;
    bool surfacesLessThan(const OutputConfiguration& other) const;
    void addSurface(ParcelableSurfaceType surface) { mSurfaces.push_back(surface); }
#if not WB_LIBCAMERASERVICE_WITH_DEPENDENCIES
    void addGraphicProducer(sp<IGraphicBufferProducer> gbp) {addSurface(gbp);}
#endif
    bool mirrorModesEqual(const OutputConfiguration& other) const;
    bool mirrorModesLessThan(const OutputConfiguration& other) const;
    const std::vector<int32_t>& getMirrorModes() const {return mMirrorModeForProducers;}
    bool sharedConfigEqual(const OutputConfiguration& other) const {
        return (mRotation == other.mRotation &&
                mSurfaceSetID == other.mSurfaceSetID &&
                mSurfaceType == other.mSurfaceType &&
                mWidth == other.mWidth &&
                mHeight == other.mHeight &&
                mIsDeferred == other.mIsDeferred &&
                mIsShared == other.mIsShared &&
                mPhysicalCameraId == other.mPhysicalCameraId &&
                mMultiResMode == other.mMultiResMode &&
                sensorPixelModesUsedEqual(other) &&
                mDynamicRangeProfile == other.mDynamicRangeProfile &&
                mColorSpace == other.mColorSpace &&
                mStreamUseCase == other.mStreamUseCase &&
                mTimestampBase == other.mTimestampBase &&
                mMirrorMode == other.mMirrorMode &&
                mUseReadoutTimestamp == other.mUseReadoutTimestamp &&
                mFormat == other.mFormat &&
                mDataspace == other.mDataspace &&
                mUsage == other.mUsage);
    }

private:

    void inferSurfaceProperties();
    std::vector<ParcelableSurfaceType>  mSurfaces;
    int                        mRotation;
    int                        mSurfaceSetID;
    int                        mSurfaceType;
    int                        mWidth;
    int                        mHeight;
    bool                       mIsDeferred;
    bool                       mIsShared;
    std::string                mPhysicalCameraId;
    int                        mMultiResMode;
    std::vector<int32_t>       mSensorPixelModesUsed;
    int64_t                    mDynamicRangeProfile;
    int32_t                    mColorSpace;
    int64_t                    mStreamUseCase;
    int                        mTimestampBase;
    int                        mMirrorMode;
    std::vector<int>           mMirrorModeForProducers; // 1:1 mapped with mGbps
    bool                       mUseReadoutTimestamp;
    int                        mFormat;
    int                        mDataspace;
    int64_t                    mUsage;
};
} // namespace params
} // namespace camera2
} // namespace hardware


using hardware::camera2::params::OutputConfiguration;

}; // namespace android

#endif
