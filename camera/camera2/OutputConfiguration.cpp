/*
**
** Copyright 2015-2018, The Android Open Source Project
**
** Licensed under the Apache License, Version 2.0 (the "License");
** you may not use this file except in compliance with the License.
** You may obtain a copy of the License at
**
**     http://www.apache.org/licenses/LICENSE-2.0
**
** Unless required by applicable law or agreed to in writing, software
** distributed under the License is distributed on an "AS IS" BASIS,
** WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
** See the License for the specific language governing permissions and
** limitations under the License.
*/

#define LOG_TAG "OutputConfiguration"
//#define LOG_NDEBUG 0

#include <utils/Log.h>

#include <camera/camera2/OutputConfiguration.h>
#include <camera/StringUtils.h>
#include <binder/Parcel.h>
#include <gui/view/Surface.h>
#include <system/camera_metadata.h>
#include <utils/String8.h>

namespace android {


const int OutputConfiguration::INVALID_ROTATION = -1;
const int OutputConfiguration::INVALID_SET_ID = -1;

const std::vector<sp<IGraphicBufferProducer>>&
        OutputConfiguration::getGraphicBufferProducers() const {
    return mGbps;
}

int OutputConfiguration::getRotation() const {
    return mRotation;
}

int OutputConfiguration::getSurfaceSetID() const {
    return mSurfaceSetID;
}

int OutputConfiguration::getSurfaceType() const {
    return mSurfaceType;
}

int OutputConfiguration::getWidth() const {
    return mWidth;
}

int OutputConfiguration::getHeight() const {
    return mHeight;
}

bool OutputConfiguration::isDeferred() const {
    return mIsDeferred;
}

bool OutputConfiguration::isShared() const {
    return mIsShared;
}

std::string OutputConfiguration::getPhysicalCameraId() const {
    return mPhysicalCameraId;
}

bool OutputConfiguration::isMultiResolution() const {
    return mIsMultiResolution;
}

const std::vector<int32_t> &OutputConfiguration::getSensorPixelModesUsed() const {
    return mSensorPixelModesUsed;
}

int64_t OutputConfiguration::getDynamicRangeProfile() const {
    return mDynamicRangeProfile;
}

int64_t OutputConfiguration::getStreamUseCase() const {
    return mStreamUseCase;
}

int OutputConfiguration::getTimestampBase() const {
    return mTimestampBase;
}

int OutputConfiguration::getMirrorMode() const {
    return mMirrorMode;
}

OutputConfiguration::OutputConfiguration() :
        mRotation(INVALID_ROTATION),
        mSurfaceSetID(INVALID_SET_ID),
        mSurfaceType(SURFACE_TYPE_UNKNOWN),
        mWidth(0),
        mHeight(0),
        mIsDeferred(false),
        mIsShared(false),
        mIsMultiResolution(false),
        mDynamicRangeProfile(ANDROID_REQUEST_AVAILABLE_DYNAMIC_RANGE_PROFILES_MAP_STANDARD),
        mStreamUseCase(ANDROID_SCALER_AVAILABLE_STREAM_USE_CASES_DEFAULT),
        mTimestampBase(TIMESTAMP_BASE_DEFAULT),
        mMirrorMode(MIRROR_MODE_AUTO) {
}

OutputConfiguration::OutputConfiguration(const android::Parcel& parcel) :
        mRotation(INVALID_ROTATION),
        mSurfaceSetID(INVALID_SET_ID) {
    readFromParcel(&parcel);
}

status_t OutputConfiguration::readFromParcel(const android::Parcel* parcel) {
    status_t err = OK;
    int rotation = 0;

    if (parcel == nullptr) return BAD_VALUE;

    if ((err = parcel->readInt32(&rotation)) != OK) {
        ALOGE("%s: Failed to read rotation from parcel", __FUNCTION__);
        return err;
    }

    int setID = INVALID_SET_ID;
    if ((err = parcel->readInt32(&setID)) != OK) {
        ALOGE("%s: Failed to read surface set ID from parcel", __FUNCTION__);
        return err;
    }

    int surfaceType = SURFACE_TYPE_UNKNOWN;
    if ((err = parcel->readInt32(&surfaceType)) != OK) {
        ALOGE("%s: Failed to read surface type from parcel", __FUNCTION__);
        return err;
    }

    int width = 0;
    if ((err = parcel->readInt32(&width)) != OK) {
        ALOGE("%s: Failed to read surface width from parcel", __FUNCTION__);
        return err;
    }

    int height = 0;
    if ((err = parcel->readInt32(&height)) != OK) {
        ALOGE("%s: Failed to read surface height from parcel", __FUNCTION__);
        return err;
    }

    int isDeferred = 0;
    if ((err = parcel->readInt32(&isDeferred)) != OK) {
        ALOGE("%s: Failed to read surface isDeferred flag from parcel", __FUNCTION__);
        return err;
    }

    int isShared = 0;
    if ((err = parcel->readInt32(&isShared)) != OK) {
        ALOGE("%s: Failed to read surface isShared flag from parcel", __FUNCTION__);
        return err;
    }

    if (isDeferred && surfaceType != SURFACE_TYPE_SURFACE_VIEW &&
            surfaceType != SURFACE_TYPE_SURFACE_TEXTURE) {
        ALOGE("%s: Invalid surface type for deferred configuration", __FUNCTION__);
        return BAD_VALUE;
    }

    std::vector<view::Surface> surfaceShims;
    if ((err = parcel->readParcelableVector(&surfaceShims)) != OK) {
        ALOGE("%s: Failed to read surface(s) from parcel", __FUNCTION__);
        return err;
    }

    String16 physicalCameraId;
    parcel->readString16(&physicalCameraId);
    mPhysicalCameraId = toStdString(physicalCameraId);

    int isMultiResolution = 0;
    if ((err = parcel->readInt32(&isMultiResolution)) != OK) {
        ALOGE("%s: Failed to read surface isMultiResolution flag from parcel", __FUNCTION__);
        return err;
    }

    std::vector<int32_t> sensorPixelModesUsed;
    if ((err = parcel->readInt32Vector(&sensorPixelModesUsed)) != OK) {
        ALOGE("%s: Failed to read sensor pixel mode(s) from parcel", __FUNCTION__);
        return err;
    }
    int64_t dynamicProfile;
    if ((err = parcel->readInt64(&dynamicProfile)) != OK) {
        ALOGE("%s: Failed to read surface dynamic range profile flag from parcel", __FUNCTION__);
        return err;
    }

    int64_t streamUseCase = ANDROID_SCALER_AVAILABLE_STREAM_USE_CASES_DEFAULT;
    if ((err = parcel->readInt64(&streamUseCase)) != OK) {
        ALOGE("%s: Failed to read stream use case from parcel", __FUNCTION__);
        return err;
    }

    int timestampBase = TIMESTAMP_BASE_DEFAULT;
    if ((err = parcel->readInt32(&timestampBase)) != OK) {
        ALOGE("%s: Failed to read timestamp base from parcel", __FUNCTION__);
        return err;
    }

    int mirrorMode = MIRROR_MODE_AUTO;
    if ((err = parcel->readInt32(&mirrorMode)) != OK) {
        ALOGE("%s: Failed to read mirroring mode from parcel", __FUNCTION__);
        return err;
    }

    mRotation = rotation;
    mSurfaceSetID = setID;
    mSurfaceType = surfaceType;
    mWidth = width;
    mHeight = height;
    mIsDeferred = isDeferred != 0;
    mIsShared = isShared != 0;
    mIsMultiResolution = isMultiResolution != 0;
    mStreamUseCase = streamUseCase;
    mTimestampBase = timestampBase;
    mMirrorMode = mirrorMode;
    for (auto& surface : surfaceShims) {
        ALOGV("%s: OutputConfiguration: %p, name %s", __FUNCTION__,
                surface.graphicBufferProducer.get(),
                toString8(surface.name).c_str());
        mGbps.push_back(surface.graphicBufferProducer);
    }

    mSensorPixelModesUsed = std::move(sensorPixelModesUsed);
    mDynamicRangeProfile = dynamicProfile;

    ALOGV("%s: OutputConfiguration: rotation = %d, setId = %d, surfaceType = %d,"
          " physicalCameraId = %s, isMultiResolution = %d, streamUseCase = %" PRId64
          ", timestampBase = %d, mirrorMode = %d",
          __FUNCTION__, mRotation, mSurfaceSetID, mSurfaceType,
          mPhysicalCameraId.c_str(), mIsMultiResolution, mStreamUseCase, timestampBase,
          mMirrorMode);

    return err;
}

OutputConfiguration::OutputConfiguration(sp<IGraphicBufferProducer>& gbp, int rotation,
        const std::string& physicalId,
        int surfaceSetID, bool isShared) {
    mGbps.push_back(gbp);
    mRotation = rotation;
    mSurfaceSetID = surfaceSetID;
    mIsDeferred = false;
    mIsShared = isShared;
    mPhysicalCameraId = physicalId;
    mIsMultiResolution = false;
    mDynamicRangeProfile = ANDROID_REQUEST_AVAILABLE_DYNAMIC_RANGE_PROFILES_MAP_STANDARD;
    mStreamUseCase = ANDROID_SCALER_AVAILABLE_STREAM_USE_CASES_DEFAULT;
    mTimestampBase = TIMESTAMP_BASE_DEFAULT;
    mMirrorMode = MIRROR_MODE_AUTO;
}

OutputConfiguration::OutputConfiguration(
        const std::vector<sp<IGraphicBufferProducer>>& gbps,
    int rotation, const std::string& physicalCameraId, int surfaceSetID,  int surfaceType,
    int width, int height, bool isShared)
  : mGbps(gbps), mRotation(rotation), mSurfaceSetID(surfaceSetID), mSurfaceType(surfaceType),
    mWidth(width), mHeight(height), mIsDeferred(false), mIsShared(isShared),
    mPhysicalCameraId(physicalCameraId), mIsMultiResolution(false),
    mDynamicRangeProfile(ANDROID_REQUEST_AVAILABLE_DYNAMIC_RANGE_PROFILES_MAP_STANDARD),
    mStreamUseCase(ANDROID_SCALER_AVAILABLE_STREAM_USE_CASES_DEFAULT),
    mTimestampBase(TIMESTAMP_BASE_DEFAULT),
    mMirrorMode(MIRROR_MODE_AUTO) { }

status_t OutputConfiguration::writeToParcel(android::Parcel* parcel) const {

    if (parcel == nullptr) return BAD_VALUE;
    status_t err = OK;

    err = parcel->writeInt32(mRotation);
    if (err != OK) return err;

    err = parcel->writeInt32(mSurfaceSetID);
    if (err != OK) return err;

    err = parcel->writeInt32(mSurfaceType);
    if (err != OK) return err;

    err = parcel->writeInt32(mWidth);
    if (err != OK) return err;

    err = parcel->writeInt32(mHeight);
    if (err != OK) return err;

    err = parcel->writeInt32(mIsDeferred ? 1 : 0);
    if (err != OK) return err;

    err = parcel->writeInt32(mIsShared ? 1 : 0);
    if (err != OK) return err;

    std::vector<view::Surface> surfaceShims;
    for (auto& gbp : mGbps) {
        view::Surface surfaceShim;
        surfaceShim.name = String16("unknown_name"); // name of surface
        surfaceShim.graphicBufferProducer = gbp;
        surfaceShims.push_back(surfaceShim);
    }
    err = parcel->writeParcelableVector(surfaceShims);
    if (err != OK) return err;

    String16 physicalCameraId = toString16(mPhysicalCameraId);
    err = parcel->writeString16(physicalCameraId);
    if (err != OK) return err;

    err = parcel->writeInt32(mIsMultiResolution ? 1 : 0);
    if (err != OK) return err;

    err = parcel->writeParcelableVector(mSensorPixelModesUsed);
    if (err != OK) return err;

    err = parcel->writeInt64(mDynamicRangeProfile);
    if (err != OK) return err;

    err = parcel->writeInt64(mStreamUseCase);
    if (err != OK) return err;

    err = parcel->writeInt32(mTimestampBase);
    if (err != OK) return err;

    err = parcel->writeInt32(mMirrorMode);
    if (err != OK) return err;

    return OK;
}

template <typename T>
static bool simpleVectorsEqual(T first, T second) {
    if (first.size() != second.size()) {
        return false;
    }

    for (size_t i = 0; i < first.size(); i++) {
        if (first[i] != second[i]) {
            return false;
        }
    }
    return true;
}

bool OutputConfiguration::gbpsEqual(const OutputConfiguration& other) const {
    const std::vector<sp<IGraphicBufferProducer> >& otherGbps =
            other.getGraphicBufferProducers();
    return simpleVectorsEqual(otherGbps, mGbps);
}

bool OutputConfiguration::sensorPixelModesUsedEqual(const OutputConfiguration& other) const {
    const std::vector<int32_t>& othersensorPixelModesUsed = other.getSensorPixelModesUsed();
    return simpleVectorsEqual(othersensorPixelModesUsed, mSensorPixelModesUsed);
}

bool OutputConfiguration::sensorPixelModesUsedLessThan(const OutputConfiguration& other) const {
    const std::vector<int32_t>& spms = other.getSensorPixelModesUsed();

    if (mSensorPixelModesUsed.size() !=  spms.size()) {
        return mSensorPixelModesUsed.size() < spms.size();
    }

    for (size_t i = 0; i < spms.size(); i++) {
        if (mSensorPixelModesUsed[i] != spms[i]) {
            return mSensorPixelModesUsed[i] < spms[i];
        }
    }

    return false;
}

bool OutputConfiguration::gbpsLessThan(const OutputConfiguration& other) const {
    const std::vector<sp<IGraphicBufferProducer> >& otherGbps =
            other.getGraphicBufferProducers();

    if (mGbps.size() !=  otherGbps.size()) {
        return mGbps.size() < otherGbps.size();
    }

    for (size_t i = 0; i < mGbps.size(); i++) {
        if (mGbps[i] != otherGbps[i]) {
            return mGbps[i] < otherGbps[i];
        }
    }

    return false;
}
}; // namespace android
