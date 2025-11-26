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
#include <com_android_internal_camera_flags.h>
#include <binder/Parcel.h>
#include <gui/view/Surface.h>
#include <system/camera_metadata.h>
#include <system/graphics.h>
#include <utils/String8.h>

namespace flags = com::android::internal::camera::flags;

namespace android {

const int OutputConfiguration::INVALID_ROTATION = -1;
const int OutputConfiguration::ROTATION_0 = 0;
const int OutputConfiguration::INVALID_SET_ID = -1;

const std::vector<ParcelableSurfaceType>& OutputConfiguration::getSurfaces() const {
    return mSurfaces;
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

int OutputConfiguration::getMultiResMode() const {
    return mMultiResMode;
}

const std::vector<int32_t> &OutputConfiguration::getSensorPixelModesUsed() const {
    return mSensorPixelModesUsed;
}

int64_t OutputConfiguration::getDynamicRangeProfile() const {
    return mDynamicRangeProfile;
}

int32_t OutputConfiguration::getColorSpace() const {
    return mColorSpace;
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

int OutputConfiguration::getMirrorMode(ParcelableSurfaceType surface) const {
    if (!flags::mirror_mode_shared_surfaces()) {
        return mMirrorMode;
    }

    if (mSurfaces.size() != mMirrorModeForProducers.size()) {
        ALOGE("%s: mSurfaces size doesn't match mMirrorModeForProducers: %zu vs %zu",
                __FUNCTION__, mSurfaces.size(), mMirrorModeForProducers.size());
        return mMirrorMode;
    }

    // Use per-producer mirror mode if available.
    for (size_t i = 0; i < mSurfaces.size(); i++) {
        if (mSurfaces[i] == surface) {
            return mMirrorModeForProducers[i];
        }
    }
    // For surface that doesn't belong to this output configuration, use
    // mMirrorMode as default.
    ALOGW("%s: Surface doesn't belong to this OutputConfiguration!", __FUNCTION__);
    return mMirrorMode;
}

bool OutputConfiguration::useReadoutTimestamp() const {
    return mUseReadoutTimestamp;
}

int OutputConfiguration::getFormat() const {
    return mFormat;
}

int OutputConfiguration::getDataspace() const {
    return mDataspace;
}

int64_t OutputConfiguration::getUsage() const {
    return mUsage;
}

bool OutputConfiguration::isComplete() const {
    return !((mSurfaceType == SURFACE_TYPE_MEDIA_RECORDER ||
              mSurfaceType == SURFACE_TYPE_MEDIA_CODEC ||
              mSurfaceType == SURFACE_TYPE_IMAGE_READER) &&
             mSurfaces.empty());
}

OutputConfiguration::OutputConfiguration() :
        mRotation(INVALID_ROTATION),
        mSurfaceSetID(INVALID_SET_ID),
        mSurfaceType(SURFACE_TYPE_UNKNOWN),
        mWidth(0),
        mHeight(0),
        mIsDeferred(false),
        mIsShared(false),
        mMultiResMode(MULTI_RES_OFF),
        mDynamicRangeProfile(ANDROID_REQUEST_AVAILABLE_DYNAMIC_RANGE_PROFILES_MAP_STANDARD),
        mColorSpace(ANDROID_REQUEST_AVAILABLE_COLOR_SPACE_PROFILES_MAP_UNSPECIFIED),
        mStreamUseCase(ANDROID_SCALER_AVAILABLE_STREAM_USE_CASES_DEFAULT),
        mTimestampBase(TIMESTAMP_BASE_DEFAULT),
        mMirrorMode(MIRROR_MODE_AUTO),
        mUseReadoutTimestamp(false),
        mFormat(HAL_PIXEL_FORMAT_IMPLEMENTATION_DEFINED),
        mDataspace(0),
        mUsage(0) {
}

OutputConfiguration::OutputConfiguration(int surfaceType, int width, int height, int format,
        int32_t colorSpace, int mirrorMode, bool useReadoutTimestamp, int timestampBase,
        int dataspace, int64_t usage, int64_t streamusecase, std::string physicalCamId):
        mRotation(ROTATION_0),
        mSurfaceSetID(INVALID_SET_ID),
        mSurfaceType(surfaceType),
        mWidth(width),
        mHeight(height),
        mIsDeferred(false),
        mIsShared(false),
        mPhysicalCameraId(physicalCamId),
        mMultiResMode(MULTI_RES_OFF),
        mDynamicRangeProfile(ANDROID_REQUEST_AVAILABLE_DYNAMIC_RANGE_PROFILES_MAP_STANDARD),
        mColorSpace(colorSpace),
        mStreamUseCase(streamusecase),
        mTimestampBase(timestampBase),
        mMirrorMode(mirrorMode),
        mUseReadoutTimestamp(useReadoutTimestamp),
        mFormat(format),
        mDataspace(dataspace),
        mUsage(usage){
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

    if (!flags::seamless_transitions()) {
        if (isDeferred && surfaceType != SURFACE_TYPE_SURFACE_VIEW &&
                surfaceType != SURFACE_TYPE_SURFACE_TEXTURE) {
            ALOGE("%s: Invalid surface type for deferred configuration", __FUNCTION__);
            return BAD_VALUE;
        }
    }

    std::vector<view::Surface> surfaceShims;
    if ((err = parcel->readParcelableVector(&surfaceShims)) != OK) {
        ALOGE("%s: Failed to read surface(s) from parcel", __FUNCTION__);
        return err;
    }

    String16 physicalCameraId;
    parcel->readString16(&physicalCameraId);
    mPhysicalCameraId = toStdString(physicalCameraId);

    int multiResMode = 0;
    if ((err = parcel->readInt32(&multiResMode)) != OK) {
        ALOGE("%s: Failed to read surface multiResMode from parcel", __FUNCTION__);
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
    int32_t colorSpace;
    if ((err = parcel->readInt32(&colorSpace)) != OK) {
        ALOGE("%s: Failed to read surface color space flag from parcel", __FUNCTION__);
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

    std::vector<int> mirrorModeForProducers;
    if ((err = parcel->readInt32Vector(&mirrorModeForProducers)) != OK) {
        ALOGE("%s: Failed to read mirroring mode for surfaces from parcel", __FUNCTION__);
        return err;
    }

    int useReadoutTimestamp = 0;
    if ((err = parcel->readInt32(&useReadoutTimestamp)) != OK) {
        ALOGE("%s: Failed to read useReadoutTimestamp flag from parcel", __FUNCTION__);
        return err;
    }

    int format = HAL_PIXEL_FORMAT_IMPLEMENTATION_DEFINED;
    if ((err = parcel->readInt32(&format)) != OK) {
        ALOGE("%s: Failed to read format from parcel", __FUNCTION__);
        return err;
    }

    int dataspace = 0;
    if ((err = parcel->readInt32(&dataspace)) != OK) {
        ALOGE("%s: Failed to read dataspace from parcel", __FUNCTION__);
        return err;
    }

    int64_t usage = 0;
    if ((err = parcel->readInt64(&usage)) != OK) {
        ALOGE("%s: Failed to read usage flag from parcel", __FUNCTION__);
        return err;
    }

    mRotation = rotation;
    mSurfaceSetID = setID;
    mSurfaceType = surfaceType;
    mWidth = width;
    mHeight = height;
    mIsDeferred = isDeferred != 0;
    mIsShared = isShared != 0;
    mMultiResMode = multiResMode;
    mStreamUseCase = streamUseCase;
    mTimestampBase = timestampBase;
    mMirrorMode = mirrorMode;
    mMirrorModeForProducers = std::move(mirrorModeForProducers);
    mUseReadoutTimestamp = useReadoutTimestamp != 0;
    for (auto& surface : surfaceShims) {
#if WB_LIBCAMERASERVICE_WITH_DEPENDENCIES
        IF_ALOGV() {
            uint64_t bufferID;
            surface.getUniqueId(&bufferID);
            ALOGV("%s: OutputConfiguration: %" PRIu64 ", name %s", __FUNCTION__,
                    bufferID, toString8(surface.name).c_str());
        }
#else
        ALOGV("%s: OutputConfiguration: %p, name %s", __FUNCTION__,
                surface.graphicBufferProducer.get(),
                toString8(surface.name).c_str());
#endif
        mSurfaces.push_back(flagtools::toParcelableSurfaceType(surface));
    }

    mSensorPixelModesUsed = std::move(sensorPixelModesUsed);
    mDynamicRangeProfile = dynamicProfile;
    mColorSpace = colorSpace;
    mFormat = format;
    mDataspace = dataspace;
    mUsage = usage;

    ALOGV("%s: OutputConfiguration: rotation = %d, setId = %d, surfaceType = %d,"
          " physicalCameraId = %s, multiResMode = %d, streamUseCase = %" PRId64
          ", timestampBase = %d, mirrorMode = %d, useReadoutTimestamp = %d, format = %d, "
          "dataspace = %d, usage = %" PRId64,
          __FUNCTION__, mRotation, mSurfaceSetID, mSurfaceType,
          mPhysicalCameraId.c_str(), mMultiResMode, mStreamUseCase, timestampBase,
          mMirrorMode, mUseReadoutTimestamp, mFormat, mDataspace, mUsage);

    return err;
}


void OutputConfiguration::inferSurfaceProperties() {
    if (mSurfaces.empty()) {
        return;
    }

#if WB_LIBCAMERASERVICE_WITH_DEPENDENCIES
    if (mSurfaces[0].graphicBufferProducer->query(NATIVE_WINDOW_FORMAT, &mFormat) != OK) {
        ALOGE("%s: NATIVE_WINDOW_FORMAT query failed", __FUNCTION__);
    }
    if (mSurfaces[0].graphicBufferProducer->query(NATIVE_WINDOW_DEFAULT_DATASPACE,
            &mDataspace) != OK) {
        ALOGE("%s: NATIVE_WINDOW_DEFAULT_DATASPACE query failed", __FUNCTION__);
    }
    if (mSurfaces[0].graphicBufferProducer->query(NATIVE_WINDOW_WIDTH, &mWidth) != OK) {
        ALOGE("%s: NATIVE_WINDOW_WIDTH query failed", __FUNCTION__);
    }
    if (mSurfaces[0].graphicBufferProducer->query(NATIVE_WINDOW_HEIGHT, &mHeight) != OK) {
        ALOGE("%s: NATIVE_WINDOW_HEIGHT query failed", __FUNCTION__);
    }
#else
    if (mSurfaces[0]->query(NATIVE_WINDOW_FORMAT, &mFormat) != OK) {
        ALOGE("%s: NATIVE_WINDOW_FORMAT query failed", __FUNCTION__);
    }
    if (mSurfaces[0]->query(NATIVE_WINDOW_DEFAULT_DATASPACE, &mDataspace) != OK) {
        ALOGE("%s: NATIVE_WINDOW_DEFAULT_DATASPACE query failed", __FUNCTION__);
    }
    if (mSurfaces[0]->query(NATIVE_WINDOW_WIDTH, &mWidth) != OK) {
        ALOGE("%s: NATIVE_WINDOW_WIDTH query failed", __FUNCTION__);
    }
    if (mSurfaces[0]->query(NATIVE_WINDOW_HEIGHT, &mHeight) != OK) {
        ALOGE("%s: NATIVE_WINDOW_HEIGHT query failed", __FUNCTION__);
    }
#endif
}

OutputConfiguration::OutputConfiguration(ParcelableSurfaceType& surface, int rotation,
        const std::string& physicalId,
        int surfaceSetID, bool isShared) {
    mSurfaces.push_back(surface);
    mRotation = rotation;
    mSurfaceSetID = surfaceSetID;
    mIsDeferred = false;
    mIsShared = isShared;
    mPhysicalCameraId = physicalId;
    mMultiResMode = MULTI_RES_OFF;
    mDynamicRangeProfile = ANDROID_REQUEST_AVAILABLE_DYNAMIC_RANGE_PROFILES_MAP_STANDARD;
    mColorSpace = ANDROID_REQUEST_AVAILABLE_COLOR_SPACE_PROFILES_MAP_UNSPECIFIED;
    mStreamUseCase = ANDROID_SCALER_AVAILABLE_STREAM_USE_CASES_DEFAULT;
    mTimestampBase = TIMESTAMP_BASE_DEFAULT;
    mMirrorMode = MIRROR_MODE_AUTO;
    mMirrorModeForProducers.push_back(mMirrorMode);
    mUseReadoutTimestamp = false;
    mFormat = HAL_PIXEL_FORMAT_IMPLEMENTATION_DEFINED;
    mDataspace = 0;
    mUsage = 0;
    inferSurfaceProperties();
}

OutputConfiguration::OutputConfiguration(
        const std::vector<ParcelableSurfaceType>& surfaces,
    int rotation, const std::string& physicalCameraId, int surfaceSetID,  int surfaceType,
    int width, int height, bool isShared, int format, int dataSpace)
  : mSurfaces(surfaces), mRotation(rotation), mSurfaceSetID(surfaceSetID),
    mSurfaceType(surfaceType), mWidth(width), mHeight(height), mIsDeferred(false),
    mIsShared(isShared), mPhysicalCameraId(physicalCameraId), mMultiResMode(MULTI_RES_OFF),
    mDynamicRangeProfile(ANDROID_REQUEST_AVAILABLE_DYNAMIC_RANGE_PROFILES_MAP_STANDARD),
    mColorSpace(ANDROID_REQUEST_AVAILABLE_COLOR_SPACE_PROFILES_MAP_UNSPECIFIED),
    mStreamUseCase(ANDROID_SCALER_AVAILABLE_STREAM_USE_CASES_DEFAULT),
    mTimestampBase(TIMESTAMP_BASE_DEFAULT),
    mMirrorMode(MIRROR_MODE_AUTO), mMirrorModeForProducers(surfaces.size(), mMirrorMode),
    mUseReadoutTimestamp(false), mFormat(format),
    mDataspace(dataSpace), mUsage(0) { }

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

#if WB_LIBCAMERASERVICE_WITH_DEPENDENCIES
    err = parcel->writeParcelableVector(mSurfaces);
#else
    std::vector<view::Surface> surfaceShims;
    for (auto& gbp : mSurfaces) {
        view::Surface surfaceShim;
        surfaceShim.name = String16("unknown_name"); // name of surface
        surfaceShim.graphicBufferProducer = gbp;
        surfaceShims.push_back(surfaceShim);
    }
    err = parcel->writeParcelableVector(surfaceShims);
#endif
    if (err != OK) return err;

    String16 physicalCameraId = toString16(mPhysicalCameraId);
    err = parcel->writeString16(physicalCameraId);
    if (err != OK) return err;

    err = parcel->writeInt32(mMultiResMode);
    if (err != OK) return err;

    err = parcel->writeParcelableVector(mSensorPixelModesUsed);
    if (err != OK) return err;

    err = parcel->writeInt64(mDynamicRangeProfile);
    if (err != OK) return err;

    err = parcel->writeInt32(mColorSpace);
    if (err != OK) return err;

    err = parcel->writeInt64(mStreamUseCase);
    if (err != OK) return err;

    err = parcel->writeInt32(mTimestampBase);
    if (err != OK) return err;

    err = parcel->writeInt32(mMirrorMode);
    if (err != OK) return err;

    err = parcel->writeInt32Vector(mMirrorModeForProducers);
    if (err != OK) return err;

    err = parcel->writeInt32(mUseReadoutTimestamp ? 1 : 0);
    if (err != OK) return err;

    err = parcel->writeInt32(mFormat);
    if (err != OK) return err;

    err = parcel->writeInt32(mDataspace);
    if (err != OK) return err;

    err = parcel->writeInt64(mUsage);
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

template <typename T>
static bool simpleVectorsLessThan(T first, T second) {
    if (first.size() != second.size()) {
        return first.size() < second.size();
    }

    for (size_t i = 0; i < first.size(); i++) {
        if (first[i] != second[i]) {
            return first[i] < second[i];
        }
    }
    return false;
}

bool OutputConfiguration::surfacesEqual(const OutputConfiguration& other) const {
    const std::vector<ParcelableSurfaceType>& otherSurfaces = other.getSurfaces();
    return simpleVectorsEqual(otherSurfaces, mSurfaces);
}

bool OutputConfiguration::sensorPixelModesUsedEqual(const OutputConfiguration& other) const {
    const std::vector<int32_t>& othersensorPixelModesUsed = other.getSensorPixelModesUsed();
    return simpleVectorsEqual(othersensorPixelModesUsed, mSensorPixelModesUsed);
}

bool OutputConfiguration::mirrorModesEqual(const OutputConfiguration& other) const {
    const std::vector<int>& otherMirrorModes = other.getMirrorModes();
    return simpleVectorsEqual(otherMirrorModes, mMirrorModeForProducers);
}

bool OutputConfiguration::sensorPixelModesUsedLessThan(const OutputConfiguration& other) const {
    const std::vector<int32_t>& spms = other.getSensorPixelModesUsed();
    return simpleVectorsLessThan(mSensorPixelModesUsed, spms);
}

bool OutputConfiguration::mirrorModesLessThan(const OutputConfiguration& other) const {
    const std::vector<int>& otherMirrorModes = other.getMirrorModes();
    return simpleVectorsLessThan(mMirrorModeForProducers, otherMirrorModes);
}

bool OutputConfiguration::surfacesLessThan(const OutputConfiguration& other) const {
    const std::vector<ParcelableSurfaceType>& otherSurfaces = other.getSurfaces();

    if (mSurfaces.size() != otherSurfaces.size()) {
        return mSurfaces.size() < otherSurfaces.size();
    }

    for (size_t i = 0; i < mSurfaces.size(); i++) {
        if (mSurfaces[i] != otherSurfaces[i]) {
            return mSurfaces[i] < otherSurfaces[i];
        }
    }

    return false;
}
}; // namespace android
