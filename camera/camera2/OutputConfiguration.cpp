/*
**
** Copyright 2015, The Android Open Source Project
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
#include <gui/Surface.h>
#include <binder/Parcel.h>

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

OutputConfiguration::OutputConfiguration() :
        mRotation(INVALID_ROTATION),
        mSurfaceSetID(INVALID_SET_ID),
        mSurfaceType(SURFACE_TYPE_UNKNOWN),
        mWidth(0),
        mHeight(0) {
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

    // numSurfaces is the total number of surfaces for this OutputConfiguration,
    // regardless the surface is deferred or not.
    int numSurfaces = 0;
    if ((err = parcel->readInt32(&numSurfaces)) != OK) {
        ALOGE("%s: Failed to read maxSurfaces from parcel", __FUNCTION__);
        return err;
    }
    if (numSurfaces < 1) {
        ALOGE("%s: there has to be at least 1 surface per"
              " outputConfiguration", __FUNCTION__);
        return BAD_VALUE;
    }

    // Read all surfaces from parcel. If a surface is deferred, readFromPacel
    // returns error, and a null surface is put into the mGbps. We assume all
    // deferred surfaces are after non-deferred surfaces in the parcel.
    // TODO: Need better way to detect deferred surface than using error
    // return from readFromParcel.
    std::vector<sp<IGraphicBufferProducer>> gbps;
    for (int i = 0; i < numSurfaces; i++) {
        view::Surface surfaceShim;
        if ((err = surfaceShim.readFromParcel(parcel)) != OK) {
            // Read surface failure for deferred surface configuration is expected.
            if ((surfaceType == SURFACE_TYPE_SURFACE_VIEW ||
                    surfaceType == SURFACE_TYPE_SURFACE_TEXTURE)) {
                ALOGV("%s: Get null surface from a deferred surface configuration (%dx%d)",
                        __FUNCTION__, width, height);
                err = OK;
            } else {
                ALOGE("%s: Failed to read surface from parcel", __FUNCTION__);
                return err;
            }
        }
        gbps.push_back(surfaceShim.graphicBufferProducer);
        ALOGV("%s: OutputConfiguration: gbps[%d] : %p, name %s", __FUNCTION__,
                i, gbps[i].get(), String8(surfaceShim.name).string());
    }

    mRotation = rotation;
    mSurfaceSetID = setID;
    mSurfaceType = surfaceType;
    mWidth = width;
    mHeight = height;
    mGbps = std::move(gbps);

    ALOGV("%s: OutputConfiguration: rotation = %d, setId = %d, surfaceType = %d",
            __FUNCTION__, mRotation, mSurfaceSetID, mSurfaceType);

    return err;
}

OutputConfiguration::OutputConfiguration(sp<IGraphicBufferProducer>& gbp, int rotation,
        int surfaceSetID) {
    mGbps.push_back(gbp);
    mRotation = rotation;
    mSurfaceSetID = surfaceSetID;
}

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

    int numSurfaces = mGbps.size();
    err = parcel->writeInt32(numSurfaces);
    if (err != OK) return err;

    for (int i = 0; i < numSurfaces; i++) {
        view::Surface surfaceShim;
        surfaceShim.name = String16("unknown_name"); // name of surface
        surfaceShim.graphicBufferProducer = mGbps[i];

        err = surfaceShim.writeToParcel(parcel);
        if (err != OK) return err;
    }

    return OK;
}

bool OutputConfiguration::gbpsEqual(const OutputConfiguration& other) const {
    const std::vector<sp<IGraphicBufferProducer> >& otherGbps =
            other.getGraphicBufferProducers();

    if (mGbps.size() != otherGbps.size()) {
        return false;
    }

    for (size_t i = 0; i < mGbps.size(); i++) {
        if (mGbps[i] != otherGbps[i]) {
            return false;
        }
    }

    return true;
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
