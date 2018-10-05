/*
 * Copyright (C) 2015 The Android Open Source Project
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

#define LOG_TAG "APM::VolumeCurve"
//#define LOG_NDEBUG 0

#include "VolumeCurve.h"
#include "TypeConverter.h"

namespace android {

float VolumeCurve::volIndexToDb(int indexInUi, int volIndexMin, int volIndexMax) const
{
    ALOG_ASSERT(!mCurvePoints.isEmpty(), "Invalid volume curve");

    size_t nbCurvePoints = mCurvePoints.size();
    // the volume index in the UI is relative to the min and max volume indices for this stream
    int nbSteps = 1 + mCurvePoints[nbCurvePoints - 1].mIndex - mCurvePoints[0].mIndex;
    if (indexInUi < volIndexMin) {
        ALOGV("VOLUME remapping index from %d to min index %d", indexInUi, volIndexMin);
        indexInUi = volIndexMin;
    } else if (indexInUi > volIndexMax) {
        ALOGV("VOLUME remapping index from %d to max index %d", indexInUi, volIndexMax);
        indexInUi = volIndexMax;
    }
    int volIdx = (nbSteps * (indexInUi - volIndexMin)) / (volIndexMax - volIndexMin);

    // Where would this volume index been inserted in the curve point
    size_t indexInUiPosition = mCurvePoints.orderOf(CurvePoint(volIdx, 0));
    if (indexInUiPosition >= nbCurvePoints) {
        //use last point of table
        return mCurvePoints[nbCurvePoints - 1].mAttenuationInMb / 100.0f;
    }
    if (indexInUiPosition == 0) {
        if (indexInUiPosition != mCurvePoints[0].mIndex) {
            return VOLUME_MIN_DB; // out of bounds
        }
        return mCurvePoints[0].mAttenuationInMb / 100.0f;
    }
    // linear interpolation in the attenuation table in dB
    float decibels = (mCurvePoints[indexInUiPosition - 1].mAttenuationInMb / 100.0f) +
            ((float)(volIdx - mCurvePoints[indexInUiPosition - 1].mIndex)) *
                ( ((mCurvePoints[indexInUiPosition].mAttenuationInMb / 100.0f) -
                        (mCurvePoints[indexInUiPosition - 1].mAttenuationInMb / 100.0f)) /
                    ((float)(mCurvePoints[indexInUiPosition].mIndex -
                            mCurvePoints[indexInUiPosition - 1].mIndex)) );

    ALOGV("VOLUME mDeviceCategory %d, mStreamType %d vol index=[%d %d %d], dB=[%.1f %.1f %.1f]",
            mDeviceCategory, mStreamType,
            mCurvePoints[indexInUiPosition - 1].mIndex, volIdx,
            mCurvePoints[indexInUiPosition].mIndex,
            ((float)mCurvePoints[indexInUiPosition - 1].mAttenuationInMb / 100.0f), decibels,
            ((float)mCurvePoints[indexInUiPosition].mAttenuationInMb / 100.0f));

    return decibels;
}

void VolumeCurve::dump(String8 *dst) const
{
    dst->append(" {");
    for (size_t i = 0; i < mCurvePoints.size(); i++) {
        dst->appendFormat("(%3d, %5d)",
                 mCurvePoints[i].mIndex, mCurvePoints[i].mAttenuationInMb);
        dst->append(i == (mCurvePoints.size() - 1) ? " }\n" : ", ");
    }
}

void VolumeCurvesForStream::dump(String8 *dst, int spaces = 0, bool curvePoints) const
{
    if (!curvePoints) {
        dst->appendFormat("%s         %02d         %02d         ",
                 mCanBeMuted ? "true " : "false", mIndexMin, mIndexMax);
        for (size_t i = 0; i < mIndexCur.size(); i++) {
            dst->appendFormat("%04x : %02d, ", mIndexCur.keyAt(i), mIndexCur.valueAt(i));
        }
        dst->append("\n");
        return;
    }

    for (size_t i = 0; i < size(); i++) {
        std::string deviceCatLiteral;
        DeviceCategoryConverter::toString(keyAt(i), deviceCatLiteral);
        dst->appendFormat("%*s %s :",
                 spaces, "", deviceCatLiteral.c_str());
        valueAt(i)->dump(dst);
    }
    dst->append("\n");
}

void VolumeCurvesCollection::dump(String8 *dst) const
{
    dst->append("\nStreams dump:\n");
    dst->append(
             " Stream  Can be muted  Index Min  Index Max  Index Cur [device : index]...\n");
    for (size_t i = 0; i < size(); i++) {
        dst->appendFormat(" %02zu      ", i);
        valueAt(i).dump(dst);
    }
    dst->append("\nVolume Curves for Use Cases (aka Stream types) dump:\n");
    for (size_t i = 0; i < size(); i++) {
        std::string streamTypeLiteral;
        StreamTypeConverter::toString(keyAt(i), streamTypeLiteral);
        dst->appendFormat(
                 " %s (%02zu): Curve points for device category (index, attenuation in millibel)\n",
                 streamTypeLiteral.c_str(), i);
        valueAt(i).dump(dst, 2, true);
    }
}

} // namespace android
