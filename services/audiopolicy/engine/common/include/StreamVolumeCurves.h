/*
 * Copyright (C) 2018 The Android Open Source Project
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

#pragma once

#include <VolumeCurve.h>
#include <map>

namespace android {

class StreamVolumeCurves
{
public:
    StreamVolumeCurves() = default;

    /**
     * @brief switchVolumeCurve control API for Engine, allows to switch the volume curves
     * from one stream type to another.
     * @param src source stream type
     * @param dst destination stream type
     */
    status_t switchVolumeCurve(audio_stream_type_t streamSrc, audio_stream_type_t streamDst)
    {
        if (!hasCurvesFor(streamSrc) || !hasCurvesFor(streamDst)) {
            ALOGE("%s: No curves defined for streams %d %d", __FUNCTION__, streamSrc, streamDst);
            return NO_INIT;
        }
        const VolumeCurves &sourceCurves = getCurvesFor(streamSrc);
        VolumeCurves &dstCurves = editCurvesFor(streamDst);
        return dstCurves.switchCurvesFrom(sourceCurves);
    }
    void dump(String8 *dst, int spaces = 0) const;

    void add(const VolumeCurves &curves, audio_stream_type_t streamType)
    {
        mCurves.emplace(streamType, curves);
    }

    bool hasCurvesFor(audio_stream_type_t stream)
    {
        return mCurves.find(stream) != end(mCurves);
    }

    VolumeCurves &editCurvesFor(audio_stream_type_t stream)
    {
        ALOG_ASSERT(mCurves.find(stream) != end(mCurves), "Invalid stream type for Volume Curve");
        return mCurves[stream];
    }
    const VolumeCurves &getCurvesFor(audio_stream_type_t stream) const
    {
        ALOG_ASSERT(mCurves.find(stream) != end(mCurves), "Invalid stream type for Volume Curve");
        return mCurves.at(stream);
    }
    /**
     * @brief getVolumeCurvesForStream
     * @param stream type for which the volume curves interface is requested
     * @return the VolumeCurves for a given stream type.
     */
    VolumeCurves &getVolumeCurvesForStream(audio_stream_type_t stream)
    {
        ALOG_ASSERT(mCurves.find(stream) != end(mCurves), "Invalid stream type for Volume Curve");
        return mCurves[stream];
    }
    /**
     * @brief restoreOriginVolumeCurve helper control API for engine to restore the original volume
     * curves for a given stream type
     * @param stream for which the volume curves will be restored.
     */
    status_t restoreOriginVolumeCurve(audio_stream_type_t stream)
    {
        if (!hasCurvesFor(stream)) {
            ALOGE("%s: No curves defined for streams", __FUNCTION__);
            return NO_INIT;
        }
        return switchVolumeCurve(stream, stream);
    }

private:
    std::map<audio_stream_type_t, VolumeCurves> mCurves;
};

} // namespace android
