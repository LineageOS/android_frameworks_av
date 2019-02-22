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

#define LOG_TAG "APM::Engine::StreamVolumeCurves"
//#define LOG_NDEBUG 0

#include "StreamVolumeCurves.h"
#include <TypeConverter.h>

namespace android {

void StreamVolumeCurves::dump(String8 *dst, int spaces) const
{
    if (mCurves.empty()) {
        return;
    }
    dst->appendFormat("\n%*sStreams dump:\n", spaces, "");
    dst->appendFormat(
                "%*sStream  Can be muted  Index Min  Index Max  Index Cur [device : index]...\n", spaces + 2, "");
    for (const auto &streamCurve : mCurves) {
        streamCurve.second.dump(dst, spaces + 2, false);
    }
    dst->appendFormat("\n%*sVolume Curves for Use Cases (aka Stream types) dump:\n", spaces, "");
    for (const auto &streamCurve : mCurves) {
        std::string streamTypeLiteral;
        StreamTypeConverter::toString(streamCurve.first, streamTypeLiteral);
        dst->appendFormat(
                    " %s (%02d): Curve points for device category (index, attenuation in millibel)\n",
                    streamTypeLiteral.c_str(), streamCurve.first);
        streamCurve.second.dump(dst, spaces + 2, true);
    }
}

} // namespace android
