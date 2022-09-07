/*
 * Copyright (C) 2016 The Android Open Source Project
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

//#define LOG_NDEBUG 0
#define LOG_TAG "ColorUtils"

#include <inttypes.h>
#include <media/stagefright/foundation/ColorUtils.h>
#include <media/NdkMediaFormat.h>
#include <utils/Log.h>

namespace android {

// static
void ColorUtils::setHDRStaticInfoIntoAMediaFormat(
        const HDRStaticInfo &info, AMediaFormat *format) {
    uint8_t *data = (uint8_t *) malloc(25);
    if (data != NULL) {
        fillHdrStaticInfoBuffer(info, data);
        AMediaFormat_setBuffer(format, "hdr-static-info", data, 25);
        free(data);
    }
}

}  // namespace android

