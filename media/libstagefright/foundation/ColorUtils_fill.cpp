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
#include <arpa/inet.h>
#include <media/stagefright/foundation/ColorUtils.h>

namespace android {

// shortcut names for brevity in the following tables
typedef ColorAspects CA;
typedef ColorUtils CU;

#define HI_UINT16(a) (((a) >> 8) & 0xFF)
#define LO_UINT16(a) ((a) & 0xFF)

//
// static
void ColorUtils::fillHdrStaticInfoBuffer( const HDRStaticInfo &info, uint8_t *data) {
    // Static_Metadata_Descriptor_ID
    data[0] = info.mID;

    // display primary 0
    data[1] = LO_UINT16(info.sType1.mR.x);
    data[2] = HI_UINT16(info.sType1.mR.x);
    data[3] = LO_UINT16(info.sType1.mR.y);
    data[4] = HI_UINT16(info.sType1.mR.y);

    // display primary 1
    data[5] = LO_UINT16(info.sType1.mG.x);
    data[6] = HI_UINT16(info.sType1.mG.x);
    data[7] = LO_UINT16(info.sType1.mG.y);
    data[8] = HI_UINT16(info.sType1.mG.y);

    // display primary 2
    data[9] = LO_UINT16(info.sType1.mB.x);
    data[10] = HI_UINT16(info.sType1.mB.x);
    data[11] = LO_UINT16(info.sType1.mB.y);
    data[12] = HI_UINT16(info.sType1.mB.y);

    // white point
    data[13] = LO_UINT16(info.sType1.mW.x);
    data[14] = HI_UINT16(info.sType1.mW.x);
    data[15] = LO_UINT16(info.sType1.mW.y);
    data[16] = HI_UINT16(info.sType1.mW.y);

    // MaxDisplayLuminance
    data[17] = LO_UINT16(info.sType1.mMaxDisplayLuminance);
    data[18] = HI_UINT16(info.sType1.mMaxDisplayLuminance);

    // MinDisplayLuminance
    data[19] = LO_UINT16(info.sType1.mMinDisplayLuminance);
    data[20] = HI_UINT16(info.sType1.mMinDisplayLuminance);

    // MaxContentLightLevel
    data[21] = LO_UINT16(info.sType1.mMaxContentLightLevel);
    data[22] = HI_UINT16(info.sType1.mMaxContentLightLevel);

    // MaxFrameAverageLightLevel
    data[23] = LO_UINT16(info.sType1.mMaxFrameAverageLightLevel);
    data[24] = HI_UINT16(info.sType1.mMaxFrameAverageLightLevel);
}


}  // namespace android

