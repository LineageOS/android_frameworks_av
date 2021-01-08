/*
 * Copyright (C) 2004-2010 NXP Software
 * Copyright (C) 2010 The Android Open Source Project
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

/**********************************************************************************
   INCLUDE FILES
***********************************************************************************/

#include "VectorArithmetic.h"
#include "LVM_Macros.h"

void Mac3s_Sat_Float(const LVM_FLOAT* src, const LVM_FLOAT val, LVM_FLOAT* dst, LVM_INT16 n) {
    LVM_INT16 ii;
    LVM_FLOAT srcval;
    LVM_FLOAT Temp, dInVal;

    for (ii = n; ii != 0; ii--) {
        srcval = *src;
        src++;

        Temp = srcval * val;

        dInVal = (LVM_FLOAT)*dst;
        Temp = Temp + dInVal;

        if (Temp > 1.000000f) {
            *dst = 1.000000f;
        } else if (Temp < -1.000000f) {
            *dst = -1.000000f;
        } else {
            *dst = Temp;
        }
        dst++;
    }

    return;
}
