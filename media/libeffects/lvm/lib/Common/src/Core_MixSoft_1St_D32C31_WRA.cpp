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

#include "Mixer_private.h"
#include "LVM_Macros.h"

/**********************************************************************************
   FUNCTION CORE_MIXSOFT_1ST_D32C31_WRA
***********************************************************************************/
void Core_MixSoft_1St_D32C31_WRA(   Mix_1St_Cll_FLOAT_t       *pInstance,
                                    const LVM_FLOAT     *src,
                                    LVM_FLOAT     *dst,
                                    LVM_INT16     n)
{
    LVM_FLOAT Temp1,Temp2;
    LVM_INT16 OutLoop;
    LVM_INT16 InLoop;
    LVM_FLOAT TargetTimesOneMinAlpha;
    LVM_FLOAT CurrentTimesAlpha;

    LVM_INT16 ii;

    InLoop = (LVM_INT16)(n >> 2); /* Process per 4 samples */
    OutLoop = (LVM_INT16)(n - (InLoop << 2));

    TargetTimesOneMinAlpha = (1.0f - pInstance->Alpha) * pInstance->Target; /* float * float in float */
    if (pInstance->Target >= pInstance->Current)
    {
        TargetTimesOneMinAlpha += (LVM_FLOAT)(2.0f / 2147483647.0f); /* Ceil*/
    }

    if (OutLoop != 0)
    {
        CurrentTimesAlpha = (pInstance->Current * pInstance->Alpha);
        pInstance->Current = TargetTimesOneMinAlpha + CurrentTimesAlpha;

        for (ii = OutLoop; ii != 0; ii--)
        {
            Temp1 = *src;
            src++;

            Temp2 = Temp1 * (pInstance->Current);
            *dst = Temp2;
            dst++;
        }
    }

    for (ii = InLoop; ii != 0; ii--)
    {
        CurrentTimesAlpha = pInstance->Current * pInstance->Alpha;
        pInstance->Current = TargetTimesOneMinAlpha + CurrentTimesAlpha;

            Temp1 = *src;
            src++;

            Temp2 = Temp1 * (pInstance->Current);
            *dst = Temp2;
            dst++;

            Temp1 = *src;
            src++;

            Temp2 = Temp1 * (pInstance->Current);
            *dst = Temp2;
            dst++;

            Temp1 = *src;
            src++;

            Temp2 = Temp1 * (pInstance->Current);
            *dst = Temp2;
            dst++;

            Temp1 = *src;
            src++;
            Temp2 = Temp1 * (pInstance->Current);
            *dst = Temp2;
            dst++;
    }
}
/**********************************************************************************/
