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

#include "LVC_Mixer_Private.h"
#include "LVM_Macros.h"

/**********************************************************************************
   FUNCTION LVCore_MIXSOFT_1ST_D16C31_WRA
***********************************************************************************/
void LVC_Core_MixInSoft_D16C31_SAT(LVMixer3_FLOAT_st *ptrInstance,
                                   const LVM_FLOAT   *src,
                                         LVM_FLOAT   *dst,
                                         LVM_INT16   n)
{

    LVM_INT16   OutLoop;
    LVM_INT16   InLoop;
    LVM_INT32   ii,jj;
    Mix_Private_FLOAT_st  *pInstance = (Mix_Private_FLOAT_st *)(ptrInstance->PrivateParams);
    LVM_FLOAT   Delta = pInstance->Delta;
    LVM_FLOAT   Current = pInstance->Current;
    LVM_FLOAT   Target = pInstance->Target;
    LVM_FLOAT   Temp;

    InLoop = (LVM_INT16)(n >> 2); /* Process per 4 samples */
    OutLoop = (LVM_INT16)(n - (InLoop << 2));

    if(Current < Target){
        if (OutLoop){
            Temp = Current + Delta;
            Current = Temp;
            if (Current > Target)
                Current = Target;

           for (ii = OutLoop; ii != 0; ii--){
                Temp = ((LVM_FLOAT)*dst) + (((LVM_FLOAT)*(src++) * Current));
                if (Temp > 1.0f)
                    *dst++ = 1.0f;
                else if (Temp < -1.0f)
                    *dst++ = -1.0f;
                else
                    *dst++ = (LVM_FLOAT)Temp;
            }
        }

        for (ii = InLoop; ii != 0; ii--){
            Temp = Current + Delta;
            Current = Temp;
            if (Current > Target)
                Current = Target;

            for (jj = 4; jj != 0 ; jj--){
                Temp = ((LVM_FLOAT)*dst) + (((LVM_FLOAT)*(src++) * Current));
                if (Temp > 1.0f)
                    *dst++ = 1.0f;
                else if (Temp < -1.0f)
                    *dst++ = -1.0f;
                else
                    *dst++ = (LVM_FLOAT)Temp;
            }
        }
    }
    else{
        if (OutLoop){
            Current -= Delta;
            if (Current < Target)
                Current = Target;

            for (ii = OutLoop; ii != 0; ii--){
                Temp = ((LVM_FLOAT)*dst) + (((LVM_FLOAT)*(src++) * Current));
                if (Temp > 1.0f)
                    *dst++ = 1.0f;
                else if (Temp < -1.0f)
                    *dst++ = -1.0f;
                else
                    *dst++ = (LVM_FLOAT)Temp;
            }
        }

        for (ii = InLoop; ii != 0; ii--){
            Current -= Delta;
            if (Current < Target)
                Current = Target;

            for (jj = 4; jj != 0 ; jj--){
                Temp = ((LVM_FLOAT)*dst) + (((LVM_FLOAT)*(src++) * Current));
                if (Temp > 1.0f)
                    *dst++ = 1.0f;
                else if (Temp < -1.0f)
                    *dst++ = -1.0f;
                else
                    *dst++ = (LVM_FLOAT)Temp;
            }
        }
    }
    pInstance->Current = Current;
}
#ifdef SUPPORT_MC
/*
 * FUNCTION:       LVC_Core_MixInSoft_Mc_D16C31_SAT
 *
 * DESCRIPTION:
 *  Mixer function with support for processing multichannel input.
 *
 * PARAMETERS:
 *  ptrInstance    Instance pointer
 *  src            Source
 *  dst            Destination
 *  NrFrames       Number of frames
 *  NrChannels     Number of channels
 *
 * RETURNS:
 *  void
 *
 */
void LVC_Core_MixInSoft_Mc_D16C31_SAT(LVMixer3_FLOAT_st *ptrInstance,
                                      const LVM_FLOAT   *src,
                                            LVM_FLOAT   *dst,
                                            LVM_INT16   NrFrames,
                                            LVM_INT16   NrChannels)
{

    LVM_INT16   OutLoop;
    LVM_INT16   InLoop;
    LVM_INT32   ii, jj;
    Mix_Private_FLOAT_st  *pInstance = (Mix_Private_FLOAT_st *)(ptrInstance->PrivateParams);
    LVM_FLOAT   Delta = pInstance->Delta;
    LVM_FLOAT   Current = pInstance->Current;
    LVM_FLOAT   Target = pInstance->Target;
    LVM_FLOAT   Temp;

    /*
     * Same operation is performed on consecutive frames.
     * So two frames are processed in one iteration and
     * the loop will run only for half the NrFrames value times.
     */
    InLoop = (LVM_INT16)(NrFrames >> 1);
    /* OutLoop is calculated to handle cases where NrFrames value can be odd.*/
    OutLoop = (LVM_INT16)(NrFrames - (InLoop << 1));

    if (Current < Target) {
        if (OutLoop) {
            Temp = Current + Delta;
            Current = Temp;
            if (Current > Target)
                Current = Target;

           for (ii = OutLoop*NrChannels; ii != 0; ii--) {
                Temp = (*dst) + (*(src++) * Current);
                if (Temp > 1.0f)
                    *dst++ = 1.0f;
                else if (Temp < -1.0f)
                    *dst++ = -1.0f;
                else
                    *dst++ = Temp;
            }
        }

        for (ii = InLoop; ii != 0; ii--) {
            Temp = Current + Delta;
            Current = Temp;
            if (Current > Target)
                Current = Target;

            for (jj = NrChannels; jj != 0 ; jj--) {
                Temp = (*dst) + (*(src++) * Current);
                if (Temp > 1.0f)
                    *dst++ = 1.0f;
                else if (Temp < -1.0f)
                    *dst++ = -1.0f;
                else
                    *dst++ = Temp;

                Temp = (*dst) + (*(src++) * Current);
                if (Temp > 1.0f)
                    *dst++ = 1.0f;
                else if (Temp < -1.0f)
                    *dst++ = -1.0f;
                else
                    *dst++ = Temp;

            }
        }
    }
    else{
        if (OutLoop) {
            Current -= Delta;
            if (Current < Target)
                Current = Target;

            for (ii = OutLoop*NrChannels; ii != 0; ii--) {
                Temp = (*dst) + (*(src++) * Current);
                if (Temp > 1.0f)
                    *dst++ = 1.0f;
                else if (Temp < -1.0f)
                    *dst++ = -1.0f;
                else
                    *dst++ = Temp;
            }
        }

        for (ii = InLoop; ii != 0; ii--) {
            Current -= Delta;
            if (Current < Target)
                Current = Target;

            for (jj = NrChannels; jj != 0 ; jj--) {
                Temp = (*dst) + (*(src++) * Current);
                if (Temp > 1.0f)
                    *dst++ = 1.0f;
                else if (Temp < -1.0f)
                    *dst++ = -1.0f;
                else
                    *dst++ = Temp;

                Temp = (*dst) + (*(src++) * Current);
                if (Temp > 1.0f)
                    *dst++ = 1.0f;
                else if (Temp < -1.0f)
                    *dst++ = -1.0f;
                else
                    *dst++ = Temp;

            }
        }
    }
    pInstance->Current = Current;
}

#endif
/**********************************************************************************/
