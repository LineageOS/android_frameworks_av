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
#include "ScalarArithmetic.h"
#include "LVM_Macros.h"

/**********************************************************************************
   FUNCTION LVC_Core_MixSoft_1St_2i_D16C31_WRA
***********************************************************************************/
static LVM_FLOAT ADD2_SAT_FLOAT(LVM_FLOAT a,
                                LVM_FLOAT b,
                                LVM_FLOAT c)
{
    LVM_FLOAT temp;
    temp = a + b ;
    if (temp < -1.0f)
        c = -1.0f;
    else if (temp > 1.0f)
        c = 1.0f;
    else
        c = temp;
    return c;
}
void LVC_Core_MixSoft_1St_2i_D16C31_WRA( LVMixer3_FLOAT_st        *ptrInstance1,
                                         LVMixer3_FLOAT_st        *ptrInstance2,
                                         const LVM_FLOAT    *src,
                                         LVM_FLOAT          *dst,
                                         LVM_INT16          n)
{
    LVM_INT16   OutLoop;
    LVM_INT16   InLoop;
    LVM_INT32   ii;
    Mix_Private_FLOAT_st  *pInstanceL = (Mix_Private_FLOAT_st *)(ptrInstance1->PrivateParams);
    Mix_Private_FLOAT_st  *pInstanceR = (Mix_Private_FLOAT_st *)(ptrInstance2->PrivateParams);

    LVM_FLOAT   DeltaL = pInstanceL->Delta;
    LVM_FLOAT   CurrentL = pInstanceL->Current;
    LVM_FLOAT   TargetL = pInstanceL->Target;

    LVM_FLOAT   DeltaR = pInstanceR->Delta;
    LVM_FLOAT   CurrentR = pInstanceR->Current;
    LVM_FLOAT   TargetR = pInstanceR->Target;

    LVM_FLOAT   Temp = 0;

    InLoop = (LVM_INT16)(n >> 2); /* Process per 4 samples */
    OutLoop = (LVM_INT16)(n - (InLoop << 2));

    if (OutLoop)
    {
        if(CurrentL < TargetL)
        {
            ADD2_SAT_FLOAT(CurrentL, DeltaL, Temp);
            CurrentL = Temp;
            if (CurrentL > TargetL)
                CurrentL = TargetL;
        }
        else
        {
            CurrentL -= DeltaL;
            if (CurrentL < TargetL)
                CurrentL = TargetL;
        }

        if(CurrentR < TargetR)
        {
            ADD2_SAT_FLOAT(CurrentR, DeltaR, Temp);
            CurrentR = Temp;
            if (CurrentR > TargetR)
                CurrentR = TargetR;
        }
        else
        {
            CurrentR -= DeltaR;
            if (CurrentR < TargetR)
                CurrentR = TargetR;
        }

        for (ii = OutLoop * 2; ii != 0; ii -= 2)
        {
            *(dst++) = (LVM_FLOAT)(((LVM_FLOAT)*(src++) * (LVM_FLOAT)CurrentL));
            *(dst++) = (LVM_FLOAT)(((LVM_FLOAT)*(src++) * (LVM_FLOAT)CurrentR));
        }
    }

    for (ii = InLoop * 2; ii != 0; ii-=2)
    {
        if(CurrentL < TargetL)
        {
            ADD2_SAT_FLOAT(CurrentL, DeltaL, Temp);
            CurrentL = Temp;
            if (CurrentL > TargetL)
                CurrentL = TargetL;
        }
        else
        {
            CurrentL -= DeltaL;
            if (CurrentL < TargetL)
                CurrentL = TargetL;
        }

        if(CurrentR < TargetR)
        {
            ADD2_SAT_FLOAT(CurrentR, DeltaR, Temp);
            CurrentR = Temp;
            if (CurrentR > TargetR)
                CurrentR = TargetR;
        }
        else
        {
            CurrentR -= DeltaR;
            if (CurrentR < TargetR)
                CurrentR = TargetR;
        }

        *(dst++) = (LVM_FLOAT)(((LVM_FLOAT)*(src++) * (LVM_FLOAT)CurrentL));
        *(dst++) = (LVM_FLOAT)(((LVM_FLOAT)*(src++) * (LVM_FLOAT)CurrentR));
        *(dst++) = (LVM_FLOAT)(((LVM_FLOAT)*(src++) * (LVM_FLOAT)CurrentL));
        *(dst++) = (LVM_FLOAT)(((LVM_FLOAT)*(src++) * (LVM_FLOAT)CurrentR));
        *(dst++) = (LVM_FLOAT)(((LVM_FLOAT)*(src++) * (LVM_FLOAT)CurrentL));
        *(dst++) = (LVM_FLOAT)(((LVM_FLOAT)*(src++) * (LVM_FLOAT)CurrentR));
        *(dst++) = (LVM_FLOAT)(((LVM_FLOAT)*(src++) * (LVM_FLOAT)CurrentL));
        *(dst++) = (LVM_FLOAT)(((LVM_FLOAT)*(src++) * (LVM_FLOAT)CurrentR));
    }
    pInstanceL->Current = CurrentL;
    pInstanceR->Current = CurrentR;

}
#ifdef SUPPORT_MC
void LVC_Core_MixSoft_1St_MC_float_WRA (Mix_Private_FLOAT_st **ptrInstance,
                                         const LVM_FLOAT      *src,
                                         LVM_FLOAT            *dst,
                                         LVM_INT16            NrFrames,
                                         LVM_INT16            NrChannels)
{
    LVM_INT32   ii, ch;
    LVM_FLOAT   Temp =0.0f;
    LVM_FLOAT   tempCurrent[NrChannels];
    for (ch = 0; ch < NrChannels; ch++)
    {
        tempCurrent[ch] = ptrInstance[ch]->Current;
    }
    for (ii = NrFrames; ii > 0; ii--)
    {
        for (ch = 0; ch < NrChannels; ch++)
        {
            Mix_Private_FLOAT_st *pInstance = ptrInstance[ch];
            const LVM_FLOAT   Delta = pInstance->Delta;
            LVM_FLOAT         Current = tempCurrent[ch];
            const LVM_FLOAT   Target = pInstance->Target;
            if (Current < Target)
            {
                ADD2_SAT_FLOAT(Current, Delta, Temp);
                Current = Temp;
                if (Current > Target)
                    Current = Target;
            }
            else
            {
                Current -= Delta;
                if (Current < Target)
                    Current = Target;
            }
            *dst++ = *src++ * Current;
            tempCurrent[ch] = Current;
        }
    }
    for (ch = 0; ch < NrChannels; ch++)
    {
        ptrInstance[ch]->Current = tempCurrent[ch];
    }
}
#endif
/**********************************************************************************/
