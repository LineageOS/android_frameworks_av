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

#include "LVM_Types.h"
#include "LVM_Macros.h"
#include "LVC_Mixer_Private.h"

/************************************************************************/
/* FUNCTION:                                                            */
/*   LVMixer3_SetTarget                                                 */
/*                                                                      */
/* DESCRIPTION:                                                         */
/*  This function updates the private instance parameters: Shift,Target,*/
/*  Current for a given Audio Stream based on new value of TargetGain   */
/*                                                                      */
/*  This function caclulates the "Shift" required to provide the        */
/*  integer part of TargetGain and fractional gain values "Target" and  */
/*  "Current" based on maximum(TargetGain,CurrentGain)                  */
/*  E.g. CurrentGain=1.9 and TargetGain=2.5 then based on               */
/*  MaxGain of 2.5, Shift = 2, Current=1.9/4=0.475, Target=2.5/4=0.625  */
/*  Therefore integer gain of 4 is provided by Left Shift of 2 and      */
/*  fraction gain is provided through Current=0.475 and Target=0.625    */
/* PARAMETERS:                                                          */
/*  pStream         - ptr to Instance Parameter Structure LVMixer3_st   */
/*                    for an Audio Stream                               */
/*  TargetGain      - TargetGain value in Q 16.15 format                */
/*                                                                      */
/* RETURNS:                                                             */
/*  void                                                                */
/*                                                                      */
/************************************************************************/
void LVC_Mixer_SetTarget(LVMixer3_FLOAT_st *pStream,
                         LVM_FLOAT         TargetGain)
{
    Mix_Private_FLOAT_st *pInstance = (Mix_Private_FLOAT_st *)pStream->PrivateParams;
    pInstance->Target = TargetGain;               // Update gain Target
}
