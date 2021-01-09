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

#ifndef _VECTOR_ARITHMETIC_H_
#define _VECTOR_ARITHMETIC_H_

#include "LVM_Types.h"

/**********************************************************************************
    VARIOUS FUNCTIONS
***********************************************************************************/

void LoadConst_Float(const LVM_FLOAT val, LVM_FLOAT* dst, LVM_INT16 n);

void Copy_Float(const LVM_FLOAT* src, LVM_FLOAT* dst, LVM_INT16 n);
void Copy_Float_Mc_Stereo(const LVM_FLOAT* src, LVM_FLOAT* dst, LVM_INT16 NrFrames,
                          LVM_INT32 NrChannels);
void Copy_Float_Stereo_Mc(const LVM_FLOAT* src, LVM_FLOAT* StereoOut, LVM_FLOAT* dst,
                          LVM_INT16 NrFrames, LVM_INT32 NrChannels);

void Mult3s_Float(const LVM_FLOAT* src, const LVM_FLOAT val, LVM_FLOAT* dst, LVM_INT16 n);

void DelayMix_Float(const LVM_FLOAT* src, /* Source 1, to be delayed */
                    LVM_FLOAT* delay,     /* Delay buffer */
                    LVM_INT16 size,       /* Delay size */
                    LVM_FLOAT* dst,       /* Source/destination */
                    LVM_INT16* pOffset,   /* Delay offset */
                    LVM_INT16 n);         /* Number of stereo samples */
void Add2_Sat_Float(const LVM_FLOAT* src, LVM_FLOAT* dst, LVM_INT16 n);
void Mac3s_Sat_Float(const LVM_FLOAT* src, const LVM_FLOAT val, LVM_FLOAT* dst, LVM_INT16 n);

/**********************************************************************************
    SHIFT FUNCTIONS
***********************************************************************************/
void Shift_Sat_Float(const LVM_INT16 val, const LVM_FLOAT* src, LVM_FLOAT* dst, LVM_INT16 n);
/**********************************************************************************
    AUDIO FORMAT CONVERSION FUNCTIONS
***********************************************************************************/
void MonoTo2I_Float(const LVM_FLOAT* src, LVM_FLOAT* dst, LVM_INT16 n);
void From2iToMono_Float(const LVM_FLOAT* src, LVM_FLOAT* dst, LVM_INT16 n);
void FromMcToMono_Float(const LVM_FLOAT* src, LVM_FLOAT* dst, LVM_INT16 NrFrames,
                        LVM_INT16 NrChannels);
void MSTo2i_Sat_Float(const LVM_FLOAT* srcM, const LVM_FLOAT* srcS, LVM_FLOAT* dst, LVM_INT16 n);
void From2iToMS_Float(const LVM_FLOAT* src, LVM_FLOAT* dstM, LVM_FLOAT* dstS, LVM_INT16 n);
void JoinTo2i_Float(const LVM_FLOAT* srcL, const LVM_FLOAT* srcR, LVM_FLOAT* dst, LVM_INT16 n);

/**********************************************************************************/

#endif /* _VECTOR_ARITHMETIC_H_ */

/**********************************************************************************/
