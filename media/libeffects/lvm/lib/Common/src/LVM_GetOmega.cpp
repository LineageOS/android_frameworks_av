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
#include "Filter.h"
#include "LVM_Macros.h"

/************************************************************************************/
/*                                                                                  */
/* Defines and Tables for 2*Pi/Fs                                                   */
/*                                                                                  */
/************************************************************************************/

#define LVVDL_2PiBy_8000        1727108826  /* In Q41 format */
#define LVVDL_2PiBy_11025       1253230894  /* In Q41 format */
#define LVVDL_2PiBy_12000       1151405884  /* In Q41 format */

#define LVVDL_2PiByFs_SHIFT1    12          /* Qformat shift for 8kHz, 11.025kHz and 12kHz i.e. 12=41-29 */
#define LVVDL_2PiByFs_SHIFT2    13          /* Qformat shift for 16kHz, 22.050kHz and 24kHz i.e. 13=42-29 */
#define LVVDL_2PiByFs_SHIFT3    14          /* Qformat shift for 32kHz, 44.1kHz and 48kHz i.e. 14=43-29 */
#define LVVDL_2PiBy_8000_f        0.000785398f
#define LVVDL_2PiBy_11025_f       0.000569903f
#define LVVDL_2PiBy_12000_f       0.000523599f
#define LVVDL_2PiBy_16000_f       0.000392700f
#define LVVDL_2PiBy_22050_f       0.000284952f
#define LVVDL_2PiBy_24000_f       0.000261800f
#define LVVDL_2PiBy_32000_f       0.000196350f
#define LVVDL_2PiBy_44100_f       0.000142476f
#define LVVDL_2PiBy_48000_f       0.000130900f

#define LVVDL_2PiBy_88200_f       0.000071238f
#define LVVDL_2PiBy_96000_f       0.000065450f
#define LVVDL_2PiBy_176400_f      0.000035619f
#define LVVDL_2PiBy_192000_f      0.000032725f
const LVM_FLOAT     LVVDL_2PiOnFsTable[] =  {LVVDL_2PiBy_8000_f,
                                             LVVDL_2PiBy_11025_f,
                                             LVVDL_2PiBy_12000_f,
                                             LVVDL_2PiBy_16000_f,
                                             LVVDL_2PiBy_22050_f,
                                             LVVDL_2PiBy_24000_f,
                                             LVVDL_2PiBy_32000_f,
                                             LVVDL_2PiBy_44100_f,
                                             LVVDL_2PiBy_48000_f
                                            ,LVVDL_2PiBy_88200_f
                                            ,LVVDL_2PiBy_96000_f
                                            ,LVVDL_2PiBy_176400_f
                                            ,LVVDL_2PiBy_192000_f
                                           };
/*-------------------------------------------------------------------------*/
/* FUNCTION:                                                               */
/*   LVM_GetOmega                                                          */
/*                                                                         */
/* LVM_INT32 LVM_GetOmega(LVM_UINT16                  Fc,                  */
/*                        LVM_Fs_en                   Fs)                  */
/*                                                                         */
/* DESCRIPTION:                                                            */
/*   This function calculates the value of w using Fc and Fs               */
/*                                                                         */
/* PARAMETERS:                                                             */
/*                                                                         */
/*  LVM_UINT16          Fc     The corner frequency in Hz Q16.0 format     */
/*  LVM_Fs_en           Fs     The SampleRate                              */
/* RETURNS:                                                                */
/*   w=2*pi*Fc/Fs in Q2.29 format                                          */
/*-------------------------------------------------------------------------*/
LVM_FLOAT LVM_GetOmega(LVM_UINT32                  Fc,
                       LVM_Fs_en                   Fs)
{
    LVM_FLOAT   w;
    w = (LVM_FLOAT)Fc * LVVDL_2PiOnFsTable[Fs];
    return w;
}
