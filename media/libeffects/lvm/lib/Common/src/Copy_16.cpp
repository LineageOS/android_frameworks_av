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

/**********************************************************************************
   FUNCTION COPY_16
***********************************************************************************/

void Copy_16( const LVM_INT16 *src,
                    LVM_INT16 *dst,
                    LVM_INT16  n )
{
    LVM_INT16 ii;

    if (src > dst)
    {
        for (ii = n; ii != 0; ii--)
        {
            *dst = *src;
            dst++;
            src++;
        }
    }
    else
    {
        src += n - 1;
        dst += n - 1;
        for (ii = n; ii != 0; ii--)
        {
            *dst = *src;
            dst--;
            src--;
        }
    }

    return;
}
void Copy_Float( const LVM_FLOAT *src,
                 LVM_FLOAT *dst,
                 LVM_INT16  n )
{
    LVM_INT16 ii;

    if (src > dst)
    {
        for (ii = n; ii != 0; ii--)
        {
            *dst = *src;
            dst++;
            src++;
        }
    }
    else
    {
        src += n - 1;
        dst += n - 1;
        for (ii = n; ii != 0; ii--)
        {
            *dst = *src;
            dst--;
            src--;
        }
    }

    return;
}
#ifdef SUPPORT_MC
// Extract out the stereo channel pair from multichannel source.
void Copy_Float_Mc_Stereo(const LVM_FLOAT *src,
                 LVM_FLOAT *dst,
                 LVM_INT16 NrFrames, /* Number of frames */
                 LVM_INT32 NrChannels)
{
    LVM_INT16 ii;

    if (NrChannels >= 2)
    {
        for (ii = NrFrames; ii != 0; ii--)
        {
            dst[0] = src[0];
            dst[1] = src[1];
            dst += 2;
            src += NrChannels;
        }
    }
    else if (NrChannels == 1)
    {   // not expected to occur, provided for completeness.
        src += (NrFrames - 1);
        dst += 2 * (NrFrames - 1);
        for (ii = NrFrames; ii != 0; ii--)
        {
            dst[0] = src[0];
            dst[1] = src[0];
            dst -= 2;
            src --;
        }
    }
}

// Merge a multichannel source with stereo contained in StereoOut, to dst.
void Copy_Float_Stereo_Mc(const LVM_FLOAT *src,
                 LVM_FLOAT *StereoOut,
                 LVM_FLOAT *dst,
                 LVM_INT16 NrFrames, /* Number of frames*/
                 LVM_INT32 NrChannels)
{
    LVM_INT16 ii, jj;

    // pack dst with stereo information of StereoOut
    // together with the upper channels of src.
    StereoOut += 2 * (NrFrames - 1);
    dst += NrChannels * (NrFrames - 1);
    src += NrChannels * (NrFrames - 1);
    for (ii = NrFrames; ii != 0; ii--)
    {
        dst[1] = StereoOut[1];
        dst[0] = StereoOut[0]; // copy 1 before 0 is required for NrChannels == 3.
        for (jj = 2; jj < NrChannels; jj++)
        {
            dst[jj] = src[jj];
        }
        dst    -= NrChannels;
        src    -= NrChannels;
        StereoOut -= 2;
    }
}
#endif
/**********************************************************************************/
