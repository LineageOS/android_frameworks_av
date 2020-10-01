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

/****************************************************************************************/
/*                                                                                      */
/*  Header file for the application layer interface of Concert Sound and Concert        */
/*  Sound EX.                                                                           */
/*                                                                                      */
/*  This files includes all definitions, types, structures and function                 */
/*  prototypes required by the calling layer. All other types, structures and           */
/*  functions are private.                                                              */
/*                                                                                      */
/****************************************************************************************/
/*                                                                                      */
/*  Note: 1                                                                             */
/*  =======                                                                             */
/*  The algorithm can execute either with separate input and output buffers or with     */
/*  a common buffer, i.e. the data is processed in-place. If the buffers are the        */
/*  same then the MIPs will be slightly higher and an extra stereo scratch buffer is    */
/*  required.                                                                           */
/*                                                                                      */
/****************************************************************************************/
/*                                                                                      */
/*  Note: 2                                                                             */
/*  =======                                                                             */
/*  Two data formats are support Stereo and Mono-In-Stereo. The data is interleaved as  */
/*  follows:                                                                            */
/*              Byte Offset         Stereo Input         Mono-In-Stereo Input           */
/*              ===========         ============         ====================           */
/*                  0               Left Sample #1          Mono Sample #1              */
/*                  2               Right Sample #1         Mono Sample #1              */
/*                  4               Left Sample #2          Mono Sample #2              */
/*                  6               Right Sample #2         Mono Sample #2              */
/*                  .                      .                     .                      */
/*                  .                      .                     .                      */
/*                                                                                      */
/*  Mono format data is not supported, the calling routine must convert a Mono stream   */
/*  in to Mono-In-Stereo format.                                                        */
/*                                                                                      */
/****************************************************************************************/

#ifndef LVCS_H
#define LVCS_H

/****************************************************************************************/
/*                                                                                      */
/*  Includes                                                                            */
/*                                                                                      */
/****************************************************************************************/

#include "LVM_Types.h"
#include "LVM_Common.h"

/****************************************************************************************/
/*                                                                                      */
/*  Definitions                                                                         */
/*                                                                                      */
/****************************************************************************************/

/* Effect Level */
#define LVCS_EFFECT_LOW 16384    /* Effect scaling 50% */
#define LVCS_EFFECT_MEDIUM 24576 /* Effect scaling 75% */
#define LVCS_EFFECT_HIGH 32767   /* Effect Scaling 100% */

/* Callback events */
#define LVCS_EVENT_NONE 0x0000   /* Not a valid event */
#define LVCS_EVENT_ALGOFF 0x0001 /* CS has completed switch off */

/****************************************************************************************/
/*                                                                                      */
/*  Types                                                                               */
/*                                                                                      */
/****************************************************************************************/

/* Instance handle */
typedef void* LVCS_Handle_t;

/* Operating modes */
typedef enum { LVCS_OFF = 0, LVCS_ON = 15, LVCS_MAX = LVM_MAXENUM } LVCS_Modes_en;

/* Function return status */
typedef enum {
    LVCS_SUCCESS = 0,        /* Successful return from a routine */
    LVCS_NULLADDRESS = 1,    /* NULL allocation address */
    LVCS_TOOMANYSAMPLES = 2, /* Maximum block size exceeded */
    LVCS_STATUSMAX = LVM_MAXENUM
} LVCS_ReturnStatus_en;

/*
 * Source data formats
 */
typedef enum {
    LVCS_STEREO = 0,
    LVCS_MONOINSTEREO = 1,
    LVCS_SOURCEMAX = LVM_MAXENUM
} LVCS_SourceFormat_en;

/*
 * Supported output devices
 */
typedef enum {
    LVCS_HEADPHONES = 0,
    LVCS_EX_HEADPHONES = 1,
    LVCS_SPEAKERTYPE_MAX = LVM_MAXENUM
} LVCS_SpeakerType_en;

/*
 * Speaker Coefficients Table
 */
typedef struct {
    void* pTable1;
    void* pTable2;
    void* pTable3;
    void* pTable4;
    void* pTable5;
    void* pTable6;
    void* pTable7;
    void* pTable8;
} LVCS_CSMS_Coef_Tables_t;

/****************************************************************************************/
/*                                                                                      */
/*  Structures                                                                          */
/*                                                                                      */
/****************************************************************************************/

/* Concert Sound parameter structure */
typedef struct {
    LVCS_Modes_en OperatingMode;       /* Algorithm mode */
    LVCS_SpeakerType_en SpeakerType;   /* Output device type */
    LVCS_SourceFormat_en SourceFormat; /* Source data format */
    LVM_Mode_en CompressorMode;        /* Non-Linear Compressor Mode */
    LVM_Fs_en SampleRate;              /* Sampling rate */
    LVM_INT16 EffectLevel;             /* Effect level */
    LVM_UINT16 ReverbLevel;            /* Reverb level in % */
    LVM_INT32 NrChannels;
} LVCS_Params_t;

/* Concert Sound Capability structure */
typedef struct {
    /* General parameters */
    LVM_UINT16 MaxBlockSize; /* Maximum block size in sample pairs */

    /* Callback parameters */
    LVM_Callback CallBack; /* Bundle callback */
    void* pBundleInstance; /* Bundle instance handle */

} LVCS_Capabilities_t;

/****************************************************************************************/
/*                                                                                      */
/*  Function Prototypes                                                                 */
/*                                                                                      */
/****************************************************************************************/

/************************************************************************************/
/*                                                                                  */
/* FUNCTION:                LVCS_Init                                               */
/*                                                                                  */
/* DESCRIPTION:                                                                     */
/*  Create and initialisation function for the Concert Sound module                 */
/*                                                                                  */
/* PARAMETERS:                                                                      */
/*  phInstance              Pointer to instance handle                              */
/*  pCapabilities           Pointer to the capabilities structure                   */
/*  pScratch                Pointer to the scratch buffer                           */
/*                                                                                  */
/* RETURNS:                                                                         */
/*  LVCS_Success            Initialisation succeeded                                */
/*  LVDBE_NULLADDRESS       One or more memory has a NULL pointer                   */
/*                                                                                  */
/* NOTES:                                                                           */
/*  1.  This function must not be interrupted by the LVCS_Process function          */
/*                                                                                  */
/************************************************************************************/
LVCS_ReturnStatus_en LVCS_Init(LVCS_Handle_t* phInstance, LVCS_Capabilities_t* pCapabilities,
                               void* pScratch);

/************************************************************************************/
/*                                                                                  */
/* FUNCTION:                LVCS_DeInit                                             */
/*                                                                                  */
/* DESCRIPTION:                                                                     */
/*  Free memories created during the LVCS_Init call including instance handle       */
/*                                                                                  */
/* PARAMETERS:                                                                      */
/*  phInstance              Pointer to instance handle                              */
/*                                                                                  */
/* NOTES:                                                                           */
/*  1.  This function must not be interrupted by the LVCS_Process function          */
/*                                                                                  */
/************************************************************************************/
void LVCS_DeInit(LVCS_Handle_t* phInstance);

/****************************************************************************************/
/*                                                                                      */
/* FUNCTION:                 LVCS_GetParameters                                         */
/*                                                                                      */
/* DESCRIPTION:                                                                         */
/*  Request the Concert Sound parameters. The current parameter set is returned         */
/*  via the parameter pointer.                                                          */
/*                                                                                      */
/* PARAMETERS:                                                                          */
/*  hInstance                Instance handle                                            */
/*  pParams                  Pointer to an empty parameter structure                    */
/*                                                                                      */
/* RETURNS:                                                                             */
/*  LVCS_Success             Always succeeds                                            */
/*                                                                                      */
/* NOTES:                                                                               */
/*  1.  This function may be interrupted by the LVCS_Process function                   */
/*                                                                                      */
/****************************************************************************************/

LVCS_ReturnStatus_en LVCS_GetParameters(LVCS_Handle_t hInstance, LVCS_Params_t* pParams);

/****************************************************************************************/
/*                                                                                      */
/* FUNCTION:                LVCS_Control                                                */
/*                                                                                      */
/* DESCRIPTION:                                                                         */
/*  Sets or changes the Concert Sound parameters.                                       */
/*                                                                                      */
/* PARAMETERS:                                                                          */
/*  hInstance               Instance handle                                             */
/*  pParams                 Pointer to a parameter structure                            */
/*                                                                                      */
/* RETURNS:                                                                             */
/*  LVCS_Success            Succeeded                                                   */
/*                                                                                      */
/* NOTES:                                                                               */
/*  1.  This function must not be interrupted by the LVCS_Process function              */
/*                                                                                      */
/****************************************************************************************/

LVCS_ReturnStatus_en LVCS_Control(LVCS_Handle_t hInstance, LVCS_Params_t* pParams);

/****************************************************************************************/
/*                                                                                      */
/* FUNCTION:                LVCS_Process                                                */
/*                                                                                      */
/* DESCRIPTION:                                                                         */
/*  Process function for the Concert Sound module. The implementation supports two      */
/*  variants of the algorithm, one for headphones and one for mobile speakers.          */
/*                                                                                      */
/* PARAMETERS:                                                                          */
/*  hInstance               Instance handle                                             */
/*  pInData                 Pointer to the input data                                   */
/*  pOutData                Pointer to the output data                                  */
/*  NumSamples              Number of samples in the input buffer                       */
/*                                                                                      */
/* RETURNS:                                                                             */
/*  LVCS_Success            Succeeded                                                   */
/*  LVCS_TooManySamples     NumSamples was larger than the maximum block size           */
/*                                                                                      */
/* NOTES:                                                                               */
/*                                                                                      */
/****************************************************************************************/
LVCS_ReturnStatus_en LVCS_Process(LVCS_Handle_t hInstance, const LVM_FLOAT* pInData,
                                  LVM_FLOAT* pOutData, LVM_UINT16 NumSamples);

#endif /* LVCS_H */
