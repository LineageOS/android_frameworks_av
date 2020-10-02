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

#ifndef _LVPSA_H_
#define _LVPSA_H_

#include "LVM_Types.h"

/****************************************************************************************/
/*                                                                                      */
/*  TYPES DEFINITIONS                                                                   */
/*                                                                                      */
/****************************************************************************************/
/* Level detection speed control parameters */
typedef enum {
    LVPSA_SPEED_LOW,    /* Low speed level   detection                                       */
    LVPSA_SPEED_MEDIUM, /* Medium speed level   detection                                    */
    LVPSA_SPEED_HIGH,   /* High speed level   detection                                      */
    LVPSA_SPEED_DUMMY = LVM_MAXINT_32 /* Force 32 bits enum, don't use it! */
} LVPSA_LevelDetectSpeed_en;

/* Filter control parameters */
typedef struct {
    LVM_UINT16 CenterFrequency; /* Center frequency of the band-pass filter (in Hz) */
    LVM_UINT16 QFactor; /* Quality factor of the filter             (in 1/100)               */
    LVM_INT16 PostGain; /* Postgain to apply after the filtering    (in dB Q16.0)            */

} LVPSA_FilterParam_t;

/* LVPSA initialization parameters */
typedef struct {
    LVM_UINT16
            SpectralDataBufferDuration; /* Spectral data buffer duration in time (ms in Q16.0) */
    LVM_UINT16 MaxInputBlockSize;       /* Maximum expected input block size (in samples)       */
    LVM_UINT16 nBands; /* Number of bands of the SA                                         */
    LVPSA_FilterParam_t*
            pFiltersParams; /* Points to nBands filter param structures for filters settings     */

} LVPSA_InitParams_t, *pLVPSA_InitParams_t;

/* LVPSA control parameters */
typedef struct {
    LVM_Fs_en Fs; /* Input sampling rate                                               */
    LVPSA_LevelDetectSpeed_en LevelDetectionSpeed; /* Level detection speed */

} LVPSA_ControlParams_t, *pLVPSA_ControlParams_t;

/* Audio time type */
typedef LVM_INT32 LVPSA_Time;

/* Module instance Handle */
typedef void* pLVPSA_Handle_t;

/* LVPSA return codes */
typedef enum {
    LVPSA_OK, /* The function ran without any problem                              */
    LVPSA_ERROR_INVALIDPARAM, /* A parameter is incorrect */
    LVPSA_ERROR_WRONGTIME,   /* An incorrect AudioTime is used                                    */
    LVPSA_ERROR_NULLADDRESS, /* A pointer has a NULL value                                        */
    LVPSA_RETURN_DUMMY = LVM_MAXINT_32 /* Force 32 bits enum, don't use it! */
} LVPSA_RETURN;

/*********************************************************************************************************************************
   FUNCTIONS PROTOTYPE
**********************************************************************************************************************************/
/************************************************************************************/
/*                                                                                  */
/* FUNCTION:            LVPSA_Init                                                  */
/*                                                                                  */
/* DESCRIPTION:                                                                     */
/*  Create and Initialize the LVPSA module including instance handle                */
/*                                                                                  */
/*                                                                                  */
/* PARAMETERS:                                                                      */
/*  phInstance          Pointer to the instance handle                              */
/*  InitParams          Init parameters structure                                   */
/*  ControlParams       Control parameters structure                                */
/*  pScratch            Pointer to bundle scratch memory area                       */
/*                                                                                  */
/*                                                                                  */
/* RETURNS:                                                                         */
/*  LVPSA_OK            Succeeds                                                    */
/*  otherwise           Error due to bad parameters                                 */
/*                                                                                  */
/************************************************************************************/
LVPSA_RETURN LVPSA_Init(pLVPSA_Handle_t* phInstance, LVPSA_InitParams_t* pInitParams,
                        LVPSA_ControlParams_t* pControlParams, void* pScratch);

/************************************************************************************/
/*                                                                                  */
/* FUNCTION:            LVPSA_DeInit                                                */
/*                                                                                  */
/* DESCRIPTION:                                                                     */
/*    Free the memories created in LVPSA_Init call including instance handle        */
/*                                                                                  */
/* PARAMETERS:                                                                      */
/*  phInstance          Pointer to the instance handle                              */
/*                                                                                  */
/************************************************************************************/
void LVPSA_DeInit(pLVPSA_Handle_t* phInstance);

/*********************************************************************************************************************************/
/*                                                                                                                               */
/* FUNCTION:            LVPSA_Control */
/*                                                                                                                               */
/* DESCRIPTION: */
/*  Controls the LVPSA module. */
/*                                                                                                                               */
/* PARAMETERS: */
/*  hInstance           Instance Handle */
/*  pNewParams          Pointer to the instance new control parameters */
/*                                                                                                                               */
/* RETURNS: */
/*  LVPSA_OK            Succeeds */
/*  otherwise           Error due to bad parameters */
/*                                                                                                                               */
/*********************************************************************************************************************************/
LVPSA_RETURN LVPSA_Control(pLVPSA_Handle_t hInstance, LVPSA_ControlParams_t* pNewParams);

/*********************************************************************************************************************************/
/*                                                                                                                               */
/* FUNCTION:            LVPSA_Process */
/*                                                                                                                               */
/* DESCRIPTION: */
/*  The process calculates the levels of the frequency bands. */
/*                                                                                                                               */
/* PARAMETERS: */
/*  hInstance           Instance Handle */
/*  pLVPSA_InputSamples Pointer to the input samples buffer */
/*  InputBlockSize      Number of mono samples to process */
/*  AudioTime           Playback time of the first input sample */
/*                                                                                                                               */
/*                                                                                                                               */
/* RETURNS: */
/*  LVPSA_OK            Succeeds */
/*  otherwise           Error due to bad parameters */
/*                                                                                                                               */
/*********************************************************************************************************************************/
LVPSA_RETURN LVPSA_Process(pLVPSA_Handle_t hInstance, LVM_FLOAT* pLVPSA_InputSamples,
                           LVM_UINT16 InputBlockSize, LVPSA_Time AudioTime);
/*********************************************************************************************************************************/
/*                                                                                                                               */
/* FUNCTION:            LVPSA_GetSpectrum */
/*                                                                                                                               */
/* DESCRIPTION: */
/*  This function is used for memory allocation and free. */
/*                                                                                                                               */
/*                                                                                                                               */
/* PARAMETERS: */
/*  hInstance            Instance Handle */
/*  GetSpectrumAudioTime Time to retrieve the values at */
/*  pCurrentValues       Pointer to an empty buffer : Current level values output */
/*  pPeakValues          Pointer to an empty buffer : Peak level values output */
/*                                                                                                                               */
/*                                                                                                                               */
/* RETURNS: */
/*  LVPSA_OK            Succeeds */
/*  otherwise           Error due to bad parameters */
/*                                                                                                                               */
/*********************************************************************************************************************************/
LVPSA_RETURN LVPSA_GetSpectrum(pLVPSA_Handle_t hInstance, LVPSA_Time GetSpectrumAudioTime,
                               LVM_UINT8* pCurrentValues, LVM_UINT8* pPeakValues);

/*********************************************************************************************************************************/
/*                                                                                                                               */
/* FUNCTION:            LVPSA_GetControlParams */
/*                                                                                                                               */
/* DESCRIPTION: */
/*  Get the current control parameters of the LVPSA module. */
/*                                                                                                                               */
/* PARAMETERS: */
/*  hInstance           Instance Handle */
/*  pParams             Pointer to an empty control parameters structure */
/* RETURNS: */
/*  LVPSA_OK            Succeeds */
/*  otherwise           Error due to bad parameters */
/*                                                                                                                               */
/*********************************************************************************************************************************/
LVPSA_RETURN LVPSA_GetControlParams(pLVPSA_Handle_t hInstance, LVPSA_ControlParams_t* pParams);

/*********************************************************************************************************************************/
/*                                                                                                                               */
/* FUNCTION:            LVPSA_GetInitParams */
/*                                                                                                                               */
/* DESCRIPTION: */
/*  Get the initialization parameters of the LVPSA module. */
/*                                                                                                                               */
/* PARAMETERS: */
/*  hInstance           Instance Handle */
/*  pParams             Pointer to an empty init parameters structure */
/* RETURNS: */
/*  LVPSA_OK            Succeeds */
/*  otherwise           Error due to bad parameters */
/*                                                                                                                               */
/*********************************************************************************************************************************/
LVPSA_RETURN LVPSA_GetInitParams(pLVPSA_Handle_t hInstance, LVPSA_InitParams_t* pParams);

#endif /* _LVPSA_H */
