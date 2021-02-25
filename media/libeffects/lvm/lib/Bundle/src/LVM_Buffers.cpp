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
/*                                                                                        */
/*    Includes                                                                              */
/*                                                                                        */
/****************************************************************************************/

#include "LVM_Private.h"
#include "VectorArithmetic.h"

#include <log/log.h>

/****************************************************************************************/
/*                                                                                      */
/* FUNCTION:                 LVM_BufferManagedIn                                        */
/*                                                                                      */
/* DESCRIPTION:                                                                         */
/*    Full buffer management allowing the user to provide input and output buffers on   */
/*  any alignment and with any number of samples. The alignment is corrected within     */
/*  the buffer management and the samples are grouped in to blocks of the correct size  */
/*  before processing.                                                                  */
/*                                                                                      */
/* PARAMETERS:                                                                          */
/*    hInstance        -    Instance handle                                             */
/*    pInData            -    Pointer to the input data stream                          */
/*  *pToProcess        -    Pointer to pointer to the start of data processing          */
/*  *pProcessed        -    Pointer to pointer to the destination of the processed data */
/*    pNumSamples        -    Pointer to the number of samples to process               */
/*                                                                                      */
/* RETURNS:                                                                             */
/*    None                                                                              */
/*                                                                                      */
/* NOTES:                                                                               */
/*                                                                                      */
/****************************************************************************************/
void LVM_BufferManagedIn(LVM_Handle_t hInstance, const LVM_FLOAT* pInData, LVM_FLOAT** pToProcess,
                         LVM_FLOAT** pProcessed, LVM_UINT16* pNumSamples) {
    LVM_INT16 SampleCount; /* Number of samples to be processed this call */
    LVM_INT16 NumSamples;  /* Number of samples in scratch buffer */
    LVM_FLOAT* pStart;
    LVM_Instance_t* pInstance = (LVM_Instance_t*)hInstance;
    LVM_Buffer_t* pBuffer;
    LVM_FLOAT* pDest;
    LVM_INT16 NumChannels = pInstance->NrChannels;

    /*
     * Set the processing address pointers
     */
    pBuffer = pInstance->pBufferManagement;
    pDest = pBuffer->pScratch;
    *pToProcess = pBuffer->pScratch;
    *pProcessed = pBuffer->pScratch;

    /*
     * Check if it is the first call of a block
     */
    if (pInstance->SamplesToProcess == 0) {
        /*
         * First call for a new block of samples
         */
        pInstance->SamplesToProcess = (LVM_INT16)(*pNumSamples + pBuffer->InDelaySamples);
        pInstance->pInputSamples = (LVM_FLOAT*)pInData;
        pBuffer->BufferState = LVM_FIRSTCALL;
    }
    pStart = pInstance->pInputSamples; /* Pointer to the input samples */
    pBuffer->SamplesToOutput = 0;      /* Samples to output is same as
                                          number read for inplace processing */

    /*
     * Calculate the number of samples to process this call and update the buffer state
     */
    if (pInstance->SamplesToProcess > pInstance->InternalBlockSize) {
        /*
         * Process the maximum bock size of samples.
         */
        SampleCount = pInstance->InternalBlockSize;
        NumSamples = pInstance->InternalBlockSize;
    } else {
        /*
         * Last call for the block, so calculate how many frames and samples to process
         */
        LVM_INT16 NumFrames;

        NumSamples = pInstance->SamplesToProcess;
        NumFrames = (LVM_INT16)(NumSamples >> MIN_INTERNAL_BLOCKSHIFT);
        SampleCount = (LVM_INT16)(NumFrames << MIN_INTERNAL_BLOCKSHIFT);

        /*
         * Update the buffer state
         */
        if (pBuffer->BufferState == LVM_FIRSTCALL) {
            pBuffer->BufferState = LVM_FIRSTLASTCALL;
        } else {
            pBuffer->BufferState = LVM_LASTCALL;
        }
    }
    *pNumSamples = (LVM_UINT16)SampleCount; /* Set the number of samples to process this call */

    /*
     * Copy samples from the delay buffer as required
     */
    if (((pBuffer->BufferState == LVM_FIRSTCALL) || (pBuffer->BufferState == LVM_FIRSTLASTCALL)) &&
        (pBuffer->InDelaySamples != 0)) {
        Copy_Float(&pBuffer->InDelayBuffer[0],                          /* Source */
                   pDest,                                               /* Destination */
                   (LVM_INT16)(NumChannels * pBuffer->InDelaySamples)); /* Number of delay \
                                                                    samples, left and right */
        NumSamples = (LVM_INT16)(NumSamples - pBuffer->InDelaySamples); /* Update sample count */
        pDest += NumChannels * pBuffer->InDelaySamples; /* Update the destination pointer */
    }

    /*
     * Copy the rest of the samples for this call from the input buffer
     */
    if (NumSamples > 0) {
        Copy_Float(pStart,                                 /* Source */
                   pDest,                                  /* Destination */
                   (LVM_INT16)(NumChannels * NumSamples)); /* Number of input samples */
        pStart += NumChannels * NumSamples;                /* Update the input pointer */

        /*
         * Update the input data pointer and samples to output
         */
        /* Update samples to output */
        pBuffer->SamplesToOutput = (LVM_INT16)(pBuffer->SamplesToOutput + NumSamples);
    }

    /*
     * Update the sample count and input pointer
     */
    /* Update the count of samples */
    pInstance->SamplesToProcess = (LVM_INT16)(pInstance->SamplesToProcess - SampleCount);
    pInstance->pInputSamples = pStart; /* Update input sample pointer */

    /*
     * Save samples to the delay buffer if any left unprocessed
     */
    if ((pBuffer->BufferState == LVM_FIRSTLASTCALL) || (pBuffer->BufferState == LVM_LASTCALL)) {
        NumSamples = pInstance->SamplesToProcess;
        pStart = pBuffer->pScratch;          /* Start of the buffer */
        pStart += NumChannels * SampleCount; /* Offset by the number of processed samples */
        if (NumSamples != 0) {
            Copy_Float(pStart,                                 /* Source */
                       &pBuffer->InDelayBuffer[0],             /* Destination */
                       (LVM_INT16)(NumChannels * NumSamples)); /* Number of input samples */
        }

        /*
         * Update the delay sample count
         */
        pBuffer->InDelaySamples = NumSamples; /* Number of delay sample pairs */
        pInstance->SamplesToProcess = 0;      /* All Samples used */
    }
}

/****************************************************************************************/
/*                                                                                      */
/* FUNCTION:                 LVM_BufferUnmanagedIn                                      */
/*                                                                                      */
/* DESCRIPTION:                                                                         */
/*    This mode is selected by the user code and disables the buffer management with the */
/*  exception of the maximum block size processing. The user must ensure that the       */
/*  input and output buffers are 32-bit aligned and also that the number of samples to  */
/*    process is a correct multiple of samples.                                         */
/*                                                                                      */
/* PARAMETERS:                                                                          */
/*    hInstance        -    Instance handle                                             */
/*  *pToProcess        -    Pointer to the start of data processing                     */
/*  *pProcessed        -    Pointer to the destination of the processed data            */
/*    pNumSamples        -    Pointer to the number of samples to process               */
/*                                                                                      */
/* RETURNS:                                                                             */
/*    None                                                                              */
/*                                                                                      */
/* NOTES:                                                                               */
/*                                                                                      */
/****************************************************************************************/
void LVM_BufferUnmanagedIn(LVM_Handle_t hInstance, LVM_FLOAT** pToProcess, LVM_FLOAT** pProcessed,
                           LVM_UINT16* pNumSamples) {
    LVM_Instance_t* pInstance = (LVM_Instance_t*)hInstance;

    /*
     * Check if this is the first call of a block
     */
    if (pInstance->SamplesToProcess == 0) {
        pInstance->SamplesToProcess = (LVM_INT16)*pNumSamples; /* Get the number of samples
                                                                            on first call */
        pInstance->pInputSamples = *pToProcess;                /* Get the I/O pointers */
        pInstance->pOutputSamples = *pProcessed;

        /*
         * Set te block size to process
         */
        if (pInstance->SamplesToProcess > pInstance->InternalBlockSize) {
            *pNumSamples = (LVM_UINT16)pInstance->InternalBlockSize;
        } else {
            *pNumSamples = (LVM_UINT16)pInstance->SamplesToProcess;
        }
    }

    /*
     * Set the process pointers
     */
    *pToProcess = pInstance->pInputSamples;
    *pProcessed = pInstance->pOutputSamples;
}

/****************************************************************************************/
/*                                                                                      */
/* FUNCTION:                 LVM_BufferOptimisedIn                                      */
/*                                                                                      */
/* DESCRIPTION:                                                                         */
/*    Optimised buffer management for the case where the data is outplace processing,   */
/*    the output data is 32-bit aligned and there are sufficient samples to allow some  */
/*    processing directly in the output buffer. This saves one data copy per sample     */
/*    compared with the unoptimsed version.                                             */
/*                                                                                      */
/* PARAMETERS:                                                                          */
/*    hInstance        -    Instance handle                                             */
/*    pInData            -    Pointer to the input data stream                          */
/*  *pToProcess        -    Pointer to the start of data processing                     */
/*  *pProcessed        -    Pointer to the destination of the processed data            */
/*    pNumSamples        -    Pointer to the number of samples to process               */
/*                                                                                      */
/* RETURNS:                                                                             */
/*    None                                                                              */
/*                                                                                      */
/* NOTES:                                                                               */
/*                                                                                      */
/****************************************************************************************/

/****************************************************************************************/
/*                                                                                      */
/* FUNCTION:                 LVM_BufferIn                                               */
/*                                                                                      */
/* DESCRIPTION:                                                                         */
/*    This function manages the data input, it has the following features:              */
/*        - Accepts data in 16-bit aligned memory                                       */
/*        - Copies the data to 32-bit aligned memory                                    */
/*        - Converts Mono inputs to Mono-in-Stereo                                      */
/*        - Accepts any number of samples as input, except 0                            */
/*        - Breaks the input sample stream in to blocks of the configured frame size or */
/*          multiples of the frame size                                                 */
/*        - Limits the processing block size to the maximum block size.                 */
/*        - Works with inplace or outplace processing automatically                     */
/*                                                                                      */
/*  To manage the data the function has a number of operating states:                   */
/*        LVM_FIRSTCALL        - The first call for this block of input samples         */
/*        LVM_MAXBLOCKCALL    - The current block is the maximum size. Only used for the */
/*                              second and subsequent blocks.                           */
/*        LVM_LASTCALL        - The last call for this block of input samples           */
/*        LVM_FIRSTLASTCALL    - This is the first and last call for this block of input*/
/*                              samples, this occurs when the number of samples to      */
/*                              process is less than the maximum block size.            */
/*                                                                                      */
/*    The function uses an internal delay buffer the size of the minimum frame, this is */
/*  used to temporarily hold samples when the number of samples to process is not a     */
/*  multiple of the frame size.                                                         */
/*                                                                                      */
/*    To ensure correct operation with inplace buffering the number of samples to output*/
/*  per call is calculated in this function and is set to the number of samples read    */
/*  from the input buffer.                                                              */
/*                                                                                      */
/*    The total number of samples to process is stored when the function is called for  */
/*  the first time. The value is overwritten by the size of the block to be processed   */
/*  in each call so the size of the processing blocks can be controlled. The number of  */
/*    samples actually processed for each block of input samples is always a multiple of*/
/*  the frame size so for any particular block of input samples the actual number of    */
/*  processed samples may not match the number of input samples, sometime it will be    */
/*  sometimes less. The average is the same and the difference is never more than the   */
/*  frame size.                                                                         */
/*                                                                                      */
/* PARAMETERS:                                                                          */
/*    hInstance        -    Instance handle                                             */
/*    pInData            -    Pointer to the input data stream                          */
/*  *pToProcess        -    Pointer to the start of data processing                     */
/*  *pProcessed        -    Pointer to the destination of the processed data            */
/*    pNumSamples        -    Pointer to the number of samples to process               */
/*                                                                                      */
/* RETURNS:                                                                             */
/*    None                                                                              */
/*                                                                                      */
/* NOTES:                                                                               */
/*                                                                                      */
/****************************************************************************************/
void LVM_BufferIn(LVM_Handle_t hInstance, const LVM_FLOAT* pInData, LVM_FLOAT** pToProcess,
                  LVM_FLOAT** pProcessed, LVM_UINT16* pNumSamples) {
    LVM_Instance_t* pInstance = (LVM_Instance_t*)hInstance;

    /*
     * Check which mode, managed or unmanaged
     */
    if (pInstance->InstParams.BufferMode == LVM_MANAGED_BUFFERS) {
        LVM_BufferManagedIn(hInstance, pInData, pToProcess, pProcessed, pNumSamples);
    } else {
        LVM_BufferUnmanagedIn(hInstance, pToProcess, pProcessed, pNumSamples);
    }
}
/****************************************************************************************/
/*                                                                                      */
/* FUNCTION:                 LVM_BufferManagedOut                                       */
/*                                                                                      */
/* DESCRIPTION:                                                                         */
/*  Full buffer management output. This works in conjunction with the managed input     */
/*  routine and ensures the correct number of samples are always output to the output   */
/*  buffer.                                                                             */
/*                                                                                      */
/* PARAMETERS:                                                                          */
/*    hInstance        - Instance handle                                                */
/*    pOutData        - Pointer to the output data stream                               */
/*    pNumSamples        - Pointer to the number of samples to process                  */
/*                                                                                      */
/* RETURNS:                                                                             */
/*    None                                                                              */
/*                                                                                      */
/* NOTES:                                                                               */
/*                                                                                      */
/****************************************************************************************/
void LVM_BufferManagedOut(LVM_Handle_t hInstance, LVM_FLOAT* pOutData, LVM_UINT16* pNumSamples) {
    LVM_Instance_t* pInstance = (LVM_Instance_t*)hInstance;
    LVM_Buffer_t* pBuffer = pInstance->pBufferManagement;
    LVM_INT16 SampleCount = (LVM_INT16)*pNumSamples;
    LVM_INT16 NumSamples;
    LVM_FLOAT* pStart;
    LVM_FLOAT* pDest;
    LVM_INT32 NrChannels = pInstance->NrChannels;
#define NrFrames NumSamples  // alias for clarity
#define FrameCount SampleCount

    /*
     * Set the pointers
     */
    NumSamples = pBuffer->SamplesToOutput;
    pStart = pBuffer->pScratch;

    /*
     * check if it is the first call of a block
     */
    if ((pBuffer->BufferState == LVM_FIRSTCALL) || (pBuffer->BufferState == LVM_FIRSTLASTCALL)) {
        /* First call for a new block */
        pInstance->pOutputSamples = pOutData; /* Initialise the destination */
    }
    pDest = pInstance->pOutputSamples; /* Set the output address */

    /*
     * If the number of samples is non-zero then there are still samples to send to
     * the output buffer
     */
    if ((NumSamples != 0) && (pBuffer->OutDelaySamples != 0)) {
        /*
         * Copy the delayed output buffer samples to the output
         */
        if (pBuffer->OutDelaySamples <= NumSamples) {
            /*
             * Copy all output delay samples to the output
             */
            Copy_Float(&pBuffer->OutDelayBuffer[0], /* Source */
                       pDest,                       /* Destination */
                       /* Number of delay samples */
                       (LVM_INT16)(NrChannels * pBuffer->OutDelaySamples));

            /*
             * Update the pointer and sample counts
             */
            pDest += NrChannels * pBuffer->OutDelaySamples; /* Output sample pointer */
            NumSamples = (LVM_INT16)(NumSamples - pBuffer->OutDelaySamples); /* Samples left \
                                                                                to send */
            pBuffer->OutDelaySamples = 0; /* No samples left in the buffer */
        } else {
            /*
             * Copy only some of the output delay samples to the output
             */
            Copy_Float(&pBuffer->OutDelayBuffer[0],         /* Source */
                       pDest,                               /* Destination */
                       (LVM_INT16)(NrChannels * NrFrames)); /* Number of delay samples */

            /*
             * Update the pointer and sample counts
             */
            pDest += NrChannels * NrFrames; /* Output sample pointer */
            /* No samples left in the buffer */
            pBuffer->OutDelaySamples = (LVM_INT16)(pBuffer->OutDelaySamples - NumSamples);

            /*
             * Realign the delay buffer data to avoid using circular buffer management
             */
            Copy_Float(&pBuffer->OutDelayBuffer[NrChannels * NrFrames], /* Source */
                       &pBuffer->OutDelayBuffer[0],                     /* Destination */
                       /* Number of samples to move */
                       (LVM_INT16)(NrChannels * pBuffer->OutDelaySamples));
            NumSamples = 0; /* Samples left to send */
        }
    }

    /*
     * Copy the processed results to the output
     */
    if ((NumSamples != 0) && (SampleCount != 0)) {
        if (SampleCount <= NumSamples) {
            /*
             * Copy all processed samples to the output
             */
            Copy_Float(pStart,                                /* Source */
                       pDest,                                 /* Destination */
                       (LVM_INT16)(NrChannels * FrameCount)); /* Number of processed samples */
            /*
             * Update the pointer and sample counts
             */
            pDest += NrChannels * FrameCount;                   /* Output sample pointer */
            NumSamples = (LVM_INT16)(NumSamples - SampleCount); /* Samples left to send */
            SampleCount = 0;                                    /* No samples left in the buffer */
        } else {
            /*
             * Copy only some processed samples to the output
             */
            Copy_Float(pStart,                              /* Source */
                       pDest,                               /* Destination */
                       (LVM_INT16)(NrChannels * NrFrames)); /* Number of processed samples */
            /*
             * Update the pointers and sample counts
             */
            pStart += NrChannels * NrFrames;                     /* Processed sample pointer */
            pDest += NrChannels * NrFrames;                      /* Output sample pointer */
            SampleCount = (LVM_INT16)(SampleCount - NumSamples); /* Processed samples left */
            NumSamples = 0;                                      /* Clear the sample count */
        }
    }

    /*
     * Copy the remaining processed data to the output delay buffer
     */
    if (SampleCount != 0) {
        Copy_Float(pStart, /* Source */
                   /* Destination */
                   &pBuffer->OutDelayBuffer[NrChannels * pBuffer->OutDelaySamples],
                   (LVM_INT16)(NrChannels * FrameCount)); /* Number of processed samples */
        /* Update the buffer count */
        pBuffer->OutDelaySamples = (LVM_INT16)(pBuffer->OutDelaySamples + SampleCount);
    }

    /*
     * pointers, counts and set default buffer processing
     */
    pBuffer->SamplesToOutput = NumSamples;   /* Samples left to send */
    pInstance->pOutputSamples = pDest;       /* Output sample pointer */
    pBuffer->BufferState = LVM_MAXBLOCKCALL; /* Set for the default call \
                                                     block size */
    /* This will terminate the loop when all samples processed */
    *pNumSamples = (LVM_UINT16)pInstance->SamplesToProcess;
}

/****************************************************************************************/
/*                                                                                      */
/* FUNCTION:                 LVM_BufferUnmanagedOut                                     */
/*                                                                                      */
/* DESCRIPTION:                                                                         */
/*  This works in conjunction with the unmanaged input routine and updates the number   */
/*    of samples left to be processed    and adjusts the buffer pointers.               */
/*                                                                                      */
/* PARAMETERS:                                                                          */
/*    hInstance        - Instance handle                                                */
/*    pNumSamples        - Pointer to the number of samples to process                  */
/*                                                                                      */
/* RETURNS:                                                                             */
/*    None                                                                              */
/*                                                                                      */
/* NOTES:                                                                               */
/*                                                                                      */
/****************************************************************************************/

void LVM_BufferUnmanagedOut(LVM_Handle_t hInstance, LVM_UINT16* pNumSamples) {
    LVM_Instance_t* pInstance = (LVM_Instance_t*)hInstance;
    LVM_INT16 NumChannels = pInstance->NrChannels;
#undef NrFrames
#define NrFrames (*pNumSamples)  // alias for clarity

    /*
     * Update sample counts
     */
    pInstance->pInputSamples +=
            (LVM_INT16)(*pNumSamples * NumChannels); /* Update the I/O pointers */
    pInstance->pOutputSamples += (LVM_INT16)(NrFrames * NumChannels);
    pInstance->SamplesToProcess =
            (LVM_INT16)(pInstance->SamplesToProcess - *pNumSamples); /* Update the sample count */

    /*
     * Set te block size to process
     */
    if (pInstance->SamplesToProcess > pInstance->InternalBlockSize) {
        *pNumSamples = (LVM_UINT16)pInstance->InternalBlockSize;
    } else {
        *pNumSamples = (LVM_UINT16)pInstance->SamplesToProcess;
    }
}

/****************************************************************************************/
/*                                                                                      */
/* FUNCTION:                 LVM_BufferOptimisedOut                                     */
/*                                                                                      */
/* DESCRIPTION:                                                                         */
/*  This works in conjunction with the optimised input routine and copies the last few  */
/*  processed and unprocessed samples to their respective buffers.                      */
/*                                                                                      */
/* PARAMETERS:                                                                          */
/*    hInstance        - Instance handle                                                */
/*    pNumSamples        - Pointer to the number of samples to process                  */
/*                                                                                      */
/* RETURNS:                                                                             */
/*    None                                                                              */
/*                                                                                      */
/* NOTES:                                                                               */
/*                                                                                      */
/****************************************************************************************/

/****************************************************************************************/
/*                                                                                      */
/* FUNCTION:                 LVM_BufferOut                                              */
/*                                                                                      */
/* DESCRIPTION:                                                                         */
/*  This function manages the data output, it has the following features:               */
/*        - Output data to 16-bit aligned memory                                        */
/*        - Reads data from 32-bit aligned memory                                       */
/*        - Reads data only in blocks of frame size or multiples of frame size          */
/*        - Writes the same number of samples as the LVM_BufferIn function reads        */
/*        - Works with inplace or outplace processing automatically                     */
/*                                                                                      */
/*  To manage the data the function has a number of operating states:                   */
/*        LVM_FIRSTCALL        - The first call for this block of input samples         */
/*        LVM_FIRSTLASTCALL    - This is the first and last call for this block of input*/
/*                              samples, this occurs when the number of samples to      */
/*                              process is less than the maximum block size.            */
/*                                                                                      */
/*    The function uses an internal delay buffer the size of the minimum frame, this is */
/*  used to temporarily hold samples when the number of samples to write is not a       */
/*  multiple of the frame size.                                                         */
/*                                                                                      */
/*    To ensure correct operation with inplace buffering the number of samples to output*/
/*  per call is always the same as the number of samples read from the input buffer.    */
/*                                                                                      */
/* PARAMETERS:                                                                          */
/*    hInstance        - Instance handle                                                */
/*    pOutData        - Pointer to the output data stream                               */
/*    pNumSamples        - Pointer to the number of samples to process                  */
/*                                                                                      */
/* RETURNS:                                                                             */
/*    None                                                                              */
/*                                                                                      */
/* NOTES:                                                                               */
/*                                                                                      */
/****************************************************************************************/
void LVM_BufferOut(LVM_Handle_t hInstance, LVM_FLOAT* pOutData, LVM_UINT16* pNumSamples) {
    LVM_Instance_t* pInstance = (LVM_Instance_t*)hInstance;

    /*
     * Check which mode, managed or unmanaged
     */
    if (pInstance->InstParams.BufferMode == LVM_MANAGED_BUFFERS) {
        LVM_BufferManagedOut(hInstance, pOutData, pNumSamples);
    } else {
        LVM_BufferUnmanagedOut(hInstance, pNumSamples);
    }
}
