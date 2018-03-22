/*
 * Copyright (C) 2018 The Android Open Source Project
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

#define LOG_TAG "DPFrequency"
//#define LOG_NDEBUG 0

#include <log/log.h>
#include "DPFrequency.h"
#include <algorithm>

namespace dp_fx {

using Eigen::MatrixXd;
#define MAX_BLOCKSIZE 16384 //For this implementation
#define MIN_BLOCKSIZE 8

#define CIRCULAR_BUFFER_UPSAMPLE 4  //4 times buffer size

static constexpr float MIN_ENVELOPE = 0.000001f;
//helper functionS
static inline bool isPowerOf2(unsigned long n) {
    return (n & (n - 1)) == 0;
}
static constexpr float EPSILON = 0.0000001f;

static inline bool isZero(float f) {
    return fabs(f) <= EPSILON;
}

template <class T>
bool compareEquality(T a, T b) {
    return (a == b);
}

template <> bool compareEquality<float>(float a, float b) {
    return isZero(a - b);
}

//TODO: avoid using macro for estimating change and assignment.
#define IS_CHANGED(c, a, b) { c |= !compareEquality(a,b); \
    (a) = (b); }

float dBtoLinear(float valueDb) {
    return  pow (10, valueDb / 20.0);
}

float linearToDb(float value) {
    return 20 * log10(value);
}

//ChannelBuffers helper
void ChannelBuffer::initBuffers(unsigned int blockSize, unsigned int overlapSize,
        unsigned int halfFftSize, unsigned int samplingRate, DPBase &dpBase) {
    ALOGV("ChannelBuffer::initBuffers blockSize %d, overlap %d, halfFft %d",
            blockSize, overlapSize, halfFftSize);

    mSamplingRate = samplingRate;
    mBlockSize = blockSize;

    cBInput.resize(mBlockSize * CIRCULAR_BUFFER_UPSAMPLE);
    cBOutput.resize(mBlockSize * CIRCULAR_BUFFER_UPSAMPLE);

    //fill input with half block size...
    for (unsigned int k = 0;  k < mBlockSize/2; k++) {
        cBInput.write(0);
    }

    //temp vectors
    input.resize(mBlockSize);
    output.resize(mBlockSize);
    outTail.resize(overlapSize);

    //module vectors
    mPreEqFactorVector.resize(halfFftSize, 1.0);
    mPostEqFactorVector.resize(halfFftSize, 1.0);

    mPreEqBands.resize(dpBase.getPreEqBandCount());
    mMbcBands.resize(dpBase.getMbcBandCount());
    mPostEqBands.resize(dpBase.getPostEqBandCount());
    ALOGV("mPreEqBands %zu, mMbcBands %zu, mPostEqBands %zu",mPreEqBands.size(),
            mMbcBands.size(), mPostEqBands.size());

    DPChannel *pChannel = dpBase.getChannel(0);
    if (pChannel != NULL) {
        mPreEqInUse = pChannel->getPreEq()->isInUse();
        mMbcInUse = pChannel->getMbc()->isInUse();
        mPostEqInUse = pChannel->getPostEq()->isInUse();
        mLimiterInUse = pChannel->getLimiter()->isInUse();
    }
}

void ChannelBuffer::computeBinStartStop(BandParams &bp, size_t binStart) {

    bp.binStart = binStart;
    bp.binStop = (int)(0.5 + bp.freqCutoffHz * mBlockSize / mSamplingRate);
}

//== DPFrequency

void DPFrequency::reset() {
}

size_t DPFrequency::getMinBockSize() {
    return MIN_BLOCKSIZE;
}

size_t DPFrequency::getMaxBockSize() {
    return MAX_BLOCKSIZE;
}

void DPFrequency::configure(size_t blockSize, size_t overlapSize,
        size_t samplingRate) {
    ALOGV("configure");
    mBlockSize = blockSize;
    if (mBlockSize > MAX_BLOCKSIZE) {
        mBlockSize = MAX_BLOCKSIZE;
    } else if (mBlockSize < MIN_BLOCKSIZE) {
        mBlockSize = MIN_BLOCKSIZE;
    } else {
        if (!isPowerOf2(blockSize)) {
            //find next highest power of 2.
            mBlockSize = 1 << (32 - __builtin_clz(blockSize));
        }
    }

    mHalfFFTSize = 1 + mBlockSize / 2; //including Nyquist bin
    mOverlapSize = std::min(overlapSize, mBlockSize/2);

    int channelcount = getChannelCount();
    mSamplingRate = samplingRate;
    mChannelBuffers.resize(channelcount);
    for (int ch = 0; ch < channelcount; ch++) {
        mChannelBuffers[ch].initBuffers(mBlockSize, mOverlapSize, mHalfFFTSize,
                mSamplingRate, *this);
    }

    //dsp
    fill_window(mVWindow, RDSP_WINDOW_HANNING_FLAT_TOP, mBlockSize, mOverlapSize);
}

void DPFrequency::updateParameters(ChannelBuffer &cb, int channelIndex) {
    DPChannel *pChannel = getChannel(channelIndex);

    if (pChannel == NULL) {
        ALOGE("Error: updateParameters null DPChannel %d", channelIndex);
        return;
    }

    //===Input Gain and preEq
    {
        bool changed = false;
        IS_CHANGED(changed, cb.inputGainDb, pChannel->getInputGain());
        //===EqPre
        if (cb.mPreEqInUse) {
            DPEq *pPreEq = pChannel->getPreEq();
            if (pPreEq == NULL) {
                ALOGE("Error: updateParameters null PreEq for channel: %d", channelIndex);
                return;
            }
            IS_CHANGED(changed, cb.mPreEqEnabled, pPreEq->isEnabled());
            if (cb.mPreEqEnabled) {
                for (unsigned int b = 0; b < getPreEqBandCount(); b++) {
                    DPEqBand *pEqBand = pPreEq->getBand(b);
                    if (pEqBand == NULL) {
                        ALOGE("Error: updateParameters null PreEqBand for band %d", b);
                        return; //failed.
                    }
                    ChannelBuffer::EqBandParams *pEqBandParams = &cb.mPreEqBands[b];
                    IS_CHANGED(changed, pEqBandParams->enabled, pEqBand->isEnabled());
                    IS_CHANGED(changed, pEqBandParams->freqCutoffHz,
                            pEqBand->getCutoffFrequency());
                    IS_CHANGED(changed, pEqBandParams->gainDb, pEqBand->getGain());
                }
            }
        }

        if (changed) {
            float inputGainFactor = dBtoLinear(cb.inputGainDb);
            if (cb.mPreEqInUse && cb.mPreEqEnabled) {
                ALOGV("preEq changed, recomputing! channel %d", channelIndex);
                size_t binNext = 0;
                for (unsigned int b = 0; b < getPreEqBandCount(); b++) {
                    ChannelBuffer::EqBandParams *pEqBandParams = &cb.mPreEqBands[b];

                    //frequency translation
                    cb.computeBinStartStop(*pEqBandParams, binNext);
                    binNext = pEqBandParams->binStop + 1;
                    float factor = dBtoLinear(pEqBandParams->gainDb);
                    if (!pEqBandParams->enabled) {
                        factor = inputGainFactor;
                    }
                    for (size_t k = pEqBandParams->binStart;
                            k <= pEqBandParams->binStop && k < mHalfFFTSize; k++) {
                        cb.mPreEqFactorVector[k] = factor * inputGainFactor;
                    }
                }
            } else {
                ALOGV("only input gain changed, recomputing!");
                //populate PreEq factor with input gain factor.
                for (size_t k = 0; k < mHalfFFTSize; k++) {
                    cb.mPreEqFactorVector[k] = inputGainFactor;
                }
            }
        }
    } //inputGain and preEq

    //===EqPost
    if (cb.mPostEqInUse) {
        bool changed = false;

        DPEq *pPostEq = pChannel->getPostEq();
        if (pPostEq == NULL) {
            ALOGE("Error: updateParameters null postEq for channel: %d", channelIndex);
            return; //failed.
        }
        IS_CHANGED(changed, cb.mPostEqEnabled, pPostEq->isEnabled());
        if (cb.mPostEqEnabled) {
            for (unsigned int b = 0; b < getPostEqBandCount(); b++) {
                DPEqBand *pEqBand = pPostEq->getBand(b);
                if (pEqBand == NULL) {
                    ALOGE("Error: updateParameters PostEqBand NULL for band %d", b);
                    return; //failed.
                }
                ChannelBuffer::EqBandParams *pEqBandParams = &cb.mPostEqBands[b];
                IS_CHANGED(changed, pEqBandParams->enabled, pEqBand->isEnabled());
                IS_CHANGED(changed, pEqBandParams->freqCutoffHz,
                        pEqBand->getCutoffFrequency());
                IS_CHANGED(changed, pEqBandParams->gainDb, pEqBand->getGain());
            }
            if (changed) {
                ALOGV("postEq changed, recomputing! channel %d", channelIndex);
                size_t binNext = 0;
                for (unsigned int b = 0; b < getPostEqBandCount(); b++) {
                    ChannelBuffer::EqBandParams *pEqBandParams = &cb.mPostEqBands[b];

                    //frequency translation
                    cb.computeBinStartStop(*pEqBandParams, binNext);
                    binNext = pEqBandParams->binStop + 1;
                    float factor = dBtoLinear(pEqBandParams->gainDb);
                    if (!pEqBandParams->enabled) {
                        factor = 1.0;
                    }
                    for (size_t k = pEqBandParams->binStart;
                            k <= pEqBandParams->binStop && k < mHalfFFTSize; k++) {
                        cb.mPostEqFactorVector[k] = factor;
                    }
                }
            }
        } //enabled
    }

    //===MBC
    if (cb.mMbcInUse) {
        DPMbc *pMbc = pChannel->getMbc();
        if (pMbc == NULL) {
            ALOGE("Error: updateParameters Mbc NULL for channel: %d", channelIndex);
            return;
        }
        cb.mMbcEnabled = pMbc->isEnabled();
        if (cb.mMbcEnabled) {
            bool changed = false;
            for (unsigned int b = 0; b < getMbcBandCount(); b++) {
                DPMbcBand *pMbcBand = pMbc->getBand(b);
                if (pMbcBand == NULL) {
                    ALOGE("Error: updateParameters MbcBand NULL for band %d", b);
                    return; //failed.
                }
                ChannelBuffer::MbcBandParams *pMbcBandParams = &cb.mMbcBands[b];
                pMbcBandParams->enabled = pMbcBand->isEnabled();
                IS_CHANGED(changed, pMbcBandParams->freqCutoffHz,
                        pMbcBand->getCutoffFrequency());

                pMbcBandParams->gainPreDb = pMbcBand->getPreGain();
                pMbcBandParams->gainPostDb = pMbcBand->getPostGain();
                pMbcBandParams->attackTimeMs = pMbcBand->getAttackTime();
                pMbcBandParams->releaseTimeMs = pMbcBand->getReleaseTime();
                pMbcBandParams->ratio = pMbcBand->getRatio();
                pMbcBandParams->thresholdDb = pMbcBand->getThreshold();
                pMbcBandParams->kneeWidthDb = pMbcBand->getKneeWidth();
                pMbcBandParams->noiseGateThresholdDb = pMbcBand->getNoiseGateThreshold();
                pMbcBandParams->expanderRatio = pMbcBand->getExpanderRatio();

            }

            if (changed) {
                ALOGV("mbc changed, recomputing! channel %d", channelIndex);
                size_t binNext= 0;
                for (unsigned int b = 0; b < getMbcBandCount(); b++) {
                    ChannelBuffer::MbcBandParams *pMbcBandParams = &cb.mMbcBands[b];

                    pMbcBandParams->previousEnvelope = 0;

                    //frequency translation
                    cb.computeBinStartStop(*pMbcBandParams, binNext);
                    binNext = pMbcBandParams->binStop + 1;
                }

            }

        }
    }
}

size_t DPFrequency::processSamples(const float *in, float *out, size_t samples) {
       const float *pIn = in;
       float *pOut = out;

       int channelCount = mChannelBuffers.size();
       if (channelCount < 1) {
           ALOGW("warning: no Channels ready for processing");
           return 0;
       }

       //**Check if parameters have changed and update
       for (int ch = 0; ch < channelCount; ch++) {
           updateParameters(mChannelBuffers[ch], ch);
       }

       //**separate into channels
       for (size_t k = 0; k < samples; k += channelCount) {
           for (int ch = 0; ch < channelCount; ch++) {
               mChannelBuffers[ch].cBInput.write(*pIn++);
           }
       }

       //TODO: lookahead limiters
       //TODO: apply linked limiters to all channels.
       //**Process each Channel
       for (int ch = 0; ch < channelCount; ch++) {
           processMono(mChannelBuffers[ch]);
       }

       //** estimate how much data is available in ALL channels
       size_t available = mChannelBuffers[0].cBOutput.availableToRead();
       for (int ch = 1; ch < channelCount; ch++) {
           available = std::min(available, mChannelBuffers[ch].cBOutput.availableToRead());
       }

       //** make sure to output just what the buffer can handle
       if (available > samples/channelCount) {
           available = samples/channelCount;
       }

       //**Prepend zeroes if necessary
       size_t fill = samples - (channelCount * available);
       for (size_t k = 0; k < fill; k++) {
           *pOut++ = 0;
       }

       //**interleave channels
       for (size_t k = 0; k < available; k++) {
           for (int ch = 0; ch < channelCount; ch++) {
               *pOut++ = mChannelBuffers[ch].cBOutput.read();
           }
       }

       return samples;
}

size_t DPFrequency::processMono(ChannelBuffer &cb) {

    size_t processedSamples = 0;

    size_t available = cb.cBInput.availableToRead();
    while (available >= mBlockSize - mOverlapSize) {

        //move tail of previous
        for (unsigned int k = 0; k < mOverlapSize; ++k) {
            cb.input[k] = cb.input[mBlockSize - mOverlapSize + k];
        }

        //read new available data
        for (unsigned int k = 0; k < mBlockSize - mOverlapSize; k++) {
            cb.input[mOverlapSize + k] = cb.cBInput.read();
        }

        //## Actual process
        processOneVector(cb.output, cb.input, cb);
        //##End of Process

        //mix tail (and capture new tail
        for (unsigned int k = 0; k < mOverlapSize; k++) {
            cb.output[k] += cb.outTail[k];
            cb.outTail[k] = cb.output[mBlockSize - mOverlapSize + k]; //new tail
        }

        //output data
        for (unsigned int k = 0; k < mBlockSize - mOverlapSize; k++) {
            cb.cBOutput.write(cb.output[k]);
        }

        available = cb.cBInput.availableToRead();
    }

    return processedSamples;
}

size_t DPFrequency::processOneVector(FloatVec & output, FloatVec & input,
        ChannelBuffer &cb) {

    //##apply window
    Eigen::Map<Eigen::VectorXf> eWindow(&mVWindow[0], mVWindow.size());
    Eigen::Map<Eigen::VectorXf> eInput(&input[0], input.size());

    Eigen::VectorXf eWin = eInput.cwiseProduct(eWindow); //apply window

    //##fft //TODO: refactor frequency transformations away from other stages.
    mFftServer.fwd(mComplexTemp, eWin);

    size_t cSize = mComplexTemp.size();
    size_t maxBin = std::min(cSize/2, mHalfFFTSize);

    //== EqPre (always runs)
    for (size_t k = 0; k < maxBin; k++) {
        mComplexTemp[k] *= cb.mPreEqFactorVector[k];
    }

    //== MBC
    if (cb.mMbcInUse && cb.mMbcEnabled) {
        for (size_t band = 0; band < cb.mMbcBands.size(); band++) {
            ChannelBuffer::MbcBandParams *pMbcBandParams = &cb.mMbcBands[band];
            float fEnergySum = 0;

            //apply pre gain.
            float preGainFactor = dBtoLinear(pMbcBandParams->gainPreDb);
            float preGainSquared = preGainFactor * preGainFactor;

            for (size_t k = pMbcBandParams->binStart; k <= pMbcBandParams->binStop; k++) {
                float fReal = mComplexTemp[k].real();
                float fImag = mComplexTemp[k].imag();
                float fSquare = (fReal * fReal + fImag * fImag) * preGainSquared;

                fEnergySum += fSquare;
            }

            fEnergySum = sqrt(fEnergySum /2.0);
            float fTheta = 0.0;
            float fFAtt = pMbcBandParams->attackTimeMs;
            float fFRel = pMbcBandParams->releaseTimeMs;

            float fUpdatesPerSecond = 10; //TODO: compute from framerate


            if (fEnergySum > pMbcBandParams->previousEnvelope) {
                fTheta = exp(-1.0 / (fFAtt * fUpdatesPerSecond));
            } else {
                fTheta = exp(-1.0 / (fFRel * fUpdatesPerSecond));
            }

            float fEnv = (1.0 - fTheta) * fEnergySum + fTheta * pMbcBandParams->previousEnvelope;

            //preserve for next iteration
            pMbcBandParams->previousEnvelope = fEnv;

            float fThreshold = dBtoLinear(pMbcBandParams->thresholdDb);
            float fNoiseGateThreshold = dBtoLinear(pMbcBandParams->noiseGateThresholdDb);

            float fNewFactor = 1.0;

            if (fEnv > fThreshold) {
                float fDbAbove = linearToDb(fThreshold / fEnv);
                float fDbTarget = fDbAbove / pMbcBandParams->ratio;
                float fDbChange = fDbAbove - fDbTarget;
                fNewFactor = dBtoLinear(fDbChange);
            } else if (fEnv < fNoiseGateThreshold) {
                if (fEnv < MIN_ENVELOPE) {
                    fEnv = MIN_ENVELOPE;
                }
                float fDbBelow = linearToDb(fNoiseGateThreshold / fEnv);
                float fDbTarget = fDbBelow / pMbcBandParams->expanderRatio;
                float fDbChange = fDbBelow - fDbTarget;
                fNewFactor = dBtoLinear(fDbChange);
            }

            //apply post gain.
            fNewFactor *= dBtoLinear(pMbcBandParams->gainPostDb);

            if (fNewFactor < 0) {
                fNewFactor = 0;
            }

            //apply to this band
            for (size_t k = pMbcBandParams->binStart; k <= pMbcBandParams->binStop; k++) {
                mComplexTemp[k] *= fNewFactor;
            }

        } //end per band process

    } //end MBC

    //== EqPost
    if (cb.mPostEqInUse && cb.mPostEqEnabled) {
        for (size_t k = 0; k < maxBin; k++) {
            mComplexTemp[k] *= cb.mPostEqFactorVector[k];
        }
    }

    //##ifft directly to output.
    Eigen::Map<Eigen::VectorXf> eOutput(&output[0], output.size());
    mFftServer.inv(eOutput, mComplexTemp);

    return mBlockSize;
}

} //namespace dp_fx
