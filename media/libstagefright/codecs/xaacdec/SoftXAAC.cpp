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

//#define LOG_NDEBUG 0
#define LOG_TAG "SoftXAAC"
#include <utils/Log.h>

#include "SoftXAAC.h"

#include <OMX_AudioExt.h>
#include <OMX_IndexExt.h>
#include <cutils/properties.h>
#include <media/stagefright/foundation/ADebug.h>
#include <media/stagefright/foundation/hexdump.h>
#include <media/stagefright/MediaErrors.h>
#include <utils/misc.h>
#include <math.h>

#define DRC_DEFAULT_MOBILE_REF_LEVEL 64  /* 64*-0.25dB = -16 dB below full scale for mobile conf */
#define DRC_DEFAULT_MOBILE_DRC_CUT   127 /* maximum compression of dynamic range for mobile conf */
#define DRC_DEFAULT_MOBILE_DRC_BOOST 127 /* maximum compression of dynamic range for mobile conf */
#define DRC_DEFAULT_MOBILE_DRC_HEAVY 1   /* switch for heavy compression for mobile conf */
#define DRC_DEFAULT_MOBILE_ENC_LEVEL (-1) /* encoder target level; -1 => the value is unknown, otherwise dB step value (e.g. 64 for -16 dB) */

#define PROP_DRC_OVERRIDE_REF_LEVEL  "aac_drc_reference_level"
#define PROP_DRC_OVERRIDE_CUT        "aac_drc_cut"
#define PROP_DRC_OVERRIDE_BOOST      "aac_drc_boost"
#define PROP_DRC_OVERRIDE_HEAVY      "aac_drc_heavy"
#define PROP_DRC_OVERRIDE_ENC_LEVEL "aac_drc_enc_target_level"
#define MAX_CHANNEL_COUNT            8  /* maximum number of audio channels that can be decoded */

namespace android {

template<class T>
static void InitOMXParams(T *params) {
    params->nSize = sizeof(T);
    params->nVersion.s.nVersionMajor = 1;
    params->nVersion.s.nVersionMinor = 0;
    params->nVersion.s.nRevision = 0;
    params->nVersion.s.nStep = 0;
}

static const OMX_U32 kSupportedProfiles[] = {
    OMX_AUDIO_AACObjectLC,
    OMX_AUDIO_AACObjectHE,
    OMX_AUDIO_AACObjectHE_PS,
    OMX_AUDIO_AACObjectLD,
    OMX_AUDIO_AACObjectELD,
};

SoftXAAC::SoftXAAC(
        const char *name,
        const OMX_CALLBACKTYPE *callbacks,
        OMX_PTR appData,
        OMX_COMPONENTTYPE **component)
    : SimpleSoftOMXComponent(name, callbacks, appData, component),
    mIsADTS(false),
    mInputBufferCount(0),
    mOutputBufferCount(0),
    mSignalledError(false),
    mLastInHeader(NULL),
    mPrevTimestamp(0),
    mCurrentTimestamp(0),
    mOutputPortSettingsChange(NONE),
    mXheaacCodecHandle(NULL),
    mInputBufferSize(0),
    mOutputFrameLength(1024),
    mInputBuffer(NULL),
    mOutputBuffer(NULL),
    mSampFreq(0),
    mNumChannels(0),
    mPcmWdSz(0),
    mChannelMask(0),
    mIsCodecInitialized(false),
    mIsCodecConfigFlushRequired(false)
{
    initPorts();
    CHECK_EQ(initDecoder(), (status_t)OK);
}

SoftXAAC::~SoftXAAC() {
    int errCode = deInitXAACDecoder();
    if (0 != errCode) {
        ALOGE("deInitXAACDecoder() failed %d",errCode);
    }

    mIsCodecInitialized = false;
    mIsCodecConfigFlushRequired = false;
}

void SoftXAAC::initPorts() {
    OMX_PARAM_PORTDEFINITIONTYPE def;
    InitOMXParams(&def);

    def.nPortIndex = 0;
    def.eDir = OMX_DirInput;
    def.nBufferCountMin = kNumInputBuffers;
    def.nBufferCountActual = def.nBufferCountMin;
    def.nBufferSize = 8192;
    def.bEnabled = OMX_TRUE;
    def.bPopulated = OMX_FALSE;
    def.eDomain = OMX_PortDomainAudio;
    def.bBuffersContiguous = OMX_FALSE;
    def.nBufferAlignment = 1;

    def.format.audio.cMIMEType = const_cast<char *>("audio/aac");
    def.format.audio.pNativeRender = NULL;
    def.format.audio.bFlagErrorConcealment = OMX_FALSE;
    def.format.audio.eEncoding = OMX_AUDIO_CodingAAC;

    addPort(def);

    def.nPortIndex = 1;
    def.eDir = OMX_DirOutput;
    def.nBufferCountMin = kNumOutputBuffers;
    def.nBufferCountActual = def.nBufferCountMin;
    def.nBufferSize = 4096 * MAX_CHANNEL_COUNT;
    def.bEnabled = OMX_TRUE;
    def.bPopulated = OMX_FALSE;
    def.eDomain = OMX_PortDomainAudio;
    def.bBuffersContiguous = OMX_FALSE;
    def.nBufferAlignment = 2;

    def.format.audio.cMIMEType = const_cast<char *>("audio/raw");
    def.format.audio.pNativeRender = NULL;
    def.format.audio.bFlagErrorConcealment = OMX_FALSE;
    def.format.audio.eEncoding = OMX_AUDIO_CodingPCM;

    addPort(def);
}

status_t SoftXAAC::initDecoder() {
    status_t status = UNKNOWN_ERROR;

    unsigned int ui_drc_val;
    IA_ERRORCODE err_code = IA_NO_ERROR;
    initXAACDecoder();
    if (NULL == mXheaacCodecHandle) {
        ALOGE("AAC decoder is null. initXAACDecoder Failed");
    } else {
        status = OK;
    }

    mEndOfInput = false;
    mEndOfOutput = false;

    char value[PROPERTY_VALUE_MAX];
    if (property_get(PROP_DRC_OVERRIDE_REF_LEVEL, value, NULL))
    {
        ui_drc_val = atoi(value);
        ALOGV("AAC decoder using desired DRC target reference level of %d instead of %d",ui_drc_val,
                DRC_DEFAULT_MOBILE_REF_LEVEL);
    }
    else
    {
        ui_drc_val= DRC_DEFAULT_MOBILE_REF_LEVEL;
    }

    err_code = ixheaacd_dec_api(mXheaacCodecHandle,
                                IA_API_CMD_SET_CONFIG_PARAM,
                                IA_ENHAACPLUS_DEC_CONFIG_PARAM_DRC_TARGET_LEVEL,
                                &ui_drc_val);

    ALOGV("Error code returned after DRC Target level set_config is %d", err_code);
    ALOGV("Setting IA_ENHAACPLUS_DEC_CONFIG_PARAM_DRC_TARGET_LEVEL with value %d", ui_drc_val);

    if (property_get(PROP_DRC_OVERRIDE_CUT, value, NULL))
    {
        ui_drc_val = atoi(value);
        ALOGV("AAC decoder using desired DRC attenuation factor of %d instead of %d", ui_drc_val,
                DRC_DEFAULT_MOBILE_DRC_CUT);
    }
    else
    {
        ui_drc_val=DRC_DEFAULT_MOBILE_DRC_CUT;
    }

    err_code = ixheaacd_dec_api(mXheaacCodecHandle,
                                IA_API_CMD_SET_CONFIG_PARAM,
                                IA_ENHAACPLUS_DEC_CONFIG_PARAM_DRC_CUT,
                                &ui_drc_val);
    ALOGV("Error code returned after DRC cut factor set_config is %d", err_code);
    ALOGV("Setting IA_ENHAACPLUS_DEC_CONFIG_PARAM_DRC_CUT with value %d", ui_drc_val);

    if (property_get(PROP_DRC_OVERRIDE_BOOST, value, NULL))
    {
        ui_drc_val = atoi(value);
        ALOGV("AAC decoder using desired DRC boost factor of %d instead of %d", ui_drc_val,
                DRC_DEFAULT_MOBILE_DRC_BOOST);
    }
    else
    {
        ui_drc_val = DRC_DEFAULT_MOBILE_DRC_BOOST;
    }

    err_code = ixheaacd_dec_api(mXheaacCodecHandle,
                                IA_API_CMD_SET_CONFIG_PARAM,
                                IA_ENHAACPLUS_DEC_CONFIG_PARAM_DRC_BOOST,
                                &ui_drc_val);
    ALOGV("Error code returned after DRC boost factor set_config is %d", err_code);
    ALOGV("Setting DRC_DEFAULT_MOBILE_DRC_BOOST with value %d", ui_drc_val);

    if (property_get(PROP_DRC_OVERRIDE_BOOST, value, NULL))
    {
        ui_drc_val = atoi(value);
        ALOGV("AAC decoder using desired DRC boost factor of %d instead of %d", ui_drc_val,
                DRC_DEFAULT_MOBILE_DRC_HEAVY);
    }
    else
    {
        ui_drc_val = DRC_DEFAULT_MOBILE_DRC_HEAVY;
    }

    err_code = ixheaacd_dec_api(mXheaacCodecHandle,
                                IA_API_CMD_SET_CONFIG_PARAM,
                                IA_ENHAACPLUS_DEC_CONFIG_PARAM_DRC_HEAVY_COMP,
                                &ui_drc_val);
    ALOGV("Error code returned after DRC heavy set_config is %d", err_code);
    ALOGV("Setting DRC_DEFAULT_MOBILE_DRC_HEAVY with value %d", ui_drc_val);

    return status;
}

OMX_ERRORTYPE SoftXAAC::internalGetParameter(
        OMX_INDEXTYPE index, OMX_PTR params) {

    switch ((OMX_U32) index) {

        case OMX_IndexParamAudioPortFormat:
        {
            OMX_AUDIO_PARAM_PORTFORMATTYPE *formatParams =
                (OMX_AUDIO_PARAM_PORTFORMATTYPE *)params;

            if (!isValidOMXParam(formatParams)) {
                return OMX_ErrorBadParameter;
            }

            if (formatParams->nPortIndex > 1) {
                return OMX_ErrorUndefined;
            }

            if (formatParams->nIndex > 0) {
                return OMX_ErrorNoMore;
            }

            formatParams->eEncoding =
                (formatParams->nPortIndex == 0)
                    ? OMX_AUDIO_CodingAAC : OMX_AUDIO_CodingPCM;

            return OMX_ErrorNone;
        }

        case OMX_IndexParamAudioAac:
        {
            OMX_AUDIO_PARAM_AACPROFILETYPE *aacParams =
                (OMX_AUDIO_PARAM_AACPROFILETYPE *)params;

            if (!isValidOMXParam(aacParams)) {
                return OMX_ErrorBadParameter;
            }

            if (aacParams->nPortIndex != 0) {
                return OMX_ErrorUndefined;
            }

            aacParams->nBitRate = 0;
            aacParams->nAudioBandWidth = 0;
            aacParams->nAACtools = 0;
            aacParams->nAACERtools = 0;
            aacParams->eAACProfile = OMX_AUDIO_AACObjectMain;

            aacParams->eAACStreamFormat =
                mIsADTS
                    ? OMX_AUDIO_AACStreamFormatMP4ADTS
                    : OMX_AUDIO_AACStreamFormatMP4FF;

            aacParams->eChannelMode = OMX_AUDIO_ChannelModeStereo;

            if (!isConfigured()) {
                aacParams->nChannels = 1;
                aacParams->nSampleRate = 44100;
                aacParams->nFrameLength = 0;
            } else {
                aacParams->nChannels = mNumChannels;
                aacParams->nSampleRate = mSampFreq;
                aacParams->nFrameLength = mOutputFrameLength;
            }

            return OMX_ErrorNone;
        }

        case OMX_IndexParamAudioPcm:
        {
            OMX_AUDIO_PARAM_PCMMODETYPE *pcmParams =
                (OMX_AUDIO_PARAM_PCMMODETYPE *)params;

            if (!isValidOMXParam(pcmParams)) {
                return OMX_ErrorBadParameter;
            }

            if (pcmParams->nPortIndex != 1) {
                return OMX_ErrorUndefined;
            }

            pcmParams->eNumData = OMX_NumericalDataSigned;
            pcmParams->eEndian = OMX_EndianBig;
            pcmParams->bInterleaved = OMX_TRUE;
            pcmParams->nBitPerSample = 16;
            pcmParams->ePCMMode = OMX_AUDIO_PCMModeLinear;
            pcmParams->eChannelMapping[0] = OMX_AUDIO_ChannelLF;
            pcmParams->eChannelMapping[1] = OMX_AUDIO_ChannelRF;
            pcmParams->eChannelMapping[2] = OMX_AUDIO_ChannelCF;
            pcmParams->eChannelMapping[3] = OMX_AUDIO_ChannelLFE;
            pcmParams->eChannelMapping[4] = OMX_AUDIO_ChannelLS;
            pcmParams->eChannelMapping[5] = OMX_AUDIO_ChannelRS;

            if (!isConfigured()) {
                pcmParams->nChannels = 1;
                pcmParams->nSamplingRate = 44100;
            } else {
                pcmParams->nChannels = mNumChannels;
                pcmParams->nSamplingRate = mSampFreq;
            }

            return OMX_ErrorNone;
        }

        case OMX_IndexParamAudioProfileQuerySupported:
        {
            OMX_AUDIO_PARAM_ANDROID_PROFILETYPE *profileParams =
                (OMX_AUDIO_PARAM_ANDROID_PROFILETYPE *)params;

            if (!isValidOMXParam(profileParams)) {
                return OMX_ErrorBadParameter;
            }

            if (profileParams->nPortIndex != 0) {
                return OMX_ErrorUndefined;
            }

            if (profileParams->nProfileIndex >= NELEM(kSupportedProfiles)) {
                return OMX_ErrorNoMore;
            }

            profileParams->eProfile =
                kSupportedProfiles[profileParams->nProfileIndex];

            return OMX_ErrorNone;
        }

        default:
            return SimpleSoftOMXComponent::internalGetParameter(index, params);
    }
}

OMX_ERRORTYPE SoftXAAC::internalSetParameter(
        OMX_INDEXTYPE index, const OMX_PTR params) {

    switch ((int)index) {
        case OMX_IndexParamStandardComponentRole:
        {
            const OMX_PARAM_COMPONENTROLETYPE *roleParams =
                (const OMX_PARAM_COMPONENTROLETYPE *)params;

            if (!isValidOMXParam(roleParams)) {
                return OMX_ErrorBadParameter;
            }

            if (strncmp((const char *)roleParams->cRole,
                        "audio_decoder.aac",
                        OMX_MAX_STRINGNAME_SIZE - 1)) {
                return OMX_ErrorUndefined;
            }

            return OMX_ErrorNone;
        }

        case OMX_IndexParamAudioPortFormat:
        {
            const OMX_AUDIO_PARAM_PORTFORMATTYPE *formatParams =
                (const OMX_AUDIO_PARAM_PORTFORMATTYPE *)params;

            if (!isValidOMXParam(formatParams)) {
                return OMX_ErrorBadParameter;
            }

            if (formatParams->nPortIndex > 1) {
                return OMX_ErrorUndefined;
            }

            if ((formatParams->nPortIndex == 0
                        && formatParams->eEncoding != OMX_AUDIO_CodingAAC)
                || (formatParams->nPortIndex == 1
                        && formatParams->eEncoding != OMX_AUDIO_CodingPCM)) {
                return OMX_ErrorUndefined;
            }

            return OMX_ErrorNone;
        }

        case OMX_IndexParamAudioAac:
        {
            const OMX_AUDIO_PARAM_AACPROFILETYPE *aacParams =
                (const OMX_AUDIO_PARAM_AACPROFILETYPE *)params;

            if (!isValidOMXParam(aacParams)) {
                return OMX_ErrorBadParameter;
            }

            if (aacParams->nPortIndex != 0) {
                return OMX_ErrorUndefined;
            }

            if (aacParams->eAACStreamFormat == OMX_AUDIO_AACStreamFormatMP4FF) {
                mIsADTS = false;
            } else if (aacParams->eAACStreamFormat
                        == OMX_AUDIO_AACStreamFormatMP4ADTS) {
                mIsADTS = true;
            } else {
                return OMX_ErrorUndefined;
            }

            return OMX_ErrorNone;
        }

        case OMX_IndexParamAudioAndroidAacPresentation:
        {
            const OMX_AUDIO_PARAM_ANDROID_AACPRESENTATIONTYPE *aacPresParams =
                    (const OMX_AUDIO_PARAM_ANDROID_AACPRESENTATIONTYPE *)params;

            if (!isValidOMXParam(aacPresParams)) {
                ALOGE("set OMX_ErrorBadParameter");
                return OMX_ErrorBadParameter;
            }

            // for the following parameters of the OMX_AUDIO_PARAM_AACPROFILETYPE structure,
            // a value of -1 implies the parameter is not set by the application:
            //   nMaxOutputChannels     -1 by default
            //   nDrcCut                uses default platform properties, see initDecoder()
            //   nDrcBoost                idem
            //   nHeavyCompression        idem
            //   nTargetReferenceLevel    idem
            //   nEncodedTargetLevel      idem
            if (aacPresParams->nMaxOutputChannels >= 0) {
                int max;
                if (aacPresParams->nMaxOutputChannels >= 8) { max = 8; }
                else if (aacPresParams->nMaxOutputChannels >= 6) { max = 6; }
                else if (aacPresParams->nMaxOutputChannels >= 2) { max = 2; }
                else {
                    // -1 or 0: disable downmix,  1: mono
                    max = aacPresParams->nMaxOutputChannels;
                }
            }
            /* Apply DRC Changes */
            setXAACDRCInfo(aacPresParams->nDrcCut,
                           aacPresParams->nDrcBoost,
                           aacPresParams->nTargetReferenceLevel,
                           aacPresParams->nHeavyCompression);

            return OMX_ErrorNone;
        }

        case OMX_IndexParamAudioPcm:
        {
            const OMX_AUDIO_PARAM_PCMMODETYPE *pcmParams =
                (OMX_AUDIO_PARAM_PCMMODETYPE *)params;

            if (!isValidOMXParam(pcmParams)) {
                return OMX_ErrorBadParameter;
            }

            if (pcmParams->nPortIndex != 1) {
                return OMX_ErrorUndefined;
            }

            return OMX_ErrorNone;
        }

        default:
            return SimpleSoftOMXComponent::internalSetParameter(index, params);
    }
}

bool SoftXAAC::isConfigured() const {
    return mInputBufferCount > 0;
}

void SoftXAAC::onQueueFilled(OMX_U32 /* portIndex */) {
    if (mSignalledError || mOutputPortSettingsChange != NONE) {
        ALOGE("onQueueFilled do not process %d %d",mSignalledError,mOutputPortSettingsChange);
        return;
    }

    uint8_t*  inBuffer        = NULL;
    uint32_t  inBufferLength  = 0;

    List<BufferInfo *> &inQueue = getPortQueue(0);
    List<BufferInfo *> &outQueue = getPortQueue(1);

    signed int numOutBytes = 0;

    /* If decoder call fails in between, then mOutputFrameLength is used  */
    /* Decoded output for AAC is 1024/2048 samples / channel             */
    /* TODO: For USAC mOutputFrameLength can go up to 4096                 */
    /* Note: entire buffer logic to save and retrieve assumes 2 bytes per*/
    /* sample currently                                                  */
    if (mIsCodecInitialized) {
        numOutBytes = mOutputFrameLength * (mPcmWdSz/8) * mNumChannels;
        if ((mPcmWdSz/8) != 2) {
            ALOGE("XAAC assumes 2 bytes per sample! mPcmWdSz %d",mPcmWdSz);
        }
    }

    while ((!inQueue.empty() || mEndOfInput) && !outQueue.empty()) {
        if (!inQueue.empty()) {
            BufferInfo *inInfo = *inQueue.begin();
            OMX_BUFFERHEADERTYPE *inHeader = inInfo->mHeader;

            mEndOfInput = (inHeader->nFlags & OMX_BUFFERFLAG_EOS) != 0;

            if (mInputBufferCount == 0 && !(inHeader->nFlags & OMX_BUFFERFLAG_CODECCONFIG)) {
                ALOGE("first buffer should have OMX_BUFFERFLAG_CODECCONFIG set");
                inHeader->nFlags |= OMX_BUFFERFLAG_CODECCONFIG;
            }
            if ((inHeader->nFlags & OMX_BUFFERFLAG_CODECCONFIG) != 0) {
                BufferInfo *inInfo = *inQueue.begin();
                OMX_BUFFERHEADERTYPE *inHeader = inInfo->mHeader;

                inBuffer = inHeader->pBuffer + inHeader->nOffset;
                inBufferLength = inHeader->nFilledLen;

                /* GA header configuration sent to Decoder! */
                int err_code = configXAACDecoder(inBuffer,inBufferLength);
                if (0 != err_code) {
                    ALOGW("configXAACDecoder err_code = %d", err_code);
                    mSignalledError = true;
                    notify(OMX_EventError, OMX_ErrorUndefined, err_code, NULL);
                    return;
                }
                mInputBufferCount++;
                mOutputBufferCount++; // fake increase of outputBufferCount to keep the counters aligned

                inInfo->mOwnedByUs = false;
                inQueue.erase(inQueue.begin());
                mLastInHeader = NULL;
                inInfo = NULL;
                notifyEmptyBufferDone(inHeader);
                inHeader = NULL;

                // Only send out port settings changed event if both sample rate
                // and mNumChannels are valid.
                if (mSampFreq && mNumChannels && !mIsCodecConfigFlushRequired) {
                    ALOGV("Configuring decoder: %d Hz, %d channels", mSampFreq, mNumChannels);
                    notify(OMX_EventPortSettingsChanged, 1, 0, NULL);
                    mOutputPortSettingsChange = AWAITING_DISABLED;
                }

                return;
            }

            if (inHeader->nFilledLen == 0) {
                inInfo->mOwnedByUs = false;
                inQueue.erase(inQueue.begin());
                mLastInHeader = NULL;
                inInfo = NULL;
                notifyEmptyBufferDone(inHeader);
                inHeader = NULL;
                continue;
            }

            // Restore Offset and Length for Port reconfig case
            size_t tempOffset =  inHeader->nOffset;
            size_t tempFilledLen = inHeader->nFilledLen;
            if (mIsADTS) {
                 size_t adtsHeaderSize = 0;
                // skip 30 bits, aac_frame_length follows.
                // ssssssss ssssiiip ppffffPc ccohCCll llllllll lll?????

                const uint8_t *adtsHeader = inHeader->pBuffer + inHeader->nOffset;

                bool signalError = false;
                if (inHeader->nFilledLen < 7) {
                    ALOGE("Audio data too short to contain even the ADTS header. "
                            "Got %d bytes.", inHeader->nFilledLen);
                    hexdump(adtsHeader, inHeader->nFilledLen);
                    signalError = true;
                } else {
                    bool protectionAbsent = (adtsHeader[1] & 1);

                    unsigned aac_frame_length =
                        ((adtsHeader[3] & 3) << 11)
                        | (adtsHeader[4] << 3)
                        | (adtsHeader[5] >> 5);

                    if (inHeader->nFilledLen < aac_frame_length) {
                        ALOGE("Not enough audio data for the complete frame. "
                                "Got %d bytes, frame size according to the ADTS "
                                "header is %u bytes.",
                                inHeader->nFilledLen, aac_frame_length);
                        hexdump(adtsHeader, inHeader->nFilledLen);
                        signalError = true;
                    } else {
                        adtsHeaderSize = (protectionAbsent ? 7 : 9);
                        if (aac_frame_length < adtsHeaderSize) {
                            signalError = true;
                        } else {
                            inBuffer = (uint8_t *)adtsHeader + adtsHeaderSize;
                            inBufferLength = aac_frame_length - adtsHeaderSize;

                            inHeader->nOffset += adtsHeaderSize;
                            inHeader->nFilledLen -= adtsHeaderSize;
                        }
                    }
                }

                if (signalError) {
                    mSignalledError = true;
                    notify(OMX_EventError, OMX_ErrorStreamCorrupt, ERROR_MALFORMED, NULL);
                    return;
                }

                // insert buffer size and time stamp
                if (mLastInHeader != inHeader) {
                    mCurrentTimestamp = inHeader->nTimeStamp;
                    mLastInHeader = inHeader;
                } else {
                    mCurrentTimestamp = mPrevTimestamp +
                        mOutputFrameLength  * 1000000ll / mSampFreq;
                }
            } else {
                inBuffer = inHeader->pBuffer + inHeader->nOffset;
                inBufferLength = inHeader->nFilledLen;
                mLastInHeader = inHeader;
                mCurrentTimestamp = inHeader->nTimeStamp;
            }

            int numLoops = 0;
            signed int prevSampleRate = mSampFreq;
            signed int prevNumChannels = mNumChannels;

            /* XAAC decoder expects first frame to be fed via configXAACDecoder API */
            /* which should initialize the codec. Once this state is reached, call the  */
            /* decodeXAACStream API with same frame to decode!                        */
            if (!mIsCodecInitialized) {
                int err_code = configXAACDecoder(inBuffer,inBufferLength);
                if (0 != err_code) {
                    ALOGW("configXAACDecoder Failed 2 err_code = %d", err_code);
                    mSignalledError = true;
                    notify(OMX_EventError, OMX_ErrorUndefined, err_code, NULL);
                    return;
                }
                mIsCodecConfigFlushRequired = true;
            }

            if (!mSampFreq || !mNumChannels) {
                if ((mInputBufferCount > 2) && (mOutputBufferCount <= 1)) {
                    ALOGW("Invalid AAC stream");
                    ALOGW("mSampFreq %d mNumChannels %d ",mSampFreq,mNumChannels);
                    mSignalledError = true;
                    notify(OMX_EventError, OMX_ErrorUndefined, 0, NULL);
                    return;
                }
            } else if ((mSampFreq != prevSampleRate) ||
                       (mNumChannels != prevNumChannels)) {
                ALOGV("Reconfiguring decoder: %d->%d Hz, %d->%d channels",
                      prevSampleRate, mSampFreq, prevNumChannels, mNumChannels);
                inHeader->nOffset = tempOffset;
                inHeader->nFilledLen = tempFilledLen;
                notify(OMX_EventPortSettingsChanged, 1, 0, NULL);
                mOutputPortSettingsChange = AWAITING_DISABLED;
                return;
            }

            signed int bytesConsumed = 0;
            int errorCode = 0;
            if (mIsCodecInitialized) {
                errorCode = decodeXAACStream(inBuffer,inBufferLength, &bytesConsumed, &numOutBytes);
            } else {
                ALOGW("Assumption that first frame after header initializes decoder failed!");
            }
            inHeader->nFilledLen -= bytesConsumed;
            inHeader->nOffset += bytesConsumed;

            if (inHeader->nFilledLen != 0) {
                ALOGE("All data not consumed");
            }

            /* In case of error, decoder would have given out empty buffer */
            if ((0 != errorCode) && (0 == numOutBytes) && mIsCodecInitialized) {
                numOutBytes = mOutputFrameLength * (mPcmWdSz/8) * mNumChannels;
            }
            numLoops++;

            if (0 == bytesConsumed) {
                ALOGE("bytesConsumed = 0 should never happen");
                mSignalledError = true;
                notify(OMX_EventError, OMX_ErrorUndefined, 0, NULL);
                return;
            }

            if (errorCode) {
                /* Clear buffer for output buffer is done inside XAAC codec */
                /* TODO - Check if below memset is on top of reset inside codec */
                memset(mOutputBuffer, 0, numOutBytes); // TODO: check for overflow, ASAN

                // Discard input buffer.
                if (inHeader) {
                    inHeader->nFilledLen = 0;
                }

                // fall through
            }

            if (inHeader && inHeader->nFilledLen == 0) {
                inInfo->mOwnedByUs = false;
                mInputBufferCount++;
                inQueue.erase(inQueue.begin());
                mLastInHeader = NULL;
                inInfo = NULL;
                notifyEmptyBufferDone(inHeader);
                inHeader = NULL;
            } else {
                ALOGV("inHeader->nFilledLen = %d", inHeader ? inHeader->nFilledLen : 0);
            }

            if (!outQueue.empty() && numOutBytes) {
                BufferInfo *outInfo = *outQueue.begin();
                OMX_BUFFERHEADERTYPE *outHeader = outInfo->mHeader;

                if (outHeader->nOffset != 0) {
                    ALOGE("outHeader->nOffset != 0 is not handled");
                    mSignalledError = true;
                    notify(OMX_EventError, OMX_ErrorUndefined, 0, NULL);
                    return;
                }

                signed short *outBuffer =
                        reinterpret_cast<signed short *>(outHeader->pBuffer + outHeader->nOffset);
                int samplesize = mNumChannels * sizeof(int16_t);
                if (outHeader->nOffset
                        + mOutputFrameLength * samplesize
                        > outHeader->nAllocLen) {
                    ALOGE("buffer overflow");
                    mSignalledError = true;
                    notify(OMX_EventError, OMX_ErrorUndefined, 0, NULL);
                    return;
                }
                memcpy(outBuffer, mOutputBuffer, numOutBytes);
                outHeader->nFilledLen = numOutBytes;

                if (mEndOfInput && !outQueue.empty()) {
                    outHeader->nFlags = OMX_BUFFERFLAG_EOS;
                    mEndOfOutput = true;
                } else {
                    outHeader->nFlags = 0;
                }
                outHeader->nTimeStamp = mCurrentTimestamp;
                mPrevTimestamp = mCurrentTimestamp;

                mOutputBufferCount++;
                outInfo->mOwnedByUs = false;
                outQueue.erase(outQueue.begin());
                outInfo = NULL;
                ALOGV("out timestamp %lld / %d", outHeader->nTimeStamp, outHeader->nFilledLen);
                notifyFillBufferDone(outHeader);
                outHeader = NULL;
            }
        }

        if (mEndOfInput) {
            if (!outQueue.empty()) {
                if (!mEndOfOutput) {
                    ALOGV(" empty block signaling EOS");
                    // send partial or empty block signaling EOS
                    mEndOfOutput = true;
                    BufferInfo *outInfo = *outQueue.begin();
                    OMX_BUFFERHEADERTYPE *outHeader = outInfo->mHeader;

                    outHeader->nFilledLen = 0;
                    outHeader->nFlags = OMX_BUFFERFLAG_EOS;
                    outHeader->nTimeStamp = mPrevTimestamp ;

                    mOutputBufferCount++;
                    outInfo->mOwnedByUs = false;
                    outQueue.erase(outQueue.begin());
                    outInfo = NULL;
                    notifyFillBufferDone(outHeader);
                    outHeader = NULL;
                }
                break; // if outQueue not empty but no more output
            }
        }
    }
}

void SoftXAAC::onPortFlushCompleted(OMX_U32 portIndex) {
    if (portIndex == 0) {
        // Make sure that the next buffer output does not still
        // depend on fragments from the last one decoded.
        // drain all existing data
        if (mIsCodecInitialized) {
            configflushDecode();
        }
        drainDecoder();
        mLastInHeader = NULL;
        mEndOfInput = false;
    } else {
        mEndOfOutput = false;
    }
}

void SoftXAAC::configflushDecode() {
    IA_ERRORCODE err_code;
    UWORD32 ui_init_done;
    uint32_t inBufferLength=8203;

    err_code = ixheaacd_dec_api(mXheaacCodecHandle,
                                IA_API_CMD_INIT,
                                IA_CMD_TYPE_FLUSH_MEM,
                                NULL);
    ALOGV("Codec initialized:%d",mIsCodecInitialized);
    ALOGV("Error code from first flush %d",err_code);

    err_code = ixheaacd_dec_api(mXheaacCodecHandle,
                                IA_API_CMD_SET_INPUT_BYTES,
                                0,
                                &inBufferLength);

    err_code = ixheaacd_dec_api(mXheaacCodecHandle,
                                IA_API_CMD_INIT,
                                IA_CMD_TYPE_FLUSH_MEM,
                                NULL);

    err_code = ixheaacd_dec_api(mXheaacCodecHandle,
                                IA_API_CMD_INIT,
                                IA_CMD_TYPE_INIT_DONE_QUERY,
                                &ui_init_done);

    ALOGV("Flush called");

    if (ui_init_done) {
        err_code = getXAACStreamInfo();
        ALOGV("Found Codec with below config---\nsampFreq %d\nnumChannels %d\npcmWdSz %d\nchannelMask %d\noutputFrameLength %d",
                                    mSampFreq,mNumChannels,mPcmWdSz,mChannelMask,mOutputFrameLength);
        if(mNumChannels > MAX_CHANNEL_COUNT) {
            ALOGE(" No of channels are more than max channels\n");
            mIsCodecInitialized = false;
        }
        else
            mIsCodecInitialized = true;
    }

}
int SoftXAAC::drainDecoder() {
    return 0;
}

void SoftXAAC::onReset() {
    drainDecoder();

    // reset the "configured" state
    mInputBufferCount = 0;
    mOutputBufferCount = 0;
    mEndOfInput = false;
    mEndOfOutput = false;
    mLastInHeader = NULL;

    mSignalledError = false;
    mOutputPortSettingsChange = NONE;
}

void SoftXAAC::onPortEnableCompleted(OMX_U32 portIndex, bool enabled) {
    if (portIndex != 1) {
        return;
    }

    switch (mOutputPortSettingsChange) {
        case NONE:
            break;

        case AWAITING_DISABLED:
        {
            CHECK(!enabled);
            mOutputPortSettingsChange = AWAITING_ENABLED;
            break;
        }

        default:
        {
            CHECK_EQ((int)mOutputPortSettingsChange, (int)AWAITING_ENABLED);
            CHECK(enabled);
            mOutputPortSettingsChange = NONE;
            break;
        }
    }
}

int SoftXAAC::initXAACDecoder() {
    LOOPIDX i;

    /* Error code */
    IA_ERRORCODE err_code = IA_NO_ERROR;

    /* First part                                        */
    /* Error Handler Init                                */
    /* Get Library Name, Library Version and API Version */
    /* Initialize API structure + Default config set     */
    /* Set config params from user                       */
    /* Initialize memory tables                          */
    /* Get memory information and allocate memory        */

    /* Memory variables */
    UWORD32 ui_proc_mem_tabs_size;
    /* API size */
    UWORD32 pui_ap_isize;

    mInputBufferSize = 0;
    mInputBuffer = 0;
    mOutputBuffer = 0;
    mMallocCount = 0;

    /* Process struct initing end */
    /* ******************************************************************/
    /* Initialize API structure and set config params to default        */
    /* ******************************************************************/

    /* Get the API size */
    err_code = ixheaacd_dec_api(NULL,
                                IA_API_CMD_GET_API_SIZE,
                                0,
                                &pui_ap_isize);
     ALOGV("return code of IA_API_CMD_GET_API_SIZE: %d",err_code);
    /* Allocate memory for API */
    mMemoryArray[mMallocCount] = memalign(4, pui_ap_isize);
    if (mMemoryArray[mMallocCount] == NULL) {
        ALOGE("malloc for pui_ap_isize + 4 >> %d Failed",pui_ap_isize + 4);
    }
    /* Set API object with the memory allocated */
    mXheaacCodecHandle =
        (pVOID)((WORD8*)mMemoryArray[mMallocCount]);
    mMallocCount++;

    /* Set the config params to default values */
    err_code = ixheaacd_dec_api(mXheaacCodecHandle,
                                IA_API_CMD_INIT,
                                IA_CMD_TYPE_INIT_API_PRE_CONFIG_PARAMS,
                                NULL);
    ALOGV("return code of IA_CMD_TYPE_INIT_API_PRE_CONFIG_PARAMS: %d",err_code);

    /* ******************************************************************/
    /* Set config parameters                                            */
    /* ******************************************************************/
    UWORD32 ui_mp4_flag = 1;
    err_code = ixheaacd_dec_api(mXheaacCodecHandle,
                                IA_API_CMD_SET_CONFIG_PARAM,
                                IA_ENHAACPLUS_DEC_CONFIG_PARAM_ISMP4,
                                &ui_mp4_flag);
    ALOGV("return code of IA_ENHAACPLUS_DEC_CONFIG_PARAM_ISMP4: %d",err_code);

    /* ******************************************************************/
    /* Initialize Memory info tables                                    */
    /* ******************************************************************/

    /* Get memory info tables size */
    err_code = ixheaacd_dec_api(mXheaacCodecHandle,
                                IA_API_CMD_GET_MEMTABS_SIZE,
                                0,
                                &ui_proc_mem_tabs_size);
    ALOGV("return code of IA_API_CMD_GET_MEMTABS_SIZE: %d",err_code);
    mMemoryArray[mMallocCount] = memalign(4, ui_proc_mem_tabs_size);
    if (mMemoryArray[mMallocCount] == NULL) {
        ALOGE("Malloc for size (ui_proc_mem_tabs_size + 4) = %d failed!",ui_proc_mem_tabs_size + 4);
    }

    /* Set pointer for process memory tables    */
    err_code = ixheaacd_dec_api(mXheaacCodecHandle,
                                IA_API_CMD_SET_MEMTABS_PTR,
                                0,
                                (pVOID)((WORD8*)mMemoryArray[mMallocCount]));
    ALOGV("return code of IA_API_CMD_SET_MEMTABS_PTR: %d",err_code);
    mMallocCount++;

    /* initialize the API, post config, fill memory tables  */
    err_code = ixheaacd_dec_api(mXheaacCodecHandle,
                                IA_API_CMD_INIT,
                                IA_CMD_TYPE_INIT_API_POST_CONFIG_PARAMS,
                                NULL);
    ALOGV("return code of IA_CMD_TYPE_INIT_API_POST_CONFIG_PARAMS: %d",err_code);

    /* ******************************************************************/
    /* Allocate Memory with info from library                           */
    /* ******************************************************************/
    /* There are four different types of memories, that needs to be allocated */
    /* persistent,scratch,input and output */
    for(i = 0; i < 4; i++) {
        int ui_size = 0, ui_alignment = 0, ui_type = 0;
        pVOID pv_alloc_ptr;

        /* Get memory size */
        err_code = ixheaacd_dec_api(mXheaacCodecHandle,
                                    IA_API_CMD_GET_MEM_INFO_SIZE,
                                    i,
                                    &ui_size);
        ALOGV("return code of IA_API_CMD_GET_MEM_INFO_SIZE: %d",err_code);

        /* Get memory alignment */
        err_code = ixheaacd_dec_api(mXheaacCodecHandle,
                                    IA_API_CMD_GET_MEM_INFO_ALIGNMENT,
                                    i,
                                    &ui_alignment);
        ALOGV("return code of IA_API_CMD_GET_MEM_INFO_ALIGNMENT: %d",err_code);

        /* Get memory type */
        err_code = ixheaacd_dec_api(mXheaacCodecHandle,
                                    IA_API_CMD_GET_MEM_INFO_TYPE,
                                    i,
                                    &ui_type);
        ALOGV("return code of IA_API_CMD_GET_MEM_INFO_TYPE: %d",err_code);

        mMemoryArray[mMallocCount] =
            memalign(ui_alignment , ui_size);
        if (mMemoryArray[mMallocCount] == NULL) {
            ALOGE("Malloc for size (ui_size + ui_alignment) = %d failed!",ui_size + ui_alignment);
        }
        pv_alloc_ptr =
            (pVOID )((WORD8*)mMemoryArray[mMallocCount]);
        mMallocCount++;

        /* Set the buffer pointer */
        err_code = ixheaacd_dec_api(mXheaacCodecHandle,
                                    IA_API_CMD_SET_MEM_PTR,
                                    i,
                                    pv_alloc_ptr);
        ALOGV("return code of IA_API_CMD_SET_MEM_PTR: %d",err_code);
        if (ui_type == IA_MEMTYPE_INPUT) {
            mInputBuffer = (pWORD8)pv_alloc_ptr;
            mInputBufferSize = ui_size;

        }

        if (ui_type == IA_MEMTYPE_OUTPUT) {
            mOutputBuffer = (pWORD8)pv_alloc_ptr;
        }

    }
    /* End first part */

  return IA_NO_ERROR;
}

int SoftXAAC::configXAACDecoder(uint8_t* inBuffer, uint32_t inBufferLength) {

    UWORD32 ui_init_done;
    int32_t i_bytes_consumed;

    if (mInputBufferSize < inBufferLength) {
        ALOGE("Cannot config AAC, input buffer size %d < inBufferLength %d",mInputBufferSize,inBufferLength);
        return false;
    }

    /* Copy the buffer passed by Android plugin to codec input buffer */
    memcpy(mInputBuffer, inBuffer, inBufferLength);

    /* Set number of bytes to be processed */
    IA_ERRORCODE err_code = ixheaacd_dec_api(mXheaacCodecHandle,
                                             IA_API_CMD_SET_INPUT_BYTES,
                                             0,
                                             &inBufferLength);
    ALOGV("return code of IA_API_CMD_SET_INPUT_BYTES: %d",err_code);

    if (mIsCodecConfigFlushRequired) {
        /* If codec is already initialized, then GA header is passed again */
        /* Need to call the Flush API instead of INIT_PROCESS */
        mIsCodecInitialized = false; /* Codec needs to be Reinitialized after flush */
        err_code = ixheaacd_dec_api(mXheaacCodecHandle,
                                    IA_API_CMD_INIT,
                                    IA_CMD_TYPE_GA_HDR,
                                    NULL);
        ALOGV("return code of IA_CMD_TYPE_GA_HDR: %d",err_code);
    }
    else {
        /* Initialize the process */
        err_code = ixheaacd_dec_api(mXheaacCodecHandle,
                                    IA_API_CMD_INIT,
                                    IA_CMD_TYPE_INIT_PROCESS,
                                    NULL);
        ALOGV("return code of IA_CMD_TYPE_INIT_PROCESS: %d",err_code);
    }

    /* Checking for end of initialization */
    err_code = ixheaacd_dec_api(mXheaacCodecHandle,
                                IA_API_CMD_INIT,
                                IA_CMD_TYPE_INIT_DONE_QUERY,
                                &ui_init_done);
    ALOGV("return code of IA_CMD_TYPE_INIT_DONE_QUERY: %d",err_code);

    /* How much buffer is used in input buffers */
    err_code = ixheaacd_dec_api(mXheaacCodecHandle,
                                IA_API_CMD_GET_CURIDX_INPUT_BUF,
                                0,
                                &i_bytes_consumed);
    ALOGV("return code of IA_API_CMD_GET_CURIDX_INPUT_BUF: %d",err_code);

    if(ui_init_done){
        err_code = getXAACStreamInfo();
        ALOGI("Found Codec with below config---\nsampFreq %d\nnumChannels %d\npcmWdSz %d\nchannelMask %d\noutputFrameLength %d",
                                    mSampFreq,mNumChannels,mPcmWdSz,mChannelMask,mOutputFrameLength);
        mIsCodecInitialized = true;
    }

    return err_code;
}

int SoftXAAC::decodeXAACStream(uint8_t* inBuffer,
                               uint32_t inBufferLength,
                               int32_t *bytesConsumed,
                               int32_t *outBytes) {
    if (mInputBufferSize < inBufferLength) {
        ALOGE("Cannot config AAC, input buffer size %d < inBufferLength %d",mInputBufferSize,inBufferLength);
        return -1;
    }

    /* Copy the buffer passed by Android plugin to codec input buffer */
    memcpy(mInputBuffer,inBuffer,inBufferLength);

    /* Set number of bytes to be processed */
    IA_ERRORCODE err_code = ixheaacd_dec_api(mXheaacCodecHandle,
                                             IA_API_CMD_SET_INPUT_BYTES,
                                             0,
                                             &inBufferLength);
    ALOGV("return code of IA_API_CMD_SET_INPUT_BYTES: %d",err_code);

    /* Execute process */
    err_code = ixheaacd_dec_api(mXheaacCodecHandle,
                                IA_API_CMD_EXECUTE,
                                IA_CMD_TYPE_DO_EXECUTE,
                                NULL);
    ALOGV("return code of IA_CMD_TYPE_DO_EXECUTE: %d",err_code);

    UWORD32 ui_exec_done;
    /* Checking for end of processing */
    err_code = ixheaacd_dec_api(mXheaacCodecHandle,
                                IA_API_CMD_EXECUTE,
                                IA_CMD_TYPE_DONE_QUERY,
                                &ui_exec_done);
    ALOGV("return code of IA_CMD_TYPE_DONE_QUERY: %d",err_code);

    /* How much buffer is used in input buffers */
    err_code = ixheaacd_dec_api(mXheaacCodecHandle,
                                IA_API_CMD_GET_CURIDX_INPUT_BUF,
                                0,
                                bytesConsumed);
    ALOGV("return code of IA_API_CMD_GET_CURIDX_INPUT_BUF: %d",err_code);

    /* Get the output bytes */
    err_code = ixheaacd_dec_api(mXheaacCodecHandle,
                                IA_API_CMD_GET_OUTPUT_BYTES,
                                0,
                                outBytes);
    ALOGV("return code of IA_API_CMD_GET_OUTPUT_BYTES: %d",err_code);

    return err_code;
}

int SoftXAAC::deInitXAACDecoder() {
    ALOGI("deInitXAACDecoder");

    /* Tell that the input is over in this buffer */
    IA_ERRORCODE err_code = ixheaacd_dec_api(mXheaacCodecHandle,
                                             IA_API_CMD_INPUT_OVER,
                                             0,
                                             NULL);
    ALOGV("return code of IA_API_CMD_INPUT_OVER: %d",err_code);

    for(int i = 0; i < mMallocCount; i++)
    {
        if(mMemoryArray[i])
            free(mMemoryArray[i]);
    }
    mMallocCount = 0;

    return err_code;
}

IA_ERRORCODE SoftXAAC::getXAACStreamInfo() {
    IA_ERRORCODE err_code = IA_NO_ERROR;

    /* Sampling frequency */
    err_code = ixheaacd_dec_api(mXheaacCodecHandle,
                                IA_API_CMD_GET_CONFIG_PARAM,
                                IA_ENHAACPLUS_DEC_CONFIG_PARAM_SAMP_FREQ,
                                &mSampFreq);
    ALOGV("return code of IA_ENHAACPLUS_DEC_CONFIG_PARAM_SAMP_FREQ: %d",err_code);

    /* Total Number of Channels */
    err_code = ixheaacd_dec_api(mXheaacCodecHandle,
                                IA_API_CMD_GET_CONFIG_PARAM,
                                IA_ENHAACPLUS_DEC_CONFIG_PARAM_NUM_CHANNELS,
                                &mNumChannels);
    ALOGV("return code of IA_ENHAACPLUS_DEC_CONFIG_PARAM_NUM_CHANNELS: %d",err_code);

    /* PCM word size */
    err_code = ixheaacd_dec_api(mXheaacCodecHandle,
                                IA_API_CMD_GET_CONFIG_PARAM,
                                IA_ENHAACPLUS_DEC_CONFIG_PARAM_PCM_WDSZ,
                                &mPcmWdSz);
    ALOGV("return code of IA_ENHAACPLUS_DEC_CONFIG_PARAM_PCM_WDSZ: %d",err_code);

    /* channel mask to tell the arrangement of channels in bit stream */
    err_code = ixheaacd_dec_api(mXheaacCodecHandle,
                                IA_API_CMD_GET_CONFIG_PARAM,
                                IA_ENHAACPLUS_DEC_CONFIG_PARAM_CHANNEL_MASK,
                                &mChannelMask);
    ALOGV("return code of IA_ENHAACPLUS_DEC_CONFIG_PARAM_CHANNEL_MASK: %d",err_code);

    /* Channel mode to tell MONO/STEREO/DUAL-MONO/NONE_OF_THESE */
    UWORD32 ui_channel_mode;
    err_code = ixheaacd_dec_api(mXheaacCodecHandle,
                                IA_API_CMD_GET_CONFIG_PARAM,
                                IA_ENHAACPLUS_DEC_CONFIG_PARAM_CHANNEL_MODE,
                                &ui_channel_mode);
    ALOGV("return code of IA_ENHAACPLUS_DEC_CONFIG_PARAM_CHANNEL_MODE: %d",err_code);
    if(ui_channel_mode == 0)
        ALOGV("Channel Mode: MONO_OR_PS\n");
    else if(ui_channel_mode == 1)
        ALOGV("Channel Mode: STEREO\n");
    else if(ui_channel_mode == 2)
        ALOGV("Channel Mode: DUAL-MONO\n");
    else
        ALOGV("Channel Mode: NONE_OF_THESE or MULTICHANNEL\n");

    /* Channel mode to tell SBR PRESENT/NOT_PRESENT */
    UWORD32 ui_sbr_mode;
    err_code = ixheaacd_dec_api(mXheaacCodecHandle,
                                IA_API_CMD_GET_CONFIG_PARAM,
                                IA_ENHAACPLUS_DEC_CONFIG_PARAM_SBR_MODE,
                                &ui_sbr_mode);
    ALOGV("return code of IA_ENHAACPLUS_DEC_CONFIG_PARAM_SBR_MODE: %d",err_code);
    if(ui_sbr_mode == 0)
        ALOGV("SBR Mode: NOT_PRESENT\n");
    else if(ui_sbr_mode == 1)
        ALOGV("SBR Mode: PRESENT\n");
    else
        ALOGV("SBR Mode: ILLEGAL\n");

    /* mOutputFrameLength = 1024 * (1 + SBR_MODE) for AAC */
    /* For USAC it could be 1024 * 3 , support to query  */
    /* not yet added in codec                            */
    mOutputFrameLength = 1024 * (1 + ui_sbr_mode);

    ALOGI("mOutputFrameLength %d ui_sbr_mode %d",mOutputFrameLength,ui_sbr_mode);

    return IA_NO_ERROR;
}

IA_ERRORCODE SoftXAAC::setXAACDRCInfo(int32_t drcCut,
                                      int32_t drcBoost,
                                      int32_t drcRefLevel,
                                      int32_t drcHeavyCompression) {
    IA_ERRORCODE err_code = IA_NO_ERROR;

    int32_t ui_drc_enable = 1;
    err_code = ixheaacd_dec_api(mXheaacCodecHandle,
                                IA_API_CMD_SET_CONFIG_PARAM,
                                IA_ENHAACPLUS_DEC_CONFIG_PARAM_DRC_ENABLE,
                                &ui_drc_enable);
     ALOGV("return code of IA_ENHAACPLUS_DEC_CONFIG_PARAM_DRC_ENABLE: %d",err_code);
    if (drcCut !=-1) {
        ALOGI("set drcCut=%d", drcCut);
        err_code = ixheaacd_dec_api(mXheaacCodecHandle,
                                    IA_API_CMD_SET_CONFIG_PARAM,
                                    IA_ENHAACPLUS_DEC_CONFIG_PARAM_DRC_CUT,
                                    &drcCut);
         ALOGV("return code of IA_ENHAACPLUS_DEC_CONFIG_PARAM_DRC_CUT: %d",err_code);
    }

    if (drcBoost !=-1) {
        ALOGI("set drcBoost=%d", drcBoost);
        err_code = ixheaacd_dec_api(mXheaacCodecHandle,
                                    IA_API_CMD_SET_CONFIG_PARAM,
                                    IA_ENHAACPLUS_DEC_CONFIG_PARAM_DRC_BOOST,
                                    &drcBoost);
         ALOGV("return code of IA_ENHAACPLUS_DEC_CONFIG_PARAM_DRC_BOOST: %d",err_code);
    }

    if (drcRefLevel != -1) {
        ALOGI("set drcRefLevel=%d", drcRefLevel);
        err_code = ixheaacd_dec_api(mXheaacCodecHandle,
                                    IA_API_CMD_SET_CONFIG_PARAM,
                                    IA_ENHAACPLUS_DEC_CONFIG_PARAM_DRC_TARGET_LEVEL,
                                    &drcRefLevel);
         ALOGV("return code of IA_ENHAACPLUS_DEC_CONFIG_PARAM_DRC_TARGET_LEVEL: %d",err_code);
    }

    if (drcHeavyCompression != -1) {
        ALOGI("set drcHeavyCompression=%d", drcHeavyCompression);
        err_code = ixheaacd_dec_api(mXheaacCodecHandle,
                                    IA_API_CMD_SET_CONFIG_PARAM,
                                    IA_ENHAACPLUS_DEC_CONFIG_PARAM_DRC_HEAVY_COMP,
                                    &drcHeavyCompression);
         ALOGV("return code of IA_ENHAACPLUS_DEC_CONFIG_PARAM_DRC_HEAVY_COMP: %d",err_code);
    }

    return IA_NO_ERROR;
}

}  // namespace android

android::SoftOMXComponent *createSoftOMXComponent(
        const char *name, const OMX_CALLBACKTYPE *callbacks,
        OMX_PTR appData, OMX_COMPONENTTYPE **component) {
    ALOGI("createSoftOMXComponent for SoftXAACDEC");
    return new android::SoftXAAC(name, callbacks, appData, component);
}
