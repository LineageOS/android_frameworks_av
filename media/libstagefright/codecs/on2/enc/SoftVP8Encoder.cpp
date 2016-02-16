/*
 * Copyright (C) 2016 The Android Open Source Project
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

// #define LOG_NDEBUG 0
#define LOG_TAG "SoftVP8Encoder"
#include "SoftVP8Encoder.h"

#include <utils/Log.h>
#include <utils/misc.h>

#include <media/hardware/HardwareAPI.h>
#include <media/hardware/MetadataBufferType.h>
#include <media/stagefright/foundation/ADebug.h>
#include <media/stagefright/MediaDefs.h>

#ifndef INT32_MAX
#define INT32_MAX   2147483647
#endif

namespace android {

static const CodecProfileLevel kVp8ProfileLevels[] = {
    { OMX_VIDEO_VP8ProfileMain, OMX_VIDEO_VP8Level_Version0 },
    { OMX_VIDEO_VP8ProfileMain, OMX_VIDEO_VP8Level_Version1 },
    { OMX_VIDEO_VP8ProfileMain, OMX_VIDEO_VP8Level_Version2 },
    { OMX_VIDEO_VP8ProfileMain, OMX_VIDEO_VP8Level_Version3 },
};

SoftVP8Encoder::SoftVP8Encoder(const char *name,
                               const OMX_CALLBACKTYPE *callbacks,
                               OMX_PTR appData,
                               OMX_COMPONENTTYPE **component)
    : SoftVPXEncoder(
            name, callbacks, appData, component, "video_encoder.vp8",
            OMX_VIDEO_CodingVP8, MEDIA_MIMETYPE_VIDEO_VP8, 2,
            kVp8ProfileLevels, NELEM(kVp8ProfileLevels)),
      mDCTPartitions(0) {
}

void SoftVP8Encoder::setCodecSpecificInterface() {
    mCodecInterface = vpx_codec_vp8_cx();
}

vpx_codec_err_t SoftVP8Encoder::setCodecSpecificControls() {
    vpx_codec_err_t codec_return = vpx_codec_control(mCodecContext,
                                                     VP8E_SET_TOKEN_PARTITIONS,
                                                     mDCTPartitions);
    if (codec_return != VPX_CODEC_OK) {
        ALOGE("Error setting dct partitions for vpx encoder.");
    }
    return codec_return;
}

OMX_ERRORTYPE SoftVP8Encoder::internalGetParameter(OMX_INDEXTYPE index,
                                                   OMX_PTR param) {
    // can include extension index OMX_INDEXEXTTYPE
    const int32_t indexFull = index;

    switch (indexFull) {
        case OMX_IndexParamVideoVp8:
            return internalGetVp8Params(
                (OMX_VIDEO_PARAM_VP8TYPE *)param);

        case OMX_IndexParamVideoAndroidVp8Encoder:
            return internalGetAndroidVp8Params(
                (OMX_VIDEO_PARAM_ANDROID_VP8ENCODERTYPE *)param);

        default:
            return SoftVPXEncoder::internalGetParameter(index, param);
    }
}

OMX_ERRORTYPE SoftVP8Encoder::internalSetParameter(OMX_INDEXTYPE index,
                                                   const OMX_PTR param) {
    // can include extension index OMX_INDEXEXTTYPE
    const int32_t indexFull = index;

    switch (indexFull) {
        case OMX_IndexParamVideoVp8:
            return internalSetVp8Params(
                (const OMX_VIDEO_PARAM_VP8TYPE *)param);

        case OMX_IndexParamVideoAndroidVp8Encoder:
            return internalSetAndroidVp8Params(
                (const OMX_VIDEO_PARAM_ANDROID_VP8ENCODERTYPE *)param);

        default:
            return SoftVPXEncoder::internalSetParameter(index, param);
    }
}

OMX_ERRORTYPE SoftVP8Encoder::internalGetVp8Params(
        OMX_VIDEO_PARAM_VP8TYPE* vp8Params) {
    if (vp8Params->nPortIndex != kOutputPortIndex) {
        return OMX_ErrorUnsupportedIndex;
    }

    vp8Params->eProfile = OMX_VIDEO_VP8ProfileMain;
    vp8Params->eLevel = mLevel;
    vp8Params->bErrorResilientMode = mErrorResilience;
    vp8Params->nDCTPartitions = mDCTPartitions;
    return OMX_ErrorNone;
}

OMX_ERRORTYPE SoftVP8Encoder::internalSetVp8Params(
        const OMX_VIDEO_PARAM_VP8TYPE* vp8Params) {
    if (vp8Params->nPortIndex != kOutputPortIndex) {
        return OMX_ErrorUnsupportedIndex;
    }

    if (vp8Params->eProfile != OMX_VIDEO_VP8ProfileMain) {
        return OMX_ErrorBadParameter;
    }

    if (vp8Params->eLevel == OMX_VIDEO_VP8Level_Version0 ||
        vp8Params->eLevel == OMX_VIDEO_VP8Level_Version1 ||
        vp8Params->eLevel == OMX_VIDEO_VP8Level_Version2 ||
        vp8Params->eLevel == OMX_VIDEO_VP8Level_Version3) {
        mLevel = vp8Params->eLevel;
    } else {
        return OMX_ErrorBadParameter;
    }

    mErrorResilience = vp8Params->bErrorResilientMode;
    if (vp8Params->nDCTPartitions <= kMaxDCTPartitions) {
        mDCTPartitions = vp8Params->nDCTPartitions;
    } else {
        return OMX_ErrorBadParameter;
    }
    return OMX_ErrorNone;
}

OMX_ERRORTYPE SoftVP8Encoder::internalGetAndroidVp8Params(
        OMX_VIDEO_PARAM_ANDROID_VP8ENCODERTYPE* vp8AndroidParams) {
    if (vp8AndroidParams->nPortIndex != kOutputPortIndex) {
        return OMX_ErrorUnsupportedIndex;
    }

    vp8AndroidParams->nKeyFrameInterval = mKeyFrameInterval;
    vp8AndroidParams->eTemporalPattern = mTemporalPatternType;
    vp8AndroidParams->nTemporalLayerCount = mTemporalLayers;
    vp8AndroidParams->nMinQuantizer = mMinQuantizer;
    vp8AndroidParams->nMaxQuantizer = mMaxQuantizer;
    memcpy(vp8AndroidParams->nTemporalLayerBitrateRatio,
           mTemporalLayerBitrateRatio, sizeof(mTemporalLayerBitrateRatio));
    return OMX_ErrorNone;
}

OMX_ERRORTYPE SoftVP8Encoder::internalSetAndroidVp8Params(
        const OMX_VIDEO_PARAM_ANDROID_VP8ENCODERTYPE* vp8AndroidParams) {
    if (vp8AndroidParams->nPortIndex != kOutputPortIndex) {
        return OMX_ErrorUnsupportedIndex;
    }
    if (vp8AndroidParams->eTemporalPattern != OMX_VIDEO_VPXTemporalLayerPatternNone &&
        vp8AndroidParams->eTemporalPattern != OMX_VIDEO_VPXTemporalLayerPatternWebRTC) {
        return OMX_ErrorBadParameter;
    }
    if (vp8AndroidParams->nTemporalLayerCount > OMX_VIDEO_ANDROID_MAXVP8TEMPORALLAYERS) {
        return OMX_ErrorBadParameter;
    }
    if (vp8AndroidParams->nMinQuantizer > vp8AndroidParams->nMaxQuantizer) {
        return OMX_ErrorBadParameter;
    }

    mTemporalPatternType = vp8AndroidParams->eTemporalPattern;
    if (vp8AndroidParams->eTemporalPattern == OMX_VIDEO_VPXTemporalLayerPatternWebRTC) {
        mTemporalLayers = vp8AndroidParams->nTemporalLayerCount;
    } else if (vp8AndroidParams->eTemporalPattern == OMX_VIDEO_VPXTemporalLayerPatternNone) {
        mTemporalLayers = 0;
    }
    // Check the bitrate distribution between layers is in increasing order
    if (mTemporalLayers > 1) {
        for (size_t i = 0; i < mTemporalLayers - 1; i++) {
            if (vp8AndroidParams->nTemporalLayerBitrateRatio[i + 1] <=
                    vp8AndroidParams->nTemporalLayerBitrateRatio[i]) {
                ALOGE("Wrong bitrate ratio - should be in increasing order.");
                return OMX_ErrorBadParameter;
            }
        }
    }
    mKeyFrameInterval = vp8AndroidParams->nKeyFrameInterval;
    mMinQuantizer = vp8AndroidParams->nMinQuantizer;
    mMaxQuantizer = vp8AndroidParams->nMaxQuantizer;
    memcpy(mTemporalLayerBitrateRatio, vp8AndroidParams->nTemporalLayerBitrateRatio,
            sizeof(mTemporalLayerBitrateRatio));
    ALOGD("VPx: internalSetAndroidVp8Params. BRMode: %u. TS: %zu. KF: %u."
          " QP: %u - %u BR0: %u. BR1: %u. BR2: %u",
          (uint32_t)mBitrateControlMode, mTemporalLayers, mKeyFrameInterval,
          mMinQuantizer, mMaxQuantizer, mTemporalLayerBitrateRatio[0],
          mTemporalLayerBitrateRatio[1], mTemporalLayerBitrateRatio[2]);
    return OMX_ErrorNone;
}

}  // namespace android
