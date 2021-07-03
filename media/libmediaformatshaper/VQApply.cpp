/*
 * Copyright (C) 2021 The Android Open Source Project
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
#define LOG_TAG "VQApply"
#include <utils/Log.h>

#include <string>
#include <inttypes.h>

#include <media/NdkMediaFormat.h>

#include "VQops.h"
#include "CodecProperties.h"
#include "VideoShaper.h"

namespace android {
namespace mediaformatshaper {


// these are all NDK#31 and we run as NDK#29 (to be within the module)
// the __builtin_available(android 31, *) constructs didn't work for me.
//
#define	AMEDIAFORMAT_VIDEO_QP_MAX	"video-qp-max"
#define	AMEDIAFORMAT_VIDEO_QP_MIN	"video-qp-min"

#define	AMEDIAFORMAT_VIDEO_QP_B_MAX	"video-qp-b-max"
#define	AMEDIAFORMAT_VIDEO_QP_B_MIN	"video-qp-b-min"
#define	AMEDIAFORMAT_VIDEO_QP_I_MAX	"video-qp-i-max"
#define	AMEDIAFORMAT_VIDEO_QP_I_MIN	"video-qp-i-min"
#define	AMEDIAFORMAT_VIDEO_QP_P_MAX	"video-qp-p-max"
#define	AMEDIAFORMAT_VIDEO_QP_P_MIN	"video-qp-p-min"

// defined in the SDK, but not in the NDK
//
static const int BITRATE_MODE_VBR = 1;


//
// Caller retains ownership of and responsibility for inFormat
//
int VQApply(CodecProperties *codec, vqOps_t *info, AMediaFormat* inFormat, int flags) {
    ALOGV("codecName %s inFormat %p flags x%x", codec->getName().c_str(), inFormat, flags);
    (void) info; // unused for now

    int32_t bitRateMode = -1;
    if (AMediaFormat_getInt32(inFormat, AMEDIAFORMAT_KEY_BITRATE_MODE, &bitRateMode)
        && bitRateMode != BITRATE_MODE_VBR) {
        ALOGD("minquality: applies only to VBR encoding");
        return 0;
    }

    // only proceed if we're in the handheld category.
    // We embed this information within the codec record when we build up features
    // and pass them in from MediaCodec; it's the easiest place to store it
    //
    // TODO: make a #define for ' _vq_eligible.device' here and in MediaCodec.cpp
    //
    int32_t isVQEligible = 0;
    (void) codec->getFeatureValue("_vq_eligible.device", &isVQEligible);
    if (!isVQEligible) {
        ALOGD("minquality: not an eligible device class");
        return 0;
    }

    // look at resolution to determine if we want any shaping/modification at all.
    //
    // we currently only shape (or ask the underlying codec to shape) for
    // resolution range  320x240 < target <= 1920x1080
    // NB: the < vs <=, that is deliberate.
    //

    int32_t width = 0;
    (void) AMediaFormat_getInt32(inFormat, AMEDIAFORMAT_KEY_WIDTH, &width);
    int32_t height = 0;
    (void) AMediaFormat_getInt32(inFormat, AMEDIAFORMAT_KEY_HEIGHT, &height);
    int64_t pixels = ((int64_t)width) * height;

    bool eligibleSize = true;
    if (pixels <= 320 * 240) {
        eligibleSize = false;
    } else if (pixels > 1920 * 1088) {
        eligibleSize = false;
    }

    if (!eligibleSize) {
        // we won't shape, and ask that the codec not shape
        ALOGD("minquality: %dx%d outside of shaping range", width, height);
        AMediaFormat_setInt32(inFormat, "android._encoding-quality-level", 0);
        return 0;
    }

    if (codec->supportedMinimumQuality() > 0) {
        // have the codec-provided minimum quality behavior to work at it
        ALOGD("minquality: codec claims to implement minquality=%d",
              codec->supportedMinimumQuality());

        // tell the underlying codec to do its thing; we won't try to second guess.
        // default to 1, aka S_HANDHELD;
        int32_t qualityTarget = 1;
        (void) codec->getFeatureValue("_quality.target", &qualityTarget);
        AMediaFormat_setInt32(inFormat, "android._encoding-quality-level", qualityTarget);
        return 0;
    }

    // let the codec know that we'll be enforcing the minimum quality standards
    AMediaFormat_setInt32(inFormat, "android._encoding-quality-level", 0);

    //
    // consider any and all tools available
    // -- qp
    // -- minimum bits-per-pixel
    //
    int64_t bitrateChosen = 0;
    int32_t qpChosen = INT32_MAX;

    int64_t bitrateConfigured = 0;
    int32_t bitrateConfiguredTmp = 0;
    (void) AMediaFormat_getInt32(inFormat, AMEDIAFORMAT_KEY_BIT_RATE, &bitrateConfiguredTmp);
    bitrateConfigured = bitrateConfiguredTmp;
    bitrateChosen = bitrateConfigured;

    // width, height, and pixels are calculated above

    double minimumBpp = codec->getBpp(width, height);

    int64_t bitrateFloor = pixels * minimumBpp;
    int64_t bitrateCeiling = bitrateFloor * codec->getPhaseOut();
    if (bitrateFloor > INT32_MAX) bitrateFloor = INT32_MAX;
    if (bitrateCeiling > INT32_MAX) bitrateCeiling = INT32_MAX;

    // if we are far enough above the target bpp, leave it alone
    //
    ALOGV("bitrate: configured %" PRId64 " floor %" PRId64, bitrateConfigured, bitrateFloor);
    if (bitrateConfigured >= bitrateCeiling) {
        ALOGV("high enough bitrate: configured %" PRId64 " >= ceiling %" PRId64,
                bitrateConfigured, bitrateCeiling);
        return 0;
    }

    // raise anything below the bitrate floor
    if (bitrateConfigured < bitrateFloor) {
        ALOGD("raise bitrate: configured %" PRId64 " to floor %" PRId64,
                bitrateConfigured, bitrateFloor);
        bitrateChosen = bitrateFloor;
    }

    bool qpPresent = hasQpMax(inFormat);

    // calculate a target QP value
    int32_t qpmax = codec->targetQpMax(width, height);
    if (!qpPresent) {
        // user didn't, so shaper wins
        if (qpmax != INT32_MAX) {
            ALOGV("choosing qp=%d", qpmax);
            qpChosen = qpmax;
        }
    } else if (qpmax == INT32_MAX) {
        // shaper didn't so user wins
        qpChosen = INT32_MAX;
        AMediaFormat_getInt32(inFormat, AMEDIAFORMAT_VIDEO_QP_MAX, &qpChosen);
    } else {
        // both sides want it, choose most restrictive
        int32_t value = INT32_MAX;
        AMediaFormat_getInt32(inFormat, AMEDIAFORMAT_VIDEO_QP_MAX, &value);
        qpChosen = std::min(qpmax, value);
    }

    // if QP is desired but not supported, compensate with additional bits
    if (!codec->supportsQp()) {
        if (qpChosen != INT32_MAX) {
            int64_t boost = bitrateChosen * codec->getMissingQpBoost();
            ALOGD("minquality: requested QP unsupported, boost bitrate %" PRId64 " by %" PRId64,
                bitrateChosen, boost);
            bitrateChosen =  bitrateChosen + boost;
            qpChosen = INT32_MAX;
        }
    }

    // limits
    // apply our chosen values
    //
    if (qpChosen != INT32_MAX) {
        ALOGD("minquality by QP: inject %s=%d", AMEDIAFORMAT_VIDEO_QP_MAX, qpChosen);
        AMediaFormat_setInt32(inFormat, AMEDIAFORMAT_VIDEO_QP_MAX, qpChosen);

        // caller (VideoShaper) handles spreading this across the subframes
    }

    if (bitrateChosen != bitrateConfigured) {
        if (bitrateChosen > bitrateCeiling) {
            ALOGD("minquality: bitrate increase clamped at ceiling %" PRId64,  bitrateCeiling);
            bitrateChosen = bitrateCeiling;
        }
        ALOGD("minquality/target bitrate raised from %" PRId64 " to %" PRId64 " bps",
              bitrateConfigured, bitrateChosen);
        AMediaFormat_setInt32(inFormat, AMEDIAFORMAT_KEY_BIT_RATE, (int32_t)bitrateChosen);
    }

    return 0;
}


bool hasQpMaxPerFrameType(AMediaFormat *format) {
    int32_t value;

    if (AMediaFormat_getInt32(format, AMEDIAFORMAT_VIDEO_QP_I_MAX, &value)
        || AMediaFormat_getInt32(format, AMEDIAFORMAT_VIDEO_QP_I_MIN, &value)) {
        return true;
    }
    if (AMediaFormat_getInt32(format, AMEDIAFORMAT_VIDEO_QP_P_MAX, &value)
        || AMediaFormat_getInt32(format, AMEDIAFORMAT_VIDEO_QP_P_MIN, &value)) {
        return true;
    }
    if (AMediaFormat_getInt32(format, AMEDIAFORMAT_VIDEO_QP_B_MAX, &value)
        || AMediaFormat_getInt32(format, AMEDIAFORMAT_VIDEO_QP_B_MIN, &value)) {
        return true;
    }
    return false;
}

bool hasQpMaxGlobal(AMediaFormat *format) {
    int32_t value;
    if (AMediaFormat_getInt32(format, AMEDIAFORMAT_VIDEO_QP_MAX, &value)
        || AMediaFormat_getInt32(format, AMEDIAFORMAT_VIDEO_QP_MIN, &value)) {
        return true;
    }
    return false;
}

bool hasQpMax(AMediaFormat *format) {
    if (hasQpMaxGlobal(format)) {
        return true;
    }
    return hasQpMaxPerFrameType(format);
}

void qpSpreadPerFrameType(AMediaFormat *format, int delta,
                           int qplow, int qphigh, bool override) {

     qpSpreadMinPerFrameType(format, qplow, override);
     qpSpreadMaxPerFrameType(format, delta, qphigh, override);
     // make sure that min<max for all the QP fields.
     qpVerifyMinMaxOrdering(format);
}

void qpSpreadMaxPerFrameType(AMediaFormat *format, int delta, int qphigh, bool override) {
    ALOGV("format %p delta %d  hi %d override %d", format, delta, qphigh, override);

    int32_t qpOffered = 0;
    if (AMediaFormat_getInt32(format, AMEDIAFORMAT_VIDEO_QP_MAX, &qpOffered)) {
        // propagate to frame-specific keys, choosing most restrictive
        // ensure that we don't violate min<=max rules
        {
            int32_t maxI = INT32_MAX;
            AMediaFormat_getInt32(format, AMEDIAFORMAT_VIDEO_QP_I_MAX, &maxI);
            int32_t value = std::min({qpOffered, qphigh, maxI});
            AMediaFormat_setInt32(format, AMEDIAFORMAT_VIDEO_QP_I_MAX, value);
        }
        {
            int32_t maxP = INT32_MAX;
            AMediaFormat_getInt32(format, AMEDIAFORMAT_VIDEO_QP_P_MAX, &maxP);
            int32_t value = std::min({(std::min(qpOffered, INT32_MAX-1*delta) + 1*delta),
                                     qphigh, maxP});
            AMediaFormat_setInt32(format, AMEDIAFORMAT_VIDEO_QP_P_MAX, value);
        }
        {
            int32_t maxB = INT32_MAX;
            AMediaFormat_getInt32(format, AMEDIAFORMAT_VIDEO_QP_B_MAX, &maxB);
            int32_t value = std::min({(std::min(qpOffered, INT32_MAX-2*delta) + 2*delta),
                                     qphigh, maxB});
            AMediaFormat_setInt32(format, AMEDIAFORMAT_VIDEO_QP_B_MAX, value);
        }
    }
}

void qpSpreadMinPerFrameType(AMediaFormat *format, int qplow, bool override) {
    ALOGV("format %p lo %d override %d", format, qplow, override);

    int32_t qpOffered = 0;
    if (AMediaFormat_getInt32(format, AMEDIAFORMAT_VIDEO_QP_MIN, &qpOffered)) {
        int value = std::max(qplow, qpOffered);
        // propagate to frame-specific keys, use lowest of this and existing per-frame value
        int32_t minI = INT32_MAX;
        AMediaFormat_getInt32(format, AMEDIAFORMAT_VIDEO_QP_I_MIN, &minI);
        int32_t setI = std::min(value, minI);
        AMediaFormat_setInt32(format, AMEDIAFORMAT_VIDEO_QP_I_MIN, setI);

        int32_t minP = INT32_MAX;
        AMediaFormat_getInt32(format, AMEDIAFORMAT_VIDEO_QP_P_MIN, &minP);
        int32_t setP = std::min(value, minP);
        AMediaFormat_setInt32(format, AMEDIAFORMAT_VIDEO_QP_P_MIN, setP);

        int32_t minB = INT32_MAX;
        AMediaFormat_getInt32(format, AMEDIAFORMAT_VIDEO_QP_B_MIN, &minB);
        int32_t setB = std::min(value, minB);
        AMediaFormat_setInt32(format, AMEDIAFORMAT_VIDEO_QP_B_MIN, setB);
    }
}

// XXX whether we allow min==max, or if we'll insist that min<max
void qpVerifyMinMaxOrdering(AMediaFormat *format) {
    // ensure that we don't violate min<=max rules
    int32_t maxI = INT32_MAX;
    int32_t minI = INT32_MIN;
    if (AMediaFormat_getInt32(format, AMEDIAFORMAT_VIDEO_QP_I_MAX, &maxI)
        && AMediaFormat_getInt32(format, AMEDIAFORMAT_VIDEO_QP_I_MIN, &minI)
        && minI > maxI) {
        AMediaFormat_setInt32(format, AMEDIAFORMAT_VIDEO_QP_I_MIN, maxI);
    }
    int32_t maxP = INT32_MAX;
    int32_t minP = INT32_MIN;
    if (AMediaFormat_getInt32(format, AMEDIAFORMAT_VIDEO_QP_P_MAX, &maxP)
        && AMediaFormat_getInt32(format, AMEDIAFORMAT_VIDEO_QP_P_MIN, &minP)
        && minP > maxP) {
        AMediaFormat_setInt32(format, AMEDIAFORMAT_VIDEO_QP_P_MIN, maxP);
    }
    int32_t maxB = INT32_MAX;
    int32_t minB = INT32_MIN;
    if (AMediaFormat_getInt32(format, AMEDIAFORMAT_VIDEO_QP_B_MAX, &maxB)
        && AMediaFormat_getInt32(format, AMEDIAFORMAT_VIDEO_QP_B_MIN, &minB)
        && minB > maxB) {
        AMediaFormat_setInt32(format, AMEDIAFORMAT_VIDEO_QP_B_MIN, maxB);
    }
}

}  // namespace mediaformatshaper
}  // namespace android

