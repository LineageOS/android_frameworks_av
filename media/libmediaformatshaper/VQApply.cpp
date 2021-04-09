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

#include <media/formatshaper/VQops.h>
#include <media/formatshaper/CodecProperties.h>
#include <media/formatshaper/VideoShaper.h>

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


// constants we use within the calculations
//
constexpr double BITRATE_LEAVE_UNTOUCHED = 2.0;
constexpr double BITRATE_QP_UNAVAILABLE = 1.20;
// 10% didn't work so hot on bonito (with no QP support)
// 15% is next.. still leaves a few short
// 20% ? this is on the edge of what I want do do

//
// Caller retains ownership of and responsibility for inFormat
//
int VQApply(CodecProperties *codec, vqOps_t *info, AMediaFormat* inFormat, int flags) {
    ALOGV("codecName %s inFormat %p flags x%x", codec->getName().c_str(), inFormat, flags);

    int32_t bitRateMode = -1;
    if (AMediaFormat_getInt32(inFormat, AMEDIAFORMAT_KEY_BITRATE_MODE, &bitRateMode)
        && bitRateMode != BITRATE_MODE_VBR) {
        ALOGD("minquality: applies only to VBR encoding");
        return 0;
    }

    if (codec->supportedMinimumQuality() > 0) {
        // allow the codec provided minimum quality behavior to work at it
        ALOGD("minquality: codec claims to implement minquality=%d",
              codec->supportedMinimumQuality());
        return 0;
    }

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

    int32_t width = 0;
    (void) AMediaFormat_getInt32(inFormat, AMEDIAFORMAT_KEY_WIDTH, &width);
    int32_t height = 0;
    (void) AMediaFormat_getInt32(inFormat, AMEDIAFORMAT_KEY_HEIGHT, &height);
    int64_t pixels = ((int64_t)width) * height;
    double minimumBpp = codec->getBpp(width, height);

    int64_t bitrateFloor = pixels * minimumBpp;
    if (bitrateFloor > INT32_MAX) bitrateFloor = INT32_MAX;

    // if we are far enough above the target bpp, leave it alone
    //
    ALOGV("bitrate: configured %" PRId64 " floor %" PRId64, bitrateConfigured, bitrateFloor);
    if (bitrateConfigured >= BITRATE_LEAVE_UNTOUCHED * bitrateFloor) {
        ALOGV("high enough bitrate: configured %" PRId64 " >= %f * floor %" PRId64,
                bitrateConfigured, BITRATE_LEAVE_UNTOUCHED, bitrateFloor);
        return 0;
    }

    // raise anything below the bitrate floor
    if (bitrateConfigured < bitrateFloor) {
        ALOGD("raise bitrate: configured %" PRId64 " to floor %" PRId64,
                bitrateConfigured, bitrateFloor);
        bitrateChosen = bitrateFloor;
    }

    bool qpPresent = hasQp(inFormat);

    // add QP, if not already present
    if (!qpPresent) {
        int32_t qpmax = codec->targetQpMax();
        if (qpmax != INT32_MAX) {
            ALOGV("choosing qp=%d", qpmax);
            qpChosen = qpmax;
        }
    }

    // if QP is desired but not supported, compensate with additional bits
    if (!codec->supportsQp()) {
        if (qpPresent || qpChosen != INT32_MAX) {
            ALOGD("minquality: desired QP, but unsupported, boost bitrate %" PRId64 " to %" PRId64,
                bitrateChosen, (int64_t)(bitrateChosen * BITRATE_QP_UNAVAILABLE));
            bitrateChosen =  bitrateChosen * BITRATE_QP_UNAVAILABLE;
            qpChosen = INT32_MAX;
        }
    }

    // apply our chosen values
    //
    if (qpChosen != INT32_MAX) {
        ALOGD("minquality by QP: inject %s=%d", AMEDIAFORMAT_VIDEO_QP_MAX, qpChosen);
        AMediaFormat_setInt32(inFormat, AMEDIAFORMAT_VIDEO_QP_MAX, qpChosen);

        // force spreading the QP across frame types, since we are imposing a value
        qpSpreadMaxPerFrameType(inFormat, info->qpDelta, info->qpMax, /* override */ true);
    }

    if (bitrateChosen != bitrateConfigured) {
        ALOGD("minquality/target bitrate raised from %" PRId64 " to %" PRId64 " bps",
              bitrateConfigured, bitrateChosen);
        AMediaFormat_setInt32(inFormat, AMEDIAFORMAT_KEY_BIT_RATE, (int32_t)bitrateChosen);
    }

    return 0;
}


bool hasQpPerFrameType(AMediaFormat *format) {
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

bool hasQp(AMediaFormat *format) {
    int32_t value;
    if (AMediaFormat_getInt32(format, AMEDIAFORMAT_VIDEO_QP_MAX, &value)
        || AMediaFormat_getInt32(format, AMEDIAFORMAT_VIDEO_QP_MIN, &value)) {
        return true;
    }
    return hasQpPerFrameType(format);
}

void qpSpreadPerFrameType(AMediaFormat *format, int delta,
                           int qplow, int qphigh, bool override) {
     qpSpreadMaxPerFrameType(format, delta, qphigh, override);
     qpSpreadMinPerFrameType(format, qplow, override);
}

void qpSpreadMaxPerFrameType(AMediaFormat *format, int delta, int qphigh, bool override) {
    ALOGV("format %p delta %d  hi %d override %d", format, delta, qphigh, override);

    int32_t qpOffered = 0;
    if (AMediaFormat_getInt32(format, AMEDIAFORMAT_VIDEO_QP_MAX, &qpOffered)) {
        // propagate to otherwise unspecified frame-specific keys
        int32_t maxI;
        if (override || !AMediaFormat_getInt32(format, AMEDIAFORMAT_VIDEO_QP_I_MAX, &maxI)) {
            int32_t value = std::min(qphigh, qpOffered);
            AMediaFormat_setInt32(format, AMEDIAFORMAT_VIDEO_QP_I_MAX, value);
        }
        int32_t maxP;
        if (override || !AMediaFormat_getInt32(format, AMEDIAFORMAT_VIDEO_QP_P_MAX, &maxP)) {
            int32_t value = std::min(qphigh, (std::min(qpOffered, INT32_MAX-delta) + delta));
            AMediaFormat_setInt32(format, AMEDIAFORMAT_VIDEO_QP_P_MAX, value);
        }
        int32_t maxB;
        if (override || !AMediaFormat_getInt32(format, AMEDIAFORMAT_VIDEO_QP_B_MAX, &maxB)) {
            int32_t value = std::min(qphigh, (std::min(qpOffered, INT32_MAX-2*delta) + 2*delta));
            AMediaFormat_setInt32(format, AMEDIAFORMAT_VIDEO_QP_B_MAX, value);
        }
    }
}

void qpSpreadMinPerFrameType(AMediaFormat *format, int qplow, bool override) {
    ALOGV("format %p lo %d override %d", format, qplow, override);

    int32_t qpOffered = 0;
    if (AMediaFormat_getInt32(format, AMEDIAFORMAT_VIDEO_QP_MIN, &qpOffered)) {
        int value = std::max(qplow, qpOffered);
        // propagate to otherwise unspecified frame-specific keys
        int32_t minI;
        if (!AMediaFormat_getInt32(format, AMEDIAFORMAT_VIDEO_QP_I_MIN, &minI)) {
            AMediaFormat_setInt32(format, AMEDIAFORMAT_VIDEO_QP_I_MIN, value);
        }
        int32_t minP;
        if (!AMediaFormat_getInt32(format, AMEDIAFORMAT_VIDEO_QP_P_MIN, &minP)) {
            AMediaFormat_setInt32(format, AMEDIAFORMAT_VIDEO_QP_P_MIN, value);
        }
        int32_t minB;
        if (!AMediaFormat_getInt32(format, AMEDIAFORMAT_VIDEO_QP_B_MIN, &minB)) {
            AMediaFormat_setInt32(format, AMEDIAFORMAT_VIDEO_QP_B_MIN, value);
        }
    }
}

}  // namespace mediaformatshaper
}  // namespace android

