/*
 * Copyright (C) 2017 The Android Open Source Project
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

#define LOG_TAG "CameraLatencyHistogram"
#include <inttypes.h>
#include <android-base/stringprintf.h>
#include <utils/Log.h>
#include <camera/StringUtils.h>

#include "LatencyHistogram.h"

namespace android {

CameraLatencyHistogram::CameraLatencyHistogram(int32_t binSizeMs, int32_t binCount) :
        mBinSizeMs(binSizeMs),
        mBinCount(binCount),
        mBins(binCount),
        mTotalCount(0) {
}

void CameraLatencyHistogram::add(nsecs_t start, nsecs_t end) {
    nsecs_t duration = end - start;
    int32_t durationMs = static_cast<int32_t>(duration / 1000000LL);
    int32_t binIndex = durationMs / mBinSizeMs;

    if (binIndex < 0) {
        binIndex = 0;
    } else if (binIndex >= mBinCount) {
        binIndex = mBinCount-1;
    }

    mBins[binIndex]++;
    mTotalCount++;
}

void CameraLatencyHistogram::reset() {
    memset(mBins.data(), 0, mBins.size() * sizeof(int64_t));
    mTotalCount = 0;
}

void CameraLatencyHistogram::dump(int fd, const char* name) const {
    if (mTotalCount == 0) {
        return;
    }

    std::string lines;
    lines += fmt::sprintf("%s (%" PRId64 ") samples\n", name, mTotalCount);

    std::string lineBins, lineBinCounts;
    formatHistogramText(lineBins, lineBinCounts);

    lineBins += ("\n");
    lineBinCounts += ("\n");
    lines += lineBins;
    lines += lineBinCounts;

    write(fd, lines.c_str(), lines.size());
}

void CameraLatencyHistogram::log(const char* fmt, ...) {
    if (mTotalCount == 0) {
        return;
    }

    va_list args;
    va_start(args, fmt);
    std::string histogramName;
    base::StringAppendV(&histogramName, fmt, args);
    ALOGI("%s (%" PRId64 ") samples:", histogramName.c_str(), mTotalCount);
    va_end(args);

    std::string lineBins, lineBinCounts;
    formatHistogramText(lineBins, lineBinCounts);

    ALOGI("%s", lineBins.c_str());
    ALOGI("%s", lineBinCounts.c_str());
}

void CameraLatencyHistogram::formatHistogramText(
        std::string& lineBins, std::string& lineBinCounts) const {
    lineBins = "  ";
    lineBinCounts = "  ";

    for (int32_t i = 0; i < mBinCount; i++) {
        if (i == mBinCount - 1) {
            lineBins += "    inf (max ms)";
        } else {
            lineBins += fmt::sprintf("%7d", mBinSizeMs*(i+1));
        }
        lineBinCounts += fmt::sprintf("   %02.2f", 100.0*mBins[i]/mTotalCount);
    }
    lineBinCounts += " (%)";
}

}; //namespace android
