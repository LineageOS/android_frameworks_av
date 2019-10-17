/*
 * Copyright (C) 2019 The Android Open Source Project
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
#define LOG_TAG "Stats"

#include <iostream>
#include <stdint.h>

#include "Stats.h"

/**
 * Dumps the stats of the operation for a given input media.
 *
 * \param operation      describes the operation performed on the input media
 *                       (i.e. extract/mux/decode/encode)
 * \param inputReference input media
 * \param duarationUs    is a duration of the input media in microseconds.
 */
void Stats::dumpStatistics(std::string operation, std::string inputReference, int64_t duarationUs) {
    ALOGV("In %s", __func__);
    if (!mOutputTimer.size()) {
        ALOGE("No output produced");
        return;
    }
    nsecs_t totalTimeTakenNs = getTotalTime();
    nsecs_t timeTakenPerSec = (totalTimeTakenNs * 1000000) / duarationUs;
    nsecs_t timeToFirstFrameNs = *mOutputTimer.begin() - mStartTimeNs;
    int32_t size = std::accumulate(mFrameSizes.begin(), mFrameSizes.end(), 0);
    // get min and max output intervals.
    nsecs_t intervalNs;
    nsecs_t minTimeTakenNs = INT64_MAX;
    nsecs_t maxTimeTakenNs = 0;
    nsecs_t prevIntervalNs = mStartTimeNs;
    for (int32_t idx = 0; idx < mOutputTimer.size() - 1; idx++) {
        intervalNs = mOutputTimer.at(idx) - prevIntervalNs;
        prevIntervalNs = mOutputTimer.at(idx);
        if (minTimeTakenNs > intervalNs) minTimeTakenNs = intervalNs;
        else if (maxTimeTakenNs < intervalNs) maxTimeTakenNs = intervalNs;
    }

    // Print the Stats
    ALOGI("Input Reference : %s \n", inputReference.c_str());
    ALOGI("Setup Time in nano sec : %" PRId64 "\n", mInitTimeNs);
    ALOGI("Average Time in nano sec : %" PRId64 "\n", totalTimeTakenNs / mOutputTimer.size());
    ALOGI("Time to first frame in nano sec : %" PRId64 "\n", timeToFirstFrameNs);
    ALOGI("Time taken (in nano sec) to %s 1 sec of content : %" PRId64 "\n", operation.c_str(),
          timeTakenPerSec);
    ALOGI("Total bytes %sed : %d\n", operation.c_str(), size);
    ALOGI("Minimum Time in nano sec : %" PRId64 "\n", minTimeTakenNs);
    ALOGI("Maximum Time in nano sec : %" PRId64 "\n", maxTimeTakenNs);
    ALOGI("Destroy Time in nano sec : %" PRId64 "\n", mDeInitTimeNs);
}
