/*
 * Copyright (C) 2020 The Android Open Source Project
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
#define LOG_TAG "MetricsCleaner"
#include <utils/Log.h>

#include "cleaner.h"

namespace android::mediametrics {

// place time into buckets at 0,1,2,4,8,16,32 seconds and then at minute boundaries.
// time is rounded up to the next boundary.
//
int64_t bucket_time_minutes(int64_t in_millis) {

    const int64_t SEC_TO_MS = 1000;
    const int64_t MIN_TO_MS = (60 * SEC_TO_MS);

    if (in_millis <= 0) {
        return 0;
    }
    if (in_millis <= 32 * SEC_TO_MS) {
        for (int sec = 1; sec <= 32; sec *= 2) {
            if (in_millis <= sec * SEC_TO_MS) {
                return sec * SEC_TO_MS;
            }
        }
    }
    /* up to next 1 minute boundary */
    int64_t minutes = (in_millis + MIN_TO_MS - 1) / MIN_TO_MS;
    in_millis = minutes * MIN_TO_MS;
    return in_millis;
}

} // namespace android::mediametrics
