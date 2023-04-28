/*
 * Copyright (C) 2023 The Android Open Source Project
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

#define LOG_TAG "MediaHistogram"
#include <utils/Log.h>

#include <media/stagefright/MediaHistogram.h>

#include <assert.h>
#include <inttypes.h>
#include <stdint.h>

namespace android {

bool MediaHistogram::setup(int bucketCount, int64_t width, int64_t floor)
{
    if (bucketCount <= 0 || width <= 0) {
        return false;
    }

    // get histogram buckets
    if (bucketCount == mBucketCount && mBuckets != NULL) {
        // reuse our existing buffer
        memset(mBuckets, 0, sizeof(*mBuckets) * mBucketCount);
    } else {
        // get a new pre-zeroed buffer
        int64_t *newbuckets = (int64_t *)calloc(bucketCount, sizeof (*mBuckets));
        if (newbuckets == NULL) {
            goto bad;
        }
        if (mBuckets != NULL)
            free(mBuckets);
        mBuckets = newbuckets;
    }

    mWidth = width;
    mFloor = floor;
    mCeiling = floor + bucketCount * width;
    mBucketCount = bucketCount;

    mMin = INT64_MAX;
    mMax = INT64_MIN;
    mSum = 0;
    mCount = 0;
    mBelow = mAbove = 0;

    return true;

  bad:
    if (mBuckets != NULL) {
        free(mBuckets);
        mBuckets = NULL;
    }

    return false;
}

void MediaHistogram::insert(int64_t sample)
{
    // histogram is not set up
    if (mBuckets == NULL) {
        return;
    }

    mCount++;
    mSum += sample;
    if (mMin > sample) mMin = sample;
    if (mMax < sample) mMax = sample;

    if (sample < mFloor) {
        mBelow++;
    } else if (sample >= mCeiling) {
        mAbove++;
    } else {
        int64_t slot = (sample - mFloor) / mWidth;
        assert(slot < mBucketCount);
        mBuckets[slot]++;
    }
    return;
}

std::string MediaHistogram::emit()
{
    std::string value;
    char buffer[64];

    // emits:  width,Below{bucket0,bucket1,...., bucketN}above
    // unconfigured will emit: 0,0{}0
    // XXX: is this best representation?
    snprintf(buffer, sizeof(buffer), "%" PRId64 ",%" PRId64 ",%" PRId64 "{",
             mFloor, mWidth, mBelow);
    value = buffer;
    for (int i = 0; i < mBucketCount; i++) {
        if (i != 0) {
            value = value + ",";
        }
        snprintf(buffer, sizeof(buffer), "%" PRId64, mBuckets[i]);
        value = value + buffer;
    }
    snprintf(buffer, sizeof(buffer), "}%" PRId64 , mAbove);
    value = value + buffer;
    return value;
}

} // android
