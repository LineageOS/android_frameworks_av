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
#include <sstream>
#include <stdio.h>

namespace android {


MediaHistogram::MediaHistogram() {
    mBuckets = nullptr;
    mBucketLimits = nullptr;
    mBucketCount = 0;
    mFloor = mCeiling = mWidth = 0;
    mBelow = 0;
    mAbove = 0;
    mSum = 0;
    mCount = 0;
    mMin = INT64_MAX;
    mMax = INT64_MIN;
}

void MediaHistogram::clear() {
    if (mBuckets != nullptr) {
        free(mBuckets);
        mBuckets = nullptr;
    }
    if (mBucketLimits != nullptr) {
        free(mBucketLimits);
        mBucketLimits = nullptr;
    }
    mBucketCount = 0;
}

bool MediaHistogram::setup(int bucketCount, int64_t width, int64_t floor)
{
    if (bucketCount <= 0 || width <= 0) {
        return false;
    }
    if (!allocate(bucketCount, false)) {
        return false;
    }
    mWidth = width;
    mFloor = floor;
    mCeiling = floor + bucketCount * width;
    mMin = INT64_MAX;
    mMax = INT64_MIN;
    mSum = 0;
    mCount = 0;
    mBelow = mAbove = 0;
    return true;
}

bool MediaHistogram::setup(const std::vector<int64_t> &bucketLimits) {
    if (bucketLimits.size() <= 1) {
        return false;
    }
    int bucketCount = bucketLimits.size() - 1;
    if (!allocate(bucketCount, true)) {
        return false;
    }

    mWidth = -1;
    mFloor = bucketLimits[0];
    for (int i = 0; i < bucketCount; ++i) {
        mBucketLimits[i] = bucketLimits[i + 1];
    }
    mCeiling = bucketLimits[bucketCount];
    mMin = INT64_MAX;
    mMax = INT64_MIN;
    mSum = 0;
    mCount = 0;
    mBelow = mAbove = 0;
    return true;
}

bool MediaHistogram::allocate(int bucketCount, bool withBucketLimits) {
    assert(bucketCount > 0);
    if (bucketCount != mBucketCount) {
        clear();
        mBuckets = (int64_t *) calloc(bucketCount, sizeof(*mBuckets));
        if (mBuckets == nullptr) {
            return false;
        }
    }
    if (withBucketLimits && mBucketLimits == nullptr) {
        mBucketLimits = (int64_t *) calloc(bucketCount, sizeof(*mBucketLimits));
        if (mBucketLimits == nullptr) {
            clear();
            return false;
        }
    }
    mBucketCount = bucketCount;
    memset(mBuckets, 0, sizeof(*mBuckets) * mBucketCount);
    return true;
}

void MediaHistogram::insert(int64_t sample)
{
    // histogram is not set up
    if (mBuckets == nullptr) {
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
    } else if (mBucketLimits == nullptr) {
        int64_t slot = (sample - mFloor) / mWidth;
        assert(slot < mBucketCount);
        mBuckets[slot]++;
    } else {
        // A binary search might be more efficient for large number of buckets, but it is expected
        // that there will never be a large amount of buckets, so keep the code simple.
        for (int slot = 0; slot < mBucketCount; ++slot) {
            if (sample < mBucketLimits[slot]) {
                mBuckets[slot]++;
                break;
            }
        }
    }
    return;
}

std::string MediaHistogram::emit() const
{
    // emits:  floor,width,below{bucket0,bucket1,...., bucketN}above
    // or.. emits:  below{bucket0,bucket1,...., bucketN}above
    // unconfigured will emit: 0,0,0{}0
    // XXX: is this best representation?
    std::stringstream ss;
    if (mBucketLimits == nullptr) {
        ss << mFloor << "," << mWidth << "," << mBelow << "{";
    } else {
        ss << mBelow << "{";
    }
    for (int i = 0; i < mBucketCount; i++) {
        if (i != 0) {
            ss << ",";
        }
        ss << mBuckets[i];
    }
    ss << "}" << mAbove;
    return ss.str();
}

} // android
