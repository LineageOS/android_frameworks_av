/*
 * Copyright 2023, The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef MEDIA_HISTOGRAM_H_
#define MEDIA_HISTOGRAM_H_

#include <string>
#include <vector>

namespace android {

class MediaHistogram {
    public:
    MediaHistogram();
    ~MediaHistogram() { clear(); };
    void clear();
    bool setup(int bucketCount, int64_t width, int64_t floor = 0);
    bool setup(const std::vector<int64_t> &bucketLimits);
    void insert(int64_t sample);
    int64_t getMin() const { return mMin; }
    int64_t getMax() const { return mMax; }
    int64_t getCount() const { return mCount; }
    int64_t getSum() const { return mSum; }
    int64_t getAvg() const { return mSum / (mCount == 0 ? 1 : mCount); }
    std::string emit() const;
private:
    MediaHistogram(const MediaHistogram &); // disallow

    bool allocate(int bucketCount, bool withBucketLimits);

    int64_t mFloor, mCeiling, mWidth;
    int64_t mBelow, mAbove;
    int64_t mMin, mMax, mSum, mCount;

    int mBucketCount;
    int64_t *mBuckets;
    int64_t *mBucketLimits;
};

} // android

#endif // MEDIA_HISTOGRAM_H_