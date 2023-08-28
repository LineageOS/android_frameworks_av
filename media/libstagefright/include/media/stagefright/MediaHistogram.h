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

#include <limits>
#include <sstream>
#include <string>
#include <vector>

namespace android {

template<typename T>
class MediaHistogram {
public:
    MediaHistogram();
    void clear();
    bool setup(size_t bucketCount, T width, T floor = 0);
    bool setup(const std::vector<T> &bucketLimits);
    void insert(T sample);
    size_t size() const;
    int64_t operator[](int) const;
    T getMin() const { return mMin; }
    T getMax() const { return mMax; }
    T getCount() const { return mCount; }
    T getSum() const { return mSum; }
    T getAvg() const { return mSum / (mCount == 0 ? 1 : mCount); }
    T getPercentile(int) const;
    std::string emit() const;
    std::string emitBuckets() const;
private:
    MediaHistogram(const MediaHistogram &); // disallow

    void allocate(size_t bucketCount, bool withBucketLimits);

    T mFloor, mCeiling, mWidth;
    T mMin, mMax, mSum;
    int64_t mBelow, mAbove, mCount;
    std::vector<T> mBuckets;
    std::vector<T> mBucketLimits;
};

template<typename T>
MediaHistogram<T>::MediaHistogram() {
    mWidth = mCeiling = mFloor = -1;
    clear();
}

template<typename T>
void MediaHistogram<T>::clear() {
    for (int i = 0; i < mBuckets.size(); ++i) {
        mBuckets[i] = 0;
    }
    mMin = std::numeric_limits<T>::max();
    mMax = std::numeric_limits<T>::min();
    mSum = 0;
    mCount = 0;
    mBelow = mAbove = 0;
}

template<typename T>
bool MediaHistogram<T>::setup(size_t bucketCount, T width, T floor) {
    if (bucketCount <= 0 || width <= 0) {
        return false;
    }
    allocate(bucketCount, false);

    mWidth = width;
    mFloor = floor;
    mCeiling = floor + bucketCount * width;
    clear();
    return true;
}

template<typename T>
bool MediaHistogram<T>::setup(const std::vector<T> &bucketLimits) {
    if (bucketLimits.size() <= 1) {
        return false;
    }
    // The floor is the first bucket limit value, so offset by 1
    size_t bucketCount = bucketLimits.size() - 1;
    allocate(bucketCount, true);

    mWidth = -1;
    mFloor = bucketLimits[0];
    for (size_t i = 0; i < bucketCount; ++i) {
        // The floor is the first bucket, so offset by 1
        mBucketLimits[i] = bucketLimits[i + 1];
    }
    mCeiling = bucketLimits[bucketCount];
    clear();
    return true;
}

template<typename T>
void MediaHistogram<T>::allocate(size_t bucketCount, bool withBucketLimits) {
    assert(bucketCount > 0);
    if (bucketCount != mBuckets.size()) {
        mBuckets = std::vector<T>(bucketCount, 0);
    }
    if (withBucketLimits && mBucketLimits.size() != bucketCount) {
        mBucketLimits = std::vector<T>(bucketCount, 0);
    }
}

template<typename T>
void MediaHistogram<T>::insert(T sample) {
    // histogram is not set up
    if (mBuckets.size() == 0) {
        return;
    }

    mCount++;
    mSum += sample;
    mMin = std::min(mMin, sample);
    mMax = std::max(mMax, sample);

    if (sample < mFloor) {
        mBelow++;
    } else if (sample >= mCeiling) {
        mAbove++;
    } else if (mWidth == -1) {
        // A binary search might be more efficient for large number of buckets, but it is expected
        // that there will never be a large amount of buckets, so keep the code simple.
        for (size_t slot = 0; slot < mBucketLimits.size(); ++slot) {
            if (sample < mBucketLimits[slot]) {
                mBuckets[slot]++;
                break;
            }
        }
    } else {
        int64_t slot = (sample - mFloor) / mWidth;
        assert(slot < mBuckets.size());
        mBuckets[slot]++;
    }
    return;
}

template<typename T>
size_t MediaHistogram<T>::size() const {
    return mBuckets.size() + 1;
}

template<typename T>
int64_t MediaHistogram<T>::operator[](int i) const {
    assert(i >= 0);
    assert(i <= mBuckets.size());
    if (i == mBuckets.size()) {
        return mAbove;
    }
    return mBuckets[i];
}

template<typename T>
std::string MediaHistogram<T>::emit() const {
    // emits:  floor,width,below{bucket0,bucket1,...., bucketN}above
    // or.. emits:  below{bucket0,bucket1,...., bucketN}above
    // unconfigured will emit: 0{}0
    // XXX: is this best representation?
    std::stringstream ss("");
    if (mWidth == -1) {
        ss << mBelow << "{";
    } else {
        ss << mFloor << "," << mWidth << "," << mBelow << "{";
    }
    for (size_t i = 0; i < mBuckets.size(); i++) {
        if (i != 0) {
            ss << ",";
        }
        ss << mBuckets[i];
    }
    ss << "}" << mAbove;
    return ss.str();
}

template<typename T>
std::string MediaHistogram<T>::emitBuckets() const {
    std::stringstream ss("");
    if (mWidth == -1) {
        ss << mFloor;
        for (size_t i = 0; i < mBucketLimits.size(); ++i) {
            ss << ',' << mBucketLimits[i];
        }
    } else {
        ss << mFloor;
        for (size_t i = 1; i <= mBuckets.size(); ++i) {
            ss << ',' << (mFloor + i * mWidth);
        }
    }
    return ss.str();
}

} // android

#endif // MEDIA_HISTOGRAM_H_