/*
 * Copyright 2017 The Android Open Source Project
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

#ifndef ANDROID_INTERPOLATOR_H
#define ANDROID_INTERPOLATOR_H

#include <map>
#include <sstream>
#include <unordered_map>

#include <android/media/InterpolatorConfig.h>
#include <binder/Parcel.h>
#include <utils/RefBase.h>

#pragma push_macro("LOG_TAG")
#undef LOG_TAG
#define LOG_TAG "Interpolator"

namespace android {

/*
 * A general purpose spline interpolator class which takes a set of points
 * and performs interpolation.  This is used for the VolumeShaper class.
 */

template <typename S, typename T>
class Interpolator : public std::map<S, T> {
public:
    // Polynomial spline interpolators
    using InterpolatorType  = media::InterpolatorType;

    explicit Interpolator(
            InterpolatorType interpolatorType = InterpolatorType::CUBIC,
            bool cache = true)
        : mCache(cache)
        , mFirstSlope(0)
        , mLastSlope(0) {
        setInterpolatorType(interpolatorType);
    }

    std::pair<S, T> first() const {
        return *this->begin();
    }

    std::pair<S, T> last() const {
        return *this->rbegin();
    }

    // find the corresponding Y point from a X point.
    T findY(S x) { // logically const, but modifies cache
        auto high = this->lower_bound(x);
        // greater than last point
        if (high == this->end()) {
            return this->rbegin()->second;
        }
        // at or before first point
        if (high == this->begin()) {
            return high->second;
        }
        // go lower.
        auto low = high;
        --low;

        // now that we have two adjacent points:
        switch (mInterpolatorType) {
        case InterpolatorType::STEP:
            return high->first == x ? high->second : low->second;
        case InterpolatorType::LINEAR:
            return ((high->first - x) * low->second + (x - low->first) * high->second)
                    / (high->first - low->first);
        case InterpolatorType::CUBIC:
        case InterpolatorType::CUBIC_MONOTONIC:
        default: {
            // See https://en.wikipedia.org/wiki/Cubic_Hermite_spline

            const S interval =  high->first - low->first;

            // check to see if we've cached the polynomial coefficients
            if (mMemo.count(low->first) != 0) {
                const S t = (x - low->first) / interval;
                const S t2 = t * t;
                const auto &memo = mMemo[low->first];
                return low->second + std::get<0>(memo) * t
                        + (std::get<1>(memo) + std::get<2>(memo) * t) * t2;
            }

            // find the neighboring points (low2 < low < high < high2)
            auto low2 = this->end();
            if (low != this->begin()) {
                low2 = low;
                --low2; // decrementing this->begin() is undefined
            }
            auto high2 = high;
            ++high2;

            // you could have catmullRom with monotonic or
            // non catmullRom (finite difference) with regular cubic;
            // the choices here minimize computation.
            bool monotonic, catmullRom;
            if (mInterpolatorType == InterpolatorType::CUBIC_MONOTONIC) {
                monotonic = true;
                catmullRom = false;
            } else {
                monotonic = false;
                catmullRom = true;
            }

            // secants are only needed for finite difference splines or
            // monotonic computation.
            // we use lazy computation here - if we precompute in
            // a single pass, duplicate secant computations may be avoided.
            S sec{}, sec0{}, sec1{};  // initialization not needed, used for clang-tidy
            if (!catmullRom || monotonic) {
                sec = (high->second - low->second) / interval;
                sec0 = low2 != this->end()
                        ? (low->second - low2->second) / (low->first - low2->first)
                        : mFirstSlope;
                sec1 = high2 != this->end()
                        ? (high2->second - high->second) / (high2->first - high->first)
                        : mLastSlope;
            }

            // compute the tangent slopes at the control points
            S m0, m1;
            if (catmullRom) {
                // Catmull-Rom spline
                m0 = low2 != this->end()
                        ? (high->second - low2->second) / (high->first - low2->first)
                        : mFirstSlope;

                m1 = high2 != this->end()
                        ? (high2->second - low->second) / (high2->first - low->first)
                        : mLastSlope;
            } else {
                // finite difference spline
                m0 = (sec0 + sec) * 0.5f;
                m1 = (sec1 + sec) * 0.5f;
            }

            if (monotonic) {
                // https://en.wikipedia.org/wiki/Monotone_cubic_interpolation
                // A sufficient condition for Fritsch–Carlson monotonicity is constraining
                // (1) the normalized slopes to be within the circle of radius 3, or
                // (2) the normalized slopes to be within the square of radius 3.
                // Condition (2) is more generous and easier to compute.
                const S maxSlope = 3 * sec;
                m0 = constrainSlope(m0, maxSlope);
                m1 = constrainSlope(m1, maxSlope);

                m0 = constrainSlope(m0, 3 * sec0);
                m1 = constrainSlope(m1, 3 * sec1);
            }

            const S t = (x - low->first) / interval;
            const S t2 = t * t;
            if (mCache) {
                // convert to cubic polynomial coefficients and compute
                m0 *= interval;
                m1 *= interval;
                const T dy = high->second - low->second;
                const S c0 = low->second;
                const S c1 = m0;
                const S c2 = 3 * dy - 2 * m0 - m1;
                const S c3 = m0 + m1 - 2 * dy;
                mMemo[low->first] = std::make_tuple(c1, c2, c3);
                return c0 + c1 * t + (c2 + c3 * t) * t2;
            } else {
                // classic Hermite interpolation
                const S t3 = t2 * t;
                const S h00 =  2 * t3 - 3 * t2     + 1;
                const S h10 =      t3 - 2 * t2 + t    ;
                const S h01 = -2 * t3 + 3 * t2        ;
                const S h11 =      t3     - t2        ;
                return h00 * low->second + (h10 * m0 + h11 * m1) * interval + h01 * high->second;
            }
        } // default
        }
    }

    InterpolatorType getInterpolatorType() const {
        return mInterpolatorType;
    }

    status_t setInterpolatorType(InterpolatorType interpolatorType) {
        switch (interpolatorType) {
        case InterpolatorType::STEP:   // Not continuous
        case InterpolatorType::LINEAR: // C0
        case InterpolatorType::CUBIC:  // C1
        case InterpolatorType::CUBIC_MONOTONIC: // C1 + other constraints
        // case InterpolatorType::CUBIC_C2:
            mInterpolatorType = interpolatorType;
            return NO_ERROR;
        default:
            ALOGE("invalid interpolatorType: %d", static_cast<int>(interpolatorType));
            return BAD_VALUE;
        }
    }

    T getFirstSlope() const {
        return mFirstSlope;
    }

    void setFirstSlope(T slope) {
        mFirstSlope = slope;
    }

    T getLastSlope() const {
        return mLastSlope;
    }

    void setLastSlope(T slope) {
        mLastSlope = slope;
    }

    void clearCache() {
        mMemo.clear();
    }

    // TODO(ytai): remove this method once it is not used.
    status_t writeToParcel(Parcel *parcel) const {
        media::InterpolatorConfig config;
        writeToConfig(&config);
        return config.writeToParcel(parcel);
    }

    void writeToConfig(media::InterpolatorConfig *config) const {
        config->type = mInterpolatorType;
        config->firstSlope = mFirstSlope;
        config->lastSlope = mLastSlope;
        for (const auto &pt : *this) {
            config->xy.push_back(pt.first);
            config->xy.push_back(pt.second);
        }
    }

    // TODO(ytai): remove this method once it is not used.
    status_t readFromParcel(const Parcel &parcel) {
        media::InterpolatorConfig config;
        status_t res = config.readFromParcel(&parcel);
        if (res != NO_ERROR) {
            return res;
        }
        return readFromConfig(config);
    }

    status_t readFromConfig(const media::InterpolatorConfig &config) {
        this->clear();
        setInterpolatorType(config.type);
        if ((config.xy.size() & 1) != 0) {
            // xy size must be even.
            return BAD_VALUE;
        }
        uint32_t size = config.xy.size() / 2;
        mFirstSlope = config.firstSlope;
        mLastSlope = config.lastSlope;

        // Note: We don't need to check size is within some bounds as
        // the Parcel read will fail if size is incorrectly specified too large.
        float lastx = 0.f; // initialization not needed, used for clang tidy
        for (uint32_t i = 0; i < size; ++i) {
            float x = config.xy[i * 2];
            float y = config.xy[i * 2 + 1];
            if ((i > 0 && !(x > lastx)) /* handle nan */
                    || y != y /* handle nan */) {
                // This is a std::map object which imposes sorted order
                // automatically on emplace.
                // Nevertheless for reading from a Parcel,
                // we require that the points be specified monotonic in x.
                return BAD_VALUE;
            }
            this->emplace(x, y);
            lastx = x;
        }
        return NO_ERROR;
    }

    std::string toString() const {
        std::stringstream ss;
        ss << "Interpolator{mInterpolatorType=" << static_cast<int32_t>(mInterpolatorType);
        ss << ", mFirstSlope=" << mFirstSlope;
        ss << ", mLastSlope=" << mLastSlope;
        ss << ", {";
        bool first = true;
        for (const auto &pt : *this) {
            if (first) {
                first = false;
                ss << "{";
            } else {
                ss << ", {";
            }
            ss << pt.first << ", " << pt.second << "}";
        }
        ss << "}}";
        return ss.str();
    }

private:
    static S constrainSlope(S slope, S maxSlope) {
        if (maxSlope > 0) {
            slope = std::min(slope, maxSlope);
            slope = std::max(slope, S(0)); // not globally monotonic
        } else {
            slope = std::max(slope, maxSlope);
            slope = std::min(slope, S(0)); // not globally monotonic
        }
        return slope;
    }

    InterpolatorType mInterpolatorType;
    bool mCache; // whether we cache spline coefficient computation

    // for cubic interpolation, the boundary conditions in slope.
    S mFirstSlope;
    S mLastSlope;

    // spline cubic polynomial coefficient cache
    std::unordered_map<S, std::tuple<S /* c1 */, S /* c2 */, S /* c3 */>> mMemo;
}; // Interpolator

} // namespace android

#pragma pop_macro("LOG_TAG")

#endif // ANDROID_INTERPOLATOR_H
