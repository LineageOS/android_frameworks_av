/*
 * Copyright (C) 2024 The Android Open Source Project
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

#ifndef CODEC_CAPABILITIES__UTILS_H_

#define CODEC_CAPABILITIES__UTILS_H_

#include <algorithm>
#include <cerrno>
#include <cmath>
#include <cstdlib>
#include <numeric>
#include <optional>
#include <regex>
#include <string>
#include <vector>

#include <utils/Log.h>

#include <media/stagefright/foundation/AUtils.h>

namespace android {

struct ProfileLevel {
    uint32_t mProfile;
    uint32_t mLevel;
    bool operator <(const ProfileLevel &o) const {
        return mProfile < o.mProfile || (mProfile == o.mProfile && mLevel < o.mLevel);
    }
};

struct Feature {
    std::string mName;
    int mValue;
    bool mDefault;
    bool mInternal;
    Feature(std::string name, int value, bool def, bool internal) {
        mName = name;
        mValue = value;
        mDefault = def;
        mInternal = internal;
    }
    Feature(std::string name, int value, bool def) :
        Feature(name, value, def, false /* internal */) {}
};

/**
 * Immutable class for describing the range of two numeric values.
 *
 * To make it immutable, all data are private and all functions are const.
 *
 * From frameworks/base/core/java/android/util/Range.java
 */
template<typename T>
struct Range {
    Range() : lower_(), upper_() {}

    Range(T l, T u) : lower_(l), upper_(u) {}

    constexpr bool empty() const { return lower_ > upper_; }

    T lower() const { return lower_; }

    T upper() const { return upper_; }

    // Check if a value is in the range.
    bool contains(T value) const {
        return lower_ <= value && upper_ >= value;
    }

    bool contains(Range<T> range) const {
        return (range.lower_ >= lower_) && (range.upper_ <= upper_);
    }

    // Clamp a value in the range
    T clamp(T value) const{
        if (value < lower_) {
            return lower_;
        } else if (value > upper_) {
            return upper_;
        } else {
            return value;
        }
    }

    // Return the intersected range
    Range<T> intersect(Range<T> range) const {
        if (lower_ >= range.lower() && range.upper() >= upper_) {
            // range includes this
            return *this;
        } else if (range.lower() >= lower_ && range.upper() <= upper_) {
            // this includes range
            return range;
        } else {
            // if ranges are disjoint returns an empty Range(lower > upper)
            Range<T> result = Range<T>(std::max(lower_, range.lower_),
                    std::min(upper_, range.upper_));
            if (result.empty()) {
                ALOGV("Failed to intersect 2 ranges as they are disjoint");
            }
            return result;
        }
    }

    /**
     * Returns the intersection of this range and the inclusive range
     * specified by {@code [lower, upper]}.
     * <p>
     * See {@link #intersect(Range)} for more details.</p>
     *
     * @param lower a non-{@code null} {@code T} reference
     * @param upper a non-{@code null} {@code T} reference
     * @return the intersection of this range and the other range
     */
    Range<T> intersect(T lower, T upper) const {
        Range<T> range = Range<T>(lower, upper);
        return this->intersect(range);
    }

    /**
     * Returns the smallest range that includes this range and
     * another range.
     *
     * E.g. if a < b < c < d, the
     * extension of [a, c] and [b, d] ranges is [a, d].
     * As the endpoints are object references, there is no guarantee
     * which specific endpoint reference is used from the input ranges:
     *
     * E.g. if a == a' < b < c, the
     * extension of [a, b] and [a', c] ranges could be either
     * [a, c] or ['a, c], where ['a, c] could be either the exact
     * input range, or a newly created range with the same endpoints.
     *
     * @param range a non-null Range<T> reference
     * @return the extension of this range and the other range.
     */
    Range<T> extend(Range<T> range) const {
        return Range<T>(std::min(lower_, range.lower_), std::max(upper_, range.upper_));
    }

    Range<T> align(T align) const {
        return this->intersect(
                divUp(lower_, align) * align, (upper_ / align) * align);
    }

    Range<T> factor(T factor) const {
        if (factor == 1) {
            return *this;
        }
        return Range(divUp(this->lower(), factor), this->upper() / factor);
    }

    // parse a string into a range
    static std::optional<Range<T>> Parse(const std::string &str) {
        if (str.empty()) {
            ALOGW("could not parse empty integer range");
            return std::nullopt;
        }
        long long lower, upper;
        std::regex regex("^([0-9]+)-([0-9]+)$");
        std::smatch match;
        errno = 0;
        if (std::regex_match(str, match, regex)) {
            lower = std::strtoll(match[1].str().c_str(), NULL, 10);
            upper = std::strtoll(match[2].str().c_str(), NULL, 10);
        } else {
            char *end;
            lower = upper = std::strtoll(str.c_str(), &end, 10);
            if (*end != '\0') {
                ALOGW("could not parse integer range: %s", str.c_str());
                return std::nullopt;
            }
        }

        if (errno == ERANGE || lower < std::numeric_limits<T>::min()
                || std::numeric_limits<T>::max() < upper || upper < lower) {
            ALOGW("could not parse integer range: %s", str.c_str());
            return std::nullopt;
        }

        return std::make_optional<Range<T>>((T)lower, (T)upper);
    }

    static Range<T> RangeFor(double v) {
        return Range((T)v, (T)ceil(v));
    }

private:
    T lower_;
    T upper_;
};

static const Range<int32_t> POSITIVE_INT32 = Range<int32_t>(1, INT32_MAX);

// found stuff that is not supported by framework (=> this should not happen)
constexpr int ERROR_CAPABILITIES_UNRECOGNIZED   = (1 << 0);
// found profile/level for which we don't have capability estimates
constexpr int ERROR_CAPABILITIES_UNSUPPORTED    = (1 << 1);
// have not found any profile/level for which we don't have capability estimate
constexpr int ERROR_CAPABILITIES_NONE_SUPPORTED = (1 << 2);

/**
 * Sorts distinct (non-intersecting) range array in ascending order.
 * From frameworks/base/media/java/android/media/Utils.java
 */
template<typename T>
void sortDistinctRanges(std::vector<Range<T>> *ranges) {
    std::sort(ranges->begin(), ranges->end(),
            [](Range<T> r1, Range<T> r2) {
        if (r1.upper() < r2.lower()) {
            return true;
        } else if (r1.lower() > r2.upper()) {
            return false;
        } else {
            ALOGE("sample rate ranges must be distinct.");
            return false;
        }
    });
}

/**
 * Returns the intersection of two sets of non-intersecting ranges
 * From frameworks/base/media/java/android/media/Utils.java
 * @param one a sorted set of non-intersecting ranges in ascending order
 * @param another another sorted set of non-intersecting ranges in ascending order
 * @return the intersection of the two sets, sorted in ascending order
 */
template<typename T>
std::vector<Range<T>> intersectSortedDistinctRanges(
        const std::vector<Range<T>> &one, const std::vector<Range<T>> &another) {
    std::vector<Range<T>> result;
    int ix = 0;
    for (Range<T> range : another) {
        while (ix < one.size() && one[ix].upper() < range.lower()) {
            ++ix;
        }
        while (ix < one.size() && one[ix].upper() < range.upper()) {
            result.push_back(range.intersect(one[ix]));
            ++ix;
        }
        if (ix == one.size()) {
            break;
        }
        if (one[ix].lower() <= range.upper()) {
            result.push_back(range.intersect(one[ix]));
        }
    }
    return result;
}

/**
 * Returns the union of two sets of non-intersecting ranges
 * @param one a sorted set of non-intersecting ranges in ascending order
 * @param another another sorted set of non-intersecting ranges in ascending order
 * @return the union of the two sets, sorted in ascending order
 */
template<typename T>
std::vector<Range<T>> unionSortedDistinctRanges(
        const std::vector<Range<T>> &one, const std::vector<Range<T>> &another) {
    std::vector<Range<T>> result;
    Range<T> last;
    int ix1 = 0;
    int ix2 = 0;
    while (ix1 < one.size() || ix2 < another.size()) {
        Range<T> temp;
        if (ix1 == one.size() || (ix2 < another.size()
                && one[ix1].lower() > another[ix2].upper())) {
            temp = another[ix2];
            ix2++;
        } else if (ix2 == another.size() || (ix1 < one.size()
                && one[ix1].upper() < another[ix2].lower())) {
            temp = one[ix1];
            ix1++;
        } else {  // not disjoint
            temp = one[ix1].extend(another[ix2]);
            ix1++;
            ix2++;
        }
        if (last.empty()) { // first time
            last = temp;
            continue;
        }
        // update last
        if (last.intersect(temp).empty()) {
            result.push_back(last);
            last = temp;
        } else {
            last = last.extend(temp);
        }
    }
    if (!last.empty()) {
        result.push_back(last);
    }

    return result;
}

/**
 * Immutable class for describing width and height dimensions in pixels.
 */
struct VideoSize {
    /**
     * Create a new immutable VideoSize instance.
     *
     * @param width The width of the size, in pixels
     * @param height The height of the size, in pixels
     */
    VideoSize(int32_t width, int32_t height);

    // default constructor
    VideoSize();

    /**
     * Get the width of the size (in pixels).
     * @return width
     */
    int32_t getWidth() const;

    /**
     * Get the height of the size (in pixels).
     * @return height
     */
    int32_t getHeight() const;

    /**
     * Check if this size is equal to another size.
     *
     * Two sizes are equal if and only if both their widths and heights are
     * equal.
     *
     * A size object is never equal to any other type of object.
     *
     * @return true if the objects were equal, false otherwise
     */
    bool equals(VideoSize other) const;

    bool empty() const;

    std::string toString() const;

    /**
     * Parses the specified string as a size value.
     *
     * The ASCII characters {@code \}{@code u002a} ('*') and
     * {@code \}{@code u0078} ('x') are recognized as separators between
     * the width and height.
     *
     * For any {@code VideoSize s}: {@code VideoSize::ParseSize(s.toString()).equals(s)}.
     * However, the method also handles sizes expressed in the
     * following forms:
     *
     * "<i>width</i>{@code x}<i>height</i>" or
     * "<i>width</i>{@code *}<i>height</i>" {@code => new VideoSize(width, height)},
     * where <i>width</i> and <i>height</i> are string integers potentially
     * containing a sign, such as "-10", "+7" or "5".
     *
     * <pre>{@code
     * VideoSize::ParseSize("3*+6").equals(new VideoSize(3, 6)) == true
     * VideoSize::ParseSize("-3x-6").equals(new VideoSize(-3, -6)) == true
     * VideoSize::ParseSize("4 by 3") => throws NumberFormatException
     * }</pre>
     *
     * @param string the string representation of a size value.
     * @return the size value represented by {@code string}.
     */
    static std::optional<VideoSize> ParseSize(std::string str);

    static std::optional<std::pair<VideoSize, VideoSize>> ParseSizeRange(const std::string str);

    static Range<int32_t> GetAllowedDimensionRange();

private:
    int32_t mWidth;
    int32_t mHeight;
};

// This is used for the std::map<VideoSize> in VideoCapabilities
struct VideoSizeCompare {
    bool operator() (const VideoSize& lhs, const VideoSize& rhs) const {
        if (lhs.getWidth() == rhs.getWidth()) {
            return lhs.getHeight() < rhs.getHeight();
        } else {
            return lhs.getWidth() < rhs.getWidth();
        }
    }
};

/**
 * An immutable data type representation a rational number.
 *
 * Contains a pair of ints representing the numerator and denominator of a
 * Rational number.
 */
struct Rational {
    /**
     * <p>Create a {@code Rational} with a given numerator and denominator.</p>
     *
     * <p>The signs of the numerator and the denominator may be flipped such that the denominator
     * is always positive. Both the numerator and denominator will be converted to their reduced
     * forms (see {@link #equals} for more details).</p>
     *
     * <p>For example,
     * <ul>
     * <li>a rational of {@code 2/4} will be reduced to {@code 1/2}.
     * <li>a rational of {@code 1/-1} will be flipped to {@code -1/1}
     * <li>a rational of {@code 5/0} will be reduced to {@code 1/0}
     * <li>a rational of {@code 0/5} will be reduced to {@code 0/1}
     * </ul>
     * </p>
     *
     * @param numerator the numerator of the rational
     * @param denominator the denominator of the rational
     *
     * @see #equals
     */
    Rational(int32_t numerator, int32_t denominator) {
        if (denominator < 0) {
            numerator = -numerator;
            denominator = -denominator;
        }

        // Convert to reduced form
        if (denominator == 0 && numerator > 0) {
            mNumerator = 1; // +Inf
            mDenominator = 0;
        } else if (denominator == 0 && numerator < 0) {
            mNumerator = -1; // -Inf
            mDenominator = 0;
        } else if (denominator == 0 && numerator == 0) {
            mNumerator = 0; // NaN
            mDenominator = 0;
        } else if (numerator == 0) {
            mNumerator = 0;
            mDenominator = 1;
        } else {
            int gcd = std::gcd(numerator, denominator);

            mNumerator = numerator / gcd;
            mDenominator = denominator / gcd;
        }
    }

    // default constructor;
    Rational() {
        Rational(0, 0);
    }

    /**
     * Gets the numerator of the rational.
     *
     * <p>The numerator will always return {@code 1} if this rational represents
     * infinity (that is, the denominator is {@code 0}).</p>
     */
    int32_t getNumerator() const {
        return mNumerator;
    }

    /**
     * Gets the denominator of the rational
     *
     * <p>The denominator may return {@code 0}, in which case the rational may represent
     * positive infinity (if the numerator was positive), negative infinity (if the numerator
     * was negative), or {@code NaN} (if the numerator was {@code 0}).</p>
     *
     * <p>The denominator will always return {@code 1} if the numerator is {@code 0}.
     */
    int32_t getDenominator() const {
        return mDenominator;
    }

    /**
     * Indicates whether this rational is a <em>Not-a-Number (NaN)</em> value.
     *
     * <p>A {@code NaN} value occurs when both the numerator and the denominator are {@code 0}.</p>
     *
     * @return {@code true} if this rational is a <em>Not-a-Number (NaN)</em> value;
     *         {@code false} if this is a (potentially infinite) number value
     */
    bool isNaN() const {
        return mDenominator == 0 && mNumerator == 0;
    }

    /**
     * Indicates whether this rational represents an infinite value.
     *
     * <p>An infinite value occurs when the denominator is {@code 0} (but the numerator is not).</p>
     *
     * @return {@code true} if this rational is a (positive or negative) infinite value;
     *         {@code false} if this is a finite number value (or {@code NaN})
     */
    bool isInfinite() const {
        return mNumerator != 0 && mDenominator == 0;
    }

    /**
     * Indicates whether this rational represents a finite value.
     *
     * <p>A finite value occurs when the denominator is not {@code 0}; in other words
     * the rational is neither infinity or {@code NaN}.</p>
     *
     * @return {@code true} if this rational is a (positive or negative) infinite value;
     *         {@code false} if this is a finite number value (or {@code NaN})
     */
    bool isFinite() const {
        return mDenominator != 0;
    }

    /**
     * Indicates whether this rational represents a zero value.
     *
     * <p>A zero value is a {@link #isFinite finite} rational with a numerator of {@code 0}.</p>
     *
     * @return {@code true} if this rational is finite zero value;
     *         {@code false} otherwise
     */
    bool isZero() const {
        return isFinite() && mNumerator == 0;
    }

    /**
     * Return a string representation of this rational, e.g. {@code "1/2"}.
     *
     * <p>The following rules of conversion apply:
     * <ul>
     * <li>{@code NaN} values will return {@code "NaN"}
     * <li>Positive infinity values will return {@code "Infinity"}
     * <li>Negative infinity values will return {@code "-Infinity"}
     * <li>All other values will return {@code "numerator/denominator"} where {@code numerator}
     * and {@code denominator} are substituted with the appropriate numerator and denominator
     * values.
     * </ul></p>
     */
    std::string toString() const {
        if (isNaN()) {
            return "NaN";
        } else if (isPosInf()) {
            return "Infinity";
        } else if (isNegInf()) {
            return "-Infinity";
        } else {
            return std::to_string(mNumerator) + "/" + std::to_string(mDenominator);
        }
    }

    /**
     * Returns the value of the specified number as a {@code double}.
     *
     * <p>The {@code double} is calculated by converting both the numerator and denominator
     * to a {@code double}; then returning the result of dividing the numerator by the
     * denominator.</p>
     *
     * @return the divided value of the numerator and denominator as a {@code double}.
     */
    double asDouble() const {
        double num = mNumerator;
        double den = mDenominator;

        return num / den;
    }

    /**
     * Returns the value of the specified number as a {@code float}.
     *
     * <p>The {@code float} is calculated by converting both the numerator and denominator
     * to a {@code float}; then returning the result of dividing the numerator by the
     * denominator.</p>
     *
     * @return the divided value of the numerator and denominator as a {@code float}.
     */
    float asfloat() const {
        float num = mNumerator;
        float den = mDenominator;

        return num / den;
    }

    /**
     * Returns the value of the specified number as a {@code int}.
     *
     * <p>{@link #isInfinite Finite} rationals are converted to an {@code int} value
     * by dividing the numerator by the denominator; conversion for non-finite values happens
     * identically to casting a floating point value to an {@code int}, in particular:
     *
     * @return the divided value of the numerator and denominator as a {@code int}.
     */
    int32_t asInt32() const {
        // Mimic float to int conversion rules from JLS 5.1.3

        if (isPosInf()) {
            return INT32_MAX;
        } else if (isNegInf()) {
            return INT32_MIN;
        } else if (isNaN()) {
            return 0;
        } else { // finite
            return mNumerator / mDenominator;
        }
    }

    /**
     * Returns the value of the specified number as a {@code long}.
     *
     * <p>{@link #isInfinite Finite} rationals are converted to an {@code long} value
     * by dividing the numerator by the denominator; conversion for non-finite values happens
     * identically to casting a floating point value to a {@code long}, in particular:
     *
     * @return the divided value of the numerator and denominator as a {@code long}.
     */
    int64_t asInt64() const {
        // Mimic float to long conversion rules from JLS 5.1.3

        if (isPosInf()) {
            return INT64_MAX;
        } else if (isNegInf()) {
            return INT64_MIN;
        } else if (isNaN()) {
            return 0;
        } else { // finite
            return mNumerator / mDenominator;
        }
    }

    /**
     * Returns the value of the specified number as a {@code short}.
     *
     * <p>{@link #isInfinite Finite} rationals are converted to a {@code short} value
     * identically to {@link #intValue}; the {@code int} result is then truncated to a
     * {@code short} before returning the value.</p>
     *
     * @return the divided value of the numerator and denominator as a {@code short}.
     */
    int16_t asInt16() const {
        return (int16_t) asInt32();
    }

    /**
     * Compare this rational to the specified rational to determine their natural order.
     *
     * Nan is considered to be equal to itself and greater than all other
     * Rational values. Otherwise, if the objects are not equal, then
     * the following rules apply:
     *
     * Positive infinity is greater than any other finite number (or negative infinity)
     * Negative infinity is less than any other finite number (or positive infinity)
     * The finite number represented by this rational is checked numerically
     * against the other finite number by converting both rationals to a common denominator multiple
     * and comparing their numerators.
     *
     * @param another the rational to be compared
     *
     * @return a negative integer, zero, or a positive integer as this object is less than,
     *         equal to, or greater than the specified rational.
     */
    // bool operator> (const Rational& another) {
    int compareTo(Rational another) const {
        if (equals(another)) {
            return 0;
        } else if (isNaN()) { // NaN is greater than the other non-NaN value
            return 1;
        } else if (another.isNaN()) { // the other NaN is greater than this non-NaN value
            return -1;
        } else if (isPosInf() || another.isNegInf()) {
            return 1; // positive infinity is greater than any non-NaN/non-posInf value
        } else if (isNegInf() || another.isPosInf()) {
            return -1; // negative infinity is less than any non-NaN/non-negInf value
        }

        // else both this and another are finite numbers

        // make the denominators the same, then compare numerators. int64_t to avoid overflow
        int64_t thisNumerator = ((int64_t)mNumerator) * another.mDenominator;
        int64_t otherNumerator = ((int64_t)another.mNumerator) * mDenominator;

        // avoid underflow from subtraction by doing comparisons
        if (thisNumerator < otherNumerator) {
            return -1;
        } else if (thisNumerator > otherNumerator) {
            return 1;
        } else {
            // This should be covered by #equals, but have this code path just in case
            return 0;
        }
    }

    bool operator > (const Rational& another) const {
        return compareTo(another) > 0;
    }

    bool operator >= (const Rational& another) const {
        return compareTo(another) >= 0;
    }

    bool operator < (const Rational& another) const {
        return compareTo(another) < 0;
    }

    bool operator <= (const Rational& another) const {
        return compareTo(another) <= 0;
    }

    bool operator == (const Rational& another) const {
        return equals(another);
    }

    static std::optional<Range<Rational>> ParseRange(const std::string str);

    static Range<Rational> ScaleRange(Range<Rational> range, int32_t num, int32_t den);

private:
    int32_t mNumerator;
    int32_t mDenominator;

    bool isPosInf() const {
        return mDenominator == 0 && mNumerator > 0;
    }

    bool isNegInf() const {
        return mDenominator == 0 && mNumerator < 0;
    }

    bool equals(Rational other) const {
        return (mNumerator == other.mNumerator && mDenominator == other.mDenominator);
    }

    Rational scale(int32_t num, int32_t den);

    /**
     * Parses the specified string as a rational value.
     * The ASCII characters {@code \}{@code u003a} (':') and
     * {@code \}{@code u002f} ('/') are recognized as separators between
     * the numerator and denominator.
     *
     * For any {@code Rational r}: {@code Rational::parseRational(r.toString()).equals(r)}.
     * However, the method also handles rational numbers expressed in the
     * following forms:
     *
     * "<i>num</i>{@code /}<i>den</i>" or
     * "<i>num</i>{@code :}<i>den</i>" {@code => new Rational(num, den);},
     * where <i>num</i> and <i>den</i> are string integers potentially
     * containing a sign, such as "-10", "+7" or "5".
     *
     * Rational::Parse("3:+6").equals(new Rational(1, 2)) == true
     * Rational::Parse("-3/-6").equals(new Rational(1, 2)) == true
     * Rational::Parse("4.56") => return std::nullopt
     *
     * @param str the string representation of a rational value.
     * @return the rational value wrapped by std::optional represented by str.
     */
    static std::optional<Rational> Parse(std::string str);
};

static const Rational NaN = Rational(0, 0);
static const Rational POSITIVE_INFINITY = Rational(1, 0);
static const Rational NEGATIVE_INFINITY = Rational(-1, 0);
static const Rational ZERO = Rational(0, 1);

}  // namespace android

#endif  // CODEC_CAPABILITIES__UTILS_H_