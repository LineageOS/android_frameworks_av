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

#include <HeifCleanAperture.h>

namespace android {
namespace heif {
namespace {

// |a| and |b| hold int32_t values. The int64_t type is used so that we can negate INT32_MIN without
// overflowing int32_t.
int64_t calculateGreatestCommonDivisor(int64_t a, int64_t b) {
    if (a < 0) {
        a *= -1;
    }
    if (b < 0) {
        b *= -1;
    }
    while (b != 0) {
        int64_t r = a % b;
        a = b;
        b = r;
    }
    return a;
}

bool overflowsInt32(int64_t x) {
    return (x < INT32_MIN) || (x > INT32_MAX);
}

Fraction calculateCenter(int32_t value) {
    Fraction f(value, 2);
    f.simplify();
    return f;
}

}  // namespace

Fraction::Fraction(int32_t n, int32_t d) {
    this->n = n;
    this->d = d;
}

void Fraction::simplify() {
    int64_t gcd = calculateGreatestCommonDivisor(n, d);
    if (gcd > 1) {
        n = static_cast<int32_t>(n / gcd);
        d = static_cast<int32_t>(d / gcd);
    }
}

bool Fraction::commonDenominator(Fraction* f) {
    simplify();
    f->simplify();
    if (d == f->d) return true;
    const int64_t this_d = d;
    const int64_t fd = f->d;
    const int64_t thisnNew = n * fd;
    const int64_t thisdNew = d * fd;
    const int64_t fnNew = f->n * this_d;
    const int64_t fdNew = f->d * this_d;
    if (overflowsInt32(thisnNew) || overflowsInt32(thisdNew) || overflowsInt32(fnNew) ||
        overflowsInt32(fdNew)) {
        return false;
    }
    n = static_cast<int32_t>(thisnNew);
    d = static_cast<int32_t>(thisdNew);
    f->n = static_cast<int32_t>(fnNew);
    f->d = static_cast<int32_t>(fdNew);
    return true;
}

bool Fraction::add(Fraction f) {
    if (!commonDenominator(&f)) {
        return false;
    }

    const int64_t result = static_cast<int64_t>(n) + f.n;
    if (overflowsInt32(result)) {
        return false;
    }
    n = static_cast<int32_t>(result);
    simplify();
    return true;
}

bool Fraction::subtract(Fraction f) {
    if (!commonDenominator(&f)) {
        return false;
    }

    const int64_t result = static_cast<int64_t>(n) - f.n;
    if (overflowsInt32(result)) {
        return false;
    }
    n = static_cast<int32_t>(result);
    simplify();
    return true;
}

bool convertCleanApertureToRect(uint32_t imageW, uint32_t imageH, const CleanAperture& clap,
                                int32_t* left, int32_t* top, int32_t* right, int32_t* bottom) {
    // ISO/IEC 14496-12:2020, Section 12.1.4.1:
    //   For horizOff and vertOff, D shall be strictly positive and N may be
    //   positive or negative. For cleanApertureWidth and cleanApertureHeight,
    //   N shall be positive and D shall be strictly positive.
    if (clap.width.d <= 0 || clap.height.d <= 0 || clap.horizOff.d <= 0 || clap.vertOff.d <= 0 ||
        clap.width.n < 0 || clap.height.n < 0 || !clap.width.isInteger() ||
        !clap.height.isInteger() || imageW > INT32_MAX || imageH > INT32_MAX) {
        return false;
    }

    const int32_t clapW = clap.width.getInt32();
    const int32_t clapH = clap.height.getInt32();
    if (clapW == 0 || clapH == 0) {
        return false;
    }

    Fraction centerX = calculateCenter(imageW);
    Fraction centerY = calculateCenter(imageH);
    Fraction halfW(clapW, 2);
    Fraction halfH(clapH, 2);

    if (!centerX.add(clap.horizOff) || !centerX.subtract(halfW) || !centerX.isInteger() ||
        centerX.n < 0 || !centerY.add(clap.vertOff) || !centerY.subtract(halfH) ||
        !centerY.isInteger() || centerY.n < 0) {
        return false;
    }

    *left = centerX.getInt32();
    *top = centerY.getInt32();
    *right = *left + clapW;
    *bottom = *top + clapH;

    // Make sure that the crop rect is within the image bounds.
    if (*left > (UINT32_MAX - clapW) || *right > imageW || *top > (UINT32_MAX - clapH) ||
        *bottom > imageH) {
        return false;
    }
    return true;
}

}  // namespace heif
}  // namespace android
