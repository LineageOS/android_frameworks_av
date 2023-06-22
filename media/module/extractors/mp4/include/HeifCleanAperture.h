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

#ifndef HEIF_CLEAN_APERTURE_H_
#define HEIF_CLEAN_APERTURE_H_

#include <stdint.h>

namespace android {
namespace heif {

struct Fraction {
    Fraction() = default;
    Fraction(int32_t n, int32_t d);

    void simplify();
    bool commonDenominator(Fraction* f);
    bool add(Fraction f);
    bool subtract(Fraction f);
    bool isInteger() const { return n % d == 0; }
    int32_t getInt32() const { return n / d; }
    int32_t n;
    int32_t d;
};

struct CleanAperture {
    Fraction width;
    Fraction height;
    Fraction horizOff;
    Fraction vertOff;
};

// Converts the CleanAperture value into a rectangle with bounds left, top, right and bottom.
// Returns true on success, false otherwise.
bool convertCleanApertureToRect(uint32_t imageW, uint32_t imageH, const CleanAperture& image,
                                int32_t* left, int32_t* top, int32_t* right, int32_t* bottom);

}  // namespace heif
}  // namespace android

#endif  // HEIF_CLEAN_APERTURE_H_
