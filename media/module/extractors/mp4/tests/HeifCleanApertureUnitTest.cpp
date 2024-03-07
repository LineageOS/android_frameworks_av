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

#include <stdint.h>

#include <HeifCleanAperture.h>
#include <gtest/gtest.h>

namespace {

using android::heif::CleanAperture;
using android::heif::convertCleanApertureToRect;
using android::heif::Fraction;

struct InvalidClapPropertyParam {
    uint32_t width;
    uint32_t height;
    CleanAperture clap;
};

const InvalidClapPropertyParam kInvalidClapPropertyTestParams[] = {
        // Zero or negative denominators.
        {120, 160, {Fraction(96, 0), Fraction(132, 1), Fraction(0, 1), Fraction(0, 1)}},
        {120, 160, {Fraction(96, -1), Fraction(132, 1), Fraction(0, 1), Fraction(0, 1)}},
        {120, 160, {Fraction(96, 1), Fraction(132, 0), Fraction(0, 1), Fraction(0, 1)}},
        {120, 160, {Fraction(96, 1), Fraction(132, -1), Fraction(0, 1), Fraction(0, 1)}},
        {120, 160, {Fraction(96, 1), Fraction(132, 1), Fraction(0, 0), Fraction(0, 1)}},
        {120, 160, {Fraction(96, 1), Fraction(132, 1), Fraction(0, -1), Fraction(0, 1)}},
        {120, 160, {Fraction(96, 1), Fraction(132, 1), Fraction(0, 1), Fraction(0, 0)}},
        {120, 160, {Fraction(96, 1), Fraction(132, 1), Fraction(0, 1), Fraction(0, -1)}},
        // Zero or negative clean aperture width or height.
        {120, 160, {Fraction(-96, 1), Fraction(132, 1), Fraction(0, 1), Fraction(0, 1)}},
        {120, 160, {Fraction(0, 1), Fraction(132, 1), Fraction(0, 1), Fraction(0, 1)}},
        {120, 160, {Fraction(96, 1), Fraction(-132, 1), Fraction(0, 1), Fraction(0, 1)}},
        {120, 160, {Fraction(96, 1), Fraction(0, 1), Fraction(0, 1), Fraction(0, 1)}},
        // Clean aperture width or height is not an integer.
        {120, 160, {Fraction(96, 5), Fraction(132, 1), Fraction(0, 1), Fraction(0, 1)}},
        {120, 160, {Fraction(96, 1), Fraction(132, 5), Fraction(0, 1), Fraction(0, 1)}},
        {722, 1024, {Fraction(385, 1), Fraction(330, 1), Fraction(103, 1), Fraction(-308, 1)}},
        {1024, 722, {Fraction(330, 1), Fraction(385, 1), Fraction(-308, 1), Fraction(103, 1)}},
};

using InvalidClapPropertyTest = ::testing::TestWithParam<InvalidClapPropertyParam>;

INSTANTIATE_TEST_SUITE_P(Parameterized, InvalidClapPropertyTest,
                         ::testing::ValuesIn(kInvalidClapPropertyTestParams));

// Negative tests for the convertCleanApertureToRect() function.
TEST_P(InvalidClapPropertyTest, ValidateClapProperty) {
    const InvalidClapPropertyParam& param = GetParam();
    int32_t left, top, right, bottom;
    EXPECT_FALSE(convertCleanApertureToRect(param.width, param.height, param.clap, &left, &top,
                                            &right, &bottom));
}

struct ValidClapPropertyParam {
    uint32_t width;
    uint32_t height;
    CleanAperture clap;

    int32_t left;
    int32_t top;
    int32_t right;
    int32_t bottom;
};

const ValidClapPropertyParam kValidClapPropertyTestParams[] = {
        {120,
         160,
         {Fraction(96, 1), Fraction(132, 1), Fraction(0, 1), Fraction(0, 1)},
         12,
         14,
         108,
         146},
        {120,
         160,
         {Fraction(60, 1), Fraction(80, 1), Fraction(-30, 1), Fraction(-40, 1)},
         0,
         0,
         60,
         80},
};

using ValidClapPropertyTest = ::testing::TestWithParam<ValidClapPropertyParam>;

INSTANTIATE_TEST_SUITE_P(Parameterized, ValidClapPropertyTest,
                         ::testing::ValuesIn(kValidClapPropertyTestParams));

// Positive tests for the convertCleanApertureToRect() function.
TEST_P(ValidClapPropertyTest, ValidateClapProperty) {
    const ValidClapPropertyParam& param = GetParam();
    int32_t left, top, right, bottom;
    EXPECT_TRUE(convertCleanApertureToRect(param.width, param.height, param.clap, &left, &top,
                                           &right, &bottom));
    EXPECT_EQ(left, param.left);
    EXPECT_EQ(top, param.top);
    EXPECT_EQ(right, param.right);
    EXPECT_EQ(bottom, param.bottom);
}

}  // namespace
