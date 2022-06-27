/*
 * Copyright 2018 The Android Open Source Project
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

/*
 * Test FlowGraph
 *
 * This file also tests a few different conversion techniques because
 * sometimes that have caused compiler bugs.
 */

#include <iostream>

#include <gtest/gtest.h>

#include "flowgraph/ClipToRange.h"
#include "flowgraph/MonoBlend.h"
#include "flowgraph/MonoToMultiConverter.h"
#include "flowgraph/SourceFloat.h"
#include "flowgraph/RampLinear.h"
#include "flowgraph/SinkFloat.h"
#include "flowgraph/SinkI16.h"
#include "flowgraph/SinkI24.h"
#include "flowgraph/SinkI32.h"
#include "flowgraph/SourceI16.h"
#include "flowgraph/SourceI24.h"

using namespace FLOWGRAPH_OUTER_NAMESPACE::flowgraph;

constexpr int kBytesPerI24Packed = 3;

constexpr int kNumSamples = 8;
constexpr std::array<float, kNumSamples> kInputFloat = {
    1.0f, 0.5f, -0.25f, -1.0f,
    0.0f, 53.9f, -87.2f, -1.02f};

// Corresponding PCM values  as integers.
constexpr std::array<int16_t, kNumSamples>  kExpectedI16 = {
    INT16_MAX, 1 << 14, INT16_MIN / 4, INT16_MIN,
    0, INT16_MAX, INT16_MIN, INT16_MIN};

constexpr std::array<int32_t, kNumSamples>  kExpectedI32 = {
    INT32_MAX, 1 << 30, INT32_MIN / 4, INT32_MIN,
    0, INT32_MAX, INT32_MIN, INT32_MIN};

// =================================== FLOAT to I16 ==============

// Simple test that tries to reproduce a Clang compiler bug.
__attribute__((noinline))
void local_convert_float_to_int16(const float *input,
                                  int16_t *output,
                                  int count) {
    for (int i = 0; i < count; i++) {
        int32_t n = (int32_t) (*input++ * 32768.0f);
        *output++ = std::min(INT16_MAX, std::max(INT16_MIN, n)); // clip
    }
}

TEST(test_flowgraph, local_convert_float_int16) {
    std::array<int16_t, kNumSamples> output;

    // Do it inline, which will probably work even with the buggy compiler.
    // This validates the expected data.
    const float *in = kInputFloat.data();
    int16_t *out = output.data();
    output.fill(777);
    for (int i = 0; i < kNumSamples; i++) {
        int32_t n = (int32_t) (*in++ * 32768.0f);
        *out++ = std::min(INT16_MAX, std::max(INT16_MIN, n)); // clip
    }
    for (int i = 0; i < kNumSamples; i++) {
        EXPECT_EQ(kExpectedI16.at(i), output.at(i)) << ", i = " << i;
    }

    // Convert audio signal using the function.
    output.fill(777);
    local_convert_float_to_int16(kInputFloat.data(), output.data(), kNumSamples);
    for (int i = 0; i < kNumSamples; i++) {
        EXPECT_EQ(kExpectedI16.at(i), output.at(i)) << ", i = " << i;
    }
}

TEST(test_flowgraph, module_sinki16) {
    static constexpr int kNumSamples = 8;
    std::array<int16_t, kNumSamples + 10> output; // larger than input

    SourceFloat sourceFloat{1};
    SinkI16 sinkI16{1};

    sourceFloat.setData(kInputFloat.data(), kNumSamples);
    sourceFloat.output.connect(&sinkI16.input);

    output.fill(777);
    int32_t numRead = sinkI16.read(output.data(), output.size());
    ASSERT_EQ(kNumSamples, numRead);
    for (int i = 0; i < numRead; i++) {
        EXPECT_EQ(kExpectedI16.at(i), output.at(i)) << ", i = " << i;
    }
}

// =================================== FLOAT to I32 ==============
// Simple test that tries to reproduce a Clang compiler bug.
__attribute__((noinline))
static int32_t clamp32FromFloat(float f)
{
    static const float scale = (float)(1UL << 31);
    static const float limpos = 1.;
    static const float limneg = -1.;

    if (f <= limneg) {
        return INT32_MIN;
    } else if (f >= limpos) {
        return INT32_MAX;
    }
    f *= scale;
    /* integer conversion is through truncation (though int to float is not).
     * ensure that we round to nearest, ties away from 0.
     */
    return f > 0 ? f + 0.5 : f - 0.5;
}

void local_convert_float_to_int32(const float *input,
                                  int32_t *output,
                                  int count) {
    for (int i = 0; i < count; i++) {
        *output++ = clamp32FromFloat(*input++);
    }
}

TEST(test_flowgraph, simple_convert_float_int32) {
    std::array<int32_t, kNumSamples> output;

    // Do it inline, which will probably work even with a buggy compiler.
    // This validates the expected data.
    const float *in = kInputFloat.data();
    output.fill(777);
    int32_t *out = output.data();
    for (int i = 0; i < kNumSamples; i++) {
        int64_t n = (int64_t) (*in++ * 2147483648.0f);
        *out++ = (int32_t)std::min((int64_t)INT32_MAX,
                                   std::max((int64_t)INT32_MIN, n)); // clip
    }
    for (int i = 0; i < kNumSamples; i++) {
        EXPECT_EQ(kExpectedI32.at(i), output.at(i)) << ", i = " << i;
    }
}

TEST(test_flowgraph, local_convert_float_int32) {
    std::array<int32_t, kNumSamples> output;
    // Convert audio signal using the function.
    output.fill(777);
    local_convert_float_to_int32(kInputFloat.data(), output.data(), kNumSamples);
    for (int i = 0; i < kNumSamples; i++) {
        EXPECT_EQ(kExpectedI32.at(i), output.at(i)) << ", i = " << i;
    }
}

TEST(test_flowgraph, module_sinki32) {
    std::array<int32_t, kNumSamples + 10> output; // larger than input

    SourceFloat sourceFloat{1};
    SinkI32 sinkI32{1};

    sourceFloat.setData(kInputFloat.data(), kNumSamples);
    sourceFloat.output.connect(&sinkI32.input);

    output.fill(777);
    int32_t numRead = sinkI32.read(output.data(), output.size());
    ASSERT_EQ(kNumSamples, numRead);
    for (int i = 0; i < numRead; i++) {
        EXPECT_EQ(kExpectedI32.at(i), output.at(i)) << ", i = " << i;
    }
}

TEST(test_flowgraph, module_mono_to_stereo) {
    static const float input[] = {1.0f, 2.0f, 3.0f};
    float output[100] = {};
    SourceFloat sourceFloat{1};
    MonoToMultiConverter monoToStereo{2};
    SinkFloat sinkFloat{2};

    sourceFloat.setData(input, 3);

    sourceFloat.output.connect(&monoToStereo.input);
    monoToStereo.output.connect(&sinkFloat.input);

    int32_t numRead = sinkFloat.read(output, 8);
    ASSERT_EQ(3, numRead);
    EXPECT_EQ(input[0], output[0]);
    EXPECT_EQ(input[0], output[1]);
    EXPECT_EQ(input[1], output[2]);
    EXPECT_EQ(input[1], output[3]);
}

TEST(test_flowgraph, module_ramp_linear) {
    constexpr int singleNumOutput = 1;
    constexpr int rampSize = 5;
    constexpr int numOutput = 100;
    constexpr float value = 1.0f;
    constexpr float initialTarget = 10.0f;
    constexpr float finalTarget = 100.0f;
    constexpr float tolerance = 0.0001f; // arbitrary
    float output[numOutput] = {};
    RampLinear rampLinear{1};
    SinkFloat sinkFloat{1};

    rampLinear.input.setValue(value);
    rampLinear.setLengthInFrames(rampSize);
    rampLinear.output.connect(&sinkFloat.input);

    // Check that the values go to the initial target instantly.
    rampLinear.setTarget(initialTarget);
    int32_t singleNumRead = sinkFloat.read(output, singleNumOutput);
    ASSERT_EQ(singleNumRead, singleNumOutput);
    EXPECT_NEAR(value * initialTarget, output[0], tolerance);

    // Now set target and check that the linear ramp works as expected.
    rampLinear.setTarget(finalTarget);
    int32_t numRead = sinkFloat.read(output, numOutput);
    const float incrementSize = (finalTarget - initialTarget) / rampSize;
    ASSERT_EQ(numOutput, numRead);

    int i = 0;
    for (; i < rampSize; i++) {
        float expected = value * (initialTarget + i * incrementSize);
        EXPECT_NEAR(expected, output[i], tolerance);
    }
    for (; i < numOutput; i++) {
        float expected = value * finalTarget;
        EXPECT_NEAR(expected, output[i], tolerance);
    }
}

// It is easiest to represent packed 24-bit data as a byte array.
// This test will read from input, convert to float, then write
// back to output as bytes.
TEST(test_flowgraph, module_packed_24) {
    static const uint8_t input[] = {0x01, 0x23, 0x45,
                                    0x67, 0x89, 0xAB,
                                    0xCD, 0xEF, 0x5A};
    uint8_t output[99] = {};
    SourceI24 sourceI24{1};
    SinkI24 sinkI24{1};

    int numInputFrames = sizeof(input) / kBytesPerI24Packed;
    sourceI24.setData(input, numInputFrames);
    sourceI24.output.connect(&sinkI24.input);

    int32_t numRead = sinkI24.read(output, sizeof(output) / kBytesPerI24Packed);
    ASSERT_EQ(numInputFrames, numRead);
    for (size_t i = 0; i < sizeof(input); i++) {
        EXPECT_EQ(input[i], output[i]);
    }
}

TEST(test_flowgraph, module_clip_to_range) {
    constexpr float myMin = -2.0f;
    constexpr float myMax = 1.5f;

    static const float input[] = {-9.7, 0.5f, -0.25, 1.0f, 12.3};
    static const float expected[] = {myMin, 0.5f, -0.25, 1.0f, myMax};
    float output[100];
    SourceFloat sourceFloat{1};
    ClipToRange clipper{1};
    SinkFloat sinkFloat{1};

    int numInputFrames = sizeof(input) / sizeof(input[0]);
    sourceFloat.setData(input, numInputFrames);

    clipper.setMinimum(myMin);
    clipper.setMaximum(myMax);

    sourceFloat.output.connect(&clipper.input);
    clipper.output.connect(&sinkFloat.input);

    int numOutputFrames = sizeof(output) / sizeof(output[0]);
    int32_t numRead = sinkFloat.read(output, numOutputFrames);
    ASSERT_EQ(numInputFrames, numRead);
    constexpr float tolerance = 0.000001f; // arbitrary
    for (int i = 0; i < numRead; i++) {
        EXPECT_NEAR(expected[i], output[i], tolerance);
    }
}

TEST(test_flowgraph, module_mono_blend) {
    // Two channel to two channel with 3 inputs and outputs.
    constexpr int numChannels = 2;
    constexpr int numFrames = 3;

    static const float input[] = {-0.7, 0.5, -0.25, 1.25, 1000, 2000};
    static const float expected[] = {-0.1, -0.1, 0.5, 0.5, 1500, 1500};
    float output[100];
    SourceFloat sourceFloat{numChannels};
    MonoBlend monoBlend{numChannels};
    SinkFloat sinkFloat{numChannels};

    sourceFloat.setData(input, numFrames);

    sourceFloat.output.connect(&monoBlend.input);
    monoBlend.output.connect(&sinkFloat.input);

    int32_t numRead = sinkFloat.read(output, numFrames);
    ASSERT_EQ(numRead, numFrames);
    constexpr float tolerance = 0.000001f; // arbitrary
    for (int i = 0; i < numRead; i++) {
        EXPECT_NEAR(expected[i], output[i], tolerance);
    }
}

