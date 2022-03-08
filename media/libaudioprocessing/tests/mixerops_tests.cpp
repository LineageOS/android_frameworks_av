/*
 * Copyright (C) 2021 The Android Open Source Project
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

//#define LOG_NDEBUG 0
#define LOG_TAG "mixerop_tests"
#include <log/log.h>

#include <inttypes.h>
#include <type_traits>

#include <../AudioMixerOps.h>
#include <gtest/gtest.h>

using namespace android;

// Note: gtest templated tests require typenames, not integers.
template <int MIXTYPE, int NCHAN>
class MixerOpsBasicTest {
public:
    static void testStereoVolume() {
        using namespace android::audio_utils::channels;

        constexpr size_t FRAME_COUNT = 1000;
        constexpr size_t SAMPLE_COUNT = FRAME_COUNT * NCHAN;

        const float in[SAMPLE_COUNT] = {[0 ... (SAMPLE_COUNT - 1)] = 1.f};

        AUDIO_GEOMETRY_SIDE sides[NCHAN];
        size_t i = 0;
        unsigned channel = canonicalChannelMaskFromCount(NCHAN);
        constexpr unsigned LFE_LFE2 =
                AUDIO_CHANNEL_OUT_LOW_FREQUENCY | AUDIO_CHANNEL_OUT_LOW_FREQUENCY_2;
        bool has_LFE_LFE2 = (channel & LFE_LFE2) == LFE_LFE2;
        while (channel != 0) {
            const int index = __builtin_ctz(channel);
            if (has_LFE_LFE2 && (1 << index) == AUDIO_CHANNEL_OUT_LOW_FREQUENCY) {
                sides[i++] = AUDIO_GEOMETRY_SIDE_LEFT; // special case
            } else if (has_LFE_LFE2 && (1 << index) == AUDIO_CHANNEL_OUT_LOW_FREQUENCY_2) {
                sides[i++] = AUDIO_GEOMETRY_SIDE_RIGHT; // special case
            } else {
                sides[i++] = sideFromChannelIdx(index);
            }
            channel &= ~(1 << index);
        }

        float vola[2] = {1.f, 0.f}; // left volume at max.
        float out[SAMPLE_COUNT]{};
        float aux[FRAME_COUNT]{};
        float volaux = 0.5;
        {
            volumeMulti<MIXTYPE, NCHAN>(out, FRAME_COUNT, in, aux, vola, volaux);
            const float *outp = out;
            const float *auxp = aux;
            const float left = vola[0];
            const float center = (vola[0] + vola[1]) * 0.5;
            const float right = vola[1];
            for (size_t i = 0; i < FRAME_COUNT; ++i) {
                for (size_t j = 0; j < NCHAN; ++j) {
                    const float audio = *outp++;
                    if (sides[j] == AUDIO_GEOMETRY_SIDE_LEFT) {
                        EXPECT_EQ(left, audio);
                    } else if (sides[j] == AUDIO_GEOMETRY_SIDE_CENTER) {
                        EXPECT_EQ(center, audio);
                    } else {
                        EXPECT_EQ(right, audio);
                    }
                }
                EXPECT_EQ(volaux, *auxp++);  // works if all channels contain 1.f
            }
        }
        float volb[2] = {0.f, 0.5f}; // right volume at half max.
        {
            // this accumulates into out, aux.
            // float out[SAMPLE_COUNT]{};
            // float aux[FRAME_COUNT]{};
            volumeMulti<MIXTYPE, NCHAN>(out, FRAME_COUNT, in, aux, volb, volaux);
            const float *outp = out;
            const float *auxp = aux;
            const float left = vola[0] + volb[0];
            const float center = (vola[0] + vola[1] + volb[0] + volb[1]) * 0.5;
            const float right = vola[1] + volb[1];
            for (size_t i = 0; i < FRAME_COUNT; ++i) {
                for (size_t j = 0; j < NCHAN; ++j) {
                    const float audio = *outp++;
                    if (sides[j] == AUDIO_GEOMETRY_SIDE_LEFT) {
                        EXPECT_EQ(left, audio);
                    } else if (sides[j] == AUDIO_GEOMETRY_SIDE_CENTER) {
                        EXPECT_EQ(center, audio);
                    } else {
                        EXPECT_EQ(right, audio);
                    }
                }
                // aux is accumulated so 2x the amplitude
                EXPECT_EQ(volaux * 2.f, *auxp++);  // works if all channels contain 1.f
            }
        }

        { // test aux as derived from out.
            // AUX channel is the weighted sum of all of the output channels prior to volume
            // adjustment.  We must set L and R to the same volume to allow computation
            // of AUX from the output values.
            const float volmono = 0.25f;
            const float vollr[2] = {volmono, volmono}; // all the same.
            float out[SAMPLE_COUNT]{};
            float aux[FRAME_COUNT]{};
            volumeMulti<MIXTYPE, NCHAN>(out, FRAME_COUNT, in, aux, vollr, volaux);
            const float *outp = out;
            const float *auxp = aux;
            for (size_t i = 0; i < FRAME_COUNT; ++i) {
                float accum = 0.f;
                for (size_t j = 0; j < NCHAN; ++j) {
                    accum += *outp++;
                }
                EXPECT_EQ(accum / NCHAN * volaux / volmono, *auxp++);
            }
        }
    }
};

TEST(mixerops, stereovolume_1) { // Note: mono not used for output sinks yet.
    MixerOpsBasicTest<MIXTYPE_MULTI_STEREOVOL, 1>::testStereoVolume();
}
TEST(mixerops, stereovolume_2) {
    MixerOpsBasicTest<MIXTYPE_MULTI_STEREOVOL, 2>::testStereoVolume();
}
TEST(mixerops, stereovolume_3) {
    MixerOpsBasicTest<MIXTYPE_MULTI_STEREOVOL, 3>::testStereoVolume();
}
TEST(mixerops, stereovolume_4) {
    MixerOpsBasicTest<MIXTYPE_MULTI_STEREOVOL, 4>::testStereoVolume();
}
TEST(mixerops, stereovolume_5) {
    MixerOpsBasicTest<MIXTYPE_MULTI_STEREOVOL, 5>::testStereoVolume();
}
TEST(mixerops, stereovolume_6) {
    MixerOpsBasicTest<MIXTYPE_MULTI_STEREOVOL, 6>::testStereoVolume();
}
TEST(mixerops, stereovolume_7) {
    MixerOpsBasicTest<MIXTYPE_MULTI_STEREOVOL, 7>::testStereoVolume();
}
TEST(mixerops, stereovolume_8) {
    MixerOpsBasicTest<MIXTYPE_MULTI_STEREOVOL, 8>::testStereoVolume();
}
TEST(mixerops, stereovolume_12) {
    if constexpr (FCC_LIMIT >= 12) { // NOTE: FCC_LIMIT is an enum, so can't #if
        MixerOpsBasicTest<MIXTYPE_MULTI_STEREOVOL, 12>::testStereoVolume();
    }
}
TEST(mixerops, stereovolume_24) {
    if constexpr (FCC_LIMIT >= 24) {
        MixerOpsBasicTest<MIXTYPE_MULTI_STEREOVOL, 24>::testStereoVolume();
    }
}
TEST(mixerops, channel_equivalence) {
    // we must match the constexpr function with the system determined channel mask from count.
    for (size_t i = 0; i < FCC_LIMIT; ++i) {
        const audio_channel_mask_t actual = canonicalChannelMaskFromCount(i);
        const audio_channel_mask_t system = audio_channel_out_mask_from_count(i);
        if (system == AUDIO_CHANNEL_INVALID) continue;
        EXPECT_EQ(system, actual);
    }
}
