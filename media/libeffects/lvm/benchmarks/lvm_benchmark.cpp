/*
 * Copyright 2020 The Android Open Source Project
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

#include <array>
#include <climits>
#include <cstdlib>
#include <random>
#include <vector>
#include <log/log.h>
#include <benchmark/benchmark.h>
#include <hardware/audio_effect.h>
#include <system/audio.h>

extern audio_effect_library_t AUDIO_EFFECT_LIBRARY_INFO_SYM;
constexpr effect_uuid_t kEffectUuids[] = {
        // NXP SW BassBoost
        {0x8631f300, 0x72e2, 0x11df, 0xb57e, {0x00, 0x02, 0xa5, 0xd5, 0xc5, 0x1b}},
        // NXP SW Virtualizer
        {0x1d4033c0, 0x8557, 0x11df, 0x9f2d, {0x00, 0x02, 0xa5, 0xd5, 0xc5, 0x1b}},
        // NXP SW Equalizer
        {0xce772f20, 0x847d, 0x11df, 0xbb17, {0x00, 0x02, 0xa5, 0xd5, 0xc5, 0x1b}},
        // NXP SW Volume
        {0x119341a0, 0x8469, 0x11df, 0x81f9, {0x00, 0x02, 0xa5, 0xd5, 0xc5, 0x1b}},
};

constexpr size_t kNumEffectUuids = std::size(kEffectUuids);

constexpr size_t kFrameCount = 2048;

constexpr audio_channel_mask_t kChMasks[] = {
        AUDIO_CHANNEL_INDEX_MASK_1,  AUDIO_CHANNEL_INDEX_MASK_2,  AUDIO_CHANNEL_INDEX_MASK_3,
        AUDIO_CHANNEL_INDEX_MASK_4,  AUDIO_CHANNEL_INDEX_MASK_5,  AUDIO_CHANNEL_INDEX_MASK_6,
        AUDIO_CHANNEL_INDEX_MASK_7,  AUDIO_CHANNEL_INDEX_MASK_8,  AUDIO_CHANNEL_INDEX_MASK_9,
        AUDIO_CHANNEL_INDEX_MASK_10, AUDIO_CHANNEL_INDEX_MASK_11, AUDIO_CHANNEL_INDEX_MASK_12,
        AUDIO_CHANNEL_INDEX_MASK_13, AUDIO_CHANNEL_INDEX_MASK_14, AUDIO_CHANNEL_INDEX_MASK_15,
        AUDIO_CHANNEL_INDEX_MASK_16, AUDIO_CHANNEL_INDEX_MASK_17, AUDIO_CHANNEL_INDEX_MASK_18,
        AUDIO_CHANNEL_INDEX_MASK_19, AUDIO_CHANNEL_INDEX_MASK_20, AUDIO_CHANNEL_INDEX_MASK_21,
        AUDIO_CHANNEL_INDEX_MASK_22, AUDIO_CHANNEL_INDEX_MASK_23, AUDIO_CHANNEL_INDEX_MASK_24,
};

constexpr size_t kNumChMasks = std::size(kChMasks);
constexpr int kSampleRate = 44100;
// TODO(b/131240940) Remove once effects are updated to produce mono output
constexpr size_t kMinOutputChannelCount = 2;

/*******************************************************************
 * A test result running on Pixel 3 for comparison.
 * The first parameter indicates the number of channels.
 * The second parameter indicates the effect.
 * 0: Bass Boost, 1: Virtualizer, 2: Equalizer, 3: Volume
 * -----------------------------------------------------
 * Benchmark           Time             CPU   Iterations
 * -----------------------------------------------------
 * BM_LVM/2/0       62455 ns        62283 ns        11214
 * BM_LVM/2/1      110086 ns       109751 ns         6350
 * BM_LVM/2/2       44017 ns        43890 ns        15982
 * BM_LVM/2/3       21660 ns        21596 ns        32568
 * BM_LVM/3/0       71925 ns        71698 ns         9745
 * BM_LVM/3/1      117043 ns       116754 ns         6007
 * BM_LVM/3/2       48899 ns        48781 ns        14334
 * BM_LVM/3/3       23607 ns        23540 ns        29739
 * BM_LVM/4/0       81296 ns        81095 ns         8632
 * BM_LVM/4/1      122435 ns       122132 ns         5733
 * BM_LVM/4/2       53744 ns        53612 ns        13068
 * BM_LVM/4/3       25846 ns        25783 ns        27188
 * BM_LVM/5/0       98557 ns        98311 ns         7120
 * BM_LVM/5/1      131626 ns       131269 ns         5296
 * BM_LVM/5/2       66892 ns        66732 ns        10458
 * BM_LVM/5/3       31797 ns        31721 ns        22092
 * BM_LVM/6/0      111880 ns       111596 ns         6278
 * BM_LVM/6/1      140207 ns       139846 ns         5000
 * BM_LVM/6/2       75683 ns        75496 ns         9253
 * BM_LVM/6/3       37669 ns        37571 ns        18663
 * BM_LVM/7/0      128265 ns       127957 ns         5470
 * BM_LVM/7/1      149522 ns       149159 ns         4699
 * BM_LVM/7/2       92024 ns        91798 ns         7631
 * BM_LVM/7/3       43372 ns        43268 ns        16181
 * BM_LVM/8/0      141897 ns       141548 ns         4945
 * BM_LVM/8/1      158062 ns       157661 ns         4438
 * BM_LVM/8/2       98042 ns        97801 ns         7151
 * BM_LVM/8/3       49044 ns        48923 ns        14314
 * BM_LVM/9/0      174692 ns       174228 ns         4026
 * BM_LVM/9/1      183048 ns       182560 ns         3834
 * BM_LVM/9/2      131020 ns       130675 ns         5347
 * BM_LVM/9/3       71102 ns        70915 ns         9801
 * BM_LVM/10/0     189079 ns       188576 ns         3699
 * BM_LVM/10/1     187989 ns       187472 ns         3737
 * BM_LVM/10/2     140093 ns       139717 ns         5007
 * BM_LVM/10/3      78175 ns        77963 ns         8919
 * BM_LVM/11/0     207577 ns       207007 ns         3371
 * BM_LVM/11/1     198186 ns       197640 ns         3535
 * BM_LVM/11/2     157214 ns       156786 ns         4459
 * BM_LVM/11/3      85912 ns        85681 ns         8153
 * BM_LVM/12/0     220861 ns       220265 ns         3169
 * BM_LVM/12/1     208759 ns       208184 ns         3355
 * BM_LVM/12/2     165533 ns       165088 ns         4234
 * BM_LVM/12/3      92616 ns        92364 ns         7528
 * BM_LVM/13/0     238573 ns       237920 ns         2945
 * BM_LVM/13/1     219130 ns       218520 ns         3209
 * BM_LVM/13/2     183193 ns       182692 ns         3830
 * BM_LVM/13/3     100546 ns       100274 ns         7005
 * BM_LVM/14/0     254820 ns       254135 ns         2748
 * BM_LVM/14/1     230161 ns       229530 ns         3049
 * BM_LVM/14/2     192195 ns       191671 ns         3635
 * BM_LVM/14/3     107770 ns       107477 ns         6502
 * BM_LVM/15/0     273695 ns       272954 ns         2531
 * BM_LVM/15/1     240718 ns       240049 ns         2801
 * BM_LVM/15/2     220914 ns       220309 ns         3191
 * BM_LVM/15/3     124321 ns       123978 ns         5664
 * BM_LVM/16/0     285769 ns       284969 ns         2459
 * BM_LVM/16/1     251692 ns       250983 ns         2789
 * BM_LVM/16/2     224554 ns       223917 ns         3132
 * BM_LVM/16/3     122048 ns       121706 ns         5753
 * BM_LVM/17/0     310027 ns       309154 ns         2266
 * BM_LVM/17/1     262008 ns       261259 ns         2681
 * BM_LVM/17/2     247530 ns       246827 ns         2842
 * BM_LVM/17/3     129513 ns       129146 ns         5418
 * BM_LVM/18/0     322755 ns       321844 ns         2173
 * BM_LVM/18/1     263266 ns       262514 ns         2671
 * BM_LVM/18/2     257606 ns       256875 ns         2731
 * BM_LVM/18/3     136550 ns       136164 ns         5129
 * BM_LVM/19/0     338551 ns       337591 ns         2069
 * BM_LVM/19/1     275929 ns       275134 ns         2535
 * BM_LVM/19/2     270331 ns       269554 ns         2596
 * BM_LVM/19/3     144551 ns       144138 ns         4838
 * BM_LVM/20/0     352633 ns       351617 ns         1993
 * BM_LVM/20/1     286607 ns       285713 ns         2371
 * BM_LVM/20/2     283541 ns       282689 ns         2407
 * BM_LVM/20/3     152355 ns       151904 ns         4604
 * BM_LVM/21/0     370557 ns       369456 ns         1889
 * BM_LVM/21/1     298251 ns       297351 ns         2352
 * BM_LVM/21/2     296806 ns       295917 ns         2364
 * BM_LVM/21/3     160212 ns       159735 ns         4330
 * BM_LVM/22/0     386431 ns       385224 ns         1826
 * BM_LVM/22/1     308901 ns       307925 ns         2273
 * BM_LVM/22/2     309077 ns       308140 ns         2274
 * BM_LVM/22/3     167492 ns       166987 ns         4194
 * BM_LVM/23/0     404455 ns       403218 ns         1729
 * BM_LVM/23/1     322026 ns       321014 ns         2187
 * BM_LVM/23/2     326616 ns       325623 ns         2152
 * BM_LVM/23/3     175873 ns       175328 ns         4007
 * BM_LVM/24/0     416949 ns       415676 ns         1684
 * BM_LVM/24/1     329803 ns       328779 ns         2128
 * BM_LVM/24/2     337648 ns       336626 ns         2080
 * BM_LVM/24/3     183192 ns       182634 ns         3824
 *******************************************************************/

static void BM_LVM(benchmark::State& state) {
    const size_t chMask = kChMasks[state.range(0) - 1];
    const effect_uuid_t uuid = kEffectUuids[state.range(1)];
    const size_t channelCount = audio_channel_count_from_out_mask(chMask);

    // Initialize input buffer with deterministic pseudo-random values
    std::minstd_rand gen(chMask);
    std::uniform_real_distribution<> dis(-1.0f, 1.0f);
    std::vector<float> input(kFrameCount * channelCount);
    for (auto& in : input) {
        in = dis(gen);
    }

    effect_handle_t effectHandle = nullptr;
    if (int status = AUDIO_EFFECT_LIBRARY_INFO_SYM.create_effect(&uuid, 1, 1, &effectHandle);
        status != 0) {
        ALOGE("create_effect returned an error = %d\n", status);
        return;
    }

    effect_config_t config{};
    config.inputCfg.samplingRate = config.outputCfg.samplingRate = kSampleRate;
    config.inputCfg.channels = config.outputCfg.channels = chMask;
    config.inputCfg.format = config.outputCfg.format = AUDIO_FORMAT_PCM_FLOAT;

    int reply = 0;
    uint32_t replySize = sizeof(reply);
    if (int status = (*effectHandle)
                             ->command(effectHandle, EFFECT_CMD_SET_CONFIG, sizeof(effect_config_t),
                                       &config, &replySize, &reply);
        status != 0) {
        ALOGE("command returned an error = %d\n", status);
        return;
    }

    if (int status =
                (*effectHandle)
                        ->command(effectHandle, EFFECT_CMD_ENABLE, 0, nullptr, &replySize, &reply);
        status != 0) {
        ALOGE("Command enable call returned error %d\n", reply);
        return;
    }

    // Run the test
    for (auto _ : state) {
        std::vector<float> output(kFrameCount * std::max(channelCount, kMinOutputChannelCount));

        benchmark::DoNotOptimize(input.data());
        benchmark::DoNotOptimize(output.data());

        audio_buffer_t inBuffer = {.frameCount = kFrameCount, .f32 = input.data()};
        audio_buffer_t outBuffer = {.frameCount = kFrameCount, .f32 = output.data()};
        (*effectHandle)->process(effectHandle, &inBuffer, &outBuffer);

        benchmark::ClobberMemory();
    }

    state.SetComplexityN(state.range(0));

    if (int status = AUDIO_EFFECT_LIBRARY_INFO_SYM.release_effect(effectHandle); status != 0) {
        ALOGE("release_effect returned an error = %d\n", status);
        return;
    }
}

static void LVMArgs(benchmark::internal::Benchmark* b) {
    // TODO(b/131240940) Test single channel once effects are updated to process mono data
    for (int i = 2; i <= kNumChMasks; i++) {
        for (int j = 0; j < kNumEffectUuids; ++j) {
            b->Args({i, j});
        }
    }
}

BENCHMARK(BM_LVM)->Apply(LVMArgs);

BENCHMARK_MAIN();
