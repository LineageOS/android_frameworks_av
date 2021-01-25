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

/*******************************************************************
 * A test result running on Pixel 3 for comparison.
 * The first parameter indicates the channel mask index.
 * The second parameter indicates the effect index.
 * 0: Automatic Gain Control,
 * 1: Acoustic Echo Canceler,
 * 2: Noise Suppressor,
 * 3: Automatic Gain Control 2
 * ---------------------------------------------------------------
 * Benchmark                     Time             CPU   Iterations
 * ---------------------------------------------------------------
 * BM_PREPROCESSING/1/0       48179 ns        48041 ns        12349
 * BM_PREPROCESSING/1/1       57559 ns        57403 ns        12270
 * BM_PREPROCESSING/1/2       17524 ns        17466 ns        39982
 * BM_PREPROCESSING/1/3        2608 ns         2599 ns       268399
 * BM_PREPROCESSING/2/0       94198 ns        93926 ns         7470
 * BM_PREPROCESSING/2/1      109196 ns       108899 ns         6459
 * BM_PREPROCESSING/2/2       34098 ns        33986 ns        20576
 * BM_PREPROCESSING/2/3        3231 ns         3221 ns       216606
 * BM_PREPROCESSING/3/0      141532 ns       141132 ns         5030
 * BM_PREPROCESSING/3/1      161199 ns       160745 ns         4387
 * BM_PREPROCESSING/3/2       50663 ns        50535 ns        13619
 * BM_PREPROCESSING/3/3        3967 ns         3955 ns       177005
 * BM_PREPROCESSING/4/0      187032 ns       186486 ns         3706
 * BM_PREPROCESSING/4/1      212872 ns       212264 ns         3304
 * BM_PREPROCESSING/4/2       67649 ns        67476 ns        10128
 * BM_PREPROCESSING/4/3        4728 ns         4713 ns       148547
 * BM_PREPROCESSING/5/0      233874 ns       233188 ns         2954
 * BM_PREPROCESSING/5/1      262798 ns       262052 ns         2680
 * BM_PREPROCESSING/5/2       84592 ns        84368 ns         8203
 * BM_PREPROCESSING/5/3        5472 ns         5455 ns       127784
 * BM_PREPROCESSING/6/0      284777 ns       283911 ns         2468
 * BM_PREPROCESSING/6/1      315631 ns       314726 ns         2233
 * BM_PREPROCESSING/6/2      101200 ns       100931 ns         6802
 * BM_PREPROCESSING/6/3        6152 ns         6133 ns       113951
 * BM_PREPROCESSING/7/0      327207 ns       326153 ns         2112
 * BM_PREPROCESSING/7/1      367510 ns       366410 ns         1915
 * BM_PREPROCESSING/7/2      118574 ns       118250 ns         5795
 * BM_PREPROCESSING/7/3        6956 ns         6935 ns       100783
 * BM_PREPROCESSING/8/0      372603 ns       371470 ns         1880
 * BM_PREPROCESSING/8/1      418882 ns       417625 ns         1685
 * BM_PREPROCESSING/8/2      136155 ns       135777 ns         4986
 * BM_PREPROCESSING/8/3        7734 ns         7711 ns        91581
 * BM_PREPROCESSING/9/0      424795 ns       423464 ns         1657
 * BM_PREPROCESSING/9/1      469073 ns       467687 ns         1506
 * BM_PREPROCESSING/9/2      153170 ns       152737 ns         4519
 * BM_PREPROCESSING/9/3        8393 ns         8363 ns        83603
 * BM_PREPROCESSING/10/0     472440 ns       470926 ns         1489
 * BM_PREPROCESSING/10/1     516984 ns       515480 ns         1000
 * BM_PREPROCESSING/10/2     168802 ns       168348 ns         4097
 * BM_PREPROCESSING/10/3       9127 ns         9100 ns        76913
 * BM_PREPROCESSING/11/0     509690 ns       508113 ns         1360
 * BM_PREPROCESSING/11/1     569076 ns       567390 ns         1310
 * BM_PREPROCESSING/11/2     185678 ns       185165 ns         3729
 * BM_PREPROCESSING/11/3       9789 ns         9760 ns        71342
 * BM_PREPROCESSING/12/0     563858 ns       562108 ns         1270
 * BM_PREPROCESSING/12/1     619656 ns       617791 ns         1198
 * BM_PREPROCESSING/12/2     202882 ns       202316 ns         3406
 * BM_PREPROCESSING/12/3      10610 ns        10579 ns        66287
 * BM_PREPROCESSING/13/0     602944 ns       601094 ns         1167
 * BM_PREPROCESSING/13/1     675401 ns       673293 ns         1107
 * BM_PREPROCESSING/13/2     220677 ns       220051 ns         3131
 * BM_PREPROCESSING/13/3      11301 ns        11265 ns        62022
 * BM_PREPROCESSING/14/0     659495 ns       657375 ns         1071
 * BM_PREPROCESSING/14/1     726551 ns       724295 ns         1024
 * BM_PREPROCESSING/14/2     238595 ns       237922 ns         2901
 * BM_PREPROCESSING/14/3      11941 ns        11906 ns        58788
 * BM_PREPROCESSING/15/0     698377 ns       696134 ns         1014
 * BM_PREPROCESSING/15/1     772532 ns       770217 ns          960
 * BM_PREPROCESSING/15/2     253219 ns       252505 ns         2736
 * BM_PREPROCESSING/15/3      12669 ns        12632 ns        55452
 * BM_PREPROCESSING/16/0     742054 ns       739708 ns          936
 * BM_PREPROCESSING/16/1     828029 ns       825484 ns          902
 * BM_PREPROCESSING/16/2     272419 ns       271658 ns         2545
 * BM_PREPROCESSING/16/3      13473 ns        13431 ns        52088
 * BM_PREPROCESSING/17/0     794444 ns       791916 ns          891
 * BM_PREPROCESSING/17/1     879429 ns       876704 ns          841
 * BM_PREPROCESSING/17/2     290059 ns       289216 ns         2391
 * BM_PREPROCESSING/17/3      14257 ns        14210 ns        49425
 * BM_PREPROCESSING/18/0     852221 ns       849430 ns          839
 * BM_PREPROCESSING/18/1     931121 ns       928308 ns          799
 * BM_PREPROCESSING/18/2     307995 ns       307104 ns         2253
 * BM_PREPROCESSING/18/3      14947 ns        14900 ns        46872
 * BM_PREPROCESSING/19/0     888752 ns       885893 ns          781
 * BM_PREPROCESSING/19/1     983398 ns       980285 ns          756
 * BM_PREPROCESSING/19/2     325669 ns       324705 ns         2132
 * BM_PREPROCESSING/19/3      15677 ns        15629 ns        44693
 * BM_PREPROCESSING/20/0     933651 ns       930697 ns          746
 * BM_PREPROCESSING/20/1    1033396 ns      1030235 ns          713
 * BM_PREPROCESSING/20/2     342081 ns       341077 ns         2031
 * BM_PREPROCESSING/20/3      16422 ns        16370 ns        42622
 * BM_PREPROCESSING/21/0     982521 ns       979388 ns          706
 * BM_PREPROCESSING/21/1    1085340 ns      1081926 ns          682
 * BM_PREPROCESSING/21/2     360862 ns       359810 ns         1926
 * BM_PREPROCESSING/21/3      17161 ns        17107 ns        40885
 * BM_PREPROCESSING/22/0    1043560 ns      1040219 ns          678
 * BM_PREPROCESSING/22/1    1137203 ns      1133687 ns          653
 * BM_PREPROCESSING/22/2     377421 ns       376315 ns         1841
 * BM_PREPROCESSING/22/3      17903 ns        17847 ns        38984
 * BM_PREPROCESSING/23/0    1090097 ns      1086523 ns          650
 * BM_PREPROCESSING/23/1    1199267 ns      1194231 ns          619
 * BM_PREPROCESSING/23/2     395429 ns       394263 ns         1759
 * BM_PREPROCESSING/23/3      18879 ns        18818 ns        37242
 * BM_PREPROCESSING/24/0    1128638 ns      1125076 ns          629
 * BM_PREPROCESSING/24/1    1239909 ns      1236019 ns          598
 * BM_PREPROCESSING/24/2     414294 ns       413055 ns         1680
 * BM_PREPROCESSING/24/3      19583 ns        19521 ns        35771
 *******************************************************************/

#include <audio_effects/effect_aec.h>
#include <audio_effects/effect_agc.h>
#include <array>
#include <climits>
#include <cstdlib>
#include <random>
#include <vector>
#include <audio_effects/effect_agc2.h>
#include <audio_effects/effect_ns.h>
#include <benchmark/benchmark.h>
#include <hardware/audio_effect.h>
#include <log/log.h>
#include <sys/stat.h>
#include <system/audio.h>

extern audio_effect_library_t AUDIO_EFFECT_LIBRARY_INFO_SYM;

constexpr int kSampleRate = 16000;
constexpr float kTenMilliSecVal = 0.01;
constexpr unsigned int kStreamDelayMs = 0;
constexpr effect_uuid_t kEffectUuids[] = {
        // agc uuid
        {0xaa8130e0, 0x66fc, 0x11e0, 0xbad0, {0x00, 0x02, 0xa5, 0xd5, 0xc5, 0x1b}},
        // aec uuid
        {0xbb392ec0, 0x8d4d, 0x11e0, 0xa896, {0x00, 0x02, 0xa5, 0xd5, 0xc5, 0x1b}},
        // ns  uuid
        {0xc06c8400, 0x8e06, 0x11e0, 0x9cb6, {0x00, 0x02, 0xa5, 0xd5, 0xc5, 0x1b}},
        // agc2 uuid
        {0x89f38e65, 0xd4d2, 0x4d64, 0xad0e, {0x2b, 0x3e, 0x79, 0x9e, 0xa8, 0x86}},
};
constexpr size_t kNumEffectUuids = std::size(kEffectUuids);
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

// types of pre processing modules
enum PreProcId {
    PREPROC_AGC,  // Automatic Gain Control
    PREPROC_AEC,  // Acoustic Echo Canceler
    PREPROC_NS,   // Noise Suppressor
    PREPROC_AGC2,  // Automatic Gain Control 2
    PREPROC_NUM_EFFECTS
};

int preProcCreateEffect(effect_handle_t* pEffectHandle, uint32_t effectType,
                        effect_config_t* pConfig, int sessionId, int ioId) {
    if (int status = AUDIO_EFFECT_LIBRARY_INFO_SYM.create_effect(&kEffectUuids[effectType],
                                                                 sessionId, ioId, pEffectHandle);
        status != 0) {
        ALOGE("Audio Preprocessing create returned an error = %d\n", status);
        return EXIT_FAILURE;
    }
    int reply = 0;
    uint32_t replySize = sizeof(reply);
    if (effectType == PREPROC_AEC) {
        if (int status = (**pEffectHandle)
                                 ->command(*pEffectHandle, EFFECT_CMD_SET_CONFIG_REVERSE,
                                           sizeof(effect_config_t), pConfig, &replySize, &reply);
            status != 0) {
            ALOGE("Set config reverse command returned an error = %d\n", status);
            return EXIT_FAILURE;
        }
    }
    if (int status = (**pEffectHandle)
                             ->command(*pEffectHandle, EFFECT_CMD_SET_CONFIG,
                                       sizeof(effect_config_t), pConfig, &replySize, &reply);
        status != 0) {
        ALOGE("Set config command returned an error = %d\n", status);
        return EXIT_FAILURE;
    }
    return reply;
}

int preProcSetConfigParam(effect_handle_t effectHandle, uint32_t paramType, uint32_t paramValue) {
    int reply = 0;
    uint32_t replySize = sizeof(reply);
    uint32_t paramData[2] = {paramType, paramValue};
    effect_param_t* effectParam = (effect_param_t*)malloc(sizeof(*effectParam) + sizeof(paramData));
    memcpy(&effectParam->data[0], &paramData[0], sizeof(paramData));
    effectParam->psize = sizeof(paramData[0]);
    (*effectHandle)
            ->command(effectHandle, EFFECT_CMD_SET_PARAM, sizeof(effect_param_t), effectParam,
                      &replySize, &reply);
    free(effectParam);
    return reply;
}

short preProcGetShortVal(float paramValue) {
    return static_cast<short>(paramValue * std::numeric_limits<short>::max());
}

static void BM_PREPROCESSING(benchmark::State& state) {
    const size_t chMask = kChMasks[state.range(0) - 1];
    const size_t channelCount = audio_channel_count_from_in_mask(chMask);

    PreProcId effectType = (PreProcId)state.range(1);

    int32_t sessionId = 1;
    int32_t ioId = 1;
    effect_handle_t effectHandle = nullptr;
    effect_config_t config{};
    config.inputCfg.samplingRate = config.outputCfg.samplingRate = kSampleRate;
    config.inputCfg.channels = config.outputCfg.channels = chMask;
    config.inputCfg.format = config.outputCfg.format = AUDIO_FORMAT_PCM_16_BIT;

    if (int status = preProcCreateEffect(&effectHandle, state.range(1), &config, sessionId, ioId);
        status != 0) {
        ALOGE("Create effect call returned error %i", status);
        return;
    }

    int reply = 0;
    uint32_t replySize = sizeof(reply);
    if (int status =
                (*effectHandle)
                        ->command(effectHandle, EFFECT_CMD_ENABLE, 0, nullptr, &replySize, &reply);
        status != 0) {
        ALOGE("Command enable call returned error %d\n", reply);
        return;
    }

    // Initialize input buffer with deterministic pseudo-random values
    const int frameLength = (int)(kSampleRate * kTenMilliSecVal);
    std::minstd_rand gen(chMask);
    std::uniform_real_distribution<> dis(-1.0f, 1.0f);
    std::vector<short> in(frameLength * channelCount);
    for (auto& i : in) {
        i = preProcGetShortVal(dis(gen));
    }
    std::vector<short> farIn(frameLength * channelCount);
    for (auto& i : farIn) {
        i = preProcGetShortVal(dis(gen));
    }
    std::vector<short> out(frameLength * channelCount);

    // Run the test
    for (auto _ : state) {
        benchmark::DoNotOptimize(in.data());
        benchmark::DoNotOptimize(out.data());
        benchmark::DoNotOptimize(farIn.data());

        audio_buffer_t inBuffer = {.frameCount = (size_t)frameLength, .s16 = in.data()};
        audio_buffer_t outBuffer = {.frameCount = (size_t)frameLength, .s16 = out.data()};
        audio_buffer_t farInBuffer = {.frameCount = (size_t)frameLength, .s16 = farIn.data()};

        if (PREPROC_AEC == effectType) {
            if (int status =
                        preProcSetConfigParam(effectHandle, AEC_PARAM_ECHO_DELAY, kStreamDelayMs);
                status != 0) {
                ALOGE("preProcSetConfigParam returned Error %d\n", status);
                return;
            }
        }
        if (int status = (*effectHandle)->process(effectHandle, &inBuffer, &outBuffer);
            status != 0) {
            ALOGE("\nError: Process i = %d returned with error %d\n", (int)state.range(1), status);
            return;
        }
        if (PREPROC_AEC == effectType) {
            if (int status =
                        (*effectHandle)->process_reverse(effectHandle, &farInBuffer, &outBuffer);
                status != 0) {
                ALOGE("\nError: Process reverse i = %d returned with error %d\n",
                      (int)state.range(1), status);
                return;
            }
        }
    }
    benchmark::ClobberMemory();

    state.SetComplexityN(state.range(0));

    if (int status = AUDIO_EFFECT_LIBRARY_INFO_SYM.release_effect(effectHandle); status != 0) {
        ALOGE("release_effect returned an error = %d\n", status);
        return;
    }
}

static void preprocessingArgs(benchmark::internal::Benchmark* b) {
    for (int i = 1; i <= (int)kNumChMasks; i++) {
        for (int j = 0; j < (int)kNumEffectUuids; ++j) {
            b->Args({i, j});
        }
    }
}

BENCHMARK(BM_PREPROCESSING)->Apply(preprocessingArgs);

BENCHMARK_MAIN();
