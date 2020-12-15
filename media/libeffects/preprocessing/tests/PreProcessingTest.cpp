/*
 * Copyright (C) 2020 The Android Open Source Project
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

#include <getopt.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/stat.h>
#include <vector>

#include <audio_effects/effect_aec.h>
#include <audio_effects/effect_agc.h>
#include <audio_effects/effect_agc2.h>
#include <audio_effects/effect_ns.h>
#include <log/log.h>

// This is the only symbol that needs to be imported
extern audio_effect_library_t AUDIO_EFFECT_LIBRARY_INFO_SYM;

//------------------------------------------------------------------------------
// local definitions
//------------------------------------------------------------------------------

// types of pre processing modules
enum PreProcId {
    PREPROC_AGC,  // Automatic Gain Control
    PREPROC_AGC2,  // Automatic Gain Control 2
    PREPROC_AEC,  // Acoustic Echo Canceler
    PREPROC_NS,   // Noise Suppressor
    PREPROC_NUM_EFFECTS
};

enum PreProcParams {
    ARG_HELP = 1,
    ARG_INPUT,
    ARG_OUTPUT,
    ARG_FAR,
    ARG_FS,
    ARG_CH_MASK,
    ARG_AGC_TGT_LVL,
    ARG_AGC_COMP_LVL,
    ARG_AEC_DELAY,
    ARG_NS_LVL,
    ARG_AGC2_GAIN,
    ARG_AGC2_LVL,
    ARG_AGC2_SAT_MGN
};

struct preProcConfigParams_t {
    int samplingFreq = 16000;
    audio_channel_mask_t chMask = AUDIO_CHANNEL_IN_MONO;
    int nsLevel = 0;         // a value between 0-3
    int agcTargetLevel = 3;  // in dB
    int agcCompLevel = 9;    // in dB
    float agc2Gain = 0.f;              // in dB
    float agc2SaturationMargin = 2.f;  // in dB
    int agc2Level = 0;                 // either kRms(0) or kPeak(1)
    int aecDelay = 0;  // in ms
};

const effect_uuid_t kPreProcUuids[PREPROC_NUM_EFFECTS] = {
        {0xaa8130e0, 0x66fc, 0x11e0, 0xbad0, {0x00, 0x02, 0xa5, 0xd5, 0xc5, 0x1b}},  // agc uuid
        {0x89f38e65, 0xd4d2, 0x4d64, 0xad0e, {0x2b, 0x3e, 0x79, 0x9e, 0xa8, 0x86}},  // agc2 uuid
        {0xbb392ec0, 0x8d4d, 0x11e0, 0xa896, {0x00, 0x02, 0xa5, 0xd5, 0xc5, 0x1b}},  // aec uuid
        {0xc06c8400, 0x8e06, 0x11e0, 0x9cb6, {0x00, 0x02, 0xa5, 0xd5, 0xc5, 0x1b}},  // ns  uuid
};

constexpr audio_channel_mask_t kPreProcConfigChMask[] = {
        AUDIO_CHANNEL_IN_MONO,
        AUDIO_CHANNEL_IN_STEREO,
        AUDIO_CHANNEL_IN_FRONT_BACK,
        AUDIO_CHANNEL_IN_6,
        AUDIO_CHANNEL_IN_2POINT0POINT2,
        AUDIO_CHANNEL_IN_2POINT1POINT2,
        AUDIO_CHANNEL_IN_3POINT0POINT2,
        AUDIO_CHANNEL_IN_3POINT1POINT2,
        AUDIO_CHANNEL_IN_5POINT1,
        AUDIO_CHANNEL_IN_VOICE_UPLINK_MONO,
        AUDIO_CHANNEL_IN_VOICE_DNLINK_MONO,
        AUDIO_CHANNEL_IN_VOICE_CALL_MONO,
};

constexpr int kPreProcConfigChMaskCount = std::size(kPreProcConfigChMask);

void printUsage() {
    printf("\nUsage: ");
    printf("\n     <executable> [options]\n");
    printf("\nwhere options are, ");
    printf("\n     --input <inputfile>");
    printf("\n           path to the input file");
    printf("\n     --output <outputfile>");
    printf("\n           path to the output file");
    printf("\n     --help");
    printf("\n           Prints this usage information");
    printf("\n     --fs <sampling_freq>");
    printf("\n           Sampling frequency in Hz, default 16000.");
    printf("\n     -ch_mask <channel_mask>\n");
    printf("\n         0  - AUDIO_CHANNEL_IN_MONO");
    printf("\n         1  - AUDIO_CHANNEL_IN_STEREO");
    printf("\n         2  - AUDIO_CHANNEL_IN_FRONT_BACK");
    printf("\n         3  - AUDIO_CHANNEL_IN_6");
    printf("\n         4  - AUDIO_CHANNEL_IN_2POINT0POINT2");
    printf("\n         5  - AUDIO_CHANNEL_IN_2POINT1POINT2");
    printf("\n         6  - AUDIO_CHANNEL_IN_3POINT0POINT2");
    printf("\n         7  - AUDIO_CHANNEL_IN_3POINT1POINT2");
    printf("\n         8  - AUDIO_CHANNEL_IN_5POINT1");
    printf("\n         9  - AUDIO_CHANNEL_IN_VOICE_UPLINK_MONO");
    printf("\n         10 - AUDIO_CHANNEL_IN_VOICE_DNLINK_MONO ");
    printf("\n         11 - AUDIO_CHANNEL_IN_VOICE_CALL_MONO ");
    printf("\n         default 0");
    printf("\n     --far <farend_file>");
    printf("\n           Path to far-end file needed for echo cancellation");
    printf("\n     --aec");
    printf("\n           Enable Echo Cancellation, default disabled");
    printf("\n     --ns");
    printf("\n           Enable Noise Suppression, default disabled");
    printf("\n     --agc");
    printf("\n           Enable Gain Control, default disabled");
    printf("\n     --agc2");
    printf("\n           Enable Gain Controller 2, default disabled");
    printf("\n     --ns_lvl <ns_level>");
    printf("\n           Noise Suppression level in dB, default value 0dB");
    printf("\n     --agc_tgt_lvl <target_level>");
    printf("\n           AGC Target Level in dB, default value 3dB");
    printf("\n     --agc_comp_lvl <comp_level>");
    printf("\n           AGC Comp Level in dB, default value 9dB");
    printf("\n     --agc2_gain <fixed_digital_gain>");
    printf("\n           AGC Fixed Digital Gain in dB, default value 0dB");
    printf("\n     --agc2_lvl <level_estimator>");
    printf("\n           AGC Adaptive Digital Level Estimator, default value kRms");
    printf("\n     --agc2_sat_mgn <saturation_margin>");
    printf("\n           AGC Adaptive Digital Saturation Margin in dB, default value 2dB");
    printf("\n     --aec_delay <delay>");
    printf("\n           AEC delay value in ms, default value 0ms");
    printf("\n");
}

constexpr float kTenMilliSecVal = 0.01;

int preProcCreateEffect(effect_handle_t* pEffectHandle, uint32_t effectType,
                        effect_config_t* pConfig, int sessionId, int ioId) {
    if (int status = AUDIO_EFFECT_LIBRARY_INFO_SYM.create_effect(&kPreProcUuids[effectType],
                                                                 sessionId, ioId, pEffectHandle);
        status != 0) {
        ALOGE("Audio Preprocessing create returned an error = %d\n", status);
        return EXIT_FAILURE;
    }
    int reply = 0;
    uint32_t replySize = sizeof(reply);
    if (effectType == PREPROC_AEC) {
        (**pEffectHandle)
                ->command(*pEffectHandle, EFFECT_CMD_SET_CONFIG_REVERSE, sizeof(effect_config_t),
                          pConfig, &replySize, &reply);
    }
    (**pEffectHandle)
            ->command(*pEffectHandle, EFFECT_CMD_SET_CONFIG, sizeof(effect_config_t), pConfig,
                      &replySize, &reply);
    return reply;
}

int preProcSetConfigParam(uint32_t paramType, uint32_t paramValue, effect_handle_t effectHandle) {
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

int main(int argc, const char* argv[]) {
    if (argc == 1) {
        printUsage();
        return EXIT_FAILURE;
    }
    const char* inputFile = nullptr;
    const char* outputFile = nullptr;
    const char* farFile = nullptr;
    int effectEn[PREPROC_NUM_EFFECTS] = {0};

    const option long_opts[] = {
            {"help", no_argument, nullptr, ARG_HELP},
            {"input", required_argument, nullptr, ARG_INPUT},
            {"output", required_argument, nullptr, ARG_OUTPUT},
            {"far", required_argument, nullptr, ARG_FAR},
            {"fs", required_argument, nullptr, ARG_FS},
            {"ch_mask", required_argument, nullptr, ARG_CH_MASK},
            {"agc_tgt_lvl", required_argument, nullptr, ARG_AGC_TGT_LVL},
            {"agc_comp_lvl", required_argument, nullptr, ARG_AGC_COMP_LVL},
            {"agc2_gain", required_argument, nullptr, ARG_AGC2_GAIN},
            {"agc2_lvl", required_argument, nullptr, ARG_AGC2_LVL},
            {"agc2_sat_mgn", required_argument, nullptr, ARG_AGC2_SAT_MGN},
            {"aec_delay", required_argument, nullptr, ARG_AEC_DELAY},
            {"ns_lvl", required_argument, nullptr, ARG_NS_LVL},
            {"aec", no_argument, &effectEn[PREPROC_AEC], 1},
            {"agc", no_argument, &effectEn[PREPROC_AGC], 1},
            {"agc2", no_argument, &effectEn[PREPROC_AGC2], 1},
            {"ns", no_argument, &effectEn[PREPROC_NS], 1},
            {nullptr, 0, nullptr, 0},
    };
    struct preProcConfigParams_t preProcCfgParams {};

    while (true) {
        const int opt = getopt_long(argc, (char* const*)argv, "i:o:", long_opts, nullptr);
        if (opt == -1) {
            break;
        }
        switch (opt) {
            case ARG_HELP:
                printUsage();
                return 0;
            case ARG_INPUT: {
                inputFile = (char*)optarg;
                break;
            }
            case ARG_OUTPUT: {
                outputFile = (char*)optarg;
                break;
            }
            case ARG_FAR: {
                farFile = (char*)optarg;
                break;
            }
            case ARG_FS: {
                preProcCfgParams.samplingFreq = atoi(optarg);
                break;
            }
            case ARG_CH_MASK: {
                int chMaskIdx = atoi(optarg);
                if (chMaskIdx < 0 or chMaskIdx > kPreProcConfigChMaskCount) {
                    ALOGE("Channel Mask index not in correct range\n");
                    printUsage();
                    return EXIT_FAILURE;
                }
                preProcCfgParams.chMask = kPreProcConfigChMask[chMaskIdx];
                break;
            }
            case ARG_AGC_TGT_LVL: {
                preProcCfgParams.agcTargetLevel = atoi(optarg);
                break;
            }
            case ARG_AGC_COMP_LVL: {
                preProcCfgParams.agcCompLevel = atoi(optarg);
                break;
            }
            case ARG_AGC2_GAIN: {
                preProcCfgParams.agc2Gain = atof(optarg);
                break;
            }
            case ARG_AGC2_LVL: {
                preProcCfgParams.agc2Level = atoi(optarg);
                break;
            }
            case ARG_AGC2_SAT_MGN: {
                preProcCfgParams.agc2SaturationMargin = atof(optarg);
                break;
            }
            case ARG_AEC_DELAY: {
                preProcCfgParams.aecDelay = atoi(optarg);
                break;
            }
            case ARG_NS_LVL: {
                preProcCfgParams.nsLevel = atoi(optarg);
                break;
            }
            default:
                break;
        }
    }

    if (inputFile == nullptr) {
        ALOGE("Error: missing input file\n");
        printUsage();
        return EXIT_FAILURE;
    }

    std::unique_ptr<FILE, decltype(&fclose)> inputFp(fopen(inputFile, "rb"), &fclose);
    if (inputFp == nullptr) {
        ALOGE("Cannot open input file %s\n", inputFile);
        return EXIT_FAILURE;
    }

    std::unique_ptr<FILE, decltype(&fclose)> farFp(fopen(farFile, "rb"), &fclose);
    std::unique_ptr<FILE, decltype(&fclose)> outputFp(fopen(outputFile, "wb"), &fclose);
    if (effectEn[PREPROC_AEC]) {
        if (farFile == nullptr) {
            ALOGE("Far end signal file required for echo cancellation \n");
            return EXIT_FAILURE;
        }
        if (farFp == nullptr) {
            ALOGE("Cannot open far end stream file %s\n", farFile);
            return EXIT_FAILURE;
        }
        struct stat statInput, statFar;
        (void)fstat(fileno(inputFp.get()), &statInput);
        (void)fstat(fileno(farFp.get()), &statFar);
        if (statInput.st_size != statFar.st_size) {
            ALOGE("Near and far end signals are of different sizes");
            return EXIT_FAILURE;
        }
    }
    if (outputFile != nullptr && outputFp == nullptr) {
        ALOGE("Cannot open output file %s\n", outputFile);
        return EXIT_FAILURE;
    }

    int32_t sessionId = 1;
    int32_t ioId = 1;
    effect_handle_t effectHandle[PREPROC_NUM_EFFECTS] = {nullptr};
    effect_config_t config;
    config.inputCfg.samplingRate = config.outputCfg.samplingRate = preProcCfgParams.samplingFreq;
    config.inputCfg.channels = config.outputCfg.channels = preProcCfgParams.chMask;
    config.inputCfg.format = config.outputCfg.format = AUDIO_FORMAT_PCM_16_BIT;

    // Create all the effect handles
    for (int i = 0; i < PREPROC_NUM_EFFECTS; i++) {
        if (int status = preProcCreateEffect(&effectHandle[i], i, &config, sessionId, ioId);
            status != 0) {
            ALOGE("Create effect call returned error %i", status);
            return EXIT_FAILURE;
        }
    }

    for (int i = 0; i < PREPROC_NUM_EFFECTS; i++) {
        if (effectEn[i] == 1) {
            int reply = 0;
            uint32_t replySize = sizeof(reply);
            (*effectHandle[i])
                    ->command(effectHandle[i], EFFECT_CMD_ENABLE, 0, nullptr, &replySize, &reply);
            if (reply != 0) {
                ALOGE("Command enable call returned error %d\n", reply);
                return EXIT_FAILURE;
            }
        }
    }

    // Set Config Params of the effects
    if (effectEn[PREPROC_AGC]) {
        if (int status = preProcSetConfigParam(AGC_PARAM_TARGET_LEVEL,
                                               (uint32_t)preProcCfgParams.agcTargetLevel,
                                               effectHandle[PREPROC_AGC]);
            status != 0) {
            ALOGE("Invalid AGC Target Level. Error %d\n", status);
            return EXIT_FAILURE;
        }
        if (int status = preProcSetConfigParam(AGC_PARAM_COMP_GAIN,
                                               (uint32_t)preProcCfgParams.agcCompLevel,
                                               effectHandle[PREPROC_AGC]);
            status != 0) {
            ALOGE("Invalid AGC Comp Gain. Error %d\n", status);
            return EXIT_FAILURE;
        }
    }
    if (effectEn[PREPROC_AGC2]) {
        if (int status = preProcSetConfigParam(AGC2_PARAM_FIXED_DIGITAL_GAIN,
                                               (float)preProcCfgParams.agc2Gain,
                                               effectHandle[PREPROC_AGC2]);
            status != 0) {
            ALOGE("Invalid AGC2 Fixed Digital Gain. Error %d\n", status);
            return EXIT_FAILURE;
        }
        if (int status = preProcSetConfigParam(AGC2_PARAM_ADAPT_DIGI_LEVEL_ESTIMATOR,
                                               (uint32_t)preProcCfgParams.agc2Level,
                                               effectHandle[PREPROC_AGC2]);
            status != 0) {
            ALOGE("Invalid AGC2 Level Estimator. Error %d\n", status);
            return EXIT_FAILURE;
        }
        if (int status = preProcSetConfigParam(AGC2_PARAM_ADAPT_DIGI_EXTRA_SATURATION_MARGIN,
                                               (float)preProcCfgParams.agc2SaturationMargin,
                                               effectHandle[PREPROC_AGC2]);
            status != 0) {
            ALOGE("Invalid AGC2 Saturation Margin. Error %d\n", status);
            return EXIT_FAILURE;
        }
    }
    if (effectEn[PREPROC_NS]) {
        if (int status = preProcSetConfigParam(NS_PARAM_LEVEL, (uint32_t)preProcCfgParams.nsLevel,
                                               effectHandle[PREPROC_NS]);
            status != 0) {
            ALOGE("Invalid Noise Suppression level Error %d\n", status);
            return EXIT_FAILURE;
        }
    }

    // Process Call
    const int frameLength = (int)(preProcCfgParams.samplingFreq * kTenMilliSecVal);
    const int ioChannelCount = audio_channel_count_from_in_mask(preProcCfgParams.chMask);
    const int ioFrameSize = ioChannelCount * sizeof(short);
    int frameCounter = 0;
    while (true) {
        std::vector<short> in(frameLength * ioChannelCount);
        std::vector<short> out(frameLength * ioChannelCount);
        std::vector<short> farIn(frameLength * ioChannelCount);
        size_t samplesRead = fread(in.data(), ioFrameSize, frameLength, inputFp.get());
        if (samplesRead == 0) {
            break;
        }
        audio_buffer_t inputBuffer, outputBuffer;
        audio_buffer_t farInBuffer{};
        inputBuffer.frameCount = samplesRead;
        outputBuffer.frameCount = samplesRead;
        inputBuffer.s16 = in.data();
        outputBuffer.s16 = out.data();

        if (farFp != nullptr) {
            samplesRead = fread(farIn.data(), ioFrameSize, frameLength, farFp.get());
            if (samplesRead == 0) {
                break;
            }
            farInBuffer.frameCount = samplesRead;
            farInBuffer.s16 = farIn.data();
        }

        for (int i = 0; i < PREPROC_NUM_EFFECTS; i++) {
            if (effectEn[i] == 1) {
                if (i == PREPROC_AEC) {
                    if (int status = preProcSetConfigParam(AEC_PARAM_ECHO_DELAY,
                                                           (uint32_t)preProcCfgParams.aecDelay,
                                                           effectHandle[PREPROC_AEC]);
                        status != 0) {
                        ALOGE("preProcSetConfigParam returned Error %d\n", status);
                        return EXIT_FAILURE;
                    }
                }
                if (int status = (*effectHandle[i])
                                         ->process(effectHandle[i], &inputBuffer, &outputBuffer);
                    status != 0) {
                    ALOGE("\nError: Process i = %d returned with error %d\n", i, status);
                    return EXIT_FAILURE;
                }
                if (i == PREPROC_AEC) {
                    if (int status = (*effectHandle[i])
                                             ->process_reverse(effectHandle[i], &farInBuffer,
                                                               &outputBuffer);
                        status != 0) {
                        ALOGE("\nError: Process reverse i = %d returned with error %d\n", i,
                              status);
                        return EXIT_FAILURE;
                    }
                }
            }
        }
        if (outputFp != nullptr) {
            size_t samplesWritten =
                    fwrite(out.data(), ioFrameSize, outputBuffer.frameCount, outputFp.get());
            if (samplesWritten != outputBuffer.frameCount) {
                ALOGE("\nError: Output file writing failed");
                break;
            }
        }
        frameCounter += frameLength;
    }
    // Release all the effect handles created
    for (int i = 0; i < PREPROC_NUM_EFFECTS; i++) {
        if (int status = AUDIO_EFFECT_LIBRARY_INFO_SYM.release_effect(effectHandle[i]);
            status != 0) {
            ALOGE("Audio Preprocessing release returned an error = %d\n", status);
            return EXIT_FAILURE;
        }
    }
    return EXIT_SUCCESS;
}
