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
#include <assert.h>
#include <getopt.h>
#include <inttypes.h>
#include <iterator>
#include <math.h>
#include <stdlib.h>
#include <string.h>
#include <vector>

#include <audio_utils/channels.h>
#include <audio_utils/primitives.h>
#include <log/log.h>
#include <system/audio.h>

#include "EffectReverb.h"

// This is the only symbol that needs to be exported
extern audio_effect_library_t AUDIO_EFFECT_LIBRARY_INFO_SYM;

// Global Variables
enum ReverbParams {
    ARG_HELP = 1,
    ARG_INPUT,
    ARG_OUTPUT,
    ARG_FS,
    ARG_CH_MASK,
    ARG_PRESET,
    ARG_AUX,
    ARG_MONO_MODE,
    ARG_FILE_CH,
};

const effect_uuid_t kReverbUuids[] = {
        {0x172cdf00,
         0xa3bc,
         0x11df,
         0xa72f,
         {0x00, 0x02, 0xa5, 0xd5, 0xc5, 0x1b}},  // preset-insert mode
        {0xf29a1400,
         0xa3bb,
         0x11df,
         0x8ddc,
         {0x00, 0x02, 0xa5, 0xd5, 0xc5, 0x1b}},  // preset-aux mode
};

// structures
struct reverbConfigParams_t {
    int fChannels = 2;
    int monoMode = false;
    int frameLength = 256;
    int preset = 0;
    int nrChannels = 2;
    int sampleRate = 48000;
    int auxiliary = 0;
    audio_channel_mask_t chMask = AUDIO_CHANNEL_OUT_STEREO;
};

constexpr audio_channel_mask_t kReverbConfigChMask[] = {
        AUDIO_CHANNEL_OUT_MONO,
        AUDIO_CHANNEL_OUT_STEREO,
        AUDIO_CHANNEL_OUT_2POINT1,
        AUDIO_CHANNEL_OUT_2POINT0POINT2,
        AUDIO_CHANNEL_OUT_QUAD,
        AUDIO_CHANNEL_OUT_QUAD_BACK,
        AUDIO_CHANNEL_OUT_QUAD_SIDE,
        AUDIO_CHANNEL_OUT_SURROUND,
        AUDIO_CHANNEL_INDEX_MASK_4,
        AUDIO_CHANNEL_OUT_2POINT1POINT2,
        AUDIO_CHANNEL_OUT_3POINT0POINT2,
        AUDIO_CHANNEL_OUT_PENTA,
        AUDIO_CHANNEL_INDEX_MASK_5,
        AUDIO_CHANNEL_OUT_3POINT1POINT2,
        AUDIO_CHANNEL_OUT_5POINT1,
        AUDIO_CHANNEL_OUT_5POINT1_BACK,
        AUDIO_CHANNEL_OUT_5POINT1_SIDE,
        AUDIO_CHANNEL_INDEX_MASK_6,
        AUDIO_CHANNEL_OUT_6POINT1,
        AUDIO_CHANNEL_INDEX_MASK_7,
        AUDIO_CHANNEL_OUT_5POINT1POINT2,
        AUDIO_CHANNEL_OUT_7POINT1,
        AUDIO_CHANNEL_INDEX_MASK_8,
        AUDIO_CHANNEL_INDEX_MASK_9,
        AUDIO_CHANNEL_INDEX_MASK_10,
        AUDIO_CHANNEL_INDEX_MASK_11,
        AUDIO_CHANNEL_INDEX_MASK_12,
        AUDIO_CHANNEL_INDEX_MASK_13,
        AUDIO_CHANNEL_INDEX_MASK_14,
        AUDIO_CHANNEL_INDEX_MASK_15,
        AUDIO_CHANNEL_INDEX_MASK_16,
        AUDIO_CHANNEL_INDEX_MASK_17,
        AUDIO_CHANNEL_INDEX_MASK_18,
        AUDIO_CHANNEL_INDEX_MASK_19,
        AUDIO_CHANNEL_INDEX_MASK_20,
        AUDIO_CHANNEL_INDEX_MASK_21,
        AUDIO_CHANNEL_INDEX_MASK_22,
        AUDIO_CHANNEL_INDEX_MASK_23,
        AUDIO_CHANNEL_INDEX_MASK_24,
};

constexpr int kReverbConfigChMaskCount = std::size(kReverbConfigChMask);

int reverbCreateEffect(effect_handle_t* pEffectHandle, effect_config_t* pConfig, int sessionId,
                       int ioId, int auxFlag) {
    if (int status = AUDIO_EFFECT_LIBRARY_INFO_SYM.create_effect(&kReverbUuids[auxFlag], sessionId,
                                                                 ioId, pEffectHandle);
        status != 0) {
        ALOGE("Reverb create returned an error = %d\n", status);
        return EXIT_FAILURE;
    }
    int reply = 0;
    uint32_t replySize = sizeof(reply);
    (**pEffectHandle)
            ->command(*pEffectHandle, EFFECT_CMD_SET_CONFIG, sizeof(effect_config_t), pConfig,
                      &replySize, &reply);
    return reply;
}

int reverbSetConfigParam(uint32_t paramType, uint32_t paramValue, effect_handle_t effectHandle) {
    int reply = 0;
    uint32_t replySize = sizeof(reply);
    uint32_t paramData[2] = {paramType, paramValue};
    effect_param_t* effectParam = (effect_param_t*)malloc(sizeof(*effectParam) + sizeof(paramData));
    memcpy(&effectParam->data[0], &paramData[0], sizeof(paramData));
    effectParam->psize = sizeof(paramData[0]);
    effectParam->vsize = sizeof(paramData[1]);
    int status = (*effectHandle)
                         ->command(effectHandle, EFFECT_CMD_SET_PARAM,
                                   sizeof(effect_param_t) + sizeof(paramData), effectParam,
                                   &replySize, &reply);
    free(effectParam);
    if (status != 0) {
        ALOGE("Reverb set config returned an error = %d\n", status);
        return status;
    }
    return reply;
}

void printUsage() {
    printf("\nUsage: ");
    printf("\n     <executable> [options]\n");
    printf("\nwhere options are, ");
    printf("\n     --input <inputfile>");
    printf("\n           path to the input file");
    printf("\n     --output <outputfile>");
    printf("\n           path to the output file");
    printf("\n     --help");
    printf("\n           prints this usage information");
    printf("\n     --chMask <channel_mask>\n");
    printf("\n           0  - AUDIO_CHANNEL_OUT_MONO");
    printf("\n           1  - AUDIO_CHANNEL_OUT_STEREO");
    printf("\n           2  - AUDIO_CHANNEL_OUT_2POINT1");
    printf("\n           3  - AUDIO_CHANNEL_OUT_2POINT0POINT2");
    printf("\n           4  - AUDIO_CHANNEL_OUT_QUAD");
    printf("\n           5  - AUDIO_CHANNEL_OUT_QUAD_BACK");
    printf("\n           6  - AUDIO_CHANNEL_OUT_QUAD_SIDE");
    printf("\n           7  - AUDIO_CHANNEL_OUT_SURROUND");
    printf("\n           8  - canonical channel index mask for 4 ch: (1 << 4) - 1");
    printf("\n           9  - AUDIO_CHANNEL_OUT_2POINT1POINT2");
    printf("\n           10 - AUDIO_CHANNEL_OUT_3POINT0POINT2");
    printf("\n           11 - AUDIO_CHANNEL_OUT_PENTA");
    printf("\n           12 - canonical channel index mask for 5 ch: (1 << 5) - 1");
    printf("\n           13 - AUDIO_CHANNEL_OUT_3POINT1POINT2");
    printf("\n           14 - AUDIO_CHANNEL_OUT_5POINT1");
    printf("\n           15 - AUDIO_CHANNEL_OUT_5POINT1_BACK");
    printf("\n           16 - AUDIO_CHANNEL_OUT_5POINT1_SIDE");
    printf("\n           17 - canonical channel index mask for 6 ch: (1 << 6) - 1");
    printf("\n           18 - AUDIO_CHANNEL_OUT_6POINT1");
    printf("\n           19 - canonical channel index mask for 7 ch: (1 << 7) - 1");
    printf("\n           20 - AUDIO_CHANNEL_OUT_5POINT1POINT2");
    printf("\n           21 - AUDIO_CHANNEL_OUT_7POINT1");
    printf("\n           22 - canonical channel index mask for 8 ch: (1 << 8) - 1");
    printf("\n           default 0");
    printf("\n     --fs <sampling_freq>");
    printf("\n           Sampling frequency in Hz, default 48000.");
    printf("\n     --preset <preset_value>");
    printf("\n           0 - None");
    printf("\n           1 - Small Room");
    printf("\n           2 - Medium Room");
    printf("\n           3 - Large Room");
    printf("\n           4 - Medium Hall");
    printf("\n           5 - Large Hall");
    printf("\n           6 - Plate");
    printf("\n           default 0");
    printf("\n     --fch <file_channels>");
    printf("\n           number of channels in input file (1 through 8), default 1");
    printf("\n     --M");
    printf("\n           Mono mode (force all input audio channels to be identical)");
    printf("\n     --aux <auxiliary_flag> ");
    printf("\n           0 - Insert Mode on");
    printf("\n           1 - auxiliary Mode on");
    printf("\n           default 0");
    printf("\n");
}

int main(int argc, const char* argv[]) {
    if (argc == 1) {
        printUsage();
        return EXIT_FAILURE;
    }

    reverbConfigParams_t revConfigParams{};  // default initialize
    const char* inputFile = nullptr;
    const char* outputFile = nullptr;

    const option long_opts[] = {
            {"help", no_argument, nullptr, ARG_HELP},
            {"input", required_argument, nullptr, ARG_INPUT},
            {"output", required_argument, nullptr, ARG_OUTPUT},
            {"fs", required_argument, nullptr, ARG_FS},
            {"chMask", required_argument, nullptr, ARG_CH_MASK},
            {"preset", required_argument, nullptr, ARG_PRESET},
            {"aux", required_argument, nullptr, ARG_AUX},
            {"M", no_argument, &revConfigParams.monoMode, true},
            {"fch", required_argument, nullptr, ARG_FILE_CH},
            {nullptr, 0, nullptr, 0},
    };

    while (true) {
        const int opt = getopt_long(argc, (char* const*)argv, "i:o:", long_opts, nullptr);
        if (opt == -1) {
            break;
        }
        switch (opt) {
            case ARG_HELP:
                printUsage();
                return EXIT_SUCCESS;
            case ARG_INPUT: {
                inputFile = (char*)optarg;
                break;
            }
            case ARG_OUTPUT: {
                outputFile = (char*)optarg;
                break;
            }
            case ARG_FS: {
                revConfigParams.sampleRate = atoi(optarg);
                break;
            }
            case ARG_CH_MASK: {
                int chMaskIdx = atoi(optarg);
                if (chMaskIdx < 0 or chMaskIdx > kReverbConfigChMaskCount) {
                    ALOGE("Channel Mask index not in correct range\n");
                    printUsage();
                    return EXIT_FAILURE;
                }
                revConfigParams.chMask = kReverbConfigChMask[chMaskIdx];
                break;
            }
            case ARG_PRESET: {
                revConfigParams.preset = atoi(optarg);
                break;
            }
            case ARG_AUX: {
                revConfigParams.auxiliary = atoi(optarg);
                break;
            }
            case ARG_MONO_MODE: {
                break;
            }
            case ARG_FILE_CH: {
                revConfigParams.fChannels = atoi(optarg);
                break;
            }
            default:
                break;
        }
    }

    if (inputFile == nullptr) {
        ALOGE("Error: missing input files\n");
        printUsage();
        return EXIT_FAILURE;
    }
    std::unique_ptr<FILE, decltype(&fclose)> inputFp(fopen(inputFile, "rb"), &fclose);

    if (inputFp == nullptr) {
        ALOGE("Cannot open input file %s\n", inputFile);
        return EXIT_FAILURE;
    }

    if (outputFile == nullptr) {
        ALOGE("Error: missing output files\n");
        printUsage();
        return EXIT_FAILURE;
    }
    std::unique_ptr<FILE, decltype(&fclose)> outputFp(fopen(outputFile, "wb"), &fclose);

    if (outputFp == nullptr) {
        ALOGE("Cannot open output file %s\n", outputFile);
        return EXIT_FAILURE;
    }

    int32_t sessionId = 1;
    int32_t ioId = 1;
    effect_handle_t effectHandle = nullptr;
    effect_config_t config;
    config.inputCfg.samplingRate = config.outputCfg.samplingRate = revConfigParams.sampleRate;
    config.inputCfg.channels = config.outputCfg.channels = revConfigParams.chMask;
    config.inputCfg.format = config.outputCfg.format = AUDIO_FORMAT_PCM_FLOAT;
    if (AUDIO_CHANNEL_OUT_MONO == revConfigParams.chMask) {
        config.outputCfg.channels = AUDIO_CHANNEL_OUT_STEREO;
    }
    if (int status = reverbCreateEffect(&effectHandle, &config, sessionId, ioId,
                                        revConfigParams.auxiliary);
        status != 0) {
        ALOGE("Create effect call returned error %i", status);
        return EXIT_FAILURE;
    }

    int reply = 0;
    uint32_t replySize = sizeof(reply);
    (*effectHandle)->command(effectHandle, EFFECT_CMD_ENABLE, 0, nullptr, &replySize, &reply);
    if (reply != 0) {
        ALOGE("Command enable call returned error %d\n", reply);
        return EXIT_FAILURE;
    }

    if (int status = reverbSetConfigParam(REVERB_PARAM_PRESET, (uint32_t)revConfigParams.preset,
                                          effectHandle);
        status != 0) {
        ALOGE("Invalid reverb preset. Error %d\n", status);
        return EXIT_FAILURE;
    }

    revConfigParams.nrChannels = audio_channel_count_from_out_mask(revConfigParams.chMask);
    const int channelCount = revConfigParams.nrChannels;
    const int frameLength = revConfigParams.frameLength;
#ifdef BYPASS_EXEC
    const int frameSize = (int)channelCount * sizeof(float);
#endif
    const int ioChannelCount = revConfigParams.fChannels;
    const int ioFrameSize = ioChannelCount * sizeof(short);
    const int maxChannelCount = std::max(channelCount, ioChannelCount);
    /*
     * Mono input will be converted to 2 channels internally in the process call
     * by copying the same data into the second channel.
     * Hence when channelCount is 1, output buffer should be allocated for
     * 2 channels. The outChannelCount takes care of allocation of sufficient
     * memory for the output buffer.
     */
    const int outChannelCount = (channelCount == 1 ? 2 : channelCount);

    std::vector<short> in(frameLength * maxChannelCount);
    std::vector<short> out(frameLength * outChannelCount);
    std::vector<float> floatIn(frameLength * channelCount);
    std::vector<float> floatOut(frameLength * outChannelCount);

    int frameCounter = 0;

    while (fread(in.data(), ioFrameSize, frameLength, inputFp.get()) == (size_t)frameLength) {
        if (ioChannelCount != channelCount) {
            adjust_channels(in.data(), ioChannelCount, in.data(), channelCount, sizeof(short),
                            frameLength * ioFrameSize);
        }
        memcpy_to_float_from_i16(floatIn.data(), in.data(), frameLength * channelCount);

        // Mono mode will replicate the first channel to all other channels.
        // This ensures all audio channels are identical. This is useful for testing
        // Bass Boost, which extracts a mono signal for processing.
        if (revConfigParams.monoMode && channelCount > 1) {
            for (int i = 0; i < frameLength; ++i) {
                auto* fp = &floatIn[i * channelCount];
                std::fill(fp + 1, fp + channelCount, *fp);  // replicate ch 0
            }
        }

        audio_buffer_t inputBuffer, outputBuffer;
        inputBuffer.frameCount = outputBuffer.frameCount = frameLength;
        inputBuffer.f32 = floatIn.data();
        outputBuffer.f32 = floatOut.data();
#ifndef BYPASS_EXEC
        if (int status = (*effectHandle)->process(effectHandle, &inputBuffer, &outputBuffer);
            status != 0) {
            ALOGE("\nError: Process returned with error %d\n", status);
            return EXIT_FAILURE;
        }
#else
        memcpy(floatOut.data(), floatIn.data(), frameLength * frameSize);
#endif
        memcpy_to_i16_from_float(out.data(), floatOut.data(), frameLength * outChannelCount);

        if (ioChannelCount != outChannelCount) {
            adjust_channels(out.data(), outChannelCount, out.data(), ioChannelCount, sizeof(short),
                            frameLength * outChannelCount * sizeof(short));
        }
        (void)fwrite(out.data(), ioFrameSize, frameLength, outputFp.get());
        frameCounter += frameLength;
    }

    if (int status = AUDIO_EFFECT_LIBRARY_INFO_SYM.release_effect(effectHandle); status != 0) {
        ALOGE("Audio Preprocessing release returned an error = %d\n", status);
        return EXIT_FAILURE;
    }
    printf("frameCounter: [%d]\n", frameCounter);

    return EXIT_SUCCESS;
}
