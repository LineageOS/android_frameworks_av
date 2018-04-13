/*
 * Copyright (C) 2016 The Android Open Source Project
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

// Audio loopback tests to measure the round trip latency and glitches.

#include <algorithm>
#include <assert.h>
#include <cctype>
#include <errno.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <aaudio/AAudio.h>
#include <aaudio/AAudioTesting.h>

#include "AAudioSimplePlayer.h"
#include "AAudioSimpleRecorder.h"
#include "AAudioExampleUtils.h"
#include "LoopbackAnalyzer.h"

// Tag for machine readable results as property = value pairs
#define RESULT_TAG              "RESULT: "
#define NUM_SECONDS             5
#define NUM_INPUT_CHANNELS      1
#define FILENAME_ALL            "/data/loopback_all.wav"
#define FILENAME_ECHOS          "/data/loopback_echos.wav"
#define APP_VERSION             "0.1.22"

struct LoopbackData {
    AAudioStream      *inputStream = nullptr;
    int32_t            inputFramesMaximum = 0;
    int16_t           *inputData = nullptr;
    int16_t            peakShort = 0;
    float             *conversionBuffer = nullptr;
    int32_t            actualInputChannelCount = 0;
    int32_t            actualOutputChannelCount = 0;
    int32_t            inputBuffersToDiscard = 10;
    int32_t            minNumFrames = INT32_MAX;
    int32_t            maxNumFrames = 0;
    bool               isDone = false;

    aaudio_result_t    inputError = AAUDIO_OK;
    aaudio_result_t    outputError = AAUDIO_OK;

    SineAnalyzer       sineAnalyzer;
    EchoAnalyzer       echoAnalyzer;
    AudioRecording     audioRecording;
    LoopbackProcessor *loopbackProcessor;
};

static void convertPcm16ToFloat(const int16_t *source,
                                float *destination,
                                int32_t numSamples) {
    const float scaler = 1.0f / 32768.0f;
    for (int i = 0; i < numSamples; i++) {
        destination[i] = source[i] * scaler;
    }
}

// ====================================================================================
// ========================= CALLBACK =================================================
// ====================================================================================
// Callback function that fills the audio output buffer.
static aaudio_data_callback_result_t MyDataCallbackProc(
        AAudioStream *outputStream,
        void *userData,
        void *audioData,
        int32_t numFrames
) {
    (void) outputStream;
    aaudio_data_callback_result_t result = AAUDIO_CALLBACK_RESULT_CONTINUE;
    LoopbackData *myData = (LoopbackData *) userData;
    float  *outputData = (float  *) audioData;

    // Read audio data from the input stream.
    int32_t framesRead;

    if (numFrames > myData->inputFramesMaximum) {
        myData->inputError = AAUDIO_ERROR_OUT_OF_RANGE;
        return AAUDIO_CALLBACK_RESULT_STOP;
    }

    if (numFrames > myData->maxNumFrames) {
        myData->maxNumFrames = numFrames;
    }
    if (numFrames < myData->minNumFrames) {
        myData->minNumFrames = numFrames;
    }

    if (myData->inputBuffersToDiscard > 0) {
        // Drain the input.
        do {
            framesRead = AAudioStream_read(myData->inputStream, myData->inputData,
                                       numFrames, 0);
            if (framesRead < 0) {
                myData->inputError = framesRead;
                printf("ERROR in read = %d", framesRead);
                result = AAUDIO_CALLBACK_RESULT_STOP;
            } else if (framesRead > 0) {
                myData->inputBuffersToDiscard--;
            }
        } while(framesRead > 0);
    } else {
        framesRead = AAudioStream_read(myData->inputStream, myData->inputData,
                                       numFrames, 0);
        if (framesRead < 0) {
            myData->inputError = framesRead;
            printf("ERROR in read = %d", framesRead);
            result = AAUDIO_CALLBACK_RESULT_STOP;
        } else if (framesRead > 0) {

            myData->audioRecording.write(myData->inputData,
                                        myData->actualInputChannelCount,
                                         framesRead);

            int32_t numSamples = framesRead * myData->actualInputChannelCount;
            convertPcm16ToFloat(myData->inputData, myData->conversionBuffer, numSamples);

            myData->loopbackProcessor->process(myData->conversionBuffer,
                                              myData->actualInputChannelCount,
                                              outputData,
                                              myData->actualOutputChannelCount,
                                              framesRead);
            myData->isDone = myData->loopbackProcessor->isDone();
            if (myData->isDone) {
                result = AAUDIO_CALLBACK_RESULT_STOP;
            }
        }
    }

    return result;
}

static void MyErrorCallbackProc(
        AAudioStream *stream __unused,
        void *userData __unused,
        aaudio_result_t error) {
    printf("Error Callback, error: %d\n",(int)error);
    LoopbackData *myData = (LoopbackData *) userData;
    myData->outputError = error;
}

static void usage() {
    printf("Usage: aaudio_loopback [OPTION]...\n\n");
    AAudioArgsParser::usage();
    printf("      -C{channels}      number of input channels\n");
    printf("      -g{gain}          recirculating loopback gain\n");
    printf("      -P{inPerf}        set input AAUDIO_PERFORMANCE_MODE*\n");
    printf("          n for _NONE\n");
    printf("          l for _LATENCY\n");
    printf("          p for _POWER_SAVING\n");
    printf("      -t{test}          select test mode\n");
    printf("          m for sine magnitude\n");
    printf("          e for echo latency (default)\n");
    printf("          f for file latency, analyzes %s\n\n", FILENAME_ECHOS);
    printf("      -X  use EXCLUSIVE mode for input\n");
    printf("Example:  aaudio_loopback -n2 -pl -Pl -x\n");
}

static aaudio_performance_mode_t parsePerformanceMode(char c) {
    aaudio_performance_mode_t mode = AAUDIO_ERROR_ILLEGAL_ARGUMENT;
    c = tolower(c);
    switch (c) {
        case 'n':
            mode = AAUDIO_PERFORMANCE_MODE_NONE;
            break;
        case 'l':
            mode = AAUDIO_PERFORMANCE_MODE_LOW_LATENCY;
            break;
        case 'p':
            mode = AAUDIO_PERFORMANCE_MODE_POWER_SAVING;
            break;
        default:
            printf("ERROR in value performance mode %c\n", c);
            break;
    }
    return mode;
}

enum {
    TEST_SINE_MAGNITUDE = 0,
    TEST_ECHO_LATENCY,
    TEST_FILE_LATENCY,
};

static int parseTestMode(char c) {
    int testMode = TEST_ECHO_LATENCY;
    c = tolower(c);
    switch (c) {
        case 'm':
            testMode = TEST_SINE_MAGNITUDE;
            break;
        case 'e':
            testMode = TEST_ECHO_LATENCY;
            break;
        case 'f':
            testMode = TEST_FILE_LATENCY;
            break;
        default:
            printf("ERROR in value test mode %c\n", c);
            break;
    }
    return testMode;
}

void printAudioGraph(AudioRecording &recording, int numSamples) {
    int32_t start = recording.size() / 2;
    int32_t end = start + numSamples;
    if (end >= recording.size()) {
        end = recording.size() - 1;
    }
    float *data = recording.getData();
    // Normalize data so we can see it better.
    float maxSample = 0.01;
    for (int32_t i = start; i < end; i++) {
        float samplePos = fabs(data[i]);
        if (samplePos > maxSample) {
            maxSample = samplePos;
        }
    }
    float gain = 0.98f / maxSample;
    for (int32_t i = start; i < end; i++) {
        float sample = data[i];
        printf("%5.3f ", sample); // actual value
        sample *= gain;
        printAudioScope(sample);
    }
}


// ====================================================================================
// TODO break up this large main() function into smaller functions
int main(int argc, const char **argv)
{

    AAudioArgsParser      argParser;
    AAudioSimplePlayer    player;
    AAudioSimpleRecorder  recorder;
    LoopbackData          loopbackData;
    AAudioStream         *outputStream = nullptr;

    aaudio_result_t       result = AAUDIO_OK;
    aaudio_sharing_mode_t requestedInputSharingMode     = AAUDIO_SHARING_MODE_SHARED;
    int                   requestedInputChannelCount = NUM_INPUT_CHANNELS;
    const aaudio_format_t requestedInputFormat = AAUDIO_FORMAT_PCM_I16;
    const aaudio_format_t requestedOutputFormat = AAUDIO_FORMAT_PCM_FLOAT;
    aaudio_format_t       actualInputFormat;
    aaudio_format_t       actualOutputFormat;
    aaudio_performance_mode_t inputPerformanceLevel = AAUDIO_PERFORMANCE_MODE_LOW_LATENCY;
    int32_t               actualSampleRate = 0;

    int testMode = TEST_ECHO_LATENCY;
    double gain = 1.0;

    int32_t framesPerBurst = 0;
    float *outputData = NULL;

    // Make printf print immediately so that debug info is not stuck
    // in a buffer if we hang or crash.
    setvbuf(stdout, NULL, _IONBF, (size_t) 0);

    printf("%s - Audio loopback using AAudio V" APP_VERSION "\n", argv[0]);

    for (int i = 1; i < argc; i++) {
        const char *arg = argv[i];
        if (argParser.parseArg(arg)) {
            // Handle options that are not handled by the ArgParser
            if (arg[0] == '-') {
                char option = arg[1];
                switch (option) {
                    case 'C':
                        requestedInputChannelCount = atoi(&arg[2]);
                        break;
                    case 'g':
                        gain = atof(&arg[2]);
                        break;
                    case 'P':
                        inputPerformanceLevel = parsePerformanceMode(arg[2]);
                        break;
                    case 'X':
                        requestedInputSharingMode = AAUDIO_SHARING_MODE_EXCLUSIVE;
                        break;
                    case 't':
                        testMode = parseTestMode(arg[2]);
                        break;
                    default:
                        usage();
                        exit(EXIT_FAILURE);
                        break;
                }
            } else {
                usage();
                exit(EXIT_FAILURE);
                break;
            }
        }

    }

    if (inputPerformanceLevel < 0) {
        printf("illegal inputPerformanceLevel = %d\n", inputPerformanceLevel);
        exit(EXIT_FAILURE);
    }

    int32_t requestedDuration = argParser.getDurationSeconds();
    int32_t recordingDuration = std::min(60, requestedDuration);

    switch(testMode) {
        case TEST_SINE_MAGNITUDE:
            loopbackData.loopbackProcessor = &loopbackData.sineAnalyzer;
            break;
        case TEST_ECHO_LATENCY:
            loopbackData.echoAnalyzer.setGain(gain);
            loopbackData.loopbackProcessor = &loopbackData.echoAnalyzer;
            break;
        case TEST_FILE_LATENCY: {
            loopbackData.echoAnalyzer.setGain(gain);

            loopbackData.loopbackProcessor = &loopbackData.echoAnalyzer;
            int read = loopbackData.loopbackProcessor->load(FILENAME_ECHOS);
            printf("main() read %d mono samples from %s on Android device\n", read, FILENAME_ECHOS);
            loopbackData.loopbackProcessor->report();
            return 0;
        }
            break;
        default:
            exit(1);
            break;
    }

    printf("OUTPUT stream ----------------------------------------\n");
    argParser.setFormat(requestedOutputFormat);
    result = player.open(argParser, MyDataCallbackProc, MyErrorCallbackProc, &loopbackData);
    if (result != AAUDIO_OK) {
        fprintf(stderr, "ERROR -  player.open() returned %d\n", result);
        exit(1);
    }
    outputStream = player.getStream();
    argParser.compareWithStream(outputStream);

    actualOutputFormat = AAudioStream_getFormat(outputStream);
    assert(actualOutputFormat == AAUDIO_FORMAT_PCM_FLOAT);

    actualSampleRate = AAudioStream_getSampleRate(outputStream);
    loopbackData.audioRecording.allocate(recordingDuration * actualSampleRate);
    loopbackData.audioRecording.setSampleRate(actualSampleRate);

    printf("INPUT stream ----------------------------------------\n");
    // Use different parameters for the input.
    argParser.setNumberOfBursts(AAUDIO_UNSPECIFIED);
    argParser.setFormat(requestedInputFormat);
    argParser.setPerformanceMode(inputPerformanceLevel);
    argParser.setChannelCount(requestedInputChannelCount);
    argParser.setSharingMode(requestedInputSharingMode);
    result = recorder.open(argParser);
    if (result != AAUDIO_OK) {
        fprintf(stderr, "ERROR -  recorder.open() returned %d\n", result);
        goto finish;
    }
    loopbackData.inputStream = recorder.getStream();
    argParser.compareWithStream(loopbackData.inputStream);

    // This is the number of frames that are read in one chunk by a DMA controller
    // or a DSP or a mixer.
    framesPerBurst = AAudioStream_getFramesPerBurst(outputStream);

    actualInputFormat = AAudioStream_getFormat(outputStream);
    assert(actualInputFormat == AAUDIO_FORMAT_PCM_I16);


    loopbackData.actualInputChannelCount = recorder.getChannelCount();
    loopbackData.actualOutputChannelCount = player.getChannelCount();

    // Allocate a buffer for the audio data.
    loopbackData.inputFramesMaximum = 32 * framesPerBurst;
    loopbackData.inputBuffersToDiscard = 200;

    loopbackData.inputData = new int16_t[loopbackData.inputFramesMaximum
                                         * loopbackData.actualInputChannelCount];
    loopbackData.conversionBuffer = new float[loopbackData.inputFramesMaximum *
                                              loopbackData.actualInputChannelCount];

    loopbackData.loopbackProcessor->reset();

    result = recorder.start();
    if (result != AAUDIO_OK) {
        printf("ERROR - AAudioStream_requestStart(input) returned %d = %s\n",
               result, AAudio_convertResultToText(result));
        goto finish;
    }

    result = player.start();
    if (result != AAUDIO_OK) {
        printf("ERROR - AAudioStream_requestStart(output) returned %d = %s\n",
               result, AAudio_convertResultToText(result));
        goto finish;
    }

    printf("------- sleep while the callback runs --------------\n");
    fflush(stdout);
    for (int i = requestedDuration; i > 0 ; i--) {
        if (loopbackData.inputError != AAUDIO_OK) {
            printf("  ERROR on input stream\n");
            break;
        } else if (loopbackData.outputError != AAUDIO_OK) {
                printf("  ERROR on output stream\n");
                break;
        } else if (loopbackData.isDone) {
                printf("  test says it is done!\n");
                break;
        } else {
            sleep(1);
            printf("%4d: ", i);
            loopbackData.loopbackProcessor->printStatus();

            int64_t inputFramesWritten = AAudioStream_getFramesWritten(loopbackData.inputStream);
            int64_t inputFramesRead = AAudioStream_getFramesRead(loopbackData.inputStream);
            int64_t outputFramesWritten = AAudioStream_getFramesWritten(outputStream);
            int64_t outputFramesRead = AAudioStream_getFramesRead(outputStream);
            printf(" INPUT: wr %lld rd %lld state %s, OUTPUT: wr %lld rd %lld state %s, xruns %d\n",
                   (long long) inputFramesWritten,
                   (long long) inputFramesRead,
                   AAudio_convertStreamStateToText(AAudioStream_getState(loopbackData.inputStream)),
                   (long long) outputFramesWritten,
                   (long long) outputFramesRead,
                   AAudio_convertStreamStateToText(AAudioStream_getState(outputStream)),
                   AAudioStream_getXRunCount(outputStream)
            );
        }
    }

    if (loopbackData.loopbackProcessor->getResult() < 0) {
        printf("ERROR: Could not get a good loopback signal. Probably because the volume was too low.\n");
    } else {
        printf("input error = %d = %s\n",
               loopbackData.inputError, AAudio_convertResultToText(loopbackData.inputError));

        printf("AAudioStream_getXRunCount %d\n", AAudioStream_getXRunCount(outputStream));
        printf("framesRead    = %8d\n", (int) AAudioStream_getFramesRead(outputStream));
        printf("framesWritten = %8d\n", (int) AAudioStream_getFramesWritten(outputStream));
        printf("min numFrames = %8d\n", (int) loopbackData.minNumFrames);
        printf("max numFrames = %8d\n", (int) loopbackData.maxNumFrames);

        if (loopbackData.inputError == AAUDIO_OK) {
            if (testMode == TEST_SINE_MAGNITUDE) {
                printAudioGraph(loopbackData.audioRecording, 200);
            }
            loopbackData.loopbackProcessor->report();
        }

        int written = loopbackData.loopbackProcessor->save(FILENAME_ECHOS);
        if (written > 0) {
            printf("main() wrote %8d mono samples to \"%s\" on Android device\n",
                   written, FILENAME_ECHOS);
        }

        written = loopbackData.audioRecording.save(FILENAME_ALL);
        if (written > 0) {
            printf("main() wrote %8d mono samples to \"%s\" on Android device\n",
                   written, FILENAME_ALL);
        }
    }

finish:
    player.close();
    recorder.close();
    delete[] loopbackData.conversionBuffer;
    delete[] loopbackData.inputData;
    delete[] outputData;

    printf(RESULT_TAG "result = %s\n", AAudio_convertResultToText(result));
    if ((result != AAUDIO_OK)) {
        return EXIT_FAILURE;
    } else {
        printf("SUCCESS\n");
        return EXIT_SUCCESS;
    }
}

