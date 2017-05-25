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

// Play an impulse and then record it.
// Measure the round trip latency.

#include <assert.h>
#include <cctype>
#include <math.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <aaudio/AAudio.h>

#define INPUT_PEAK_THRESHOLD    0.1f
#define SILENCE_FRAMES          10000
#define SAMPLE_RATE             48000
#define NUM_SECONDS             7
#define FILENAME                "/data/oboe_input.raw"

#define NANOS_PER_MICROSECOND ((int64_t)1000)
#define NANOS_PER_MILLISECOND (NANOS_PER_MICROSECOND * 1000)
#define MILLIS_PER_SECOND     1000
#define NANOS_PER_SECOND      (NANOS_PER_MILLISECOND * MILLIS_PER_SECOND)

class AudioRecorder
{
public:
    AudioRecorder() {
    }
    ~AudioRecorder() {
        delete[] mData;
    }

    void allocate(int maxFrames) {
        delete[] mData;
        mData = new float[maxFrames];
        mMaxFrames = maxFrames;
    }

    void record(int16_t *inputData, int inputChannelCount, int numFrames) {
        // stop at end of buffer
        if ((mFrameCounter + numFrames) > mMaxFrames) {
            numFrames = mMaxFrames - mFrameCounter;
        }
        for (int i = 0; i < numFrames; i++) {
            mData[mFrameCounter++] = inputData[i * inputChannelCount] * (1.0f / 32768);
        }
    }

    void record(float *inputData, int inputChannelCount, int numFrames) {
        // stop at end of buffer
        if ((mFrameCounter + numFrames) > mMaxFrames) {
            numFrames = mMaxFrames - mFrameCounter;
        }
        for (int i = 0; i < numFrames; i++) {
            mData[mFrameCounter++] = inputData[i * inputChannelCount];
        }
    }

    int save(const char *fileName) {
        FILE *fid = fopen(fileName, "wb");
        if (fid == NULL) {
            return errno;
        }
        int written = fwrite(mData, sizeof(float), mFrameCounter, fid);
        fclose(fid);
        return written;
    }

private:
    float *mData = NULL;
    int32_t mFrameCounter = 0;
    int32_t mMaxFrames = 0;
};

// ====================================================================================
// ========================= Loopback Processor =======================================
// ====================================================================================
class LoopbackProcessor {
public:

    // Calculate mean and standard deviation.
    double calculateAverageLatency(double *deviation) {
        if (mLatencyCount <= 0) {
            return -1.0;
        }
        double sum = 0.0;
        for (int i = 0; i < mLatencyCount; i++) {
            sum += mLatencyArray[i];
        }
        double average = sum /  mLatencyCount;
        sum = 0.0;
        for (int i = 0; i < mLatencyCount; i++) {
            double error = average - mLatencyArray[i];
            sum += error * error; // squared
        }
        *deviation = sqrt(sum / mLatencyCount);
        return average;
    }

    float getMaxAmplitude() const { return mMaxAmplitude; }
    int   getMeasurementCount() const { return mLatencyCount; }
    float getAverageAmplitude() const { return mAmplitudeTotal / mAmplitudeCount; }

    // TODO Convert this to a feedback circuit and then use auto-correlation to measure the period.
    void process(float *inputData, int inputChannelCount,
            float *outputData, int outputChannelCount,
            int numFrames) {
        (void) outputChannelCount;

        // Measure peak and average amplitude.
        for (int i = 0; i < numFrames; i++) {
            float sample = inputData[i * inputChannelCount];
            if (sample > mMaxAmplitude) {
                mMaxAmplitude = sample;
            }
            if (sample < 0) {
                sample = 0 - sample;
            }
            mAmplitudeTotal += sample;
            mAmplitudeCount++;
        }

        // Clear output.
        memset(outputData, 0, numFrames * outputChannelCount * sizeof(float));

        // Wait a while between hearing the pulse and starting a new one.
        if (mState == STATE_SILENT) {
            mCounter += numFrames;
            if (mCounter > SILENCE_FRAMES) {
                //printf("LoopbackProcessor send impulse, burst #%d\n", mBurstCounter);
                // copy impulse
                for (float sample : mImpulse) {
                    *outputData = sample;
                    outputData += outputChannelCount;
                }
                mState = STATE_LISTENING;
                mCounter = 0;
            }
        }
        // Start listening as soon as we send the impulse.
        if (mState ==  STATE_LISTENING) {
            for (int i = 0; i < numFrames; i++) {
                float sample = inputData[i * inputChannelCount];
                if (sample >= INPUT_PEAK_THRESHOLD) {
                    mLatencyArray[mLatencyCount++] = mCounter;
                    if (mLatencyCount >= MAX_LATENCY_VALUES) {
                        mState = STATE_DONE;
                    } else {
                        mState = STATE_SILENT;
                    }
                    mCounter = 0;
                    break;
                } else {
                    mCounter++;
                }
            }
        }
    }

    void echo(float *inputData, int inputChannelCount,
            float *outputData, int outputChannelCount,
            int numFrames) {
        int channelsValid = (inputChannelCount < outputChannelCount)
            ? inputChannelCount : outputChannelCount;
        for (int i = 0; i < numFrames; i++) {
            int ic;
            for (ic = 0; ic < channelsValid; ic++) {
                outputData[ic] = inputData[ic];
            }
            for (ic = 0; ic < outputChannelCount; ic++) {
                outputData[ic] = 0;
            }
            inputData += inputChannelCount;
            outputData += outputChannelCount;
        }
    }
private:
    enum {
        STATE_SILENT,
        STATE_LISTENING,
        STATE_DONE
    };

    enum {
        MAX_LATENCY_VALUES = 64
    };

    int     mState = STATE_SILENT;
    int32_t mCounter = 0;
    int32_t mLatencyArray[MAX_LATENCY_VALUES];
    int32_t mLatencyCount = 0;
    float   mMaxAmplitude = 0;
    float   mAmplitudeTotal = 0;
    int32_t mAmplitudeCount = 0;
    static const float mImpulse[5];
};

const float LoopbackProcessor::mImpulse[5] = {0.5f, 0.9f, 0.0f, -0.9f, -0.5f};

// TODO make this a class that manages its own buffer allocation
struct LoopbackData {
    AAudioStream     *inputStream = nullptr;
    int32_t           inputFramesMaximum = 0;
    int16_t          *inputData = nullptr;
    float            *conversionBuffer = nullptr;
    int32_t           actualInputChannelCount = 0;
    int32_t           actualOutputChannelCount = 0;
    int32_t           inputBuffersToDiscard = 10;

    aaudio_result_t   inputError;
    LoopbackProcessor loopbackProcessor;
    AudioRecorder     audioRecorder;
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
    LoopbackData *myData = (LoopbackData *) userData;
    float  *outputData = (float  *) audioData;

    // Read audio data from the input stream.
    int32_t framesRead;

    if (numFrames > myData->inputFramesMaximum) {
        myData->inputError = AAUDIO_ERROR_OUT_OF_RANGE;
        return AAUDIO_CALLBACK_RESULT_STOP;
    }

    if (myData->inputBuffersToDiscard > 0) {
        // Drain the input.
        do {
            framesRead = AAudioStream_read(myData->inputStream, myData->inputData,
                                       numFrames, 0);
            if (framesRead < 0) {
                myData->inputError = framesRead;
            } else if (framesRead > 0) {
                myData->inputBuffersToDiscard--;
            }
        } while(framesRead > 0);
    } else {
        framesRead = AAudioStream_read(myData->inputStream, myData->inputData,
                                       numFrames, 0);
        if (framesRead < 0) {
            myData->inputError = framesRead;
        } else if (framesRead > 0) {
            // Process valid input data.
            myData->audioRecorder.record(myData->inputData,
                                         myData->actualInputChannelCount,
                                         framesRead);

            int32_t numSamples = framesRead * myData->actualInputChannelCount;
            convertPcm16ToFloat(myData->inputData, myData->conversionBuffer, numSamples);

            myData->loopbackProcessor.process(myData->conversionBuffer,
                                              myData->actualInputChannelCount,
                                              outputData,
                                              myData->actualOutputChannelCount,
                                              framesRead);
        }
    }

    return AAUDIO_CALLBACK_RESULT_CONTINUE;
}

static void usage() {
    printf("loopback: -b{burstsPerBuffer} -p{outputPerfMode} -P{inputPerfMode}\n");
    printf("          -b{burstsPerBuffer} for example 2 for double buffered\n");
    printf("          -p{outputPerfMode}  set output AAUDIO_PERFORMANCE_MODE*\n");
    printf("          -P{inputPerfMode}   set input AAUDIO_PERFORMANCE_MODE*\n");
    printf("              n for _NONE\n");
    printf("              l for _LATENCY\n");
    printf("              p for _POWER_SAVING;\n");
    printf("For example:  loopback -b2 -pl -Pn\n");
}

static aaudio_performance_mode_t parsePerformanceMode(char c) {
    aaudio_performance_mode_t mode = AAUDIO_PERFORMANCE_MODE_NONE;
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
            printf("ERROR invalue performance mode %c\n", c);
            break;
    }
    return mode;
}

// ====================================================================================
// TODO break up this large main() function into smaller functions
int main(int argc, const char **argv)
{
    aaudio_result_t result = AAUDIO_OK;
    LoopbackData loopbackData;
    AAudioStream *outputStream = nullptr;

    const int requestedInputChannelCount = 1;
    const int requestedOutputChannelCount = AAUDIO_UNSPECIFIED;
    const int requestedSampleRate = SAMPLE_RATE;
    int actualSampleRate = 0;
    const aaudio_audio_format_t requestedInputFormat = AAUDIO_FORMAT_PCM_I16;
    const aaudio_audio_format_t requestedOutputFormat = AAUDIO_FORMAT_PCM_FLOAT;
    aaudio_audio_format_t actualInputFormat;
    aaudio_audio_format_t actualOutputFormat;

    const aaudio_sharing_mode_t requestedSharingMode = AAUDIO_SHARING_MODE_EXCLUSIVE;
    //const aaudio_sharing_mode_t requestedSharingMode = AAUDIO_SHARING_MODE_SHARED;
    aaudio_sharing_mode_t       actualSharingMode;

    AAudioStreamBuilder  *builder = nullptr;
    aaudio_stream_state_t state = AAUDIO_STREAM_STATE_UNINITIALIZED;
    int32_t framesPerBurst = 0;
    float *outputData = NULL;
    double deviation;
    double latency;
    aaudio_performance_mode_t outputPerformanceLevel = AAUDIO_PERFORMANCE_MODE_LOW_LATENCY;
    aaudio_performance_mode_t inputPerformanceLevel = AAUDIO_PERFORMANCE_MODE_LOW_LATENCY;

    int32_t burstsPerBuffer = 1; // single buffered

    for (int i = 1; i < argc; i++) {
        const char *arg = argv[i];
        if (arg[0] == '-') {
            char option = arg[1];
            switch (option) {
                case 'b':
                    burstsPerBuffer = atoi(&arg[2]);
                    break;
                case 'p':
                    outputPerformanceLevel = parsePerformanceMode(arg[2]);
                    break;
                case 'P':
                    inputPerformanceLevel = parsePerformanceMode(arg[2]);
                    break;
                default:
                    usage();
                    break;
            }
        } else {
            break;
        }
    }

    loopbackData.audioRecorder.allocate(NUM_SECONDS * SAMPLE_RATE);

    // Make printf print immediately so that debug info is not stuck
    // in a buffer if we hang or crash.
    setvbuf(stdout, NULL, _IONBF, (size_t) 0);

    printf("%s - Audio loopback using AAudio\n", argv[0]);

    // Use an AAudioStreamBuilder to contain requested parameters.
    result = AAudio_createStreamBuilder(&builder);
    if (result < 0) {
        goto finish;
    }

    // Request common stream properties.
    AAudioStreamBuilder_setSampleRate(builder, requestedSampleRate);
    AAudioStreamBuilder_setFormat(builder, requestedInputFormat);
    AAudioStreamBuilder_setSharingMode(builder, requestedSharingMode);

    // Open the input stream.
    AAudioStreamBuilder_setDirection(builder, AAUDIO_DIRECTION_INPUT);
    AAudioStreamBuilder_setPerformanceMode(builder, inputPerformanceLevel);
    AAudioStreamBuilder_setChannelCount(builder, requestedInputChannelCount);

    result = AAudioStreamBuilder_openStream(builder, &loopbackData.inputStream);
    printf("AAudioStreamBuilder_openStream(input) returned %d = %s\n",
           result, AAudio_convertResultToText(result));
    if (result < 0) {
        goto finish;
    }

    // Create an output stream using the Builder.
    AAudioStreamBuilder_setDirection(builder, AAUDIO_DIRECTION_OUTPUT);
    AAudioStreamBuilder_setFormat(builder, requestedOutputFormat);
    AAudioStreamBuilder_setPerformanceMode(builder, outputPerformanceLevel);
    AAudioStreamBuilder_setChannelCount(builder, requestedOutputChannelCount);
    AAudioStreamBuilder_setDataCallback(builder, MyDataCallbackProc, &loopbackData);

    result = AAudioStreamBuilder_openStream(builder, &outputStream);
    printf("AAudioStreamBuilder_openStream(output) returned %d = %s\n",
           result, AAudio_convertResultToText(result));
    if (result != AAUDIO_OK) {
        goto finish;
    }

    printf("Stream INPUT ---------------------\n");
    loopbackData.actualInputChannelCount = AAudioStream_getChannelCount(loopbackData.inputStream);
    printf("    channelCount: requested = %d, actual = %d\n", requestedInputChannelCount,
           loopbackData.actualInputChannelCount);
    printf("    framesPerBurst = %d\n", AAudioStream_getFramesPerBurst(loopbackData.inputStream));

    actualInputFormat = AAudioStream_getFormat(loopbackData.inputStream);
    printf("    dataFormat: requested = %d, actual = %d\n", requestedInputFormat, actualInputFormat);
    assert(actualInputFormat == AAUDIO_FORMAT_PCM_I16);

    printf("Stream OUTPUT ---------------------\n");
    // Check to see what kind of stream we actually got.
    actualSampleRate = AAudioStream_getSampleRate(outputStream);
    printf("    sampleRate: requested = %d, actual = %d\n", requestedSampleRate, actualSampleRate);

    loopbackData.actualOutputChannelCount = AAudioStream_getChannelCount(outputStream);
    printf("    channelCount: requested = %d, actual = %d\n", requestedOutputChannelCount,
           loopbackData.actualOutputChannelCount);

    actualSharingMode = AAudioStream_getSharingMode(outputStream);
    printf("    sharingMode: requested = %d, actual = %d\n", requestedSharingMode, actualSharingMode);

    // This is the number of frames that are read in one chunk by a DMA controller
    // or a DSP or a mixer.
    framesPerBurst = AAudioStream_getFramesPerBurst(outputStream);
    printf("    framesPerBurst = %d\n", framesPerBurst);

    printf("    bufferCapacity = %d\n", AAudioStream_getBufferCapacityInFrames(outputStream));

    actualOutputFormat = AAudioStream_getFormat(outputStream);
    printf("    dataFormat: requested = %d, actual = %d\n", requestedOutputFormat, actualOutputFormat);
    assert(actualOutputFormat == AAUDIO_FORMAT_PCM_FLOAT);

    // Allocate a buffer for the audio data.
    loopbackData.inputFramesMaximum = 32 * framesPerBurst;

    loopbackData.inputData = new int16_t[loopbackData.inputFramesMaximum * loopbackData.actualInputChannelCount];
    loopbackData.conversionBuffer = new float[loopbackData.inputFramesMaximum *
                                              loopbackData.actualInputChannelCount];

    result = AAudioStream_setBufferSizeInFrames(outputStream, burstsPerBuffer * framesPerBurst);
    if (result < 0) { // may be positive buffer size
        fprintf(stderr, "ERROR - AAudioStream_setBufferSize() returned %d\n", result);
        goto finish;
    }
    printf("AAudioStream_setBufferSize() actual = %d\n",result);

    // Start output first so input stream runs low.
    result = AAudioStream_requestStart(outputStream);
    if (result != AAUDIO_OK) {
        fprintf(stderr, "ERROR - AAudioStream_requestStart(output) returned %d = %s\n",
                result, AAudio_convertResultToText(result));
        goto finish;
    }

    result = AAudioStream_requestStart(loopbackData.inputStream);
    if (result != AAUDIO_OK) {
        fprintf(stderr, "ERROR - AAudioStream_requestStart(input) returned %d = %s\n",
                result, AAudio_convertResultToText(result));
        goto finish;
    }

    printf("------- sleep while the callback runs --------------\n");
    fflush(stdout);
    sleep(NUM_SECONDS);


    printf("input error = %d = %s\n",
                loopbackData.inputError, AAudio_convertResultToText(loopbackData.inputError));

    printf("AAudioStream_getXRunCount %d\n", AAudioStream_getXRunCount(outputStream));
    printf("framesRead    = %d\n", (int) AAudioStream_getFramesRead(outputStream));
    printf("framesWritten = %d\n", (int) AAudioStream_getFramesWritten(outputStream));

    latency = loopbackData.loopbackProcessor.calculateAverageLatency(&deviation);
    printf("measured peak    = %8.5f\n", loopbackData.loopbackProcessor.getMaxAmplitude());
    printf("threshold        = %8.5f\n", INPUT_PEAK_THRESHOLD);
    printf("measured average = %8.5f\n", loopbackData.loopbackProcessor.getAverageAmplitude());
    printf("# latency measurements = %d\n", loopbackData.loopbackProcessor.getMeasurementCount());
    printf("measured latency = %8.2f +/- %4.5f frames\n", latency, deviation);
    printf("measured latency = %8.2f msec  <===== !!\n", (1000.0 * latency / actualSampleRate));

    {
        int written = loopbackData.audioRecorder.save(FILENAME);
        printf("wrote %d samples to %s\n", written, FILENAME);
    }

finish:
    AAudioStream_close(outputStream);
    AAudioStream_close(loopbackData.inputStream);
    delete[] loopbackData.conversionBuffer;
    delete[] loopbackData.inputData;
    delete[] outputData;
    AAudioStreamBuilder_delete(builder);

    printf("exiting - AAudio result = %d = %s\n", result, AAudio_convertResultToText(result));
    return (result != AAUDIO_OK) ? EXIT_FAILURE : EXIT_SUCCESS;
}

