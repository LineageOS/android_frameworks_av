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

#include <algorithm>
#include <assert.h>
#include <cctype>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <aaudio/AAudio.h>
#include <aaudio/AAudioTesting.h>

// Tag for machine readable results as property = value pairs
#define RESULT_TAG              "RESULT: "
#define SAMPLE_RATE             48000
#define NUM_SECONDS             5
#define NUM_INPUT_CHANNELS      1
#define FILENAME                "/data/oboe_input.raw"

#define NANOS_PER_MICROSECOND ((int64_t)1000)
#define NANOS_PER_MILLISECOND (NANOS_PER_MICROSECOND * 1000)
#define MILLIS_PER_SECOND     1000
#define NANOS_PER_SECOND      (NANOS_PER_MILLISECOND * MILLIS_PER_SECOND)

#define MAX_ZEROTH_PARTIAL_BINS   40

static const float s_Impulse[] = {
        0.0f, 0.0f, 0.0f, 0.0f, 0.0f, // silence on each side of the impulse
        0.5f, 0.9f, 0.0f, -0.9f, -0.5f, // bipolar
        0.0f, 0.0f, 0.0f, 0.0f, 0.0f};


static double calculateCorrelation(const float *a,
                                   const float *b,
                                   int windowSize)
{
    double correlation = 0.0;
    double sumProducts = 0.0;
    double sumSquares = 0.0;

    // Correlate a against b.
    for (int i = 0; i < windowSize; i++) {
        float s1 = a[i];
        float s2 = b[i];
        // Use a normalized cross-correlation.
        sumProducts += s1 * s2;
        sumSquares += ((s1 * s1) + (s2 * s2));
    }

    if (sumSquares >= 0.00000001) {
        correlation = (float) (2.0 * sumProducts / sumSquares);
    }
    return correlation;
}

static int calculateCorrelations(const float *haystack, int haystackSize,
                                 const float *needle, int needleSize,
                                 float *results, int resultSize)
{
    int ic;
    int maxCorrelations = haystackSize - needleSize;
    int numCorrelations = std::min(maxCorrelations, resultSize);

    for (ic = 0; ic < numCorrelations; ic++) {
        double correlation = calculateCorrelation(&haystack[ic], needle, needleSize);
        results[ic] = correlation;
    }

    return numCorrelations;
}

/*==========================================================================================*/
/**
 * Scan until we get a correlation of a single scan that goes over the tolerance level,
 * peaks then drops back down.
 */
static double findFirstMatch(const float *haystack, int haystackSize,
                             const float *needle, int needleSize, double threshold  )
{
    int ic;
    // How many correlations can we calculate?
    int numCorrelations = haystackSize - needleSize;
    double maxCorrelation = 0.0;
    int peakIndex = -1;
    double location = -1.0;

    for (ic = 0; ic < numCorrelations; ic++) {
        double correlation = calculateCorrelation(&haystack[ic], needle, needleSize);

        if( (correlation > maxCorrelation) ) {
            maxCorrelation = correlation;
            peakIndex = ic;
        }

        //printf("PaQa_FindFirstMatch: ic = %4d, correlation = %8f, maxSum = %8f\n",
        //    ic, correlation, maxSum );
        // Are we past what we were looking for?
        if((maxCorrelation > threshold) && (correlation < 0.5 * maxCorrelation)) {
            location = peakIndex;
            break;
        }
    }

    return location;
}

typedef struct LatencyReport_s {
    double latencyInFrames;
    double confidence;
} LatencyReport;

// Apply a technique similar to Harmonic Product Spectrum Analysis to find echo fundamental.
// Using first echo instead of the original impulse for a better match.
int measureLatencyFromEchos(const float *haystack, int haystackSize,
                          const float *needle, int needleSize,
                          LatencyReport *report) {
    double threshold = 0.1;

    // Find first peak
    int first = (int) (findFirstMatch(haystack,
                                      haystackSize,
                                      needle,
                                      needleSize,
                                      threshold) + 0.5);

    // Use first echo as the needle for the other echos because
    // it will be more similar.
    needle = &haystack[first];
    int again = (int) (findFirstMatch(haystack,
                                      haystackSize,
                                      needle,
                                      needleSize,
                                      threshold) + 0.5);

    printf("first = %d, again at %d\n", first, again);
    first = again;

    // Allocate results array
    int remaining = haystackSize - first;
    int generous = 48000 * 2;
    int numCorrelations = std::min(remaining, generous);
    float *correlations = new float[numCorrelations];
    float *harmonicSums = new float[numCorrelations](); // cleared to zero

    // Generate correlation for every position.
    numCorrelations = calculateCorrelations(&haystack[first], remaining,
                                            needle, needleSize,
                                            correlations, numCorrelations);

    // Add higher harmonics mapped onto lower harmonics.
    // This reinforces the "fundamental" echo.
    const int numEchoes = 10;
    for (int partial = 1; partial < numEchoes; partial++) {
        for (int i = 0; i < numCorrelations; i++) {
            harmonicSums[i / partial] += correlations[i] / partial;
        }
    }

    // Find highest peak in correlation array.
    float maxCorrelation = 0.0;
    float sumOfPeaks = 0.0;
    int peakIndex = 0;
    const int skip = MAX_ZEROTH_PARTIAL_BINS; // skip low bins
    for (int i = skip; i < numCorrelations; i++) {
        if (harmonicSums[i] > maxCorrelation) {
            maxCorrelation = harmonicSums[i];
            sumOfPeaks += maxCorrelation;
            peakIndex = i;
            printf("maxCorrelation = %f at %d\n", maxCorrelation, peakIndex);
        }
    }

    report->latencyInFrames = peakIndex;
    if (sumOfPeaks < 0.0001) {
        report->confidence = 0.0;
    } else {
        report->confidence = maxCorrelation / sumOfPeaks;
    }

    delete[] correlations;
    delete[] harmonicSums;
    return 0;
}

class AudioRecording
{
public:
    AudioRecording() {
    }
    ~AudioRecording() {
        delete[] mData;
    }

    void allocate(int maxFrames) {
        delete[] mData;
        mData = new float[maxFrames];
        mMaxFrames = maxFrames;
    }

    // Write SHORT data from the first channel.
    int write(int16_t *inputData, int inputChannelCount, int numFrames) {
        // stop at end of buffer
        if ((mFrameCounter + numFrames) > mMaxFrames) {
            numFrames = mMaxFrames - mFrameCounter;
        }
        for (int i = 0; i < numFrames; i++) {
            mData[mFrameCounter++] = inputData[i * inputChannelCount] * (1.0f / 32768);
        }
        return numFrames;
    }

    // Write FLOAT data from the first channel.
    int write(float *inputData, int inputChannelCount, int numFrames) {
        // stop at end of buffer
        if ((mFrameCounter + numFrames) > mMaxFrames) {
            numFrames = mMaxFrames - mFrameCounter;
        }
        for (int i = 0; i < numFrames; i++) {
            mData[mFrameCounter++] = inputData[i * inputChannelCount];
        }
        return numFrames;
    }

    int size() {
        return mFrameCounter;
    }

    float *getData() {
        return mData;
    }

    int save(const char *fileName, bool writeShorts = true) {
        int written = 0;
        const int chunkSize = 64;
        FILE *fid = fopen(fileName, "wb");
        if (fid == NULL) {
            return -errno;
        }

        if (writeShorts) {
            int16_t buffer[chunkSize];
            int32_t framesLeft = mFrameCounter;
            int32_t cursor = 0;
            while (framesLeft) {
                int32_t framesToWrite = framesLeft < chunkSize ? framesLeft : chunkSize;
                for (int i = 0; i < framesToWrite; i++) {
                    buffer[i] = (int16_t) (mData[cursor++] * 32767);
                }
                written += fwrite(buffer, sizeof(int16_t), framesToWrite, fid);
                framesLeft -= framesToWrite;
            }
        } else {
            written = fwrite(mData, sizeof(float), mFrameCounter, fid);
        }
        fclose(fid);
        return written;
    }

private:
    float  *mData = nullptr;
    int32_t mFrameCounter = 0;
    int32_t mMaxFrames = 0;
};

// ====================================================================================
class LoopbackProcessor {
public:
    virtual ~LoopbackProcessor() = default;

    virtual void process(float *inputData, int inputChannelCount,
                 float *outputData, int outputChannelCount,
                 int numFrames) = 0;


    virtual void report() = 0;

    void setSampleRate(int32_t sampleRate) {
        mSampleRate = sampleRate;
    }

    int32_t getSampleRate() {
        return mSampleRate;
    }

private:
    int32_t mSampleRate = SAMPLE_RATE;
};


// ====================================================================================
class EchoAnalyzer : public LoopbackProcessor {
public:

    EchoAnalyzer() : LoopbackProcessor() {
        audioRecorder.allocate(NUM_SECONDS * SAMPLE_RATE);
    }

    void setGain(float gain) {
        mGain = gain;
    }

    float getGain() {
        return mGain;
    }

    void report() override {

        const float *needle = s_Impulse;
        int needleSize = (int)(sizeof(s_Impulse) / sizeof(float));
        float *haystack = audioRecorder.getData();
        int haystackSize = audioRecorder.size();
        int result = measureLatencyFromEchos(haystack, haystackSize,
                                              needle, needleSize,
                                              &latencyReport);
        if (latencyReport.confidence < 0.01) {
            printf(" ERROR - confidence too low = %f\n", latencyReport.confidence);
        } else {
            double latencyMillis = 1000.0 * latencyReport.latencyInFrames / getSampleRate();
            printf(RESULT_TAG "latency.frames     = %8.2f\n", latencyReport.latencyInFrames);
            printf(RESULT_TAG "latency.msec       = %8.2f\n", latencyMillis);
            printf(RESULT_TAG "latency.confidence = %8.6f\n", latencyReport.confidence);
        }
    }

    void process(float *inputData, int inputChannelCount,
                 float *outputData, int outputChannelCount,
                 int numFrames) override {
        int channelsValid = std::min(inputChannelCount, outputChannelCount);

        audioRecorder.write(inputData, inputChannelCount, numFrames);

        if (mLoopCounter < mLoopStart) {
            // Output silence at the beginning.
            for (int i = 0; i < numFrames; i++) {
                int ic;
                for (ic = 0; ic < outputChannelCount; ic++) {
                    outputData[ic] = 0;
                }
                inputData += inputChannelCount;
                outputData += outputChannelCount;
            }
        } else if (mLoopCounter == mLoopStart) {
            // Send a bipolar impulse that we can easily detect.
            for (float sample : s_Impulse) {
                *outputData = sample;
                outputData += outputChannelCount;
            }
        } else {
            // Echo input to output.
            for (int i = 0; i < numFrames; i++) {
                int ic;
                for (ic = 0; ic < channelsValid; ic++) {
                    outputData[ic] = inputData[ic] * mGain;
                }
                for (; ic < outputChannelCount; ic++) {
                    outputData[ic] = 0;
                }
                inputData += inputChannelCount;
                outputData += outputChannelCount;
            }
        }

        mLoopCounter++;
    }

private:
    int   mLoopCounter = 0;
    int   mLoopStart = 1000;
    float mGain = 1.0f;

    AudioRecording     audioRecorder;
    LatencyReport      latencyReport;
};


// ====================================================================================
class SineAnalyzer : public LoopbackProcessor {
public:

    void report() override {
        double magnitude = calculateMagnitude();
        printf("sine magnitude = %7.5f\n", magnitude);
        printf("sine frames    = %7d\n", mFrameCounter);
        printf("sine frequency = %7.1f Hz\n", mFrequency);
    }

    double calculateMagnitude(double *phasePtr = NULL) {
        if (mFrameCounter == 0) {
            return 0.0;
        }
        double sinMean = mSinAccumulator / mFrameCounter;
        double cosMean = mCosAccumulator / mFrameCounter;
        double magnitude = 2.0 * sqrt( (sinMean * sinMean) + (cosMean * cosMean ));
        if( phasePtr != NULL )
        {
            double phase = atan2( sinMean, cosMean );
            *phasePtr = phase;
        }
        return magnitude;
    }

    void process(float *inputData, int inputChannelCount,
                 float *outputData, int outputChannelCount,
                 int numFrames) override {
        double phaseIncrement = 2.0 * M_PI * mFrequency / getSampleRate();

        for (int i = 0; i < numFrames; i++) {
            // Multiply input by sine/cosine
            float sample = inputData[i * inputChannelCount];
            float sinOut = sinf(mPhase);
            mSinAccumulator += sample * sinOut;
            mCosAccumulator += sample * cosf(mPhase);
            // Advance and wrap phase
            mPhase += phaseIncrement;
            if (mPhase > (2.0 * M_PI)) {
                mPhase -= (2.0 * M_PI);
            }

            // Output sine wave so we can measure it.
            outputData[i * outputChannelCount] = sinOut;
        }
        mFrameCounter += numFrames;

        double magnitude = calculateMagnitude();
        if (mWaiting) {
            if (magnitude < 0.001) {
                // discard silence
                mFrameCounter = 0;
                mSinAccumulator = 0.0;
                mCosAccumulator = 0.0;
            } else {
                mWaiting = false;
            }
        }
    };

    void setFrequency(int32_t frequency) {
        mFrequency = frequency;
    }

    int32_t getFrequency() {
        return mFrequency;
    }

private:
    double  mFrequency = 300.0;
    double  mPhase = 0.0;
    int32_t mFrameCounter = 0;
    double  mSinAccumulator = 0.0;
    double  mCosAccumulator = 0.0;
    bool    mWaiting = true;
};

// TODO make this a class that manages its own buffer allocation
struct LoopbackData {
    AAudioStream      *inputStream = nullptr;
    int32_t            inputFramesMaximum = 0;
    int16_t           *inputData = nullptr;
    float             *conversionBuffer = nullptr;
    int32_t            actualInputChannelCount = 0;
    int32_t            actualOutputChannelCount = 0;
    int32_t            inputBuffersToDiscard = 10;

    aaudio_result_t    inputError;
    SineAnalyzer       sineAnalyzer;
    EchoAnalyzer       echoAnalyzer;
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

    if (myData->inputBuffersToDiscard > 0) {
        // Drain the input.
        do {
            framesRead = AAudioStream_read(myData->inputStream, myData->inputData,
                                       numFrames, 0);
            if (framesRead < 0) {
                myData->inputError = framesRead;
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
            result = AAUDIO_CALLBACK_RESULT_STOP;
        } else if (framesRead > 0) {

            int32_t numSamples = framesRead * myData->actualInputChannelCount;
            convertPcm16ToFloat(myData->inputData, myData->conversionBuffer, numSamples);

            myData->loopbackProcessor->process(myData->conversionBuffer,
                                              myData->actualInputChannelCount,
                                              outputData,
                                              myData->actualOutputChannelCount,
                                              framesRead);
        }
    }

    return result;
}


static void usage() {
    printf("loopback: -n{numBursts} -p{outPerf} -P{inPerf} -t{test} -g{gain} -f{freq}\n");
    printf("          -c{inputChannels}\n");
    printf("          -f{freq}  sine frequency\n");
    printf("          -g{gain}  recirculating loopback gain\n");
    printf("          -m enable MMAP mode\n");
    printf("          -n{numBursts} buffer size, for example 2 for double buffered\n");
    printf("          -p{outPerf}  set output AAUDIO_PERFORMANCE_MODE*\n");
    printf("          -P{inPerf}   set input AAUDIO_PERFORMANCE_MODE*\n");
    printf("              n for _NONE\n");
    printf("              l for _LATENCY\n");
    printf("              p for _POWER_SAVING;\n");
    printf("          -t{test}   select test mode\n");
    printf("              m for sine magnitude\n");
    printf("              e for echo latency (default)\n");
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
            printf("ERROR in value performance mode %c\n", c);
            break;
    }
    return mode;
}

enum {
    TEST_SINE_MAGNITUDE = 0,
    TEST_ECHO_LATENCY,
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
        default:
            printf("ERROR in value test mode %c\n", c);
            break;
    }
    return testMode;
}

// ====================================================================================
// TODO break up this large main() function into smaller functions
int main(int argc, const char **argv)
{
    aaudio_result_t result = AAUDIO_OK;
    LoopbackData loopbackData;
    AAudioStream *outputStream = nullptr;

    int requestedInputChannelCount = NUM_INPUT_CHANNELS;
    const int requestedOutputChannelCount = AAUDIO_UNSPECIFIED;
    const int requestedSampleRate = SAMPLE_RATE;
    int actualSampleRate = 0;
    const aaudio_format_t requestedInputFormat = AAUDIO_FORMAT_PCM_I16;
    const aaudio_format_t requestedOutputFormat = AAUDIO_FORMAT_PCM_FLOAT;
    aaudio_format_t actualInputFormat;
    aaudio_format_t actualOutputFormat;
    int testMode = TEST_ECHO_LATENCY;
    double frequency = 1000.0;
    double gain = 1.0;

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
                case 'c':
                    requestedInputChannelCount = atoi(&arg[2]);
                    break;
                case 'f':
                    frequency = atof(&arg[2]);
                    break;
                case 'g':
                    gain = atof(&arg[2]);
                    break;
                case 'm':
                    AAudio_setMMapPolicy(AAUDIO_POLICY_AUTO);
                    break;
                case 'n':
                    burstsPerBuffer = atoi(&arg[2]);
                    break;
                case 'p':
                    outputPerformanceLevel = parsePerformanceMode(arg[2]);
                    break;
                case 'P':
                    inputPerformanceLevel = parsePerformanceMode(arg[2]);
                    break;
                case 't':
                    testMode = parseTestMode(arg[2]);
                    break;
                default:
                    usage();
                    exit(0);
                    break;
            }
        } else {
            usage();
            exit(0);
            break;
        }
    }


    switch(testMode) {
        case TEST_SINE_MAGNITUDE:
            loopbackData.sineAnalyzer.setFrequency(frequency);
            loopbackData.loopbackProcessor = &loopbackData.sineAnalyzer;
            break;
        case TEST_ECHO_LATENCY:
            loopbackData.echoAnalyzer.setGain(gain);
            loopbackData.loopbackProcessor = &loopbackData.echoAnalyzer;
            break;
        default:
            exit(1);
            break;
    }

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
    printf("    bufferSize     = %d\n",
           AAudioStream_getBufferSizeInFrames(loopbackData.inputStream));
    printf("    bufferCapacity = %d\n",
           AAudioStream_getBufferCapacityInFrames(loopbackData.inputStream));

    actualSharingMode = AAudioStream_getSharingMode(loopbackData.inputStream);
    printf("    sharingMode: requested = %d, actual = %d\n",
           requestedSharingMode, actualSharingMode);

    actualInputFormat = AAudioStream_getFormat(loopbackData.inputStream);
    printf("    dataFormat: requested = %d, actual = %d\n",
           requestedInputFormat, actualInputFormat);
    assert(actualInputFormat == AAUDIO_FORMAT_PCM_I16);

    printf("    is MMAP used?         = %s\n", AAudioStream_isMMapUsed(loopbackData.inputStream)
                                               ? "yes" : "no");


    printf("Stream OUTPUT ---------------------\n");
    // Check to see what kind of stream we actually got.
    actualSampleRate = AAudioStream_getSampleRate(outputStream);
    printf("    sampleRate: requested = %d, actual = %d\n", requestedSampleRate, actualSampleRate);
    loopbackData.echoAnalyzer.setSampleRate(actualSampleRate);

    loopbackData.actualOutputChannelCount = AAudioStream_getChannelCount(outputStream);
    printf("    channelCount: requested = %d, actual = %d\n", requestedOutputChannelCount,
           loopbackData.actualOutputChannelCount);

    actualSharingMode = AAudioStream_getSharingMode(outputStream);
    printf("    sharingMode: requested = %d, actual = %d\n",
           requestedSharingMode, actualSharingMode);

    // This is the number of frames that are read in one chunk by a DMA controller
    // or a DSP or a mixer.
    framesPerBurst = AAudioStream_getFramesPerBurst(outputStream);
    printf("    framesPerBurst = %d\n", framesPerBurst);

    result = AAudioStream_setBufferSizeInFrames(outputStream, burstsPerBuffer * framesPerBurst);
    if (result < 0) { // may be positive buffer size
        fprintf(stderr, "ERROR - AAudioStream_setBufferSize() returned %d\n", result);
        goto finish;
    }
    printf("    bufferSize     = %d\n", AAudioStream_getBufferSizeInFrames(outputStream));
    printf("    bufferCapacity = %d\n", AAudioStream_getBufferCapacityInFrames(outputStream));

    actualOutputFormat = AAudioStream_getFormat(outputStream);
    printf("    dataFormat: requested = %d, actual = %d\n",
           requestedOutputFormat, actualOutputFormat);
    assert(actualOutputFormat == AAUDIO_FORMAT_PCM_FLOAT);

    printf("    is MMAP used?         = %s\n", AAudioStream_isMMapUsed(outputStream)
                                               ? "yes" : "no");

    // Allocate a buffer for the audio data.
    loopbackData.inputFramesMaximum = 32 * framesPerBurst;
    loopbackData.inputBuffersToDiscard = 100;

    loopbackData.inputData = new int16_t[loopbackData.inputFramesMaximum
                                         * loopbackData.actualInputChannelCount];
    loopbackData.conversionBuffer = new float[loopbackData.inputFramesMaximum *
                                              loopbackData.actualInputChannelCount];


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

    loopbackData.loopbackProcessor->report();

//    {
//        int written = loopbackData.audioRecorder.save(FILENAME);
//        printf("wrote %d mono samples to %s on Android device\n", written, FILENAME);
//    }


finish:
    AAudioStream_close(outputStream);
    AAudioStream_close(loopbackData.inputStream);
    delete[] loopbackData.conversionBuffer;
    delete[] loopbackData.inputData;
    delete[] outputData;
    AAudioStreamBuilder_delete(builder);

    printf(RESULT_TAG "error = %d = %s\n", result, AAudio_convertResultToText(result));
    if ((result != AAUDIO_OK)) {
        printf("error %d = %s\n", result, AAudio_convertResultToText(result));
        return EXIT_FAILURE;
    } else {
        printf("SUCCESS\n");
        return EXIT_SUCCESS;
    }
}

