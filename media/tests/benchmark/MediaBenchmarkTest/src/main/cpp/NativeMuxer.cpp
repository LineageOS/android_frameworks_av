/*
 * Copyright (C) 2019 The Android Open Source Project
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
#define LOG_TAG "NativeMuxer"

#include <jni.h>
#include <fstream>
#include <string>
#include <sys/stat.h>

#include "Muxer.h"

MUXER_OUTPUT_T getMuxerOutFormat(const char *fmt);

extern "C" JNIEXPORT int32_t JNICALL Java_com_android_media_benchmark_library_Native_Mux(
        JNIEnv *env, jobject thiz, jstring jInputFilePath, jstring jInputFileName,
        jstring jOutputFilePath, jstring jStatsFile, jstring jFormat) {
    UNUSED(thiz);
    ALOGV("Mux the samples given by extractor");
    const char *inputFilePath = env->GetStringUTFChars(jInputFilePath, nullptr);
    const char *inputFileName = env->GetStringUTFChars(jInputFileName, nullptr);
    string sInputFile = string(inputFilePath) + string(inputFileName);
    FILE *inputFp = fopen(sInputFile.c_str(), "rb");
    if (!inputFp) {
        ALOGE("Unable to open input file for reading");
        return -1;
    }

    const char *fmt = env->GetStringUTFChars(jFormat, nullptr);
    MUXER_OUTPUT_T outputFormat = getMuxerOutFormat(fmt);
    if (outputFormat == MUXER_OUTPUT_FORMAT_INVALID) {
        ALOGE("output format is MUXER_OUTPUT_FORMAT_INVALID");
        return MUXER_OUTPUT_FORMAT_INVALID;
    }

    Muxer *muxerObj = new Muxer();
    Extractor *extractor = muxerObj->getExtractor();
    if (!extractor) {
        ALOGE("Extractor creation failed");
        return -1;
    }

    // Read file properties
    struct stat buf;
    stat(sInputFile.c_str(), &buf);
    size_t fileSize = buf.st_size;
    int32_t fd = fileno(inputFp);

    int32_t trackCount = extractor->initExtractor(fd, fileSize);
    if (trackCount <= 0) {
        ALOGE("initExtractor failed");
        return -1;
    }

    for (int curTrack = 0; curTrack < trackCount; curTrack++) {
        int32_t status = extractor->setupTrackFormat(curTrack);
        if (status != 0) {
            ALOGE("Track Format invalid");
            return -1;
        }

        uint8_t *inputBuffer = (uint8_t *) malloc(fileSize);
        if (!inputBuffer) {
            ALOGE("Allocation Failed");
            return -1;
        }
        vector<AMediaCodecBufferInfo> frameInfos;
        AMediaCodecBufferInfo info;
        uint32_t inputBufferOffset = 0;

        // Get Frame Data
        while (1) {
            status = extractor->getFrameSample(info);
            if (status || !info.size) break;
            // copy the meta data and buffer to be passed to muxer
            if (inputBufferOffset + info.size > fileSize) {
                ALOGE("Memory allocated not sufficient");
                if (inputBuffer) {
                    free(inputBuffer);
                    inputBuffer = nullptr;
                }
                return -1;
            }
            memcpy(inputBuffer + inputBufferOffset, extractor->getFrameBuf(),
                   static_cast<size_t>(info.size));
            info.offset = inputBufferOffset;
            frameInfos.push_back(info);
            inputBufferOffset += info.size;
        }

        const char *outputFilePath = env->GetStringUTFChars(jOutputFilePath, nullptr);
        FILE *outputFp = fopen(((string) outputFilePath).c_str(), "w+b");
        env->ReleaseStringUTFChars(jOutputFilePath, outputFilePath);

        if (!outputFp) {
            ALOGE("Unable to open output file for writing");
            if (inputBuffer) {
                free(inputBuffer);
                inputBuffer = nullptr;
            }
            return -1;
        }
        int32_t outFd = fileno(outputFp);

        status = muxerObj->initMuxer(outFd, (MUXER_OUTPUT_T) outputFormat);
        if (status != 0) {
            ALOGE("initMuxer failed");
            if (inputBuffer) {
                free(inputBuffer);
                inputBuffer = nullptr;
            }
            return -1;
        }

        status = muxerObj->mux(inputBuffer, frameInfos);
        if (status != 0) {
            ALOGE("Mux failed");
            if (inputBuffer) {
                free(inputBuffer);
                inputBuffer = nullptr;
            }
            return -1;
        }
        muxerObj->deInitMuxer();
        const char *statsFile = env->GetStringUTFChars(jStatsFile, nullptr);
        string muxFormat(fmt);
        muxerObj->dumpStatistics(string(inputFileName), muxFormat, statsFile);
        env->ReleaseStringUTFChars(jStatsFile, statsFile);
        env->ReleaseStringUTFChars(jInputFilePath, inputFilePath);
        env->ReleaseStringUTFChars(jInputFileName, inputFileName);

        if (inputBuffer) {
            free(inputBuffer);
            inputBuffer = nullptr;
        }
        if (outputFp) {
            fclose(outputFp);
            outputFp = nullptr;
        }
        muxerObj->resetMuxer();
    }
    if (inputFp) {
        fclose(inputFp);
        inputFp = nullptr;
    }
    env->ReleaseStringUTFChars(jFormat, fmt);
    extractor->deInitExtractor();
    delete muxerObj;

    return 0;
}

MUXER_OUTPUT_T getMuxerOutFormat(const char *fmt) {
    static const struct {
        const char *name;
        int value;
    } kFormatMaps[] = {{"mp4",  MUXER_OUTPUT_FORMAT_MPEG_4},
                       {"webm", MUXER_OUTPUT_FORMAT_WEBM},
                       {"3gpp", MUXER_OUTPUT_FORMAT_3GPP},
                       {"ogg",  MUXER_OUTPUT_FORMAT_OGG}};

    int32_t muxOutputFormat = MUXER_OUTPUT_FORMAT_INVALID;
    for (auto kFormatMap : kFormatMaps) {
        if (!strcmp(fmt, kFormatMap.name)) {
            muxOutputFormat = kFormatMap.value;
            break;
        }
    }
    return (MUXER_OUTPUT_T) muxOutputFormat;
}
