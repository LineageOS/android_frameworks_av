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
#define LOG_TAG "NativeDecoder"

#include <jni.h>
#include <fstream>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>

#include <android/log.h>

#include "Decoder.h"

extern "C" JNIEXPORT int JNICALL Java_com_android_media_benchmark_library_Native_Decode(
        JNIEnv *env, jobject thiz, jstring jFilePath, jstring jFileName, jstring jStatsFile,
        jstring jCodecName, jboolean asyncMode) {
    const char *filePath = env->GetStringUTFChars(jFilePath, nullptr);
    const char *fileName = env->GetStringUTFChars(jFileName, nullptr);
    string sFilePath = string(filePath) + string(fileName);
    UNUSED(thiz);
    FILE *inputFp = fopen(sFilePath.c_str(), "rb");
    env->ReleaseStringUTFChars(jFileName, fileName);
    env->ReleaseStringUTFChars(jFilePath, filePath);
    if (!inputFp) {
        ALOGE("Unable to open input file for reading");
        return -1;
    }

    Decoder *decoder = new Decoder();
    Extractor *extractor = decoder->getExtractor();
    if (!extractor) {
        ALOGE("Extractor creation failed");
        return -1;
    }

    // Read file properties
    struct stat buf;
    stat(sFilePath.c_str(), &buf);
    size_t fileSize = buf.st_size;
    if (fileSize > kMaxBufferSize) {
        ALOGE("File size greater than maximum buffer size");
        return -1;
    }
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
            ALOGE("Insufficient memory");
            return -1;
        }

        vector<AMediaCodecBufferInfo> frameInfo;
        AMediaCodecBufferInfo info;
        uint32_t inputBufferOffset = 0;

        // Get frame data
        while (1) {
            status = extractor->getFrameSample(info);
            if (status || !info.size) break;
            // copy the meta data and buffer to be passed to decoder
            if (inputBufferOffset + info.size > kMaxBufferSize) {
                ALOGE("Memory allocated not sufficient");
                free(inputBuffer);
                return -1;
            }
            memcpy(inputBuffer + inputBufferOffset, extractor->getFrameBuf(), info.size);
            frameInfo.push_back(info);
            inputBufferOffset += info.size;
        }

        const char *codecName = env->GetStringUTFChars(jCodecName, nullptr);
        string sCodecName = string(codecName);
        decoder->setupDecoder();
        status = decoder->decode(inputBuffer, frameInfo, sCodecName, asyncMode);
        if (status != AMEDIA_OK) {
            ALOGE("Decode returned error");
            free(inputBuffer);
            env->ReleaseStringUTFChars(jCodecName, codecName);
            return -1;
        }
        decoder->deInitCodec();
        const char *inputReference = env->GetStringUTFChars(jFileName, nullptr);
        const char *statsFile = env->GetStringUTFChars(jStatsFile, nullptr);
        string sInputReference = string(inputReference);
        decoder->dumpStatistics(sInputReference, sCodecName, (asyncMode ? "async" : "sync"),
                                statsFile);
        env->ReleaseStringUTFChars(jCodecName, codecName);
        env->ReleaseStringUTFChars(jStatsFile, statsFile);
        env->ReleaseStringUTFChars(jFileName, inputReference);
        if (inputBuffer) {
            free(inputBuffer);
            inputBuffer = nullptr;
        }
        decoder->resetDecoder();
    }
    if (inputFp) {
        fclose(inputFp);
        inputFp = nullptr;
    }
    extractor->deInitExtractor();
    delete decoder;
    return 0;
}
