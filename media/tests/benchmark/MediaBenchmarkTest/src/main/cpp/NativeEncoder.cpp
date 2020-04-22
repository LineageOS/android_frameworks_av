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
#define LOG_TAG "NativeEncoder"

#include <jni.h>
#include <sys/stat.h>
#include <fstream>
#include <iostream>

#include <android/log.h>

#include "Decoder.h"
#include "Encoder.h"

#include <stdio.h>

constexpr int32_t ENCODE_DEFAULT_FRAME_RATE = 25;

extern "C" JNIEXPORT int JNICALL Java_com_android_media_benchmark_library_Native_Encode(
        JNIEnv *env, jobject thiz, jstring jFilePath, jstring jFileName, jstring jStatsFile,
        jstring jCodecName, jstring jMime, jint jBitRate, jint jColorFormat, jint jFrameInterval,
        jint jWidth, jint jHeight, jint jProfile, jint jLevel, jint jSampleRate,
        jint jNumChannels) {
    UNUSED(thiz);
    const char *filePath = env->GetStringUTFChars(jFilePath, nullptr);
    const char *fileName = env->GetStringUTFChars(jFileName, nullptr);
    string inputFile = string(filePath) + string(fileName);
    const char *codecName = env->GetStringUTFChars(jCodecName, nullptr);
    string sCodecName = string(codecName);
    const char *mime = env->GetStringUTFChars(jMime, nullptr);

    ifstream eleStream;
    eleStream.open(inputFile, ifstream::binary | ifstream::ate);
    if (!eleStream.is_open()) {
        ALOGE("%s - File failed to open for reading!", fileName);
        env->ReleaseStringUTFChars(jFileName, fileName);
        return -1;
    }

    bool asyncMode[2] = {true, false};
    for (bool mode : asyncMode) {
        size_t eleSize = eleStream.tellg();
        eleStream.seekg(0, ifstream::beg);

        // Set encoder params
        encParameter encParams;
        encParams.width = jWidth;
        encParams.height = jHeight;
        encParams.bitrate = jBitRate;
        encParams.iFrameInterval = jFrameInterval;
        encParams.sampleRate = jSampleRate;
        encParams.numChannels = jNumChannels;
        encParams.frameRate = ENCODE_DEFAULT_FRAME_RATE;
        encParams.colorFormat = jColorFormat;
        encParams.profile = jProfile;
        encParams.level = jLevel;

        Encoder *encoder = new Encoder();
        encoder->setupEncoder();
        auto status = encoder->encode(sCodecName, eleStream, eleSize, mode, encParams,
                                      const_cast<char *>(mime));
        if (status != AMEDIA_OK) {
            ALOGE("Encoder returned error");
            return -1;
        }
        ALOGV("Encoding complete with codec %s for asyncMode = %d", sCodecName.c_str(), mode);
        encoder->deInitCodec();
        const char *statsFile = env->GetStringUTFChars(jStatsFile, nullptr);
        string inputReference;
        int64_t clipDurationUs;
        if (!strncmp(mime, "video/", 6)) {
            inputReference = string(fileName) + "_" + to_string(jWidth) + "x" + to_string(jHeight) +
                             "_" + to_string(jBitRate) + "bps";
            int32_t frameSize = jWidth * jHeight * 3 / 2;
            clipDurationUs =
                    (((eleSize + frameSize - 1) / frameSize) / ENCODE_DEFAULT_FRAME_RATE) * 1000000;
        } else {
            inputReference = string(fileName) + "_" + to_string(jSampleRate) + "hz_" +
                             to_string(jNumChannels) + "ch_" + to_string(jBitRate) + "bps";
            clipDurationUs = (eleSize / (jSampleRate * jNumChannels)) * 1000000;
        }
        encoder->dumpStatistics(inputReference, clipDurationUs, sCodecName,
                                (mode ? "async" : "sync"), statsFile);
        env->ReleaseStringUTFChars(jStatsFile, statsFile);
        encoder->resetEncoder();
        delete encoder;
        encoder = nullptr;
    }
    eleStream.close();
    env->ReleaseStringUTFChars(jFilePath, filePath);
    env->ReleaseStringUTFChars(jFileName, fileName);
    env->ReleaseStringUTFChars(jMime, mime);
    env->ReleaseStringUTFChars(jCodecName, codecName);
    return 0;
}
