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
constexpr int32_t ENCODE_DEFAULT_AUDIO_BIT_RATE = 128000 /* 128 Kbps */;
constexpr int32_t ENCODE_DEFAULT_BIT_RATE = 8000000 /* 8 Mbps */;
constexpr int32_t ENCODE_MIN_BIT_RATE = 600000 /* 600 Kbps */;

extern "C" JNIEXPORT int JNICALL Java_com_android_media_benchmark_library_Native_Encode(
        JNIEnv *env, jobject thiz, jstring jFilePath, jstring jFileName, jstring jOutFilePath,
        jstring jStatsFile, jstring jCodecName) {
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
        uint8_t *inputBuffer = (uint8_t *)malloc(fileSize);
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
        string decName = "";
        const char *outputFilePath = env->GetStringUTFChars(jOutFilePath, nullptr);
        FILE *outFp = fopen(outputFilePath, "wb");
        if (outFp == nullptr) {
            ALOGE("%s - File failed to open for writing!", outputFilePath);
            free(inputBuffer);
            return -1;
        }
        decoder->setupDecoder();
        status = decoder->decode(inputBuffer, frameInfo, decName, false /*asyncMode */, outFp);
        if (status != AMEDIA_OK) {
            ALOGE("Decode returned error");
            free(inputBuffer);
            return -1;
        }

        AMediaFormat *decoderFormat = decoder->getFormat();
        AMediaFormat *format = extractor->getFormat();
        if (inputBuffer) {
            free(inputBuffer);
            inputBuffer = nullptr;
        }
        const char *mime = nullptr;
        AMediaFormat_getString(format, AMEDIAFORMAT_KEY_MIME, &mime);
        if (!mime) {
            ALOGE("Error in AMediaFormat_getString");
            return -1;
        }
        ifstream eleStream;
        eleStream.open(outputFilePath, ifstream::binary | ifstream::ate);
        if (!eleStream.is_open()) {
            ALOGE("%s - File failed to open for reading!", outputFilePath);
            env->ReleaseStringUTFChars(jOutFilePath, outputFilePath);
            return -1;
        }
        const char *codecName = env->GetStringUTFChars(jCodecName, NULL);
        const char *inputReference = env->GetStringUTFChars(jFileName, nullptr);
        string sCodecName = string(codecName);
        string sInputReference = string(inputReference);

        bool asyncMode[2] = {true, false};
        for (int i = 0; i < 2; i++) {
            size_t eleSize = eleStream.tellg();
            eleStream.seekg(0, ifstream::beg);

            // Get encoder params
            encParameter encParams;
            if (!strncmp(mime, "video/", 6)) {
                AMediaFormat_getInt32(format, AMEDIAFORMAT_KEY_WIDTH, &encParams.width);
                AMediaFormat_getInt32(format, AMEDIAFORMAT_KEY_HEIGHT, &encParams.height);
                AMediaFormat_getInt32(format, AMEDIAFORMAT_KEY_FRAME_RATE, &encParams.frameRate);
                AMediaFormat_getInt32(format, AMEDIAFORMAT_KEY_BIT_RATE, &encParams.bitrate);
                if (encParams.bitrate <= 0 || encParams.frameRate <= 0) {
                    encParams.frameRate = ENCODE_DEFAULT_FRAME_RATE;
                    if (!strcmp(mime, "video/3gpp") || !strcmp(mime, "video/mp4v-es")) {
                        encParams.bitrate = ENCODE_MIN_BIT_RATE /* 600 Kbps */;
                    } else {
                        encParams.bitrate = ENCODE_DEFAULT_BIT_RATE /* 8 Mbps */;
                    }
                }
                AMediaFormat_getInt32(format, AMEDIAFORMAT_KEY_PROFILE, &encParams.profile);
                AMediaFormat_getInt32(format, AMEDIAFORMAT_KEY_LEVEL, &encParams.level);
                AMediaFormat_getInt32(decoderFormat, AMEDIAFORMAT_KEY_COLOR_FORMAT,
                                      &encParams.colorFormat);
            } else {
                AMediaFormat_getInt32(format, AMEDIAFORMAT_KEY_SAMPLE_RATE, &encParams.sampleRate);
                AMediaFormat_getInt32(format, AMEDIAFORMAT_KEY_CHANNEL_COUNT,
                                      &encParams.numChannels);
                encParams.bitrate = ENCODE_DEFAULT_AUDIO_BIT_RATE;
            }
            Encoder *encoder = new Encoder();
            encoder->setupEncoder();
            status = encoder->encode(sCodecName, eleStream, eleSize, asyncMode[i], encParams,
                                     (char *)mime);
            if (status != AMEDIA_OK) {
                ALOGE("Encoder returned error");
                return -1;
            }
            ALOGV("Encoding complete with codec %s for asyncMode = %d", sCodecName.c_str(),
                  asyncMode[i]);
            encoder->deInitCodec();
            const char *statsFile = env->GetStringUTFChars(jStatsFile, nullptr);
            encoder->dumpStatistics(sInputReference, extractor->getClipDuration(), sCodecName,
                                    (asyncMode[i] ? "async" : "sync"), statsFile);
            env->ReleaseStringUTFChars(jStatsFile, statsFile);
            encoder->resetEncoder();
            delete encoder;
            encoder = nullptr;
        }
        eleStream.close();
        if (outFp) {
            fclose(outFp);
            outFp = nullptr;
        }
        env->ReleaseStringUTFChars(jFileName, inputReference);
        env->ReleaseStringUTFChars(jCodecName, codecName);
        env->ReleaseStringUTFChars(jOutFilePath, outputFilePath);
        if (format) {
            AMediaFormat_delete(format);
            format = nullptr;
        }
        if (decoderFormat) {
            AMediaFormat_delete(decoderFormat);
            decoderFormat = nullptr;
        }
        decoder->deInitCodec();
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
