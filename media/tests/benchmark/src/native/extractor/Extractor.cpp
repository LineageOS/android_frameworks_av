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
#define LOG_TAG "extractor"

#include <iostream>

#include "Extractor.h"

int32_t Extractor::initExtractor(int32_t fd, size_t fileSize) {
    mStats = new Stats();

    mFrameBuf = (uint8_t *)calloc(kMaxBufferSize, sizeof(uint8_t));
    if (!mFrameBuf) return -1;

    int64_t sTime = mStats->getCurTime();

    mExtractor = AMediaExtractor_new();
    if (!mExtractor) return AMEDIACODEC_ERROR_INSUFFICIENT_RESOURCE;
    media_status_t status = AMediaExtractor_setDataSourceFd(mExtractor, fd, 0, fileSize);
    if (status != AMEDIA_OK) return status;

    int64_t eTime = mStats->getCurTime();
    int64_t timeTaken = mStats->getTimeDiff(sTime, eTime);
    mStats->setInitTime(timeTaken);

    return AMediaExtractor_getTrackCount(mExtractor);
}

void *Extractor::getCSDSample(AMediaCodecBufferInfo &frameInfo, int32_t csdIndex) {
    char csdName[kMaxCSDStrlen];
    void *csdBuffer = nullptr;
    frameInfo.presentationTimeUs = 0;
    frameInfo.flags = AMEDIACODEC_BUFFER_FLAG_CODEC_CONFIG;
    snprintf(csdName, sizeof(csdName), "csd-%d", csdIndex);

    size_t size;
    bool csdFound = AMediaFormat_getBuffer(mFormat, csdName, &csdBuffer, &size);
    if (!csdFound) return nullptr;
    frameInfo.size = (int32_t)size;
    mStats->addFrameSize(frameInfo.size);

    return csdBuffer;
}

int32_t Extractor::getFrameSample(AMediaCodecBufferInfo &frameInfo) {
    int32_t size = AMediaExtractor_readSampleData(mExtractor, mFrameBuf, kMaxBufferSize);
    if (size < 0) return -1;

    frameInfo.flags = AMediaExtractor_getSampleFlags(mExtractor);
    frameInfo.size = size;
    mStats->addFrameSize(frameInfo.size);
    frameInfo.presentationTimeUs = AMediaExtractor_getSampleTime(mExtractor);
    AMediaExtractor_advance(mExtractor);

    return 0;
}

int32_t Extractor::setupTrackFormat(int32_t trackId) {
    AMediaExtractor_selectTrack(mExtractor, trackId);
    mFormat = AMediaExtractor_getTrackFormat(mExtractor, trackId);
    if (!mFormat) return AMEDIA_ERROR_INVALID_OBJECT;

    bool durationFound = AMediaFormat_getInt64(mFormat, AMEDIAFORMAT_KEY_DURATION, &mDurationUs);
    if (!durationFound) return AMEDIA_ERROR_INVALID_OBJECT;

    return AMEDIA_OK;
}

int32_t Extractor::extract(int32_t trackId) {
    int32_t status = setupTrackFormat(trackId);
    if (status != AMEDIA_OK) return status;

    int32_t idx = 0;
    AMediaCodecBufferInfo frameInfo;
    while (1) {
        memset(&frameInfo, 0, sizeof(AMediaCodecBufferInfo));
        void *csdBuffer = getCSDSample(frameInfo, idx);
        if (!csdBuffer || !frameInfo.size) break;
        idx++;
    }

    mStats->setStartTime();
    while (1) {
        int32_t status = getFrameSample(frameInfo);
        if (status || !frameInfo.size) break;
        mStats->addOutputTime();
    }

    if (mFormat) {
        AMediaFormat_delete(mFormat);
        mFormat = nullptr;
    }

    AMediaExtractor_unselectTrack(mExtractor, trackId);

    return AMEDIA_OK;
}

void Extractor::dumpStatistics(string inputReference, string componentName, string statsFile) {
    string operation = "extract";
    mStats->dumpStatistics(operation, inputReference, mDurationUs, componentName, "", statsFile);
}

void Extractor::deInitExtractor() {
    if (mFrameBuf) {
        free(mFrameBuf);
        mFrameBuf = nullptr;
    }

    int64_t sTime = mStats->getCurTime();
    if (mExtractor) {
        // TODO: (b/140128505) Multiple calls result in DoS.
        // Uncomment call to AMediaExtractor_delete() once this is resolved
        // AMediaExtractor_delete(mExtractor);
        mExtractor = nullptr;
    }
    int64_t eTime = mStats->getCurTime();
    int64_t deInitTime = mStats->getTimeDiff(sTime, eTime);
    mStats->setDeInitTime(deInitTime);
}
