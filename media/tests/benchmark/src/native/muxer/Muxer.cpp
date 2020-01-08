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
#define LOG_TAG "muxer"

#include <fstream>
#include <iostream>

#include "Muxer.h"

int32_t Muxer::initMuxer(int32_t fd, MUXER_OUTPUT_T outputFormat) {
    if (!mFormat) mFormat = mExtractor->getFormat();
    if (!mStats) mStats = new Stats();

    int64_t sTime = mStats->getCurTime();
    mMuxer = AMediaMuxer_new(fd, (OutputFormat)outputFormat);
    if (!mMuxer) {
        ALOGV("Unable to create muxer");
        return AMEDIA_ERROR_INVALID_OBJECT;
    }
    /*
     * AMediaMuxer_addTrack returns the index of the new track or a negative value
     * in case of failure, which can be interpreted as a media_status_t.
     */
    ssize_t index = AMediaMuxer_addTrack(mMuxer, mFormat);
    if (index < 0) {
        ALOGV("Format not supported");
        return index;
    }
    AMediaMuxer_start(mMuxer);
    int64_t eTime = mStats->getCurTime();
    int64_t timeTaken = mStats->getTimeDiff(sTime, eTime);
    mStats->setInitTime(timeTaken);
    return AMEDIA_OK;
}

void Muxer::deInitMuxer() {
    if (mFormat) {
        AMediaFormat_delete(mFormat);
        mFormat = nullptr;
    }
    if (!mMuxer) return;
    int64_t sTime = mStats->getCurTime();
    AMediaMuxer_stop(mMuxer);
    AMediaMuxer_delete(mMuxer);
    int64_t eTime = mStats->getCurTime();
    int64_t timeTaken = mStats->getTimeDiff(sTime, eTime);
    mStats->setDeInitTime(timeTaken);
}

void Muxer::resetMuxer() {
    if (mStats) mStats->reset();
}

void Muxer::dumpStatistics(string inputReference, string componentName, string statsFile) {
    string operation = "mux";
    mStats->dumpStatistics(operation, inputReference, mExtractor->getClipDuration(), componentName,
                           "", statsFile);
}

int32_t Muxer::mux(uint8_t *inputBuffer, vector<AMediaCodecBufferInfo> &frameInfos) {
    // Mux frame data
    size_t frameIdx = 0;
    mStats->setStartTime();
    while (frameIdx < frameInfos.size()) {
        AMediaCodecBufferInfo info = frameInfos.at(frameIdx);
        media_status_t status = AMediaMuxer_writeSampleData(mMuxer, 0, inputBuffer, &info);
        if (status != 0) {
            ALOGE("Error in AMediaMuxer_writeSampleData");
            return status;
        }
        mStats->addOutputTime();
        mStats->addFrameSize(info.size);
        frameIdx++;
    }
    return AMEDIA_OK;
}
