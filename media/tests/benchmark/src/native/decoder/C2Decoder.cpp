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
#define LOG_TAG "C2Decoder"
#include <log/log.h>

#include "C2Decoder.h"
#include <iostream>

int32_t C2Decoder::createCodec2Component(string compName, AMediaFormat *format) {
    ALOGV("In %s", __func__);
    mListener.reset(new CodecListener(
            [this](std::list<std::unique_ptr<C2Work>> &workItems) { handleWorkDone(workItems); }));
    if (!mListener) return -1;

    const char *mime = nullptr;
    AMediaFormat_getString(format, AMEDIAFORMAT_KEY_MIME, &mime);
    if (!mime) {
        ALOGE("Error in AMediaFormat_getString");
        return -1;
    }
    // Configure the plugin with Input properties
    std::vector<C2Param *> configParam;
    if (!strncmp(mime, "audio/", 6)) {
        int32_t sampleRate, numChannels;
        AMediaFormat_getInt32(format, AMEDIAFORMAT_KEY_SAMPLE_RATE, &sampleRate);
        AMediaFormat_getInt32(format, AMEDIAFORMAT_KEY_CHANNEL_COUNT, &numChannels);
        C2StreamSampleRateInfo::output sampleRateInfo(0u, sampleRate);
        C2StreamChannelCountInfo::output channelCountInfo(0u, numChannels);
        configParam.push_back(&sampleRateInfo);
        configParam.push_back(&channelCountInfo);

    } else {
        int32_t width, height;
        AMediaFormat_getInt32(format, AMEDIAFORMAT_KEY_WIDTH, &width);
        AMediaFormat_getInt32(format, AMEDIAFORMAT_KEY_HEIGHT, &height);
        C2StreamPictureSizeInfo::input inputSize(0u, width, height);
        configParam.push_back(&inputSize);
    }

    int64_t sTime = mStats->getCurTime();
    mComponent = mClient->CreateComponentByName(compName.c_str(), mListener, &mClient);
    if (mComponent == nullptr) {
        ALOGE("Create component failed for %s", compName.c_str());
        return -1;
    }
    std::vector<std::unique_ptr<C2SettingResult>> failures;
    int32_t status = mComponent->config(configParam, C2_DONT_BLOCK, &failures);
    if (failures.size() != 0) {
        ALOGE("Invalid Configuration");
        return -1;
    }

    status |= mComponent->start();
    int64_t eTime = mStats->getCurTime();
    int64_t timeTaken = mStats->getTimeDiff(sTime, eTime);
    mStats->setInitTime(timeTaken);
    return status;
}

int32_t C2Decoder::decodeFrames(uint8_t *inputBuffer, vector<AMediaCodecBufferInfo> &frameInfo) {
    ALOGV("In %s", __func__);
    typedef std::unique_lock<std::mutex> ULock;
    c2_status_t status = C2_OK;
    mStats->setStartTime();
    while (1) {
        if (mNumInputFrame == frameInfo.size()) break;
        std::unique_ptr<C2Work> work;
        // Prepare C2Work
        {
            ULock l(mQueueLock);
            if (mWorkQueue.empty()) mQueueCondition.wait_for(l, MAX_RETRY * TIME_OUT);
            if (!mWorkQueue.empty()) {
                mStats->addInputTime();
                work.swap(mWorkQueue.front());
                mWorkQueue.pop_front();
            } else {
                std::cout << "Wait for generating C2Work exceeded timeout" << std::endl;
                return -1;
            }
        }

        uint32_t flags = frameInfo[mNumInputFrame].flags;
        if (flags == AMEDIACODEC_BUFFER_FLAG_CODEC_CONFIG) {
            flags = C2FrameData::FLAG_CODEC_CONFIG;
        }
        if (mNumInputFrame == (frameInfo.size() - 1)) {
            flags |= C2FrameData::FLAG_END_OF_STREAM;
        }
        work->input.flags = (C2FrameData::flags_t)flags;
        work->input.ordinal.timestamp = frameInfo[mNumInputFrame].presentationTimeUs;
        work->input.ordinal.frameIndex = mNumInputFrame;
        work->input.buffers.clear();
        int size = frameInfo[mNumInputFrame].size;
        int alignedSize = ALIGN(size, PAGE_SIZE);
        if (size) {
            std::shared_ptr<C2LinearBlock> block;
            status = mLinearPool->fetchLinearBlock(
                    alignedSize, {C2MemoryUsage::CPU_READ, C2MemoryUsage::CPU_WRITE}, &block);
            if (status != C2_OK || block == nullptr) {
                std::cout << "C2LinearBlock::map() failed : " << status << std::endl;
                return status;
            }

            C2WriteView view = block->map().get();
            if (view.error() != C2_OK) {
                std::cout << "C2LinearBlock::map() failed : " << view.error() << std::endl;
                return view.error();
            }
            memcpy(view.base(), inputBuffer + mOffset, size);
            work->input.buffers.emplace_back(new LinearBuffer(block, size));
            mStats->addFrameSize(size);
        }
        work->worklets.clear();
        work->worklets.emplace_back(new C2Worklet);

        std::list<std::unique_ptr<C2Work>> items;
        items.push_back(std::move(work));
        // queue() invokes process() function of C2 Plugin.
        status = mComponent->queue(&items);
        if (status != C2_OK) {
            ALOGE("queue failed");
            return status;
        }
        ALOGV("Frame #%d size = %d queued", mNumInputFrame, size);
        mNumInputFrame++;
        mOffset += size;
    }
    return status;
}

void C2Decoder::deInitCodec() {
    ALOGV("In %s", __func__);
    if (!mComponent) return;

    int64_t sTime = mStats->getCurTime();
    mComponent->stop();
    mComponent->release();
    mComponent = nullptr;
    int64_t eTime = mStats->getCurTime();
    int64_t timeTaken = mStats->getTimeDiff(sTime, eTime);
    mStats->setDeInitTime(timeTaken);
}

void C2Decoder::dumpStatistics(string inputReference, int64_t durationUs) {
    string operation = "c2decode";
    mStats->dumpStatistics(operation, inputReference, durationUs);
}

void C2Decoder::resetDecoder() {
    mOffset = 0;
    mNumInputFrame = 0;
    if (mStats) mStats->reset();
}
