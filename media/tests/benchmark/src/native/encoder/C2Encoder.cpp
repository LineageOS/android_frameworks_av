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
#define LOG_TAG "C2Encoder"

#include "C2Encoder.h"

int32_t C2Encoder::createCodec2Component(string compName, AMediaFormat *format) {
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
        mIsAudioEncoder = true;
        int32_t numChannels;
        if (!AMediaFormat_getInt32(format, AMEDIAFORMAT_KEY_SAMPLE_RATE, &mSampleRate)) {
            ALOGE("AMEDIAFORMAT_KEY_SAMPLE_RATE not set");
            return -1;
        }
        if (!AMediaFormat_getInt32(format, AMEDIAFORMAT_KEY_CHANNEL_COUNT, &numChannels)) {
            ALOGE("AMEDIAFORMAT_KEY_CHANNEL_COUNT not set");
            return -1;
        }
        C2StreamSampleRateInfo::input sampleRateInfo(0u, mSampleRate);
        C2StreamChannelCountInfo::input channelCountInfo(0u, numChannels);
        configParam.push_back(&sampleRateInfo);
        configParam.push_back(&channelCountInfo);
    } else {
        mIsAudioEncoder = false;
        if (!AMediaFormat_getInt32(format, AMEDIAFORMAT_KEY_WIDTH, &mWidth)) {
            ALOGE("AMEDIAFORMAT_KEY_WIDTH not set");
            return -1;
        }
        if (!AMediaFormat_getInt32(format, AMEDIAFORMAT_KEY_HEIGHT, &mHeight)) {
            ALOGE("AMEDIAFORMAT_KEY_HEIGHT not set");
            return -1;
        }
        C2StreamPictureSizeInfo::input inputSize(0u, mWidth, mHeight);
        configParam.push_back(&inputSize);

        if (!AMediaFormat_getInt32(format, AMEDIAFORMAT_KEY_FRAME_RATE, &mFrameRate) ||
            (mFrameRate <= 0)) {
            mFrameRate = KDefaultFrameRate;
        }
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

// In encoder components, fetch the size of input buffer allocated
int32_t C2Encoder::getInputMaxBufSize() {
    int32_t bitStreamInfo[1] = {0};
    std::vector<std::unique_ptr<C2Param>> inParams;
    c2_status_t status = mComponent->query({}, {C2StreamMaxBufferSizeInfo::input::PARAM_TYPE},
                                           C2_DONT_BLOCK, &inParams);
    if (status != C2_OK && inParams.size() == 0) {
        ALOGE("Query MaxBufferSizeInfo failed => %d", status);
        return status;
    } else {
        size_t offset = sizeof(C2Param);
        for (size_t i = 0; i < inParams.size(); ++i) {
            C2Param *param = inParams[i].get();
            bitStreamInfo[i] = *(int32_t *)((uint8_t *)param + offset);
        }
    }
    mInputMaxBufSize = bitStreamInfo[0];
    if (mInputMaxBufSize < 0) {
        ALOGE("Invalid mInputMaxBufSize %d\n", mInputMaxBufSize);
        return -1;
    }
    return status;
}

int32_t C2Encoder::encodeFrames(ifstream &eleStream, size_t inputBufferSize) {
    ALOGV("In %s", __func__);
    int32_t frameSize = 0;
    if (!mIsAudioEncoder) {
        frameSize = mWidth * mHeight * 3 / 2;
    } else {
        frameSize = DEFAULT_AUDIO_FRAME_SIZE;
        if (getInputMaxBufSize() != 0) return -1;
        if (frameSize > mInputMaxBufSize) {
            frameSize = mInputMaxBufSize;
        }
    }
    int32_t numFrames = (inputBufferSize + frameSize - 1) / frameSize;
    // Temporary buffer to read data from the input file
    char *data = (char *)malloc(frameSize);
    if (!data) {
        ALOGE("Insufficient memory to read from input file");
        return -1;
    }

    typedef std::unique_lock<std::mutex> ULock;
    uint64_t presentationTimeUs = 0;
    size_t offset = 0;
    c2_status_t status = C2_OK;

    mStats->setStartTime();
    while (numFrames > 0) {
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
                cout << "Wait for generating C2Work exceeded timeout" << endl;
                return -1;
            }
        }

        if (mIsAudioEncoder) {
            presentationTimeUs = mNumInputFrame * frameSize * (1000000 / mSampleRate);
        } else {
            presentationTimeUs = mNumInputFrame * (1000000 / mFrameRate);
        }
        uint32_t flags = 0;
        if (numFrames == 1) flags |= C2FrameData::FLAG_END_OF_STREAM;

        work->input.flags = (C2FrameData::flags_t)flags;
        work->input.ordinal.timestamp = presentationTimeUs;
        work->input.ordinal.frameIndex = mNumInputFrame;
        work->input.buffers.clear();

        if (inputBufferSize - offset < frameSize) {
            frameSize = inputBufferSize - offset;
        }
        eleStream.read(data, frameSize);
        if (eleStream.gcount() != frameSize) {
            ALOGE("read() from file failed. Incorrect bytes read");
            return -1;
        }
        offset += frameSize;

        if (frameSize) {
            if (mIsAudioEncoder) {
                std::shared_ptr<C2LinearBlock> block;
                status = mLinearPool->fetchLinearBlock(
                        frameSize, {C2MemoryUsage::CPU_READ, C2MemoryUsage::CPU_WRITE}, &block);
                if (status != C2_OK || !block) {
                    cout << "fetchLinearBlock failed : " << status << endl;
                    return status;
                }
                C2WriteView view = block->map().get();
                if (view.error() != C2_OK) {
                    cout << "C2LinearBlock::map() failed : " << view.error() << endl;
                    return view.error();
                }

                memcpy(view.base(), data, frameSize);
                work->input.buffers.emplace_back(new LinearBuffer(block));
            } else {
                std::shared_ptr<C2GraphicBlock> block;
                status = mGraphicPool->fetchGraphicBlock(
                        mWidth, mHeight, HAL_PIXEL_FORMAT_YV12,
                        {C2MemoryUsage::CPU_READ, C2MemoryUsage::CPU_WRITE}, &block);
                if (status != C2_OK || !block) {
                    cout << "fetchGraphicBlock failed : " << status << endl;
                    return status;
                }
                C2GraphicView view = block->map().get();
                if (view.error() != C2_OK) {
                    cout << "C2GraphicBlock::map() failed : " << view.error() << endl;
                    return view.error();
                }

                uint8_t *pY = view.data()[C2PlanarLayout::PLANE_Y];
                uint8_t *pU = view.data()[C2PlanarLayout::PLANE_U];
                uint8_t *pV = view.data()[C2PlanarLayout::PLANE_V];
                memcpy(pY, data, mWidth * mHeight);
                memcpy(pU, data + mWidth * mHeight, (mWidth * mHeight >> 2));
                memcpy(pV, data + (mWidth * mHeight * 5 >> 2), mWidth * mHeight >> 2);
                work->input.buffers.emplace_back(new GraphicBuffer(block));
            }
            mStats->addFrameSize(frameSize);
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
        ALOGV("Frame #%d size = %d queued", mNumInputFrame, frameSize);
        numFrames--;
        mNumInputFrame++;
    }
    free(data);
    return status;
}

void C2Encoder::deInitCodec() {
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

void C2Encoder::dumpStatistics(string inputReference, int64_t durationUs) {
    string operation = "c2encode";
    mStats->dumpStatistics(operation, inputReference, durationUs);
}

void C2Encoder::resetEncoder() {
    mIsAudioEncoder = false;
    mNumInputFrame = 0;
    mEos = false;
    if (mStats) mStats->reset();
}
