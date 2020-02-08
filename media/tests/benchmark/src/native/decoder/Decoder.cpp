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
#define LOG_TAG "decoder"

#include <iostream>

#include "Decoder.h"

tuple<ssize_t, uint32_t, int64_t> readSampleData(uint8_t *inputBuffer, int32_t &offset,
                                                 vector<AMediaCodecBufferInfo> &frameInfo,
                                                 uint8_t *buf, int32_t frameID, size_t bufSize) {
    ALOGV("In %s", __func__);
    if (frameID == (int32_t)frameInfo.size()) {
        return make_tuple(0, AMEDIACODEC_BUFFER_FLAG_END_OF_STREAM, 0);
    }
    uint32_t flags = frameInfo[frameID].flags;
    int64_t timestamp = frameInfo[frameID].presentationTimeUs;
    ssize_t bytesCount = frameInfo[frameID].size;
    if (bufSize < bytesCount) {
        ALOGE("Error : Buffer size is insufficient to read sample");
        return make_tuple(0, AMEDIA_ERROR_MALFORMED, 0);
    }

    memcpy(buf, inputBuffer + offset, bytesCount);
    offset += bytesCount;
    return make_tuple(bytesCount, flags, timestamp);
}

void Decoder::onInputAvailable(AMediaCodec *mediaCodec, int32_t bufIdx) {
    ALOGV("In %s", __func__);
    if (mediaCodec == mCodec && mediaCodec) {
        if (mSawInputEOS || bufIdx < 0) return;
        if (mSignalledError) {
            CallBackHandle::mSawError = true;
            mDecoderDoneCondition.notify_one();
            return;
        }

        size_t bufSize;
        uint8_t *buf = AMediaCodec_getInputBuffer(mCodec, bufIdx, &bufSize);
        if (!buf) {
            mErrorCode = AMEDIA_ERROR_IO;
            mSignalledError = true;
            mDecoderDoneCondition.notify_one();
            return;
        }

        ssize_t bytesRead = 0;
        uint32_t flag = 0;
        int64_t presentationTimeUs = 0;
        tie(bytesRead, flag, presentationTimeUs) =
                readSampleData(mInputBuffer, mOffset, mFrameMetaData, buf, mNumInputFrame, bufSize);
        if (flag == AMEDIA_ERROR_MALFORMED) {
            mErrorCode = (media_status_t)flag;
            mSignalledError = true;
            mDecoderDoneCondition.notify_one();
            return;
        }

        if (flag == AMEDIACODEC_BUFFER_FLAG_END_OF_STREAM) mSawInputEOS = true;
        ALOGV("%s bytesRead : %zd presentationTimeUs : %" PRId64 " mSawInputEOS : %s", __FUNCTION__,
              bytesRead, presentationTimeUs, mSawInputEOS ? "TRUE" : "FALSE");

        media_status_t status = AMediaCodec_queueInputBuffer(mCodec, bufIdx, 0 /* offset */,
                                                             bytesRead, presentationTimeUs, flag);
        if (AMEDIA_OK != status) {
            mErrorCode = status;
            mSignalledError = true;
            mDecoderDoneCondition.notify_one();
            return;
        }
        mStats->addFrameSize(bytesRead);
        mNumInputFrame++;
    }
}

void Decoder::onOutputAvailable(AMediaCodec *mediaCodec, int32_t bufIdx,
                                AMediaCodecBufferInfo *bufferInfo) {
    ALOGV("In %s", __func__);
    if (mediaCodec == mCodec && mediaCodec) {
        if (mSawOutputEOS || bufIdx < 0) return;
        if (mSignalledError) {
            CallBackHandle::mSawError = true;
            mDecoderDoneCondition.notify_one();
            return;
        }

        if (mOutFp != nullptr) {
            size_t bufSize;
            uint8_t *buf = AMediaCodec_getOutputBuffer(mCodec, bufIdx, &bufSize);
            if (buf) {
                fwrite(buf, sizeof(char), bufferInfo->size, mOutFp);
                ALOGV("bytes written into file  %d\n", bufferInfo->size);
            }
        }

        AMediaCodec_releaseOutputBuffer(mCodec, bufIdx, false);
        mSawOutputEOS = (0 != (bufferInfo->flags & AMEDIACODEC_BUFFER_FLAG_END_OF_STREAM));
        mNumOutputFrame++;
        ALOGV("%s index : %d  mSawOutputEOS : %s count : %u", __FUNCTION__, bufIdx,
              mSawOutputEOS ? "TRUE" : "FALSE", mNumOutputFrame);

        if (mSawOutputEOS) {
            CallBackHandle::mIsDone = true;
            mDecoderDoneCondition.notify_one();
        }
    }
}

void Decoder::onFormatChanged(AMediaCodec *mediaCodec, AMediaFormat *format) {
    ALOGV("In %s", __func__);
    if (mediaCodec == mCodec && mediaCodec) {
        ALOGV("%s { %s }", __FUNCTION__, AMediaFormat_toString(format));
        mFormat = format;
    }
}

void Decoder::onError(AMediaCodec *mediaCodec, media_status_t err) {
    ALOGV("In %s", __func__);
    if (mediaCodec == mCodec && mediaCodec) {
        ALOGE("Received Error %d", err);
        mErrorCode = err;
        mSignalledError = true;
        mDecoderDoneCondition.notify_one();
    }
}

void Decoder::setupDecoder() {
    if (!mFormat) mFormat = mExtractor->getFormat();
}

AMediaFormat *Decoder::getFormat() {
    ALOGV("In %s", __func__);
    return AMediaCodec_getOutputFormat(mCodec);
}

int32_t Decoder::decode(uint8_t *inputBuffer, vector<AMediaCodecBufferInfo> &frameInfo,
                        string &codecName, bool asyncMode, FILE *outFp) {
    ALOGV("In %s", __func__);
    mInputBuffer = inputBuffer;
    mFrameMetaData = frameInfo;
    mOffset = 0;
    mOutFp = outFp;

    const char *mime = nullptr;
    AMediaFormat_getString(mFormat, AMEDIAFORMAT_KEY_MIME, &mime);
    if (!mime) return AMEDIA_ERROR_INVALID_OBJECT;

    int64_t sTime = mStats->getCurTime();
    mCodec = createMediaCodec(mFormat, mime, codecName, false /*isEncoder*/);
    if (!mCodec) return AMEDIA_ERROR_INVALID_OBJECT;

    if (asyncMode) {
        AMediaCodecOnAsyncNotifyCallback aCB = {OnInputAvailableCB, OnOutputAvailableCB,
                                                OnFormatChangedCB, OnErrorCB};
        AMediaCodec_setAsyncNotifyCallback(mCodec, aCB, this);

        mIOThread = thread(&CallBackHandle::ioThread, this);
    }

    AMediaCodec_start(mCodec);
    int64_t eTime = mStats->getCurTime();
    int64_t timeTaken = mStats->getTimeDiff(sTime, eTime);
    mStats->setInitTime(timeTaken);

    mStats->setStartTime();
    if (!asyncMode) {
        while (!mSawOutputEOS && !mSignalledError) {
            /* Queue input data */
            if (!mSawInputEOS) {
                ssize_t inIdx = AMediaCodec_dequeueInputBuffer(mCodec, kQueueDequeueTimeoutUs);
                if (inIdx < 0 && inIdx != AMEDIACODEC_INFO_TRY_AGAIN_LATER) {
                    ALOGE("AMediaCodec_dequeueInputBuffer returned invalid index %zd\n", inIdx);
                    mErrorCode = (media_status_t)inIdx;
                    return mErrorCode;
                } else if (inIdx >= 0) {
                    mStats->addInputTime();
                    onInputAvailable(mCodec, inIdx);
                }
            }

            /* Dequeue output data */
            AMediaCodecBufferInfo info;
            ssize_t outIdx = AMediaCodec_dequeueOutputBuffer(mCodec, &info, kQueueDequeueTimeoutUs);
            if (outIdx == AMEDIACODEC_INFO_OUTPUT_FORMAT_CHANGED) {
                mFormat = AMediaCodec_getOutputFormat(mCodec);
                const char *s = AMediaFormat_toString(mFormat);
                ALOGI("Output format: %s\n", s);
            } else if (outIdx >= 0) {
                mStats->addOutputTime();
                onOutputAvailable(mCodec, outIdx, &info);
            } else if (!(outIdx == AMEDIACODEC_INFO_TRY_AGAIN_LATER ||
                         outIdx == AMEDIACODEC_INFO_OUTPUT_BUFFERS_CHANGED)) {
                ALOGE("AMediaCodec_dequeueOutputBuffer returned invalid index %zd\n", outIdx);
                mErrorCode = (media_status_t)outIdx;
                return mErrorCode;
            }
        }
    } else {
        unique_lock<mutex> lock(mMutex);
        mDecoderDoneCondition.wait(lock, [this]() { return (mSawOutputEOS || mSignalledError); });
    }
    if (mSignalledError) {
        ALOGE("Received Error while Decoding");
        return mErrorCode;
    }

    if (codecName.empty()) {
        char *decName;
        AMediaCodec_getName(mCodec, &decName);
        codecName.assign(decName);
        AMediaCodec_releaseName(mCodec, decName);
    }
    return AMEDIA_OK;
}

void Decoder::deInitCodec() {
    if (mFormat) {
        AMediaFormat_delete(mFormat);
        mFormat = nullptr;
    }
    if (!mCodec) return;
    int64_t sTime = mStats->getCurTime();
    AMediaCodec_stop(mCodec);
    AMediaCodec_delete(mCodec);
    int64_t eTime = mStats->getCurTime();
    int64_t timeTaken = mStats->getTimeDiff(sTime, eTime);
    mStats->setDeInitTime(timeTaken);
}

void Decoder::dumpStatistics(string inputReference, string componentName, string mode,
                             string statsFile) {
    int64_t durationUs = mExtractor->getClipDuration();
    string operation = "decode";
    mStats->dumpStatistics(operation, inputReference, durationUs, componentName, mode, statsFile);
}

void Decoder::resetDecoder() {
    if (mStats) mStats->reset();
    if (mInputBuffer) mInputBuffer = nullptr;
    if (!mFrameMetaData.empty()) mFrameMetaData.clear();
}
