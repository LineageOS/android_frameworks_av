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
#define LOG_TAG "encoder"

#include <fstream>

#include "Encoder.h"

void Encoder::onInputAvailable(AMediaCodec *mediaCodec, int32_t bufIdx) {
    ALOGV("In %s", __func__);
    if (mediaCodec == mCodec && mediaCodec) {
        if (mSawInputEOS || bufIdx < 0) return;
        if (mSignalledError) {
            CallBackHandle::mSawError = true;
            mEncoderDoneCondition.notify_one();
            return;
        }

        size_t bufSize = 0;
        char *buf = (char *)AMediaCodec_getInputBuffer(mCodec, bufIdx, &bufSize);
        if (!buf) {
            mErrorCode = AMEDIA_ERROR_IO;
            mSignalledError = true;
            mEncoderDoneCondition.notify_one();
            return;
        }

        if (mInputBufferSize < mOffset) {
            ALOGE("Out of bound access of input buffer\n");
            mErrorCode = AMEDIA_ERROR_MALFORMED;
            mSignalledError = true;
            mEncoderDoneCondition.notify_one();
            return;
        }
        size_t bytesToRead = mParams.frameSize;
        if (mInputBufferSize - mOffset < mParams.frameSize) {
            bytesToRead = mInputBufferSize - mOffset;
        }
        //b/148655275 - Update Frame size, as Format value may not be valid
        if (bufSize < bytesToRead) {
            if(mNumInputFrame == 0) {
                mParams.frameSize = bufSize;
                bytesToRead = bufSize;
                mParams.numFrames = (mInputBufferSize + mParams.frameSize - 1) / mParams.frameSize;
            } else {
                ALOGE("bytes to read %zu bufSize %zu \n", bytesToRead, bufSize);
                mErrorCode = AMEDIA_ERROR_MALFORMED;
                mSignalledError = true;
                mEncoderDoneCondition.notify_one();
                return;
            }
        }
        if (bytesToRead < mParams.frameSize && mNumInputFrame < mParams.numFrames - 1) {
            ALOGE("Partial frame at frameID %d bytesToRead %zu frameSize %d total numFrames %d\n",
                  mNumInputFrame, bytesToRead, mParams.frameSize, mParams.numFrames);
            mErrorCode = AMEDIA_ERROR_MALFORMED;
            mSignalledError = true;
            mEncoderDoneCondition.notify_one();
            return;
        }
        mEleStream->read(buf, bytesToRead);
        size_t bytesgcount = mEleStream->gcount();
        if (bytesgcount != bytesToRead) {
            ALOGE("bytes to read %zu actual bytes read %zu \n", bytesToRead, bytesgcount);
            mErrorCode = AMEDIA_ERROR_MALFORMED;
            mSignalledError = true;
            mEncoderDoneCondition.notify_one();
            return;
        }

        uint32_t flag = 0;
        if (mNumInputFrame == mParams.numFrames - 1 || bytesToRead == 0) {
            ALOGD("Sending EOS on input Last frame\n");
            flag |= AMEDIACODEC_BUFFER_FLAG_END_OF_STREAM;
        }

        uint64_t presentationTimeUs;
        if (!strncmp(mMime, "video/", 6)) {
            presentationTimeUs = mNumInputFrame * (1000000 / mParams.frameRate);
        } else {
            presentationTimeUs =
                    (uint64_t)mNumInputFrame * mParams.frameSize * 1000000 / mParams.sampleRate;
        }

        if (flag == AMEDIACODEC_BUFFER_FLAG_END_OF_STREAM) mSawInputEOS = true;
        ALOGV("%s bytesRead : %zd presentationTimeUs : %" PRIu64 " mSawInputEOS : %s", __FUNCTION__,
              bytesToRead, presentationTimeUs, mSawInputEOS ? "TRUE" : "FALSE");

        media_status_t status = AMediaCodec_queueInputBuffer(mCodec, bufIdx, 0 /* offset */,
                                                             bytesToRead, presentationTimeUs, flag);
        if (AMEDIA_OK != status) {
            mErrorCode = status;
            mSignalledError = true;
            mEncoderDoneCondition.notify_one();
            return;
        }
        mNumInputFrame++;
        mOffset += bytesToRead;
    }
}

void Encoder::onOutputAvailable(AMediaCodec *mediaCodec, int32_t bufIdx,
                                AMediaCodecBufferInfo *bufferInfo) {
    ALOGV("In %s", __func__);
    if (mediaCodec == mCodec && mediaCodec) {
        if (mSawOutputEOS || bufIdx < 0) return;
        if (mSignalledError) {
            CallBackHandle::mSawError = true;
            mEncoderDoneCondition.notify_one();
            return;
        }

        mStats->addFrameSize(bufferInfo->size);
        AMediaCodec_releaseOutputBuffer(mCodec, bufIdx, false);
        mSawOutputEOS = (0 != (bufferInfo->flags & AMEDIACODEC_BUFFER_FLAG_END_OF_STREAM));
        mNumOutputFrame++;
        ALOGV("%s index : %d  mSawOutputEOS : %s count : %u", __FUNCTION__, bufIdx,
              mSawOutputEOS ? "TRUE" : "FALSE", mNumOutputFrame);
        if (mSawOutputEOS) {
            CallBackHandle::mIsDone = true;
            mEncoderDoneCondition.notify_one();
        }
    }
}

void Encoder::onFormatChanged(AMediaCodec *mediaCodec, AMediaFormat *format) {
    ALOGV("In %s", __func__);
    if (mediaCodec == mCodec && mediaCodec) {
        ALOGV("%s { %s }", __FUNCTION__, AMediaFormat_toString(format));
        mFormat = format;
    }
}

void Encoder::onError(AMediaCodec *mediaCodec, media_status_t err) {
    ALOGV("In %s", __func__);
    if (mediaCodec == mCodec && mediaCodec) {
        ALOGE("Received Error %d", err);
        mErrorCode = err;
        mSignalledError = true;
        mEncoderDoneCondition.notify_one();
    }
}

void Encoder::setupEncoder() {
    if (!mFormat) mFormat = AMediaFormat_new();
}

void Encoder::deInitCodec() {
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

void Encoder::resetEncoder() {
    if (mStats) mStats->reset();
    if (mEleStream) mEleStream = nullptr;
    if (mMime) mMime = nullptr;
    mInputBufferSize = 0;
    memset(&mParams, 0, sizeof mParams);
}

void Encoder::dumpStatistics(string inputReference, int64_t durationUs, string componentName,
                             string mode, string statsFile) {
    string operation = "encode";
    mStats->dumpStatistics(operation, inputReference, durationUs, componentName, mode, statsFile);
}

int32_t Encoder::encode(string &codecName, ifstream &eleStream, size_t eleSize, bool asyncMode,
                        encParameter encParams, char *mime) {
    ALOGV("In %s", __func__);
    mEleStream = &eleStream;
    mInputBufferSize = eleSize;
    mParams = encParams;
    mOffset = 0;
    mMime = mime;
    AMediaFormat_setString(mFormat, AMEDIAFORMAT_KEY_MIME, mMime);

    // Set Format
    if (!strncmp(mMime, "video/", 6)) {
        AMediaFormat_setInt32(mFormat, AMEDIAFORMAT_KEY_WIDTH, mParams.width);
        AMediaFormat_setInt32(mFormat, AMEDIAFORMAT_KEY_HEIGHT, mParams.height);
        AMediaFormat_setInt32(mFormat, AMEDIAFORMAT_KEY_FRAME_RATE, mParams.frameRate);
        AMediaFormat_setInt32(mFormat, AMEDIAFORMAT_KEY_BIT_RATE, mParams.bitrate);
        AMediaFormat_setInt32(mFormat, AMEDIAFORMAT_KEY_I_FRAME_INTERVAL, 1);
        if (mParams.profile && mParams.level) {
            AMediaFormat_setInt32(mFormat, AMEDIAFORMAT_KEY_PROFILE, mParams.profile);
            AMediaFormat_setInt32(mFormat, AMEDIAFORMAT_KEY_LEVEL, mParams.level);
        }
        AMediaFormat_setInt32(mFormat, AMEDIAFORMAT_KEY_COLOR_FORMAT, mParams.colorFormat);
    } else {
        AMediaFormat_setInt32(mFormat, AMEDIAFORMAT_KEY_SAMPLE_RATE, mParams.sampleRate);
        AMediaFormat_setInt32(mFormat, AMEDIAFORMAT_KEY_CHANNEL_COUNT, mParams.numChannels);
        AMediaFormat_setInt32(mFormat, AMEDIAFORMAT_KEY_BIT_RATE, mParams.bitrate);
    }
    const char *s = AMediaFormat_toString(mFormat);
    ALOGI("Input format: %s\n", s);

    int64_t sTime = mStats->getCurTime();
    mCodec = createMediaCodec(mFormat, mMime, codecName, true /*isEncoder*/);
    if (!mCodec) return AMEDIA_ERROR_INVALID_OBJECT;
    int64_t eTime = mStats->getCurTime();
    int64_t timeTaken = mStats->getTimeDiff(sTime, eTime);

    if (!strncmp(mMime, "video/", 6)) {
        mParams.frameSize = mParams.width * mParams.height * 3 / 2;
    } else {
        mParams.frameSize = kDefaultAudioEncodeFrameSize;
        // Get mInputMaxBufSize
        AMediaFormat *inputFormat = AMediaCodec_getInputFormat(mCodec);
        AMediaFormat_getInt32(inputFormat, AMEDIAFORMAT_KEY_MAX_INPUT_SIZE, &mParams.maxFrameSize);
        if (mParams.maxFrameSize < 0) {
            mParams.maxFrameSize = kDefaultAudioEncodeFrameSize;
        }
        if (mParams.frameSize > mParams.maxFrameSize) {
            mParams.frameSize = mParams.maxFrameSize;
        }
    }
    mParams.numFrames = (mInputBufferSize + mParams.frameSize - 1) / mParams.frameSize;

    sTime = mStats->getCurTime();
    if (asyncMode) {
        AMediaCodecOnAsyncNotifyCallback aCB = {OnInputAvailableCB, OnOutputAvailableCB,
                                                OnFormatChangedCB, OnErrorCB};
        AMediaCodec_setAsyncNotifyCallback(mCodec, aCB, this);
        mIOThread = thread(&CallBackHandle::ioThread, this);
    }
    AMediaCodec_start(mCodec);
    eTime = mStats->getCurTime();
    timeTaken += mStats->getTimeDiff(sTime, eTime);
    mStats->setInitTime(timeTaken);

    mStats->setStartTime();
    if (!asyncMode) {
        while (!mSawOutputEOS && !mSignalledError) {
            // Queue input data
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

            // Dequeue output data
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
        mEncoderDoneCondition.wait(lock, [this]() { return (mSawOutputEOS || mSignalledError); });
    }
    if (mSignalledError) {
        ALOGE("Received Error while Encoding");
        return mErrorCode;
    }

    if (codecName.empty()) {
        char *encName;
        AMediaCodec_getName(mCodec, &encName);
        codecName.assign(encName);
        AMediaCodec_releaseName(mCodec, encName);
    }
    return AMEDIA_OK;
}
