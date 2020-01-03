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
#define LOG_TAG "BenchmarkCommon"

#include "BenchmarkCommon.h"
#include <iostream>

void CallBackHandle::ioThread() {
    ALOGV("In %s mIsDone : %d, mSawError : %d ", __func__, mIsDone, mSawError);
    while (!mIsDone && !mSawError) {
        auto task = mIOQueue.pop();
        task();
    }
}

void OnInputAvailableCB(AMediaCodec *codec, void *userdata, int32_t index) {
    ALOGV("OnInputAvailableCB: index(%d)", index);
    CallBackHandle *self = (CallBackHandle *)userdata;
    self->getStats()->addInputTime();
    self->mIOQueue.push([self, codec, index]() { self->onInputAvailable(codec, index); });
}

void OnOutputAvailableCB(AMediaCodec *codec, void *userdata, int32_t index,
                         AMediaCodecBufferInfo *bufferInfo) {
    ALOGV("OnOutputAvailableCB: index(%d), (%d, %d, %lld, 0x%x)", index, bufferInfo->offset,
          bufferInfo->size, (long long)bufferInfo->presentationTimeUs, bufferInfo->flags);
    CallBackHandle *self = (CallBackHandle *)userdata;
    self->getStats()->addOutputTime();
    AMediaCodecBufferInfo bufferInfoCopy = *bufferInfo;
    self->mIOQueue.push([self, codec, index, bufferInfoCopy]() {
        AMediaCodecBufferInfo bc = bufferInfoCopy;
        self->onOutputAvailable(codec, index, &bc);
    });
}

void OnFormatChangedCB(AMediaCodec *codec, void *userdata, AMediaFormat *format) {
    ALOGV("OnFormatChangedCB: format(%s)", AMediaFormat_toString(format));
    CallBackHandle *self = (CallBackHandle *)userdata;
    self->mIOQueue.push([self, codec, format]() { self->onFormatChanged(codec, format); });
}

void OnErrorCB(AMediaCodec *codec, void *userdata, media_status_t err, int32_t actionCode,
               const char *detail) {
    (void)codec;
    ALOGE("OnErrorCB: err(%d), actionCode(%d), detail(%s)", err, actionCode, detail);
    CallBackHandle *self = (CallBackHandle *)userdata;
    self->mSawError = true;
    self->mIOQueue.push([self, codec, err]() { self->onError(codec, err); });
}

AMediaCodec *createMediaCodec(AMediaFormat *format, const char *mime, string codecName,
                              bool isEncoder) {
    ALOGV("In %s", __func__);
    if (!mime) {
        ALOGE("Please specify a mime type to create codec");
        return nullptr;
    }

    AMediaCodec *codec;
    if (!codecName.empty()) {
        codec = AMediaCodec_createCodecByName(codecName.c_str());
        if (!codec) {
            ALOGE("Unable to create codec by name: %s", codecName.c_str());
            return nullptr;
        }
    } else {
        if (isEncoder) {
            codec = AMediaCodec_createEncoderByType(mime);
        } else {
            codec = AMediaCodec_createDecoderByType(mime);
        }
        if (!codec) {
            ALOGE("Unable to create codec by mime: %s", mime);
            return nullptr;
        }
    }

    /* Configure codec with the given format*/
    const char *s = AMediaFormat_toString(format);
    ALOGI("Input format: %s\n", s);

    media_status_t status = AMediaCodec_configure(codec, format, nullptr, nullptr, isEncoder);
    if (status != AMEDIA_OK) {
        ALOGE("AMediaCodec_configure failed %d", status);
        return nullptr;
    }
    return codec;
}
