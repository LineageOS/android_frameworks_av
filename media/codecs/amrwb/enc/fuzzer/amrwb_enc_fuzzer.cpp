/******************************************************************************
 *
 * Copyright (C) 2020 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 *****************************************************************************
 * Originally developed and contributed by Ittiam Systems Pvt. Ltd, Bangalore
 */
#include <string.h>
#include <utils/Log.h>
#include <algorithm>
#include "cmnMemory.h"
#include "voAMRWB.h"
#include "cnst.h"

typedef int(VO_API *VOGETAUDIOENCAPI)(VO_AUDIO_CODECAPI *pEncHandle);
const int32_t kInputBufferSize = L_FRAME16k * sizeof(int16_t) * 2;
const int32_t kOutputBufferSize = 2 * kInputBufferSize;
const int32_t kModes[] = {VOAMRWB_MD66 /* 6.60kbps */,    VOAMRWB_MD885 /* 8.85kbps */,
                          VOAMRWB_MD1265 /* 12.65kbps */, VOAMRWB_MD1425 /* 14.25kbps */,
                          VOAMRWB_MD1585 /* 15.85kbps */, VOAMRWB_MD1825 /* 18.25kbps */,
                          VOAMRWB_MD1985 /* 19.85kbps */, VOAMRWB_MD2305 /* 23.05kbps */,
                          VOAMRWB_MD2385 /* 23.85kbps */, VOAMRWB_N_MODES /* Invalid Mode */};
const VOAMRWBFRAMETYPE kFrameTypes[] = {VOAMRWB_DEFAULT, VOAMRWB_ITU, VOAMRWB_RFC3267};

class Codec {
   public:
    Codec() = default;
    ~Codec() { deInitEncoder(); }
    bool initEncoder(const uint8_t *data);
    void deInitEncoder();
    void encodeFrames(const uint8_t *data, size_t size);

   private:
    VO_AUDIO_CODECAPI *mApiHandle = nullptr;
    VO_MEM_OPERATOR *mMemOperator = nullptr;
    VO_HANDLE mEncoderHandle = nullptr;
};

bool Codec::initEncoder(const uint8_t *data) {
    uint8_t startByte = *data;
    int32_t mode = kModes[(startByte >> 4) % 10];
    VOAMRWBFRAMETYPE frameType = kFrameTypes[startByte % 3];
    mMemOperator = new VO_MEM_OPERATOR;
    if (!mMemOperator) {
        return false;
    }

    mMemOperator->Alloc = cmnMemAlloc;
    mMemOperator->Copy = cmnMemCopy;
    mMemOperator->Free = cmnMemFree;
    mMemOperator->Set = cmnMemSet;
    mMemOperator->Check = cmnMemCheck;

    VO_CODEC_INIT_USERDATA userData;
    memset(&userData, 0, sizeof(userData));
    userData.memflag = VO_IMF_USERMEMOPERATOR;
    userData.memData = (VO_PTR)mMemOperator;

    mApiHandle = new VO_AUDIO_CODECAPI;
    if (!mApiHandle) {
        return false;
    }
    if (VO_ERR_NONE != voGetAMRWBEncAPI(mApiHandle)) {
        // Failed to get api handle
        return false;
    }
    if (VO_ERR_NONE != mApiHandle->Init(&mEncoderHandle, VO_AUDIO_CodingAMRWB, &userData)) {
        // Failed to init AMRWB encoder
        return false;
    }
    if (VO_ERR_NONE != mApiHandle->SetParam(mEncoderHandle, VO_PID_AMRWB_FRAMETYPE, &frameType)) {
        // Failed to set AMRWB encoder frame type
        return false;
    }
    if (VO_ERR_NONE != mApiHandle->SetParam(mEncoderHandle, VO_PID_AMRWB_MODE, &mode)) {
        // Failed to set AMRWB encoder mode
        return false;
    }
    return true;
}

void Codec::deInitEncoder() {
    if (mEncoderHandle) {
        mApiHandle->Uninit(mEncoderHandle);
        mEncoderHandle = nullptr;
    }
    if (mApiHandle) {
        delete mApiHandle;
        mApiHandle = nullptr;
    }
    if (mMemOperator) {
        delete mMemOperator;
        mMemOperator = nullptr;
    }
}

void Codec::encodeFrames(const uint8_t *data, size_t size) {
    do {
        int32_t minSize = std::min((int32_t)size, kInputBufferSize);
        uint8_t outputBuf[kOutputBufferSize] = {};
        VO_CODECBUFFER inData;
        VO_CODECBUFFER outData;
        VO_AUDIO_OUTPUTINFO outFormat;
        inData.Buffer = (unsigned char *)data;
        inData.Length = minSize;
        outData.Buffer = outputBuf;
        mApiHandle->SetInputData(mEncoderHandle, &inData);
        mApiHandle->GetOutputData(mEncoderHandle, &outData, &outFormat);
        data += minSize;
        size -= minSize;
    } while (size > 0);
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 1) {
        return 0;
    }
    Codec *codec = new Codec();
    if (!codec) {
        return 0;
    }
    if (codec->initEncoder(data)) {
        // Consume first byte
        ++data;
        --size;
        codec->encodeFrames(data, size);
    }
    delete codec;
    return 0;
}
