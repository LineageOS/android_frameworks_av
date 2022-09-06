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
#include "gsmamr_enc.h"

// Constants for AMR-NB
const int32_t kNumInputSamples = L_FRAME;  // 160 samples
const int32_t kOutputBufferSize = 2 * kNumInputSamples * sizeof(Word16);
const Mode kModes[9] = {MR475, /* 4.75 kbps */
                        MR515, /* 5.15 kbps */
                        MR59,  /* 5.90 kbps */
                        MR67,  /* 6.70 kbps */
                        MR74,  /* 7.40 kbps */
                        MR795, /* 7.95 kbps */
                        MR102, /* 10.2 kbps */
                        MR122, /* 12.2 kbps */
                        MRDTX, /* DTX       */};
const Word16 kOutputFormat[3] = {AMR_TX_WMF, AMR_TX_IF2, AMR_TX_ETS};

class Codec {
   public:
    Codec() = default;
    ~Codec() { deInitEncoder(); }
    Word16 initEncoder(const uint8_t *data);
    void deInitEncoder();
    void encodeFrames(const uint8_t *data, size_t size);

   private:
    void *mEncState = nullptr;
    void *mSidState = nullptr;
};

Word16 Codec::initEncoder(const uint8_t *data) {
    return AMREncodeInit(&mEncState, &mSidState, (*data >> 1) & 0x01 /* dtx_enable flag */);
}

void Codec::deInitEncoder() {
    if (mEncState) {
        AMREncodeExit(&mEncState, &mSidState);
        mEncState = nullptr;
        mSidState = nullptr;
    }
}

void Codec::encodeFrames(const uint8_t *data, size_t size) {
    AMREncodeReset(mEncState, mSidState);
    uint8_t startByte = *data;
    int modeIndex = ((startByte >> 3) % 9);
    int outputFormatIndex = (startByte % 3);
    Mode mode = kModes[modeIndex];
    Word16 outputFormat = kOutputFormat[outputFormatIndex];

    // Consume startByte
    data++;
    size--;

    while (size > 0) {
        Frame_Type_3GPP frameType = (Frame_Type_3GPP)mode;

        Word16 inputBuf[kNumInputSamples] = {};
        int32_t minSize = std::min(size, sizeof(inputBuf));

        uint8_t outputBuf[kOutputBufferSize] = {};
        memcpy(inputBuf, data, minSize);

        AMREncode(mEncState, mSidState, mode, inputBuf, outputBuf, &frameType, outputFormat);

        data += minSize;
        size -= minSize;
    }
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 1) {
        return 0;
    }
    Codec *codec = new Codec();
    if (!codec) {
        return 0;
    }
    if (codec->initEncoder(data) == 0) {
        codec->encodeFrames(data, size);
    }
    delete codec;
    return 0;
}
