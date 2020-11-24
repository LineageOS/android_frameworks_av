/*
 * Copyright (C) 2020 The Android Open Source Project
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
#include <algorithm>
#include "mp4enc_api.h"

constexpr int8_t kIDRFrameRefreshIntervalInSec = 1;
constexpr MP4RateControlType krcType[] = {CONSTANT_Q, CBR_1, VBR_1, CBR_2, VBR_2, CBR_LOWDELAY};
#ifdef MPEG4
constexpr MP4EncodingMode kEncodingMode[] = {SHORT_HEADER, SHORT_HEADER_WITH_ERR_RES,
                                             DATA_PARTITIONING_MODE, COMBINE_MODE_NO_ERR_RES,
                                             COMBINE_MODE_WITH_ERR_RES};
constexpr size_t kMaxWidth = 10240;
constexpr size_t kMaxHeight = 10240;
#else
constexpr MP4EncodingMode kEncodingMode[] = {H263_MODE, H263_MODE_WITH_ERR_RES};
constexpr int kWidth[] = {128, 176, 352, 704, 1408};
constexpr int kHeight[] = {96, 144, 288, 576, 1152};
constexpr size_t kWidthNum = std::size(kWidth);
constexpr size_t kHeightNum = std::size(kHeight);
#endif

constexpr size_t krcTypeNum = std::size(krcType);
constexpr size_t kEncodingModeNum = std::size(kEncodingMode);
constexpr size_t kMaxQP = 51;

enum {
    IDX_WD_BYTE_1,
    IDX_WD_BYTE_2,
    IDX_HT_BYTE_1,
    IDX_HT_BYTE_2,
    IDX_FRAME_RATE,
    IDX_RC_TYPE,
    IDX_PACKET_SIZE,
    IDX_I_FRAME_QP,
    IDX_P_FRAME_QP,
    IDX_ENABLE_RVLC,
    IDX_QUANT_TYPE,
    IDX_NO_FRAME_SKIPPED_FLAG,
    IDX_ENABLE_SCENE_DETECT,
    IDX_NUM_INTRA_MB,
    IDX_SEARCH_RANGE,
    IDX_ENABLE_MV_8x8,
    IDX_USE_AC_PRED,
    IDX_INTRA_DC_VLC_THRESHOLD,
    IDX_ENC_MODE,
    IDX_LAST
};

class Codec {
   public:
    Codec() = default;
    ~Codec() { deInitEncoder(); }
    bool initEncoder(const uint8_t *data);
    void encodeFrames(const uint8_t *data, size_t size);
    void deInitEncoder();

   private:
    int32_t mFrameWidth = 352;
    int32_t mFrameHeight = 288;
    float mFrameRate = 25.0f;
    VideoEncOptions *mEncodeHandle = nullptr;
    VideoEncControls *mEncodeControl = nullptr;
};

bool Codec::initEncoder(const uint8_t *data) {
    mEncodeHandle = new VideoEncOptions;
    if (!mEncodeHandle) {
        return false;
    }
    memset(mEncodeHandle, 0, sizeof(VideoEncOptions));
    mEncodeControl = new VideoEncControls;
    if (!mEncodeControl) {
        return false;
    }
    memset(mEncodeControl, 0, sizeof(VideoEncControls));
    PVGetDefaultEncOption(mEncodeHandle, 0);

#ifdef MPEG4
    mFrameWidth = ((data[IDX_WD_BYTE_1] << 8) | data[IDX_WD_BYTE_2]) % kMaxWidth;
    mFrameHeight = ((data[IDX_HT_BYTE_1] << 8) | data[IDX_HT_BYTE_2]) % kMaxHeight;
#else
    mFrameWidth = kWidth[data[IDX_WD_BYTE_1] % kWidthNum];
    mFrameHeight = kHeight[data[IDX_HT_BYTE_1] % kHeightNum];
#endif
    mFrameRate = data[IDX_FRAME_RATE];
    mEncodeHandle->rcType = krcType[data[IDX_RC_TYPE] % krcTypeNum];
    mEncodeHandle->profile_level = CORE_PROFILE_LEVEL2;
    mEncodeHandle->packetSize = data[IDX_PACKET_SIZE];
    mEncodeHandle->iQuant[0] = (data[IDX_I_FRAME_QP] % kMaxQP) + 1;
    mEncodeHandle->pQuant[0] = (data[IDX_P_FRAME_QP] % kMaxQP) + 1;
    mEncodeHandle->rvlcEnable = (data[IDX_ENABLE_RVLC] & 0x01) ? PV_OFF : PV_ON;
    mEncodeHandle->quantType[0] = (data[IDX_QUANT_TYPE] & 0x01) ? 0 : 1;
    mEncodeHandle->noFrameSkipped = (data[IDX_NO_FRAME_SKIPPED_FLAG] & 0x01) ? PV_OFF : PV_ON;
    mEncodeHandle->sceneDetect = (data[IDX_ENABLE_SCENE_DETECT] & 0x01) ? PV_OFF : PV_ON;
    mEncodeHandle->numIntraMB = data[IDX_NUM_INTRA_MB] & 0x07;
    mEncodeHandle->searchRange = data[IDX_SEARCH_RANGE] & 0x1F;
    mEncodeHandle->mv8x8Enable = (data[IDX_ENABLE_MV_8x8] & 0x01) ? PV_OFF : PV_ON;
    mEncodeHandle->useACPred = (data[IDX_USE_AC_PRED] & 0x01) ? PV_OFF : PV_ON;
    mEncodeHandle->intraDCVlcTh = data[IDX_INTRA_DC_VLC_THRESHOLD] & 0x07;
    mEncodeHandle->encMode = kEncodingMode[data[IDX_ENC_MODE] % kEncodingModeNum];
    mEncodeHandle->encWidth[0] = mFrameWidth;
    mEncodeHandle->encHeight[0] = mFrameHeight;
    mEncodeHandle->encFrameRate[0] = mFrameRate;
    mEncodeHandle->tickPerSrc = mEncodeHandle->timeIncRes / mFrameRate;
    mEncodeHandle->intraPeriod = (kIDRFrameRefreshIntervalInSec * mFrameRate);
    if (!PVInitVideoEncoder(mEncodeControl, mEncodeHandle)) {
        return false;
    }
    return true;
}

void Codec::deInitEncoder() {
    if (mEncodeControl) {
        PVCleanUpVideoEncoder(mEncodeControl);
        delete mEncodeControl;
        mEncodeControl = nullptr;
    }
    if (mEncodeHandle) {
        delete mEncodeHandle;
        mEncodeHandle = nullptr;
    }
}

void Codec::encodeFrames(const uint8_t *data, size_t size) {
    size_t inputBufferSize = (mFrameWidth * mFrameHeight * 3) / 2;
    size_t outputBufferSize = inputBufferSize * 2;
    uint8_t *outputBuffer = new uint8_t[outputBufferSize];
    uint8_t *inputBuffer = new uint8_t[inputBufferSize];

    // Get VOL header.
    int32_t sizeOutputBuffer = outputBufferSize;
    PVGetVolHeader(mEncodeControl, outputBuffer, &sizeOutputBuffer, 0);

    size_t numFrame = 0;
    while (size > 0) {
        size_t bytesConsumed = std::min(size, inputBufferSize);
        memcpy(inputBuffer, data, bytesConsumed);
        if (bytesConsumed < inputBufferSize) {
            memset(inputBuffer + bytesConsumed, data[0], inputBufferSize - bytesConsumed);
        }
        VideoEncFrameIO videoIn{}, videoOut{};
        videoIn.height = mFrameHeight;
        videoIn.pitch = mFrameWidth;
        videoIn.timestamp = (numFrame * 1000) / mFrameRate;
        videoIn.yChan = inputBuffer;
        videoIn.uChan = videoIn.yChan + videoIn.height * videoIn.pitch;
        videoIn.vChan = videoIn.uChan + ((videoIn.height * videoIn.pitch) >> 2);
        uint32_t modTimeMs = 0;
        int32_t dataLength = outputBufferSize;
        int32_t nLayer = 0;
        PVEncodeVideoFrame(mEncodeControl, &videoIn, &videoOut, &modTimeMs, outputBuffer,
                           &dataLength, &nLayer);
        MP4HintTrack hintTrack;
        PVGetHintTrack(mEncodeControl, &hintTrack);
        PVGetOverrunBuffer(mEncodeControl);
        ++numFrame;
        data += bytesConsumed;
        size -= bytesConsumed;
    }
    delete[] inputBuffer;
    delete[] outputBuffer;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < IDX_LAST) {
        return 0;
    }
    Codec *codec = new Codec();
    if (!codec) {
        return 0;
    }
    if (codec->initEncoder(data)) {
        data += IDX_LAST;
        size -= IDX_LAST;
        codec->encodeFrames(data, size);
    }
    delete codec;
    return 0;
}
