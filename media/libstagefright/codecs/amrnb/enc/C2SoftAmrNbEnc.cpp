/*
 * Copyright (C) 2018 The Android Open Source Project
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

#define LOG_NDEBUG 0
#define LOG_TAG "C2SoftAmrNbEnc"
#include <utils/Log.h>

#include "gsmamr_enc.h"

#include "C2SoftAmrNbEnc.h"

#include <C2PlatformSupport.h>
#include <SimpleC2Interface.h>

#include <media/stagefright/foundation/ADebug.h>
#include <media/stagefright/foundation/MediaDefs.h>

namespace android {

constexpr char kComponentName[] = "c2.google.amrnb.encoder";

static std::shared_ptr<C2ComponentInterface> BuildIntf(
        const char *name, c2_node_id_t id,
        std::function<void(C2ComponentInterface*)> deleter =
            std::default_delete<C2ComponentInterface>()) {
    return SimpleC2Interface::Builder(name, id, deleter)
            .inputFormat(C2FormatAudio)
            .outputFormat(C2FormatCompressed)
            .inputMediaType(MEDIA_MIMETYPE_AUDIO_RAW)
            .outputMediaType(MEDIA_MIMETYPE_AUDIO_AMR_NB)
            .build();
}

C2SoftAmrNbEnc::C2SoftAmrNbEnc(const char *name, c2_node_id_t id)
    : SimpleC2Component(BuildIntf(name, id)),
      mEncState(nullptr),
      mSidState(nullptr) {
}

C2SoftAmrNbEnc::~C2SoftAmrNbEnc() {
    onRelease();
}

c2_status_t C2SoftAmrNbEnc::onInit() {
    bool dtx_enable = false;

    if (AMREncodeInit(&mEncState, &mSidState, dtx_enable) != 0)
        return C2_CORRUPTED;
    mMode = MR795;
    mIsFirst = true;
    mSignalledError = false;
    mSignalledOutputEos = false;
    mAnchorTimeStamp = 0;
    mProcessedSamples = 0;
    mFilledLen = 0;

    return C2_OK;
}

void C2SoftAmrNbEnc::onRelease() {
    if (mEncState) {
        AMREncodeExit(&mEncState, &mSidState);
        mEncState = mSidState = nullptr;
    }
}

c2_status_t C2SoftAmrNbEnc::onStop() {
    if (AMREncodeReset(mEncState, mSidState) != 0)
        return C2_CORRUPTED;
    mIsFirst = true;
    mSignalledError = false;
    mSignalledOutputEos = false;
    mAnchorTimeStamp = 0;
    mProcessedSamples = 0;
    mFilledLen = 0;

    return C2_OK;
}

void C2SoftAmrNbEnc::onReset() {
    (void) onStop();
}

c2_status_t C2SoftAmrNbEnc::onFlush_sm() {
    return onStop();
}

static void fillEmptyWork(const std::unique_ptr<C2Work> &work) {
    work->worklets.front()->output.flags = work->input.flags;
    work->worklets.front()->output.buffers.clear();
    work->worklets.front()->output.ordinal = work->input.ordinal;
    work->workletsProcessed = 1u;
}

void C2SoftAmrNbEnc::process(
        const std::unique_ptr<C2Work> &work,
        const std::shared_ptr<C2BlockPool> &pool) {
    work->result = C2_OK;
    work->workletsProcessed = 0u;
    if (mSignalledError || mSignalledOutputEos) {
        work->result = C2_BAD_VALUE;
        return;
    }

    const C2ConstLinearBlock inBuffer = work->input.buffers[0]->data().linearBlocks().front();
    bool eos = ((work->input.flags & C2FrameData::FLAG_END_OF_STREAM) != 0);
    size_t inOffset = inBuffer.offset();
    size_t inSize = inBuffer.size();
    C2ReadView rView = work->input.buffers[0]->data().linearBlocks().front().map().get();
    if (inSize && rView.error()) {
        ALOGE("read view map failed %d", rView.error());
        work->result = C2_CORRUPTED;
        return;
    }

    ALOGV("in buffer attr. size %zu timestamp %d frameindex %d, flags %x",
          inSize, (int)work->input.ordinal.timestamp.peeku(),
          (int)work->input.ordinal.frameIndex.peeku(), work->input.flags);

    size_t outCapacity = kNumBytesPerInputFrame;
    outCapacity += mFilledLen + inSize;
    std::shared_ptr<C2LinearBlock> outputBlock;
    C2MemoryUsage usage = { C2MemoryUsage::CPU_READ, C2MemoryUsage::CPU_WRITE };
    c2_status_t err = pool->fetchLinearBlock(outCapacity, usage, &outputBlock);
    if (err != C2_OK) {
        ALOGE("fetchLinearBlock for Output failed with status %d", err);
        work->result = C2_NO_MEMORY;
        return;
    }
    C2WriteView wView = outputBlock->map().get();
    if (wView.error()) {
        ALOGE("write view map failed %d", wView.error());
        work->result = C2_CORRUPTED;
        return;
    }

    uint64_t outTimeStamp = mProcessedSamples * 1000000ll / kSampleRate;
    const uint8_t *inPtr = rView.data() + inOffset;
    size_t inPos = 0;
    size_t outPos = 0;
    while (inPos < inSize) {
        int validSamples = mFilledLen / sizeof(int16_t);
        if ((inPos + (kNumBytesPerInputFrame - mFilledLen)) <= inSize) {
            memcpy(mInputFrame + validSamples, inPtr + inPos,
                   (kNumBytesPerInputFrame - mFilledLen));
            inPos += (kNumBytesPerInputFrame - mFilledLen);
        } else {
            memcpy(mInputFrame + validSamples, inPtr + inPos, (inSize - inPos));
            mFilledLen += (inSize - inPos);
            inPos += (inSize - inPos);
            if (eos) {
                validSamples = mFilledLen / sizeof(int16_t);
                memset(mInputFrame + validSamples, 0, (kNumBytesPerInputFrame - mFilledLen));
            } else break;
        }
        Frame_Type_3GPP frameType;
        int numEncBytes = AMREncode(mEncState, mSidState, mMode, mInputFrame,
                                    wView.data() + outPos, &frameType,
                                    AMR_TX_WMF);
        if (numEncBytes < 0 || numEncBytes > ((int)outCapacity - (int)outPos)) {
            ALOGE("encodeFrame call failed, state [%d %zu %zu]", numEncBytes, outPos, outCapacity);
            mSignalledError = true;
            work->result = C2_CORRUPTED;
            return;
        }
        // Convert header byte from WMF to IETF format.
        if (numEncBytes > 0)
            wView.data()[outPos] = ((wView.data()[outPos] << 3) | 4) & 0x7c;
        outPos += numEncBytes;
        mProcessedSamples += kNumSamplesPerFrame;
        mFilledLen = 0;
    }
    ALOGV("causal sample size %d", mFilledLen);
    if (mIsFirst) {
        mIsFirst = false;
        mAnchorTimeStamp = work->input.ordinal.timestamp.peekull();
    }
    fillEmptyWork(work);
    if (outPos != 0) {
        work->worklets.front()->output.buffers.push_back(
                createLinearBuffer(std::move(outputBlock), 0, outPos));
        work->worklets.front()->output.ordinal.timestamp = mAnchorTimeStamp + outTimeStamp;
    }
    if (eos) {
        mSignalledOutputEos = true;
        ALOGV("signalled EOS");
        if (mFilledLen) ALOGV("Discarding trailing %d bytes", mFilledLen);
    }
}

c2_status_t C2SoftAmrNbEnc::drain(
        uint32_t drainMode,
        const std::shared_ptr<C2BlockPool> &pool) {
    (void) pool;
    if (drainMode == NO_DRAIN) {
        ALOGW("drain with NO_DRAIN: no-op");
        return C2_OK;
    }
    if (drainMode == DRAIN_CHAIN) {
        ALOGW("DRAIN_CHAIN not supported");
        return C2_OMITTED;
    }

    onFlush_sm();
    return C2_OK;
}

class C2SoftAmrNbEncFactory : public C2ComponentFactory {
public:
    virtual c2_status_t createComponent(
            c2_node_id_t id,
            std::shared_ptr<C2Component>* const component,
            std::function<void(C2Component*)> deleter) override {
        *component = std::shared_ptr<C2Component>(new C2SoftAmrNbEnc(kComponentName, id), deleter);
        return C2_OK;
    }

    virtual c2_status_t createInterface(
            c2_node_id_t id,
            std::shared_ptr<C2ComponentInterface>* const interface,
            std::function<void(C2ComponentInterface*)> deleter) override {
        *interface = BuildIntf(kComponentName, id, deleter);
        return C2_OK;
    }

    virtual ~C2SoftAmrNbEncFactory() override = default;
};

}  // namespace android

extern "C" ::C2ComponentFactory* CreateCodec2Factory() {
    ALOGV("in %s", __func__);
    return new ::android::C2SoftAmrNbEncFactory();
}

extern "C" void DestroyCodec2Factory(::C2ComponentFactory* factory) {
    ALOGV("in %s", __func__);
    delete factory;
}
