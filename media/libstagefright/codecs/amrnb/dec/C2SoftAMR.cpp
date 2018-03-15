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
#define LOG_TAG "C2SoftAMR"
#include <utils/Log.h>

#include "C2SoftAMR.h"

#include <C2PlatformSupport.h>
#include <SimpleC2Interface.h>

#include <media/stagefright/foundation/ADebug.h>
#include <media/stagefright/foundation/MediaDefs.h>

#include "gsmamr_dec.h"
#include "pvamrwbdecoder.h"

namespace android {

#ifdef AMRNB
  constexpr char kComponentName[] = "c2.google.amrnb.decoder";
#else
  constexpr char kComponentName[] = "c2.google.amrwb.decoder";
#endif

static std::shared_ptr<C2ComponentInterface> BuildIntf(
        const char *name, c2_node_id_t id,
        std::function<void(C2ComponentInterface*)> deleter =
            std::default_delete<C2ComponentInterface>()) {
    return SimpleC2Interface::Builder(name, id, deleter)
            .inputFormat(C2FormatCompressed)
            .outputFormat(C2FormatAudio)
            .inputMediaType(
#ifdef AMRNB
                    MEDIA_MIMETYPE_AUDIO_AMR_NB
#else
                    MEDIA_MIMETYPE_AUDIO_AMR_WB
#endif
            )
            .outputMediaType(MEDIA_MIMETYPE_AUDIO_RAW)
            .build();
}

C2SoftAMR::C2SoftAMR(const char *name, c2_node_id_t id)
    : SimpleC2Component(BuildIntf(name, id)),
      mAmrHandle(nullptr),
      mDecoderBuf(nullptr),
      mDecoderCookie(nullptr) {
}

C2SoftAMR::~C2SoftAMR() {
    (void)onRelease();
}

c2_status_t C2SoftAMR::onInit() {
    status_t err = initDecoder();
    return err == OK ? C2_OK : C2_NO_MEMORY;
}

c2_status_t C2SoftAMR::onStop() {
    if (!mIsWide) {
        Speech_Decode_Frame_reset(mAmrHandle);
    } else {
        pvDecoder_AmrWb_Reset(mAmrHandle, 0 /* reset_all */);
    }
    mSignalledError = false;
    mSignalledOutputEos = false;

    return C2_OK;
}

void C2SoftAMR::onReset() {
    (void)onStop();
}

void C2SoftAMR::onRelease() {
    if (!mIsWide) {
        GSMDecodeFrameExit(&mAmrHandle);
        mAmrHandle = nullptr;
    } else {
        free(mDecoderBuf);
        mDecoderBuf = nullptr;

        mAmrHandle = nullptr;
        mDecoderCookie = nullptr;
    }
}

c2_status_t C2SoftAMR::onFlush_sm() {
    return onStop();
}

status_t C2SoftAMR::initDecoder() {
#ifdef AMRNB
    mIsWide = false;
#else
    mIsWide = true;
#endif
    if (!mIsWide) {
        if (GSMInitDecode(&mAmrHandle, (int8_t *)"AMRNBDecoder"))
            return UNKNOWN_ERROR;
    } else {
        uint32_t memReq = pvDecoder_AmrWbMemRequirements();
        mDecoderBuf = malloc(memReq);
        if (mDecoderBuf) {
            pvDecoder_AmrWb_Init(&mAmrHandle, mDecoderBuf, &mDecoderCookie);
        }
        else {
            return NO_MEMORY;
        }
    }
    mSignalledError = false;
    mSignalledOutputEos = false;

    return OK;
}

static size_t getFrameSize(bool isWide, unsigned FM) {
    static const size_t kFrameSizeNB[16] = {
        12, 13, 15, 17, 19, 20, 26, 31,
        5, 6, 5, 5, // SID
        0, 0, 0, // future use
        0 // no data
    };
    static const size_t kFrameSizeWB[16] = {
        17, 23, 32, 36, 40, 46, 50, 58, 60,
        5, // SID
        0, 0, 0, 0, // future use
        0, // speech lost
        0 // no data
    };

    if (FM > 15 || (isWide && FM > 9 && FM < 14) || (!isWide && FM > 11 && FM < 15)) {
        ALOGE("illegal AMR frame mode %d", FM);
        return 0;
    }
    // add 1 for header byte
    return (isWide ? kFrameSizeWB[FM] : kFrameSizeNB[FM]) + 1;
}

static status_t calculateNumFrames(const uint8 *input, size_t inSize,
                                   std::vector<size_t> *frameSizeList, bool isWide) {
    for (size_t k = 0; k < inSize;) {
        int16_t FM = ((input[0] >> 3) & 0x0f);
        size_t frameSize = getFrameSize(isWide, FM);
        if (frameSize == 0) return UNKNOWN_ERROR;
        if ((inSize - k) >= frameSize) {
            input += frameSize;
            k += frameSize;
        }
        else break;
        frameSizeList->push_back(frameSize);
    }
    return OK;
}

void C2SoftAMR::process(
        const std::unique_ptr<C2Work> &work,
        const std::shared_ptr<C2BlockPool> &pool) {
    work->result = C2_OK;
    work->workletsProcessed = 0u;
    if (mSignalledError || mSignalledOutputEos) {
        work->result = C2_BAD_VALUE;
        return;
    }

    const C2ConstLinearBlock inBuffer =
            work->input.buffers[0]->data().linearBlocks().front();
    C2ReadView rView = work->input.buffers[0]->data().linearBlocks().front().map().get();
    size_t inOffset = inBuffer.offset();
    size_t inSize = inBuffer.size();
    bool eos = (work->input.flags & C2FrameData::FLAG_END_OF_STREAM) != 0;

    if (inSize && rView.error()) {
        ALOGE("read view map failed %d", rView.error());
        work->result = rView.error();
        return;
    }
    if (inSize == 0) {
        work->worklets.front()->output.flags = work->input.flags;
        work->worklets.front()->output.buffers.clear();
        work->worklets.front()->output.ordinal = work->input.ordinal;
        work->workletsProcessed = 1u;
        if (eos) {
            mSignalledOutputEos = true;
            ALOGV("signalled EOS");
        }
        return;
    }

    ALOGV("in buffer attr. size %zu timestamp %d frameindex %d", inSize,
          (int)work->input.ordinal.timestamp.peeku(), (int)work->input.ordinal.frameIndex.peeku());

    std::vector<size_t> frameSizeList;
    if (OK != calculateNumFrames(rView.data() + inOffset, inSize, &frameSizeList,
                                 mIsWide)) {
        work->result = C2_CORRUPTED;
        mSignalledError = true;
        return;
    }
    if (frameSizeList.empty()) {
        ALOGE("input size smaller than expected");
        work->result = C2_CORRUPTED;
        mSignalledError = true;
        return;
    }

    int16_t outSamples = mIsWide ? kNumSamplesPerFrameWB : kNumSamplesPerFrameNB;
    size_t calOutSize = outSamples * frameSizeList.size() * sizeof(int16_t);
    std::shared_ptr<C2LinearBlock> block;
    C2MemoryUsage usage = { C2MemoryUsage::CPU_READ, C2MemoryUsage::CPU_WRITE };
    c2_status_t err = pool->fetchLinearBlock(calOutSize, usage, &block);
    if (err != C2_OK) {
        ALOGE("fetchLinearBlock for Output failed with status %d", err);
        work->result = C2_NO_MEMORY;
        return;
    }
    C2WriteView wView = block->map().get();
    if (wView.error()) {
        ALOGE("write view map failed %d", wView.error());
        work->result = wView.error();
        return;
    }

    int16_t *output = reinterpret_cast<int16_t *>(wView.data());
    auto it = frameSizeList.begin();
    const uint8_t *inPtr = rView.data() + inOffset;
    size_t inPos = 0;
    while (inPos < inSize) {
        if (it == frameSizeList.end()) {
            ALOGD("unexpected trailing bytes, ignoring them");
            break;
        }
        uint8_t *input = const_cast<uint8_t *>(inPtr + inPos);
        int16_t FM = ((*input >> 3) & 0x0f);
        if (!mIsWide) {
            int32_t numBytesRead = AMRDecode(mAmrHandle,
                                             (Frame_Type_3GPP) FM,
                                             input + 1, output, MIME_IETF);
            if (static_cast<size_t>(numBytesRead + 1) != *it) {
                ALOGE("panic, parsed size does not match decoded size");
                work->result = C2_CORRUPTED;
                mSignalledError = true;
                return;
            }
        } else {
            if (FM >= 9) {
                // Produce silence instead of comfort noise and for
                // speech lost/no data.
                memset(output, 0, outSamples * sizeof(int16_t));
            } else {
                int16_t FT;
                RX_State_wb rx_state;
                int16_t numRecSamples;

                mime_unsorting(const_cast<uint8_t *>(&input[1]),
                               mInputSampleBuffer, &FT, &FM, 1, &rx_state);
                pvDecoder_AmrWb(FM, mInputSampleBuffer, output, &numRecSamples,
                                mDecoderBuf, FT, mDecoderCookie);
                if (numRecSamples != outSamples) {
                    ALOGE("Sample output per frame incorrect");
                    work->result = C2_CORRUPTED;
                    mSignalledError = true;
                    return;
                }
                /* Delete the 2 LSBs (14-bit output) */
                for (int i = 0; i < numRecSamples; ++i) {
                    output[i] &= 0xfffC;
                }
            }
        }
        inPos += *it;
        output += outSamples;
        ++it;
    }

    work->worklets.front()->output.flags = work->input.flags;
    work->worklets.front()->output.buffers.clear();
    work->worklets.front()->output.buffers.push_back(createLinearBuffer(block));
    work->worklets.front()->output.ordinal = work->input.ordinal;
    work->workletsProcessed = 1u;
    if (eos) {
        mSignalledOutputEos = true;
        ALOGV("signalled EOS");
    }
}

c2_status_t C2SoftAMR::drain(
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
    return C2_OK;
}

class C2SoftAMRDecFactory : public C2ComponentFactory {
public:
    virtual c2_status_t createComponent(
            c2_node_id_t id,
            std::shared_ptr<C2Component>* const component,
            std::function<void(C2Component*)> deleter) override {
        *component = std::shared_ptr<C2Component>(new C2SoftAMR(kComponentName, id), deleter);
        return C2_OK;
    }

    virtual c2_status_t createInterface(
            c2_node_id_t id,
            std::shared_ptr<C2ComponentInterface>* const interface,
            std::function<void(C2ComponentInterface*)> deleter) override {
        *interface = BuildIntf(kComponentName, id, deleter);
        return C2_OK;
    }

    virtual ~C2SoftAMRDecFactory() override = default;
};

}  // namespace android

extern "C" ::C2ComponentFactory* CreateCodec2Factory() {
    ALOGV("in %s", __func__);
    return new ::android::C2SoftAMRDecFactory();
}

extern "C" void DestroyCodec2Factory(::C2ComponentFactory* factory) {
    ALOGV("in %s", __func__);
    delete factory;
}
