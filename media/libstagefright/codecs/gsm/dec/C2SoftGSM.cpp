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
#define LOG_TAG "C2SoftGSM"
#include <utils/Log.h>

#include "C2SoftGSM.h"

#include <C2PlatformSupport.h>
#include <SimpleC2Interface.h>

#include <media/stagefright/foundation/ADebug.h>
#include <media/stagefright/foundation/MediaDefs.h>

namespace android {

constexpr char kComponentName[] = "c2.google.gsm.decoder";

static std::shared_ptr<C2ComponentInterface> BuildIntf(
        const char *name, c2_node_id_t id,
        std::function<void(C2ComponentInterface*)> deleter =
            std::default_delete<C2ComponentInterface>()) {
    return SimpleC2Interface::Builder(name, id, deleter)
            .inputFormat(C2FormatCompressed)
            .outputFormat(C2FormatAudio)
            .inputMediaType(MEDIA_MIMETYPE_AUDIO_MSGSM)
            .outputMediaType(MEDIA_MIMETYPE_AUDIO_RAW)
            .build();
}

C2SoftGSM::C2SoftGSM(const char *name, c2_node_id_t id)
    : SimpleC2Component(BuildIntf(name, id)),
      mGsm(nullptr) {
}

C2SoftGSM::~C2SoftGSM() {
    onRelease();
}

c2_status_t C2SoftGSM::onInit() {
    if (!mGsm) mGsm = gsm_create();
    if (!mGsm) return C2_NO_MEMORY;
    int msopt = 1;
    (void)gsm_option(mGsm, GSM_OPT_WAV49, &msopt);
    mSignalledError = false;
    mSignalledEos = false;
    return C2_OK;
}

c2_status_t C2SoftGSM::onStop() {
    if (mGsm) {
        gsm_destroy(mGsm);
        mGsm = nullptr;
    }
    if (!mGsm) mGsm = gsm_create();
    if (!mGsm) return C2_NO_MEMORY;
    int msopt = 1;
    (void)gsm_option(mGsm, GSM_OPT_WAV49, &msopt);
    mSignalledError = false;
    mSignalledEos = false;
    return C2_OK;
}

void C2SoftGSM::onReset() {
    (void)onStop();
}

void C2SoftGSM::onRelease() {
    if (mGsm) {
        gsm_destroy(mGsm);
        mGsm = nullptr;
    }
}

c2_status_t C2SoftGSM::onFlush_sm() {
    return onStop();
}

static size_t decodeGSM(gsm handle, int16_t *out, size_t outCapacity,
                        uint8_t *in, size_t inSize) {
    size_t outSize = 0;

    if (inSize % MSGSM_IN_FRM_SZ == 0
            && (inSize / MSGSM_IN_FRM_SZ * MSGSM_OUT_FRM_SZ * sizeof(*out)
                    <= outCapacity)) {
        while (inSize > 0) {
            gsm_decode(handle, in, out);
            in += FRGSM_IN_FRM_SZ;
            inSize -= FRGSM_IN_FRM_SZ;
            out += FRGSM_OUT_FRM_SZ;
            outSize += FRGSM_OUT_FRM_SZ;

            gsm_decode(handle, in, out);
            in += FRGSM_IN_FRM_SZ_MINUS_1;
            inSize -= FRGSM_IN_FRM_SZ_MINUS_1;
            out += FRGSM_OUT_FRM_SZ;
            outSize += FRGSM_OUT_FRM_SZ;
        }
    }

    return outSize * sizeof(int16_t);
}

void C2SoftGSM::process(
        const std::unique_ptr<C2Work> &work,
        const std::shared_ptr<C2BlockPool> &pool) {
    work->result = C2_OK;
    work->workletsProcessed = 0u;
    if (mSignalledError || mSignalledEos) {
        work->result = C2_BAD_VALUE;
        return;
    }

    const C2ConstLinearBlock inBuffer = work->input.buffers[0]->data().linearBlocks().front();
    bool eos = ((work->input.flags & C2FrameData::FLAG_END_OF_STREAM) != 0);
    C2ReadView rView = work->input.buffers[0]->data().linearBlocks().front().map().get();
    size_t inOffset = inBuffer.offset();
    size_t inSize = inBuffer.size();
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
            mSignalledEos = true;
            ALOGV("signalled EOS");
        }
        return;
    }
    ALOGV("in buffer attr. size %zu timestamp %d frameindex %d", inSize,
          (int)work->input.ordinal.timestamp.peeku(), (int)work->input.ordinal.frameIndex.peeku());

    size_t outCapacity = (inSize / MSGSM_IN_FRM_SZ ) * MSGSM_OUT_FRM_SZ * sizeof(int16_t);
    std::shared_ptr<C2LinearBlock> block;
    C2MemoryUsage usage = { C2MemoryUsage::CPU_READ, C2MemoryUsage::CPU_WRITE };
    c2_status_t err = pool->fetchLinearBlock(outCapacity, usage, &block);
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
    uint8_t *input = const_cast<uint8_t *>(rView.data() + inOffset);
    size_t outSize = decodeGSM(mGsm, output, outCapacity, input, inSize);
    if (!outSize) {
        ALOGE("encountered improper insize or outsize");
        mSignalledError = true;
        work->result = C2_CORRUPTED;
        return;
    }
    ALOGV("out buffer attr. size %zu", outSize);
    work->worklets.front()->output.flags = work->input.flags;
    work->worklets.front()->output.buffers.clear();
    work->worklets.front()->output.buffers.push_back(createLinearBuffer(block, 0, outSize));
    work->worklets.front()->output.ordinal = work->input.ordinal;
    work->workletsProcessed = 1u;
    if (eos) {
        mSignalledEos = true;
        ALOGV("signalled EOS");
    }
}

c2_status_t C2SoftGSM::drain(
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

class C2SoftGSMDecFactory : public C2ComponentFactory {
public:
    virtual c2_status_t createComponent(
            c2_node_id_t id,
            std::shared_ptr<C2Component>* const component,
            std::function<void(C2Component*)> deleter) override {
        *component = std::shared_ptr<C2Component>(new C2SoftGSM(kComponentName, id), deleter);
        return C2_OK;
    }

    virtual c2_status_t createInterface(
            c2_node_id_t id,
            std::shared_ptr<C2ComponentInterface>* const interface,
            std::function<void(C2ComponentInterface*)> deleter) override {
        *interface = BuildIntf(kComponentName, id, deleter);
        return C2_OK;
    }

    virtual ~C2SoftGSMDecFactory() override = default;
};

}  // namespace android

extern "C" ::C2ComponentFactory* CreateCodec2Factory() {
    ALOGV("in %s", __func__);
    return new ::android::C2SoftGSMDecFactory();
}

extern "C" void DestroyCodec2Factory(::C2ComponentFactory* factory) {
    ALOGV("in %s", __func__);
    delete factory;
}
