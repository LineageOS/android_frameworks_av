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
#define LOG_TAG "C2SoftFlacDecoder"
#include <utils/Log.h>

#include "C2SoftFlacDecoder.h"

#include <C2PlatformSupport.h>
#include <SimpleC2Interface.h>

#include <media/stagefright/foundation/ADebug.h>
#include <media/stagefright/foundation/MediaDefs.h>

namespace android {

constexpr char kComponentName[] = "c2.google.flac.decoder";

static std::shared_ptr<C2ComponentInterface> BuildIntf(
        const char *name, c2_node_id_t id,
        std::function<void(C2ComponentInterface*)> deleter =
            std::default_delete<C2ComponentInterface>()) {
    return SimpleC2Interface::Builder(name, id, deleter)
            .inputFormat(C2FormatCompressed)
            .outputFormat(C2FormatAudio)
            .inputMediaType(MEDIA_MIMETYPE_AUDIO_FLAC)
            .outputMediaType(MEDIA_MIMETYPE_AUDIO_RAW)
            .build();
}

C2SoftFlacDecoder::C2SoftFlacDecoder(const char *name, c2_node_id_t id)
    : SimpleC2Component(BuildIntf(name, id)),
      mFLACDecoder(nullptr) {
}

C2SoftFlacDecoder::~C2SoftFlacDecoder() {
    delete mFLACDecoder;
}

c2_status_t C2SoftFlacDecoder::onInit() {
    status_t err = initDecoder();
    return err == OK ? C2_OK : C2_NO_MEMORY;
}

c2_status_t C2SoftFlacDecoder::onStop() {
    if (mFLACDecoder) mFLACDecoder->flush();
    memset(&mStreamInfo, 0, sizeof(mStreamInfo));
    mHasStreamInfo = false;
    mSignalledError = false;
    mSignalledOutputEos = false;
    mInputBufferCount = 0;
    return C2_OK;
}

void C2SoftFlacDecoder::onReset() {
    (void)onStop();
}

void C2SoftFlacDecoder::onRelease() {
}

c2_status_t C2SoftFlacDecoder::onFlush_sm() {
    return onStop();
}

status_t C2SoftFlacDecoder::initDecoder() {
    if (mFLACDecoder) {
        delete mFLACDecoder;
    }
    mFLACDecoder = FLACDecoder::Create();
    if (!mFLACDecoder) {
        ALOGE("initDecoder: failed to create FLACDecoder");
        mSignalledError = true;
        return NO_MEMORY;
    }

    memset(&mStreamInfo, 0, sizeof(mStreamInfo));
    mHasStreamInfo = false;
    mSignalledError = false;
    mSignalledOutputEos = false;
    mInputBufferCount = 0;

    return OK;
}

static void fillEmptyWork(const std::unique_ptr<C2Work> &work) {
    work->worklets.front()->output.flags = work->input.flags;
    work->worklets.front()->output.buffers.clear();
    work->worklets.front()->output.ordinal = work->input.ordinal;
    work->workletsProcessed = 1u;
}

// (TODO) add multiframe support, in plugin and FLACDecoder.cpp
void C2SoftFlacDecoder::process(
        const std::unique_ptr<C2Work> &work,
        const std::shared_ptr<C2BlockPool> &pool) {
    work->result = C2_OK;
    work->workletsProcessed = 0u;
    if (mSignalledError || mSignalledOutputEos) {
        work->result = C2_BAD_VALUE;
        return;
    }

    const C2ConstLinearBlock inBuffer = work->input.buffers[0]->data().linearBlocks().front();
    size_t inOffset = inBuffer.offset();
    size_t inSize = inBuffer.size();
    C2ReadView rView = work->input.buffers[0]->data().linearBlocks().front().map().get();
    if (inSize && rView.error()) {
        ALOGE("read view map failed %d", rView.error());
        work->result = C2_CORRUPTED;
        return;
    }
    bool eos = (work->input.flags & C2FrameData::FLAG_END_OF_STREAM) != 0;
    bool codecConfig = (work->input.flags & C2FrameData::FLAG_CODEC_CONFIG) != 0;

    ALOGV("in buffer attr. size %zu timestamp %d frameindex %d", inSize,
          (int)work->input.ordinal.timestamp.peeku(), (int)work->input.ordinal.frameIndex.peeku());

    if (inSize == 0) {
        fillEmptyWork(work);
        if (eos) {
            mSignalledOutputEos = true;
            ALOGV("signalled EOS");
        }
        return;
    }

    if (mInputBufferCount == 0 && !codecConfig) {
        ALOGV("First frame has to include configuration, forcing config");
        codecConfig = true;
    }

    uint8_t *input = const_cast<uint8_t *>(rView.data() + inOffset);
    if (codecConfig) {
        status_t decoderErr = mFLACDecoder->parseMetadata(input, inSize);
        if (decoderErr != OK && decoderErr != WOULD_BLOCK) {
            ALOGE("process: FLACDecoder parseMetaData returns error %d", decoderErr);
            mSignalledError = true;
            work->result = C2_CORRUPTED;
            return;
        }

        mInputBufferCount++;
        fillEmptyWork(work);
        if (eos) {
            mSignalledOutputEos = true;
            ALOGV("signalled EOS");
        }

        if (decoderErr == WOULD_BLOCK) {
            ALOGV("process: parseMetadata is Blocking, Continue %d", decoderErr);
        } else {
            mStreamInfo = mFLACDecoder->getStreamInfo();
            if (mStreamInfo.max_blocksize && mStreamInfo.channels)
                mHasStreamInfo = true;
            ALOGD("process: decoder configuration : %d Hz, %d channels, %d samples,"
                  " %d block size", mStreamInfo.sample_rate, mStreamInfo.channels,
                  (int)mStreamInfo.total_samples, mStreamInfo.max_blocksize);
        }
        return;
    }

    size_t outSize;
    if (mHasStreamInfo)
        outSize = mStreamInfo.max_blocksize * mStreamInfo.channels * sizeof(short);
    else
        outSize = kMaxBlockSize * FLACDecoder::kMaxChannels * sizeof(short);

    std::shared_ptr<C2LinearBlock> block;
    C2MemoryUsage usage = { C2MemoryUsage::CPU_READ, C2MemoryUsage::CPU_WRITE };
    c2_status_t err = pool->fetchLinearBlock(outSize, usage, &block);
    if (err != C2_OK) {
        ALOGE("fetchLinearBlock for Output failed with status %d", err);
        work->result = C2_NO_MEMORY;
        return;
    }
    C2WriteView wView = block->map().get();
    if (wView.error()) {
        ALOGE("write view map failed %d", wView.error());
        work->result = C2_CORRUPTED;
        return;
    }

    short *output = reinterpret_cast<short *>(wView.data());
    status_t decoderErr = mFLACDecoder->decodeOneFrame(
                            input, inSize, output, &outSize);
    if (decoderErr != OK) {
        ALOGE("process: FLACDecoder decodeOneFrame returns error %d", decoderErr);
        mSignalledError = true;
        work->result = C2_CORRUPTED;
        return;
    }

    mInputBufferCount++;
    ALOGV("out buffer attr. size %zu", outSize);
    work->worklets.front()->output.flags = work->input.flags;
    work->worklets.front()->output.buffers.clear();
    work->worklets.front()->output.buffers.push_back(createLinearBuffer(block, 0, outSize));
    work->worklets.front()->output.ordinal = work->input.ordinal;
    work->workletsProcessed = 1u;
    if (eos) {
        mSignalledOutputEos = true;
        ALOGV("signalled EOS");
    }
}

c2_status_t C2SoftFlacDecoder::drain(
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

    if (mFLACDecoder) mFLACDecoder->flush();

    return C2_OK;
}

class C2SoftFlacDecFactory : public C2ComponentFactory {
public:
    virtual c2_status_t createComponent(
            c2_node_id_t id,
            std::shared_ptr<C2Component>* const component,
            std::function<void(C2Component*)> deleter) override {
        *component = std::shared_ptr<C2Component>(new C2SoftFlacDecoder(kComponentName, id), deleter);
        return C2_OK;
    }

    virtual c2_status_t createInterface(
            c2_node_id_t id,
            std::shared_ptr<C2ComponentInterface>* const interface,
            std::function<void(C2ComponentInterface*)> deleter) override {
        *interface = BuildIntf(kComponentName, id, deleter);
        return C2_OK;
    }

    virtual ~C2SoftFlacDecFactory() override = default;
};

}  // namespace android

extern "C" ::C2ComponentFactory* CreateCodec2Factory() {
    ALOGV("in %s", __func__);
    return new ::android::C2SoftFlacDecFactory();
}

extern "C" void DestroyCodec2Factory(::C2ComponentFactory* factory) {
    ALOGV("in %s", __func__);
    delete factory;
}
