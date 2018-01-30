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
#define LOG_TAG "C2SoftVorbis"
#include <utils/Log.h>

#include <C2PlatformSupport.h>
#include <SimpleC2Interface.h>

#include <media/stagefright/foundation/ADebug.h>
#include <media/stagefright/foundation/MediaDefs.h>

#include "C2SoftVorbis.h"

extern "C" {
    #include <Tremolo/codec_internal.h>

    int _vorbis_unpack_books(vorbis_info *vi,oggpack_buffer *opb);
    int _vorbis_unpack_info(vorbis_info *vi,oggpack_buffer *opb);
    int _vorbis_unpack_comment(vorbis_comment *vc,oggpack_buffer *opb);
}

namespace android {

constexpr char kComponentName[] = "c2.google.vorbis.decoder";

static std::shared_ptr<C2ComponentInterface> BuildIntf(
        const char *name, c2_node_id_t id,
        std::function<void(C2ComponentInterface*)> deleter =
            std::default_delete<C2ComponentInterface>()) {
    return SimpleC2Interface::Builder(name, id, deleter)
            .inputFormat(C2FormatCompressed)
            .outputFormat(C2FormatAudio)
            .inputMediaType(MEDIA_MIMETYPE_AUDIO_VORBIS)
            .outputMediaType(MEDIA_MIMETYPE_AUDIO_RAW)
            .build();
}

C2SoftVorbis::C2SoftVorbis(const char *name, c2_node_id_t id)
    : SimpleC2Component(BuildIntf(name, id)),
      mState(nullptr),
      mVi(nullptr) {
}

C2SoftVorbis::~C2SoftVorbis() {
    onRelease();
}

c2_status_t C2SoftVorbis::onInit() {
    status_t err = initDecoder();
    return err == OK ? C2_OK : C2_NO_MEMORY;
}

c2_status_t C2SoftVorbis::onStop() {
    if (mState) vorbis_dsp_clear(mState);
    if (mVi) vorbis_info_clear(mVi);
    mNumFramesLeftOnPage = -1;
    mNumChannels = 1;
    mSamplingRate = 48000;
    mInputBufferCount = 0;
    mSignalledOutputEos = false;
    mSignalledError = false;

    return C2_OK;
}

void C2SoftVorbis::onReset() {
    (void)onStop();
}

void C2SoftVorbis::onRelease() {
    if (mState) {
        vorbis_dsp_clear(mState);
        delete mState;
        mState = nullptr;
    }

    if (mVi) {
        vorbis_info_clear(mVi);
        delete mVi;
        mVi = nullptr;
    }
}

status_t C2SoftVorbis::initDecoder() {
    mVi = new vorbis_info{};
    if (!mVi) return NO_MEMORY;
    vorbis_info_clear(mVi);

    mState = new vorbis_dsp_state{};
    if (!mState) return NO_MEMORY;
    vorbis_dsp_clear(mState);

    mNumFramesLeftOnPage = -1;
    mNumChannels = 1;
    mSamplingRate = 48000;
    mInputBufferCount = 0;
    mSignalledError = false;
    mSignalledOutputEos = false;

    return OK;
}

c2_status_t C2SoftVorbis::onFlush_sm() {
    mNumFramesLeftOnPage = -1;
    mSignalledOutputEos = false;
    if (mState) vorbis_dsp_restart(mState);

    return C2_OK;
}

c2_status_t C2SoftVorbis::drain(
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

static void fillEmptyWork(const std::unique_ptr<C2Work> &work) {
    work->worklets.front()->output.flags = work->input.flags;
    work->worklets.front()->output.buffers.clear();
    work->worklets.front()->output.ordinal = work->input.ordinal;
    work->workletsProcessed = 1u;
}

static void makeBitReader(
        const void *data, size_t size,
        ogg_buffer *buf, ogg_reference *ref, oggpack_buffer *bits) {
    buf->data = (uint8_t *)data;
    buf->size = size;
    buf->refcount = 1;
    buf->ptr.owner = nullptr;

    ref->buffer = buf;
    ref->begin = 0;
    ref->length = size;
    ref->next = nullptr;

    oggpack_readinit(bits, ref);
}

// (CHECK!) multiframe is tricky. decode call doesnt return the number of bytes
// consumed by the component. Also it is unclear why numPageFrames is being
// tagged at the end of input buffers for new pages. Refer lines 297-300 in
// SimpleDecodingSource.cpp
void C2SoftVorbis::process(
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
    C2ReadView rView = inBuffer.map().get();
    if (inSize && rView.error()) {
        ALOGE("read view map failed %d", rView.error());
        work->result = rView.error();
        return;
    }

    if (inSize == 0) {
        fillEmptyWork(work);
        if (eos) {
            mSignalledOutputEos = true;
            ALOGV("signalled EOS");
        }
        return;
    }

    ALOGV("in buffer attr. size %zu timestamp %d frameindex %d", inSize,
          (int)work->input.ordinal.timestamp.peeku(), (int)work->input.ordinal.frameIndex.peeku());
    const uint8_t *data = rView.data() + inOffset;
    if (mInputBufferCount < 2) {
        if (inSize < 7 || memcmp(&data[1], "vorbis", 6)) {
            ALOGE("unexpected first 7 bytes in CSD");
            mSignalledError = true;
            work->result = C2_CORRUPTED;
            return;
        }

        ogg_buffer buf;
        ogg_reference ref;
        oggpack_buffer bits;

        // skip 7 <type + "vorbis"> bytes
        makeBitReader((const uint8_t *)data + 7, inSize - 7, &buf, &ref, &bits);
        if (mInputBufferCount == 0) {
            if (data[0] != 1) {
                ALOGE("unexpected type received %d", data[0]);
                mSignalledError = true;
                work->result = C2_CORRUPTED;
                return;
            }
            vorbis_info_init(mVi);
            if (0 != _vorbis_unpack_info(mVi, &bits)) {
                ALOGE("Encountered error while unpacking info");
                mSignalledError = true;
                work->result = C2_CORRUPTED;
                return;
            }
            if (mVi->rate != mSamplingRate ||
                    mVi->channels != mNumChannels) {
                ALOGV("vorbis: rate/channels changed: %ld/%d", mVi->rate, mVi->channels);
                mSamplingRate = mVi->rate;
                mNumChannels = mVi->channels;
            }
        } else {
            if (data[0] != 5) {
                ALOGE("unexpected type received %d", data[0]);
                mSignalledError = true;
                work->result = C2_CORRUPTED;
                return;
            }
            if (0 != _vorbis_unpack_books(mVi, &bits)) {
                ALOGE("Encountered error while unpacking books");
                mSignalledError = true;
                work->result = C2_CORRUPTED;
                return;
            }
            if (0 != vorbis_dsp_init(mState, mVi)) {
                ALOGE("Encountered error while dsp init");
                mSignalledError = true;
                work->result = C2_CORRUPTED;
                return;
            }
        }
        ++mInputBufferCount;
        fillEmptyWork(work);
        if (eos) {
            mSignalledOutputEos = true;
            ALOGV("signalled EOS");
        }
        return;
    }
    int32_t numPageFrames = 0;
    if (inSize < sizeof(numPageFrames)) {
        ALOGE("input header has size %zu, expected %zu", inSize, sizeof(numPageFrames));
        mSignalledError = true;
        work->result = C2_CORRUPTED;
        return;
    }
    memcpy(&numPageFrames, data + inSize - sizeof(numPageFrames), sizeof(numPageFrames));
    inSize -= sizeof(numPageFrames);
    if (numPageFrames >= 0) {
        mNumFramesLeftOnPage = numPageFrames;
    }

    ogg_buffer buf;
    buf.data = const_cast<unsigned char*>(data);
    buf.size = inSize;
    buf.refcount = 1;
    buf.ptr.owner = nullptr;

    ogg_reference ref;
    ref.buffer = &buf;
    ref.begin = 0;
    ref.length = buf.size;
    ref.next = nullptr;

    ogg_packet pack;
    pack.packet = &ref;
    pack.bytes = ref.length;
    pack.b_o_s = 0;
    pack.e_o_s = 0;
    pack.granulepos = 0;
    pack.packetno = 0;

    size_t maxSamplesInBuffer = kMaxNumSamplesPerChannel * mVi->channels;
    size_t outCapacity =  maxSamplesInBuffer * sizeof(int16_t);
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

    int numFrames = 0;
    int ret = vorbis_dsp_synthesis(mState, &pack, 1);
    if (0 != ret) {
        ALOGE("vorbis_dsp_synthesis returned %d", ret);
        mSignalledError = true;
        work->result = C2_CORRUPTED;
        return;
    } else {
        numFrames = vorbis_dsp_pcmout(
                mState,  reinterpret_cast<int16_t *> (wView.data()),
                kMaxNumSamplesPerChannel);
        if (numFrames < 0) {
            ALOGD("vorbis_dsp_pcmout returned %d", numFrames);
            numFrames = 0;
        }
    }

    if (mNumFramesLeftOnPage >= 0) {
        if (numFrames > mNumFramesLeftOnPage) {
            ALOGV("discarding %d frames at end of page", numFrames - mNumFramesLeftOnPage);
            numFrames = mNumFramesLeftOnPage;
        }
        mNumFramesLeftOnPage -= numFrames;
    }

    if (numFrames) {
        int outSize = numFrames * sizeof(int16_t) * mVi->channels;

        work->worklets.front()->output.flags = work->input.flags;
        work->worklets.front()->output.buffers.clear();
        work->worklets.front()->output.buffers.push_back(createLinearBuffer(block, 0, outSize));
        work->worklets.front()->output.ordinal = work->input.ordinal;
        work->workletsProcessed = 1u;
    } else {
        fillEmptyWork(work);
        block.reset();
    }
    if (eos) {
        mSignalledOutputEos = true;
        ALOGV("signalled EOS");
    }
}

class C2SoftVorbisDecFactory : public C2ComponentFactory {
public:
    virtual c2_status_t createComponent(
            c2_node_id_t id,
            std::shared_ptr<C2Component>* const component,
            std::function<void(C2Component*)> deleter) override {
        *component = std::shared_ptr<C2Component>(new C2SoftVorbis(kComponentName, id), deleter);
        return C2_OK;
    }

    virtual c2_status_t createInterface(
            c2_node_id_t id,
            std::shared_ptr<C2ComponentInterface>* const interface,
            std::function<void(C2ComponentInterface*)> deleter) override {
        *interface = BuildIntf(kComponentName, id, deleter);
        return C2_OK;
    }

    virtual ~C2SoftVorbisDecFactory() override = default;
};

}  // namespace android

extern "C" ::C2ComponentFactory* CreateCodec2Factory() {
    ALOGV("in %s", __func__);
    return new ::android::C2SoftVorbisDecFactory();
}

extern "C" void DestroyCodec2Factory(::C2ComponentFactory* factory) {
    ALOGV("in %s", __func__);
    delete factory;
}
