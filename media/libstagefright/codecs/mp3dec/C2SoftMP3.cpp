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
#define LOG_TAG "C2SoftMP3"
#include <utils/Log.h>

#include "pvmp3decoder_api.h"

#include "C2SoftMP3.h"

#include <C2PlatformSupport.h>
#include <SimpleC2Interface.h>

#include <media/stagefright/foundation/ADebug.h>
#include <media/stagefright/foundation/MediaDefs.h>

#include <numeric>

namespace android {

constexpr char kComponentName[] = "c2.google.mp3.decoder";

static std::shared_ptr<C2ComponentInterface> BuildIntf(
        const char *name, c2_node_id_t id,
        std::function<void(C2ComponentInterface*)> deleter =
            std::default_delete<C2ComponentInterface>()) {
    return SimpleC2Interface::Builder(name, id, deleter)
            .inputFormat(C2FormatCompressed)
            .outputFormat(C2FormatAudio)
            .inputMediaType(MEDIA_MIMETYPE_AUDIO_MPEG)
            .outputMediaType(MEDIA_MIMETYPE_AUDIO_RAW)
            .build();
}

C2SoftMP3::C2SoftMP3(const char *name, c2_node_id_t id)
    : SimpleC2Component(BuildIntf(name, id)),
      mConfig(nullptr),
      mDecoderBuf(nullptr) {
}

C2SoftMP3::~C2SoftMP3() {
    onRelease();
}

c2_status_t C2SoftMP3::onInit() {
    status_t err = initDecoder();
    return err == OK ? C2_OK : C2_NO_MEMORY;
}

c2_status_t C2SoftMP3::onStop() {
    // Make sure that the next buffer output does not still
    // depend on fragments from the last one decoded.
    pvmp3_InitDecoder(mConfig, mDecoderBuf);
    mSignalledError = false;
    mIsFirst = true;
    mSignalledOutputEos = false;
    mAnchorTimeStamp = 0;
    mProcessedSamples = 0;

    return C2_OK;
}

void C2SoftMP3::onReset() {
    (void)onStop();
}

void C2SoftMP3::onRelease() {
    if (mDecoderBuf) {
        free(mDecoderBuf);
        mDecoderBuf = nullptr;
    }

    if (mConfig) {
        delete mConfig;
        mConfig = nullptr;
    }
}

status_t C2SoftMP3::initDecoder() {
    mConfig = new tPVMP3DecoderExternal{};
    if (!mConfig) return NO_MEMORY;
    mConfig->equalizerType = flat;
    mConfig->crcEnabled = false;

    size_t memRequirements = pvmp3_decoderMemRequirements();
    mDecoderBuf = malloc(memRequirements);
    if (!mDecoderBuf) return NO_MEMORY;

    pvmp3_InitDecoder(mConfig, mDecoderBuf);

    mNumChannels = 2;
    mSamplingRate = 44100;
    mIsFirst = true;
    mSignalledError = false;
    mSignalledOutputEos = false;
    mAnchorTimeStamp = 0;
    mProcessedSamples = 0;

    return OK;
}

/* The below code is borrowed from ./test/mp3reader.cpp */
static bool parseMp3Header(uint32_t header, size_t *frame_size,
                           uint32_t *out_sampling_rate = nullptr,
                           uint32_t *out_channels = nullptr,
                           uint32_t *out_bitrate = nullptr,
                           uint32_t *out_num_samples = nullptr) {
    *frame_size = 0;
    if (out_sampling_rate) *out_sampling_rate = 0;
    if (out_channels) *out_channels = 0;
    if (out_bitrate) *out_bitrate = 0;
    if (out_num_samples) *out_num_samples = 1152;

    if ((header & 0xffe00000) != 0xffe00000) return false;

    unsigned version = (header >> 19) & 3;
    if (version == 0x01) return false;

    unsigned layer = (header >> 17) & 3;
    if (layer == 0x00) return false;

    unsigned bitrate_index = (header >> 12) & 0x0f;
    if (bitrate_index == 0 || bitrate_index == 0x0f) return false;

    unsigned sampling_rate_index = (header >> 10) & 3;
    if (sampling_rate_index == 3) return false;

    static const int kSamplingRateV1[] = { 44100, 48000, 32000 };
    int sampling_rate = kSamplingRateV1[sampling_rate_index];
    if (version == 2 /* V2 */) {
        sampling_rate /= 2;
    } else if (version == 0 /* V2.5 */) {
        sampling_rate /= 4;
    }

    unsigned padding = (header >> 9) & 1;

    if (layer == 3) { // layer I
        static const int kBitrateV1[] =
        {
            32, 64, 96, 128, 160, 192, 224, 256, 288, 320, 352, 384, 416, 448
        };
        static const int kBitrateV2[] =
        {
            32, 48, 56, 64, 80, 96, 112, 128, 144, 160, 176, 192, 224, 256
        };

        int bitrate = (version == 3 /* V1 */) ? kBitrateV1[bitrate_index - 1] :
                kBitrateV2[bitrate_index - 1];

        if (out_bitrate) {
            *out_bitrate = bitrate;
        }
        *frame_size = (12000 * bitrate / sampling_rate + padding) * 4;
        if (out_num_samples) {
            *out_num_samples = 384;
        }
    } else { // layer II or III
        static const int kBitrateV1L2[] =
        {
            32, 48, 56, 64, 80, 96, 112, 128, 160, 192, 224, 256, 320, 384
        };

        static const int kBitrateV1L3[] =
        {
            32, 40, 48, 56, 64, 80, 96, 112, 128, 160, 192, 224, 256, 320
        };

        static const int kBitrateV2[] =
        {
            8, 16, 24, 32, 40, 48, 56, 64, 80, 96, 112, 128, 144, 160
        };

        int bitrate;
        if (version == 3 /* V1 */) {
            bitrate = (layer == 2 /* L2 */) ? kBitrateV1L2[bitrate_index - 1] :
                    kBitrateV1L3[bitrate_index - 1];

            if (out_num_samples) {
                *out_num_samples = 1152;
            }
        } else { // V2 (or 2.5)
            bitrate = kBitrateV2[bitrate_index - 1];
            if (out_num_samples) {
                *out_num_samples = (layer == 1 /* L3 */) ? 576 : 1152;
            }
        }

        if (out_bitrate) {
            *out_bitrate = bitrate;
        }

        if (version == 3 /* V1 */) {
            *frame_size = 144000 * bitrate / sampling_rate + padding;
        } else { // V2 or V2.5
            size_t tmp = (layer == 1 /* L3 */) ? 72000 : 144000;
            *frame_size = tmp * bitrate / sampling_rate + padding;
        }
    }

    if (out_sampling_rate) {
        *out_sampling_rate = sampling_rate;
    }

    if (out_channels) {
        int channel_mode = (header >> 6) & 3;

        *out_channels = (channel_mode == 3) ? 1 : 2;
    }

    return true;
}

static uint32_t U32_AT(const uint8_t *ptr) {
    return ptr[0] << 24 | ptr[1] << 16 | ptr[2] << 8 | ptr[3];
}

static status_t calculateOutSize(uint8 *header, size_t inSize,
                                 std::vector<size_t> *decodedSizes) {
    uint32_t channels;
    uint32_t numSamples;
    size_t frameSize;
    size_t totalInSize = 0;

    while (totalInSize + 4 < inSize) {
        if (!parseMp3Header(U32_AT(header + totalInSize), &frameSize,
                            nullptr, &channels, nullptr, &numSamples)) {
            ALOGE("Error in parse mp3 header during outSize estimation");
            return UNKNOWN_ERROR;
        }
        totalInSize += frameSize;
        decodedSizes->push_back(numSamples * channels * sizeof(int16_t));
    }

    if (decodedSizes->empty()) return UNKNOWN_ERROR;

    return OK;
}

c2_status_t C2SoftMP3::onFlush_sm() {
    return onStop();
}

c2_status_t C2SoftMP3::drain(
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

// TODO: Can overall error checking be improved? As in the check for validity of
//       work, pool ptr, work->input.buffers.size() == 1, ...
// TODO: Blind removal of 529 samples from the output may not work. Because
//       mpeg layer 1 frame size is 384 samples per frame. This should introduce
//       negative values and can cause SEG faults. Soft omx mp3 plugin can have
//       this problem (CHECK!)
void C2SoftMP3::process(
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

    size_t calOutSize;
    std::vector<size_t> decodedSizes;
    const uint8_t *inPtr = rView.data() + inOffset;
    if (OK != calculateOutSize(const_cast<uint8 *>(inPtr), inSize, &decodedSizes)) {
        work->result = C2_CORRUPTED;
        return;
    }
    calOutSize = std::accumulate(decodedSizes.begin(), decodedSizes.end(), 0);
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

    int outSize = 0;
    int outOffset = 0;
    auto it = decodedSizes.begin();
    size_t inPos = 0;
    while (inPos < inSize) {
        if (it == decodedSizes.end()) {
            ALOGE("unexpected trailing bytes, ignoring them");
            break;
        }

        mConfig->pInputBuffer = const_cast<uint8 *>(inPtr + inPos);
        mConfig->inputBufferCurrentLength = (inSize - inPos);
        mConfig->inputBufferMaxLength = 0;
        mConfig->inputBufferUsedLength = 0;
        mConfig->outputFrameSize = (calOutSize - outSize);
        mConfig->pOutputBuffer = reinterpret_cast<int16_t *> (wView.data() + outSize);

        ERROR_CODE decoderErr;
        if ((decoderErr = pvmp3_framedecoder(mConfig, mDecoderBuf))
                != NO_DECODING_ERROR) {
            ALOGE("mp3 decoder returned error %d", decoderErr);
            if (decoderErr != NO_ENOUGH_MAIN_DATA_ERROR
                    && decoderErr != SIDE_INFO_ERROR) {
                mSignalledError = true;
                work->result = C2_CORRUPTED;
                return;
            }

            // This is recoverable, just ignore the current frame and
            // play silence instead.
            ALOGV("ignoring error and sending silence");
            if (mConfig->outputFrameSize == 0) {
                mConfig->outputFrameSize = *it / sizeof(int16_t);
            }
            memset(mConfig->pOutputBuffer, 0, mConfig->outputFrameSize * sizeof(int16_t));
        } else if (mConfig->samplingRate != mSamplingRate
                || mConfig->num_channels != mNumChannels) {
            mSamplingRate = mConfig->samplingRate;
            mNumChannels = mConfig->num_channels;
        }
        if (*it != mConfig->outputFrameSize * sizeof(int16_t)) {
            ALOGE("panic, parsed size does not match decoded size");
            mSignalledError = true;
            work->result = C2_CORRUPTED;
            return;
        }
        outSize += mConfig->outputFrameSize * sizeof(int16_t);
        inPos += mConfig->inputBufferUsedLength;
        it++;
    }
    if (mIsFirst) {
        mIsFirst = false;
        // The decoder delay is 529 samples, so trim that many samples off
        // the start of the first output buffer. This essentially makes this
        // decoder have zero delay, which the rest of the pipeline assumes.
        outOffset = kPVMP3DecoderDelay * mNumChannels * sizeof(int16_t);
        mAnchorTimeStamp = work->input.ordinal.timestamp.peekull();
    }
    uint64_t outTimeStamp = mProcessedSamples * 1000000ll / mSamplingRate;
    mProcessedSamples += ((outSize - outOffset) / (mNumChannels * sizeof(int16_t)));
    ALOGV("out buffer attr. offset %d size %d timestamp %u", outOffset, outSize - outOffset,
          (uint32_t)(mAnchorTimeStamp + outTimeStamp));
    decodedSizes.clear();
    work->worklets.front()->output.flags = work->input.flags;
    work->worklets.front()->output.buffers.clear();
    work->worklets.front()->output.buffers.push_back(
            createLinearBuffer(block, outOffset, outSize - outOffset));
    work->worklets.front()->output.ordinal = work->input.ordinal;
    work->worklets.front()->output.ordinal.timestamp = mAnchorTimeStamp + outTimeStamp;
    work->workletsProcessed = 1u;
    if (eos) {
        mSignalledOutputEos = true;
        ALOGV("signalled EOS");
    }
}

class C2SoftMp3DecFactory : public C2ComponentFactory {
public:
    virtual c2_status_t createComponent(
            c2_node_id_t id,
            std::shared_ptr<C2Component>* const component,
            std::function<void(C2Component*)> deleter) override {
        *component = std::shared_ptr<C2Component>(new C2SoftMP3(kComponentName, id), deleter);
        return C2_OK;
    }

    virtual c2_status_t createInterface(
            c2_node_id_t id,
            std::shared_ptr<C2ComponentInterface>* const interface,
            std::function<void(C2ComponentInterface*)> deleter) override {
        *interface = BuildIntf(kComponentName, id, deleter);
        return C2_OK;
    }

    virtual ~C2SoftMp3DecFactory() override = default;
};

}  // namespace android

extern "C" ::C2ComponentFactory* CreateCodec2Factory() {
    ALOGV("in %s", __func__);
    return new ::android::C2SoftMp3DecFactory();
}

extern "C" void DestroyCodec2Factory(::C2ComponentFactory* factory) {
    ALOGV("in %s", __func__);
    delete factory;
}

