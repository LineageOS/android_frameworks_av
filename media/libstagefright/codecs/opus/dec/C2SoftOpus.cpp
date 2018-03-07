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
#define LOG_TAG "C2SoftOpus"
#include <utils/Log.h>

#include "C2SoftOpus.h"

#include <C2PlatformSupport.h>
#include <SimpleC2Interface.h>

#include <media/stagefright/foundation/ADebug.h>
#include <media/stagefright/foundation/MediaDefs.h>

extern "C" {
    #include <opus.h>
    #include <opus_multistream.h>
}

namespace android {

constexpr char kComponentName[] = "c2.google.opus.decoder";

static std::shared_ptr<C2ComponentInterface> BuildIntf(
        const char *name, c2_node_id_t id,
        std::function<void(C2ComponentInterface*)> deleter =
            std::default_delete<C2ComponentInterface>()) {
    return SimpleC2Interface::Builder(name, id, deleter)
            .inputFormat(C2FormatCompressed)
            .outputFormat(C2FormatAudio)
            .inputMediaType(MEDIA_MIMETYPE_AUDIO_OPUS)
            .outputMediaType(MEDIA_MIMETYPE_AUDIO_RAW)
            .build();
}

C2SoftOpus::C2SoftOpus(const char *name, c2_node_id_t id)
    : SimpleC2Component(BuildIntf(name, id)),
      mDecoder(nullptr) {
}

C2SoftOpus::~C2SoftOpus() {
    onRelease();
}

c2_status_t C2SoftOpus::onInit() {
    status_t err = initDecoder();
    return err == OK ? C2_OK : C2_NO_MEMORY;
}

c2_status_t C2SoftOpus::onStop() {
    if (mDecoder) {
        opus_multistream_decoder_destroy(mDecoder);
        mDecoder = nullptr;
    }
    memset(&mHeader, 0, sizeof(mHeader));
    mCodecDelay = 0;
    mSeekPreRoll = 0;
    mSamplesToDiscard = 0;
    mInputBufferCount = 0;
    mSignalledError = false;
    mSignalledOutputEos = false;

    return C2_OK;
}

void C2SoftOpus::onReset() {
    (void)onStop();
}

void C2SoftOpus::onRelease() {
    if (mDecoder) {
        opus_multistream_decoder_destroy(mDecoder);
        mDecoder = nullptr;
    }
}

status_t C2SoftOpus::initDecoder() {
    memset(&mHeader, 0, sizeof(mHeader));
    mCodecDelay = 0;
    mSeekPreRoll = 0;
    mSamplesToDiscard = 0;
    mInputBufferCount = 0;
    mSignalledError = false;
    mSignalledOutputEos = false;

    return OK;
}

c2_status_t C2SoftOpus::onFlush_sm() {
    if (mDecoder) {
        opus_multistream_decoder_ctl(mDecoder, OPUS_RESET_STATE);
        mSamplesToDiscard = mSeekPreRoll;
        mSignalledOutputEos = false;
    }
    return C2_OK;
}

c2_status_t C2SoftOpus::drain(
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

static uint16_t ReadLE16(const uint8_t *data, size_t data_size,
                         uint32_t read_offset) {
    if (read_offset + 1 > data_size)
        return 0;
    uint16_t val;
    val = data[read_offset];
    val |= data[read_offset + 1] << 8;
    return val;
}

static const int kRate = 48000;

// Opus uses Vorbis channel mapping, and Vorbis channel mapping specifies
// mappings for up to 8 channels. This information is part of the Vorbis I
// Specification:
// http://www.xiph.org/vorbis/doc/Vorbis_I_spec.html
static const int kMaxChannels = 8;

// Maximum packet size used in Xiph's opusdec.
static const int kMaxOpusOutputPacketSizeSamples = 960 * 6;

// Default audio output channel layout. Used to initialize |stream_map| in
// OpusHeader, and passed to opus_multistream_decoder_create() when the header
// does not contain mapping information. The values are valid only for mono and
// stereo output: Opus streams with more than 2 channels require a stream map.
static const int kMaxChannelsWithDefaultLayout = 2;
static const uint8_t kDefaultOpusChannelLayout[kMaxChannelsWithDefaultLayout] = { 0, 1 };

// Parses Opus Header. Header spec: http://wiki.xiph.org/OggOpus#ID_Header
static bool ParseOpusHeader(const uint8_t *data, size_t data_size,
                            OpusHeader* header) {
    // Size of the Opus header excluding optional mapping information.
    const size_t kOpusHeaderSize = 19;

    // Offset to the channel count byte in the Opus header.
    const size_t kOpusHeaderChannelsOffset = 9;

    // Offset to the pre-skip value in the Opus header.
    const size_t kOpusHeaderSkipSamplesOffset = 10;

    // Offset to the gain value in the Opus header.
    const size_t kOpusHeaderGainOffset = 16;

    // Offset to the channel mapping byte in the Opus header.
    const size_t kOpusHeaderChannelMappingOffset = 18;

    // Opus Header contains a stream map. The mapping values are in the header
    // beyond the always present |kOpusHeaderSize| bytes of data. The mapping
    // data contains stream count, coupling information, and per channel mapping
    // values:
    //   - Byte 0: Number of streams.
    //   - Byte 1: Number coupled.
    //   - Byte 2: Starting at byte 2 are |header->channels| uint8 mapping
    //             values.
    const size_t kOpusHeaderNumStreamsOffset = kOpusHeaderSize;
    const size_t kOpusHeaderNumCoupledOffset = kOpusHeaderNumStreamsOffset + 1;
    const size_t kOpusHeaderStreamMapOffset = kOpusHeaderNumStreamsOffset + 2;

    if (data_size < kOpusHeaderSize) {
        ALOGE("Header size is too small.");
        return false;
    }
    header->channels = *(data + kOpusHeaderChannelsOffset);
    if (header->channels <= 0 || header->channels > kMaxChannels) {
        ALOGE("Invalid Header, wrong channel count: %d", header->channels);
        return false;
    }

    header->skip_samples = ReadLE16(data,
                                    data_size,
                                    kOpusHeaderSkipSamplesOffset);

    header->gain_db = static_cast<int16_t>(ReadLE16(data,
                                                    data_size,
                                                    kOpusHeaderGainOffset));

    header->channel_mapping = *(data + kOpusHeaderChannelMappingOffset);
    if (!header->channel_mapping) {
        if (header->channels > kMaxChannelsWithDefaultLayout) {
            ALOGE("Invalid Header, missing stream map.");
            return false;
        }
        header->num_streams = 1;
        header->num_coupled = header->channels > 1;
        header->stream_map[0] = 0;
        header->stream_map[1] = 1;
        return true;
    }
    if (data_size < kOpusHeaderStreamMapOffset + header->channels) {
        ALOGE("Invalid stream map; insufficient data for current channel "
              "count: %d", header->channels);
        return false;
    }
    header->num_streams = *(data + kOpusHeaderNumStreamsOffset);
    header->num_coupled = *(data + kOpusHeaderNumCoupledOffset);
    if (header->num_streams + header->num_coupled != header->channels) {
        ALOGE("Inconsistent channel mapping.");
        return false;
    }
    for (int i = 0; i < header->channels; ++i)
        header->stream_map[i] = *(data + kOpusHeaderStreamMapOffset + i);
    return true;
}

// Convert nanoseconds to number of samples.
static uint64_t ns_to_samples(uint64_t ns, int rate) {
    return static_cast<double>(ns) * rate / 1000000000;
}

void C2SoftOpus::process(
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
    if (mInputBufferCount < 3) {
        if (mInputBufferCount == 0) {
            if (!ParseOpusHeader(data, inSize, &mHeader)) {
                ALOGE("Encountered error while Parsing Opus Header.");
                mSignalledError = true;
                work->result = C2_CORRUPTED;
                return;
            }
            uint8_t channel_mapping[kMaxChannels] = {0};
            if (mHeader.channels <= kMaxChannelsWithDefaultLayout) {
                memcpy(&channel_mapping,
                       kDefaultOpusChannelLayout,
                       kMaxChannelsWithDefaultLayout);
            } else {
                memcpy(&channel_mapping,
                       mHeader.stream_map,
                       mHeader.channels);
            }
            int status = OPUS_INVALID_STATE;
            mDecoder = opus_multistream_decoder_create(kRate,
                                                       mHeader.channels,
                                                       mHeader.num_streams,
                                                       mHeader.num_coupled,
                                                       channel_mapping,
                                                       &status);
            if (!mDecoder || status != OPUS_OK) {
                ALOGE("opus_multistream_decoder_create failed status = %s",
                      opus_strerror(status));
                mSignalledError = true;
                work->result = C2_CORRUPTED;
                return;
            }
            status = opus_multistream_decoder_ctl(mDecoder,
                                                  OPUS_SET_GAIN(mHeader.gain_db));
            if (status != OPUS_OK) {
                ALOGE("Failed to set OPUS header gain; status = %s",
                      opus_strerror(status));
                mSignalledError = true;
                work->result = C2_CORRUPTED;
                return;
            }
        } else {
            if (inSize < 8) {
                ALOGE("Input sample size is too small.");
                mSignalledError = true;
                work->result = C2_CORRUPTED;
                return;
            }
            int64_t samples = ns_to_samples( *(reinterpret_cast<int64_t*>
                              (const_cast<uint8_t *> (data))), kRate);
            if (mInputBufferCount == 1) {
                mCodecDelay = samples;
                mSamplesToDiscard = mCodecDelay;
            }
            else {
                mSeekPreRoll = samples;
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

    // Ignore CSD re-submissions.
    if ((work->input.flags & C2FrameData::FLAG_CODEC_CONFIG)) {
        fillEmptyWork(work);
        return;
    }

    // When seeking to zero, |mCodecDelay| samples has to be discarded
    // instead of |mSeekPreRoll| samples (as we would when seeking to any
    // other timestamp).
    if (work->input.ordinal.timestamp.peeku() == 0) mSamplesToDiscard = mCodecDelay;

    std::shared_ptr<C2LinearBlock> block;
    C2MemoryUsage usage = { C2MemoryUsage::CPU_READ, C2MemoryUsage::CPU_WRITE };
    c2_status_t err = pool->fetchLinearBlock(
                          kMaxNumSamplesPerBuffer * kMaxChannels * sizeof(int16_t),
                          usage, &block);
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

    int numSamples = opus_multistream_decode(mDecoder,
                                             data,
                                             inSize,
                                             reinterpret_cast<int16_t *> (wView.data()),
                                             kMaxOpusOutputPacketSizeSamples,
                                             0);
    if (numSamples < 0) {
        ALOGE("opus_multistream_decode returned numSamples %d", numSamples);
        numSamples = 0;
        mSignalledError = true;
        work->result = C2_CORRUPTED;
        return;
    }

    int outOffset = 0;
    if (mSamplesToDiscard > 0) {
        if (mSamplesToDiscard > numSamples) {
            mSamplesToDiscard -= numSamples;
            numSamples = 0;
        } else {
            numSamples -= mSamplesToDiscard;
            outOffset = mSamplesToDiscard * sizeof(int16_t) * mHeader.channels;
            mSamplesToDiscard = 0;
        }
    }

    if (numSamples) {
        int outSize = numSamples * sizeof(int16_t) * mHeader.channels;
        ALOGV("out buffer attr. offset %d size %d ", outOffset, outSize);

        work->worklets.front()->output.flags = work->input.flags;
        work->worklets.front()->output.buffers.clear();
        work->worklets.front()->output.buffers.push_back(createLinearBuffer(block, outOffset, outSize));
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

class C2SoftOpusDecFactory : public C2ComponentFactory {
public:
    virtual c2_status_t createComponent(
            c2_node_id_t id,
            std::shared_ptr<C2Component>* const component,
            std::function<void(C2Component*)> deleter) override {
        *component = std::shared_ptr<C2Component>(new C2SoftOpus(kComponentName, id), deleter);
        return C2_OK;
    }

    virtual c2_status_t createInterface(
            c2_node_id_t id,
            std::shared_ptr<C2ComponentInterface>* const interface,
            std::function<void(C2ComponentInterface*)> deleter) override {
        *interface = BuildIntf(kComponentName, id, deleter);
        return C2_OK;
    }

    virtual ~C2SoftOpusDecFactory() override = default;
};

}  // namespace android

extern "C" ::C2ComponentFactory* CreateCodec2Factory() {
    ALOGV("in %s", __func__);
    return new ::android::C2SoftOpusDecFactory();
}

extern "C" void DestroyCodec2Factory(::C2ComponentFactory* factory) {
    ALOGV("in %s", __func__);
    delete factory;
}
