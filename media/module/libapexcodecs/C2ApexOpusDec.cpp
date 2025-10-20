/*
 * Copyright (C) 2025 The Android Open Source Project
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

//#define LOG_NDEBUG 0
#define LOG_TAG "C2ApexOpusDec"
#include <utils/Log.h>

#include <span>
#include <sys/mman.h>

#include <android-base/hex.h>
#include <android_media_codec.h>

#include <apex/ApexCodecs.h>
#include <media/stagefright/foundation/AUtils.h>
#include <media/stagefright/foundation/MediaDefs.h>
#include <media/stagefright/foundation/OpusHeader.h>
#include <SimpleC2Interface.h>

#include "C2ApexOpusDec.h"

extern "C" {
    #include <opus.h>
    #include <opus_multistream.h>
}

namespace android::apexcodecs {

namespace {
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

// Convert nanoseconds to number of samples.
static uint64_t ns_to_samples(uint64_t ns, int rate) {
    return static_cast<double>(ns) * rate / 1000000000;
}

constexpr size_t kMaxOutputBufferSize =
    kMaxOpusOutputPacketSizeSamples * kMaxChannels * sizeof(int16_t);

}  // namespace

class C2ApexOpusDec::IntfImpl : public SimpleInterface<void>::BaseParams {
public:
    explicit IntfImpl(const std::shared_ptr<C2ReflectorHelper> &helper)
        : SimpleInterface<void>::BaseParams(
                helper,
                COMPONENT_NAME,
                C2Component::KIND_DECODER,
                C2Component::DOMAIN_AUDIO,
                MEDIA_MIMETYPE_AUDIO_OPUS) {
        noPrivateBuffers();
        noInputReferences();
        noOutputReferences();
        noInputLatency();
        noTimeStretch();
        setDerivedInstance(this);

        addParameter(
                DefineParam(mAttrib, C2_PARAMKEY_COMPONENT_ATTRIBUTES)
                .withConstValue(new C2ComponentAttributesSetting(
                    C2Component::ATTRIB_IS_TEMPORAL))
                .build());

        addParameter(
                DefineParam(mSampleRate, C2_PARAMKEY_SAMPLE_RATE)
                .withDefault(new C2StreamSampleRateInfo::output(0u, 48000))
                .withFields({C2F(mSampleRate, value).inRange(8000, 48000)})
                .withSetter((Setter<decltype(*mSampleRate)>::StrictValueWithNoDeps))
                .build());

        addParameter(
                DefineParam(mChannelCount, C2_PARAMKEY_CHANNEL_COUNT)
                .withDefault(new C2StreamChannelCountInfo::output(0u, 1))
                .withFields({C2F(mChannelCount, value).inRange(1, 8)})
                .withSetter(Setter<decltype(*mChannelCount)>::StrictValueWithNoDeps)
                .build());

        addParameter(
                DefineParam(mBitrate, C2_PARAMKEY_BITRATE)
                .withDefault(new C2StreamBitrateInfo::input(0u, 6000))
                .withFields({C2F(mBitrate, value).inRange(6000, 510000)})
                .withSetter(Setter<decltype(*mBitrate)>::NonStrictValueWithNoDeps)
                .build());

        addParameter(
                DefineParam(mInputMaxBufSize, C2_PARAMKEY_INPUT_MAX_BUFFER_SIZE)
                .withConstValue(new C2StreamMaxBufferSizeInfo::input(0u, 960 * 6))
                .build());
    }

private:
    std::shared_ptr<C2StreamSampleRateInfo::output> mSampleRate;
    std::shared_ptr<C2StreamChannelCountInfo::output> mChannelCount;
    std::shared_ptr<C2StreamBitrateInfo::input> mBitrate;
    std::shared_ptr<C2StreamMaxBufferSizeInfo::input> mInputMaxBufSize;
};

C2ApexOpusDec::C2ApexOpusDec(const std::shared_ptr<IntfImpl> &intfImpl)
    : mConfigurable(std::make_unique<ApexConfigurableImpl>(
            std::make_shared<SimpleC2Interface<IntfImpl>>(COMPONENT_NAME, 0, intfImpl))),
      mIntf(intfImpl),
      mDecoder(nullptr) {
    initDecoderStates();
}

// static
std::unique_ptr<ApexComponentIntf> C2ApexOpusDec::Create(
        const std::shared_ptr<C2ReflectorHelper> &helper) {
    return std::make_unique<C2ApexOpusDec>(std::make_shared<IntfImpl>(helper));
}

// static
std::shared_ptr<C2Component::Traits> C2ApexOpusDec::MakeTraits() {
#ifdef ENABLE_APEX_CODECS
        std::shared_ptr<C2Component::Traits> traits = std::make_shared<C2Component::Traits>();
        traits->name        = C2ApexOpusDec::COMPONENT_NAME;
        traits->domain      = C2Component::DOMAIN_AUDIO;
        traits->kind        = C2Component::KIND_DECODER;
        traits->rank        = 16;
        traits->mediaType   = MEDIA_MIMETYPE_AUDIO_OPUS;
        traits->owner       = "__ApexCodecs__";
        return traits;
#else
        return nullptr;
#endif
}


// static
void *C2ApexOpusDec::Map(void *addr, size_t size, int prot, int flags, int fd, off_t offset) {
    // TODO
    return ::mmap(addr, size, prot, flags, fd, offset);
}

// static
int C2ApexOpusDec::Unmap(void *addr, size_t size) {
    // TODO
    return ::munmap(addr, size);
}

void C2ApexOpusDec::initDecoderStates() {
    memset(&mHeader, 0, sizeof(mHeader));
    mCodecDelay = 0;
    mSeekPreRoll = 0;
    mSamplesToDiscard = 0;
    mInputBufferCount = 0;
    mSignalledError = false;
    mSignalledOutputEos = false;
}

ApexCodec_Status C2ApexOpusDec::start() {
    initDecoderStates();
    return APEXCODEC_STATUS_OK;
}

ApexCodec_Status C2ApexOpusDec::flush() {
    ALOGV("flush");
    if (mDecoder) {
        opus_multistream_decoder_ctl(mDecoder, OPUS_RESET_STATE);
        mSamplesToDiscard = mSeekPreRoll;
        mSignalledOutputEos = false;
    }
    return APEXCODEC_STATUS_OK;
}

ApexCodec_Status C2ApexOpusDec::reset() {
    if (mDecoder) {
        opus_multistream_decoder_destroy(mDecoder);
        mDecoder = nullptr;
    }
    initDecoderStates();
    return APEXCODEC_STATUS_OK;
}

std::unique_ptr<ApexConfigurableIntf> C2ApexOpusDec::getConfigurable() {
    return std::move(mConfigurable);
}

ApexCodec_Status C2ApexOpusDec::process(
        const ApexCodec_Buffer *input,
        ApexCodec_Buffer *output,
        size_t *consumed,
        size_t *produced) {
    if (__builtin_available(android 36, *)) {
        *consumed = 0;
        *produced = 0;
        ApexCodec_BufferFlags flags;
        uint64_t frameIndex;
        uint64_t timestamp;
        ApexCodec_Status err = ApexCodec_Buffer_getBufferInfo(
                const_cast<ApexCodec_Buffer *>(input), &flags, &frameIndex, &timestamp);
        if (err != APEXCODEC_STATUS_OK) {
            ALOGE("process: getting buffer info from input failed: %d", err);
            return err;
        }
        bool eos = (flags & APEXCODEC_FLAG_END_OF_STREAM) != 0;
        size_t inOffset = 0u;
        size_t inSize = 0u;
        ApexCodec_LinearBuffer inputBuffer = { nullptr, 0 };
        if (ApexCodec_Buffer_getType(
                const_cast<ApexCodec_Buffer *>(input)) == APEXCODEC_BUFFER_TYPE_LINEAR) {
            ApexCodec_Buffer_getLinearBuffer(
                    const_cast<ApexCodec_Buffer *>(input), &inputBuffer);
            inSize = inputBuffer.size;
        }
        if (inSize == 0) {
            if (eos) {
                mSignalledOutputEos = true;
                ALOGV("signalled EOS");
            }
            ApexCodec_Buffer_setBufferInfo(
                    output,
                    mSignalledOutputEos ? APEXCODEC_FLAG_END_OF_STREAM
                                        : ApexCodec_BufferFlags(0),
                    frameIndex,
                    timestamp);
            return APEXCODEC_STATUS_OK;
        }

        ALOGV("in buffer attr. size %zu timestamp %d frameindex %d", inSize,
            (int)timestamp, (int)frameIndex);
        const uint8_t *data = inputBuffer.data;
        if (mInputBufferCount < 3) {
            if (mInputBufferCount == 0) {
                size_t opusHeadSize = 0;
                size_t codecDelayBufSize = 0;
                size_t seekPreRollBufSize = 0;
                void *opusHeadBuf = NULL;
                void *codecDelayBuf = NULL;
                void *seekPreRollBuf = NULL;

                if (!GetOpusHeaderBuffers(data, inSize, &opusHeadBuf,
                                        &opusHeadSize, &codecDelayBuf,
                                        &codecDelayBufSize, &seekPreRollBuf,
                                        &seekPreRollBufSize)) {
                    ALOGE("%s encountered error in GetOpusHeaderBuffers", __func__);
                    mSignalledError = true;
                    return APEXCODEC_STATUS_CORRUPTED;
                }

                if (!ParseOpusHeader((uint8_t *)opusHeadBuf, opusHeadSize, &mHeader)) {
                    ALOGE("%s Encountered error while Parsing Opus Header.", __func__);
                    mSignalledError = true;
                    return APEXCODEC_STATUS_CORRUPTED;
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
                    return APEXCODEC_STATUS_CORRUPTED;
                }
                status = opus_multistream_decoder_ctl(mDecoder,
                                                    OPUS_SET_GAIN(mHeader.gain_db));
                if (status != OPUS_OK) {
                    ALOGE("Failed to set OPUS header gain; status = %s",
                        opus_strerror(status));
                    mSignalledError = true;
                    return APEXCODEC_STATUS_CORRUPTED;
                }

                if (codecDelayBuf && codecDelayBufSize == sizeof(uint64_t)) {
                    uint64_t value;
                    memcpy(&value, codecDelayBuf, sizeof(uint64_t));
                    mCodecDelay = ns_to_samples(value, kRate);
                    mSamplesToDiscard = mCodecDelay;
                    ++mInputBufferCount;
                }
                if (seekPreRollBuf && seekPreRollBufSize == sizeof(uint64_t)) {
                    uint64_t value;
                    memcpy(&value, seekPreRollBuf, sizeof(uint64_t));
                    mSeekPreRoll = ns_to_samples(value, kRate);
                    ++mInputBufferCount;
                }
            } else {
                if (inSize < 8) {
                    ALOGE("Input sample size is too small.");
                    mSignalledError = true;
                    return APEXCODEC_STATUS_CORRUPTED;
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

            std::vector<uint8_t> configUpdate;
            ++mInputBufferCount;
            if (mInputBufferCount == 3) {
                ALOGI("Configuring decoder: %d Hz, %d channels",
                    kRate, mHeader.channels);
                C2StreamSampleRateInfo::output sampleRateInfo(0u, kRate);
                C2StreamChannelCountInfo::output channelCountInfo(0u, mHeader.channels);
                std::vector<std::unique_ptr<C2SettingResult>> failures;
                c2_status_t err = mIntf->config(
                        { &sampleRateInfo, &channelCountInfo },
                        C2_MAY_BLOCK,
                        &failures);
                if (err == C2_OK) {
                    AppendParamsToVector(&configUpdate, &sampleRateInfo, &channelCountInfo);
                    output->setOwnedConfigUpdates(std::move(configUpdate));
                } else {
                    ALOGE("Config Update failed");
                    mSignalledError = true;
                    return APEXCODEC_STATUS_CORRUPTED;
                }
            }
            if (eos) {
                mSignalledOutputEos = true;
                ALOGV("signalled EOS");
            }
            ApexCodec_Buffer_setBufferInfo(
                    output,
                    mSignalledOutputEos ? APEXCODEC_FLAG_END_OF_STREAM
                                        : ApexCodec_BufferFlags(0),
                    frameIndex,
                    timestamp);
            *consumed = inSize;
            return APEXCODEC_STATUS_OK;
        }

        // Ignore CSD re-submissions.
        if (flags & C2FrameData::FLAG_CODEC_CONFIG) {
            ApexCodec_Buffer_setBufferInfo(
                    output,
                    mSignalledOutputEos ? APEXCODEC_FLAG_END_OF_STREAM
                                        : ApexCodec_BufferFlags(0),
                    frameIndex,
                    timestamp);
            *consumed = inSize;
            return APEXCODEC_STATUS_OK;
        }

        ApexCodec_LinearBuffer outputBuffer;
        ApexCodec_Buffer_getLinearBuffer(output, &outputBuffer);
        if (outputBuffer.size < kMaxOutputBufferSize) {
            std::vector<uint8_t> configUpdate;
            C2StreamMaxBufferSizeInfo::output outSize(
                    0u /* stream */, kMaxOutputBufferSize);
            AppendParamsToVector(&configUpdate, &outSize);
            output->setOwnedConfigUpdates(std::move(configUpdate));
            return APEXCODEC_STATUS_NO_MEMORY;
        }

        // When seeking to zero, |mCodecDelay| samples has to be discarded
        // instead of |mSeekPreRoll| samples (as we would when seeking to any
        // other timestamp).
        if (timestamp == uint64_t(0)) mSamplesToDiscard = mCodecDelay;

        ALOGV("data = %p, inSize = %zu, outputBuffer.data = %p",
              data, inSize, outputBuffer.data);
        int numSamples = opus_multistream_decode(mDecoder,
                                                data,
                                                inSize,
                                                reinterpret_cast<int16_t *>(outputBuffer.data),
                                                kMaxOpusOutputPacketSizeSamples,
                                                0);
        if (numSamples < 0) {
            ALOGE("opus_multistream_decode returned numSamples %d", numSamples);
            numSamples = 0;
            mSignalledError = true;
            return APEXCODEC_STATUS_CORRUPTED;
        }

        *consumed = inSize;
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

            outputBuffer.data = outputBuffer.data + outOffset;
            *produced = outSize;
            ApexCodec_Buffer_setBufferInfo(output, flags, frameIndex, timestamp);
            ApexCodec_Buffer_setLinearBuffer(output, &outputBuffer);
        } else {
            ApexCodec_Buffer_setBufferInfo(output, flags, frameIndex, timestamp);
            outputBuffer.data = nullptr;
            outputBuffer.size = 0;
            ApexCodec_Buffer_setLinearBuffer(output, &outputBuffer);
            *produced = 0;
        }
        if (eos) {
            mSignalledOutputEos = true;
            ALOGV("signalled EOS");
        }
        return APEXCODEC_STATUS_OK;
    } else {
        return APEXCODEC_STATUS_OMITTED;
    }
}

}  // namespace android::apexcodecs
