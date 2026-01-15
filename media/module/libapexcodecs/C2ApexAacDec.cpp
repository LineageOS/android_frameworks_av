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
#define LOG_TAG "C2ApexAacDec"
#include <log/log.h>

#include <inttypes.h>
#include <math.h>
#include <numeric>
#include <sys/mman.h>

#include <cutils/properties.h>
#include <media/stagefright/foundation/AUtils.h>
#include <media/stagefright/foundation/MediaDefs.h>
#include <media/stagefright/foundation/hexdump.h>
#include <media/stagefright/MediaErrors.h>
#include <utils/misc.h>

#include <C2PlatformSupport.h>
#include <SimpleC2Interface.h>
#include <util/C2InterfaceHelper.h>

#include "C2ApexAacDec.h"
#include "private/apex/ApexCodecsImpl.h"

namespace android {

using ::android::apexcodecs::ApexComponentIntf;
using ::android::apexcodecs::ApexConfigurableImpl;
using ::android::apexcodecs::ApexConfigurableIntf;

namespace {
    constexpr float DRC_DEFAULT_MOBILE_REF_LEVEL = -16.0;
    constexpr float DRC_DEFAULT_MOBILE_DRC_CUT = 1.0;
    constexpr float DRC_DEFAULT_MOBILE_DRC_BOOST = 1.0;
    constexpr C2Config::drc_compression_mode_t DRC_DEFAULT_MOBILE_DRC_HEAVY
            = C2Config::DRC_COMPRESSION_HEAVY;
    constexpr int32_t DRC_DEFAULT_MOBILE_DRC_EFFECT = 3;
    constexpr int32_t DRC_DEFAULT_MOBILE_DRC_ALBUM = 0;
    constexpr float DRC_DEFAULT_MOBILE_OUTPUT_LOUDNESS = 0.25;
    constexpr float DRC_DEFAULT_MOBILE_ENC_LEVEL = 0.25;
    constexpr int32_t MAX_CHANNEL_COUNT = 8;
    constexpr size_t MAX_SAMPLES_PER_FRAME = 4096;
    constexpr size_t TMP_BUFFER_COUNT = MAX_SAMPLES_PER_FRAME * MAX_CHANNEL_COUNT;
    constexpr char PROP_DRC_OVERRIDE_REF_LEVEL[] = "aac_drc_reference_level";
    constexpr char PROP_DRC_OVERRIDE_CUT[] = "aac_drc_cut";
    constexpr char PROP_DRC_OVERRIDE_BOOST[] = "aac_drc_boost";
    constexpr char PROP_DRC_OVERRIDE_HEAVY[] = "aac_drc_heavy";
    constexpr char PROP_DRC_OVERRIDE_ENC_LEVEL[] = "aac_drc_enc_target_level";
    constexpr char PROP_DRC_OVERRIDE_EFFECT[] = "ro.aac_drc_effect_type";

    constexpr size_t kDefaultOutputPortDelay = 2;
    constexpr size_t kMaxOutputPortDelay = 16;
    constexpr size_t kNumDelayBlocksMax = 8;

    // definitions based on android.media.AudioFormat.CHANNEL_OUT_*
    constexpr uint32_t CHANNEL_OUT_FL  = 0x4;
    constexpr uint32_t CHANNEL_OUT_FR  = 0x8;
    constexpr uint32_t CHANNEL_OUT_FC  = 0x10;
    constexpr uint32_t CHANNEL_OUT_LFE = 0x20;
    constexpr uint32_t CHANNEL_OUT_BL  = 0x40;
    constexpr uint32_t CHANNEL_OUT_BR  = 0x80;
    constexpr uint32_t CHANNEL_OUT_SL  = 0x800;
    constexpr uint32_t CHANNEL_OUT_SR  = 0x1000;
}

class C2ApexAacDec::IntfImpl : public SimpleInterface<void>::BaseParams {
public:
    explicit IntfImpl(const std::shared_ptr<C2ReflectorHelper> &helper)
        : SimpleInterface<void>::BaseParams(
                helper,
                COMPONENT_NAME,
                C2Component::KIND_DECODER,
                C2Component::DOMAIN_AUDIO,
                MEDIA_MIMETYPE_AUDIO_AAC) {
        ALOGV("IntfImpl created");
        noPrivateBuffers();
        noInputReferences();
        noOutputReferences();
        noInputLatency();
        noTimeStretch();

        addParameter(
                DefineParam(mAttrib, C2_PARAMKEY_COMPONENT_ATTRIBUTES)
                .withConstValue(new C2ComponentAttributesSetting(C2Component::ATTRIB_IS_TEMPORAL))
                .build());
        addParameter(
                DefineParam(mActualOutputDelay, C2_PARAMKEY_OUTPUT_DELAY)
                .withDefault(new C2PortActualDelayTuning::output(kDefaultOutputPortDelay))
                .withFields({C2F(mActualOutputDelay, value).inRange(0, kMaxOutputPortDelay)})
                .withSetter(Setter<decltype(*mActualOutputDelay)>::StrictValueWithNoDeps)
                .build());
        addParameter(
                DefineParam(mSampleRate, C2_PARAMKEY_SAMPLE_RATE)
                .withDefault(new C2StreamSampleRateInfo::output(0u, 44100))
                .withFields({C2F(mSampleRate, value).oneOf({
                    7350, 8000, 11025, 12000, 16000, 22050, 24000, 32000,
                    44100, 48000, 64000, 88200, 96000
                })})
                .withSetter(Setter<decltype(*mSampleRate)>::NonStrictValueWithNoDeps)
                .build());

        addParameter(
                DefineParam(mChannelCount, C2_PARAMKEY_CHANNEL_COUNT)
                .withDefault(new C2StreamChannelCountInfo::output(0u, 1))
                .withFields({C2F(mChannelCount, value).inRange(1, MAX_CHANNEL_COUNT)})
                .withSetter(Setter<decltype(*mChannelCount)>::StrictValueWithNoDeps)
                .build());
        addParameter(
                DefineParam(mMaxChannelCount, C2_PARAMKEY_MAX_CHANNEL_COUNT)
                .withDefault(new C2StreamMaxChannelCountInfo::input(0u, MAX_CHANNEL_COUNT))
                .withFields({C2F(mMaxChannelCount, value).inRange(1, MAX_CHANNEL_COUNT)})
                .withSetter(Setter<decltype(*mMaxChannelCount)>::StrictValueWithNoDeps)
                .build());

        addParameter(
                DefineParam(mBitrate, C2_PARAMKEY_BITRATE)
                .withDefault(new C2StreamBitrateInfo::input(0u, 64000))
                .withFields({C2F(mBitrate, value).inRange(8000, 960000)})
                .withSetter(Setter<decltype(*mBitrate)>::NonStrictValueWithNoDeps)
                .build());
        addParameter(
                DefineParam(mPcmEncodingInfo, C2_PARAMKEY_PCM_ENCODING)
                .withDefault(new C2StreamPcmEncodingInfo::output(0u, C2Config::PCM_FLOAT))
                .withFields({C2F(mPcmEncodingInfo, value).oneOf({
                     C2Config::PCM_FLOAT
                })})
                .withSetter((Setter<decltype(*mPcmEncodingInfo)>::StrictValueWithNoDeps))
                .build());
        addParameter(
                DefineParam(mAacFormat, C2_PARAMKEY_AAC_PACKAGING)
                .withDefault(new C2StreamAacFormatInfo::input(0u, C2Config::AAC_PACKAGING_RAW))
                .withFields({C2F(mAacFormat, value).oneOf({
                    C2Config::AAC_PACKAGING_RAW, C2Config::AAC_PACKAGING_ADTS
                })})
                .withSetter(Setter<decltype(*mAacFormat)>::StrictValueWithNoDeps)
                .build());
        addParameter(
                DefineParam(mProfileLevel, C2_PARAMKEY_PROFILE_LEVEL)
                .withDefault(new C2StreamProfileLevelInfo::input(0u,
                        C2Config::PROFILE_AAC_LC, C2Config::LEVEL_UNUSED))
                .withFields({
                    C2F(mProfileLevel, profile).oneOf({
                            C2Config::PROFILE_AAC_LC,
                            C2Config::PROFILE_AAC_HE,
                            C2Config::PROFILE_AAC_HE_PS,
                            C2Config::PROFILE_AAC_LD,
                            C2Config::PROFILE_AAC_ELD,
                            C2Config::PROFILE_AAC_ER_SCALABLE,
                            C2Config::PROFILE_AAC_XHE}),
                    C2F(mProfileLevel, level).equalTo(C2Config::LEVEL_UNUSED)
                })
                .withSetter(ProfileLevelSetter)
                .build());
        addParameter(
                DefineParam(mInputMaxBufSize, C2_PARAMKEY_INPUT_MAX_BUFFER_SIZE)
                .withDefault(new C2StreamMaxBufferSizeInfo::input(
                        0u, getMaxBytesPerFrame(1 /* channel count */)))
                .withFields({
                    C2F(mInputMaxBufSize, value).any()
                })
                .calculatedAs(MaxInputSizeSetter, mAacFormat, mChannelCount)
                .build());
        addParameter(
                DefineParam(mDrcCompressMode, C2_PARAMKEY_DRC_COMPRESSION_MODE)
                .withDefault(new C2StreamDrcCompressionModeTuning::input(
                        0u, C2Config::DRC_COMPRESSION_HEAVY))
                .withFields({
                    C2F(mDrcCompressMode, value).oneOf({
                            C2Config::DRC_COMPRESSION_ODM_DEFAULT,
                            C2Config::DRC_COMPRESSION_NONE,
                            C2Config::DRC_COMPRESSION_LIGHT,
                            C2Config::DRC_COMPRESSION_HEAVY})
                })
                .withSetter(Setter<decltype(*mDrcCompressMode)>::StrictValueWithNoDeps)
                .build());
        addParameter(
                DefineParam(mDrcTargetRefLevel, C2_PARAMKEY_DRC_TARGET_REFERENCE_LEVEL)
                .withDefault(new C2StreamDrcTargetReferenceLevelTuning::input(
                        0u, DRC_DEFAULT_MOBILE_REF_LEVEL))
                .withFields({C2F(mDrcTargetRefLevel, value).inRange(-31.75, 0.25)})
                .withSetter(Setter<decltype(*mDrcTargetRefLevel)>::StrictValueWithNoDeps)
                .build());
        addParameter(
                DefineParam(mDrcEncTargetLevel, C2_PARAMKEY_DRC_ENCODED_TARGET_LEVEL)
                .withDefault(new C2StreamDrcEncodedTargetLevelTuning::input(
                        0u, DRC_DEFAULT_MOBILE_ENC_LEVEL))
                .withFields({C2F(mDrcEncTargetLevel, value).inRange(-31.75, 0.25)})
                .withSetter(Setter<decltype(*mDrcEncTargetLevel)>::StrictValueWithNoDeps)
                .build());
        addParameter(
                DefineParam(mDrcBoostFactor, C2_PARAMKEY_DRC_BOOST_FACTOR)
                .withDefault(new C2StreamDrcBoostFactorTuning::input(
                        0u, DRC_DEFAULT_MOBILE_DRC_BOOST))
                .withFields({C2F(mDrcBoostFactor, value).inRange(0, 1.)})
                .withSetter(Setter<decltype(*mDrcBoostFactor)>::StrictValueWithNoDeps)
                .build());
        addParameter(
                DefineParam(mDrcAttenuationFactor, C2_PARAMKEY_DRC_ATTENUATION_FACTOR)
                .withDefault(new C2StreamDrcAttenuationFactorTuning::input(
                        0u, DRC_DEFAULT_MOBILE_DRC_CUT))
                .withFields({C2F(mDrcAttenuationFactor, value).inRange(0, 1.)})
                .withSetter(Setter<decltype(*mDrcAttenuationFactor)>::StrictValueWithNoDeps)
                .build());
        addParameter(
                DefineParam(mDrcEffectType, C2_PARAMKEY_DRC_EFFECT_TYPE)
                .withDefault(new C2StreamDrcEffectTypeTuning::input(
                        0u, C2Config::DRC_EFFECT_LIMITED_PLAYBACK_RANGE))
                .withFields({
                    C2F(mDrcEffectType, value).oneOf({
                            C2Config::DRC_EFFECT_ODM_DEFAULT,
                            C2Config::DRC_EFFECT_OFF,
                            C2Config::DRC_EFFECT_NONE,
                            C2Config::DRC_EFFECT_LATE_NIGHT,
                            C2Config::DRC_EFFECT_NOISY_ENVIRONMENT,
                            C2Config::DRC_EFFECT_LIMITED_PLAYBACK_RANGE,
                            C2Config::DRC_EFFECT_LOW_PLAYBACK_LEVEL,
                            C2Config::DRC_EFFECT_DIALOG_ENHANCEMENT,
                            C2Config::DRC_EFFECT_GENERAL_COMPRESSION})
                })
                .withSetter(Setter<decltype(*mDrcEffectType)>::StrictValueWithNoDeps)
                .build());
        addParameter(
                DefineParam(mDrcAlbumMode, C2_PARAMKEY_DRC_ALBUM_MODE)
                .withDefault(new C2StreamDrcAlbumModeTuning::input(
                        0u, C2Config::DRC_ALBUM_MODE_OFF))
                .withFields({
                    C2F(mDrcAlbumMode, value).oneOf({
                            C2Config::DRC_ALBUM_MODE_OFF,
                            C2Config::DRC_ALBUM_MODE_ON})
                })
                .withSetter(Setter<decltype(*mDrcAlbumMode)>::StrictValueWithNoDeps)
                .build());
        addParameter(
                DefineParam(mDrcOutputLoudness, C2_PARAMKEY_DRC_OUTPUT_LOUDNESS)
                .withDefault(new C2StreamDrcOutputLoudnessTuning::output(
                        0u, DRC_DEFAULT_MOBILE_OUTPUT_LOUDNESS))
                .withFields({C2F(mDrcOutputLoudness, value).inRange(-57.75, 0.25)})
                .withSetter(Setter<decltype(*mDrcOutputLoudness)>::StrictValueWithNoDeps)
                .build());
        addParameter(DefineParam(mChannelMask, C2_PARAMKEY_CHANNEL_MASK)
                .withDefault(new C2StreamChannelMaskInfo::output(0u, 0))
                .withFields({C2F(mChannelMask, value).inRange(0, 4294967292)})
                .withSetter(Setter<decltype(*mChannelMask)>::StrictValueWithNoDeps)
                .build());
    }

    bool isAdts() const { return mAacFormat->value == C2Config::AAC_PACKAGING_ADTS; }
    static C2R ProfileLevelSetter(bool mayBlock, C2P<C2StreamProfileLevelInfo::input> &me) {
        (void)mayBlock;
        ALOGV("ProfileLevelSetter: profile=%u", me.v.profile);
        if (me.v.level != C2Config::LEVEL_UNUSED) {
            ALOGV("ProfileLevelSetter: level is not LEVEL_UNUSED, correcting it.");
            me.set().level = C2Config::LEVEL_UNUSED;
        }
        return C2R::Ok();
    }

    static constexpr size_t getMaxBytesPerFrame(int channelCount) {
        // The maximum AAC frame size is 6144 bits per channel
        constexpr size_t kMaxFrameLengthPerChannel = 6144 / 8;
        // In SBR and PS modes, additional side data is signalled per frame
        constexpr size_t kAddlSideDataPerFrame = 384;
        size_t totalSize = kMaxFrameLengthPerChannel * channelCount + kAddlSideDataPerFrame;
        return std::max(totalSize, static_cast<size_t>(8192));
    }

    static C2R MaxInputSizeSetter(bool mayBlock, C2P<C2StreamMaxBufferSizeInfo::input>& me,
                                  const C2P<C2StreamAacFormatInfo::input>& aacFormat,
                                  const C2P<C2StreamChannelCountInfo::output>& channelCount) {
        (void)mayBlock;
        ALOGV("MaxInputSizeSetter: aacFormat=%d, channelCount=%u",
              static_cast<int>(aacFormat.v.value), channelCount.v.value);
        // In adts format, 13 bits are reserved for storing the length of an adts frame.
        // adts frame : adts header + aac frame(s) + crc bytes
        // so the maximum input size in adts mode is 2^13 bytes
        if (aacFormat.v.value == C2Config::AAC_PACKAGING_ADTS) {
            me.set().value = (1 << 13);
        } else {
            me.set().value = getMaxBytesPerFrame(channelCount.v.value);
        }
        ALOGV("MaxInputSizeSetter: max input size=%u", me.v.value);
        return C2R::Ok();
    }

    int32_t getDrcCompressMode() const {
        return (mDrcCompressMode->value == C2Config::DRC_COMPRESSION_HEAVY) ? 1 : 0;
    }

    int32_t getDrcTargetRefLevel() const {
        return (mDrcTargetRefLevel->value <= 0 ? -mDrcTargetRefLevel->value * 4. + 0.5 : -1);
    }

    int32_t getDrcEncTargetLevel() const {
        return (mDrcEncTargetLevel->value <= 0 ? -mDrcEncTargetLevel->value * 4. + 0.5 : -1);
    }

    int32_t getDrcBoostFactor() const {
        return mDrcBoostFactor->value * 127. + 0.5;
    }

    int32_t getDrcAttenuationFactor() const {
        return mDrcAttenuationFactor->value * 127. + 0.5;
    }

    int32_t getDrcEffectType() const {
        return mDrcEffectType->value;
    }

    int32_t getDrcAlbumMode() const {
        return mDrcAlbumMode->value;
    }

    u_int32_t getMaxChannelCount() const {
        return mMaxChannelCount->value;
    }

    int32_t getDrcOutputLoudness() const {
        return (mDrcOutputLoudness->value <= 0 ? -mDrcOutputLoudness->value * 4. + 0.5 : -1);
    }

    int32_t getPcmEncodingInfo() const {
        return mPcmEncodingInfo->value;
    }

private:
    // The media type of the output port.
    std::shared_ptr<C2PortMediaTypeSetting::output> mOutputMediaType;
    // The component's attributes, indicating it is a temporal codec.
    std::shared_ptr<C2ComponentAttributesSetting> mAttrib;
    // The actual delay of the output port.
    std::shared_ptr<C2PortActualDelayTuning::output> mActualOutputDelay;
    // The sample rate of the output audio stream.
    std::shared_ptr<C2StreamSampleRateInfo::output> mSampleRate;
    // The number of channels in the output audio stream.
    std::shared_ptr<C2StreamChannelCountInfo::output> mChannelCount;
    // The bitrate of the input audio stream.
    std::shared_ptr<C2StreamBitrateInfo::input> mBitrate;
    // The maximum size of an input buffer.
    std::shared_ptr<C2StreamMaxBufferSizeInfo::input> mInputMaxBufSize;
    // The format of the AAC stream (e.g., RAW or ADTS).
    std::shared_ptr<C2StreamAacFormatInfo::input> mAacFormat;
    // The profile and level of the AAC stream (e.g., LC, HE).
    std::shared_ptr<C2StreamProfileLevelInfo::input> mProfileLevel;
    // The Dynamic Range Control (DRC) compression mode. For MPEG-D DRC.
    std::shared_ptr<C2StreamDrcCompressionModeTuning::input> mDrcCompressMode;
    // The DRC target reference level. For MPEG-D DRC.
    std::shared_ptr<C2StreamDrcTargetReferenceLevelTuning::input> mDrcTargetRefLevel;
    // The DRC encoded target level. For MPEG-D DRC.
    std::shared_ptr<C2StreamDrcEncodedTargetLevelTuning::input> mDrcEncTargetLevel;
    // The DRC boost factor. For MPEG-D DRC.
    std::shared_ptr<C2StreamDrcBoostFactorTuning::input> mDrcBoostFactor;
    // The DRC attenuation factor. For MPEG-D DRC.
    std::shared_ptr<C2StreamDrcAttenuationFactorTuning::input> mDrcAttenuationFactor;
    // The DRC effect type. For MPEG-D DRC.
    std::shared_ptr<C2StreamDrcEffectTypeTuning::input> mDrcEffectType;
    // The DRC album mode. For MPEG-D DRC.
    std::shared_ptr<C2StreamDrcAlbumModeTuning::input> mDrcAlbumMode;
    // The maximum number of channels the decoder can handle.
    std::shared_ptr<C2StreamMaxChannelCountInfo::input> mMaxChannelCount;
    // The output loudness after DRC is applied. For MPEG-D DRC.
    std::shared_ptr<C2StreamDrcOutputLoudnessTuning::output> mDrcOutputLoudness;
    // The channel mask of the output audio.
    std::shared_ptr<C2StreamChannelMaskInfo::output> mChannelMask;
    // The encoding format of the output PCM audio (e.g., float).
    std::shared_ptr<C2StreamPcmEncodingInfo::output> mPcmEncodingInfo;
};

C2ApexAacDec::C2ApexAacDec(const std::shared_ptr<IntfImpl> &intfImpl)
    : mConfigurable(std::make_unique<ApexConfigurableImpl>(
              std::make_shared<SimpleC2Interface<IntfImpl>>(COMPONENT_NAME, 0, intfImpl))),
      mIntf(intfImpl),
      mAACDecoder(nullptr),
      mIsFirst(true),
      mInputBufferCount(0),
      mOutputBufferCount(0),
      mSignalledError(false),
      mOutputPortDelay(kDefaultOutputPortDelay),
      mEndOfInput(false),
      mEndOfOutput(false),
      mOutputDelayCompensated(0),
      mOutputDelayRingBufferSize(0),
      mOutputDelayRingBuffer(nullptr),
      mOutputDelayRingBufferWritePos(0),
      mOutputDelayRingBufferReadPos(0),
      mOutputDelayRingBufferFilled(0) {
    ALOGV("C2ApexAacDec created");
}

C2ApexAacDec::~C2ApexAacDec() {
    ALOGV("~C2ApexAacDec destroyed");
    if (mAACDecoder) {
        aacDecoder_Close(mAACDecoder);
        mAACDecoder = nullptr;
    }
}

// static
std::unique_ptr<ApexComponentIntf> C2ApexAacDec::Create(
        const std::shared_ptr<C2ReflectorHelper> &helper) {
    ALOGV("Create");
    return std::make_unique<C2ApexAacDec>(std::make_shared<IntfImpl>(helper));
}

// static
std::shared_ptr<C2Component::Traits> C2ApexAacDec::MakeTraits() {
#ifdef ENABLE_APEX_CODECS
    ALOGV("MakeTraits");
    std::shared_ptr<C2Component::Traits> traits = std::make_shared<C2Component::Traits>();
    traits->name        = C2ApexAacDec::COMPONENT_NAME;
    traits->domain      = C2Component::DOMAIN_AUDIO;
    traits->kind        = C2Component::KIND_DECODER;
    traits->rank        = 16;
    traits->mediaType   = MEDIA_MIMETYPE_AUDIO_AAC;
    traits->owner       = "__ApexCodecs__";
    return traits;
#else
    return nullptr;
#endif
}

// static
void *C2ApexAacDec::Map(void *addr, size_t size, int prot, int flags, int fd, off_t offset) {
    return ::mmap(addr, size, prot, flags, fd, offset);
}

// static
int C2ApexAacDec::Unmap(void *addr, size_t size) {
    return ::munmap(addr, size);
}

ApexCodec_Status C2ApexAacDec::start() {
    ALOGV("start");
    return initDecoder();
}

ApexCodec_Status C2ApexAacDec::flush() {
    ALOGV("flush");
    mOutputDelayRingBufferReadPos = mOutputDelayRingBufferWritePos;
    mOutputDelayRingBufferFilled = 0;
    mPendingFrameInfos.clear();
    mRingBufferFrameInfos.clear();
    mEndOfInput = false;
    mEndOfOutput = false;
    mSignalledError = false;
    return APEXCODEC_STATUS_OK;
}

ApexCodec_Status C2ApexAacDec::reset() {
    ALOGV("reset");
    if (mAACDecoder) {
        aacDecoder_Close(mAACDecoder);
        mAACDecoder = nullptr;
    }
    mPendingFrameInfos.clear();
    mRingBufferFrameInfos.clear();
    mSignalledError = false;
    mEndOfInput = false;
    mEndOfOutput = false;
    return initDecoder();
}

std::unique_ptr<ApexConfigurableIntf> C2ApexAacDec::getConfigurable() {
    ALOGV("getConfigurable");
    return std::move(mConfigurable);
}

ApexCodec_Status C2ApexAacDec::process(
        const ApexCodec_Buffer* input,
        ApexCodec_Buffer* output,
        size_t* consumed,
        size_t* produced) {
    if (mSignalledError) {
        ALOGE("process called in error state");
        return APEXCODEC_STATUS_CORRUPTED;
    }
    *consumed = 0;
    *produced = 0;
    ALOGV("process: input=%p, output=%p", input, output);
    ApexCodec_BufferFlags inFlags = (ApexCodec_BufferFlags)0;
    uint64_t frameIndex = 0, timestamp = 0;
    if (input) {
        input->getBufferInfo(&inFlags, &frameIndex, &timestamp);
        ALOGV("process input: flags=%x, frameIndex=%" PRIu64 ","
                "timestamp=%" PRIu64, inFlags, frameIndex, timestamp);
    }

    int numSamples = outputDelayRingBufferSamplesAvailable();
    ALOGV("numSamples available: %d", numSamples);
    if (numSamples > 0 && output) {
        ApexCodec_Status status = outputFromRingBuffer(output, produced, frameIndex, timestamp);
        return status;
    }

    ApexCodec_LinearBuffer inBuffer;
    // Decode data from the input buffer and place it in the ring buffer.
    if (!mEndOfInput && input &&
            input->getLinearBuffer(&inBuffer) == APEXCODEC_STATUS_OK &&
            inBuffer.size > 0) {
        if (input->getType() != APEXCODEC_BUFFER_TYPE_LINEAR) {
            ALOGE("input buffer type is not linear");
            return APEXCODEC_STATUS_BAD_VALUE;
        }
        ALOGV("input buffer size: %zu", inBuffer.size);
        bool codecConfig = (inFlags & APEXCODEC_FLAG_CODEC_CONFIG) != 0;
        ALOGV("codecConfig: %d", codecConfig);
        if (codecConfig) {
            ALOGV("processing codec config buffer (size=%zu)", inBuffer.size);
            AAC_DECODER_ERROR decoderErr =
                aacDecoder_ConfigRaw(mAACDecoder,
                                     const_cast<uint8_t *>(inBuffer.data),
                                     static_cast<uint32_t>(inBuffer.size));
            if (decoderErr != AAC_DEC_OK) {
                ALOGE("aacDecoder_ConfigRaw decoderErr = 0x%4.4x", decoderErr);
                mSignalledError = true;
                return APEXCODEC_STATUS_CORRUPTED;
            }
            *consumed = inBuffer.size;
        } else {
            mPendingFrameInfos.push_back({frameIndex, timestamp, 0});
            size_t offset = 0;
            size_t size = inBuffer.size;
            ALOGV("process loop: offset=%zu, size=%zu", offset, size);
            while (size > 0) {
                uint8_t* inPtr = const_cast<uint8_t *>(inBuffer.data + offset);
                uint32_t inBufferLength = std::min(
                       size, static_cast<size_t>(std::numeric_limits<uint32_t>::max()));
                uint32_t bytesValid = inBufferLength;
                ALOGV("inPtr=%p, inBufferLength=%u, bytesValid=%u",
                        inPtr, inBufferLength, bytesValid);
                if (mIntf->isAdts()) {
                    ALOGV("ADTS input");
                    size_t adtsHeaderSize = 0;
                    // skip 30 bits, aac_frame_length follows.
                    // ssssssss ssssiiip ppffffPc ccohCCll llllllll lll?????

                    const uint8_t *adtsHeader = inBuffer.data + offset;
                    if (size < 7) {
                        ALOGE("ADTS header too small: %zu", size);
                        mSignalledError = true;
                        return APEXCODEC_STATUS_CORRUPTED;
                    }
                    bool protectionAbsent = (adtsHeader[1] & 1);
                    unsigned aac_frame_length =
                        ((adtsHeader[3] & 3) << 11) | (adtsHeader[4] << 3) | (adtsHeader[5] >> 5);
                    ALOGV("protectionAbsent=%d, aac_frame_length=%u",
                            protectionAbsent, aac_frame_length);
                    if (size < aac_frame_length) {
                        ALOGE("Incomplete ADTS frame: %zu < %u", size, aac_frame_length);
                        mSignalledError = true;
                        return APEXCODEC_STATUS_CORRUPTED;
                    }
                    // Add two bytes for the CRC (Cyclic Redundancy Check) if protection is absent.
                    adtsHeaderSize = (protectionAbsent ? 7 : 9);
                    ALOGV("adtsHeaderSize: %zu", adtsHeaderSize);
                    if (aac_frame_length < adtsHeaderSize) {
                        ALOGE("ADTS frame length is smaller than header size");
                        mSignalledError = true;
                        return APEXCODEC_STATUS_CORRUPTED;
                    }
                    inPtr = const_cast<uint8_t *>(adtsHeader + adtsHeaderSize);
                    inBufferLength = aac_frame_length - adtsHeaderSize;
                    offset += adtsHeaderSize;
                    size -= adtsHeaderSize;
                    ALOGV("inPtr=%p, inBufferLength=%u, offset=%zu, size=%zu",
                            inPtr, inBufferLength, offset, size);
                }
                uint32_t prevSampleRate = mOutputInfo.sampling_rate;
                uint8_t prevNumChannels = mOutputInfo.num_channels;
                int16_t prevOutLoudness = mOutputInfo.output_loudness;
                ALOGV("prevSampleRate=%u, prevNumChannels=%u, prevOutLoudness=%d",
                        prevSampleRate, prevNumChannels, prevOutLoudness);
                ALOGV("Calling aacDecoder_Fill");
                aacDecoder_Fill(mAACDecoder, inPtr, inBufferLength, &bytesValid);
                uint32_t inBufferUsedLength = inBufferLength - bytesValid;
                size -= inBufferUsedLength;
                offset += inBufferUsedLength;
                ALOGV("inBufferUsedLength=%u, size=%zu, offset=%zu",
                        inBufferUsedLength, size, offset);
                AAC_DECODER_ERROR decoderErr;
                bool didDecode = false;
                do {
                    if (outputDelayRingBufferSpaceLeft() <
                            (mOutputInfo.frame_size * mOutputInfo.num_channels)) {
                        ALOGV("skipping decode: not enough space left in ringbuffer");
                        size = 0;
                        break;
                    }
                    float tmpOutBuffer[TMP_BUFFER_COUNT];
                    StreamInfo stream_info = CAacDecoderStreamInfo_default();
                    OutputInfo output_info = CAacDecoderOutputInfo_default();
                    ALOGV("Calling aacDecoder_Decode");
                    decoderErr = aacDecoder_Decode(mAACDecoder, tmpOutBuffer,
                                                   TMP_BUFFER_COUNT,
                                                   &output_info, &stream_info, NULL);
                    ALOGV("aacDecoder_Decode returned 0x%4.4x", decoderErr);
                    ALOGV("stream_info: numElements=%u, pcmChOrder=%d, aacSampleRate=%u, "
                            "aot=%d, channelConfig=%d, aacSamplesPerFrame=%u, aacNumChannels=%u, "
                            "extAot=%d, extSamplingRate=%u, flags=%u, num_consumed_bytes=%u",
                            stream_info.numElements, stream_info.pcmChOrder,
                            stream_info.aacSampleRate, stream_info.aot,
                            stream_info.channelConfig, stream_info.aacSamplesPerFrame,
                            stream_info.aacNumChannels, stream_info.extAot,
                            stream_info.extSamplingRate, stream_info.flags,
                            stream_info.num_consumed_bytes);
                    ALOGV("output_info: sampling_rate=%u, frame_size=%u, num_channels=%u, "
                          "output_delay=%u, output_loudness=%d",
                          output_info.sampling_rate, output_info.frame_size,
                          output_info.num_channels, output_info.output_delay,
                          output_info.output_loudness);
                    if (decoderErr == AAC_DEC_NOT_ENOUGH_BITS) break;
                    if (IS_OUTPUT_VALID(decoderErr)) mOutputInfo = output_info;
                    size_t generatedSamples =
                            mOutputInfo.frame_size * mOutputInfo.num_channels;
                    if (generatedSamples > std::size(tmpOutBuffer)) {
                        ALOGE("too many samples output: %zu", generatedSamples);
                        mSignalledError = true;
                        return APEXCODEC_STATUS_CORRUPTED;
                    }
                    if (decoderErr == AAC_DEC_OK) {
                        didDecode = true;
                        if (!outputDelayRingBufferPutSamples(tmpOutBuffer, generatedSamples)) {
                            ALOGE("outputDelayRingBufferPutSamples failed");
                            mSignalledError = true;
                            return APEXCODEC_STATUS_CORRUPTED;
                        }
                        if (!mPendingFrameInfos.empty()) {
                            FrameInfo info = mPendingFrameInfos.front();
                            mPendingFrameInfos.pop_front();
                            info.numSamples = generatedSamples;
                            mRingBufferFrameInfos.push_back(info);
                        }
                    } else {
                        ALOGW("aacDecoder_Decode returned error 0x%4.4x, outputting silence",
                                decoderErr);
                        size_t numOutBytes = generatedSamples * sizeof(float);
                        ALOGV("numOutBytes: %zu", numOutBytes);
                        memset(tmpOutBuffer, 0, numOutBytes);
                        if (!outputDelayRingBufferPutSamples(tmpOutBuffer, generatedSamples)) {
                            ALOGE("outputDelayRingBufferPutSamples failed for silence");
                            mSignalledError = true;
                            return APEXCODEC_STATUS_CORRUPTED;
                        }
                        if (!mPendingFrameInfos.empty()) {
                            FrameInfo info = mPendingFrameInfos.front();
                            mPendingFrameInfos.pop_front();
                            info.numSamples = generatedSamples;
                            mRingBufferFrameInfos.push_back(info);
                        }
                        ALOGE("Interrupting the codec and updating params");
                        aacDecoder_Clear(mAACDecoder);
                        *consumed = 0;
                    }
                    std::vector<uint8_t> configUpdate;
                    if (isConfigured() && (mOutputInfo.sampling_rate != prevSampleRate
                            || mOutputInfo.num_channels != prevNumChannels)) {
                        ALOGD("config changed: sampleRate %d->%d, channels %d->%d",
                              prevSampleRate, mOutputInfo.sampling_rate, prevNumChannels,
                              mOutputInfo.num_channels);
                        C2StreamSampleRateInfo::output sampleRateInfo(
                                0u, mOutputInfo.sampling_rate);
                        C2StreamChannelCountInfo::output channelCountInfo(
                                0u, mOutputInfo.num_channels);
                        C2StreamChannelMaskInfo::output channelMaskInfo(
                                0u, maskFromCount(mOutputInfo.num_channels));
                        AppendParamsToVector(&configUpdate, &sampleRateInfo,
                                             &channelCountInfo, &channelMaskInfo);
                    }
                    if (mOutputInfo.output_loudness != prevOutLoudness) {
                        ALOGD("loudness changed: %d->%d", prevOutLoudness,
                                mOutputInfo.output_loudness);
                        C2StreamDrcOutputLoudnessTuning::output drcOutLoudness(0u,
                                (float)(mOutputInfo.output_loudness * -0.25));
                        AppendParamsToVector(&configUpdate, &drcOutLoudness);
                    }
                    if (!configUpdate.empty()) {
                        ALOGD("sending config update");
                        output->setOwnedConfigUpdates(std::move(configUpdate));
                    }
                } while (decoderErr == AAC_DEC_OK);

                if (size > 0 && inBufferUsedLength == 0 &&
                        decoderErr == AAC_DEC_NOT_ENOUGH_BITS && !didDecode) {
                    ALOGW("aacDecoder_Fill consumed 0 bytes and decoder needs more bits, stopping");
                    break;
                }
            }
            *consumed = offset;
        }
    }
    if (inFlags & APEXCODEC_FLAG_END_OF_STREAM) {
        ALOGD("EOS input");
        mEndOfInput = true;
    }
    if (mEndOfInput) {
        drainDecoder();
    }
    numSamples = outputDelayRingBufferSamplesAvailable();
    ALOGV("numSamples available: %d", numSamples);
    // Add data from the ring buffer to the output buffer.
    if (numSamples > 0 && output) {
        ApexCodec_Status status = outputFromRingBuffer(output, produced, frameIndex, timestamp);
        if (status != APEXCODEC_STATUS_OK) {
            return status;
        }
    }
    // If the app using the codec has signaled APEXCODEC_FLAG_END_OF_STREAM and the output buffer
    // is empty, signal that the output buffer is empty.
    if (mEndOfInput && outputDelayRingBufferSamplesAvailable() == 0) {
        if (!mEndOfOutput) {
            ALOGD("EOS output");
            if (output) {
                ApexCodec_BufferFlags outFlags = (ApexCodec_BufferFlags)0;
                if (*produced > 0) {
                    uint64_t outFrameIndex, outTimestamp;
                    output->getBufferInfo(&outFlags, &outFrameIndex, &outTimestamp);
                    ALOGD("outFrameIndex=%lu, outTimestamp=%lu", outFrameIndex, outTimestamp);
                    outFlags = (ApexCodec_BufferFlags)(outFlags | APEXCODEC_FLAG_END_OF_STREAM);
                    output->setBufferInfo(outFlags, outFrameIndex, outTimestamp);
                } else {
                    output->setBufferInfo(APEXCODEC_FLAG_END_OF_STREAM, frameIndex, timestamp);
                }
                ALOGD("outFlags: %x", outFlags);
            }
            mEndOfOutput = true;
        }
    }
    ALOGV("consumed: %zu", *consumed);
    return APEXCODEC_STATUS_OK;
}

ApexCodec_Status C2ApexAacDec::outputFromRingBuffer(
        ApexCodec_Buffer* output,
        size_t* produced,
        uint64_t frameIndex,
        uint64_t timestamp) {
    int numSamples = outputDelayRingBufferSamplesAvailable();
    if (numSamples > 0 && output) {
        ApexCodec_LinearBuffer outLinearBuffer;
        if (output->getLinearBuffer(&outLinearBuffer) != APEXCODEC_STATUS_OK) {
            ALOGE("output->getLinearBuffer failed");
            return APEXCODEC_STATUS_BAD_VALUE;
        }
        int samplesToOutput = numSamples;
        if ((size_t)samplesToOutput * sizeof(float) > outLinearBuffer.size) {
            samplesToOutput = outLinearBuffer.size / sizeof(float);
        }
        if (!mRingBufferFrameInfos.empty()) {
            if (samplesToOutput > mRingBufferFrameInfos.front().numSamples) {
                samplesToOutput = mRingBufferFrameInfos.front().numSamples;
            }
        }
        ALOGV("producing %d samples", samplesToOutput);
        if (outputDelayRingBufferGetSamples(
                reinterpret_cast<float*>(outLinearBuffer.data), samplesToOutput)
                != samplesToOutput) {
            ALOGE("outputDelayRingBufferGetSamples failed");
            mSignalledError = true;
            return APEXCODEC_STATUS_CORRUPTED;
        }
        *produced = samplesToOutput * sizeof(float);
        ALOGV("produced: %zu", *produced);
        if (!mRingBufferFrameInfos.empty()) {
            FrameInfo& info = mRingBufferFrameInfos.front();
            info.numSamples -= samplesToOutput;
            if (info.numSamples == 0) {
                mRingBufferFrameInfos.pop_front();
                output->setBufferInfo((ApexCodec_BufferFlags)0, info.frameIndex, info.timestamp);
            } else {
                output->setBufferInfo((ApexCodec_BufferFlags)APEXCODEC_FLAG_INCOMPLETE,
                                      info.frameIndex, info.timestamp);
            }
        } else {
            output->setBufferInfo((ApexCodec_BufferFlags)0, frameIndex, timestamp);
        }
    }
    return APEXCODEC_STATUS_OK;
}

ApexCodec_Status C2ApexAacDec::initDecoder() {
    ALOGV("initDecoder");
    if (mAACDecoder) {
        ALOGV("closing existing decoder");
        aacDecoder_Close(mAACDecoder);
    }
    mAACDecoder = aacDecoder_Open(TT_MP4_ADIF);
    if (!mAACDecoder) {
        ALOGE("aacDecoder_Open failed");
        return APEXCODEC_STATUS_CORRUPTED;
    }
    ALOGV("aacDecoder_Open successful");
    mOutputInfo = CAacDecoderOutputInfo_default();
    mOutputDelayCompensated = 0;
    mOutputDelayRingBufferSize = TMP_BUFFER_COUNT * kNumDelayBlocksMax;
    mOutputDelayRingBuffer.reset(new float[mOutputDelayRingBufferSize]);
    mOutputDelayRingBufferWritePos = 0;
    mOutputDelayRingBufferReadPos = 0;
    mOutputDelayRingBufferFilled = 0;
    updateParams();
    return APEXCODEC_STATUS_OK;
}

void C2ApexAacDec::updateParams() {
    ALOGV("updateParams");
    int32_t targetRefLevel = mIntf->getDrcTargetRefLevel();
    ALOGV("  drc-ref-level: %d", targetRefLevel);
    aacDecoder_SetParam(mAACDecoder, AAC_DRC_REFERENCE_LEVEL, targetRefLevel);
    int32_t attenuationFactor = mIntf->getDrcAttenuationFactor();
    ALOGV("  drc-attenuation-factor: %d", attenuationFactor);
    aacDecoder_SetParam(mAACDecoder, AAC_DRC_ATTENUATION_FACTOR, attenuationFactor);
    int32_t boostFactor = mIntf->getDrcBoostFactor();
    ALOGV("  drc-boost-factor: %d", boostFactor);
    aacDecoder_SetParam(mAACDecoder, AAC_DRC_BOOST_FACTOR, boostFactor);
    int32_t compressMode = mIntf->getDrcCompressMode();
    ALOGV("  drc-compress-mode: %d", compressMode);
    aacDecoder_SetParam(mAACDecoder, AAC_DRC_HEAVY_COMPRESSION, compressMode);
    int32_t encTargetLevel = mIntf->getDrcEncTargetLevel();
    ALOGV("  drc-enc-target-level: %d", encTargetLevel);
    aacDecoder_SetParam(mAACDecoder, AAC_DRC_ENC_TARGET_LEVEL, encTargetLevel);
    int32_t effectType = mIntf->getDrcEffectType();
    ALOGV("  drc-effect-type: %d", effectType);
    aacDecoder_SetParam(mAACDecoder, AAC_UNIDRC_SET_EFFECT, effectType);
    int32_t albumMode = mIntf->getDrcAlbumMode();
    ALOGV("  drc-album-mode: %d", albumMode);
    aacDecoder_SetParam(mAACDecoder, AAC_UNIDRC_ALBUM_MODE, albumMode);
    u_int32_t maxChannelCount = mIntf->getMaxChannelCount();
    ALOGV("  max-channel-count: %u", maxChannelCount);
    aacDecoder_SetParam(mAACDecoder, AAC_PCM_MAX_OUTPUT_CHANNELS, maxChannelCount);
    int32_t defaultPresentationMode = AAC_DRC_PARAMETER_HANDLING_DISABLED;
    ALOGV("  drc-presentation-mode: %d", defaultPresentationMode);
    aacDecoder_SetParam(mAACDecoder, AAC_DRC_DEFAULT_PRESENTATION_MODE, defaultPresentationMode);
}

bool C2ApexAacDec::isConfigured() const {
    bool configured = mOutputInfo.sampling_rate > 0;
    ALOGV("isConfigured: %d (sample_rate=%d)", configured, mOutputInfo.sampling_rate);
    return configured;
}

void C2ApexAacDec::drainDecoder() {
    ALOGV("drainDecoder");
    while (true) {
        float tmpOutBuffer[TMP_BUFFER_COUNT];
        AAC_DECODER_ERROR decoderErr =
            aacDecoder_Drain(mAACDecoder,
                             tmpOutBuffer,
                             TMP_BUFFER_COUNT,
                             &mOutputInfo);
        if (decoderErr != AAC_DEC_OK) {
            ALOGV("aacDecoder_Drain finished with error 0x%4.4x", decoderErr);
            break;
        }
        int32_t tmpOutBufferSamples = mOutputInfo.frame_size * mOutputInfo.num_channels;
        if (tmpOutBufferSamples == 0) {
            ALOGV("aacDecoder_Drain produced 0 samples, stopping");
            break;
        }
        if (tmpOutBufferSamples > std::size(tmpOutBuffer)) {
            mSignalledError = true;
            ALOGE("Drained too many samples: %d", tmpOutBufferSamples);
            tmpOutBufferSamples = std::size(tmpOutBuffer);
        }
        ALOGV("draining %d samples", tmpOutBufferSamples);
        outputDelayRingBufferPutSamples(tmpOutBuffer, tmpOutBufferSamples);
        if (!mPendingFrameInfos.empty()) {
            FrameInfo info = mPendingFrameInfos.front();
            mPendingFrameInfos.pop_front();
            info.numSamples = tmpOutBufferSamples;
            mRingBufferFrameInfos.push_back(info);
        }
    }
}

uint32_t C2ApexAacDec::maskFromCount(uint32_t channelCount) {
    // KEY_CHANNEL_MASK expects masks formatted according to Java android.media.AudioFormat
    // where the two left-most bits are 0 for output channel mask
    switch (channelCount) {
        case 1: // mono is front left
            return (CHANNEL_OUT_FL);
        case 2: // stereo
            return (CHANNEL_OUT_FL | CHANNEL_OUT_FR);
        case 4: // 4.0 = stereo with backs
            return (CHANNEL_OUT_FL | CHANNEL_OUT_FR
                    | CHANNEL_OUT_BL | CHANNEL_OUT_BR);
        case 5: // 5.0
            return (CHANNEL_OUT_FL | CHANNEL_OUT_FC | CHANNEL_OUT_FR
                    | CHANNEL_OUT_BL | CHANNEL_OUT_BR);
        case 6: // 5.1 = 5.0 + LFE
            return (CHANNEL_OUT_FL | CHANNEL_OUT_FC | CHANNEL_OUT_FR
                    | CHANNEL_OUT_BL | CHANNEL_OUT_BR
                    | CHANNEL_OUT_LFE);
        case 7: // 7.0 = 5.0 + Sides
            return (CHANNEL_OUT_FL | CHANNEL_OUT_FC | CHANNEL_OUT_FR
                    | CHANNEL_OUT_BL | CHANNEL_OUT_BR
                    | CHANNEL_OUT_SL | CHANNEL_OUT_SR);
        case 8: // 7.1 = 7.0 + LFE
            return (CHANNEL_OUT_FL | CHANNEL_OUT_FC | CHANNEL_OUT_FR
                    | CHANNEL_OUT_BL | CHANNEL_OUT_BR | CHANNEL_OUT_SL | CHANNEL_OUT_SR
                    | CHANNEL_OUT_LFE);
        default:
            return 0;
    }
}

template <typename... Args>
bool C2ApexAacDec::AppendParamsToVector(
        std::vector<uint8_t> *configUpdate,
        Args... paramsArg) {
    constexpr size_t PARAMS_ALIGNMENT = 8;
    if (!configUpdate) {
        return false;
    }
    std::array<C2Param *, sizeof...(Args)> params{ static_cast<C2Param *>(paramsArg)... };
    if (params.size() == 0) {
        return false;
    }
    size_t offset = align(configUpdate->size(), PARAMS_ALIGNMENT);
    size_t size = offset;
    for (const C2Param *param : params) {
        if (!param || !(*param)) {
            return false;
        }
        size = align(size + param->size(), PARAMS_ALIGNMENT);
    }
    configUpdate->resize(size);
    for (const C2Param *param : params) {
        memcpy(configUpdate->data() + offset, param, param->size());
        offset = align(offset + param->size(), PARAMS_ALIGNMENT);
    }
    return true;
}

bool C2ApexAacDec::outputDelayRingBufferPutSamples(float *samples, int32_t numSamples) {
    if (numSamples == 0) return true;
    if (outputDelayRingBufferSpaceLeft() < numSamples) {
        ALOGE("RING BUFFER WOULD OVERFLOW");
        return false;
    }
    if (mOutputDelayRingBufferWritePos + numSamples <= mOutputDelayRingBufferSize) {
        memcpy(mOutputDelayRingBuffer.get() + mOutputDelayRingBufferWritePos, samples,
                numSamples * sizeof(float));
        mOutputDelayRingBufferWritePos += numSamples;
        if (mOutputDelayRingBufferWritePos == mOutputDelayRingBufferSize) {
            mOutputDelayRingBufferWritePos = 0;
        }
    } else {
        int32_t part1 = mOutputDelayRingBufferSize - mOutputDelayRingBufferWritePos;
        memcpy(mOutputDelayRingBuffer.get() + mOutputDelayRingBufferWritePos, samples,
                part1 * sizeof(float));
        int32_t part2 = numSamples - part1;
        memcpy(mOutputDelayRingBuffer.get(), samples + part1, part2 * sizeof(float));
        mOutputDelayRingBufferWritePos = part2;
    }
    mOutputDelayRingBufferFilled += numSamples;
    return true;
}

int32_t C2ApexAacDec::outputDelayRingBufferGetSamples(float *samples, int32_t numSamples) {
    if (numSamples > mOutputDelayRingBufferFilled) {
        ALOGE("RING BUFFER WOULD UNDERRUN");
        return -1;
    }
    if (mOutputDelayRingBufferReadPos + numSamples <= mOutputDelayRingBufferSize) {
        if (samples) {
            memcpy(samples, mOutputDelayRingBuffer.get() + mOutputDelayRingBufferReadPos,
                    numSamples * sizeof(float));
        }
        mOutputDelayRingBufferReadPos += numSamples;
        if (mOutputDelayRingBufferReadPos == mOutputDelayRingBufferSize) {
            mOutputDelayRingBufferReadPos = 0;
        }
    } else {
        int32_t part1 = mOutputDelayRingBufferSize - mOutputDelayRingBufferReadPos;
        if (samples) {
            memcpy(samples, mOutputDelayRingBuffer.get() + mOutputDelayRingBufferReadPos,
                    part1 * sizeof(float));
        }
        int32_t part2 = numSamples - part1;
        if (samples) {
            memcpy(samples + part1, mOutputDelayRingBuffer.get(), part2 * sizeof(float));
        }
        mOutputDelayRingBufferReadPos = part2;
    }
    mOutputDelayRingBufferFilled -= numSamples;
    return numSamples;
}

int32_t C2ApexAacDec::outputDelayRingBufferSamplesAvailable() {
    return mOutputDelayRingBufferFilled;
}

int32_t C2ApexAacDec::outputDelayRingBufferSpaceLeft() {
    return mOutputDelayRingBufferSize - mOutputDelayRingBufferFilled;
}

}  // namespace android
