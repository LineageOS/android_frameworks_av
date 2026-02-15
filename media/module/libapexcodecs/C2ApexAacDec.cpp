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

// #define LOG_NDEBUG 0
#define LOG_TAG "C2ApexAacDec"
#include <log/log.h>

#include <inttypes.h>
#include <math.h>
#include <numeric>
#include <sys/mman.h>

#include <algorithm>

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
#include "DrcPresModeWrapRustAac.h"
#include "private/apex/ApexCodecsImpl.h"

namespace android {

using ::android::apexcodecs::ApexComponentIntf;
using ::android::apexcodecs::ApexConfigurableImpl;
using ::android::apexcodecs::ApexConfigurableIntf;

namespace {
    constexpr int32_t DRC_DEFAULT_MOBILE_REF_LEVEL = 64;
    constexpr int32_t DRC_DEFAULT_MOBILE_DRC_CUT = 127;
    constexpr int32_t DRC_DEFAULT_MOBILE_DRC_BOOST = 127;
    constexpr int32_t DRC_DEFAULT_MOBILE_DRC_HEAVY = 1;
    constexpr int32_t DRC_DEFAULT_MOBILE_DRC_EFFECT = 3;
    constexpr int32_t DRC_DEFAULT_MOBILE_DRC_ALBUM = 0;
    constexpr float DRC_DEFAULT_MOBILE_OUTPUT_LOUDNESS = 0.25;
    constexpr int32_t DRC_DEFAULT_MOBILE_ENC_LEVEL = -1;
    constexpr int32_t MAX_CHANNEL_COUNT = 8;
    constexpr size_t MAX_SAMPLES_PER_FRAME = 4096;
    constexpr size_t MAX_FRAMES_TO_DECODE_PER_PROCESS_CALL = 3;
    constexpr size_t TMP_BUFFER_COUNT = MAX_SAMPLES_PER_FRAME * MAX_CHANNEL_COUNT
                                       * MAX_FRAMES_TO_DECODE_PER_PROCESS_CALL;
    constexpr char PROP_DRC_OVERRIDE_REF_LEVEL[] = "aac_drc_reference_level";
    constexpr char PROP_DRC_OVERRIDE_CUT[] = "aac_drc_cut";
    constexpr char PROP_DRC_OVERRIDE_BOOST[] = "aac_drc_boost";
    constexpr char PROP_DRC_OVERRIDE_HEAVY[] = "aac_drc_heavy";
    constexpr char PROP_DRC_OVERRIDE_ENC_LEVEL[] = "aac_drc_enc_target_level";
    constexpr char PROP_DRC_OVERRIDE_EFFECT[] = "ro.aac_drc_effect_type";
    constexpr size_t kDefaultOutputPortDelay = 2;
    constexpr size_t kMaxOutputPortDelay = 16;

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
                .withDefault(new C2StreamPcmEncodingInfo::output(0u, C2Config::PCM_16))
                .withFields({C2F(mPcmEncodingInfo, value).oneOf({
                     C2Config::PCM_16, C2Config::PCM_FLOAT
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
        C2Config::drc_compression_mode_t defaultDrcCompressionMode =
                property_get_int32(PROP_DRC_OVERRIDE_HEAVY,
                                   DRC_DEFAULT_MOBILE_DRC_HEAVY) == 1
                        ? C2Config::DRC_COMPRESSION_HEAVY
                        : C2Config::DRC_COMPRESSION_LIGHT;
        addParameter(
                DefineParam(mDrcCompressMode, C2_PARAMKEY_DRC_COMPRESSION_MODE)
                .withDefault(new C2StreamDrcCompressionModeTuning::input(
                        0u, defaultDrcCompressionMode))
                .withFields({
                    C2F(mDrcCompressMode, value).oneOf({
                            C2Config::DRC_COMPRESSION_ODM_DEFAULT,
                            C2Config::DRC_COMPRESSION_NONE,
                            C2Config::DRC_COMPRESSION_LIGHT,
                            C2Config::DRC_COMPRESSION_HEAVY})
                })
                .withSetter(Setter<decltype(*mDrcCompressMode)>::StrictValueWithNoDeps)
                .build());

        float defaultDrcTargetRefLevel = -0.25 * property_get_int32(
                PROP_DRC_OVERRIDE_REF_LEVEL,
                DRC_DEFAULT_MOBILE_REF_LEVEL);
        addParameter(
                DefineParam(mDrcTargetRefLevel, C2_PARAMKEY_DRC_TARGET_REFERENCE_LEVEL)
                .withDefault(new C2StreamDrcTargetReferenceLevelTuning::input(
                        0u, defaultDrcTargetRefLevel))
                .withFields({C2F(mDrcTargetRefLevel, value).inRange(-31.75, 0.25)})
                .withSetter(Setter<decltype(*mDrcTargetRefLevel)>::StrictValueWithNoDeps)
                .build());

        float defaultDrcEncTargetLevel = -0.25 * property_get_int32(
                PROP_DRC_OVERRIDE_ENC_LEVEL,
                DRC_DEFAULT_MOBILE_ENC_LEVEL);
        addParameter(
                DefineParam(mDrcEncTargetLevel, C2_PARAMKEY_DRC_ENCODED_TARGET_LEVEL)
                .withDefault(new C2StreamDrcEncodedTargetLevelTuning::input(
                        0u, defaultDrcEncTargetLevel))
                .withFields({C2F(mDrcEncTargetLevel, value).inRange(-31.75, 0.25)})
                .withSetter(Setter<decltype(*mDrcEncTargetLevel)>::StrictValueWithNoDeps)
                .build());

        float defaultDrcBoostFactor = property_get_int32(
                PROP_DRC_OVERRIDE_BOOST,
                DRC_DEFAULT_MOBILE_DRC_BOOST) / 127.;
        addParameter(
                DefineParam(mDrcBoostFactor, C2_PARAMKEY_DRC_BOOST_FACTOR)
                .withDefault(new C2StreamDrcBoostFactorTuning::input(
                        0u, defaultDrcBoostFactor))
                .withFields({C2F(mDrcBoostFactor, value).inRange(0, 1.)})
                .withSetter(Setter<decltype(*mDrcBoostFactor)>::StrictValueWithNoDeps)
                .build());

        float defaultDrcAttenuationFactor = property_get_int32(
                PROP_DRC_OVERRIDE_CUT,
                DRC_DEFAULT_MOBILE_DRC_CUT) / 127.;
        addParameter(
                DefineParam(mDrcAttenuationFactor, C2_PARAMKEY_DRC_ATTENUATION_FACTOR)
                .withDefault(new C2StreamDrcAttenuationFactorTuning::input(
                        0u, defaultDrcAttenuationFactor))
                .withFields({C2F(mDrcAttenuationFactor, value).inRange(0, 1.)})
                .withSetter(Setter<decltype(*mDrcAttenuationFactor)>::StrictValueWithNoDeps)
                .build());
        C2Config::drc_effect_type_t defaultDrcEffectType =
                (C2Config::drc_effect_type_t)property_get_int32(
                        PROP_DRC_OVERRIDE_EFFECT, DRC_DEFAULT_MOBILE_DRC_EFFECT);
        addParameter(
                DefineParam(mDrcEffectType, C2_PARAMKEY_DRC_EFFECT_TYPE)
                .withDefault(new C2StreamDrcEffectTypeTuning::input(
                        0u, defaultDrcEffectType))
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
        mIsFirstInput(true),
        mIsFirstOutput(true),
        mSignalledError(false),
        mEndOfInput(false),
        mEndOfOutput(false),
        mCurrentTimestampUs(0),
        mCurrentFrameIndex(0),
        mSamplesToDiscard(0),
        mLeftoverSamples(0),
        mDeviceApiLevel(android_get_device_api_level()) {
    mLeftoverBuffer.resize(TMP_BUFFER_COUNT);
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
    if (mAACDecoder) {
        if (aacDecoder_Clear(mAACDecoder) != AAC_DEC_OK) {
            ALOGE("aacDecoder_Clear failed");
            return APEXCODEC_STATUS_CORRUPTED;
        }
        mEndOfInput = false;
        mEndOfOutput = false;
        ALOGV("flush: clearing leftover %zu samples and %zu pending timestamps",
                mLeftoverSamples, mPendingTimestamps.size());
        mLeftoverSamples = 0;
        mPendingTimestamps = {};
        mLeftoverBuffer.resize(TMP_BUFFER_COUNT);
        mIsFirstInput = true;
        mIsFirstOutput = true;
    }
    return APEXCODEC_STATUS_OK;
}

ApexCodec_Status C2ApexAacDec::reset() {
    ALOGV("reset");
    if (mAACDecoder) {
        aacDecoder_Close(mAACDecoder);
        mAACDecoder = nullptr;
    }
    mSignalledError = false;
    mEndOfInput = false;
    mEndOfOutput = false;
    mSamplesToDiscard = 0;
    ALOGV("reset: clearing leftover %zu samples and %zu pending timestamps",
            mLeftoverSamples, mPendingTimestamps.size());
    mLeftoverSamples = 0;
    mLeftoverBuffer.resize(TMP_BUFFER_COUNT);
    mPendingTimestamps = {};
    mIsFirstInput = true;
    mIsFirstOutput = true;
    mCurrentTimestampUs = 0;
    mCurrentFrameIndex = 0;
    mOutputInfo = CAacDecoderOutputInfo_default();
    mStreamInfo = CAacDecoderStreamInfo_default();
    mMetadataInfo = CAacDecoderMetadataInfo_default();
    return APEXCODEC_STATUS_OK;
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
    ALOGV("process: input=%p, output=%p", input, output);
    constexpr size_t kMaxOutputBufferSize = TMP_BUFFER_COUNT * sizeof(float);
    if (mSignalledError) {
        ALOGE("process called in error state");
        return APEXCODEC_STATUS_CORRUPTED;
    }
    *consumed = 0;
    *produced = 0;

    ApexCodec_LinearBuffer configUpdates;
    if (input) {
        ApexCodec_LinearBuffer configUpdates;
        bool ownedByClient;
        if (input->getConfigUpdates(&configUpdates, &ownedByClient) == APEXCODEC_STATUS_OK &&
                configUpdates.size > 0) {
            ALOGV("configUpdates.size: %zu", configUpdates.size);
            std::vector<C2Param *> c2Params;
            uint8_t *data = configUpdates.data;
            size_t size = configUpdates.size;
            constexpr size_t PARAMS_ALIGNMENT = 8;
            while (size > 0) {
                ALOGV("configUpdates size: %zu", size);
                size_t paramSize = ((C2Param *)data)->size();
                if (paramSize > size || paramSize == 0) {
                    mSignalledError = true;
                    return APEXCODEC_STATUS_CORRUPTED;
                }
                c2Params.emplace_back(C2Param::From(data, paramSize));
                data += align(paramSize, PARAMS_ALIGNMENT);
                size -= align(paramSize, PARAMS_ALIGNMENT);
            }
            if (!c2Params.empty()) {
                ALOGV("config: %zu params", c2Params.size());
                std::vector<std::unique_ptr<C2SettingResult>> failures;
                (void)mIntf->config(c2Params, C2_MAY_BLOCK, &failures);
                ALOGV("config done");
            }
        }
    }

    ApexCodec_BufferFlags inFlags = (ApexCodec_BufferFlags)0;
    uint64_t frameIndex = 0, timestamp = 0;

    uint32_t prevSampleRate = mOutputInfo.sampling_rate;
    uint8_t prevNumChannels = mOutputInfo.num_channels;
    int16_t prevOutLoudness = mOutputInfo.output_loudness;
    AUDIO_OBJECT_TYPE prevExtAot = mStreamInfo.extAot;
    // SBR and PS are dual rate systems, so the sample rate is doubled.
    if (prevExtAot == AOT_SBR || prevExtAot == AOT_PS) {
        prevSampleRate *= 2;
    }

    ApexCodec_LinearBuffer outLinearBuffer;
    if (output->getLinearBuffer(&outLinearBuffer) != APEXCODEC_STATUS_OK) {
        ALOGE("output->getLinearBuffer failed");
        return APEXCODEC_STATUS_BAD_VALUE;
    }

    if (outLinearBuffer.size < kMaxOutputBufferSize) {
        std::vector<uint8_t> configUpdate;
        C2StreamMaxBufferSizeInfo::output outSize(0u, kMaxOutputBufferSize);
        AppendParamsToVector(&configUpdate, &outSize);
        output->setOwnedConfigUpdates(std::move(configUpdate));
        return APEXCODEC_STATUS_NO_MEMORY;
    }

    if (input) {
        input->getBufferInfo(&inFlags, &frameIndex, &timestamp);
    }
    ALOGV("process input: flags=%x, frameIndex=%" PRIu64 ","
            "timestamp=%" PRIu64, inFlags, frameIndex, timestamp);

    ApexCodec_LinearBuffer inBuffer;
    AAC_DECODER_ERROR decoderErr = AAC_DEC_OK;
    OutputInfo output_info = CAacDecoderOutputInfo_default();
    std::vector<float> tmpOutBuffer(TMP_BUFFER_COUNT);
    bool decoded = false;
    bool codecConfig = (inFlags & APEXCODEC_FLAG_CODEC_CONFIG) != 0;
    ALOGV("codecConfig: %d", codecConfig);

    if (inFlags & APEXCODEC_FLAG_END_OF_STREAM) {
        mEndOfInput = true;
    }

    if (!mEndOfInput && input &&
            input->getLinearBuffer(&inBuffer) == APEXCODEC_STATUS_OK &&
            inBuffer.size > 0) {
        if (input->getType() != APEXCODEC_BUFFER_TYPE_LINEAR) {
            ALOGE("input buffer type is not linear");
            return APEXCODEC_STATUS_BAD_VALUE;
        }

        ALOGV("input buffer size: %zu", inBuffer.size);
        if (codecConfig) {
            ALOGV("processing codec config buffer (size=%zu)", inBuffer.size);
            decoderErr = aacDecoder_ConfigRaw(mAACDecoder,
                                     const_cast<uint8_t *>(inBuffer.data),
                                     static_cast<uint32_t>(inBuffer.size));
            if (decoderErr != AAC_DEC_OK) {
                ALOGE("aacDecoder_ConfigRaw decoderErr = 0x%4.4x", decoderErr);
                mSignalledError = true;
                ALOGV("codec config buffer size: %zu", inBuffer.size);
                for (size_t i = 0; i < inBuffer.size; ++i) {
                    ALOGV("codec config buffer data[%zu]: %02x", i, inBuffer.data[i]);
                }
                return APEXCODEC_STATUS_CORRUPTED;
            }
            *consumed = inBuffer.size;
        } else {
            mPendingTimestamps.emplace(timestamp, frameIndex);
            size_t offset = 0;
            size_t size = inBuffer.size;
            while (size > 0) {
                uint8_t* inPtr = const_cast<uint8_t *>(inBuffer.data) + offset;
                uint32_t inBufferLength = size;
                uint32_t bytesValid = inBufferLength;
                unsigned aac_frame_length = 0;
                if (mIntf->isAdts()) {
                    // ADTS parsing logic
                    ALOGV("ADTS input");
                    size_t adtsHeaderSize = 0;
                    const uint8_t *adtsHeader = inBuffer.data + offset;
                    if (size < 7) {
                        ALOGV("ADTS header too small: %zu. Leftover", size);
                        break;
                    }
                    bool protectionAbsent = (adtsHeader[1] & 1);
                    aac_frame_length =
                        ((adtsHeader[3] & 3) << 11) | (adtsHeader[4] << 3) | (adtsHeader[5] >> 5);
                    ALOGV("protectionAbsent=%d, aac_frame_length=%u",
                            protectionAbsent, aac_frame_length);
                    if (size < aac_frame_length) {
                        ALOGV("Incomplete ADTS frame: %zu < %u. Leftover", size, aac_frame_length);
                        break;
                    }
                    adtsHeaderSize = (protectionAbsent ? 7 : 9);
                    ALOGV("adtsHeaderSize: %zu", adtsHeaderSize);
                    if (aac_frame_length < adtsHeaderSize) {
                        ALOGE("ADTS frame length is smaller than header size");
                        mSignalledError = true;
                        return APEXCODEC_STATUS_CORRUPTED;
                    }
                    inPtr = const_cast<uint8_t *>(adtsHeader + adtsHeaderSize);
                    inBufferLength = aac_frame_length - adtsHeaderSize;
                }
                bytesValid = inBufferLength;
                aacDecoder_Fill(mAACDecoder, inPtr, inBufferLength, &bytesValid);

                size_t consumedInFill = inBufferLength - bytesValid;
                if (mIntf->isAdts()) {
                    offset += aac_frame_length;
                    size -= aac_frame_length;
                } else {
                    offset += consumedInFill;
                    size -= consumedInFill;
                }
                if (consumedInFill != inBufferLength && !mIntf->isAdts()) {
                    ALOGE("aacDecoder_Fill did not consume all data");
                    break;
                }
                if (!mIntf->isAdts()) {
                    break;
                }
            }

            mDrcWrap.submitStreamData(&mStreamInfo, &mOutputInfo, &mMetadataInfo);
            updateParams();
            mDrcWrap.update();

            decoderErr = aacDecoder_Decode(mAACDecoder, tmpOutBuffer.data(),
                                            TMP_BUFFER_COUNT,
                                            &mOutputInfo, &mStreamInfo,
                                            &mMetadataInfo);
            decoded = true;
            *consumed = offset;
            ALOGV("consumed: %zu", *consumed);

            if (offset > 0) {
                mIsFirstInput = false;
            }
        }
    } else if (mEndOfInput && !mEndOfOutput && !mPendingTimestamps.empty()) {
        ALOGV("draining");
        decoderErr = aacDecoder_Drain(
                mAACDecoder, tmpOutBuffer.data(), TMP_BUFFER_COUNT, &mOutputInfo);
        ALOGV("Drained %zu samples from decoder, status = %d",
              (size_t)mOutputInfo.frame_size * mOutputInfo.num_channels, decoderErr);
        decoded = true;
    } else {
        ALOGV("no input, no output, no pending timestamps");
    }

    if (decoded) {
        while (decoderErr != AAC_DEC_NOT_ENOUGH_BITS) {
            ALOGV("decoded data");
            size_t generatedSamples = 0;

            if (IS_OUTPUT_VALID(decoderErr)) {
                if (mIsFirstOutput) {
                    mSamplesToDiscard = mOutputInfo.output_delay * mOutputInfo.num_channels;

                    ALOGV("mOutputInfo.output_delay: %d", mOutputInfo.output_delay);
                    mIsFirstOutput = false;
                    size_t delayInFrames = 0;
                    if (mOutputInfo.frame_size > 0) {
                        delayInFrames =
                                (mOutputInfo.output_delay + mOutputInfo.frame_size - 1)
                                / mOutputInfo.frame_size;
                    }
                    if (delayInFrames > 0) {
                        C2PortActualDelayTuning::output opd(delayInFrames);
                        std::vector<uint8_t> configUpdate;
                        AppendParamsToVector(&configUpdate, &opd);
                        output->setOwnedConfigUpdates(std::move(configUpdate));
                    }
                }
                generatedSamples = mOutputInfo.frame_size * mOutputInfo.num_channels;
            }
            if (generatedSamples > tmpOutBuffer.size()) {
                ALOGE("too many samples output: %zu", generatedSamples);
                mSignalledError = true;
                return APEXCODEC_STATUS_CORRUPTED;
            }
            ALOGV("generatedSamples: %zu, mSamplesToDiscard: %d",
                    generatedSamples, mSamplesToDiscard);

            size_t outOffsetSamples = 0;
            if (mSamplesToDiscard > 0) {
                if (mSamplesToDiscard >= generatedSamples) {
                    mSamplesToDiscard -= generatedSamples;
                    generatedSamples = 0;
                } else {
                    outOffsetSamples = mSamplesToDiscard;
                    generatedSamples -= mSamplesToDiscard;
                    mSamplesToDiscard = 0;
                }
            }

            if (generatedSamples > 0) {
                if (mLeftoverSamples + generatedSamples > mLeftoverBuffer.size()) {
                    mLeftoverBuffer.resize(mLeftoverSamples + generatedSamples);
                }
                ALOGV("mLeftoverSamples: %zu -> %zu (added %zu)",
                        mLeftoverSamples, mLeftoverSamples + generatedSamples, generatedSamples);
                memcpy(mLeftoverBuffer.data() + mLeftoverSamples,
                       tmpOutBuffer.data() + outOffsetSamples,
                       generatedSamples * sizeof(float));
                mLeftoverSamples += generatedSamples;
            }

            int32_t pcmEncoding = mIntf->getPcmEncodingInfo();
            size_t frameSamples = isConfigured() ?
                    (mOutputInfo.frame_size * mOutputInfo.num_channels) : 0;
            if (frameSamples > 0 && mLeftoverSamples >= frameSamples) {
                ALOGV("have enough samples for a frame. frameSamples: %zu, mLeftoverSamples: %zu",
                        frameSamples, mLeftoverSamples);
                size_t sampleSize = (pcmEncoding == C2Config::PCM_16)
                        ? sizeof(int16_t) : sizeof(float);
                if (frameSamples * sampleSize > outLinearBuffer.size) {
                    ALOGE("output buffer too small for a frame");
                    mSignalledError = true;
                    return APEXCODEC_STATUS_NO_MEMORY;
                }

                uint8_t *outPtr = outLinearBuffer.data;
                outPtr += *produced;
                if (pcmEncoding == C2Config::PCM_16) {
                    int16_t* out = reinterpret_cast<int16_t*>(outPtr);
                    for (size_t i = 0; i < frameSamples; ++i) {
                        float val = mLeftoverBuffer[i] * 32767.f;
                        val = std::max(-32768.f, std::min(32767.f, val));
                        out[i] = static_cast<int16_t>(roundf(val));
                    }
                } else {
                    memcpy(outPtr, mLeftoverBuffer.data(), frameSamples * sampleSize);
                }
                *produced += frameSamples * sampleSize;

                memmove(mLeftoverBuffer.data(),
                        mLeftoverBuffer.data() + frameSamples,
                        (mLeftoverSamples - frameSamples) * sizeof(float));
                mLeftoverSamples -= frameSamples;
                ALOGV("consumed %zu samples for a frame, remaining leftover: %zu",
                        frameSamples, mLeftoverSamples);
                ALOGV("pending timestamps size : %zu", mPendingTimestamps.size());
            }

            ALOGV("produced: %zu", *produced);
            std::vector<uint8_t> configUpdate;
            uint32_t currentSampleRate = mOutputInfo.sampling_rate;
            // SBR and PS are dual rate systems, so the sample rate is doubled.
            if (mStreamInfo.extAot == AOT_SBR || mStreamInfo.extAot == AOT_PS) {
                currentSampleRate *= 2;
            }
            if (isConfigured() && (currentSampleRate != prevSampleRate
                    || mOutputInfo.num_channels != prevNumChannels)) {
                ALOGD("config changed: sampleRate %d->%d, channels %d->%d",
                        prevSampleRate, currentSampleRate, prevNumChannels,
                        mOutputInfo.num_channels);
                C2StreamSampleRateInfo::output sampleRateInfo(
                        0u, currentSampleRate);
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

            C2StreamDrcAttenuationFactorTuning::input currentAttenuationFactor(
                    0u, (C2FloatValue)(mIntf->getDrcAttenuationFactor() / 127.));
            AppendParamsToVector(&configUpdate, &currentAttenuationFactor);

            C2StreamDrcBoostFactorTuning::input currentBoostFactor(
                    0u, (C2FloatValue)(mIntf->getDrcBoostFactor() / 127.));
            AppendParamsToVector(&configUpdate, &currentBoostFactor);

            if (mDeviceApiLevel < 31 /* __ANDROID_API_S__ */) {
                // We used to report DRC compression mode in the output format
                // in Q and R, but stopped doing that in S
                C2StreamDrcCompressionModeTuning::input currentCompressMode(
                        0u, (C2Config::drc_compression_mode_t)mIntf->getDrcCompressMode());
                AppendParamsToVector(&configUpdate, &currentCompressMode);
            }

            C2StreamDrcEncodedTargetLevelTuning::input currentEncodedTargetLevel(
                    0u, (C2FloatValue)(mIntf->getDrcEncTargetLevel() * -0.25));
            AppendParamsToVector(&configUpdate, &currentEncodedTargetLevel);

            C2StreamDrcAlbumModeTuning::input currentAlbumMode(
                    0u, (C2Config::drc_album_mode_t)mIntf->getDrcAlbumMode());
            AppendParamsToVector(&configUpdate, &currentAlbumMode);

            C2StreamDrcTargetReferenceLevelTuning::input currentTargetRefLevel(
                    0u, (float)(mIntf->getDrcTargetRefLevel() * -0.25));
            AppendParamsToVector(&configUpdate, &currentTargetRefLevel);

            C2StreamDrcEffectTypeTuning::input currentEffectType(
                    0u, (C2Config::drc_effect_type_t)mIntf->getDrcEffectType());
            AppendParamsToVector(&configUpdate, &currentEffectType);

            C2StreamMaxChannelCountInfo::input currentMaxChannelCnt(0u,
                                                                    mIntf->getMaxChannelCount());
            AppendParamsToVector(&configUpdate, &currentMaxChannelCnt);

            ALOGV("DRC params: %d, %d, %d, %d, %d, %d, %d, %d",
                    mIntf->getDrcTargetRefLevel(), mIntf->getDrcAttenuationFactor(),
                    mIntf->getDrcBoostFactor(), mIntf->getDrcCompressMode(),
                    mIntf->getDrcEncTargetLevel(), mIntf->getDrcEffectType(),
                    mIntf->getDrcAlbumMode(), mIntf->getMaxChannelCount());

            if (!configUpdate.empty()) {
                output->setOwnedConfigUpdates(std::move(configUpdate));
            }
            // Write output buffer info into temporary buffers as they will be empty if there
            // is not enough data to decode a full frame.
            OutputInfo tempOutputInfo;
            StreamInfo tempStreamInfo;
            MetadataInfo tempMetadataInfo;
            decoderErr = aacDecoder_Decode(mAACDecoder, tmpOutBuffer.data(),
                                            TMP_BUFFER_COUNT,
                                            &tempOutputInfo, &tempStreamInfo,
                                            &tempMetadataInfo);
        }
        if (*produced > 0 && !mPendingTimestamps.empty()) {
            mCurrentTimestampUs = mPendingTimestamps.front().first;
            mCurrentFrameIndex = mPendingTimestamps.front().second;
            mPendingTimestamps.pop();
            ALOGV("popped timestamp %" PRIu64 " and frameIndex %" PRIu64,
                    mCurrentTimestampUs, mCurrentFrameIndex);
        }
    }

    ALOGV("consumed: %zu, produced: %zu", *consumed, *produced);
    ALOGV("mEndOfInput: %d, mEndOfOutput: %d, mCurrentFrameIndex: %" PRIu64,
            mEndOfInput, mEndOfOutput, mCurrentFrameIndex);
    ALOGV("mCurrentTimestampUs: %" PRIu64, mCurrentTimestampUs);
    ALOGV("mPendingTimestamps size: %zu", mPendingTimestamps.size());
    ALOGV("mLeftoverSamples: %zu", mLeftoverSamples);
    ALOGV("frameIndex: %" PRIu64, frameIndex);
    if (*produced > 0) {
        bool eos = mEndOfOutput || (mEndOfInput && mPendingTimestamps.empty());
        if (eos) {
            if (mCurrentFrameIndex == frameIndex) {
                ALOGV("produced and emitting EOS with frameIndex: %" PRIu64, mCurrentFrameIndex);
                output->setBufferInfo(APEXCODEC_FLAG_END_OF_STREAM,
                        mCurrentFrameIndex, mCurrentTimestampUs);
            } else {
                ALOGV("emitting second to last buffer with frameIndex: %"
                        PRIu64, mCurrentFrameIndex);
                output->setBufferInfo((ApexCodec_BufferFlags)0,
                        mCurrentFrameIndex, mCurrentTimestampUs);
            }
            mEndOfOutput = true;
        } else {
            ALOGV("emitting buffer with frameIndex: %" PRIu64, mCurrentFrameIndex);
            output->setBufferInfo((ApexCodec_BufferFlags)0,
                    mCurrentFrameIndex, mCurrentTimestampUs);
        }
    } else if (mEndOfInput && mPendingTimestamps.empty()) {
        ALOGV("emitting EOS with frameIndex: %" PRIu64, frameIndex);
        output->setBufferInfo(APEXCODEC_FLAG_END_OF_STREAM,
                frameIndex, timestamp);
        mEndOfOutput = true;
    } else if (codecConfig) {
        ALOGV("emitting buffer with frameIndex: %" PRIu64, frameIndex);
        output->setBufferInfo((ApexCodec_BufferFlags)0, frameIndex, timestamp);
    } else if (*consumed > 0) {
        ALOGV("emitting incomplete buffer with frameIndex: %" PRIu64, frameIndex);
        output->setBufferInfo(APEXCODEC_FLAG_INCOMPLETE, frameIndex, timestamp);
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
    mOutputInfo = CAacDecoderOutputInfo_default();
    mStreamInfo = CAacDecoderStreamInfo_default();
    mMetadataInfo = CAacDecoderMetadataInfo_default();
    mDrcWrap.setDecoderHandle(mAACDecoder);
    mDrcWrap.submitStreamData(&mStreamInfo, &mOutputInfo, &mMetadataInfo);

    ALOGV("aacDecoder_Open successful");
    updateParams();
    return APEXCODEC_STATUS_OK;
}

void C2ApexAacDec::updateParams() {
    ALOGV("updateParams");
    int32_t targetRefLevel = mIntf->getDrcTargetRefLevel();
    ALOGV("  drc-ref-level: %d", targetRefLevel);
    mDrcWrap.setParam(DRC_PRES_MODE_WRAP_DESIRED_TARGET, (unsigned)targetRefLevel);

    int32_t attenuationFactor = mIntf->getDrcAttenuationFactor();
    ALOGV("  drc-attenuation-factor: %d", attenuationFactor);
    mDrcWrap.setParam(DRC_PRES_MODE_WRAP_DESIRED_ATT_FACTOR, (unsigned)attenuationFactor);

    int32_t boostFactor = mIntf->getDrcBoostFactor();
    ALOGV("  drc-boost-factor: %d", boostFactor);
    mDrcWrap.setParam(DRC_PRES_MODE_WRAP_DESIRED_BOOST_FACTOR, (unsigned)boostFactor);

    int32_t compressMode = mIntf->getDrcCompressMode();
    ALOGV("  drc-compress-mode: %d", compressMode);
    mDrcWrap.setParam(DRC_PRES_MODE_WRAP_DESIRED_HEAVY, (unsigned)compressMode);

    int32_t encTargetLevel = mIntf->getDrcEncTargetLevel();
    ALOGV("  drc-enc-target-level: %d", encTargetLevel);
    mDrcWrap.setParam(DRC_PRES_MODE_WRAP_ENCODER_TARGET, (unsigned)encTargetLevel);

    int32_t effectType = mIntf->getDrcEffectType();
    ALOGV("  drc-effect-type: %d", effectType);
    aacDecoder_SetParam(mAACDecoder, AAC_UNIDRC_SET_EFFECT, effectType);

    int32_t albumMode = mIntf->getDrcAlbumMode();
    ALOGV("  drc-album-mode: %d", albumMode);
    aacDecoder_SetParam(mAACDecoder, AAC_UNIDRC_ALBUM_MODE, albumMode);

    u_int32_t maxChannelCount = mIntf->getMaxChannelCount();
    ALOGV("  max-channel-count: %u", maxChannelCount);
    aacDecoder_SetParam(mAACDecoder, AAC_PCM_MAX_OUTPUT_CHANNELS, maxChannelCount);
}

bool C2ApexAacDec::isConfigured() const {
    bool configured = mOutputInfo.sampling_rate > 0;
    ALOGV("isConfigured: %d (sample_rate=%d)", configured, mOutputInfo.sampling_rate);
    return configured;
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
}  // namespace android
