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
#define LOG_TAG "C2SoftXheAacEnc"
#define PCMBUFSIZE      (4096 * 40)
#define MAXFRAMESIZE    (4096)
#include <utils/Log.h>

#include <android_media_swcodec_flags.h>
#include <android/api-level.h>
#include <android-base/properties.h>

#include <array>
#include <cinttypes>
#include <fstream>    // std::ifstream
#include <vector>     // std::vector
#include <string>     // std::string
#include <stdexcept>  // std::runtime_error

#include <C2PlatformSupport.h>
#include <SimpleC2Interface.h>
#include <media/stagefright/foundation/MediaDefs.h>
#include <media/stagefright/foundation/hexdump.h>

#include "C2SoftXheAacEnc.h"

namespace android {

namespace {

constexpr char COMPONENT_NAME[] = "c2.android.xheaac.encoder";

}  // namespace

class C2SoftXheAacEnc::IntfImpl : public SimpleInterface<void>::BaseParams {
  public:
    IIS_XHEAACENC_INSTANCE_HANDLE mInstance = nullptr;
    explicit IntfImpl(const std::shared_ptr<C2ReflectorHelper> &helper)
        : SimpleInterface<void>::BaseParams(
                  helper,
                  COMPONENT_NAME,
                  C2Component::KIND_ENCODER,
                  C2Component::DOMAIN_AUDIO,
                  MEDIA_MIMETYPE_AUDIO_AAC) {
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
                        .withDefault(new C2StreamSampleRateInfo::input(0u, 44100))
                        .withFields({C2F(mSampleRate, value).oneOf({
                                16000, 22050, 24000, 32000, 44100, 48000
                        })})
                        .withSetter((Setter<decltype(*mSampleRate)>::StrictValueWithNoDeps))
                        .build());

        addParameter(
                DefineParam(mChannelCount, C2_PARAMKEY_CHANNEL_COUNT)
                        .withDefault(new C2StreamChannelCountInfo::input(0u, 1))
                        .withFields({C2F(mChannelCount, value).inRange(1, kMaxChannelCount)})
                        .withSetter(Setter<decltype(*mChannelCount)>::StrictValueWithNoDeps)
                        .build());

        addParameter(
                DefineParam(mInputMaxBufSize, C2_PARAMKEY_INPUT_MAX_BUFFER_SIZE)
                        .withDefault(new C2StreamMaxBufferSizeInfo::input(0u, 8192))
                        .calculatedAs(MaxBufSizeCalculator, mChannelCount)
                        .build());

        addParameter(
                DefineParam(mKeyFramePeriodUs, C2_PARAMKEY_SYNC_FRAME_INTERVAL)
                        .withDefault(new C2StreamSyncFrameIntervalTuning::output(0u, 0))
                        .withFields({C2F(mKeyFramePeriodUs, value).any()})
                        .withSetter(Setter<decltype(*mKeyFramePeriodUs)>::StrictValueWithNoDeps)
                        .build());

        addParameter(
                DefineParam(mBitrateMode, C2_PARAMKEY_BITRATE_MODE)
                        .withDefault(new C2StreamBitrateModeTuning::output(
                                0, C2Config::BITRATE_CONST))
                        .withFields({C2F(mBitrateMode, value).oneOf({
                                C2Config::BITRATE_CONST, C2Config::BITRATE_VARIABLE})})
                        .withSetter(Setter<decltype(*mBitrateMode)>::StrictValueWithNoDeps)
                        .build());

        addParameter(
                DefineParam(mQuality, C2_PARAMKEY_QUALITY)
                        .withDefault(new C2StreamQualityTuning::output(0u, kDefaultQualityLevel))
                        .withFields({C2F(mQuality, value).inRange(0, kMaxQualityLevel)})
                        .withSetter(Setter<decltype(*mQuality)>::NonStrictValueWithNoDeps)
                        .build());

        addParameter(
                DefineParam(mBitrate, C2_PARAMKEY_BITRATE)
                        .withDefault(new C2StreamBitrateInfo::output(0u, 64000))
                        .withFields({C2F(mBitrate, value).inRange(12000, 320000)})
                        .withSetter(SetBitrate, mBitrateMode, mQuality, mChannelCount)
                        .build());

        addParameter(
                DefineParam(mOutputSampleRate, C2_PARAMKEY_CODED_SAMPLE_RATE)
                        .withDefault(new C2StreamSampleRateInfo::output(0u, 44100))
                        .withFields({C2F(mOutputSampleRate, value).oneOf({44100, 48000})})
                        .withSetter((Setter<decltype(*mOutputSampleRate)>::StrictValueWithNoDeps))
                        .build());

        addParameter(
                DefineParam(mProfileLevel, C2_PARAMKEY_PROFILE_LEVEL)
                        .withDefault(new C2StreamProfileLevelInfo::output(
                                0u, C2Config::PROFILE_AAC_XHE, C2Config::LEVEL_UNUSED))
                        .withFields({
                                C2F(mProfileLevel, profile).oneOf({
                                        C2Config::PROFILE_AAC_XHE}),
                                C2F(mProfileLevel, level).oneOf({
                                        C2Config::LEVEL_UNUSED
                                })
                        })
                        .withSetter(ProfileLevelSetter)
                        .build());

        addParameter(
                DefineParam(mAudioPresentationId, C2_PARAMKEY_AUDIO_PRESENTATION_ID)
                        .withDefault(new C2AudioPresentationIdTuning(0))
                        .withFields({C2F(mAudioPresentationId, value).any()})
                        .withSetter(Setter<decltype(*mAudioPresentationId)>::StrictValueWithNoDeps)
                        .build());
    }

    uint32_t getSampleRate() const { return mSampleRate->value; }
    uint32_t getChannelCount() const { return mChannelCount->value; }
    int32_t getStreamId() const { return static_cast<int32_t>(mAudioPresentationId->value); }
    uint32_t getBitrate() const { return mBitrate->value; }
    uint32_t getConstantRapInterval() const { return mKeyFramePeriodUs->value / 1000; }
    C2Config::bitrate_mode_t getBitrateMode() const { return mBitrateMode->value; }
    uint32_t getQuality() const { return mQuality->value; }

    static C2R MaxBufSizeCalculator(
            bool /* mayBlock */,
            C2P<C2StreamMaxBufferSizeInfo::input> &me,
            const C2P<C2StreamChannelCountInfo::input> &channelCount) {
        me.set().value = 1024 * sizeof(short) * channelCount.v.value;
        return C2R::Ok();
    }

    static C2R SetBitrate(bool /* mayBlock */,
            C2InterfaceHelper::C2P<C2StreamBitrateInfo::output> &me,
            const C2InterfaceHelper::C2P<C2StreamBitrateModeTuning::output>& mode,
            const C2InterfaceHelper::C2P<C2StreamQualityTuning::output>& quality,
            const C2InterfaceHelper::C2P<C2StreamChannelCountInfo::input>& channels) {
        // See documentation for IIS_XHEAACENC_BITRATEMODE
        static const std::array<std::array<uint32_t, kMaxQualityLevel + 1>, kMaxChannelCount>
                TARGET_BITRATES{{// Mono
                                 {20'000, 32'000, 40'000, 56'000, 72'000, 104'000, 136'000},
                                 // Stereo
                                 {24'000, 40'000, 64'000, 96'000, 128'000, 192'000, 256'000}}};

        if (mode.v.value == C2Config::BITRATE_VARIABLE) {
            me.set().value = TARGET_BITRATES[channels.v.value - 1][quality.v.value];
        }
        return C2R::Ok();
    }

    static C2R ProfileLevelSetter(bool mayBlock, C2P<C2StreamProfileLevelInfo::output> &me) {
        (void)mayBlock;
        (void)me;  // TODO: validate
        return C2R::Ok();
    }

  private:
    std::shared_ptr<C2StreamSampleRateInfo::input> mSampleRate;
    std::shared_ptr<C2StreamChannelCountInfo::input> mChannelCount;
    std::shared_ptr<C2StreamBitrateInfo::output> mBitrate;
    std::shared_ptr<C2StreamSyncFrameIntervalTuning::output> mKeyFramePeriodUs;
    std::shared_ptr<C2StreamBitrateModeTuning::output> mBitrateMode;
    std::shared_ptr<C2StreamQualityTuning::output> mQuality;
    std::shared_ptr<C2AudioPresentationIdTuning> mAudioPresentationId;

    // These are not used internally, but are "out-parameters" used by successive components
    std::shared_ptr<C2StreamMaxBufferSizeInfo::input> mInputMaxBufSize;
    std::shared_ptr<C2StreamSampleRateInfo::output> mOutputSampleRate;
    std::shared_ptr<C2StreamProfileLevelInfo::output> mProfileLevel;
};

C2SoftXheAacEnc::C2SoftXheAacEnc(
        const char *name,
        c2_node_id_t id,
        const std::shared_ptr<IntfImpl> &intfImpl)
    : SimpleC2Component(std::make_shared<SimpleInterface<IntfImpl>>(name, id, intfImpl)),
      mIntf(intfImpl),
      mInstance(nullptr),
      mFrameSize(0),
      mOutBufferSize(0),
      mOutSampleRate(0),
      mSentCodecSpecificData(false),
      mSignalledError(0)
{
}

C2SoftXheAacEnc::C2SoftXheAacEnc(
        const char *name,
        c2_node_id_t id,
        const std::shared_ptr<C2ReflectorHelper> &helper)
    : C2SoftXheAacEnc(name, id, std::make_shared<IntfImpl>(helper)) {
}

C2SoftXheAacEnc::~C2SoftXheAacEnc() {
    onReset();
}

c2_status_t C2SoftXheAacEnc::onInit() {
    ALOGV("onInit");
    return initEncoder();
}

static IIS_XHEAACENC_CHANNELCONFIG getChannelConfig(uint32_t nChannels) {
    IIS_XHEAACENC_CHANNELCONFIG config = IIS_XHEAACENC_CHANNELCONFIG_INVALID;
    switch (nChannels) {
        case 1: config = IIS_XHEAACENC_CHANNELCONFIG_MONO; break;
        case 2: config = IIS_XHEAACENC_CHANNELCONFIG_STEREO; break;
        default:
            config = IIS_XHEAACENC_CHANNELCONFIG_INVALID;
            ALOGE("xHE-AAC only supports mono and stereo channel configuration.");
    }
    return config;
}

c2_status_t C2SoftXheAacEnc::initEncoder() {
    ALOGV("initEncoder");
    auto config = setAudioParams();
    if (!config) {
        ALOGV("bad config");
        return C2_BAD_VALUE;
    }
    ALOGV("opening encoder");
    if (IIS_XHEAACENC_NO_ERROR != IIS_xHEAACEnc_Open(&mInstance, config)) {
        ALOGE("Failed to init xHE-AAC encoder");
        IIS_xHEAACEnc_Config_Delete(config);
        return C2_CORRUPTED;
    }
    ALOGV("deleting config");
    IIS_xHEAACEnc_Config_Delete(config);

    ALOGV("getting buffer size");
    if (IIS_XHEAACENC_NO_ERROR != IIS_xHEAACEnc_GetParam(mInstance,
                IIS_XHEAACENC_PARAMETER_MIN_OUTBUF_SIZE, IIS_XHEAACENC_PARAM_AUTO,
                &mOutBufferSize, sizeof(mOutBufferSize))) {
        ALOGE("Failed to get xHE-AAC encoder config parameters enc buf");
        return C2_CORRUPTED;
    }

    ALOGV("getting frame size");
    if (IIS_XHEAACENC_NO_ERROR != IIS_xHEAACEnc_GetParam(mInstance,
            IIS_XHEAACENC_PARAMETER_FRAMESAMPLES, IIS_XHEAACENC_PARAM_AUTO, &mFrameSize,
            sizeof(mFrameSize))) {
        ALOGE("Failed to get xHE-AAC encoder config parameters enc frame");
        return C2_CORRUPTED;
    }

    ALOGV("getting sample rate");
    if (IIS_XHEAACENC_NO_ERROR != IIS_xHEAACEnc_GetParam(mInstance,
                IIS_XHEAACENC_PARAMETER_OUTSAMPLERATE, IIS_XHEAACENC_PARAM_AUTO, &mOutSampleRate,
                sizeof(mOutSampleRate))) {
        ALOGE("Failed to get xHE-AAC encoder config parameters enc sample rate");
        return C2_CORRUPTED;
    }

    ALOGV("done initializing encoder");
    return C2_OK;
}

c2_status_t C2SoftXheAacEnc::onStop() {
    ALOGV("onStop");
    mSentCodecSpecificData = false;
    mSignalledError = false;
    return C2_OK;
}

void C2SoftXheAacEnc::onReset() {
    ALOGV("onReset");
    (void)onStop();
    if (mInstance != nullptr) {
        IIS_xHEAACEnc_Delete(mInstance);
        mInstance = nullptr;
    }
    mInputBuffer.clear();
    mFrameSize = 0;
    mOutBufferSize = 0;
    mOutSampleRate = 0;
    mNextFrameTimestampOutputTicks.reset();
    mLastFrameEndTimestampUs.reset();
    mOutIndex = 0;
}

void C2SoftXheAacEnc::onRelease() {
    ALOGV("onRelease");
}

c2_status_t C2SoftXheAacEnc::onFlush_sm() {
    ALOGV("onFlush_sm");
    mSentCodecSpecificData = false;
    return C2_OK;
}

static constexpr const char* getWarningText(IIS_XHEAACENC_WARNING code) noexcept {
    switch (code) {
        case IIS_XHEAACENC_WARN_INVALID_CONFIG:
            return "The given parameter list does not result in a valid encoder configuration";
        case IIS_XHEAACENC_WARN_LOUDNESS_DEVIATION:
            return "User provided loudness level deviates between 2-10 LUFS as compared against"
                   "internal calculations";
        case IIS_XHEAACENC_WARN_LARGE_LOUDNESS_DEVIATION:
            return "User provided loudness level deviates by more than 10 LUFS as compared"
                   "against internal calculations";
        case IIS_XHEAACENC_WARN_SAMPLE_PEAK_DEVIATION:
            return "User provided sample peak value deviates by more than 0.5dB as compared"
                   "against internal calculations";
        case IIS_XHEAACENC_WARN_TOO_FEW_SAMPLES_TO_VALIDATE_LOUDNESS:
            return "User has provided too few samples to validate the loudness level internally";
        case IIS_XHEAACENC_WARN_MORE_SAMPLES_EXPECTED:
            return "User has provided too few samples as compared to the imported loudness data";
        case IIS_XHEAACENC_WARN_QUIET_MEASURED_LOUDNESS:
            return "Measured loudness level is below the quiet loudness threshold";
        default:
            return "(other)";
    }
}

IIS_XHEAACENC_CONFIG_INSTANCE_HANDLE C2SoftXheAacEnc::setAudioParams() {
    // We call when initializing the encoder for encoding.
    ALOGV("setAudioParams");
    IIS_XHEAACENC_CONFIG_INSTANCE_HANDLE config = nullptr;
    if (mIntf->getBitrateMode() == C2Config::BITRATE_CONST) {
        ALOGV("setAudioParams: %u Hz, %u channels, constant %u bps",
              mIntf->getSampleRate(), mIntf->getChannelCount(), mIntf->getBitrate());
    } else {
        ALOGV("setAudioParams: %u Hz, %u channels, VBR%u",
              mIntf->getSampleRate(), mIntf->getChannelCount(), mIntf->getQuality());
    }

    ALOGV("opening config");
    if (IIS_XHEAACENC_NO_ERROR != IIS_xHEAACEnc_Config_Open(
            &config, mIntf->getSampleRate(), getChannelConfig(mIntf->getChannelCount()))) {
        ALOGE("Failed to open xHE-AAC encoder configuration");
        return nullptr;
    }

    ALOGV("setting IIS_XHEAACENC_PARAMETER_LIVE_LOUDNESS_LEVEL");
    if (IIS_XHEAACENC_NO_ERROR != IIS_xHEAACEnc_Config_AddParamValueFloat(
            config, IIS_XHEAACENC_PARAMETER_LIVE_LOUDNESS_LEVEL, -24)) {
        ALOGE("Failed to set xHE-AAC encoder config parameters");
        return nullptr;
    }

    ALOGV("setting IIS_XHEAACENC_PARAMETER_LIVE_MODE");
    // Use the general live mode.
    if (IIS_XHEAACENC_NO_ERROR != IIS_xHEAACEnc_Config_AddParamValueInt(
            config, IIS_XHEAACENC_PARAMETER_LIVE_MODE, 0)) {
        ALOGE("Failed to set xHE-AAC encoder config parameters");
        return nullptr;
    }

    ALOGV("setting IIS_XHEAACENC_PARAMETER_AOT");
    if (IIS_XHEAACENC_NO_ERROR != IIS_xHEAACEnc_Config_AddParamValueInt(config,
            IIS_XHEAACENC_PARAMETER_AOT, IIS_XHEAACENC_AOT_USAC)) {
        ALOGE("Failed to set xHE-AAC encoder config parameters");
        return nullptr;
    }

    auto bitrateMode = IIS_XHEAACENC_BITRATEMODE_INVALID;
    if (mIntf->getBitrateMode() == C2Config::BITRATE_CONST) {
        bitrateMode = IIS_XHEAACENC_BITRATEMODE_CBR;
    } else if (mIntf->getQuality() == 0) {
        bitrateMode = IIS_XHEAACENC_BITRATEMODE_AAC_VBR0;
    } else {
        bitrateMode = static_cast<IIS_XHEAACENC_BITRATEMODE>(
                IIS_XHEAACENC_BITRATEMODE_AAC_VBR1 + mIntf->getQuality() - 1);
    }

    ALOGV("setting IIS_XHEAACENC_PARAMETER_BITRATEMODE");
    if (IIS_XHEAACENC_NO_ERROR != IIS_xHEAACEnc_Config_AddParamValueInt(
            config, IIS_XHEAACENC_PARAMETER_BITRATEMODE, bitrateMode)) {
        ALOGE("Failed to set xHE-AAC encoder config parameters");
        return nullptr;
    }

    ALOGV("setting IIS_XHEAACENC_PARAMETER_BITRATE");
    if (mIntf->getBitrateMode() == C2Config::BITRATE_CONST) {
        if (IIS_XHEAACENC_NO_ERROR != IIS_xHEAACEnc_Config_AddParamValueInt(
                config, IIS_XHEAACENC_PARAMETER_BITRATE, mIntf->getBitrate())) {
            ALOGE("Failed to set xHE-AAC encoder config parameters");
            return nullptr;
        }
    }
    ALOGV("setting IIS_XHEAACENC_PARAMETER_TRANSPORTFORMAT");
    if (IIS_XHEAACENC_NO_ERROR != IIS_xHEAACEnc_Config_AddParamValueInt(
            config, IIS_XHEAACENC_PARAMETER_TRANSPORTFORMAT, IIS_XHEAACENC_TRANSPORTFORMAT_RAW)) {
        ALOGE("Failed to set xHE-AAC encoder config parameters");
        return nullptr;
    }

    ALOGV("setting IIS_XHEAACENC_PARAMETER_STREAMID");
    if (IIS_XHEAACENC_NO_ERROR != IIS_xHEAACEnc_Config_AddParamValueInt(
            config, IIS_XHEAACENC_PARAMETER_STREAMID, mIntf->getStreamId())) {
        ALOGE("Failed to set xHE-AAC encoder config parameters");
        return nullptr;
    }

    ALOGV("setting IIS_XHEAACENC_PARAMETER_RAP_INTERVAL_MS");
    if (mIntf->getConstantRapInterval() > 0 &&
        IIS_XHEAACENC_NO_ERROR != IIS_xHEAACEnc_Config_AddParamValueInt(
            config, IIS_XHEAACENC_PARAMETER_RAP_INTERVAL_MS, mIntf->getConstantRapInterval())) {
        ALOGE("Failed to set xHE-AAC encoder config parameters");
        return nullptr;
    }

    ALOGV("finalizing config");
    auto code = IIS_xHEAACEnc_Config_Finalize(config);
    if (code == IIS_XHEAACENC_WARNING_CONFIG || code == IIS_XHEAACENC_WARNING_INVALID_CONFIG) {
        int numWarnings = 0;
        const IIS_XHEAACENC_WARNING* warnings = nullptr;
        IIS_xHEAACEnc_GetConfigWarnings(config, &numWarnings, &warnings);
        for (int i = 0; i < numWarnings; ++i) {
            ALOGW("Warning in xHE-AAC encoder configuration: %s", getWarningText(warnings[i]));
        }
    } else if (code != IIS_XHEAACENC_NO_ERROR) {
        ALOGE("Failed to finalize xHE-AAC encoder config");
        return nullptr;
    }

    ALOGV("done with config");
    return config;
}


static void MaybeLogTimestampWarning(
        long long lastFrameEndTimestampUs, long long inputTimestampUs) {
    using Clock = std::chrono::steady_clock;
    thread_local Clock::time_point sLastLogTimestamp{};
    thread_local int32_t sOverlapCount = -1;
    if (Clock::now() - sLastLogTimestamp > std::chrono::minutes(1) || sOverlapCount < 0) {
        AString countMessage = "";
        if (sOverlapCount > 0) {
            countMessage = AStringPrintf(
                    "(%d overlapping timestamp detected since last log)", sOverlapCount);
        }
        ALOGI("Correcting overlapping timestamp: last frame ended at %lldus but "
              "current frame is starting at %lldus. Using the last frame's end timestamp %s",
              lastFrameEndTimestampUs, inputTimestampUs, countMessage.c_str());
        sLastLogTimestamp = Clock::now();
        sOverlapCount = 0;
    } else {
        ALOGV("Correcting overlapping timestamp: last frame ended at %lldus but "
              "current frame is starting at %lldus. Using the last frame's end timestamp",
              lastFrameEndTimestampUs, inputTimestampUs);
        ++sOverlapCount;
    }
}

static c2_status_t fetchLinearBlock(C2BlockPool& pool, uint32_t size,
                                    std::shared_ptr<C2LinearBlock>* block)
{
    C2MemoryUsage usage = { C2MemoryUsage::CPU_READ, C2MemoryUsage::CPU_WRITE };
    c2_status_t err = pool.fetchLinearBlock(size, usage, block);
    if (err != C2_OK) {
        ALOGE("fetchLinearBlock failed : err = %d", err);
    }
    return err;
}

void C2SoftXheAacEnc::process(
        const std::unique_ptr<C2Work> &work,
        const std::shared_ptr<C2BlockPool> &pool) {

    // Initialize output work
    work->result = C2_OK;
    work->workletsProcessed = 1u;
    work->worklets.front()->output.flags = work->input.flags;

    if (mSignalledError) {
        return;
    }

    bool eos = (work->input.flags & C2FrameData::FLAG_END_OF_STREAM) != 0;

    uint32_t channelCount = mIntf->getChannelCount();

    if (!mSentCodecSpecificData) {
        IIS_XHEAACENC_ASCINFO xHEAACAscInfo{};
        if (IIS_XHEAACENC_NO_ERROR != IIS_xHEAACEnc_GetAscInfo(mInstance, &xHEAACAscInfo)) {
            ALOGE("Failed to get xHE-AAC encoder config parameters ASC INFO");
            return;
        }

        uint32_t ascSizeBytes = xHEAACAscInfo.ascSizeBits / 8
                                + (xHEAACAscInfo.ascSizeBits % 8 ? 1 : 0);
        std::unique_ptr<C2StreamInitDataInfo::output> csd =
                C2StreamInitDataInfo::output::AllocUnique(ascSizeBytes, 0u);
        if (!csd) {
            ALOGE("CSD allocation failed");
            mSignalledError = true;
            work->result = C2_NO_MEMORY;
            return;
        }
        memcpy(csd->m.value, xHEAACAscInfo.ascBuffer, ascSizeBytes);
        ALOGV("put csd: %u bytes", ascSizeBytes);
        work->worklets.front()->output.configUpdate.push_back(std::move(csd));

        // Send update in sample format, if it differs
        if (mOutSampleRate != mIntf->getSampleRate()) {
            C2StreamSampleRateInfo::output sampleRateInfo(0u, mOutSampleRate);

            std::vector<std::unique_ptr<C2SettingResult>> failures;
            c2_status_t err = mIntf->config({ &sampleRateInfo }, C2_MAY_BLOCK, &failures);
            if (err == C2_OK) {
                work->worklets.front()->output.configUpdate.push_back(
                        C2Param::Copy(sampleRateInfo));
            } else {
                ALOGE("Config Update failed");
                mSignalledError = true;
                work->result = C2_CORRUPTED;
                return;
            }
        }

        mSentCodecSpecificData = true;
    }

    uint8_t temp[1];
    C2ReadView view = mDummyReadView;
    const uint8_t *data = temp;
    uint32_t capacity = 0u;
    if (!work->input.buffers.empty()) {
        view = work->input.buffers[0]->data().linearBlocks().front().map().get();
        data = view.data();
        capacity = view.capacity();
        if (capacity && view.error()) {
            ALOGE("error reading C2Work view: %d", view.error());
            work->result = C2_CORRUPTED;
            return;
        }
    }

    c2_cntr64_t inputTimestampUs = work->input.ordinal.timestamp;
    if (inputTimestampUs < mLastFrameEndTimestampUs.value_or(inputTimestampUs)) {
        MaybeLogTimestampWarning(mLastFrameEndTimestampUs->peekll(),
                                 inputTimestampUs.peekll());
        inputTimestampUs = *mLastFrameEndTimestampUs;
    }
    if (capacity > 0 || eos) {
        if (!mNextFrameTimestampOutputTicks) {
            mNextFrameTimestampOutputTicks = ((work->input.ordinal.timestamp.peeku()
                    * mOutSampleRate + 500'000ll) / 1'000'000ll);
        }
        mLastFrameEndTimestampUs = inputTimestampUs + (capacity / sizeof(int16_t) * 1'000'000ll
                                                       / channelCount / mIntf->getSampleRate());
    }

    std::shared_ptr<C2LinearBlock> block;
    std::unique_ptr<C2WriteView> wView;

    uint64_t inputIndex = work->input.ordinal.frameIndex.peeku();

    class FillWork {
      public:
        FillWork(uint32_t flags, C2WorkOrdinalStruct ordinal,
                 const std::shared_ptr<C2Buffer> &buffer)
            : mFlags(flags), mOrdinal(ordinal), mBuffer(buffer) {
        }
        ~FillWork() = default;

        void operator()(const std::unique_ptr<C2Work> &work) {
            work->worklets.front()->output.flags = (C2FrameData::flags_t)mFlags;
            work->worklets.front()->output.buffers.clear();
            work->worklets.front()->output.ordinal = mOrdinal;
            work->workletsProcessed = 1u;
            work->result = C2_OK;
            if (mBuffer) {
                work->worklets.front()->output.buffers.push_back(mBuffer);
            }
            ALOGV("timestamp = %lld, index = %lld, w/%s buffer",
                  mOrdinal.timestamp.peekll(),
                  mOrdinal.frameIndex.peekll(),
                  mBuffer ? "" : "o");
        }

      private:
        const uint32_t mFlags;
        const C2WorkOrdinalStruct mOrdinal;
        const std::shared_ptr<C2Buffer> mBuffer;
    };

    struct OutputBuffer {
        std::shared_ptr<C2Buffer> buffer;
        c2_cntr64_t timestampOutputTicks;
    };
    std::list<OutputBuffer> outputBuffers{};

    IIS_XHEAACENC_RETURN_CODE encoderErr = IIS_XHEAACENC_NO_ERROR;
    auto encoderState = IIS_XHEAACENC_ENCODER_STATE_STARTUP;
    while ((encoderErr == IIS_XHEAACENC_NO_ERROR) &&
           (encoderState != IIS_XHEAACENC_ENCODER_STATE_READY_TO_CLOSE) &&
           (capacity > 0 || eos)) {
        // collect and convert input samples
        uint32_t nSamplesNext = 0;
        if (IIS_xHEAACEnc_GetParam(mInstance, IIS_XHEAACENC_PARAMETER_SAMPLES_NEXT,
                                   IIS_XHEAACENC_PARAM_AUTO, &nSamplesNext, sizeof(int))) {
            ALOGE("Failed to get xHE-AAC encoder config parameters nSamplesNext");
            work->result = C2_BAD_VALUE;
            return;
        }
        mInputBuffer.reserve(nSamplesNext);
        uint32_t samplesMissing = nSamplesNext - mInputBuffer.size();
        uint32_t samplesRead = std::min(capacity / (uint32_t)sizeof(int16_t), samplesMissing);
        ALOGV("nSamplesNext = %u, capacity = %u, samplesRead = %u, eos = %u", nSamplesNext,
              (uint32_t)(capacity/sizeof(int16_t)), samplesRead, eos);

        for (int i=0; i < samplesRead; ++i) {
            int32_t sample = data[2 * i + 1] << 8 | data[2 * i];
            sample = ((sample & 0xFFFF) ^ 0x8000) - 0x8000;
            mInputBuffer.push_back((float)sample / INT16_MAX);
        }
        capacity -= samplesRead * sizeof(int16_t);
        data += samplesRead * sizeof(int16_t);

        if (!eos && mInputBuffer.size() < nSamplesNext) {
            break;
        }

        // obtain memory for output
        if (!block) {
            if (C2_OK != fetchLinearBlock(*pool, mOutBufferSize, &block)) {
                work->result = C2_NO_MEMORY;
                return;
            }
            wView.reset(new C2WriteView(block->map().get()));
        }

        IIS_XHEAACENC_AUINFO auInfo;
        int outBytes = 0;
        // in case of eos, allow feeding fewer samples, but ensure all channels are fed the same
        // amount
        uint32_t inSamples = (mInputBuffer.size() / channelCount) * channelCount;
        encoderErr = IIS_xHEAACEnc_EncodeFrame(mInstance,
                                               mInputBuffer.data(),
                                               inSamples,
                                               wView->data(),
                                               &outBytes,
                                               wView->size(),
                                               &auInfo);

        if (encoderErr < IIS_XHEAACENC_ERROR_FIRST) {
            if (outBytes > 0) {
                c2_cntr64_t currentFrameTimestampOutputTicks = *mNextFrameTimestampOutputTicks;
                mNextFrameTimestampOutputTicks = currentFrameTimestampOutputTicks
                                                 + auInfo.auSamplesValid;
                outputBuffers.emplace_back(createLinearBuffer(block, 0, outBytes),
                                           currentFrameTimestampOutputTicks);

                if (auInfo.isSyncFrame == IIS_XHEAACENC_SYNCFRAME_IMMEDIATE_PLAY_OUT_FRAME) {
                    ALOGV("Sync frame produced");
                    outputBuffers.back().buffer->setInfo(
                            std::make_shared<C2StreamPictureTypeMaskInfo::output>(
                                    0u /* stream id */, C2Config::SYNC_FRAME));
                }
                wView.reset();
                block.reset();
            }

            encoderErr = IIS_xHEAACEnc_GetEncoderState(mInstance, &encoderState);
        } else {
            ALOGE("EncodeFrame call failed: %d", encoderErr);
            capacity = 0;
            mSignalledError = true;
            work->result = C2_CORRUPTED;
            return;
        }
        ALOGV("encoderErr = %d, encoderState = %d, auSamplesValid = %d, capacity = %u,"
              "inSamples = %d, outBytes = %d, mNextFrameTimestampOutputTicks = %lld, eos = %u",
              encoderErr, encoderState, auInfo.auSamplesValid,
              (uint32_t)(capacity/sizeof(int16_t)), inSamples, outBytes,
              mNextFrameTimestampOutputTicks->peekll(), eos);
        mInputBuffer.clear();
    }

    while (outputBuffers.size() > 1) {
        const OutputBuffer& front = outputBuffers.front();
        C2WorkOrdinalStruct ordinal = work->input.ordinal;
        ordinal.frameIndex = mOutIndex++;
        ordinal.timestamp = (front.timestampOutputTicks.peeku() * 1'000'000LL
                             + (mOutSampleRate / 2)) / mOutSampleRate;
        cloneAndSend(
                inputIndex,
                work,
                FillWork(C2FrameData::FLAG_INCOMPLETE, ordinal, front.buffer));
        outputBuffers.pop_front();
    }

    std::shared_ptr<C2Buffer> buffer;
    C2WorkOrdinalStruct ordinal = work->input.ordinal;

    if (!outputBuffers.empty()) {
        ordinal.timestamp = (outputBuffers.front().timestampOutputTicks.peeku() * 1'000'000LL
                             + (mOutSampleRate / 2)) / mOutSampleRate;
        buffer = outputBuffers.front().buffer;
    }

    ordinal.frameIndex = mOutIndex++;
    if (eos) {
        cloneAndSend(
                inputIndex,
                work,
                FillWork(C2FrameData::FLAG_INCOMPLETE, ordinal, buffer));
        // Schedule a separate work without buffer to properly signal the end of the
        // (possibly shorter) last frame
        C2WorkOrdinalStruct eosOrdinal = work->input.ordinal;
        eosOrdinal.frameIndex = mOutIndex++;
        eosOrdinal.timestamp = (mNextFrameTimestampOutputTicks.value_or(0U).peeku() * 1'000'000LL
                             + (mOutSampleRate / 2)) / mOutSampleRate;
        // Mark the end of stream
        FillWork(C2FrameData::FLAG_END_OF_STREAM, eosOrdinal, nullptr)(work);
    } else {
        // Mark the end of frame
        FillWork((C2FrameData::flags_t)(0), ordinal, buffer)(work);
    }
}

c2_status_t C2SoftXheAacEnc::drain(
        uint32_t drainMode,
        const std::shared_ptr<C2BlockPool> &pool) {
    (void) drainMode;
    (void) pool;
    switch (drainMode) {
        case DRAIN_COMPONENT_NO_EOS:
            [[fallthrough]];
        case NO_DRAIN:
            return C2_OK;
        case DRAIN_CHAIN:
            return C2_OMITTED;
        case DRAIN_COMPONENT_WITH_EOS:
            break;
        default:
            return C2_BAD_VALUE;
    }

    (void)pool;
    mSentCodecSpecificData = false;
    mNextFrameTimestampOutputTicks.reset();
    mLastFrameEndTimestampUs.reset();
    return C2_OK;
}

class C2SoftXheAacEncFactory : public C2ComponentFactory {
  public:
    C2SoftXheAacEncFactory() : mHelper(std::static_pointer_cast<C2ReflectorHelper>(
                                       GetCodec2PlatformComponentStore()->getParamReflector())) {
    }

    virtual c2_status_t createComponent(
            c2_node_id_t id,
            std::shared_ptr<C2Component>* const component,
            std::function<void(C2Component*)> deleter) override {
        *component = std::shared_ptr<C2Component>(
                new C2SoftXheAacEnc(COMPONENT_NAME,
                                    id,
                                    std::make_shared<C2SoftXheAacEnc::IntfImpl>(mHelper)),
                deleter);
        return C2_OK;
    }

    virtual c2_status_t createInterface(
            c2_node_id_t id, std::shared_ptr<C2ComponentInterface>* const interface,
            std::function<void(C2ComponentInterface*)> deleter) override {
        *interface = std::shared_ptr<C2ComponentInterface>(
                new SimpleInterface<C2SoftXheAacEnc::IntfImpl>(
                        COMPONENT_NAME, id, std::make_shared<C2SoftXheAacEnc::IntfImpl>(mHelper)),
                deleter);
        return C2_OK;
    }

    virtual ~C2SoftXheAacEncFactory() override = default;

  private:
    std::shared_ptr<C2ReflectorHelper> mHelper;
};

}  // namespace android

__attribute__((cfi_canonical_jump_table))
extern "C" ::C2ComponentFactory* CreateCodec2Factory() {
    ALOGV("in %s", __func__);
    if (!android::media::swcodec::flags::xhe_aac_software_encoder()) {
        ALOGV("xHE-AAC SW Codec is not enabled");
        return nullptr;
    }

    int apiLevel = android_get_device_api_level();
    bool isPreview = (android::base::GetIntProperty("ro.build.version.preview_sdk", 0) != 0);
    if (isPreview) {
        apiLevel++;
    }
    if (apiLevel < 37) {
        ALOGV("xHE-AAC SW Codec is not supported on API level %d", apiLevel);
        return nullptr;
    }

    return new ::android::C2SoftXheAacEncFactory();
}

__attribute__((cfi_canonical_jump_table))
extern "C" void DestroyCodec2Factory(::C2ComponentFactory* factory) {
    ALOGV("in %s", __func__);
    delete factory;
}
