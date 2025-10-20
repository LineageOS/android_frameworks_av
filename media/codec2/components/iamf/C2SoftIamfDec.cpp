/*
 * Copyright (C) 2024 The Android Open Source Project
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
#define LOG_TAG "C2SoftIamfDec"

#include "C2SoftIamfDec.h"

#include <cstddef>
#include <cstdint>
#include <optional>

#include <C2PlatformSupport.h>
#include <SimpleC2Interface.h>
#include <android-base/properties.h>
#include <android_media_swcodec_flags.h>
#include <iamf_tools/iamf_decoder_factory.h>
#include <iamf_tools/iamf_decoder_interface.h>
#include <iamf_tools/iamf_tools_api_types.h>
#include <log/log.h>
#include <media/stagefright/foundation/MediaDefs.h>  // For MEDIA_MIMETYPE_AUDIO_IAMF

#include "LayoutTranslation.h"

namespace android {
namespace {
constexpr char COMPONENT_NAME[] = "c2.android.iamf.decoder";

}  // namespace

using ::iamf_tools::api::IamfDecoderFactory;
using ::iamf_tools::api::IamfDecoderInterface;
using ::iamf_tools::api::IamfStatus;
using ::std::shared_ptr;

class C2SoftIamfDec::IntfImpl : public SimpleInterface<void>::BaseParams {
  public:
    explicit IntfImpl(const shared_ptr<C2ReflectorHelper>& helper)
        : SimpleInterface<void>::BaseParams(helper, COMPONENT_NAME, C2Component::KIND_DECODER,
                                            C2Component::DOMAIN_AUDIO, MEDIA_MIMETYPE_AUDIO_IAMF) {
        noInputLatency();
        noPrivateBuffers();
        noInputReferences();
        noOutputReferences();
        noTimeStretch();
        setDerivedInstance(this);

        addParameter(DefineParam(mAttrib, C2_PARAMKEY_COMPONENT_ATTRIBUTES)
                             .withConstValue(new C2ComponentAttributesSetting(
                                     C2Component::ATTRIB_IS_TEMPORAL))
                             .build());

        // ===== Parameters for the input bitstream =====
        // The profile will be updated by the decoder once the DescriptorObus have all been parsed.
        // Level is unused by IAMF.
        // The profiles requested are set in GetIamfDecoderSettings and used to initialize the
        // decoder.
        std::vector<unsigned int> profiles = {
                C2Config::PROFILE_IAMF_SIMPLE_OPUS,
                C2Config::PROFILE_IAMF_SIMPLE_PCM,
                C2Config::PROFILE_IAMF_BASE_OPUS,
                C2Config::PROFILE_IAMF_BASE_PCM,
        };
        if (android::media::swcodec::flags::iamf_aac_flac()) {
            profiles.push_back(C2Config::PROFILE_IAMF_SIMPLE_FLAC);
            profiles.push_back(C2Config::PROFILE_IAMF_BASE_FLAC);
            profiles.push_back(C2Config::PROFILE_IAMF_SIMPLE_AAC);
            profiles.push_back(C2Config::PROFILE_IAMF_BASE_AAC);
        }
        addParameter(
                DefineParam(mProfileLevel, C2_PARAMKEY_PROFILE_LEVEL)
                        .withDefault(new C2StreamProfileLevelInfo::input(
                                0u, C2Config::PROFILE_IAMF_SIMPLE_PCM, C2Config::LEVEL_UNUSED))
                        .withFields({C2F(mProfileLevel, profile).oneOf(profiles),
                                     C2F(mProfileLevel, level).oneOf({C2Config::LEVEL_UNUSED})})
                        .withSetter(ProfileLevelSetter)
                        .build());

        addParameter(DefineParam(mInputMaxBufSize, C2_PARAMKEY_INPUT_MAX_BUFFER_SIZE)
                             // Starting with a safe max size based on max(opus,aac,flac) + space
                             // for DescriptorObus. Opus: 960*6, Aac: 8196, Flac: 32768
                             .withConstValue(new C2StreamMaxBufferSizeInfo::input(0u, 36000))
                             .build());

        // ===== Params for the output audio =====
        // The max output channel count is a way of setting the requested output layout when
        // CHANNEL_MASK cannot be used due to API level.  Default to 0 so we can see when it is set.
        // IN/OUT details: Optionally set by the caller and read by the decoder.
        addParameter(
                DefineParam(mMaxOutputChannelCount, C2_PARAMKEY_MAX_CHANNEL_COUNT)
                        .withDefault(new C2StreamMaxChannelCountInfo::output(
                                0u, UNSET_MAX_OUTPUT_CHANNELS))
                        .withFields({C2F(mMaxOutputChannelCount, value).any()})
                        .withSetter(
                                Setter<decltype(*mMaxOutputChannelCount)>::StrictValueWithNoDeps)
                        .build());

        // The ChannelMask represents what the physical speaker layout of the decoded (output)
        // audio. Only a fixed set of Layouts are supported by IAMF and the any given Layout might
        // not be present in the given file.  The actual Layout of the output audio is updated once
        // the DescriptorObus are processed.
        //
        // IN/OUT details: Set by the caller (if possible based on API level), then read by the
        // decoder (instead of MAX_OUTPUT_CHANNELS).  In either case, it is set the decoder and read
        // by the caller to see what output layout is actually produced.
        addParameter(
                DefineParam(mRenderedChannelMask, C2_PARAMKEY_CHANNEL_MASK)
                        .withDefault(
                                new C2StreamChannelMaskInfo::output(0u, UNSET_OUTPUT_CHANNEL_MASK))
                        .withFields({C2F(mRenderedChannelMask, value).inRange(0, 4294967292)})
                        .withSetter(Setter<decltype(*mRenderedChannelMask)>::StrictValueWithNoDeps)
                        .build());

        // Channel Count matches the ChannelMask above.
        // IN/OUT details: Set by the decoder and read by the caller.
        addParameter(DefineParam(mChannelCount, C2_PARAMKEY_CHANNEL_COUNT)
                             .withDefault(new C2StreamChannelCountInfo::output(0u, 0))
                             .withFields({C2F(mChannelCount, value).inRange(1, 24)})
                             .withSetter(Setter<decltype(*mChannelCount)>::StrictValueWithNoDeps)
                             .build());

        // The sample rate will be determined by the content in the IAMF stream and updated once the
        // DescriptorObus are processed.
        // IN/OUT details: Set by the decoder, read by the caller.
        addParameter(DefineParam(mSampleRate, C2_PARAMKEY_SAMPLE_RATE)
                             .withDefault(new C2StreamSampleRateInfo::output(0u, 48000))
                             // This decoder is currently PCM and Opus only.
                             // IAMF spec allows PCM with sample rates {44.1k, 16k, 32k, 48k, 96k}.
                             .withFields({C2F(mSampleRate, value)
                                                  .oneOf({16000, 32000, 44100, 48000, 96000})})
                             .withSetter((Setter<decltype(*mSampleRate)>::StrictValueWithNoDeps))
                             .build());

        // Only output audio in 16-bit ints are supported by this decoder.
        // N.B.: Calculation of output buffer size below in this file assumes int16_t samples.
        addParameter(
                DefineParam(mPcmEncodingInfo, C2_PARAMKEY_PCM_ENCODING)
                        .withDefault(new C2StreamPcmEncodingInfo::output(0u, C2Config::PCM_16))
                        .withFields({C2F(mPcmEncodingInfo, value).oneOf({C2Config::PCM_16})})
                        .withSetter((Setter<decltype(*mPcmEncodingInfo)>::StrictValueWithNoDeps))
                        .build());
    }

    uint32_t getOutputChannelMask() const { return mRenderedChannelMask->value; }
    uint32_t getMaxOutputChannelCount() const { return mMaxOutputChannelCount->value; }
    C2Config::pcm_encoding_t getOutputPcmEncoding() const { return mPcmEncodingInfo->value; }

    static C2R ProfileLevelSetter(bool mayBlock, C2P<C2StreamProfileLevelInfo::input>& me) {
        (void)mayBlock;
        (void)me;  // TODO: validate
        return C2R::Ok();
    }

  private:
    // Params relating to the input IAMF bitstream.
    shared_ptr<C2StreamProfileLevelInfo::input> mProfileLevel;
    shared_ptr<C2StreamMaxBufferSizeInfo::input> mInputMaxBufSize;
    // Params relating to the output audio.
    shared_ptr<C2StreamChannelMaskInfo::output> mRenderedChannelMask;
    std::shared_ptr<C2StreamChannelCountInfo::output> mChannelCount;
    std::shared_ptr<C2AudioPresentationIdTuning> mMixPresentationId;
    std::shared_ptr<C2StreamMaxChannelCountInfo::output> mMaxOutputChannelCount;
    shared_ptr<C2StreamSampleRateInfo::output> mSampleRate;
    shared_ptr<C2StreamPcmEncodingInfo::output> mPcmEncodingInfo;
};

C2SoftIamfDec::C2SoftIamfDec(const char* name, c2_node_id_t id,
                             const shared_ptr<IntfImpl>& intfImpl)
    : SimpleC2Component(std::make_shared<SimpleInterface<IntfImpl>>(name, id, intfImpl)),
      mIntf(intfImpl) {}

C2SoftIamfDec::~C2SoftIamfDec() {
    onRelease();
}

std::optional<iamf_tools::api::OutputLayout> C2SoftIamfDec::getTargetOutputLayout() {
    // The channel count or channel mask may be used to set the output layout since channel mask was
    // not available to configure the decoder prior to 25Q2.  The second time the layout is changed,
    // both of them will be set based on what is reported by the decoder, so we must be careful that
    // we're using the actual new layout, as opposed to just reusing a value from a previous config.
    auto currentChannelMask = mIntf->getOutputChannelMask();
    auto currentChannelCount = mIntf->getMaxOutputChannelCount();
    const bool channelMaskChanged = mCachedOutputChannelMask != currentChannelMask;

    if (currentChannelMask != UNSET_OUTPUT_CHANNEL_MASK && channelMaskChanged) {
        ALOGI("Channel mask set, trying to use value %d", currentChannelMask);
        // If the channel mask has been set, we'll use that.
        return c2_soft_iamf_internal::GetIamfLayout(currentChannelMask);
    }
    // Fall back to using the max output channels.
    ALOGI("Channel mask not set or unchanged, checking max channel count: %d", currentChannelCount);

    if (currentChannelCount == UNSET_MAX_OUTPUT_CHANNELS) {
        ALOGI("Max output channels not set. We will allow the decoder to pick a default from the "
              "content.");
        return std::nullopt;
    }
    if (currentChannelCount <= 1) {
        ALOGI("max output channels set to %d, using mono.", currentChannelCount);
        return iamf_tools::api::OutputLayout::kIAMF_SoundSystemExtension_0_1_0;
    }
    if (currentChannelCount <= 5) {  // 2 to 5 channels, use stereo.
        ALOGI("max output channels set to %d, using stereo.", currentChannelCount);
        return iamf_tools::api::OutputLayout::kItu2051_SoundSystemA_0_2_0;
    }
    if (currentChannelCount <= 7) {  // 6 or 7 channels, use 5.1.
        ALOGI("max output channels set to %d, using 5.1.", currentChannelCount);
        return iamf_tools::api::OutputLayout::kItu2051_SoundSystemB_0_5_0;
    }
    if (currentChannelCount <= 9) {  // 8 or 9 channels, use 7.1.
        ALOGI("max output channels set to %d, using 7.1.", currentChannelCount);
        return iamf_tools::api::OutputLayout::kItu2051_SoundSystemI_0_7_0;
    }
    if (currentChannelCount == 10) {  // 10 channels, use Sound System D, 5.1.4.
        ALOGI("max output channels set to %d, using Sound System D, (5.1.4)", currentChannelCount);
        return iamf_tools::api::OutputLayout::kItu2051_SoundSystemD_4_5_0;
    }
    if (currentChannelCount == 11) {  // Exactly 11 channels, use Sound System E.
        ALOGI("max output channels set to %d, using Sound System E (4+5+1)", currentChannelCount);
        return iamf_tools::api::OutputLayout::kItu2051_SoundSystemE_4_5_1;
    }
    if (currentChannelCount == 12) {  // Exactly 12 channels, use Sound System J, 7.1.4.
        ALOGI("max output channels set to %d, using Sound System J (7.1.4)", currentChannelCount);
        return iamf_tools::api::OutputLayout::kItu2051_SoundSystemJ_4_7_0;
    }
    if (currentChannelCount <= 15) {  // 13 to 15 channels, use Sound System G (4+9+0)
        ALOGI("max output channels set to %d, using Sound System G (4+9+0)", currentChannelCount);
        return iamf_tools::api::OutputLayout::kItu2051_SoundSystemG_4_9_0;
    }
    if (currentChannelCount < 24) {  // 16 to 23 channels, use 9.1.6
        ALOGI("max output channels set to %d, using 9.1.6", currentChannelCount);
        return iamf_tools::api::OutputLayout::kIAMF_SoundSystemExtension_6_9_0;
    }
    if (currentChannelCount == 24) {  // 24 channels use Sound System H (22.2)
        ALOGI("max output channels set to %d, using Sound System H (22.2)", currentChannelCount);
        return iamf_tools::api::OutputLayout::kItu2051_SoundSystemH_9_10_3;
    }
    // Any other value.
    ALOGW("Max output channels set to %d, but that does not correspond to a valid IAMF layout.  "
          " We will allow the decoder to pick a default from the content.",
          currentChannelCount);
    return std::nullopt;
}

IamfDecoderFactory::Settings C2SoftIamfDec::getIamfDecoderSettings() {
    auto requested_layout = getTargetOutputLayout();
    return {
            .requested_mix = {.output_layout = requested_layout},
            .channel_ordering = ::iamf_tools::api::ChannelOrdering::kOrderingForAndroid,
            .requested_profile_versions =
                    {
                            // Explicitly only request simple and base.
                            ::iamf_tools::api::ProfileVersion::kIamfSimpleProfile,
                            ::iamf_tools::api::ProfileVersion::kIamfBaseProfile,
                    },
            .requested_output_sample_type = ::iamf_tools::api::OutputSampleType::kInt16LittleEndian,
    };
}

void C2SoftIamfDec::resetDecodingState() {
    mIamfDecoder = nullptr;
    mOutputBufferSizeBytes = 0;
    mCreatedWithDescriptorObus = false;
    mFetchedAndUpdatedParameters = false;
    mSignalledError = false;
    mSignalledEos = false;
}

c2_status_t C2SoftIamfDec::createDecoder() {
    ALOGV("Creating new decoder.");
    resetDecodingState();

    const auto settings = getIamfDecoderSettings();
    mIamfDecoder = IamfDecoderFactory::Create(settings);
    if (mIamfDecoder == nullptr) {
        // IamfDecoder::Create fails if it cannot create the ReadBitBuffer.
        mSignalledError = true;
        return C2_NO_MEMORY;
    }
    mCreatedWithDescriptorObus = false;
    ALOGV("Decoder created.");
    return C2_OK;
}

c2_status_t C2SoftIamfDec::createNewDecoderWithDescriptorObus(const uint8_t* data,
                                                              size_t dataSize) {
    ALOGV("Creating new decoder from Descriptor OBUs.");
    resetDecodingState();
    const auto settings = getIamfDecoderSettings();
    mIamfDecoder = IamfDecoderFactory::CreateFromDescriptors(settings, data, dataSize);
    if (mIamfDecoder == nullptr) {
        ALOGW("Failed to create decoder.");
        // IamfDecoder::Create fails if it cannot create the ReadBitBuffer.
        mSignalledError = true;
        return C2_NO_MEMORY;
    }
    mCreatedWithDescriptorObus = true;
    ALOGV("Decoder created with Descriptor OBUs");
    return C2_OK;
}

c2_status_t C2SoftIamfDec::onInit() {
    ALOGV("onInit.");
    // We don't create an underlying decoder here because we don't know if we'll be given
    // Descriptor OBUs or not.  We'll create depending on what we get the first time process
    // receives data.
    resetDecodingState();
    return C2_OK;
}

c2_status_t C2SoftIamfDec::onStop() {
    ALOGV("onStop.");
    // onStop should preserve the mIntf state, but not the underlying decoder.
    resetDecodingState();
    return C2_OK;
}

void C2SoftIamfDec::onReset() {
    ALOGV("onReset.");
    resetDecodingState();
}

void C2SoftIamfDec::onRelease() {
    ALOGV("onRelease.");
    // onRelease, the decoder is guaranteed not to be used again, so we release the decoder.
    resetDecodingState();
}

c2_status_t C2SoftIamfDec::onFlush_sm() {
    ALOGV("onFlush_sm.");
    if (mIamfDecoder != nullptr) {
        IamfStatus status = mIamfDecoder->Reset();  // Throw away any pending work.
        // The decoder may fail to reset if it was not created with DescriptorOBUs.
        if (!status.ok()) {
            ALOGE("Failed to reset. Error: %s", status.error_message.c_str());
            // We failed to Reset.  We'll just get rid of the decoder.
            mIamfDecoder = nullptr;
        }
    }
    // We may be jumping back in time, so we should clear the EOS flag.
    mSignalledEos = false;
    return C2_OK;
}

void C2SoftIamfDec::getAnyTemporalUnits(const std::unique_ptr<C2Work>& work,
                                        const std::shared_ptr<C2BlockPool>& pool) {
    if (mIamfDecoder == nullptr) {
        ALOGV("mIamfDecoder is null, no temporal units to fetch.");
        return;
    }
    while (mIamfDecoder->IsTemporalUnitAvailable()) {
        // Get writing block into a Span for writing by the |mIamfDecoder|.
        shared_ptr<C2LinearBlock> block;
        c2_status_t fetch_block_status =
                pool->fetchLinearBlock(mOutputBufferSizeBytes,
                                       {C2MemoryUsage::CPU_READ, C2MemoryUsage::CPU_WRITE}, &block);
        if (fetch_block_status != C2_OK) {
            ALOGE("fetchLinearBlock for Output failed with status %d", fetch_block_status);
            mSignalledError = true;
            work->result = C2_NO_MEMORY;
            return;
        }
        C2WriteView wView = block->map().get();
        if (wView.error()) {
            ALOGE("write view map failed %d", wView.error());
            mSignalledError = true;
            work->result = C2_CORRUPTED;
            return;
        }
        size_t bytesWritten = 0;
        IamfStatus status = mIamfDecoder->GetOutputTemporalUnit(
                wView.data(), mOutputBufferSizeBytes, bytesWritten);
        if (!status.ok()) {
            ALOGE("Failed to get temporal unit. Error message: %s", status.error_message.c_str());
            mSignalledError = true;
            work->result = C2_CORRUPTED;
            return;
        }
        ALOGV("out buffer attr. size %zu", bytesWritten);
        work->worklets.front()->output.buffers.push_back(
                createLinearBuffer(block, 0, bytesWritten));
        work->worklets.front()->output.ordinal = work->input.ordinal;
    }
}

c2_status_t C2SoftIamfDec::fetchValuesAndUpdateParameters(const std::unique_ptr<C2Work>& work) {
    if (mIamfDecoder == nullptr) {
        ALOGE("mIamfDecoder is null, cannot fetch values.");
        mSignalledError = true;
        work->result = C2_BAD_VALUE;
        return C2_BAD_VALUE;
    }

    // Here we should get the sample rate info and Layout and update.
    uint32_t sampleRate;
    IamfStatus sampleRateStatus = mIamfDecoder->GetSampleRate(sampleRate);
    if (!sampleRateStatus.ok()) {
        ALOGE("Failed to get sample rate. Error message: %s",
              sampleRateStatus.error_message.c_str());
        mSignalledError = true;
        work->result = C2_CORRUPTED;
        return C2_CORRUPTED;
    }
    ALOGV("successfully got sample rate: %d", sampleRate);
    C2StreamSampleRateInfo::output sampleRateInfo(0u, sampleRate);

    // The Layout used may be different than what was requested in IamfDecoder::Create
    // because of the content of the stream.  Here we get the actual Layout that will be
    // used and convert to a ChannelMask.
    ::iamf_tools::api::SelectedMix actualMix;
    IamfStatus outputMixStatus = mIamfDecoder->GetOutputMix(actualMix);
    mActualOutputMix = actualMix;
    if (!outputMixStatus.ok()) {
        ALOGE("Failed to get output layout. Error message: %s",
              outputMixStatus.error_message.c_str());
        mSignalledError = true;
        work->result = C2_CORRUPTED;
        return C2_CORRUPTED;
    }
    ALOGV("successfully got actual output layout: %d", actualMix.output_layout);
    uint32_t actualChannelMask =
            c2_soft_iamf_internal::GetAndroidChannelMask(actualMix.output_layout);
    C2StreamChannelMaskInfo::output channelMaskInfo(0u, actualChannelMask);

    // Get the number of output channels.
    int numOutputChannels;
    IamfStatus numOutputChannelsStatus = mIamfDecoder->GetNumberOfOutputChannels(numOutputChannels);
    if (!numOutputChannelsStatus.ok()) {
        ALOGE("Failed to get number of output channels. Error message: %s",
              numOutputChannelsStatus.error_message.c_str());
        mSignalledError = true;
        work->result = C2_CORRUPTED;
        return C2_CORRUPTED;
    }
    ALOGV("successfully got number of output channels: %d", numOutputChannels);
    C2StreamChannelCountInfo::output channelCountInfo(0u, numOutputChannels);

    // We collect the failures but do not use them.
    std::vector<std::unique_ptr<C2SettingResult>> failures;
    // Update the config in the params.
    const c2_status_t configStatus = mIntf->config(
            {&sampleRateInfo, &channelMaskInfo, &channelCountInfo}, C2_MAY_BLOCK, &failures);
    if (configStatus != C2_OK) {
        ALOGE("Config Update failed");
        mSignalledError = true;
        work->result = C2_CORRUPTED;
        return C2_CORRUPTED;
    }
    // Include the config update in the work for the caller to see.
    work->worklets.front()->output.configUpdate.push_back(C2Param::Copy(sampleRateInfo));
    work->worklets.front()->output.configUpdate.push_back(C2Param::Copy(channelMaskInfo));
    work->worklets.front()->output.configUpdate.push_back(C2Param::Copy(channelCountInfo));
    ALOGV("successfully updated config.");

    mCachedOutputChannelMask = mIntf->getOutputChannelMask();
    mCachedMaxOutputChannelCount = mIntf->getMaxOutputChannelCount();

    // We want to calculate the max size we need for the write buffer for output and for
    // that, we need the frame size.
    uint32_t frameSize;
    IamfStatus frameSizeStatus = mIamfDecoder->GetFrameSize(frameSize);
    if (!frameSizeStatus.ok()) {
        ALOGE("Failed to get frame size. Error message: %s", frameSizeStatus.error_message.c_str());
        mSignalledError = true;
        work->result = C2_CORRUPTED;
        return C2_CORRUPTED;
    }
    ALOGV("successfully got frame size: %d", frameSize);

    // N.B.: Calculation of this number assumes int16_t samples.
    mOutputBufferSizeBytes = (size_t)frameSize * sizeof(int16_t) * (size_t)numOutputChannels;
    ALOGV("calculated frame size bytes: %zu", mOutputBufferSizeBytes);

    mFetchedAndUpdatedParameters = true;
    return C2_OK;
}

void C2SoftIamfDec::process(const std::unique_ptr<C2Work>& work,
                            const shared_ptr<C2BlockPool>& pool) {
    // Since the decoder is often created with Descriptor OBUs (i.e. a codec config), we don't
    // necessarily have a mIamfDecoder instance yet.

    if (mSignalledError || mSignalledEos) {
        // We already had an error or EOS signalled previously, we should not have
        // had `process` called again.
        ALOGW("process called after error or EOS, ignoring.");
        work->result = C2_BAD_VALUE;
        return;
    }

    // N.B.: Android only supports single input buffer and single worklet.
    // Initialize output work to assume OK and that we will process one worklet.
    work->result = C2_OK;
    work->workletsProcessed = 1u;
    // For output buffers, `configUpdate` is for communicating responses, start clear.
    work->worklets.front()->output.configUpdate.clear();
    // Copy flags from work->input to first worklet's output.
    work->worklets.front()->output.flags = work->input.flags;
    // Clear output buffers
    work->worklets.front()->output.buffers.clear();

    // mDummyReadView provided by SimpleC2Component just returns C2_NO_INIT.
    // It is here as a placeholder.
    C2ReadView readView = mDummyReadView;
    size_t inSize = 0u;  // Initially zero until set from readView.
    if (!work->input.buffers.empty()) {
        // Input buffers are not empty, so there is work to be done.
        readView = work->input.buffers[0]->data().linearBlocks().front().map().get();
        inSize = readView.capacity();
        // readView could give a capacity of 0 when there are no new bytes to process,
        // so it signals an error only when the readView has an error.
        if (inSize != 0 && readView.error()) {
            ALOGE("ReadView map failed %d", readView.error());
            mSignalledError = true;
            work->result = C2_CORRUPTED;
            return;
        }
    }

    // If channel mask or max output channel count has changed, we reset the decoder if and only if
    // the new values result in a different layout.
    // We want to do this before decoding so that if there is a change, the latest buffers can be
    // decoded with the new layout.
    const bool layoutChangesWaitingToBeApplied =
            mCachedOutputChannelMask != mIntf->getOutputChannelMask() ||
            mCachedMaxOutputChannelCount != mIntf->getMaxOutputChannelCount();
    if (mIamfDecoder != nullptr && layoutChangesWaitingToBeApplied) {
        if (!mCreatedWithDescriptorObus) {
            ALOGW("The decoder was not created by first providing the IAMF Descriptor OBUs as a "
                  "whole (and signalling that with the FLAG_CODEC_CONFIG flag), so the layout "
                  "cannot be changed dynamically during playback. We will continue decoding with "
                  "the existing layout.");
        } else if (auto newLayout = getTargetOutputLayout();
                   !newLayout.has_value() || newLayout == mActualOutputMix->output_layout) {
            ALOGI("The layout has not changed, we will continue decoding with the existing "
                  "layout.");
        } else {
            // Since resetting to a different layout is disruptive, only do it if we're sure it
            // results in a different output IAMF Layout.  At this point we know we both can and
            // need to reset the decoder.
            ALOGV("Output layout has actually changed, we will reset decoder.  Channel Mask: %d,"
                  "channel count: %d, layout: %d",
                  mCachedOutputChannelMask, mCachedMaxOutputChannelCount, *newLayout);
            ::iamf_tools::api::SelectedMix unusedSelectedMix;  // We fetch all config below.
            IamfStatus status =
                    mIamfDecoder->ResetWithNewMix({.output_layout = newLayout}, unusedSelectedMix);
            if (!status.ok()) {
                // Layout cannot be changed if decoder was not created with Descriptor OBUs.
                ALOGE("Failed to reset with new layout. Error message: %s",
                      status.error_message.c_str());
                mSignalledError = true;
                work->result = C2_CORRUPTED;
                return;
            }
            ALOGV("Reset IAMF decoder.  New output parameters: ");
            c2_status_t updateStatus = fetchValuesAndUpdateParameters(work);
            if (updateStatus != C2_OK) {
                // Specific error logged in `fetchValuesAndUpdateParameters`.
                return;
            }
        }
    }

    if (inSize > 0) {
        // There is work to do.
        const bool isCodecConfig = work->input.flags & C2FrameData::FLAG_CODEC_CONFIG;
        if (isCodecConfig) {
            ALOGV("Got Codec2 FLAG_CODEC_CONFIG, meaning IAMF Descriptor OBUs are in the buffer.");
            // If the CodecConfig flag is set, then we're assuming the buffer contains
            // exactly and only the DescriptorObus.  We can re-create the IamfDecoder with the
            // DescriptorObus (Codec Config) for more efficient decoding of all subsequent Temporal
            // Units.
            c2_status_t createStatus = createNewDecoderWithDescriptorObus(readView.data(), inSize);
            if (createStatus != C2_OK) {
                ALOGE("Failed to initialize decoder with descriptor OBUs. Error code: %d",
                      createStatus);
                mSignalledError = true;
                work->result = C2_CORRUPTED;
                return;
            }
        } else {
            if (mIamfDecoder == nullptr) {
                c2_status_t createStatus = createDecoder();
                if (createStatus != C2_OK) {
                    ALOGE("Failed to create decoder. Error code: %d", createStatus);
                    mSignalledError = true;
                    work->result = C2_CORRUPTED;
                    return;
                }
            }
            // Since we did not get a CodecConfig, we just try to Decode.
            IamfStatus decodeStatus = mIamfDecoder->Decode(readView.data(), inSize);
            if (!decodeStatus.ok()) {
                ALOGE("Failed to decode. Error message: %s", decodeStatus.error_message.c_str());
                mSignalledError = true;
                work->result = C2_CORRUPTED;
                return;
            }
        }
    } else {
        // If inSize is still zero at this point, then there is no input to process.
        work->worklets.front()->output.ordinal = work->input.ordinal;
        work->workletsProcessed = 1u;
        // No more data to send to decode if inSize is 0 and EOS signalled.
        if (work->input.flags & C2FrameData::FLAG_END_OF_STREAM && mIamfDecoder != nullptr) {
            IamfStatus status = mIamfDecoder->SignalEndOfDecoding();
            if (!status.ok()) {
                ALOGE("Failed to signal EOS. Error message: %s", status.error_message.c_str());
                mSignalledError = true;
                work->result = C2_CORRUPTED;
                return;
            }
            mSignalledEos = true;
            ALOGI("signalled EOS");
        }
        // For IAMF, we will still try to fetch a temporal unit at EOS.
        getAnyTemporalUnits(work, pool);
        return;
    }

    ALOGV("in buffer attr. size %zu timestamp %d frameindex %d", inSize,
          (int)work->input.ordinal.timestamp.peeku(), (int)work->input.ordinal.frameIndex.peeku());

    // The first time that IsDescriptorProcessingComplete returns true, we update config.
    if (!mFetchedAndUpdatedParameters && mIamfDecoder != nullptr &&
        mIamfDecoder->IsDescriptorProcessingComplete()) {
        // First time we are seeing descriptor processing as complete.
        ALOGV("Decoder signaled descriptor processing complete.");
        c2_status_t configStatus = fetchValuesAndUpdateParameters(work);
        if (configStatus != C2_OK) {
            // Specific error logged in `fetchValuesAndUpdateParameters`.
            return;
        }
    }

    // In any case, check for finished temporal units to return.
    getAnyTemporalUnits(work, pool);
}

c2_status_t C2SoftIamfDec::drain(uint32_t drainMode, const shared_ptr<C2BlockPool>& pool) {
    // Practically speaking, drain is unused.
    (void)pool;
    // SimpleC2Component
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

class C2SoftIamfDecFactory : public C2ComponentFactory {
  public:
    C2SoftIamfDecFactory()
        : mHelper(std::static_pointer_cast<C2ReflectorHelper>(
                  GetCodec2PlatformComponentStore()->getParamReflector())) {}

    virtual c2_status_t createComponent(c2_node_id_t id, shared_ptr<C2Component>* const component,
                                        std::function<void(C2Component*)> deleter) override {
        *component = shared_ptr<C2Component>(
                new C2SoftIamfDec(COMPONENT_NAME, id,
                                  std::make_shared<C2SoftIamfDec::IntfImpl>(mHelper)),
                deleter);
        return C2_OK;
    }

    virtual c2_status_t createInterface(
            c2_node_id_t id, shared_ptr<C2ComponentInterface>* const interface,
            std::function<void(C2ComponentInterface*)> deleter) override {
        *interface = shared_ptr<C2ComponentInterface>(
                new SimpleInterface<C2SoftIamfDec::IntfImpl>(
                        COMPONENT_NAME, id, std::make_shared<C2SoftIamfDec::IntfImpl>(mHelper)),
                deleter);
        return C2_OK;
    }

    virtual ~C2SoftIamfDecFactory() override = default;

  private:
    shared_ptr<C2ReflectorHelper> mHelper;
};

}  // namespace android

static bool SufficientSdkVersion() {
    static int sCurrentSdk = 0;
    static std::string sCurrentCodeName;
    static std::once_flag sCheckOnce;
    std::call_once(sCheckOnce, [&]() {
        sCurrentSdk = android_get_device_api_level();
        sCurrentCodeName = android::base::GetProperty("ro.build.version.codename", "<none>");
    });
    return sCurrentSdk >= 36 || sCurrentCodeName == "Baklava";
}

__attribute__((cfi_canonical_jump_table)) extern "C" ::C2ComponentFactory* CreateCodec2Factory() {
    ALOGI("in %s", __func__);
    if (!android::media::swcodec::flags::iamf_software_decoder()) {
        ALOGI("IAMF SW decoder is disabled by flag.");
        return nullptr;
    }

    bool enabled = SufficientSdkVersion();
    if (!enabled) {
        return nullptr;
    }
    return new ::android::C2SoftIamfDecFactory();
}

__attribute__((cfi_canonical_jump_table)) extern "C" void DestroyCodec2Factory(
        ::C2ComponentFactory* factory) {
    ALOGI("in %s", __func__);
    delete factory;
}
