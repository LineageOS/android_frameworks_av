/*
 * Copyright (C) 2023 The Android Open Source Project
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

#pragma once

#include <cstddef>
#include <map>
#include <memory>
#include <utils/Errors.h>

#include <aidl/android/hardware/audio/effect/IEffect.h>

#include <system/audio_effect.h>
#include <system/audio_effects/audio_effects_utils.h>

namespace android {
namespace effect {

class EffectConversionHelperAidl {
  protected:
    EffectConversionHelperAidl(
            std::shared_ptr<::aidl::android::hardware::audio::effect::IEffect> effect,
            int32_t sessionId, int32_t ioId,
            const ::aidl::android::hardware::audio::effect::Descriptor& desc);

    status_t handleCommand(uint32_t cmdCode, uint32_t cmdSize, void* pCmdData, uint32_t* replySize,
                           void* pReplyData);

  private:
    const int32_t mSessionId;
    const int32_t mIoId;
    const ::aidl::android::hardware::audio::effect::Descriptor mDesc;
    ::aidl::android::media::audio::common::AudioUuid mTypeUuid;
    const std::shared_ptr<::aidl::android::hardware::audio::effect::IEffect> mEffect;
    ::aidl::android::hardware::audio::effect::IEffect::OpenEffectReturn mOpenReturn;
    ::aidl::android::hardware::audio::effect::Parameter::Common mCommon;

    const aidl::android::media::audio::common::AudioFormatDescription kDefaultFormatDescription = {
            .type = aidl::android::media::audio::common::AudioFormatType::PCM,
            .pcm = aidl::android::media::audio::common::PcmType::FLOAT_32_BIT};

    static constexpr int kDefaultframeCount = 0x100;

    using AudioChannelLayout = aidl::android::media::audio::common::AudioChannelLayout;
    const aidl::android::media::audio::common::AudioConfig kDefaultAudioConfig = {
            .base = {.sampleRate = 44100,
                     .channelMask = AudioChannelLayout::make<AudioChannelLayout::layoutMask>(
                             AudioChannelLayout::LAYOUT_STEREO),
                     .format = kDefaultFormatDescription},
            .frameCount = kDefaultframeCount};
    // command handler map
    typedef status_t (EffectConversionHelperAidl::*CommandHandler)(uint32_t /* cmdSize */,
                                                                   const void* /* pCmdData */,
                                                                   uint32_t* /* replySize */,
                                                                   void* /* pReplyData */);
    static const std::map<uint32_t /* effect_command_e */, CommandHandler> mCommandHandlerMap;

    // parameter set/get handler map
    typedef status_t (EffectConversionHelperAidl::*SetParameter)(
            android::effect::utils::EffectParamReader& param);
    typedef status_t (EffectConversionHelperAidl::*GetParameter)(
            android::effect::utils::EffectParamWriter& param);
    static const std::map<::aidl::android::media::audio::common::AudioUuid /* TypeUUID */,
                          std::pair<SetParameter, GetParameter>>
            mParameterHandlerMap;

    status_t handleInit(uint32_t cmdSize, const void* pCmdData, uint32_t* replySize,
                        void* pReplyData);
    status_t handleSetParameter(uint32_t cmdSize, const void* pCmdData, uint32_t* replySize,
                                void* pReplyData);
    status_t handleGetParameter(uint32_t cmdSize, const void* pCmdData, uint32_t* replySize,
                                void* pReplyData);
    status_t handleSetConfig(uint32_t cmdSize, const void* pCmdData, uint32_t* replySize,
                             void* pReplyData);
    status_t handleGetConfig(uint32_t cmdSize, const void* pCmdData, uint32_t* replySize,
                             void* pReplyData);
    status_t handleEnable(uint32_t cmdSize, const void* pCmdData, uint32_t* replySize,
                          void* pReplyData);
    status_t handleDisable(uint32_t cmdSize, const void* pCmdData, uint32_t* replySize,
                           void* pReplyData);
    status_t handleReset(uint32_t cmdSize, const void* pCmdData, uint32_t* replySize,
                         void* pReplyData);
    status_t handleSetDevice(uint32_t cmdSize, const void* pCmdData, uint32_t* replySize,
                             void* pReplyData);
    status_t handleSetVolume(uint32_t cmdSize, const void* pCmdData, uint32_t* replySize,
                             void* pReplyData);
    status_t handleSetOffload(uint32_t cmdSize, const void* pCmdData, uint32_t* replySize,
                              void* pReplyData);
    status_t handleFirstPriority(uint32_t cmdSize, const void* pCmdData, uint32_t* replySize,
                                 void* pReplyData);

    // set/get parameter handler
    status_t setAecParameter(android::effect::utils::EffectParamReader& param);
    status_t getAecParameter(android::effect::utils::EffectParamWriter& param);
    status_t setAgcParameter(android::effect::utils::EffectParamReader& param);
    status_t getAgcParameter(android::effect::utils::EffectParamWriter& param);
    status_t setBassBoostParameter(android::effect::utils::EffectParamReader& param);
    status_t getBassBoostParameter(android::effect::utils::EffectParamWriter& param);
    status_t setDownmixParameter(android::effect::utils::EffectParamReader& param);
    status_t getDownmixParameter(android::effect::utils::EffectParamWriter& param);
};

}  // namespace effect
}  // namespace android
