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

#include <utils/Errors.h>

#include <aidl/android/hardware/audio/effect/BpEffect.h>
#include <fmq/AidlMessageQueue.h>
#include <system/audio_effect.h>
#include <system/audio_effects/audio_effects_utils.h>

namespace android {
namespace effect {

class EffectConversionHelperAidl {
  public:
    status_t handleCommand(uint32_t cmdCode, uint32_t cmdSize, void* pCmdData, uint32_t* replySize,
                           void* pReplyData);
    virtual ~EffectConversionHelperAidl() {}

    using StatusMQ = ::android::AidlMessageQueue<
            ::aidl::android::hardware::audio::effect::IEffect::Status,
            ::aidl::android::hardware::common::fmq::SynchronizedReadWrite>;
    using DataMQ = ::android::AidlMessageQueue<
            float, ::aidl::android::hardware::common::fmq::SynchronizedReadWrite>;
    std::shared_ptr<StatusMQ> getStatusMQ() { return mStatusQ; }
    std::shared_ptr<DataMQ> getInputMQ() { return mInputQ; }
    std::shared_ptr<DataMQ> getOutputMQ() { return mOutputQ; }
    std::shared_ptr<android::hardware::EventFlag> getEventFlagGroup() { return mEfGroup; }

    bool isBypassing() const;
    bool isTunnel() const;
    bool isBypassingOrTunnel() const;

    ::aidl::android::hardware::audio::effect::Descriptor getDescriptor() const;
    status_t reopen();

  protected:
    const int32_t mSessionId;
    const int32_t mIoId;
    const ::aidl::android::hardware::audio::effect::Descriptor mDesc;
    const std::shared_ptr<::aidl::android::hardware::audio::effect::IEffect> mEffect;
    // whether the effect is instantiated on an input stream
    const bool mIsInputStream;
    ::aidl::android::hardware::audio::effect::Parameter::Common mCommon;

    EffectConversionHelperAidl(
            std::shared_ptr<::aidl::android::hardware::audio::effect::IEffect> effect,
            int32_t sessionId, int32_t ioId,
            const ::aidl::android::hardware::audio::effect::Descriptor& desc, bool isProxy);

    status_t handleSetParameter(uint32_t cmdSize, const void* pCmdData, uint32_t* replySize,
                                void* pReplyData);
    status_t handleGetParameter(uint32_t cmdSize, const void* pCmdData, uint32_t* replySize,
                                void* pReplyData);

  private:
    const bool mIsProxyEffect;

    static constexpr int kDefaultframeCount = 0x100;

    template <typename T, typename = std::enable_if_t<std::is_arithmetic_v<T>>>
    static inline std::string numericPointerToString(T* pt) {
        return pt ? std::to_string(*pt) : "nullptr";
    }

    const aidl::android::media::audio::common::AudioConfig kDefaultAudioConfig = {
            .base = {.sampleRate = 44100,
                     .channelMask = aidl::android::media::audio::common::AudioChannelLayout::make<
                             aidl::android::media::audio::common::AudioChannelLayout::layoutMask>(
                             aidl::android::media::audio::common::AudioChannelLayout::
                                     LAYOUT_STEREO),
                     .format = {.type = aidl::android::media::audio::common::AudioFormatType::PCM,
                                .pcm = aidl::android::media::audio::common::PcmType::FLOAT_32_BIT}},
            .frameCount = kDefaultframeCount};

    // command handler map
    typedef status_t (EffectConversionHelperAidl::*CommandHandler)(uint32_t /* cmdSize */,
                                                                   const void* /* pCmdData */,
                                                                   uint32_t* /* replySize */,
                                                                   void* /* pReplyData */);
    static const std::map<uint32_t /* effect_command_e */, CommandHandler> mCommandHandlerMap;
    // data and status FMQ
    std::shared_ptr<StatusMQ> mStatusQ = nullptr;
    std::shared_ptr<DataMQ> mInputQ = nullptr, mOutputQ = nullptr;

    struct EventFlagDeleter {
        void operator()(::android::hardware::EventFlag* flag) const {
            if (flag) {
                ::android::hardware::EventFlag::deleteEventFlag(&flag);
            }
        }
    };
    std::shared_ptr<android::hardware::EventFlag> mEfGroup = nullptr;
    status_t updateEventFlags();
    void updateDataMqs(
            const ::aidl::android::hardware::audio::effect::IEffect::OpenEffectReturn& ret);
    void updateMqsAndEventFlags(
            const ::aidl::android::hardware::audio::effect::IEffect::OpenEffectReturn& ret);

    status_t handleInit(uint32_t cmdSize, const void* pCmdData, uint32_t* replySize,
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
    status_t handleSetAudioSource(uint32_t cmdSize, const void* pCmdData, uint32_t* replySize,
                                  void* pReplyData);
    status_t handleSetAudioMode(uint32_t cmdSize, const void* pCmdData, uint32_t* replySize,
                                void* pReplyData);
    status_t handleSetDevice(uint32_t cmdSize, const void* pCmdData, uint32_t* replySize,
                             void* pReplyData);
    status_t handleSetVolume(uint32_t cmdSize, const void* pCmdData, uint32_t* replySize,
                             void* pReplyData);
    status_t handleSetOffload(uint32_t cmdSize, const void* pCmdData, uint32_t* replySize,
                              void* pReplyData);
    status_t handleVisualizerCapture(uint32_t cmdSize, const void* pCmdData, uint32_t* replySize,
                                     void* pReplyData);
    status_t handleVisualizerMeasure(uint32_t cmdSize, const void* pCmdData, uint32_t* replySize,
                                     void* pReplyData);

    // implemented by conversion of each effect
    virtual status_t setParameter(utils::EffectParamReader& param) = 0;
    virtual status_t getParameter(utils::EffectParamWriter& param) = 0;
    virtual status_t visualizerCapture(uint32_t* replySize __unused, void* pReplyData __unused) {
        return BAD_VALUE;
    }
    virtual status_t visualizerMeasure(uint32_t* replySize __unused, void* pReplyData __unused) {
        return BAD_VALUE;
    }
};

}  // namespace effect
}  // namespace android
