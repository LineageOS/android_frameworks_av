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

#include <media/AidlConversionNdk.h>
#include <system/audio_effect.h>
#include <system/audio_effects/effect_aec.h>
#include <system/audio_effects/effect_downmix.h>
#include <system/audio_effects/effect_dynamicsprocessing.h>
#include <system/audio_effects/effect_hapticgenerator.h>
#include <system/audio_effects/effect_ns.h>
#include <system/audio_effects/effect_visualizer.h>

namespace android {
namespace effect {

static const size_t kEffectParamSize = sizeof(effect_param_t);
static const size_t kEffectConfigSize = sizeof(effect_config_t);

class EffectConversionHelperAidl {
  protected:
    EffectConversionHelperAidl(
            std::shared_ptr<::aidl::android::hardware::audio::effect::IEffect> effect,
            int32_t sessionId, int32_t ioId, ::aidl::android::media::audio::common::AudioUuid uuid)
        : mSessionId(sessionId),
          mIoId(ioId),
          mTypeUuid(std::move(uuid)),
          mEffect(std::move(effect)) {}

    status_t handleCommand(uint32_t cmdCode, uint32_t cmdSize, void* pCmdData, uint32_t* replySize,
                           void* pReplyData);

  private:
    const int32_t mSessionId;
    const int32_t mIoId;
    ::aidl::android::media::audio::common::AudioUuid mTypeUuid;
    const std::shared_ptr<::aidl::android::hardware::audio::effect::IEffect> mEffect;

    // command handler map
    typedef status_t (EffectConversionHelperAidl::*CommandHandler)(uint32_t /* cmdSize */,
                                                                   const void* /* pCmdData */,
                                                                   uint32_t* /* replySize */,
                                                                   void* /* pReplyData */);
    static const std::map<uint32_t /* effect_command_e */, CommandHandler> mCommandHandlerMap;

    // parameter set/get handler map
    typedef status_t (EffectConversionHelperAidl::*SetParameter)(const effect_param_t& param);
    typedef status_t (EffectConversionHelperAidl::*GetParameter)(effect_param_t& param);
    static const std::map<::aidl::android::media::audio::common::AudioUuid /* TypeUUID */,
                          std::pair<SetParameter, GetParameter>>
            mParameterHandlerMap;

    // align to 32 bit boundary
    static constexpr size_t padding(size_t size) {
        return ((size - 1) / sizeof(int) + 1) * sizeof(int);
    }
    static constexpr bool validatePVsize(const effect_param_t& param, size_t p, size_t v) {
        return padding(param.psize) == p && param.vsize == v;
    }
    static constexpr bool validateCommandSize(const effect_param_t& param, size_t size) {
        return padding(param.psize) + param.vsize + kEffectParamSize <= size;
    }

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

    // AEC parameter handler
    status_t setAecParameter(const effect_param_t& param);
    status_t getAecParameter(effect_param_t& param);
};

}  // namespace effect
}  // namespace android
