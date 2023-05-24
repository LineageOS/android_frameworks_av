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

#include <aidl/android/hardware/audio/effect/BpEffect.h>
#include "EffectConversionHelperAidl.h"

namespace android {
namespace effect {

class AidlConversionDp : public EffectConversionHelperAidl {
  public:
    AidlConversionDp(std::shared_ptr<::aidl::android::hardware::audio::effect::IEffect> effect,
                     int32_t sessionId, int32_t ioId,
                     const ::aidl::android::hardware::audio::effect::Descriptor& desc,
                     bool isProxyEffect)
        : EffectConversionHelperAidl(effect, sessionId, ioId, desc, isProxyEffect) {}
    ~AidlConversionDp() {}

  private:
    aidl::android::hardware::audio::effect::DynamicsProcessing::EngineArchitecture mEngine;

    status_t setParameter(utils::EffectParamReader& param) override;
    status_t getParameter(utils::EffectParamWriter& param) override;

    ConversionResult<
            aidl::android::hardware::audio::effect::DynamicsProcessing::ChannelConfig>
    readChannelConfigFromParam(utils::EffectParamReader& param);
    ConversionResult<aidl::android::hardware::audio::effect::DynamicsProcessing::EqBandConfig>
    readEqBandConfigFromParam(utils::EffectParamReader& param);
    ConversionResult<
            aidl::android::hardware::audio::effect::DynamicsProcessing::MbcBandConfig>
    readMbcBandConfigFromParam(utils::EffectParamReader& param);
    ConversionResult<
            aidl::android::hardware::audio::effect::DynamicsProcessing::LimiterConfig>
    readLimiterConfigFromParam(utils::EffectParamReader& param);
    ConversionResult<
            aidl::android::hardware::audio::effect::DynamicsProcessing::EngineArchitecture>
    readEngineArchitectureFromParam(utils::EffectParamReader& param);

    status_t getChannelConfig(aidl::android::hardware::audio::effect::DynamicsProcessing::Tag tag,
                              utils::EffectParamWriter& writer);
    status_t getEqBandConfig(aidl::android::hardware::audio::effect::DynamicsProcessing::Tag tag,
                             utils::EffectParamWriter& param);
    status_t getMbcBandConfig(utils::EffectParamWriter& param);
    status_t getLimiterConfig(utils::EffectParamWriter& param);

};

}  // namespace effect
}  // namespace android
