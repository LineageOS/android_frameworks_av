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

#include <aidl/android/hardware/audio/effect/IEffect.h>
#include "EffectConversionHelperAidl.h"

namespace android {
namespace effect {

class AidlConversionVisualizer : public EffectConversionHelperAidl {
  public:
    AidlConversionVisualizer(
            std::shared_ptr<::aidl::android::hardware::audio::effect::IEffect> effect,
            int32_t sessionId, int32_t ioId,
            const ::aidl::android::hardware::audio::effect::Descriptor& desc, bool isProxyEffect)
        : EffectConversionHelperAidl(effect, sessionId, ioId, desc, isProxyEffect) {}
    ~AidlConversionVisualizer() {}

  private:
    uint32_t mCaptureSize = 0;
    status_t setParameter(utils::EffectParamReader& param) override;
    status_t getParameter(utils::EffectParamWriter& param) override;
    status_t visualizerCapture(uint32_t* replySize, void* pReplyData) override;
    status_t visualizerMeasure(uint32_t* replySize, void* pReplyData) override;
};

}  // namespace effect
}  // namespace android
