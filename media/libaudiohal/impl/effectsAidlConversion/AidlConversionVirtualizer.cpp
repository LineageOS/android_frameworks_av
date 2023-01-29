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

#include <cstdint>
#include <cstring>
#include <optional>
#define LOG_TAG "AidlConversionVirtualizer"
//#define LOG_NDEBUG 0

#include <error/expected_utils.h>
#include <media/AidlConversionNdk.h>
#include <media/AidlConversionEffect.h>
#include <media/audiohal/AudioEffectUuid.h>
#include <system/audio_effects/effect_spatializer.h>

#include <utils/Log.h>

#include "AidlConversionVirtualizer.h"

namespace android {
namespace effect {

using ::aidl::android::aidl_utils::statusTFromBinderStatus;
using ::aidl::android::hardware::audio::effect::Parameter;
using ::android::status_t;
using utils::EffectParamReader;
using utils::EffectParamWriter;

status_t AidlConversionVirtualizer::setParameter(EffectParamReader& param) {
    uint32_t type = 0;
    uint16_t value = 0;
    if (!param.validateParamValueSize(sizeof(uint32_t), sizeof(uint16_t)) ||
        OK != param.readFromParameter(&type) || OK != param.readFromValue(&value)) {
        ALOGE("%s invalid param %s", __func__, param.toString().c_str());
        return BAD_VALUE;
    }
    Parameter aidlParam;
    // TODO
    return statusTFromBinderStatus(mEffect->setParameter(aidlParam));
}

status_t AidlConversionVirtualizer::getParameter(EffectParamWriter& param) {
    uint32_t type = 0, value = 0;
    if (!param.validateParamValueSize(sizeof(uint32_t), sizeof(uint32_t)) ||
        OK != param.readFromParameter(&type)) {
        ALOGE("%s invalid param %s", __func__, param.toString().c_str());
        param.setStatus(BAD_VALUE);
        return BAD_VALUE;
    }
    // TODO
    return param.writeToValue(&value);
}

} // namespace effect
} // namespace android
