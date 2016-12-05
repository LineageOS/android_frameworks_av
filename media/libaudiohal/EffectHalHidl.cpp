/*
 * Copyright (C) 2016 The Android Open Source Project
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

#define LOG_TAG "EffectHalHidl"
//#define LOG_NDEBUG 0

#include <media/EffectsFactoryApi.h>
#include <utils/Log.h>

#include "ConversionHelperHidl.h"
#include "EffectHalHidl.h"
#include "HidlUtils.h"

using ::android::hardware::audio::effect::V2_0::Result;
using ::android::hardware::hidl_vec;
using ::android::hardware::Return;
using ::android::hardware::Status;

namespace android {

EffectHalHidl::EffectHalHidl(const sp<IEffect>& effect, uint64_t effectId)
        : mEffect(effect), mEffectId(effectId) {
}

EffectHalHidl::~EffectHalHidl() {
}

// static
void EffectHalHidl::effectDescriptorToHal(
        const EffectDescriptor& descriptor, effect_descriptor_t* halDescriptor) {
    HidlUtils::uuidToHal(descriptor.type, &halDescriptor->type);
    HidlUtils::uuidToHal(descriptor.uuid, &halDescriptor->uuid);
    halDescriptor->flags = static_cast<uint32_t>(descriptor.flags);
    halDescriptor->cpuLoad = descriptor.cpuLoad;
    halDescriptor->memoryUsage = descriptor.memoryUsage;
    memcpy(halDescriptor->name, descriptor.name.data(), descriptor.name.size());
    memcpy(halDescriptor->implementor,
            descriptor.implementor.data(), descriptor.implementor.size());
}

// static
status_t EffectHalHidl::analyzeResult(const Result& result) {
    switch (result) {
        case Result::OK: return OK;
        case Result::INVALID_ARGUMENTS: return BAD_VALUE;
        case Result::INVALID_STATE: return NOT_ENOUGH_DATA;
        case Result::NOT_INITIALIZED: return NO_INIT;
        case Result::NOT_SUPPORTED: return INVALID_OPERATION;
        case Result::RESULT_TOO_BIG: return NO_MEMORY;
        default: return NO_INIT;
    }
}

status_t EffectHalHidl::process(audio_buffer_t */*inBuffer*/, audio_buffer_t */*outBuffer*/) {
    // Idea -- intercept set buffer config command, capture audio format, use it
    // for determining frame size in bytes on input and output.
    return OK;
}

status_t EffectHalHidl::processReverse(audio_buffer_t */*inBuffer*/, audio_buffer_t */*outBuffer*/) {
    return OK;
}

status_t EffectHalHidl::command(uint32_t cmdCode, uint32_t cmdSize, void *pCmdData,
        uint32_t *replySize, void *pReplyData) {
    if (mEffect == 0) return NO_INIT;
    hidl_vec<uint8_t> hidlData;
    hidlData.setToExternal(reinterpret_cast<uint8_t*>(pCmdData), cmdSize);
    status_t status;
    Return<void> ret = mEffect->command(cmdCode, hidlData, *replySize,
            [&](int32_t s, const hidl_vec<uint8_t>& result) {
                status = s;
                if (status == 0) {
                    if (*replySize > result.size()) *replySize = result.size();
                    if (pReplyData && *replySize > 0) {
                        memcpy(pReplyData, &result[0], *replySize);
                    }
                }
            });
    return status;
}

status_t EffectHalHidl::getDescriptor(effect_descriptor_t *pDescriptor) {
    if (mEffect == 0) return NO_INIT;
    Result retval = Result::NOT_INITIALIZED;
    Return<void> ret = mEffect->getDescriptor(
            [&](Result r, const EffectDescriptor& result) {
                retval = r;
                if (retval == Result::OK) {
                    effectDescriptorToHal(result, pDescriptor);
                }
            });
    ConversionHelperHidl::crashIfHalIsDead(ret.getStatus());
    return ret.getStatus().isOk() ? analyzeResult(retval) : ret.getStatus().transactionError();
}

} // namespace android
