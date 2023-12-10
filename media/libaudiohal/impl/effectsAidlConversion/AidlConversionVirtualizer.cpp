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
#include <media/AidlConversionCppNdk.h>
#include <media/AidlConversionNdk.h>
#include <media/AidlConversionEffect.h>
#include <system/audio_effects/aidl_effects_utils.h>
#include <system/audio_effects/effect_virtualizer.h>

#include <utils/Log.h>

#include "AidlConversionVirtualizer.h"

namespace android {
namespace effect {

using ::aidl::android::aidl_utils::statusTFromBinderStatus;
using ::aidl::android::getParameterSpecificField;
using ::aidl::android::hardware::audio::effect::Parameter;
using ::aidl::android::hardware::audio::effect::Range;
using ::aidl::android::hardware::audio::effect::Virtualizer;
using ::aidl::android::hardware::audio::effect::VendorExtension;
using ::aidl::android::media::audio::common::AudioDeviceDescription;
using ::android::status_t;
using utils::EffectParamReader;
using utils::EffectParamWriter;

status_t AidlConversionVirtualizer::setParameter(EffectParamReader& param) {
    uint32_t type = 0;
    if (OK != param.readFromParameter(&type)) {
        ALOGE("%s invalid param %s", __func__, param.toString().c_str());
        return BAD_VALUE;
    }
    Parameter aidlParam;
    switch (type) {
        case VIRTUALIZER_PARAM_STRENGTH: {
            int16_t strength = 0;
            if (OK != param.readFromValue(&strength)) {
                ALOGE("%s invalid param %s for type %d", __func__, param.toString().c_str(), type);
                return BAD_VALUE;
            }
            aidlParam = MAKE_SPECIFIC_PARAMETER(Virtualizer, virtualizer, strengthPm, strength);
            break;
        }
        case VIRTUALIZER_PARAM_FORCE_VIRTUALIZATION_MODE: {
            audio_devices_t deviceType;
            if (OK != param.readFromValue(&deviceType)) {
                ALOGE("%s invalid param %s for type %d", __func__, param.toString().c_str(), type);
                return BAD_VALUE;
            }
            AudioDeviceDescription deviceDesc = VALUE_OR_RETURN_STATUS(
                    ::aidl::android::legacy2aidl_audio_devices_t_AudioDeviceDescription(
                            deviceType));
            aidlParam = MAKE_SPECIFIC_PARAMETER(Virtualizer, virtualizer, device, deviceDesc);
            break;
        }
        default: {
            // for vendor extension, copy data area to the DefaultExtension, parameter ignored
            VendorExtension ext = VALUE_OR_RETURN_STATUS(
                    aidl::android::legacy2aidl_EffectParameterReader_VendorExtension(param));
            aidlParam = MAKE_SPECIFIC_PARAMETER(Virtualizer, virtualizer, vendor, ext);
            break;
        }
    }
    return statusTFromBinderStatus(mEffect->setParameter(aidlParam));
}

status_t AidlConversionVirtualizer::getParameter(EffectParamWriter& param) {
    uint32_t type = 0;
    if (OK != param.readFromParameter(&type)) {
        ALOGE("%s invalid param %s", __func__, param.toString().c_str());
        param.setStatus(BAD_VALUE);
        return BAD_VALUE;
    }
    Parameter aidlParam;
    switch (type) {
        case VIRTUALIZER_PARAM_STRENGTH_SUPPORTED: {
            // an invalid range indicates not setting support for this parameter
            uint32_t support =
                    ::aidl::android::hardware::audio::effect::isRangeValid<Range::Tag::virtualizer>(
                            Virtualizer::strengthPm, mDesc.capability);
            return param.writeToValue(&support);
        }
        case VIRTUALIZER_PARAM_STRENGTH: {
            Parameter::Id id = MAKE_SPECIFIC_PARAMETER_ID(Virtualizer, virtualizerTag,
                                                          Virtualizer::strengthPm);
            RETURN_STATUS_IF_ERROR(statusTFromBinderStatus(mEffect->getParameter(id, &aidlParam)));
            int16_t strength = VALUE_OR_RETURN_STATUS(GET_PARAMETER_SPECIFIC_FIELD(
                    aidlParam, Virtualizer, virtualizer, Virtualizer::strengthPm, int32_t));
            return param.writeToValue(&strength);
        }
        case VIRTUALIZER_PARAM_VIRTUAL_SPEAKER_ANGLES: {
            audio_channel_mask_t mask;
            audio_devices_t device;
            if (OK != param.readFromParameter(&mask) || OK != param.readFromParameter(&device)) {
                ALOGW("%s illegal param %s", __func__, param.toString().c_str());
                return BAD_VALUE;
            }
            Virtualizer::SpeakerAnglesPayload payload = {
                    .layout = VALUE_OR_RETURN_STATUS(
                            ::aidl::android::legacy2aidl_audio_channel_mask_t_AudioChannelLayout(
                                    mask, false)),
                    .device = VALUE_OR_RETURN_STATUS(
                            ::aidl::android::legacy2aidl_audio_devices_t_AudioDeviceDescription(
                                    device))};
            Virtualizer::Id vId = UNION_MAKE(Virtualizer::Id, speakerAnglesPayload, payload);
            Parameter::Id id = UNION_MAKE(Parameter::Id, virtualizerTag, vId);
            RETURN_STATUS_IF_ERROR(statusTFromBinderStatus(mEffect->getParameter(id, &aidlParam)));
            const auto& angles = VALUE_OR_RETURN_STATUS(GET_PARAMETER_SPECIFIC_FIELD(
                    aidlParam, Virtualizer, virtualizer, Virtualizer::speakerAngles,
                    std::vector<Virtualizer::ChannelAngle>));
            for (const auto& angle : angles) {
                const audio_channel_mask_t chMask = ::aidl::android::
                        aidl2legacy_AudioChannelLayout_layout_audio_channel_mask_t_bits(
                                angle.channel, false);
                ALOGW("%s aidl %d ch %d", __func__, angle.channel, chMask);
                if (OK != param.writeToValue(&chMask) ||
                    OK != param.writeToValue(&angle.azimuthDegree) ||
                    OK != param.writeToValue(&angle.elevationDegree)) {
                    ALOGW("%s can't write angles to param %s", __func__, param.toString().c_str());
                    return BAD_VALUE;
                }
            }
            return OK;
        }
        case VIRTUALIZER_PARAM_VIRTUALIZATION_MODE: {
            Parameter::Id id = MAKE_SPECIFIC_PARAMETER_ID(Virtualizer, virtualizerTag,
                                                          Virtualizer::device);
            RETURN_STATUS_IF_ERROR(statusTFromBinderStatus(mEffect->getParameter(id, &aidlParam)));
            AudioDeviceDescription device = VALUE_OR_RETURN_STATUS(
                    GET_PARAMETER_SPECIFIC_FIELD(aidlParam, Virtualizer, virtualizer,
                                                 Virtualizer::device, AudioDeviceDescription));
            const audio_devices_t deviceType = VALUE_OR_RETURN_STATUS(
                    ::aidl::android::aidl2legacy_AudioDeviceDescription_audio_devices_t(device));
            return param.writeToValue(&deviceType);
        }
        default: {
            VENDOR_EXTENSION_GET_AND_RETURN(Virtualizer, virtualizer, param);
        }
    }
}

} // namespace effect
} // namespace android
