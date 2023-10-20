/*
 * Copyright 2018 The Android Open Source Project
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

//#define LOG_NDEBUG 0
#define LOG_TAG "Codec2-AIDL-ParamTypes"
#include <android-base/logging.h>

#include <android/binder_manager.h>
#include <android/sysprop/MediaProperties.sysprop.h>
#include <codec2/aidl/ParamTypes.h>
#include <codec2/common/ParamTypes.h>

#include "ParamTypes-specialization.h"

namespace android {

using ::aidl::android::hardware::media::c2::FieldId;
using ::aidl::android::hardware::media::c2::FieldSupportedValues;
using ::aidl::android::hardware::media::c2::Params;
using ::aidl::android::hardware::media::c2::Status;
using ::aidl::android::hardware::media::c2::ValueRange;

// {offset, size} -> FieldId
template<>
void SetFieldId(FieldId *d, uint32_t offset, uint32_t size) {
    d->offset = offset;
    d->sizeBytes = size;
}

// FieldId -> offset
template<>
uint32_t GetOffsetFromFieldId(const FieldId &s) {
    return s.offset;
}

// FieldId -> size
template<>
uint32_t GetSizeFromFieldId(const FieldId &s) {
    return s.sizeBytes;
}

template<>
void SetStatus(Status *dst, c2_status_t src) {
    dst->status = src;
}

template<>
c2_status_t GetStatus(const Status &status) {
    return static_cast<c2_status_t>(status.status);
}

static constexpr FieldSupportedValues::Tag EMPTY = FieldSupportedValues::empty;
static constexpr FieldSupportedValues::Tag RANGE = FieldSupportedValues::range;
static constexpr FieldSupportedValues::Tag VALUES = FieldSupportedValues::values;
static constexpr FieldSupportedValues::Tag FLAGS = FieldSupportedValues::flags;

// C2FieldSupportedValues -> FieldSupportedValues
template<>
bool objcpy(FieldSupportedValues *d, const C2FieldSupportedValues &s) {
    switch (s.type) {
    case C2FieldSupportedValues::EMPTY: {
            d->set<EMPTY>(true);
            break;
        }
    case C2FieldSupportedValues::RANGE: {
            ValueRange range{};
            if (!objcpy(&range, s.range)) {
                LOG(ERROR) << "Invalid C2FieldSupportedValues::range.";
                d->set<RANGE>(range);
                return false;
            }
            d->set<RANGE>(range);
            break;
        }
    case C2FieldSupportedValues::VALUES: {
            std::vector<int64_t> values;
            copyVector<int64_t>(&values, s.values);
            d->set<VALUES>(values);
            break;
        }
    case C2FieldSupportedValues::FLAGS: {
            std::vector<int64_t> flags;
            copyVector<int64_t>(&flags, s.values);
            d->set<FLAGS>(flags);
            break;
        }
    default:
        LOG(DEBUG) << "Unrecognized C2FieldSupportedValues::type_t "
                   << "with underlying value " << underlying_value(s.type)
                   << ".";
        return false;
    }
    return true;
}

// FieldSupportedValues -> C2FieldSupportedValues
template<>
bool objcpy(C2FieldSupportedValues *d, const FieldSupportedValues &s) {
    switch (s.getTag()) {
    case FieldSupportedValues::empty: {
            d->type = C2FieldSupportedValues::EMPTY;
            break;
        }
    case FieldSupportedValues::range: {
            d->type = C2FieldSupportedValues::RANGE;
            if (!objcpy(&d->range, s.get<RANGE>())) {
                LOG(ERROR) << "Invalid FieldSupportedValues::range.";
                return false;
            }
            d->values.resize(0);
            break;
        }
    case FieldSupportedValues::values: {
            d->type = C2FieldSupportedValues::VALUES;
            copyVector<uint64_t>(&d->values, s.get<VALUES>());
            break;
        }
    case FieldSupportedValues::flags: {
            d->type = C2FieldSupportedValues::FLAGS;
            copyVector<uint64_t>(&d->values, s.get<FLAGS>());
            break;
        }
    default:
        LOG(WARNING) << "Unrecognized FieldSupportedValues::getDiscriminator()";
        return false;
    }
    return true;
}

template<>
const std::vector<uint8_t> &GetBlob<Params>(const Params &params) {
    return params.params;
}

template<>
std::vector<uint8_t> *GetBlob<Params>(Params *params) {
    return &params->params;
}

} // namespace android

namespace aidl {
namespace android {
namespace hardware {
namespace media {
namespace c2 {
namespace utils {

bool IsSelected() {
    // TODO: read from aconfig flags
    const bool enabled = false;

    if (!enabled) {
        // Cannot select AIDL if not enabled
        return false;
    }
    using ::android::sysprop::MediaProperties::codec2_hal_selection;
    using ::android::sysprop::MediaProperties::codec2_hal_selection_values;
    constexpr codec2_hal_selection_values AIDL = codec2_hal_selection_values::AIDL;
    constexpr codec2_hal_selection_values HIDL = codec2_hal_selection_values::HIDL;
    codec2_hal_selection_values selection = codec2_hal_selection().value_or(HIDL);
    switch (selection) {
    case AIDL:
        return true;
    case HIDL:
        return false;
    default:
        LOG(FATAL) << "Unexpected codec2 HAL selection value: " << (int)selection;
    }

    return false;
}

const char* asString(Status status, const char* def) {
    return asString(static_cast<c2_status_t>(status.status), def);
}

// C2FieldSupportedValuesQuery -> FieldSupportedValuesQuery
bool ToAidl(
        FieldSupportedValuesQuery* d,
        const C2FieldSupportedValuesQuery& s) {
    return ::android::objcpy(d, nullptr, s);
}

// FieldSupportedValuesQuery -> C2FieldSupportedValuesQuery
bool FromAidl(
        C2FieldSupportedValuesQuery* d,
        const FieldSupportedValuesQuery& s) {
    return ::android::objcpy(d, s);
}

// C2FieldSupportedValuesQuery -> FieldSupportedValuesQueryResult
bool ToAidl(
        FieldSupportedValuesQueryResult* d,
        const C2FieldSupportedValuesQuery& s) {
    return ::android::objcpy(nullptr, d, s);
}

// FieldSupportedValuesQuery, FieldSupportedValuesQueryResult ->
// C2FieldSupportedValuesQuery
bool FromAidl(
        C2FieldSupportedValuesQuery* d,
        const FieldSupportedValuesQuery& sq,
        const FieldSupportedValuesQueryResult& sr) {
    return ::android::objcpy(d, sq, sr);
}

// C2Component::Traits -> IComponentStore::ComponentTraits
bool ToAidl(
        IComponentStore::ComponentTraits *d,
        const C2Component::Traits &s) {
    return ::android::objcpy(d, s);
}

// ComponentTraits -> C2Component::Traits, std::unique_ptr<std::vector<std::string>>
bool FromAidl(
        C2Component::Traits* d,
        const IComponentStore::ComponentTraits& s) {
    return ::android::objcpy(d, s);
}

// C2SettingResult -> SettingResult
bool ToAidl(SettingResult *d, const C2SettingResult &s) {
    return ::android::objcpy(d, s);
}

// SettingResult -> std::unique_ptr<C2SettingResult>
bool FromAidl(std::unique_ptr<C2SettingResult> *d, const SettingResult &s) {
    return ::android::objcpy(d, s);
}

// C2ParamDescriptor -> ParamDescriptor
bool ToAidl(ParamDescriptor *d, const C2ParamDescriptor &s) {
    return ::android::objcpy(d, s);
}

// ParamDescriptor -> C2ParamDescriptor
bool FromAidl(std::shared_ptr<C2ParamDescriptor> *d, const ParamDescriptor &s) {
    return ::android::objcpy(d, s);
}

// C2StructDescriptor -> StructDescriptor
bool ToAidl(StructDescriptor *d, const C2StructDescriptor &s) {
    return ::android::objcpy(d, s);
}

// StructDescriptor -> C2StructDescriptor
bool FromAidl(std::unique_ptr<C2StructDescriptor> *d, const StructDescriptor &s) {
    return ::android::objcpy(d, s);
}

// Params -> std::vector<C2Param*>
bool ParseParamsBlob(std::vector<C2Param*> *params, const Params &blob) {
    return ::android::parseParamsBlob(params, blob);
}

// std::vector<const C2Param*> -> Params
bool CreateParamsBlob(
        Params *blob,
        const std::vector<const C2Param*> &params) {
    return ::android::_createParamsBlob(blob, params);
}

// std::vector<C2Param*> -> Params
bool CreateParamsBlob(
        Params *blob,
        const std::vector<C2Param*> &params) {
    return ::android::_createParamsBlob(blob, params);
}

// std::vector<std::unique_ptr<C2Param>> -> Params
bool CreateParamsBlob(
        Params *blob,
        const std::vector<std::unique_ptr<C2Param>> &params) {
    return ::android::_createParamsBlob(blob, params);
}

// std::vector<std::unique_ptr<C2Tuning>> -> Params
bool CreateParamsBlob(
        Params *blob,
        const std::vector<std::unique_ptr<C2Tuning>> &params) {
    return ::android::_createParamsBlob(blob, params);
}

// std::vector<std::shared_ptr<const C2Info>> -> Params
bool CreateParamsBlob(
        Params *blob,
        const std::vector<std::shared_ptr<const C2Info>> &params) {
    return ::android::_createParamsBlob(blob, params);
}

// Params -> std::vector<std::unique_ptr<C2Param>>
bool CopyParamsFromBlob(
        std::vector<std::unique_ptr<C2Param>>* params,
        Params blob) {
    return ::android::_copyParamsFromBlob(params, blob);
}

// Params -> std::vector<std::unique_ptr<C2Tuning>>
bool CopyParamsFromBlob(
        std::vector<std::unique_ptr<C2Tuning>>* params,
        Params blob) {
    return ::android::_copyParamsFromBlob(params, blob);
}

// Params -> update std::vector<std::unique_ptr<C2Param>>
bool UpdateParamsFromBlob(
        const std::vector<C2Param*>& params,
        const Params& blob) {
    return ::android::updateParamsFromBlob(params, blob);
}

}  // namespace utils
}  // namespace c2
}  // namespace media
}  // namespace hardware
}  // namespace android
}  // namespace aidl
