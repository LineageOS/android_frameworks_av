/*
 * Copyright 2022 The Android Open Source Project
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

#ifndef CODEC2_AIDL_UTILS_PARAM_TYPES_SPECIALIZATIONS_H
#define CODEC2_AIDL_UTILS_PARAM_TYPES_SPECIALIZATIONS_H

#include <aidl/android/hardware/media/c2/FieldId.h>
#include <aidl/android/hardware/media/c2/FieldSupportedValues.h>
#include <aidl/android/hardware/media/c2/Params.h>
#include <aidl/android/hardware/media/c2/Status.h>
#include <codec2/common/ParamTypes.h>

namespace android {

using ::aidl::android::hardware::media::c2::FieldId;
using ::aidl::android::hardware::media::c2::FieldSupportedValues;
using ::aidl::android::hardware::media::c2::Params;
using ::aidl::android::hardware::media::c2::Status;

// {offset, size} -> FieldId
template<>
void SetFieldId(FieldId *d, uint32_t offset, uint32_t size);

// FieldId -> offset
template<>
uint32_t GetOffsetFromFieldId(const FieldId &s);

// FieldId -> size
template<>
uint32_t GetSizeFromFieldId(const FieldId &s);

template<>
void SetStatus(Status *dst, c2_status_t src);

template<>
c2_status_t GetStatus(const Status &status);

// C2FieldSupportedValues -> FieldSupportedValues
template<>
bool objcpy(FieldSupportedValues *d, const C2FieldSupportedValues &s);

// FieldSupportedValues -> C2FieldSupportedValues
template<>
bool objcpy(C2FieldSupportedValues *d, const FieldSupportedValues &s);

template<>
struct _ParamsBlobHelper<Params> { typedef std::vector<uint8_t> BlobType; };

template<>
const std::vector<uint8_t> &GetBlob<Params>(const Params &params);

template<>
std::vector<uint8_t> *GetBlob<Params>(Params *params);

} // namespace android



#endif  // CODEC2_AIDL_UTILS_PARAM_TYPES_SPECIALIZATIONS_H
