/*
 * Copyright (C) 2018 The Android Open Source Project
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

#ifndef VENDOR_GOOGLE_MEDIA_C2_V1_0_TYPES_H
#define VENDOR_GOOGLE_MEDIA_C2_V1_0_TYPES_H

#include <vendor/google/media/c2/1.0/types.h>
#include <vendor/google/media/c2/1.0/IComponentStore.h>

#include <C2Param.h>
#include <C2Component.h>
#include <C2Work.h>

namespace vendor {
namespace google {
namespace media {
namespace c2 {
namespace V1_0 {
namespace implementation {

using ::android::hardware::hidl_bitfield;
using ::android::hardware::hidl_handle;
using ::android::hardware::hidl_string;
using ::android::hardware::hidl_vec;
using ::android::sp;

// Types of metadata for Blocks.
struct C2Hidl_Range {
    uint32_t offset;
    uint32_t length; // Do not use "size" because the name collides with C2Info::size().
};
typedef C2GlobalParam<C2Info, C2Hidl_Range, 0> C2Hidl_RangeInfo;

struct C2Hidl_Rect {
    uint32_t left;
    uint32_t top;
    uint32_t width;
    uint32_t height;
};
typedef C2GlobalParam<C2Info, C2Hidl_Rect, 1> C2Hidl_RectInfo;

// C2SettingResult -> SettingResult
Status C2_HIDE objcpy(
        SettingResult* d,
        const C2SettingResult& s);

// SettingResult -> C2SettingResult
c2_status_t C2_HIDE objcpy(
        C2SettingResult* d,
        const SettingResult& s);

// C2ParamDescriptor -> ParamDescriptor
Status C2_HIDE objcpy(
        ParamDescriptor* d,
        const C2ParamDescriptor& s);

// ParamDescriptor -> std::unique_ptr<C2ParamDescriptor>
c2_status_t C2_HIDE objcpy(
        std::unique_ptr<C2ParamDescriptor>* d,
        const ParamDescriptor& s);

// C2FieldSupportedValuesQuery -> FieldSupportedValuesQuery
Status C2_HIDE objcpy(
        FieldSupportedValuesQuery* d,
        const C2FieldSupportedValuesQuery& s);

// FieldSupportedValuesQuery -> C2FieldSupportedValuesQuery
c2_status_t C2_HIDE objcpy(
        C2FieldSupportedValuesQuery* d,
        const FieldSupportedValuesQuery& s);

// C2FieldSupportedValuesQuery -> FieldSupportedValuesQueryResult
Status C2_HIDE objcpy(
        FieldSupportedValuesQueryResult* d,
        const C2FieldSupportedValuesQuery& s);

// FieldSupportedValuesQuery, FieldSupportedValuesQueryResult -> C2FieldSupportedValuesQuery
c2_status_t C2_HIDE objcpy(
        C2FieldSupportedValuesQuery* d,
        const FieldSupportedValuesQuery& sq,
        const FieldSupportedValuesQueryResult& sr);

// C2Component::Traits -> ComponentTraits
Status C2_HIDE objcpy(
        IComponentStore::ComponentTraits* d,
        const C2Component::Traits& s);

// ComponentTraits -> C2Component::Traits
c2_status_t C2_HIDE objcpy(
        C2Component::Traits* d,
        const IComponentStore::ComponentTraits& s);

// C2StructDescriptor -> StructDescriptor
Status C2_HIDE objcpy(
        StructDescriptor* d,
        const C2StructDescriptor& s);

// StructDescriptor -> C2StructDescriptor
// TODO: This cannot be implemented yet because C2StructDescriptor does not
// allow dynamic construction/modification.
c2_status_t C2_HIDE objcpy(
        C2StructDescriptor* d,
        const StructDescriptor& s);

// std::list<std::unique_ptr<C2Work>> -> WorkBundle
// TODO: Connect with Bufferpool
Status C2_HIDE objcpy(
        WorkBundle* d,
        const std::list<std::unique_ptr<C2Work>>& s);

// WorkBundle -> std::list<std::unique_ptr<C2Work>>
// TODO: Connect with Bufferpool
c2_status_t C2_HIDE objcpy(
        std::list<std::unique_ptr<C2Work>>* d,
        const WorkBundle& s);

/**
 * Parses a params blob and returns C2Param pointers to its params.
 * \param[out] params target vector of C2Param pointers
 * \param[in] blob parameter blob to parse
 * \retval C2_OK if the full blob was parsed
 * \retval C2_BAD_VALUE otherwise
 */
c2_status_t parseParamsBlob(
        std::vector<C2Param*> *params,
        const hidl_vec<uint8_t> &blob);

/**
 * Concatenates a list of C2Params into a params blob.
 * \param[out] blob target blob
 * \param[in] params parameters to concatenate
 * \retval C2_OK if the blob was successfully created
 * \retval C2_BAD_VALUE if the blob was not successful (this only happens if the parameters were
 *         not const)
 */
Status createParamsBlob(
        hidl_vec<uint8_t> *blob,
        const std::vector<C2Param*> &params);
Status createParamsBlob(
        hidl_vec<uint8_t> *blob,
        const std::vector<std::unique_ptr<C2Param>> &params);
Status createParamsBlob(
        hidl_vec<uint8_t> *blob,
        const std::vector<std::shared_ptr<const C2Info>> &params);
Status createParamsBlob(
        hidl_vec<uint8_t> *blob,
        const std::vector<std::unique_ptr<C2Tuning>> &params);

}  // namespace implementation
}  // namespace V1_0
}  // namespace c2
}  // namespace media
}  // namespace google
}  // namespace vendor

#endif  // VENDOR_GOOGLE_MEDIA_C2_V1_0_TYPES_H
