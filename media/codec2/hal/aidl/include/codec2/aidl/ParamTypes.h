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

#ifndef CODEC2_AIDL_UTILS_PARAM_TYPES_H
#define CODEC2_AIDL_UTILS_PARAM_TYPES_H

#include <aidl/android/hardware/media/c2/FieldSupportedValuesQuery.h>
#include <aidl/android/hardware/media/c2/FieldSupportedValuesQueryResult.h>
#include <aidl/android/hardware/media/c2/IComponentStore.h>
#include <aidl/android/hardware/media/c2/ParamDescriptor.h>
#include <aidl/android/hardware/media/c2/SettingResult.h>
#include <aidl/android/hardware/media/c2/Status.h>
#include <aidl/android/hardware/media/c2/StructDescriptor.h>

#include <C2Component.h>
#include <C2Param.h>
#include <C2ParamDef.h>
#include <util/C2Debug-base.h>

namespace aidl {
namespace android {
namespace hardware {
namespace media {
namespace c2 {
namespace utils {

// Returns true iff AIDL c2 HAL is enabled
bool IsEnabled();

// Make asString() and operator<< work with Status as well as c2_status_t.
C2_DECLARE_AS_STRING_AND_DEFINE_STREAM_OUT(Status);

/**
 * All To/FromAidl() functions will return a boolean value indicating whether the
 * conversion succeeds or not.
 */

// C2SettingResult -> SettingResult
bool ToAidl(
        SettingResult* d,
        const C2SettingResult& s);

// SettingResult -> std::unique_ptr<C2SettingResult>
bool FromAidl(
        std::unique_ptr<C2SettingResult>* d,
        const SettingResult& s);

// C2ParamDescriptor -> ParamDescriptor
bool ToAidl(
        ParamDescriptor* d,
        const C2ParamDescriptor& s);

// ParamDescriptor -> std::shared_ptr<C2ParamDescriptor>
bool FromAidl(
        std::shared_ptr<C2ParamDescriptor>* d,
        const ParamDescriptor& s);

// C2FieldSupportedValuesQuery -> FieldSupportedValuesQuery
bool ToAidl(
        FieldSupportedValuesQuery* d,
        const C2FieldSupportedValuesQuery& s);

// FieldSupportedValuesQuery -> C2FieldSupportedValuesQuery
bool FromAidl(
        C2FieldSupportedValuesQuery* d,
        const FieldSupportedValuesQuery& s);

// C2FieldSupportedValuesQuery -> FieldSupportedValuesQueryResult
bool ToAidl(
        FieldSupportedValuesQueryResult* d,
        const C2FieldSupportedValuesQuery& s);

// FieldSupportedValuesQuery, FieldSupportedValuesQueryResult -> C2FieldSupportedValuesQuery
bool FromAidl(
        C2FieldSupportedValuesQuery* d,
        const FieldSupportedValuesQuery& sq,
        const FieldSupportedValuesQueryResult& sr);

// C2Component::Traits -> ComponentTraits
bool ToAidl(
        IComponentStore::ComponentTraits* d,
        const C2Component::Traits& s);

// ComponentTraits -> C2Component::Traits
bool FromAidl(
        C2Component::Traits* d,
        const IComponentStore::ComponentTraits& s);

// C2StructDescriptor -> StructDescriptor
bool ToAidl(
        StructDescriptor* d,
        const C2StructDescriptor& s);

// StructDescriptor -> C2StructDescriptor
bool FromAidl(
        std::unique_ptr<C2StructDescriptor>* d,
        const StructDescriptor& s);

/**
 * Parses a params blob and returns C2Param pointers to its params. The pointers
 * point to locations inside the underlying buffer of \p blob. If \p blob is
 * destroyed, the pointers become invalid.
 *
 * \param[out] params target vector of C2Param pointers
 * \param[in] blob parameter blob to parse
 * \retval true if the full blob was parsed
 * \retval false otherwise
 */
bool ParseParamsBlob(
        std::vector<C2Param*> *params,
        const Params &blob);

/**
 * Concatenates a list of C2Params into a params blob.
 *
 * \param[out] blob target blob
 * \param[in] params parameters to concatenate
 * \retval true if the blob was successfully created
 * \retval false if the blob was not successful (this only happens if the
 *         parameters were not const)
 */
bool CreateParamsBlob(
        Params *blob,
        const std::vector<C2Param*> &params);
bool CreateParamsBlob(
        Params *blob,
        const std::vector<std::unique_ptr<C2Param>> &params);
bool CreateParamsBlob(
        Params *blob,
        const std::vector<std::shared_ptr<const C2Info>> &params);
bool CreateParamsBlob(
        Params *blob,
        const std::vector<std::unique_ptr<C2Tuning>> &params);

/**
 * Parses a params blob and create a vector of C2Params whose members are copies
 * of the params in the blob.
 *
 * \param[out] params the resulting vector
 * \param[in] blob parameter blob to parse
 * \retval true if the full blob was parsed and params was constructed
 * \retval false otherwise
 */
bool CopyParamsFromBlob(
        std::vector<std::unique_ptr<C2Param>>* params,
        const Params &blob);
bool CopyParamsFromBlob(
        std::vector<std::unique_ptr<C2Tuning>>* params,
        const Params &blob);

/**
 * Parses a params blob and applies updates to params.
 *
 * \param[in,out] params params to be updated
 * \param[in] blob parameter blob containing updates
 * \retval true if the full blob was parsed and params was updated
 * \retval false otherwise
 */
bool UpdateParamsFromBlob(
        const std::vector<C2Param*>& params,
        const Params& blob);

}  // namespace utils
}  // namespace c2
}  // namespace media
}  // namespace hardware
}  // namespace android
}  // namespace aidl

#endif  // CODEC2_AIDL_UTILS_PARAM_TYPES_H
