/*
 * Copyright (C) 2025 The Android Open Source Project
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

#include <apex/ApexCodecsImpl.h>

namespace android::apexcodecs {

ApexConfigurableImpl::ApexConfigurableImpl(
        const std::shared_ptr<C2ComponentInterface> &intf) : mConfigurable(intf) {}

ApexCodec_Status ApexConfigurableImpl::config(
        const std::vector<C2Param *> &params,
        std::vector<std::unique_ptr<C2SettingResult>> *results) const {
    return (ApexCodec_Status)mConfigurable->config_vb(params, C2_MAY_BLOCK, results);
}

ApexCodec_Status ApexConfigurableImpl::query(
        const std::vector<C2Param::Index> &heapParamIndices,
        std::vector<std::unique_ptr<C2Param>>* const heapParams) const {
    return (ApexCodec_Status)mConfigurable->query_vb(
            {}, heapParamIndices, C2_MAY_BLOCK, heapParams);
}

ApexCodec_Status ApexConfigurableImpl::querySupportedParams(
        std::vector<std::shared_ptr<C2ParamDescriptor>> * const params) const {
    return (ApexCodec_Status)mConfigurable->querySupportedParams_nb(params);
}

ApexCodec_Status ApexConfigurableImpl::querySupportedValues(
        std::vector<C2FieldSupportedValuesQuery> &fields) const {
    return (ApexCodec_Status)mConfigurable->querySupportedValues_vb(fields, C2_MAY_BLOCK);
}

}  // namespace android::apexcodecs
