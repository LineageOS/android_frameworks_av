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
#define LOG_TAG "Codec2-Configurable-Aidl"
#include <android-base/logging.h>

#include <android/binder_auto_utils.h>
#include <android-base/hex.h>
#include <codec2/aidl/Configurable.h>
#include <codec2/aidl/ParamTypes.h>

#include <C2ParamInternal.h>

namespace aidl {
namespace android {
namespace hardware {
namespace media {
namespace c2 {
namespace utils {

using ::ndk::ScopedAStatus;

CachedConfigurable::CachedConfigurable(
        std::unique_ptr<ConfigurableC2Intf>&& intf)
      : mIntf{std::move(intf)} {
}

c2_status_t CachedConfigurable::init(
        const std::shared_ptr<ParameterCache>& cache) {
    // Retrieve supported parameters from store
    c2_status_t init = mIntf->querySupportedParams(&mSupportedParams);
    c2_status_t validate = cache->validate(mSupportedParams);
    return init == C2_OK ? C2_OK : validate;
}

// Methods from ::android::hardware::media::c2::V1_0::IConfigurable follow.

ScopedAStatus CachedConfigurable::getId(int32_t* id) {
    *id = mIntf->getId();
    return ScopedAStatus::ok();
}

ScopedAStatus CachedConfigurable::getName(std::string* name) {
    *name = mIntf->getName();
    return ScopedAStatus::ok();
}

ScopedAStatus CachedConfigurable::query(
        const std::vector<int32_t>& indices,
        bool mayBlock,
        QueryResult *queryResult) {
    typedef C2Param::Index Index;
    std::vector<Index> c2heapParamIndices(
            (Index*)indices.data(),
            (Index*)indices.data() + indices.size());
    std::vector<std::unique_ptr<C2Param>> c2heapParams;
    c2_status_t c2res = mIntf->query(
            c2heapParamIndices,
            mayBlock ? C2_MAY_BLOCK : C2_DONT_BLOCK,
            &c2heapParams);

    if (!CreateParamsBlob(&(queryResult->params), c2heapParams)) {
        LOG(WARNING) << "query -- invalid output params.";
    }
    queryResult->status.status = c2res;
    return ScopedAStatus::ok();
}

ScopedAStatus CachedConfigurable::config(
        const Params& params,
        bool mayBlock,
        ConfigResult* result) {
    // inParams is not writable, so create a copy as config modifies the parameters
    std::vector<C2Param*> c2params;
    if (!ParseParamsBlob(&c2params, params)) {
        LOG(WARNING) << "config -- invalid input params.";
        return ScopedAStatus::fromServiceSpecificError(C2_CORRUPTED);
    }
    // TODO: check if blob was invalid
    std::vector<std::unique_ptr<C2SettingResult>> c2failures;
    c2_status_t c2res = mIntf->config(
            c2params,
            mayBlock ? C2_MAY_BLOCK : C2_DONT_BLOCK,
            &c2failures);
    result->failures.resize(c2failures.size());
    {
        size_t ix = 0;
        for (const std::unique_ptr<C2SettingResult>& c2result : c2failures) {
            if (c2result) {
                if (ToAidl(&result->failures[ix], *c2result)) {
                    ++ix;
                } else {
                    LOG(DEBUG) << "config -- invalid setting results.";
                    break;
                }
            }
        }
        result->failures.resize(ix);
    }
    if (!CreateParamsBlob(&result->params, c2params)) {
        LOG(DEBUG) << "config -- invalid output params.";
    }
    result->status.status = c2res;
    return ScopedAStatus::ok();
}

ScopedAStatus CachedConfigurable::querySupportedParams(
        int32_t start,
        int32_t count,
        std::vector<ParamDescriptor>* paramDesc) {
    C2LinearRange request = C2LinearCapacity(mSupportedParams.size()).range(
            start, count);
    paramDesc->resize(request.size());
    int32_t res = Status::OK;
    size_t dstIx = 0;
    for (size_t srcIx = request.offset(); srcIx < request.endOffset(); ++srcIx) {
        if (mSupportedParams[srcIx]) {
            if (ToAidl(&(*paramDesc)[dstIx], *mSupportedParams[srcIx])) {
                ++dstIx;
            } else {
                res = Status::CORRUPTED;
                LOG(WARNING) << "querySupportedParams -- invalid output params.";
                break;
            }
        }
    }
    paramDesc->resize(dstIx);
    if (res == Status::OK) {
        return ScopedAStatus::ok();
    }
    return ScopedAStatus::fromServiceSpecificError(res);
}

ScopedAStatus CachedConfigurable::querySupportedValues(
        const std::vector<FieldSupportedValuesQuery>& fields,
        bool mayBlock,
        QuerySupportedValuesResult *queryValues) {
    std::vector<C2FieldSupportedValuesQuery> c2fields;
    {
        // C2FieldSupportedValuesQuery objects are restricted in that some
        // members are const.
        // C2ParamField - required for its constructor - has no constructors
        // from fields. Use C2ParamInspector.
        for (const FieldSupportedValuesQuery &query : fields) {
            c2fields.emplace_back(_C2ParamInspector::CreateParamField(
                    (uint32_t)query.field.index,
                    query.field.fieldId.offset,
                    query.field.fieldId.sizeBytes),
                    query.type == FieldSupportedValuesQuery::Type::POSSIBLE ?
                    C2FieldSupportedValuesQuery::POSSIBLE :
                    C2FieldSupportedValuesQuery::CURRENT);
        }
    }
    c2_status_t c2res = mIntf->querySupportedValues(
            c2fields,
            mayBlock ? C2_MAY_BLOCK : C2_DONT_BLOCK);
    queryValues->values.resize(fields.size());
    size_t dstIx = 0;
    for (const C2FieldSupportedValuesQuery &res : c2fields) {
        if (ToAidl(&(queryValues->values[dstIx]), res)) {
            ++dstIx;
        } else {
            queryValues->values.resize(dstIx);
            c2res = C2_CORRUPTED;
            LOG(WARNING) << "querySupportedValues -- invalid output params.";
            break;
        }
    }
    queryValues->status.status = c2res;
    return ScopedAStatus::ok();
}

}  // namespace utils
}  // namespace c2
}  // namespace media
}  // namespace hardware
}  // namespace android
}  // namespace aidl

