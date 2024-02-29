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
#define LOG_TAG "Codec2-ComponentInterface"
#include <android-base/logging.h>

#include <codec2/hidl/1.0/Component.h>
#include <codec2/hidl/1.0/ComponentInterface.h>
#include <codec2/hidl/1.0/ComponentStore.h>

#include <hidl/HidlBinderSupport.h>
#include <utils/Timers.h>

#include <C2Debug.h>
#include <C2PlatformSupport.h>

#include <chrono>
#include <thread>

namespace android {
namespace hardware {
namespace media {
namespace c2 {
namespace V1_0 {
namespace utils {

using namespace ::android;

namespace /* unnamed */ {

// Implementation of ConfigurableC2Intf based on C2ComponentInterface
struct CompIntf : public ConfigurableC2Intf {
    CompIntf(const std::shared_ptr<C2ComponentInterface>& intf,
        const std::shared_ptr<MultiAccessUnitInterface>& multiAccessUnitIntf):
        ConfigurableC2Intf{intf->getName(), intf->getId()},
        mIntf{intf}, mMultiAccessUnitIntf{multiAccessUnitIntf} {
    }

    virtual c2_status_t config(
            const std::vector<C2Param*>& params,
            c2_blocking_t mayBlock,
            std::vector<std::unique_ptr<C2SettingResult>>* const failures
            ) override {
        std::vector<C2Param*> paramsToIntf;
        std::vector<C2Param*> paramsToLargeFrameIntf;
        c2_status_t err = C2_OK;
        if (mMultiAccessUnitIntf == nullptr) {
            err = mIntf->config_vb(params, mayBlock, failures);
            return err;
        }
        for (auto &p : params) {
            if (mMultiAccessUnitIntf->isParamSupported(p->index())) {
                paramsToLargeFrameIntf.push_back(p);
            } else {
                paramsToIntf.push_back(p);
            }
        }
        c2_status_t err1 = C2_OK;
        if (paramsToIntf.size() > 0) {
            err1 = mIntf->config_vb(paramsToIntf, mayBlock, failures);
        }
        if (err1 != C2_OK) {
            LOG(ERROR) << "We have a failed config";
        }
        c2_status_t err2 = C2_OK;
        if (paramsToLargeFrameIntf.size() > 0) {
            err2 = mMultiAccessUnitIntf->config(
                    paramsToLargeFrameIntf, mayBlock, failures);
        }
        // TODO: correct failure vector
        return err1 != C2_OK ? err1 : err2;
    }

    virtual c2_status_t query(
            const std::vector<C2Param::Index>& indices,
            c2_blocking_t mayBlock,
            std::vector<std::unique_ptr<C2Param>>* const params
            ) const override {
        c2_status_t err = C2_OK;
        if (mMultiAccessUnitIntf == nullptr) {
            err = mIntf->query_vb({}, indices, mayBlock, params);
            return err;
        }
        std::vector<C2Param::Index> paramsToIntf;
        std::vector<C2Param::Index> paramsToLargeFrameIntf;
        for (auto &i : indices) {
            if (mMultiAccessUnitIntf->isParamSupported(i)) {
                paramsToLargeFrameIntf.push_back(i);
            } else {
                paramsToIntf.push_back(i);
            }
        }
        c2_status_t err1 = C2_OK;
        if (paramsToIntf.size() > 0) {
            err1 = mIntf->query_vb({}, paramsToIntf, mayBlock, params);
        }
        c2_status_t err2 = C2_OK;
        if (paramsToLargeFrameIntf.size() > 0) {
            err2 = mMultiAccessUnitIntf->query(
                    {}, paramsToLargeFrameIntf, mayBlock, params);
        }
        // TODO: correct failure vector
        return err1 != C2_OK ? err1 : err2;
    }

    virtual c2_status_t querySupportedParams(
            std::vector<std::shared_ptr<C2ParamDescriptor>>* const params
            ) const override {
        c2_status_t err = mIntf->querySupportedParams_nb(params);
        if (mMultiAccessUnitIntf != nullptr) {
            err =  mMultiAccessUnitIntf->querySupportedParams(params);
        }
        return err;
    }

    virtual c2_status_t querySupportedValues(
            std::vector<C2FieldSupportedValuesQuery>& fields,
            c2_blocking_t mayBlock) const override {
        if (mMultiAccessUnitIntf == nullptr) {
           return  mIntf->querySupportedValues_vb(fields, mayBlock);
        }
        std::vector<C2FieldSupportedValuesQuery> dup = fields;
        std::vector<C2FieldSupportedValuesQuery> queryArray[2];
        std::map<C2ParamField, std::pair<uint32_t, size_t>> queryMap;
        c2_status_t err = C2_OK;
        for (int i = 0 ; i < fields.size(); i++) {
            const C2ParamField &field = fields[i].field();
            uint32_t queryArrayIdx = 1;
            if (mMultiAccessUnitIntf->isValidField(field)) {
                queryArrayIdx = 0;
            }
            queryMap[field] = std::make_pair(
                    queryArrayIdx, queryArray[queryArrayIdx].size());
            queryArray[queryArrayIdx].push_back(fields[i]);
        }
        if (queryArray[0].size() > 0) {
            err = mMultiAccessUnitIntf->querySupportedValues(queryArray[0], mayBlock);
        }
        if (queryArray[1].size() > 0) {
             err = mIntf->querySupportedValues_vb(queryArray[1], mayBlock);
        }
        for (int i = 0 ; i < dup.size(); i++) {
            auto it = queryMap.find(dup[i].field());
            if (it != queryMap.end()) {
                std::pair<uint32_t, size_t> queryid = it->second;
                fields[i] = queryArray[queryid.first][queryid.second];
            }
        }
        return err;
    }

protected:
    std::shared_ptr<C2ComponentInterface> mIntf;
    std::shared_ptr<MultiAccessUnitInterface> mMultiAccessUnitIntf;
};

} // unnamed namespace


// ComponentInterface
ComponentInterface::ComponentInterface(
        const std::shared_ptr<C2ComponentInterface>& intf,
        const std::shared_ptr<ParameterCache>& cache):ComponentInterface(intf, nullptr, cache) {
}

ComponentInterface::ComponentInterface(
        const std::shared_ptr<C2ComponentInterface>& intf,
        const std::shared_ptr<MultiAccessUnitInterface>& multiAccessUnitIntf,
        const std::shared_ptr<ParameterCache>& cache)
      : mInterface{intf},
        mConfigurable{new CachedConfigurable(
                std::make_unique<CompIntf>(intf, multiAccessUnitIntf))} {
    mInit = mConfigurable->init(cache);
}

c2_status_t ComponentInterface::status() const {
    return mInit;
}

Return<sp<IConfigurable>> ComponentInterface::getConfigurable() {
    return mConfigurable;
}

}  // namespace utils
}  // namespace V1_0
}  // namespace c2
}  // namespace media
}  // namespace hardware
}  // namespace android

