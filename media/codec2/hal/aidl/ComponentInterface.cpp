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

#include <android/binder_auto_utils.h>
#include <codec2/aidl/ComponentInterface.h>
#include <codec2/aidl/Configurable.h>

#include <utils/Timers.h>

#include <C2Debug.h>
#include <C2PlatformSupport.h>

#include <chrono>
#include <thread>

namespace aidl {
namespace android {
namespace hardware {
namespace media {
namespace c2 {
namespace utils {

using ::ndk::ScopedAStatus;

namespace /* unnamed */ {

// Implementation of ConfigurableC2Intf based on C2ComponentInterface
struct CompIntf : public ConfigurableC2Intf {
    CompIntf(const std::shared_ptr<C2ComponentInterface>& intf) :
        ConfigurableC2Intf{intf->getName(), intf->getId()},
        mIntf{intf} {
    }

    virtual c2_status_t config(
            const std::vector<C2Param*>& params,
            c2_blocking_t mayBlock,
            std::vector<std::unique_ptr<C2SettingResult>>* const failures
            ) override {
        return mIntf->config_vb(params, mayBlock, failures);
    }

    virtual c2_status_t query(
            const std::vector<C2Param::Index>& indices,
            c2_blocking_t mayBlock,
            std::vector<std::unique_ptr<C2Param>>* const params
            ) const override {
        return mIntf->query_vb({}, indices, mayBlock, params);
    }

    virtual c2_status_t querySupportedParams(
            std::vector<std::shared_ptr<C2ParamDescriptor>>* const params
            ) const override {
        return mIntf->querySupportedParams_nb(params);
    }

    virtual c2_status_t querySupportedValues(
            std::vector<C2FieldSupportedValuesQuery>& fields,
            c2_blocking_t mayBlock) const override {
        return mIntf->querySupportedValues_vb(fields, mayBlock);
    }

protected:
    std::shared_ptr<C2ComponentInterface> mIntf;
};

} // unnamed namespace

// ComponentInterface
ComponentInterface::ComponentInterface(
        const std::shared_ptr<C2ComponentInterface>& intf,
        const std::shared_ptr<ParameterCache>& cache)
      : mInterface{intf},
        mConfigurable{SharedRefBase::make<CachedConfigurable>(
                std::make_unique<CompIntf>(intf))} {
    mInit = mConfigurable->init(cache);
}

c2_status_t ComponentInterface::status() const {
    return mInit;
}

ScopedAStatus ComponentInterface::getConfigurable(
        std::shared_ptr<IConfigurable> *configurable) {
    *configurable = mConfigurable;
    return ScopedAStatus::ok();
}

}  // namespace utils
}  // namespace c2
}  // namespace media
}  // namespace hardware
}  // namespace android
}  // namespace aidl

