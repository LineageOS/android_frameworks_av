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

#ifndef CODEC2_AIDL_UTILS_CONFIGURABLE_H
#define CODEC2_AIDL_UTILS_CONFIGURABLE_H

#include <aidl/android/hardware/media/c2/BnConfigurable.h>

#include <C2Component.h>
#include <C2Param.h>
#include <C2.h>

#include <memory>

namespace aidl {
namespace android {
namespace hardware {
namespace media {
namespace c2 {
namespace utils {

struct ComponentStore;

/**
 * Codec2 objects of different types may have different querying and configuring
 * functions, but across the Treble boundary, they share the same HIDL
 * interface, IConfigurable.
 *
 * ConfigurableC2Intf is an abstract class that a Codec2 object can implement to
 * easily expose an IConfigurable instance. See CachedConfigurable below.
 */
struct ConfigurableC2Intf {
    C2String getName() const { return mName; }
    uint32_t getId() const { return mId; }
    /** C2ComponentInterface::query_vb sans stack params */
    virtual c2_status_t query(
            const std::vector<C2Param::Index> &indices,
            c2_blocking_t mayBlock,
            std::vector<std::unique_ptr<C2Param>>* const params) const = 0;
    /** C2ComponentInterface::config_vb */
    virtual c2_status_t config(
            const std::vector<C2Param*> &params,
            c2_blocking_t mayBlock,
            std::vector<std::unique_ptr<C2SettingResult>>* const failures) = 0;
    /** C2ComponentInterface::querySupportedParams_nb */
    virtual c2_status_t querySupportedParams(
            std::vector<std::shared_ptr<C2ParamDescriptor>>* const params) const = 0;
    /** C2ComponentInterface::querySupportedParams_nb */
    virtual c2_status_t querySupportedValues(
            std::vector<C2FieldSupportedValuesQuery>& fields, c2_blocking_t mayBlock) const = 0;

    virtual ~ConfigurableC2Intf() = default;

    ConfigurableC2Intf(const C2String& name, uint32_t id)
          : mName{name}, mId{id} {}

protected:
    C2String mName; /* cached component name */
    uint32_t mId;
};

/**
 * Type for validating and caching parameters when CachedConfigurable is
 * initialized.
 *
 * This is meant to be created by the ComponentStore. The purpose of abstracting
 * this is to allow different versions of ComponentStore to work with this
 * CachedConfigurable.
 */
struct ParameterCache {
    virtual c2_status_t validate(
            const std::vector<std::shared_ptr<C2ParamDescriptor>>&) = 0;
    virtual ~ParameterCache() = default;
};

/**
 * Implementation of the IConfigurable interface that supports caching of
 * supported parameters from a supplied ComponentStore.
 *
 * CachedConfigurable essentially converts a ConfigurableC2Intf into HIDL's
 * IConfigurable. A Codec2 object generally implements ConfigurableC2Intf and
 * passes the implementation to the constructor of CachedConfigurable.
 *
 * Note that caching happens
 */
struct CachedConfigurable : public BnConfigurable {
    CachedConfigurable(std::unique_ptr<ConfigurableC2Intf>&& intf);

    // Populates mSupportedParams.
    c2_status_t init(const std::shared_ptr<ParameterCache> &cache);

    // Methods from ::android::hardware::media::c2::V1_0::IConfigurable

    virtual ::ndk::ScopedAStatus getId(int32_t* id) override;

    virtual ::ndk::ScopedAStatus getName(std::string* name) override;

    virtual ::ndk::ScopedAStatus query(
            const std::vector<int32_t>& indices,
            bool mayBlock,
            QueryResult* result) override;

    virtual ::ndk::ScopedAStatus config(
            const ::aidl::android::hardware::media::c2::Params& params,
            bool mayBlock,
            ConfigResult* result) override;

    virtual ::ndk::ScopedAStatus querySupportedParams(
            int32_t start,
            int32_t count,
            std::vector<ParamDescriptor>* paramDesc) override;

    virtual ::ndk::ScopedAStatus querySupportedValues(
            const std::vector<FieldSupportedValuesQuery>& fields,
            bool mayBlock,
            QuerySupportedValuesResult* result) override;

protected:
    // Common Codec2.0 interface wrapper
    std::unique_ptr<ConfigurableC2Intf> mIntf;

    // Cached supported params
    std::vector<std::shared_ptr<C2ParamDescriptor>> mSupportedParams;
};

}  // namespace utils
}  // namespace c2
}  // namespace media
}  // namespace hardware
}  // namespace android
}  // namespace aidl

#endif  // CODEC2_AIDL_UTILS_CONFIGURABLE_H

