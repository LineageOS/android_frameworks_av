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

#ifndef HARDWARE_GOOGLE_MEDIA_C2_V1_0_UTILS_CONFIGURABLE_H
#define HARDWARE_GOOGLE_MEDIA_C2_V1_0_UTILS_CONFIGURABLE_H

#include <codec2/hidl/1.0/ConfigurableC2Intf.h>

#include <C2Component.h>
#include <C2Param.h>
#include <C2.h>

#include <hardware/google/media/c2/1.0/IConfigurable.h>
#include <hidl/Status.h>

#include <memory>

namespace hardware {
namespace google {
namespace media {
namespace c2 {
namespace V1_0 {
namespace utils {

using ::android::hardware::hidl_array;
using ::android::hardware::hidl_memory;
using ::android::hardware::hidl_string;
using ::android::hardware::hidl_vec;
using ::android::hardware::Return;
using ::android::hardware::Void;
using ::android::sp;

struct ComponentStore;

/**
 * Implementation of the IConfigurable interface that supports caching of
 * supported parameters from a supplied ComponentStore.
 *
 * This is mainly the same for all of the configurable C2 interfaces though
 * there are slight differences in the blocking behavior. This is handled in the
 * ConfigurableC2Intf implementations.
 */
struct CachedConfigurable : public IConfigurable {
    CachedConfigurable(std::unique_ptr<ConfigurableC2Intf>&& intf);

    c2_status_t init(ComponentStore* store);

    // Methods from ::android::hardware::media::c2::V1_0::IConfigurable

    virtual Return<void> getName(getName_cb _hidl_cb) override;

    virtual Return<void> query(
            const hidl_vec<uint32_t>& indices,
            bool mayBlock,
            query_cb _hidl_cb) override;

    virtual Return<void> config(
            const hidl_vec<uint8_t>& inParams,
            bool mayBlock,
            config_cb _hidl_cb) override;

    virtual Return<void> querySupportedParams(
            uint32_t start,
            uint32_t count,
            querySupportedParams_cb _hidl_cb) override;

    virtual Return<void> querySupportedValues(
            const hidl_vec<FieldSupportedValuesQuery>& inFields,
            bool mayBlock,
            querySupportedValues_cb _hidl_cb) override;

protected:
    // Common Codec2.0 interface wrapper
    std::unique_ptr<ConfigurableC2Intf> mIntf;

    // Cached supported params
    std::vector<std::shared_ptr<C2ParamDescriptor>> mSupportedParams;
};

/**
 * Template that implements the `IConfigurable` interface for an inherited
 * interface. Classes that implement a child interface `I` of `IConfigurable`
 * can derive from `Configurable<I>`.
 */
template <typename I>
struct Configurable : public I {
    Configurable(const sp<CachedConfigurable>& intf): mIntf(intf) {
    }

    c2_status_t init(ComponentStore* store) {
        return mIntf->init(store);
    }

    // Methods from ::android::hardware::media::c2::V1_0::IConfigurable

    using getName_cb = typename I::getName_cb;
    virtual Return<void> getName(getName_cb _hidl_cb) override {
        return mIntf->getName(_hidl_cb);
    }

    using query_cb = typename I::query_cb;
    virtual Return<void> query(
            const hidl_vec<uint32_t>& indices,
            bool mayBlock,
            query_cb _hidl_cb) override {
        return mIntf->query(indices, mayBlock, _hidl_cb);
    }

    using config_cb = typename I::config_cb;
    virtual Return<void> config(
            const hidl_vec<uint8_t>& inParams,
            bool mayBlock,
            config_cb _hidl_cb) override {
        return mIntf->config(inParams, mayBlock, _hidl_cb);
    }

    using querySupportedParams_cb = typename I::querySupportedParams_cb;
    virtual Return<void> querySupportedParams(
            uint32_t start,
            uint32_t count,
            querySupportedParams_cb _hidl_cb) override {
        return mIntf->querySupportedParams(start, count, _hidl_cb);
    }

    using querySupportedValues_cb = typename I::querySupportedValues_cb;
    virtual Return<void> querySupportedValues(
            const hidl_vec<FieldSupportedValuesQuery>& inFields,
            bool mayBlock,
            querySupportedValues_cb _hidl_cb) override {
        return mIntf->querySupportedValues(inFields, mayBlock, _hidl_cb);
    }

protected:
    sp<CachedConfigurable> mIntf;
};

}  // namespace utils
}  // namespace V1_0
}  // namespace c2
}  // namespace media
}  // namespace google
}  // namespace hardware

#endif  // HARDWARE_GOOGLE_MEDIA_C2_V1_0_UTILS_CONFIGURABLE_H
