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

#ifndef VENDOR_GOOGLE_MEDIA_C2_V1_0_COMPONENTSTORE_H
#define VENDOR_GOOGLE_MEDIA_C2_V1_0_COMPONENTSTORE_H

#include <codec2/hidl/1.0/Component.h>
#include <codec2/hidl/1.0/Configurable.h>
#include <C2Component.h>
#include <C2Param.h>
#include <C2.h>

#include <vendor/google/media/c2/1.0/IComponentStore.h>
#include <android/hardware/media/bufferpool/1.0/IClientManager.h>
#include <hidl/MQDescriptor.h>
#include <hidl/Status.h>

#include <vector>
#include <map>
#include <memory>

namespace vendor {
namespace google {
namespace media {
namespace c2 {
namespace V1_0 {
namespace implementation {

using ::android::hardware::media::bufferpool::V1_0::IClientManager;

using ::android::hardware::hidl_array;
using ::android::hardware::hidl_memory;
using ::android::hardware::hidl_string;
using ::android::hardware::hidl_vec;
using ::android::hardware::Return;
using ::android::hardware::Void;
using ::android::sp;

struct ComponentStore : public Configurable<IComponentStore> {
    ComponentStore(const std::shared_ptr<C2ComponentStore>& store);
    virtual ~ComponentStore() = default;

    c2_status_t status() const {
        return mInit;
    }

    c2_status_t validateSupportedParams(
            const std::vector<std::shared_ptr<C2ParamDescriptor>>& params);

    // Methods from ::android::hardware::media::c2::V1_0::IComponentStore
    Return<void> createComponent(
            const hidl_string& name,
            const sp<IComponentListener>& listener,
            const sp<IClientManager>& pool,
            createComponent_cb _hidl_cb) override;
    Return<void> createInterface(
            const hidl_string& name,
            createInterface_cb _hidl_cb) override;
    Return<void> listComponents(listComponents_cb _hidl_cb) override;
    Return<sp<IInputSurface>> createInputSurface() override;
    Return<void> getStructDescriptors(
            const hidl_vec<uint32_t>& indices,
            getStructDescriptors_cb _hidl_cb) override;
    Return<sp<IClientManager>> getPoolClientManager() override;
    Return<Status> copyBuffer(
            const Buffer& src,
            const Buffer& dst) override;

protected:
    c2_status_t mInit;
    std::shared_ptr<C2ComponentStore> mStore;
    std::shared_ptr<C2ParamReflector> mParamReflector;
    std::map<C2Param::CoreIndex, std::shared_ptr<C2StructDescriptor>>
            mStructDescriptors;

    sp<IClientManager> mPoolManager;
};

}  // namespace implementation
}  // namespace V1_0
}  // namespace c2
}  // namespace media
}  // namespace google
}  // namespace vendor

#endif  // VENDOR_GOOGLE_MEDIA_C2_V1_0_COMPONENTSTORE_H
