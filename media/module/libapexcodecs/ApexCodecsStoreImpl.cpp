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

//#define LOG_NDEBUG 0
#define LOG_TAG "ApexCodecsStoreImpl"
#include <utils/Log.h>

#include <android-base/no_destructor.h>
#include <apex/ApexCodecsImpl.h>
#include <util/C2InterfaceHelper.h>

namespace android::apexcodecs {

class ApexComponentStoreImpl : public ApexComponentStoreIntf {
public:
    ApexComponentStoreImpl() : mReflector(std::make_shared<C2ReflectorHelper>()) {
    }
    std::vector<std::shared_ptr<const C2Component::Traits>> listComponents() const override {
        return std::vector(mTraits);
    }
    std::unique_ptr<ApexComponentIntf> createComponent(const char *name [[maybe_unused]]) override {
        return nullptr;
    }
    std::shared_ptr<C2ParamReflector> getParamReflector() const override {
        return mReflector;
    }

private:
    std::vector<std::shared_ptr<const C2Component::Traits>> mTraits;
    std::shared_ptr<C2ReflectorHelper> mReflector;
};

}  // namespace android::apexcodecs

extern "C" void *GetApexComponentStore() {
    static ::android::base::NoDestructor<::android::apexcodecs::ApexComponentStoreImpl> sStore;
    return sStore.get();
}
