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

#include <ranges>

#include <android-base/no_destructor.h>
#include <apex/ApexCodecsImpl.h>

#ifdef ENABLE_APEX_CODECS
#include <util/C2InterfaceHelper.h>
#include "C2ApexOpusDec.h"
#endif

namespace android::apexcodecs {

#ifdef ENABLE_APEX_CODECS

namespace {

struct ComponentDesc {
    std::shared_ptr<const C2Component::Traits> traits;
    std::function<std::unique_ptr<ApexComponentIntf>(
            const std::shared_ptr<C2ReflectorHelper>&)> createComponentFn;
};

template <typename... Codecs>
class StoreImpl {
public:
    StoreImpl() : mCodecs(BuildCodecs()) {}

    std::vector<std::shared_ptr<const C2Component::Traits>> listComponents() const {
        auto view = std::views::values(mCodecs)
                  | std::views::transform([](const ComponentDesc &desc) { return desc.traits; });
        return std::vector(view.begin(), view.end());
    }

    std::unique_ptr<ApexComponentIntf> createComponent(
            const char *name, const std::shared_ptr<C2ReflectorHelper> &reflector) {
        if (mCodecs.count(name) == 0) {
            return nullptr;
        }
        return mCodecs.at(name).createComponentFn(reflector);
    }

private:
    static std::map<std::string, ComponentDesc> BuildCodecs() {
        std::map<std::string, ComponentDesc> codecs;
        ((codecs[Codecs::COMPONENT_NAME] = ComponentDesc{
            Codecs::MakeTraits(),
            Codecs::Create,
        }), ...);
        std::erase_if(codecs, [](const auto &pair) {
            return pair.second.traits == nullptr;
        });
        return codecs;
    }

    const std::map<std::string, ComponentDesc> mCodecs;
};

}  // namespace

class ApexComponentStoreImpl : public ApexComponentStoreIntf {
public:
    ApexComponentStoreImpl() : mReflector(std::make_shared<C2ReflectorHelper>()) {
    }

    std::vector<std::shared_ptr<const C2Component::Traits>> listComponents() const override {
        return mImpl.listComponents();
    }
    std::unique_ptr<ApexComponentIntf> createComponent(const char *name) override {
        return mImpl.createComponent(name, mReflector);
    }
    std::shared_ptr<C2ParamReflector> getParamReflector() const override {
        return mReflector;
    }

private:
    StoreImpl<
        C2ApexOpusDec
    > mImpl;
    std::shared_ptr<C2ReflectorHelper> mReflector;
};

#else

class ApexComponentStoreImpl : public ApexComponentStoreIntf {
public:
    ApexComponentStoreImpl() = default;

    std::vector<std::shared_ptr<const C2Component::Traits>> listComponents() const override {
        return {};
    }
    std::unique_ptr<ApexComponentIntf> createComponent(const char *) override {
        return nullptr;
    }
    std::shared_ptr<C2ParamReflector> getParamReflector() const override {
        return nullptr;
    }
};

#endif

}  // namespace android::apexcodecs

extern "C" void *GetApexComponentStore() {
    static ::android::base::NoDestructor<::android::apexcodecs::ApexComponentStoreImpl> sStore;
    return sStore.get();
}
