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

#include <sys/mman.h>

#include <android-base/no_destructor.h>
#include <android-base/properties.h>
#include <android_media_swcodec_flags.h>
#include <apex/ApexCodecsImpl.h>

#ifdef ENABLE_APEX_CODECS
#include <android/api-level.h>
#include <util/C2InterfaceHelper.h>
#include "C2ApexAacDec.h"

#ifdef __aarch64__
#include "C2ApexOpusDec.h"
#endif

#endif

namespace android::apexcodecs {

#ifdef ENABLE_APEX_CODECS

namespace {

static int GetApiLevel() {
    int apiLevel = android_get_device_api_level();
    bool isPreview = (android::base::GetIntProperty("ro.build.version.preview_sdk", 0) != 0);
    return isPreview ? apiLevel + 1 : apiLevel;
}

struct ComponentDesc {
    std::shared_ptr<const C2Component::Traits> traits;
    std::function<std::unique_ptr<ApexComponentIntf>(
            const std::shared_ptr<C2ReflectorHelper>&)> createComponentFn;
    ApexCodec_MapFn mapFn;
    ApexCodec_UnmapFn unmapFn;
};

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

    ApexCodec_MapFn getMapFn(const char *name) const {
        if (mCodecs.count(name) == 0) {
            return ::mmap;
        }
        return mCodecs.at(name).mapFn;
    }


    ApexCodec_UnmapFn getUnmapFn(const char *name) const {
        if (mCodecs.count(name) == 0) {
            return ::munmap;
        }
        return mCodecs.at(name).unmapFn;
    }

private:
    template <typename Codec>
    static void AddCodec(std::map<std::string, ComponentDesc> *codecs) {
        if (!codecs) {
            return;
        }
        (*codecs)[Codec::COMPONENT_NAME] = ComponentDesc{
            Codec::MakeTraits(),
            Codec::Create,
            Codec::Map,
            Codec::Unmap,
        };
    }

    static std::map<std::string, ComponentDesc> BuildCodecs() {
        std::map<std::string, ComponentDesc> codecs;
#ifdef __aarch64__
        if (android::media::swcodec::flags::opus_inproc_software_decoder()) {
            static bool sIs64bitOnly = []() {
                return ::android::base::GetProperty("ro.product.cpu.abilist32", "").empty();
            }();
            if (GetApiLevel() >= 37 && sIs64bitOnly ) {
                AddCodec<C2ApexOpusDec>(&codecs);
            }
        }
#endif
        if (android::media::swcodec::flags::rust_aac_software_decoder()) {
            if (GetApiLevel() >= 37) {
                AddCodec<C2ApexAacDec>(&codecs);
            }
        }
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
    ApexCodec_MapFn getMapFn(const char *name) const override {
        return mImpl.getMapFn(name);
    }
    ApexCodec_UnmapFn getUnmapFn(const char *name) const override {
        return mImpl.getUnmapFn(name);
    }

private:
    StoreImpl mImpl;
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
    ApexCodec_MapFn getMapFn(const char *) const override {
        return ::mmap;
    }
    ApexCodec_UnmapFn getUnmapFn(const char *) const override {
        return ::munmap;
    }
};

#endif

}  // namespace android::apexcodecs

extern "C" void *GetApexComponentStore() {
    static ::android::base::NoDestructor<::android::apexcodecs::ApexComponentStoreImpl> sStore;
    return sStore.get();
}
