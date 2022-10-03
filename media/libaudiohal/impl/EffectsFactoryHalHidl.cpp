/*
 * Copyright (C) 2016 The Android Open Source Project
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

#define LOG_TAG "EffectsFactoryHalHidl"
//#define LOG_NDEBUG 0

#include <optional>
#include <tuple>

#include <cutils/native_handle.h>

#include <UuidUtils.h>
#include <util/EffectUtils.h>
#include <utils/Log.h>

#include "EffectConversionHelperHidl.h"
#include "EffectBufferHalHidl.h"
#include "EffectHalHidl.h"
#include "EffectsFactoryHalHidl.h"

using ::android::hardware::audio::common::CPP_VERSION::implementation::UuidUtils;
using ::android::hardware::audio::effect::CPP_VERSION::implementation::EffectUtils;
using ::android::hardware::Return;

namespace android {
namespace effect {

using namespace ::android::hardware::audio::common::CPP_VERSION;
using namespace ::android::hardware::audio::effect::CPP_VERSION;

class EffectDescriptorCache {
  public:
    using QueryResult = std::tuple<Return<void>, Result, hidl_vec<EffectDescriptor>>;
    QueryResult queryAllDescriptors(IEffectsFactory* effectsFactory);
  private:
    std::mutex mLock;
    std::optional<hidl_vec<EffectDescriptor>> mLastDescriptors;  // GUARDED_BY(mLock)
};

EffectDescriptorCache::QueryResult EffectDescriptorCache::queryAllDescriptors(
        IEffectsFactory* effectsFactory) {
    {
        std::lock_guard l(mLock);
        if (mLastDescriptors.has_value()) {
            return {::android::hardware::Void(), Result::OK, mLastDescriptors.value()};
        }
    }
    Result retval = Result::NOT_INITIALIZED;
    hidl_vec<EffectDescriptor> descriptors;
    Return<void> ret = effectsFactory->getAllDescriptors(
            [&](Result r, const hidl_vec<EffectDescriptor>& result) {
                retval = r;
                if (retval == Result::OK) {
                    descriptors = result;
                }
            });
    if (ret.isOk() && retval == Result::OK) {
        std::lock_guard l(mLock);
        mLastDescriptors = descriptors;
    }
    return {std::move(ret), retval, std::move(descriptors)};
}

EffectsFactoryHalHidl::EffectsFactoryHalHidl(sp<IEffectsFactory> effectsFactory)
        : EffectConversionHelperHidl("EffectsFactory"), mCache(new EffectDescriptorCache) {
    ALOG_ASSERT(effectsFactory != nullptr, "Provided IEffectsFactory service is NULL");
    mEffectsFactory = effectsFactory;
}

status_t EffectsFactoryHalHidl::queryNumberEffects(uint32_t *pNumEffects) {
    if (mEffectsFactory == 0) return NO_INIT;
    auto [ret, retval, descriptors] = mCache->queryAllDescriptors(mEffectsFactory.get());
    if (ret.isOk() && retval == Result::OK) {
        *pNumEffects = descriptors.size();
        return OK;
    } else if (ret.isOk()) {
        return NO_INIT;
    }
    return processReturn(__FUNCTION__, ret);
}

status_t EffectsFactoryHalHidl::getDescriptor(
        uint32_t index, effect_descriptor_t *pDescriptor) {
    if (pDescriptor == nullptr) {
        return BAD_VALUE;
    }
    if (mEffectsFactory == 0) return NO_INIT;
    auto [ret, retval, descriptors] = mCache->queryAllDescriptors(mEffectsFactory.get());
    if (ret.isOk() && retval == Result::OK) {
        if (index >= descriptors.size()) return NAME_NOT_FOUND;
        EffectUtils::effectDescriptorToHal(descriptors[index], pDescriptor);
    } else if (ret.isOk()) {
        return NO_INIT;
    }
    return processReturn(__FUNCTION__, ret);
}

status_t EffectsFactoryHalHidl::getDescriptor(
        const effect_uuid_t *pEffectUuid, effect_descriptor_t *pDescriptor) {
    if (pDescriptor == nullptr || pEffectUuid == nullptr) {
        return BAD_VALUE;
    }
    if (mEffectsFactory == 0) return NO_INIT;
    Uuid hidlUuid;
    UuidUtils::uuidFromHal(*pEffectUuid, &hidlUuid);
    Result retval = Result::NOT_INITIALIZED;
    Return<void> ret = mEffectsFactory->getDescriptor(hidlUuid,
            [&](Result r, const EffectDescriptor& result) {
                retval = r;
                if (retval == Result::OK) {
                    EffectUtils::effectDescriptorToHal(result, pDescriptor);
                }
            });
    if (ret.isOk()) {
        if (retval == Result::OK) return OK;
        else if (retval == Result::INVALID_ARGUMENTS) return NAME_NOT_FOUND;
        else return NO_INIT;
    }
    return processReturn(__FUNCTION__, ret);
}

status_t EffectsFactoryHalHidl::getDescriptors(const effect_uuid_t *pEffectType,
                                               std::vector<effect_descriptor_t> *descriptors) {
    if (pEffectType == nullptr || descriptors == nullptr) {
        return BAD_VALUE;
    }
    if (mEffectsFactory == 0) return NO_INIT;

    auto [ret, retval, hidlDescs] = mCache->queryAllDescriptors(mEffectsFactory.get());
    if (!ret.isOk() || retval != Result::OK) {
        return processReturn(__FUNCTION__, ret, retval);
    }
    for (const auto& hidlDesc : hidlDescs) {
        effect_descriptor_t descriptor;
        EffectUtils::effectDescriptorToHal(hidlDesc, &descriptor);
        if (memcmp(&descriptor.type, pEffectType, sizeof(effect_uuid_t)) == 0) {
            descriptors->push_back(descriptor);
        }
    }
    return descriptors->empty() ? NAME_NOT_FOUND : NO_ERROR;
}

status_t EffectsFactoryHalHidl::createEffect(
        const effect_uuid_t *pEffectUuid, int32_t sessionId, int32_t ioId,
        int32_t deviceId __unused, sp<EffectHalInterface> *effect) {
    if (mEffectsFactory == 0) return NO_INIT;
    Uuid hidlUuid;
    UuidUtils::uuidFromHal(*pEffectUuid, &hidlUuid);
    Result retval = Result::NOT_INITIALIZED;
    Return<void> ret;
#if MAJOR_VERSION >= 6
    ret = mEffectsFactory->createEffect(
            hidlUuid, sessionId, ioId, deviceId,
            [&](Result r, const sp<IEffect>& result, uint64_t effectId) {
                retval = r;
                if (retval == Result::OK) {
                    *effect = new EffectHalHidl(result, effectId);
                }
            });
#else
    if (sessionId == AUDIO_SESSION_DEVICE && ioId == AUDIO_IO_HANDLE_NONE) {
        return INVALID_OPERATION;
    }
    ret = mEffectsFactory->createEffect(
            hidlUuid, sessionId, ioId,
            [&](Result r, const sp<IEffect>& result, uint64_t effectId) {
                retval = r;
                if (retval == Result::OK) {
                    *effect = new EffectHalHidl(result, effectId);
                }
            });
#endif
    if (ret.isOk()) {
        if (retval == Result::OK) return OK;
        else if (retval == Result::INVALID_ARGUMENTS) return NAME_NOT_FOUND;
        else return NO_INIT;
    }
    return processReturn(__FUNCTION__, ret);
}

status_t EffectsFactoryHalHidl::dumpEffects(int fd) {
    if (mEffectsFactory == 0) return NO_INIT;
    native_handle_t* hidlHandle = native_handle_create(1, 0);
    hidlHandle->data[0] = fd;
    Return<void> ret = mEffectsFactory->debug(hidlHandle, {} /* options */);
    native_handle_delete(hidlHandle);

    // TODO(b/111997867, b/177271958)  Workaround - remove when fixed.
    // A Binder transmitted fd may not close immediately due to a race condition b/111997867
    // when the remote binder thread removes the last refcount to the fd blocks in the
    // kernel for binder activity. We send a Binder ping() command to unblock the thread
    // and complete the fd close / release.
    //
    // See DeviceHalHidl::dump(), EffectHalHidl::dump(), StreamHalHidl::dump(),
    //     EffectsFactoryHalHidl::dumpEffects().

    (void)mEffectsFactory->ping(); // synchronous Binder call

    return processReturn(__FUNCTION__, ret);
}

status_t EffectsFactoryHalHidl::allocateBuffer(size_t size, sp<EffectBufferHalInterface>* buffer) {
    return EffectBufferHalHidl::allocate(size, buffer);
}

status_t EffectsFactoryHalHidl::mirrorBuffer(void* external, size_t size,
                          sp<EffectBufferHalInterface>* buffer) {
    return EffectBufferHalHidl::mirror(external, size, buffer);
}

} // namespace effect

// When a shared library is built from a static library, even explicit
// exports from a static library are optimized out unless actually used by
// the shared library. See EffectsFactoryHalHidlEntry.cpp.
extern "C" void* createIEffectsFactoryImpl() {
    auto service = hardware::audio::effect::CPP_VERSION::IEffectsFactory::getService();
    return service ? new effect::EffectsFactoryHalHidl(service) : nullptr;
}

} // namespace android
