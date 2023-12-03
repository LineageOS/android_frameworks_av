/*
 * Copyright 2020 The Android Open Source Project
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
#define LOG_TAG "Codec2-FilterWrapperStub"

#include <FilterWrapper.h>

namespace android {

FilterWrapper::FilterWrapper(std::unique_ptr<Plugin> &&) {
}

FilterWrapper::~FilterWrapper() {
}

std::shared_ptr<C2ComponentInterface> FilterWrapper::maybeWrapInterface(
        const std::shared_ptr<C2ComponentInterface> intf) {
    return intf;
}

std::shared_ptr<C2Component> FilterWrapper::maybeWrapComponent(
        const std::shared_ptr<C2Component> comp) {
    return comp;
}

bool FilterWrapper::isFilteringEnabled(const std::shared_ptr<C2ComponentInterface> &) {
    return false;
}

c2_status_t FilterWrapper::createBlockPool(
        C2PlatformAllocatorStore::id_t allocatorId,
        std::shared_ptr<const C2Component> component,
        std::shared_ptr<C2BlockPool> *pool) {
    C2PlatformAllocatorDesc allocatorParam;
    allocatorParam.allocatorId = allocatorId;
    return createBlockPool(allocatorParam, component, pool);
}

c2_status_t FilterWrapper::createBlockPool(
        C2PlatformAllocatorDesc &allocatorParam,
        std::shared_ptr<const C2Component> component,
        std::shared_ptr<C2BlockPool> *pool) {
    return CreateCodec2BlockPool(allocatorParam, component, pool);
}

}  // namespace android
