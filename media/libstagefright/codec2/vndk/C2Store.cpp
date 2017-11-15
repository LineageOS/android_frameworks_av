/*
 * Copyright (C) 2017 The Android Open Source Project
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

#include <C2AllocatorGralloc.h>
#include <C2AllocatorIon.h>
#include <C2Component.h>
#include <C2PlatformSupport.h>

#include <map>
#include <memory>
#include <mutex>

namespace android {

class C2PlatformAllocatorStore : public C2AllocatorStore {
public:
    enum ID_ : uint32_t {
        ION = PLATFORM_START,
        GRALLOC,
    };

    C2PlatformAllocatorStore(
        /* ionmapper */
    );
    virtual C2Status createAllocator(ID id, std::shared_ptr<C2Allocator> *const allocator);

private:
    // returns a shared-singleton ion allocator
    std::shared_ptr<C2Allocator> getIonAllocator();

    // returns a shared-singleton gralloc allocator
    std::shared_ptr<C2Allocator> getGrallocAllocator();
};

C2PlatformAllocatorStore::C2PlatformAllocatorStore() {
}

C2Status C2PlatformAllocatorStore::createAllocator(
        ID id, std::shared_ptr<C2Allocator> *const allocator) {
    allocator->reset();
    switch (id) {
    // TODO: should we implement a generic registry for all, and use that?
    case C2PlatformAllocatorStore::ION:
    case C2AllocatorStore::DEFAULT_LINEAR:
        *allocator = getIonAllocator();
        break;

    case C2PlatformAllocatorStore::GRALLOC:
    case C2AllocatorStore::DEFAULT_GRAPHIC:
        *allocator = getGrallocAllocator();
        break;

    default:
        return C2_NOT_FOUND;
    }
    if (*allocator == nullptr) {
        return C2_NO_MEMORY;
    }
    return C2_OK;
}

std::shared_ptr<C2Allocator> C2PlatformAllocatorStore::getIonAllocator() {
    static std::mutex mutex;
    static std::weak_ptr<C2Allocator> ionAllocator;
    std::lock_guard<std::mutex> lock(mutex);
    std::shared_ptr<C2Allocator> allocator = ionAllocator.lock();
    if (allocator == nullptr) {
        allocator = std::make_shared<C2AllocatorIon>();
        ionAllocator = allocator;
    }
    return allocator;
}

std::shared_ptr<C2Allocator> C2PlatformAllocatorStore::getGrallocAllocator() {
    static std::mutex mutex;
    static std::weak_ptr<C2Allocator> grallocAllocator;
    std::lock_guard<std::mutex> lock(mutex);
    std::shared_ptr<C2Allocator> allocator = grallocAllocator.lock();
    if (allocator == nullptr) {
        allocator = std::make_shared<C2AllocatorGralloc>();
        grallocAllocator = allocator;
    }
    return allocator;
}

std::shared_ptr<C2AllocatorStore> GetCodec2PlatformAllocatorStore() {
    return std::make_shared<C2PlatformAllocatorStore>();
}

} // namespace android