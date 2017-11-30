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
#include <C2BufferPriv.h>
#include <C2Component.h>
#include <C2PlatformSupport.h>

#include <map>
#include <memory>
#include <mutex>

namespace android {

class C2PlatformAllocatorStore : public C2AllocatorStore {
public:
    enum : id_t {
        ION = PLATFORM_START,
        GRALLOC,
    };

    C2PlatformAllocatorStore(
        /* ionmapper */
    );

    virtual c2_status_t fetchAllocator(id_t id, std::shared_ptr<C2Allocator> *const allocator) override;

    virtual std::vector<std::shared_ptr<const C2Allocator::Traits>> listAllocators_nb() const override {
        return std::vector<std::shared_ptr<const C2Allocator::Traits>>(); /// \todo
    }

    virtual C2String getName() const override {
        return "android.allocator-store";
    }

private:
    // returns a shared-singleton ion allocator
    std::shared_ptr<C2Allocator> fetchIonAllocator();

    // returns a shared-singleton gralloc allocator
    std::shared_ptr<C2Allocator> fetchGrallocAllocator();
};

C2PlatformAllocatorStore::C2PlatformAllocatorStore() {
}

c2_status_t C2PlatformAllocatorStore::fetchAllocator(
        id_t id, std::shared_ptr<C2Allocator> *const allocator) {
    allocator->reset();
    switch (id) {
    // TODO: should we implement a generic registry for all, and use that?
    case C2PlatformAllocatorStore::ION:
    case C2AllocatorStore::DEFAULT_LINEAR:
        *allocator = fetchIonAllocator();
        break;

    case C2PlatformAllocatorStore::GRALLOC:
    case C2AllocatorStore::DEFAULT_GRAPHIC:
        *allocator = fetchGrallocAllocator();
        break;

    default:
        return C2_NOT_FOUND;
    }
    if (*allocator == nullptr) {
        return C2_NO_MEMORY;
    }
    return C2_OK;
}

std::shared_ptr<C2Allocator> C2PlatformAllocatorStore::fetchIonAllocator() {
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

std::shared_ptr<C2Allocator> C2PlatformAllocatorStore::fetchGrallocAllocator() {
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

c2_status_t GetCodec2BlockPool(
        C2BlockPool::local_id_t id, std::shared_ptr<const C2Component> component,
        std::shared_ptr<C2BlockPool> *pool) {
    pool->reset();
    if (!component) {
        return C2_BAD_VALUE;
    }
    // TODO support pre-registered block pools
    std::shared_ptr<C2AllocatorStore> allocatorStore = GetCodec2PlatformAllocatorStore();
    std::shared_ptr<C2Allocator> allocator;
    c2_status_t res = C2_NOT_FOUND;

    switch (id) {
    case C2BlockPool::BASIC_LINEAR:
        res = allocatorStore->fetchAllocator(C2AllocatorStore::DEFAULT_LINEAR, &allocator);
        if (res == OK) {
            *pool = std::make_shared<C2BasicLinearBlockPool>(allocator);
        }
        break;
    case C2BlockPool::BASIC_GRAPHIC:
        res = allocatorStore->fetchAllocator(C2AllocatorStore::DEFAULT_GRAPHIC, &allocator);
        if (res == OK) {
            *pool = std::make_shared<C2BasicGraphicBlockPool>(allocator);
        }
        break;
    default:
        break;
    }
    return res;
}

} // namespace android