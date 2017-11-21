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

#ifndef STAGEFRIGHT_CODEC2_ALLOCATOR_ION_H_
#define STAGEFRIGHT_CODEC2_ALLOCATOR_ION_H_

#include <functional>

#include <C2Buffer.h>

namespace android {

class C2AllocatorIon : public C2Allocator {
public:
    // (usage, capacity) => (align, heapMask, flags)
    typedef std::function<int (C2MemoryUsage, size_t,
                      /* => */ size_t*, unsigned*, unsigned*)> usage_mapper_fn;

    virtual id_t getId() const override;

    virtual C2String getName() const override;

    virtual std::shared_ptr<const Traits> getTraits() const override {
        return nullptr; // \todo
    }

    virtual c2_status_t newLinearAllocation(
            uint32_t capacity, C2MemoryUsage usage,
            std::shared_ptr<C2LinearAllocation> *allocation) override;

    virtual c2_status_t priorLinearAllocation(
            const C2Handle *handle,
            std::shared_ptr<C2LinearAllocation> *allocation) override;

    C2AllocatorIon();

    virtual c2_status_t status() const { return mInit; }

    virtual ~C2AllocatorIon() override;

private:
    c2_status_t mInit;
    int mIonFd;
    usage_mapper_fn mUsageMapper;
};

} // namespace android

#endif // STAGEFRIGHT_CODEC2_ALLOCATOR_ION_H_
