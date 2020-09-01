/*
 * Copyright (C) 2019 The Android Open Source Project
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

#ifndef STAGEFRIGHT_CODEC2_ALLOCATOR_BLOB_H_
#define STAGEFRIGHT_CODEC2_ALLOCATOR_BLOB_H_

#include <functional>

#include <C2AllocatorGralloc.h>
#include <C2Buffer.h>

namespace android {

class C2AllocatorBlob : public C2Allocator {
public:
    virtual id_t getId() const override;

    virtual C2String getName() const override;

    virtual std::shared_ptr<const Traits> getTraits() const override;

    virtual c2_status_t newLinearAllocation(
            uint32_t capacity, C2MemoryUsage usage,
            std::shared_ptr<C2LinearAllocation> *allocation) override;

    virtual c2_status_t priorLinearAllocation(
            const C2Handle *handle,
            std::shared_ptr<C2LinearAllocation> *allocation) override;

    C2AllocatorBlob(id_t id);

    virtual ~C2AllocatorBlob() override;

    static bool isValid(const C2Handle* const o);

private:
    std::shared_ptr<const Traits> mTraits;
    // Design as C2AllocatorGralloc-backed to unify Gralloc implementations.
    std::shared_ptr<C2Allocator> mC2AllocatorGralloc;
};

} // namespace android

#endif // STAGEFRIGHT_CODEC2_ALLOCATOR_BLOB_H_
