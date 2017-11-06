
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

#ifndef STAGEFRIGHT_CODEC2_ALLOCATOR_GRALLOC_H_
#define STAGEFRIGHT_CODEC2_ALLOCATOR_GRALLOC_H_

#include <functional>

#include <C2Buffer.h>

namespace android {

class C2AllocatorGralloc : public C2Allocator {
public:
    // (usage, capacity) => (align, heapMask, flags)
    typedef std::function<int (C2MemoryUsage, size_t,
                      /* => */ size_t*, unsigned*, unsigned*)> usage_mapper_fn;

    virtual C2Error allocateGraphicBuffer(
            uint32_t width, uint32_t height, uint32_t format, C2MemoryUsage usage,
            std::shared_ptr<C2GraphicAllocation> *allocation) override;

    virtual C2Error recreateGraphicBuffer(
            const C2Handle *handle,
            std::shared_ptr<C2GraphicAllocation> *allocation) override;

    C2AllocatorGralloc();

    C2Error status() const;

    virtual ~C2AllocatorGralloc();

private:
    class Impl;
    Impl *mImpl;
};

#if 0
class C2Allocation::Impl {
public:
    Impl() : mMapped(false), mBase(nullptr) { }
    uint8_t* base() { return mMapped ? mBase : nullptr; }

    // TODO: call map...

private:
    bool mMapped;
    uint8_t *mBase;
};
#endif

} // namespace android

#endif // STAGEFRIGHT_CODEC2_ALLOCATOR_GRALLOC_H_
