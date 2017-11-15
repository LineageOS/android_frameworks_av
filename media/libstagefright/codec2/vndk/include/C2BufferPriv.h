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

#ifndef STAGEFRIGHT_CODEC2_BUFFER_PRIV_H_
#define STAGEFRIGHT_CODEC2_BUFFER_PRIV_H_

#include <functional>

#include <C2Buffer.h>

namespace android {

class C2DefaultBlockAllocator : public C2BlockAllocator {
public:
    explicit C2DefaultBlockAllocator(const std::shared_ptr<C2Allocator> &allocator);

    virtual ~C2DefaultBlockAllocator() = default;

    virtual C2Status allocateLinearBlock(
            uint32_t capacity,
            C2MemoryUsage usage,
            std::shared_ptr<C2LinearBlock> *block /* nonnull */) override;

    // TODO:
private:
    const std::shared_ptr<C2Allocator> mAllocator;
};

class C2DefaultGraphicBlockAllocator : public C2BlockAllocator {
public:
    explicit C2DefaultGraphicBlockAllocator(const std::shared_ptr<C2Allocator> &allocator);

    virtual ~C2DefaultGraphicBlockAllocator() = default;

    virtual C2Status allocateGraphicBlock(
            uint32_t width,
            uint32_t height,
            uint32_t format,
            C2MemoryUsage usage,
            std::shared_ptr<C2GraphicBlock> *block /* nonnull */) override;

private:
    const std::shared_ptr<C2Allocator> mAllocator;
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

#endif // STAGEFRIGHT_CODEC2_BUFFER_PRIV_H_
