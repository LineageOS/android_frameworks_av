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

class C2BasicLinearBlockPool : public C2BlockPool {
public:
    explicit C2BasicLinearBlockPool(const std::shared_ptr<C2Allocator> &allocator);

    virtual ~C2BasicLinearBlockPool() override = default;

    virtual C2Allocator::id_t getAllocatorId() const override {
        return mAllocator->getId();
    }

    virtual local_id_t getLocalId() const override {
        return BASIC_LINEAR;
    }

    virtual c2_status_t fetchLinearBlock(
            uint32_t capacity,
            C2MemoryUsage usage,
            std::shared_ptr<C2LinearBlock> *block /* nonnull */) override;

    // TODO: fetchCircularBlock

private:
    const std::shared_ptr<C2Allocator> mAllocator;
};

class C2BasicGraphicBlockPool : public C2BlockPool {
public:
    explicit C2BasicGraphicBlockPool(const std::shared_ptr<C2Allocator> &allocator);

    virtual ~C2BasicGraphicBlockPool() override = default;

    virtual C2Allocator::id_t getAllocatorId() const override {
        return mAllocator->getId();
    }

    virtual local_id_t getLocalId() const override {
        return BASIC_GRAPHIC;
    }

    virtual c2_status_t fetchGraphicBlock(
            uint32_t width,
            uint32_t height,
            uint32_t format,
            C2MemoryUsage usage,
            std::shared_ptr<C2GraphicBlock> *block /* nonnull */) override;

private:
    const std::shared_ptr<C2Allocator> mAllocator;
};

} // namespace android

#endif // STAGEFRIGHT_CODEC2_BUFFER_PRIV_H_
