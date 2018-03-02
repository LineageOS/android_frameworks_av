/*
 * Copyright (C) 2018 The Android Open Source Project
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

#ifndef ANDROID_STAGEFRIGHT_C2BLOCK_INTERNAL_H_
#define ANDROID_STAGEFRIGHT_C2BLOCK_INTERNAL_H_

#include <C2Buffer.h>

struct _C2BlockPoolData;

/**
 * Internal only interface for creating blocks by block pool/buffer passing implementations.
 *
 * \todo this must be hidden
 */
struct _C2BlockFactory {
    /**
     * Create a linear block from an allocation for an allotted range.
     *
     * @param alloc parent allocation
     * @param data  blockpool data
     * @param offset allotted range offset
     * @param size  allotted size
     *
     * @return shared pointer to the linear block. nullptr if there was not enough memory to
     *         create this block.
     */
    static
    std::shared_ptr<C2LinearBlock> CreateLinearBlock(
            const std::shared_ptr<C2LinearAllocation> &alloc,
            const std::shared_ptr<_C2BlockPoolData> &data = nullptr,
            size_t offset = 0,
            size_t size = ~(size_t)0);

    /**
     * Create a graphic block from an allocation for an allotted section.
     *
     * @param alloc parent allocation
     * @param data  blockpool data
     * @param crop  allotted crop region
     *
     * @return shared pointer to the graphic block. nullptr if there was not enough memory to
     *         create this block.
     */
    static
    std::shared_ptr<C2GraphicBlock> CreateGraphicBlock(
            const std::shared_ptr<C2GraphicAllocation> &alloc,
            const std::shared_ptr<_C2BlockPoolData> &data = nullptr,
            const C2Rect &allottedCrop = C2Rect(~0u, ~0u));
};

#endif // ANDROID_STAGEFRIGHT_C2BLOCK_INTERNAL_H_

