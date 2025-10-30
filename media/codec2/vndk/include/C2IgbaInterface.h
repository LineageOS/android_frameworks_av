/*
 * Copyright (C) 2025 The Android Open Source Project
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
#pragma once

#include <memory>

#include <C2.h>

#include <stdint.h>

typedef struct AHardwareBuffer AHardwareBuffer;

/**
 * c2aidl IGraphicBufferAllocator interface wrapper class.
 *
 * The interface is basically a wrapper for c2aidl IGraphicBufferAllocator
 * interface. This is used to remove unwanted dependency of C2 base
 * implementations to c2aidl media.c2 HAL.
 */
class C2IgbaInterface {
public:
    virtual ~C2IgbaInterface() = default;
    /**
     * Allocate an AHardwareBuffer.
     *
     * This wraps media.c2 IGraphicBufferAllocator::allocate interface.
     */
    virtual c2_status_t allocate(
            uint32_t width, uint32_t height, uint32_t format, uint64_t usage,
            AHardwareBuffer **pBuf, int *syncFence) = 0;

    /**
     * Deallocate an already allocated AHardwareBuffer.
     *
     * This wraps media.c2 IGraphicBufferAllocator::deallocate interface.
     */
    virtual c2_status_t deallocate(uint64_t ahwbId, bool *deallocated) = 0;
};
