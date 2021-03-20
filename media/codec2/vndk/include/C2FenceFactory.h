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

#ifndef STAGEFRIGHT_CODEC2_FENCE_FACTORY_H_
#define STAGEFRIGHT_CODEC2_FENCE_FACTORY_H_


#include <C2Buffer.h>

class C2SurfaceSyncMemory;

/**
 * C2Fence implementation factory
 */
struct _C2FenceFactory {

    class SurfaceFenceImpl;

    /*
     * Create C2Fence for BufferQueueBased blockpool.
     *
     * \param syncMem           Shared memory object for synchronization between processes.
     * \param waitId            wait id for tracking status change for C2Fence.
     */
    static C2Fence CreateSurfaceFence(
            std::shared_ptr<C2SurfaceSyncMemory> syncMem,
            uint32_t waitId);
};


#endif // STAGEFRIGHT_CODEC2_FENCE_FACTORY_H_
