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

#include <android-base/unique_fd.h>

/*
 * Create a list of fds from fence
 *
 * \param fence   C2Fence object from which associated
 *                file descriptors need to be extracted
 * \return a vector of fds otherwise return vector of size 0
 */

std::vector<int> ExtractFdsFromCodec2SyncFence(const C2Fence& fence);

class C2SurfaceSyncMemory;

/**
 * C2Fence implementation factory
 */
struct _C2FenceFactory {

    class SurfaceFenceImpl;
    class SyncFenceImpl;
    class PipeFenceImpl;

    /*
     * Create C2Fence for BufferQueueBased blockpool.
     *
     * \param syncMem           Shared memory object for synchronization between processes.
     * \param waitId            wait id for tracking status change for C2Fence.
     */
    static C2Fence CreateSurfaceFence(
            std::shared_ptr<C2SurfaceSyncMemory> syncMem,
            uint32_t waitId);

    /*
     * Create C2Fence from a fence file fd.
     *
     * \param fenceFd           Fence file descriptor.
     *                          It will be owned and closed by the returned fence object.
     */
    static C2Fence CreateSyncFence(int fenceFd);

    /*
     * Create C2Fence from list of fence file fds.
     *
     * \param fenceFds          Vector of file descriptor for fence.
     *                          It will be owned and closed by the returned fence object.
     */
    static C2Fence CreateMultipleFdSyncFence(const std::vector<int>& fenceFds);

    /*
     * Create C2Fence from an fd created by pipe()/pipe2() syscall.
     * The ownership of \p fd is transterred to the returned C2Fence.
     *
     * \param fd                An fd representing the write end from a pair of
     *                          file descriptors which are created by
     *                          pipe()/pipe2() syscall.
     */
    static C2Fence CreatePipeFence(int fd);

    /*
     * Create C2Fence from a unique_fd created by pipe()/pipe2() syscall.
     *
     * \param ufd               A unique_fd representing the write end from a pair
     *                          of file descriptors which are created by
     *                          pipe()/pipe2() syscall.
     */
    static C2Fence CreatePipeFence(::android::base::unique_fd &&ufd);

    /**
     * Create a native handle from fence for marshalling
     *
     * \return a non-null pointer if the fence can be marshalled, otherwise return nullptr
     */
    static native_handle_t* CreateNativeHandle(const C2Fence& fence);

    /*
     * Create C2Fence from a native handle.

     * \param handle           A native handle representing a fence
     *                         The fd in the native handle will be duplicated, so the caller will
     *                         still own the handle and have to close it.
     */
    static C2Fence CreateFromNativeHandle(const native_handle_t* handle);
};


#endif // STAGEFRIGHT_CODEC2_FENCE_FACTORY_H_
