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
 * Extract a list of sync fence fds from a potentially multi-sync C2Fence.
 * This will return dupped file descriptors of the fences used to creating the
 * sync fence. Specifically, for an unordered mult-sync fence, the merged
 * singular fence will not be returned even though it is created aspart of
 * constructing the C2Fence object. On the other hand, for a single fd sync
 * fence, the returned list will contain the sole file descriptor.
 *
 * \param fence   C2Fence object from which associated
 *                file descriptors need to be extracted
 * \return a vector of sync fence fds. This will be a vector of size 0 if C2Fence
 *         is not a sync fence. The caller is responsible for closing the
 *         fds in the returned vector.
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
     * Create C2Fence from a sync fence fd.
     *
     * \param fenceFd           Sync fence file descriptor.
     *                          It will be owned and closed by the returned fence object.
     * \param validate          If true, the fence fd will be validated to ensure
     *                          it is a valid pending sync fence fd.
     */
    static C2Fence CreateSyncFence(int fenceFd, bool validate = true);

    /*
     * Create C2Fence from list of sync fence fds, while also merging them to
     * create a singular fence, which can be used as a backward compatible sync
     * fence.
     *
     * \param fenceFds   Vector of sync fence file descriptors.
     *                   All file descriptors will be owned (and closed) by
     *                   the returned fence object.
     */
    [[deprecated("Use CreateUnorderedMultiSyncFence instead.")]]
    static C2Fence CreateMultipleFdSyncFence(const std::vector<int>& fenceFds) {
        return CreateUnorderedMultiSyncFence(fenceFds);
    }

    /*
     * Create C2Fence from a list of unordered sync fence fds, while also merging
     * them to create a singular fence, which can be used as a backward compatible
     * sync fence.
     *
     * \param fenceFds   Vector of sync fence file descriptors.
     *                   All file descriptors will be owned (and closed) by
     *                   the returned fence object.
     * \param status     Optional pointer to a status field. If not null, it will be
     *                   updated with the status of the operation. Possible values
     *                   are:
     *                   - C2_OK: The operation succeeded.
     *                   - C2_NO_MEMORY: The operation failed because of lack of
     *                     memory.
     *                   - C2_CORRUPTED: The operation failed because the sync
     *                     fence fds could bot be merged.
     * \return           A C2Fence object representing the sync fence fds, or
     *                   an empty C2Fence if the no C2Fence could be created.
     *                   It is possible for the operation to fail but still return
     *                   a possibly viable C2Fence object, e.g. if the merge
     *                   operation failed only partially. Similarly, it is possible
     *                   for the operation to succeed but still return an empty
     *                   C2Fence object, e.g. if all fence fds were invalid.
     */
    static C2Fence CreateUnorderedMultiSyncFence(
            const std::vector<int>& fenceFds, c2_status_t *status = nullptr /* nullable */);

    /*
     * Create C2Fence from a list of sync fence fds. Waiting for the last fence
     * must guarantee that all other fences are also signaled.
     *
     * \param fenceFds   Vector of sync fence file descriptors.
     *                   All file descriptors will be owned (and closed) by
     *                   the returned fence object.
     * \param status     Optional pointer to a status field. If not null, it will be
     *                   updated with the status of the operation. Possible values
     *                   are:
     *                   - C2_OK: The operation succeeded.
     *                   - C2_NO_MEMORY: The operation failed because of lack of
     *                     memory.
     * \return           A C2Fence object representing the sync fence fds, or
     *                   an empty C2Fence if the operation failed.  It is possible
     *                   for the operation to succeed but still return an empty
     *                   C2Fence object, e.g. if all fence fds were invalid.
     */
    static C2Fence CreateMultiSyncFence(
            const std::vector<int>& fenceFds, c2_status_t *status = nullptr /* nullable */);

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
     *
     * \param handle           A native handle representing a fence
     * \param takeOwnership    If true, the native handle and the file descriptors
     *                         within will be owned by the returned fence object.
     *                         If false (default), the caller will still own the
     *                         handle and its file descriptors and will have to
     *                         close it.
     *                         In either case the caller is responsible for
     *                         deleting the native handle.
     */
    static C2Fence CreateFromNativeHandle(
            const native_handle_t* handle, bool takeOwnership = false);
};

#endif // STAGEFRIGHT_CODEC2_FENCE_FACTORY_H_
