/*
 * Copyright 2024 The Android Open Source Project
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

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <C2Buffer.h>
#include <C2FenceFactory.h>

#include <unistd.h>

#include <android-base/unique_fd.h>
#include <linux/kcmp.h>       /* Definition of KCMP_* constants */
#include <sys/mman.h>
#include <sys/syscall.h>      /* Definition of SYS_* constants */
#include <ui/Fence.h>

namespace android {

static int fd_kcmp(int fd1, int fd2) {
    static pid_t pid = getpid();

    return syscall(SYS_kcmp, pid, pid, KCMP_FILE, fd1, fd2);
}

// matcher to check if value (arg) and fd refers to the same file
MATCHER_P(RefersToTheSameFile, fd, "") {
    return fd_kcmp(fd, arg) == 0;
}

// matcher to check if value (arg) is a dup of an fd
MATCHER_P(IsDupOf, fd, "") {
    return (ExplainMatchResult(::testing::Ne(-1), arg, result_listener) &&
            ExplainMatchResult(::testing::Ne(fd), arg, result_listener) &&
            ExplainMatchResult(RefersToTheSameFile(fd), arg, result_listener));
}

class C2FenceTest : public ::testing::Test {
public:
    C2FenceTest() = default;

    ~C2FenceTest() = default;


protected:
    enum : int32_t {
        SYNC_FENCE_DEPRECATED_MAGIC     = 3,
        SYNC_FENCE_UNORDERED_MAGIC      = '\302fsu',
        SYNC_FENCE_MAGIC                = '\302fso',
    };

    // Validate a null fence
    void validateNullFence(const C2Fence &fence);

    // Validate a single fd sync fence
    void validateSingleFdFence(const C2Fence &fence, int fd);

    // Validate a two fd unordered sync fence
    void validateTwoFdUnorderedFence(const C2Fence &fence, int fd1, int fd2, int mergeFd);

    // Validate a three fd sync fence
    void validateThreeFdFence(const C2Fence &fence, int fd1, int fd2, int fd3);
};

TEST_F(C2FenceTest, IsDupOf_sanity) {
    int fd1 = memfd_create("test1", 0 /* flags */);
    int fd2 = memfd_create("test2", 0 /* flags */);
    int fd3 = memfd_create("test3", 0 /* flags */);

    EXPECT_THAT(fd1, ::testing::Not(IsDupOf(fd2)));
    EXPECT_THAT(-1, ::testing::Not(IsDupOf(fd2)));
    EXPECT_THAT(-1, ::testing::Not(IsDupOf(-1)));
    EXPECT_THAT(fd3, ::testing::Not(IsDupOf(fd3)));

    int fd4 = dup(fd3);
    EXPECT_THAT(fd4, IsDupOf(fd3));
    EXPECT_THAT(fd3, IsDupOf(fd4));

    close(fd1);
    close(fd2);
    close(fd3);
    close(fd4);
}

TEST_F(C2FenceTest, NullFence) {
    validateNullFence(C2Fence());
}

void C2FenceTest::validateNullFence(const C2Fence &fence) {
    // Verify that the fence is valid.
    EXPECT_TRUE(fence.valid());
    EXPECT_TRUE(fence.ready());
    base::unique_fd fenceFd{fence.fd()};
    EXPECT_EQ(fenceFd.get(), -1);
    EXPECT_FALSE(fence.isHW()); // perhaps this should be false for a null fence

    // A null fence has no fds
    std::vector<int> fds = ExtractFdsFromCodec2SyncFence(fence);
    EXPECT_THAT(fds, ::testing::IsEmpty());
    for (int fd : fds) {
        close(fd);
    }

    // A null fence has no native handle
    native_handle_t *handle = _C2FenceFactory::CreateNativeHandle(fence);
    EXPECT_THAT(handle, ::testing::IsNull());
    if (handle) {
        native_handle_close(handle);
        native_handle_delete(handle);
    }
}

TEST_F(C2FenceTest, SyncFence_with_negative_fd) {
    // Create a SyncFence with a negative fd.
    C2Fence fence = _C2FenceFactory::CreateSyncFence(-1, false /* validate */);

    validateNullFence(fence);
}

TEST_F(C2FenceTest, SyncFence_with_valid_fd) {
    // Create a SyncFence with a valid fd. We cannot create an actual sync fd,
    // so we cannot test wait(), but we can verify the ABI APIs

    int fd = memfd_create("test", 0 /* flags */);

    C2Fence fence = _C2FenceFactory::CreateSyncFence(fd, false /* validate */);
    validateSingleFdFence(fence, fd);
}

void C2FenceTest::validateSingleFdFence(const C2Fence &fence, int fd) {
    // EXPECT_TRUE(fence.valid()); // need a valid sync fd to test this
    // EXPECT_TRUE(fence.ready());
    // Verify that the fence says it is a HW sync fence.
    EXPECT_TRUE(fence.isHW()); // FIXME this may be an implementation detail

    // Verify that the fd returned is a duped version of the initial fd
    base::unique_fd fenceFd{fence.fd()};
    EXPECT_THAT(fenceFd.get(), IsDupOf(fd));

    // Verify that fds returns a duped version of the initial fd
    std::vector<int> fds = ExtractFdsFromCodec2SyncFence(fence);
    EXPECT_THAT(fds, ::testing::SizeIs(1));
    EXPECT_THAT(fds, ::testing::ElementsAre(IsDupOf(fd)));
    for (int fd_i : fds) {
        close(fd_i);
    }

    native_handle_t *handle = _C2FenceFactory::CreateNativeHandle(fence);
    EXPECT_THAT(handle, ::testing::NotNull());
    if (handle) {
        EXPECT_EQ(handle->numFds, 1);
        EXPECT_EQ(handle->numInts, 1);
        EXPECT_THAT(handle->data[0], IsDupOf(fd));
        EXPECT_EQ(handle->data[1], SYNC_FENCE_MAGIC);

        native_handle_close(handle);
        native_handle_delete(handle);
    }
}

TEST_F(C2FenceTest, UnorderedMultiSyncFence_with_one_valid_test_fd) {
    // Create a multi SyncFence with a single valid fd. This should create
    // a single fd sync fence. We can only validate this through its public
    // methods: fd/fds and verify the native handle ABI.

    int fd = memfd_create("test", 0 /* flags */);

    c2_status_t status = C2_BAD_VALUE;
    C2Fence fence = _C2FenceFactory::CreateUnorderedMultiSyncFence(
        { -1, fd, -1 }, &status);
    // if we only have one valid fd, we are not merging fences, so the test fd is not validated
    EXPECT_EQ(status, C2_OK);

    validateSingleFdFence(fence, fd);
}

TEST_F(C2FenceTest, UnorderedMultiSyncFence_with_one_valid_test_fd_null_status) {
    // Create a multi SyncFence with a single valid fd. This should create
    // a single fd sync fence. We can only validate this through its public
    // methods: fd/fds and verify the native handle ABI.

    int fd = memfd_create("test", 0 /* flags */);

    C2Fence fence = _C2FenceFactory::CreateUnorderedMultiSyncFence(
        { -1, fd, -1 });

    validateSingleFdFence(fence, fd);
}

TEST_F(C2FenceTest, UnorderedMultiSyncFence_with_merge_failure) {
    // Create a multi SyncFence with a multiple non-sync fence fds. This should
    // result in a fence created, but also an error.

    int fd1 = memfd_create("test1", 0 /* flags */);
    int fd2 = memfd_create("test2", 0 /* flags */);
    int fd3 = memfd_create("test3", 0 /* flags */);

    c2_status_t status = C2_BAD_VALUE;
    C2Fence fence = _C2FenceFactory::CreateUnorderedMultiSyncFence(
        { fd1, fd2, fd3 }, &status);
    EXPECT_EQ(status, C2_CORRUPTED);

    validateThreeFdFence(fence, fd1, fd2, fd3);
}

TEST_F(C2FenceTest, UnorderedMultiSyncFence_with_merge_failure_null_status) {
    // Create a multi SyncFence with a multiple non-sync fence fds. This should
    // result in a fence created, but also an error.

    int fd1 = memfd_create("test1", 0 /* flags */);
    int fd2 = memfd_create("test2", 0 /* flags */);
    int fd3 = memfd_create("test3", 0 /* flags */);

    C2Fence fence = _C2FenceFactory::CreateUnorderedMultiSyncFence(
        { fd1, fd2, fd3 });

    validateThreeFdFence(fence, fd1, fd2, fd3);
}

TEST_F(C2FenceTest, UnorderedMultiSyncFence_with_multiple_fds) {
    // We cannot create a true unordered multi sync fence as we can only
    // create test fds and those cannot be merged. As such, we cannot
    // test the factory method CreateUnorderedMultiSyncFence. We can however
    // create a test fence from a constructed native handle.

    // Technically, we need 3 fds as if we end up with only 2, we wouldn't
    // actually need a 2nd (final fence fd) since it is equivalent to the
    // first. In fact we will generate (and always generated) a single fd
    // fence in that case.
    int fd1 = memfd_create("test1", 0 /* flags */);
    int fd2 = memfd_create("test2", 0 /* flags */);
    int mergeFd = memfd_create("test3", 0 /* flags */);

    native_handle_t *handle = native_handle_create(3 /* numfds */, 1 /* numints */);
    handle->data[0] = fd1;
    handle->data[1] = fd2;
    handle->data[2] = mergeFd;
    handle->data[3] = SYNC_FENCE_UNORDERED_MAGIC;
    C2Fence fence = _C2FenceFactory::CreateFromNativeHandle(handle, true /* takeOwnership */);
    native_handle_delete(handle);

    validateTwoFdUnorderedFence(fence, fd1, fd2, mergeFd);
}

void C2FenceTest::validateTwoFdUnorderedFence(
        const C2Fence &fence, int fd1, int fd2, int mergeFd) {
    // EXPECT_TRUE(fence.valid()); // need a valid sync fd to test this
    // EXPECT_TRUE(fence.ready());
    // Verify that the fence says it is a HW sync fence.
    EXPECT_TRUE(fence.isHW()); // FIXME this may be an implementation detail

    // Verify that the fd returned is a duped version of the merge fd
    base::unique_fd fenceFd{fence.fd()};
    EXPECT_THAT(fenceFd.get(), IsDupOf(mergeFd));

    // Verify that fds returns a duped versions of the initial fds (but not the merge fd)
    std::vector<int> fds = ExtractFdsFromCodec2SyncFence(fence);
    EXPECT_THAT(fds, ::testing::SizeIs(2));
    EXPECT_THAT(fds, ::testing::ElementsAre(IsDupOf(fd1), IsDupOf(fd2)));
    for (int fd_i : fds) {
        close(fd_i);
    }

    native_handle_t *handle = _C2FenceFactory::CreateNativeHandle(fence);
    EXPECT_THAT(handle, ::testing::NotNull());
    if (handle) {
        EXPECT_EQ(handle->numFds, 3);
        EXPECT_EQ(handle->numInts, 1);
        EXPECT_THAT(handle->data[0], IsDupOf(fd1));
        EXPECT_THAT(handle->data[1], IsDupOf(fd2));
        EXPECT_THAT(handle->data[2], IsDupOf(mergeFd));
        EXPECT_EQ(handle->data[3], SYNC_FENCE_UNORDERED_MAGIC);

        native_handle_close(handle);
        native_handle_delete(handle);
    }
}

TEST_F(C2FenceTest, MultiSyncFence_with_one_valid_test_fd) {
    // Create a multi SyncFence with a single valid fd. This should create
    // a single fd sync fence. We can only validate this through its public
    // methods: fd/fds and verify the native handle ABI.

    int fd = memfd_create("test", 0 /* flags */);

    c2_status_t status = C2_BAD_VALUE;
    C2Fence fence = _C2FenceFactory::CreateMultiSyncFence(
        { -1, fd, -1 }, &status);
    // if we only have one valid fd, we are not merging fences, so the test fds are not validated
    EXPECT_EQ(status, C2_OK);

    validateSingleFdFence(fence, fd);
}

TEST_F(C2FenceTest, MultiSyncFence_with_one_valid_test_fd_null_status) {
    // Create a multi SyncFence with a single valid fd. This should create
    // a single fd sync fence. We can only validate this through its public
    // methods: fd/fds and verify the native handle ABI.

    int fd = memfd_create("test", 0 /* flags */);

    C2Fence fence = _C2FenceFactory::CreateMultiSyncFence(
        { -1, fd, -1 });

    validateSingleFdFence(fence, fd);
}

TEST_F(C2FenceTest, MultiSyncFence_with_multiple_fds) {
    int fd1 = memfd_create("test1", 0 /* flags */);
    int fd2 = memfd_create("test2", 0 /* flags */);
    int fd3 = memfd_create("test3", 0 /* flags */);

    c2_status_t status = C2_BAD_VALUE;
    C2Fence fence = _C2FenceFactory::CreateMultiSyncFence(
        { fd1, fd2, fd3 }, &status);
    // test fds are not validated
    EXPECT_EQ(status, C2_OK);

    validateThreeFdFence(fence, fd1, fd2, fd3);
}

void C2FenceTest::validateThreeFdFence(const C2Fence &fence, int fd1, int fd2, int fd3) {
    // EXPECT_TRUE(fence.valid()); // need a valid sync fd to test this
    // EXPECT_TRUE(fence.ready());
    // Verify that the fence says it is a HW sync fence.
    EXPECT_TRUE(fence.isHW()); // FIXME this may be an implementation detail

    // Verify that the fd returned is a duped version of the final fd
    base::unique_fd fenceFd{fence.fd()};
    EXPECT_THAT(fenceFd.get(), IsDupOf(fd3));

    // Verify that fds returns a duped versions of all 3 initial fds
    std::vector<int> fds = ExtractFdsFromCodec2SyncFence(fence);
    EXPECT_THAT(fds, ::testing::SizeIs(3));
    EXPECT_THAT(fds, ::testing::ElementsAre(IsDupOf(fd1), IsDupOf(fd2), IsDupOf(fd3)));
    for (int fd_i : fds) {
        close(fd_i);
    }

    native_handle_t *handle = _C2FenceFactory::CreateNativeHandle(fence);
    EXPECT_THAT(handle, ::testing::NotNull());
    if (handle) {
        EXPECT_EQ(handle->numFds, 3);
        EXPECT_EQ(handle->numInts, 1);
        EXPECT_THAT(handle->data[0], IsDupOf(fd1));
        EXPECT_THAT(handle->data[1], IsDupOf(fd2));
        EXPECT_THAT(handle->data[2], IsDupOf(fd3));
        EXPECT_EQ(handle->data[3], SYNC_FENCE_MAGIC);

        native_handle_close(handle);
        native_handle_delete(handle);
    }
}

TEST_F(C2FenceTest, BackwardCompat_UDC_sync_fence) {
    // Create a single SyncFence from a UDC native handle

    int fd = memfd_create("test", 0 /* flags */);

    native_handle_t *handle = native_handle_create(1 /* numfds */, 1 /* numints */);
    handle->data[0] = fd;
    handle->data[1] = SYNC_FENCE_DEPRECATED_MAGIC;
    C2Fence fence = _C2FenceFactory::CreateFromNativeHandle(handle, true /* takeOwnership */);
    native_handle_delete(handle);

    validateSingleFdFence(fence, fd);
}

TEST_F(C2FenceTest, BackwardCompat_24Q1_single_fd_fence) {
    // Create a single SyncFence from a 24Q1 native handle
    // This had the same (albeit separately duped) fd twice, and used the legacy
    // magic number.

    int fd = memfd_create("test", 0 /* flags */);

    native_handle_t *handle = native_handle_create(2 /* numfds */, 1 /* numints */);
    handle->data[0] = fd;
    handle->data[1] = dup(fd);
    handle->data[2] = SYNC_FENCE_DEPRECATED_MAGIC;
    C2Fence fence = _C2FenceFactory::CreateFromNativeHandle(handle, true /* takeOwnership */);
    native_handle_delete(handle);

    validateSingleFdFence(fence, fd);
}

TEST_F(C2FenceTest, BackwardCompat_24Q3_single_fd_fence) {
    // Create a single SyncFence from the defined native handle

    int fd = memfd_create("test", 0 /* flags */);

    native_handle_t *handle = native_handle_create(1 /* numfds */, 1 /* numints */);
    handle->data[0] = fd;
    handle->data[1] = SYNC_FENCE_MAGIC;
    C2Fence fence = _C2FenceFactory::CreateFromNativeHandle(handle, true /* takeOwnership */);
    native_handle_delete(handle);

    validateSingleFdFence(fence, fd);
}

TEST_F(C2FenceTest, BackwardCompat_24Q1_multi_fd_fence) {
    // Create a single SyncFence from a 24Q1 era native handle with
    // the legacy magic number.

    int fd1 = memfd_create("test1", 0 /* flags */);
    int fd2 = memfd_create("test2", 0 /* flags */);
    int mergeFd = memfd_create("test3", 0 /* flags */);

    native_handle_t *handle = native_handle_create(3 /* numfds */, 1 /* numints */);
    handle->data[0] = fd1;
    handle->data[1] = fd2;
    handle->data[2] = mergeFd;
    handle->data[3] = SYNC_FENCE_DEPRECATED_MAGIC;
    C2Fence fence = _C2FenceFactory::CreateFromNativeHandle(handle, true /* takeOwnership */);
    native_handle_delete(handle);

    validateTwoFdUnorderedFence(fence, fd1, fd2, mergeFd);
}

// No need to create BackwardCompat_24Q3_unordered_multi_fd_fence because
// we are creating that fence already from the 24Q3 native handle layout
// in the UnorderedMultiSyncFence_with_multiple_fds test.

TEST_F(C2FenceTest, BackwardCompat_24Q3_multi_fd_fence) {
    // Create a single SyncFence from a 24Q1 era native handle with
    // the legacy magic number.

    int fd1 = memfd_create("test1", 0 /* flags */);
    int fd2 = memfd_create("test2", 0 /* flags */);
    int fd3 = memfd_create("test3", 0 /* flags */);

    native_handle_t *handle = native_handle_create(3 /* numfds */, 1 /* numints */);
    handle->data[0] = fd1;
    handle->data[1] = fd2;
    handle->data[2] = fd3;
    handle->data[3] = SYNC_FENCE_MAGIC;
    C2Fence fence = _C2FenceFactory::CreateFromNativeHandle(handle, true /* takeOwnership */);
    native_handle_delete(handle);

    validateThreeFdFence(fence, fd1, fd2, fd3);
}

} // namespace android
