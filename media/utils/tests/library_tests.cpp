/*
 * Copyright (C) 2022 The Android Open Source Project
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

#define LOG_TAG "library_tests"
#include <utils/Log.h>

#include <mediautils/Library.h>

#include <android-base/file.h>
#include <gtest/gtest.h>

using namespace android::mediautils;

namespace {

[[maybe_unused]] static int32_t here = 0;  // accessed on same thread.

#if __android__
TEST(library_tests, basic) {
    std::string path = android::base::GetExecutableDirectory() + "/libsharedtest.so";
    // The flags to loadLibrary should not include  RTLD_GLOBAL or RTLD_NODELETE
    // which prevent unloading.
    std::shared_ptr<void> library = loadLibrary(path.c_str(), RTLD_LAZY);
    ASSERT_TRUE(library);
    ASSERT_EQ(1, library.use_count());

    std::shared_ptr<int32_t*> ptr = getObjectFromLibrary<int32_t*>("gPtr", library);
    ASSERT_TRUE(ptr);
    ASSERT_EQ(2, library.use_count());

    ASSERT_EQ(nullptr, *ptr); // original contents are nullptr.

    // There is a static object destructor in libsharedtest.so that will set the
    // contents of the integer pointer (if non-null) to 1 when called.
    // This is used to detect that the library is unloaded.
    *ptr = &here;

    ptr.reset();  // Note: this shared pointer uses library's refcount.
    ASSERT_EQ(1, library.use_count());  // Verify library's refcount goes down by 1.
    ASSERT_EQ(0, here);  // the shared library's object destructor hasn't been called.

    // use weak_ptr to investigate whether the library is gone.
    std::weak_ptr<void> wlibrary = library;
    ASSERT_EQ(1, wlibrary.use_count());
    library.reset();

    // we should have released the last reference.
    ASSERT_EQ(0, wlibrary.use_count());

    // The library should unload and the global object destroyed.
    // Note on Android, specifying RTLD_GLOBAL or RTLD_NODELETE in the flags
    // will prevent unloading libraries.
    ASSERT_EQ(1, here);
}
#endif

TEST(library_tests, sad_library) {
    std::string path = android::base::GetExecutableDirectory()
            + "/something_random_library_that_doesn't_exit.so";

    std::shared_ptr<void> library = loadLibrary(path.c_str(), RTLD_LAZY);
    // We shouldn't crash on an invalid library path, just return an empty shared pointer.
    // Check the logcat for any error details.
    ASSERT_FALSE(library);
}

} // namespace
