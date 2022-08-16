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

#pragma once

#include <dlfcn.h>
#include <string>
#include <unistd.h>

namespace android::mediautils {

/**
 * Returns a shared pointer to the library instance.
 *
 * When the last reference to the library is removed, the library will be dlclose().
 *
 * Notes:
 * 1) The Android bionic linker always uses RTLD_GLOBAL for executable linking
 * which provides the symbols for other subsequent libraries.
 *
 * 2) RTLD_GLOBAL like RTLD_NODELETE disables unloading of the library
 * when the reference count drops to zero.
 *
 * 3) RTLD_LOCAL is the default in the absence of RTLD_GLOBAL.
 * RTLD_LOCAL may be ignored in some situations, for example:
 * https://stackoverflow.com/questions/56808889/static-objects-destructed-before-dlclose
 *
 * 4) We default to use RTLD_LAZY to delay symbol relocations until needed.
 * This flag may be ignored by Android.  RTLD_LAZY may allow
 * unresolved symbols if not accessed, or symbols added later with another library
 * loaded with RTLD_GLOBAL. See RTLD_NOW for comparison.
 *
 * 5) Avoid both staticly loading and dynamically loading the same library.
 * This is known to cause double free issues as library symbols may map to
 * the same location.  RTLD_DEEPBIND does not appear supported as of T.
 * https://stackoverflow.com/questions/34073051/when-we-are-supposed-to-use-rtld-deepbind
 * https://stackoverflow.com/questions/31209693/static-library-linked-two-times
 *
 * Details on Android linker and debugging here:
 * See: adb shell setprop debug.ld.all dlerror,dlopen,dlsym
 * See: https://android.googlesource.com/platform/bionic/+/master/android-changes-for-ndk-developers.md
 *
 * Some other relevant info:
 * See: Soong double_loadable:true go/double_loadable
 * See: https://en.wikipedia.org/wiki/One_Definition_Rule#Summary
 *
 * TODO(b/228093151): Consider moving to platform/system.
 *
 * \param libraryName
 * \param flags one of the dlopen RTLD_* flags. https://linux.die.net/man/3/dlopen
 * \return shared_ptr to the library. This will be nullptr if it isn't found.
 */
std::shared_ptr<void> loadLibrary(const char *libraryName, int flags = RTLD_LAZY);

/**
 * Returns a shared pointer to an object in the library
 *
 * The object will be a global variable or method in the library.
 * The object reference counting is aliased to the library shared ptr.
 *
 * Note: If any internals of the shared library are exposed, for example by
 * a method returning a pointer to library globals,
 * or returning an object whose class definition is from the library,
 * then the shared_ptr must be kept alive while such references to
 * library internals exist to prevent library unloading.
 *
 * See usage of RTLD_NODELETE as a flag to prevent unloading.
 *
 * \param objectName of the library object.
 * \param library a shared pointer to the library returned by loadLibrary().
 * \return shared_ptr to the object, but whose refcount is
 *         aliased to the library shared ptr.
 */
std::shared_ptr<void> getUntypedObjectFromLibrary(
        const char *objectName, const std::shared_ptr<void>& library);

/**
 * Returns a shared pointer to an object in the library
 *
 * This is the template typed version of getUntypedObjectFromLibrary().
 *
 * \param objectName of the library object.
 * \param library a shared pointer to the library
 * \return shared_ptr to the object, but whose refcount is
 *         aliased to the library shared ptr.
 */
template <typename T>
std::shared_ptr<T> getObjectFromLibrary(
        const char *objectName, const std::shared_ptr<void>& library) {
    return std::static_pointer_cast<T>(getUntypedObjectFromLibrary(objectName, library));
}

} // android::mediautils
