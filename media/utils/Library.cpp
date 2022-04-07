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

#define LOG_TAG "Library"
#include <utils/Log.h>
#include <mediautils/Library.h>

namespace {

std::string dlerrorIfPresent() {
    const char *dlerr = dlerror();
    if (dlerr == nullptr) return "dlerror: none";
    return std::string("dlerror: '").append(dlerr).append("'");
}

}
namespace android::mediautils {

std::shared_ptr<void> loadLibrary(const char *libraryName, int flags) {
    std::shared_ptr<void> library{
        dlopen(libraryName, flags),
        [](void *lib) {
            if (lib != nullptr) {
                const int ret = dlclose(lib);
                ALOGW_IF(ret !=0, "%s: dlclose(%p) == %d, %s",
                        __func__, lib, ret, dlerrorIfPresent().c_str());
            }
        }
    };

    if (!library) {
        ALOGW("%s: cannot load libraryName %s, %s",
            __func__, libraryName, dlerrorIfPresent().c_str());
        return {};
    }
    return library;
}

std::shared_ptr<void> getUntypedObjectFromLibrary(
        const char *objectName, const std::shared_ptr<void>& library) {
    if (!library) {
        ALOGW("%s: null library, cannot load objectName %s", __func__, objectName);
        return {};
    }
    void *ptr = dlsym(library.get(), objectName);
    if (ptr == nullptr) {
        ALOGW("%s: cannot load objectName %s, %s",
                __func__, objectName, dlerrorIfPresent().c_str());
        return {};
    }

    // Note: we use the "aliasing" constructor of the std:shared_ptr.
    //
    // https://en.cppreference.com/w/cpp/memory/shared_ptr/shared_ptr
    //
    return { library, ptr };  // returns shared_ptr to ptr, but ref counted on library.
}

} // namespace android::mediautils
