/*
 * Copyright 2018 The Android Open Source Project
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

#define LOG_TAG "MediaCodecUpdateService"
//#define LOG_NDEBUG 0

#include <android/dlext.h>
#include <dlfcn.h>
#include <media/CodecServiceRegistrant.h>
#include <utils/Log.h>
#include <utils/String8.h>

#include "MediaCodecUpdateService.h"

// Copied from GraphicsEnv.cpp
// TODO(b/37049319) Get this from a header once one exists
extern "C" {
  android_namespace_t* android_create_namespace(const char* name,
                                                const char* ld_library_path,
                                                const char* default_library_path,
                                                uint64_t type,
                                                const char* permitted_when_isolated_path,
                                                android_namespace_t* parent);
  bool android_link_namespaces(android_namespace_t* from,
                               android_namespace_t* to,
                               const char* shared_libs_sonames);
  enum {
     ANDROID_NAMESPACE_TYPE_ISOLATED = 1,
  };
}

namespace android {

void loadFromApex(const char *libDirPath) {
    ALOGV("loadFromApex: path=%s", libDirPath);

    String8 libPath = String8(libDirPath) + "/libmedia_codecserviceregistrant.so";

    android_namespace_t *codecNs = android_create_namespace("codecs",
            nullptr,  // ld_library_path
            libDirPath,
            ANDROID_NAMESPACE_TYPE_ISOLATED,
            nullptr,  // permitted_when_isolated_path
            nullptr); // parent

    if (codecNs == nullptr) {
        ALOGE("Failed to create codec namespace");
        return;
    }

    String8 linked_libraries(LINKED_LIBRARIES);
    if (!android_link_namespaces(codecNs, nullptr, linked_libraries.c_str())) {
        ALOGE("Failed to link namespace");
        return;
    }

    const android_dlextinfo dlextinfo = {
            .flags = ANDROID_DLEXT_USE_NAMESPACE,
            .library_namespace = codecNs,
    };

    void *registrantLib = android_dlopen_ext(
            libPath.string(),
            RTLD_NOW | RTLD_LOCAL, &dlextinfo);

    if (registrantLib == nullptr) {
        ALOGE("Failed to load lib from archive: %s", dlerror());
    }

    RegisterCodecServicesFunc registerCodecServices =
            reinterpret_cast<RegisterCodecServicesFunc>(
            dlsym(registrantLib, "RegisterCodecServices"));

    if (registerCodecServices == nullptr) {
        ALOGE("Cannot register codec services -- corrupted library.");
        return;
    }

    registerCodecServices();
}

}   // namespace android
