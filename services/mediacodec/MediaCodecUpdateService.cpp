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
#include <android-base/logging.h>
#include <android-base/strings.h>
#include <dirent.h>
#include <dlfcn.h>
#include <media/CodecServiceRegistrant.h>
#include <utils/Log.h>
#include <ziparchive/zip_archive.h>
#include <cutils/properties.h>

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
namespace media {

binder::Status MediaCodecUpdateService::loadPlugins(const ::std::string& apkPath) {
    ALOGV("loadPlugins %s", apkPath.c_str());

    ZipArchiveHandle zipHandle;
    void *registrantLib = NULL;
    int32_t ret = OpenArchive(apkPath.c_str(), &zipHandle);

    if (ret == 0) {
        char abilist32[PROPERTY_VALUE_MAX];
        property_get("ro.product.cpu.abilist32", abilist32, "armeabi-v7a");

        auto abis = base::Split(abilist32, ",");
        if (abis.empty()) {
            ALOGW("abilist is empty, trying armeabi-v7a ...");
            abis.push_back("armeabi-v7a");
        }

        // TODO: Only try the first entry in abilist32 for now.
        // We probably should try the next if it fails.
        String8 libPathInApk = String8("lib/") + String8(abis[0].c_str());
        String8 defaultLibPath = String8(apkPath.c_str()) + "!/" + libPathInApk;
        String8 libPath = defaultLibPath + "/libmedia_codecserviceregistrant.so";

        ZipEntry entry;
        ZipString name(libPathInApk + "/libmedia_codecserviceregistrant.so");
        ret = FindEntry(zipHandle, name, &entry);

        if (ret == 0) {
            android_namespace_t *codecNs = android_create_namespace("codecs",
                    nullptr,  // ld_library_path
                    defaultLibPath.c_str(),
                    ANDROID_NAMESPACE_TYPE_ISOLATED,
                    nullptr,  // permitted_when_isolated_path
                    nullptr); // parent

            if (codecNs != nullptr) {
                String8 linked_libraries(LINKED_LIBRARIES);
                if (android_link_namespaces(
                        codecNs, nullptr, linked_libraries.c_str())) {
                    const android_dlextinfo dlextinfo = {
                            .flags = ANDROID_DLEXT_USE_NAMESPACE,
                            .library_namespace = codecNs,
                    };

                    registrantLib = android_dlopen_ext(
                            libPath.string(),
                            RTLD_NOW | RTLD_LOCAL, &dlextinfo);

                    if (registrantLib == NULL) {
                        ALOGE("Failed to load lib from archive: %s", dlerror());
                    }
                } else {
                    ALOGE("Failed to link namespace");
                }
            } else {
                ALOGE("Failed to create codec namespace");
            }
        } else {
            ALOGE("Failed to find entry (ret=%d)", ret);
        }

        CloseArchive(zipHandle);
    } else {
        ALOGE("Failed to open archive (ret=%d)", ret);
    }

    if (registrantLib) {
        RegisterCodecServicesFunc registerCodecServices =
                reinterpret_cast<RegisterCodecServicesFunc>(
                dlsym(registrantLib, "RegisterCodecServices"));
        if (registerCodecServices) {
            registerCodecServices();
        } else {
            LOG(WARNING) << "Cannot register codec services "
                    "-- corrupted library.";
        }
    } else {
        LOG(ERROR) << "Cannot find codec service registrant.";
    }

    return binder::Status::ok();
}

}   // namespace media
}   // namespace android
