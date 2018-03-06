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

//#define LOG_NDEBUG 0
#define LOG_TAG "vendor.google.media.c2@1.0-service"

#include <C2PlatformSupport.h>
#include <C2V4l2Support.h>
#include <cutils/properties.h>

#include <codec2/hidl/1.0/ComponentStore.h>
#include <hidl/HidlTransportSupport.h>
#include <minijail.h>

// TODO: Remove this once "setenv()" call is removed.
#include <stdlib.h>

// This is created by module "codec2.system.base.policy". This can be modified.
static constexpr char kBaseSeccompPolicyPath[] =
        "/system/etc/seccomp_policy/codec2.system.base.policy";

// Additional device-specific seccomp permissions can be added in this file.
static constexpr char kExtSeccompPolicyPath[] =
        "/system/etc/seccomp_policy/codec2.system.ext.policy";

int main(int /* argc */, char** /* argv */) {
    ALOGD("vendor.google.media.c2@1.0-service-system starting...");

    // TODO: Remove this when all the build settings and sepolicies are in place.
    setenv("TREBLE_TESTING_OVERRIDE", "true", true);

    signal(SIGPIPE, SIG_IGN);
    android::SetUpMinijail(kBaseSeccompPolicyPath, kExtSeccompPolicyPath);

    // Extra threads may be needed to handle a stacked IPC sequence that
    // contains alternating binder and hwbinder calls. (See b/35283480.)
    android::hardware::configureRpcThreadpool(8, true /* callerWillJoin */);

    // Create IComponentStore service.
    {
        using namespace ::vendor::google::media::c2::V1_0;
        android::sp<IComponentStore> store =
                new implementation::ComponentStore(
                android::GetCodec2PlatformComponentStore());
        if (store == nullptr) {
            ALOGE("Cannot create Codec2's IComponentStore system service.");
        } else {
            if (store->registerAsService("system") != android::OK) {
                ALOGE("Cannot register Codec2's "
                        "IComponentStore system service.");
            } else {
                ALOGI("Codec2's IComponentStore system service created.");
            }
        }

        // To enable the v4l2 service, set this sysprop and add "v4l2" instance
        // to the system manifest file.
        if (property_get_bool("debug.stagefright.ccodec_v4l2", false)) {
            store = new implementation::ComponentStore(
                    android::GetCodec2VDAComponentStore());
            if (store == nullptr) {
                ALOGE("Cannot create Codec2's IComponentStore V4L2 service.");
            } else {
                if (store->registerAsService("v4l2") != android::OK) {
                    ALOGE("Cannot register Codec2's "
                            "IComponentStore V4L2 service.");
                } else {
                    ALOGI("Codec2's IComponentStore V4L2 service created.");
                }
            }
        }
    }

    android::hardware::joinRpcThreadpool();
    return 0;
}

