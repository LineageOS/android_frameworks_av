/*
**
** Copyright 2018, The Android Open Source Project
**
** Licensed under the Apache License, Version 2.0 (the "License");
** you may not use this file except in compliance with the License.
** You may obtain a copy of the License at
**
**     http://www.apache.org/licenses/LICENSE-2.0
**
** Unless required by applicable law or agreed to in writing, software
** distributed under the License is distributed on an "AS IS" BASIS,
** WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
** See the License for the specific language governing permissions and
** limitations under the License.
*/

#include <android-base/logging.h>

// from LOCAL_C_INCLUDES
#include "minijail.h"

#include <android-base/properties.h>
#include <binder/ProcessState.h>
#include <dlfcn.h>
#include <hidl/HidlTransportSupport.h>
#include <media/CodecServiceRegistrant.h>

#include "MediaCodecUpdateService.h"

using namespace android;

// TODO: replace policy with software codec-only policies
// Must match location in Android.mk.
static const char kSystemSeccompPolicyPath[] =
        "/system/etc/seccomp_policy/mediacodec.policy";
static const char kVendorSeccompPolicyPath[] =
        "/vendor/etc/seccomp_policy/mediacodec.policy";

// Disable Scudo's mismatch allocation check, as it is being triggered
// by some third party code.
extern "C" const char *__scudo_default_options() {
  return "DeallocationTypeMismatch=false";
}

int main(int argc __unused, char** /*argv*/)
{
    LOG(INFO) << "media swcodec service starting";
    signal(SIGPIPE, SIG_IGN);
    SetUpMinijail(kSystemSeccompPolicyPath, kVendorSeccompPolicyPath);

    std::string value = base::GetProperty("ro.build.type", "unknown");
    if (value == "userdebug" || value == "eng") {
        media::MediaCodecUpdateService::instantiate();
    }

    android::ProcessState::self()->startThreadPool();

    ::android::hardware::configureRpcThreadpool(64, false);

    // Registration of customized codec services
    void *registrantLib = dlopen(
            "libmedia_codecserviceregistrant.so",
            RTLD_NOW | RTLD_LOCAL);
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

    ::android::hardware::joinRpcThreadpool();
}
