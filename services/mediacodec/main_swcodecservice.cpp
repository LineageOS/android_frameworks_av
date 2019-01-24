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

#include <hidl/HidlTransportSupport.h>

#include "MediaCodecUpdateService.h"

using namespace android;

static const char kSystemSeccompPolicyPath[] =
        "/system/etc/seccomp_policy/mediaswcodec.policy";
static const char kVendorSeccompPolicyPath[] =
        "/vendor/etc/seccomp_policy/mediaswcodec.policy";

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

    ::android::hardware::configureRpcThreadpool(64, false);

#ifdef __LP64__
    loadFromApex("/apex/com.android.media.swcodec/lib64");
#else
    loadFromApex("/apex/com.android.media.swcodec/lib");
#endif

    ::android::hardware::joinRpcThreadpool();
}
