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

#define LOG_TAG "AAudioService"
//#define LOG_NDEBUG 0
#include <utils/Log.h>

#include <stdint.h>
#include <math.h>

#include <utils/RefBase.h>
#include <binder/TextOutput.h>

#include <binder/IInterface.h>
#include <binder/IBinder.h>
#include <binder/ProcessState.h>
#include <binder/IServiceManager.h>
#include <binder/IPCThreadState.h>

#include <cutils/ashmem.h>
#include <sys/mman.h>

#include "AAudioServiceDefinitions.h"
#include "IAAudioService.h"
#include "AAudioService.h"

using namespace android;
using namespace aaudio;

/**
 * This is used to test the AAudioService as a standalone application.
 * It is not used when the AAudioService is integrated with AudioFlinger.
 */
int main(int argc, char **argv) {
    printf("Test AAudioService %s\n", argv[1]);
    ALOGD("This is the AAudioService");

    defaultServiceManager()->addService(String16("AAudioService"), new AAudioService());
    android::ProcessState::self()->startThreadPool();
    printf("AAudioService service is now ready\n");
    IPCThreadState::self()->joinThreadPool();
    printf("AAudioService service thread joined\n");

    return 0;
}
