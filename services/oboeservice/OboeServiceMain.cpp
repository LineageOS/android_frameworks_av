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

#define LOG_TAG "OboeService"
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

#include "OboeService.h"
#include "IOboeAudioService.h"
#include "OboeAudioService.h"

using namespace android;
using namespace oboe;

/**
 * This is used to test the OboeService as a standalone application.
 * It is not used when the OboeService is integrated with AudioFlinger.
 */
int main(int argc, char **argv) {
    printf("Test OboeService %s\n", argv[1]);
    ALOGD("This is the OboeAudioService");

    defaultServiceManager()->addService(String16("OboeAudioService"), new OboeAudioService());
    android::ProcessState::self()->startThreadPool();
    printf("OboeAudioService service is now ready\n");
    IPCThreadState::self()->joinThreadPool();
    printf("OboeAudioService service thread joined\n");

    return 0;
}
