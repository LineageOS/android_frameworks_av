/*
 * Copyright (C) 2020 The Android Open Source Project
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

#include <utils/Log.h>
#include <binder/IPCThreadState.h>
#include <binder/IServiceManager.h>
#include <binder/ProcessState.h>
#include <hidl/HidlTransportSupport.h>

#include "TunerService.h"

using namespace android;

int main(int argc __unused, char** argv) {
    ALOGD("Tuner service starting");

    strcpy(argv[0], "media.tuner");
    sp<ProcessState> proc(ProcessState::self());
    sp<IServiceManager> sm = defaultServiceManager();
    ALOGD("ServiceManager: %p", sm.get());

    binder_status_t status = TunerService::instantiate();
    if (status != STATUS_OK) {
        ALOGD("Failed to add tuner service as AIDL interface");
        return -1;
    }

    ProcessState::self()->startThreadPool();
    IPCThreadState::self()->joinThreadPool();
}
