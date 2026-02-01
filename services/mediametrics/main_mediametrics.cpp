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

#define LOG_TAG "mediametrics"
//#define LOG_NDEBUG 0
#include <utils/Log.h>

#include "MediaMetricsService.h"

#ifdef  METRICS_IN_MODULE
#include <android/binder_manager.h>
#include <android/binder_process.h>
#else
#include <mediautils/LimitProcessMemory.h>
#include <binder/IPCThreadState.h>
#include <binder/IServiceManager.h>
#include <binder/ProcessState.h>
#endif

int main(int argc __unused, char **argv)
{
    using namespace android; // NOLINT (clang-tidy)

#ifdef METRICS_IN_MODULE
    // XXX: need a module-side way to limit process memory
    ALOGD("TODO: need module-side way to limit process memory");
#else
    limitProcessMemory(
        "media.metrics.maxmem", /* property that defines limit */
        (size_t)128 * (1 << 20), /* SIZE_MAX, upper limit in bytes */
        10 /* upper limit as percentage of physical RAM */);

#endif

    signal(SIGPIPE, SIG_IGN);

    // to match the service name
    // we're replacing "/system/bin/mediametrics" with "media.metrics"
    // we add a ".", but discard the path components: we finish with a shorter string
    const size_t origSize = strlen(argv[0]) + 1; // include null termination.
    strlcpy(argv[0], MediaMetricsService::kServiceName, origSize);

#ifdef METRICS_IN_MODULE
    // TODO: can we always do it this way?
    ALOGD("main_mediametrics compiled for module");

    // ABinderProcess_setThreadPoolMaxThreadCount(8);
    ABinderProcess_startThreadPool();

    MediaMetricsService* myServicep = ::new MediaMetricsService();
    binder_exception_t err = AServiceManager_addService(
                    myServicep->asBinder().get(), MediaMetricsService::kServiceName);
    if (err != 0) {
        ALOGE("AServiceManager_addService(%s) returned %d",
              MediaMetricsService::kServiceName, err);
        return EXIT_FAILURE;
    }

    // and, finally, we go off to be part of the threadpool
    ABinderProcess_joinThreadPool();
#else
    ALOGD("main_mediametrics compiled for framework");

    defaultServiceManager()->addService(
            String16(MediaMetricsService::kServiceName), new MediaMetricsService());

    sp<ProcessState> processState(ProcessState::self());
    // processState->setThreadPoolMaxThreadCount(8);
    processState->startThreadPool();
    IPCThreadState::self()->joinThreadPool();


#endif

    return EXIT_SUCCESS;
}
