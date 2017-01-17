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

#include <pthread.h>

#include <oboe/OboeDefinitions.h>

#include "OboeThread.h"

using namespace oboe;


OboeThread::OboeThread() {
    // mThread is a pthread_t of unknown size so we need memset.
    memset(&mThread, 0, sizeof(mThread));
}

void OboeThread::dispatch() {
    if (mRunnable != nullptr) {
        mRunnable->run();
    } else {
        run();
    }
}

// This is the entry point for the new thread created by createThread().
// It converts the 'C' function call to a C++ method call.
static void * OboeThread_internalThreadProc(void *arg) {
    OboeThread *oboeThread = (OboeThread *) arg;
    oboeThread->dispatch();
    return nullptr;
}

oboe_result_t OboeThread::start(Runnable *runnable) {
    if (mHasThread) {
        return OBOE_ERROR_INVALID_STATE;
    }
    mRunnable = runnable; // TODO use atomic?
    int err = pthread_create(&mThread, nullptr, OboeThread_internalThreadProc, this);
    if (err != 0) {
        ALOGE("OboeThread::pthread_create() returned %d", err);
        // TODO convert errno to oboe_result_t
        return OBOE_ERROR_INTERNAL;
    } else {
        mHasThread = true;
        return OBOE_OK;
    }
}

oboe_result_t OboeThread::stop() {
    if (!mHasThread) {
        return OBOE_ERROR_INVALID_STATE;
    }
    int err = pthread_join(mThread, nullptr);
    mHasThread = false;
    // TODO convert errno to oboe_result_t
    return err ? OBOE_ERROR_INTERNAL : OBOE_OK;
}

