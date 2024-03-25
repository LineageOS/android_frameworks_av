/*
 * Copyright (C) 2024 The Android Open Source Project
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

#include "AidlUtils.h"

#define LOG_TAG "AIDLUtils"
#include <utils/Log.h>

namespace android {

//static
HalDeathHandler& HalDeathHandler::getInstance() {
    // never-delete singleton
    static HalDeathHandler* instance = new HalDeathHandler;
    return *instance;
}

//static
void HalDeathHandler::OnBinderDied(void*) {
    ALOGE("HAL instance died, audio server is restarting");
    _exit(1);  // Avoid calling atexit handlers, as this code runs on a thread from RPC threadpool.
}

HalDeathHandler::HalDeathHandler()
        : mDeathRecipient(AIBinder_DeathRecipient_new(OnBinderDied)) {}

bool HalDeathHandler::registerHandler(AIBinder* binder) {
    binder_status_t status = AIBinder_linkToDeath(binder, mDeathRecipient.get(), nullptr);
    if (status == STATUS_OK) return true;
    ALOGE("%s: linkToDeath failed: %d", __func__, status);
    return false;
}

}  // namespace android
