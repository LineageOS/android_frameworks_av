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

#pragma once

#include <memory>
#include <string>

#include <android/binder_auto_utils.h>
#include <android/binder_ibinder.h>
#include <android/binder_manager.h>

namespace android {

class HalDeathHandler {
  public:
    static HalDeathHandler& getInstance();

    bool registerHandler(AIBinder* binder);
  private:
    static void OnBinderDied(void*);

    HalDeathHandler();

    ::ndk::ScopedAIBinder_DeathRecipient mDeathRecipient;
};

template<class Intf>
std::shared_ptr<Intf> getServiceInstance(const std::string& instanceName) {
    const std::string serviceName =
            std::string(Intf::descriptor).append("/").append(instanceName);
    std::shared_ptr<Intf> service;
    while (!service) {
        AIBinder* serviceBinder = nullptr;
        while (!serviceBinder) {
            // 'waitForService' may return a nullptr, hopefully a transient error.
            serviceBinder = AServiceManager_waitForService(serviceName.c_str());
        }
        // `fromBinder` may fail and return a nullptr if the service has died in the meantime.
        service = Intf::fromBinder(ndk::SpAIBinder(serviceBinder));
        if (service != nullptr) {
            HalDeathHandler::getInstance().registerHandler(serviceBinder);
        }
    }
    return service;
}

}  // namespace android
