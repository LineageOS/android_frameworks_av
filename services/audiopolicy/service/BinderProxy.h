/*
 * Copyright (C) 2019 The Android Open Source Project
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

#include <mutex>
#include <type_traits>
#include <binder/IInterface.h>
#include <binder/IServiceManager.h>
#include <utils/Log.h>

namespace android {

// A simple utility that caches a proxy for a service and handles death notification.
// Typically, intended to be used as a static-lifetime object.
//
// Example usage:
// static BinderProxy<IMyInterface> myInterface("my_interface_svc");
// ...
// myInterface.waitServiceOrDie()->doSomething();
//
// If the service is unavailable, will wait until it becomes available.
// Will die if the service doesn't implement the requested interface, or cannot be used for
// permission reasons.
template<typename ServiceType>
class BinderProxy {
public:
    static_assert(std::is_base_of_v<IInterface, ServiceType>,
                  "Service type must be a sub-type of IInterface.");

    explicit BinderProxy(std::string_view serviceName)
            : mServiceName(serviceName), mDeathRecipient(new DeathRecipient(this)) {}

    ~BinderProxy() {
        if (mDelegate != nullptr) {
            sp<IBinder> binder = IInterface::asBinder(mDelegate);
            if (binder != nullptr) {
                binder->unlinkToDeath(mDeathRecipient);
            }
        }
    }

    sp<ServiceType> waitServiceOrDie() {
        std::lock_guard<std::mutex> _l(mDelegateMutex);
        if (mDelegate == nullptr) {
            mDelegate = waitForService<ServiceType>(String16(mServiceName.c_str()));
            LOG_ALWAYS_FATAL_IF(mDelegate == nullptr,
                                "Service %s doesn't implement the required interface.",
                                mServiceName.c_str());
            sp<IBinder> binder = IInterface::asBinder(mDelegate);
            if (binder != nullptr) {
                binder->linkToDeath(mDeathRecipient);
            }
        }
        return mDelegate;
    }

private:
    sp<ServiceType> mDelegate;
    std::mutex mDelegateMutex;
    const std::string mServiceName;
    sp<IBinder::DeathRecipient> mDeathRecipient;

    class DeathRecipient : public IBinder::DeathRecipient {
    public:
        DeathRecipient(BinderProxy* proxy) : mProxy(proxy) {}

        void binderDied(const wp<IBinder>&) override {
            mProxy->binderDied();
        }

    private:
        BinderProxy* const mProxy;
    };

    void binderDied() {
        std::lock_guard<std::mutex> _l(mDelegateMutex);
        mDelegate.clear();
        ALOGW("Binder died: %s", mServiceName.c_str());
    }
};

}  // namespace android
