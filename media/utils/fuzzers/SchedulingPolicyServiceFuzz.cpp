/*
 * Copyright 2020 The Android Open Source Project
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
#define LOG_TAG "BatteryNotifierFuzzer"
#include <batterystats/IBatteryStats.h>
#include <binder/IServiceManager.h>
#include <utils/String16.h>
#include <android/log.h>
#include <mediautils/SchedulingPolicyService.h>
#include "fuzzer/FuzzedDataProvider.h"
using android::IBatteryStats;
using android::IBinder;
using android::IInterface;
using android::IServiceManager;
using android::sp;
using android::String16;
using android::defaultServiceManager;
using android::requestCpusetBoost;
using android::requestPriority;
sp<IBatteryStats> getBatteryService() {
    sp<IBatteryStats> batteryStatService;
    const sp<IServiceManager> sm(defaultServiceManager());
    if (sm != nullptr) {
        const String16 name("batterystats");
        sp<IBinder> obj = sm->checkService(name);
        if (!obj) {
            ALOGW("batterystats service unavailable!");
            return nullptr;
        }
        batteryStatService = checked_interface_cast<IBatteryStats>(obj);
        if (batteryStatService == nullptr) {
            ALOGW("batterystats service interface is invalid");
            return nullptr;
        }
    }
    return batteryStatService;
}
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    FuzzedDataProvider data_provider(data, size);
    sp<IBatteryStats> batteryStatService = getBatteryService();
    // There is some state here, but it's mostly focused around thread-safety, so
    // we won't worry about order.
    int32_t priority = data_provider.ConsumeIntegral<int32_t>();
    bool is_for_app = data_provider.ConsumeBool();
    bool async = data_provider.ConsumeBool();
    requestPriority(getpid(), gettid(), priority, is_for_app, async);
    // TODO: Verify and re-enable in AOSP (R).
    // bool enable = data_provider.ConsumeBool();
    // We are just using batterystats to avoid the need
    // to register a new service.
    // requestCpusetBoost(enable, IInterface::asBinder(batteryStatService));
    return 0;
}

