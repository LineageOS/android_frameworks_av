/*
 * Copyright 2021 The Android Open Source Project
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
#define LOG_NDEBUG 1
#define LOG_TAG "clearkey-main"

#include "CreatePluginFactories.h"

#include <android-base/logging.h>

#include <android/binder_manager.h>
#include <android/binder_process.h>

using ::android::base::InitLogging;
using ::android::base::StderrLogger;

using ::aidl::android::hardware::drm::clearkey::createCryptoFactory;
using ::aidl::android::hardware::drm::clearkey::createDrmFactory;
using ::aidl::android::hardware::drm::clearkey::CryptoFactory;
using ::aidl::android::hardware::drm::clearkey::DrmFactory;

int main(int /*argc*/, char* argv[]) {
    InitLogging(argv, StderrLogger);
    ::android::base::SetMinimumLogSeverity(::android::base::VERBOSE);
    ABinderProcess_setThreadPoolMaxThreadCount(8);

    binder_status_t status{};
    std::shared_ptr<DrmFactory> drmFactory = createDrmFactory();
    const std::string drmInstance = std::string() + DrmFactory::descriptor + "/clearkey";
    status = AServiceManager_registerLazyService(drmFactory->asBinder().get(),
                                                 drmInstance.c_str());
    CHECK(status == STATUS_OK);

    std::shared_ptr<CryptoFactory> cryptoFactory = createCryptoFactory();
    const std::string cryptoInstance = std::string() + CryptoFactory::descriptor + "/clearkey";
    status = AServiceManager_registerLazyService(cryptoFactory->asBinder().get(),
                                                 cryptoInstance.c_str());
    CHECK(status == STATUS_OK);

    ABinderProcess_joinThreadPool();
    return EXIT_FAILURE;  // should not reached
}
