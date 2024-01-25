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

#define LOG_TAG "test_multiple_close_simultaneously"

#include <chrono>
#include <condition_variable>
#include <shared_mutex>
#include <string>
#include <thread>

#include <gtest/gtest.h>

#include <binder/IBinder.h>
#include <binder/IServiceManager.h>
#include <utils/Log.h>

#include <aaudio/AAudio.h>
#include <aaudio/IAAudioService.h>
#include <aaudio/StreamRequest.h>
#include <aaudio/StreamParameters.h>

using namespace android;
using namespace aaudio;

#define AAUDIO_SERVICE_NAME "media.aaudio"

static constexpr int THREAD_NUM = 2;
static constexpr auto TEST_DURATION = std::chrono::minutes(1);

static std::string sError;
static bool sTestPassed = true;

struct Signal {
    std::atomic_int value{0};
    std::shared_mutex lock;
    std::condition_variable_any cv;
};

class AAudioServiceDeathRecipient : public IBinder::DeathRecipient {
public:
    void binderDied(const wp<IBinder>& who __unused) override {
        sError = "AAudioService is dead";
        ALOGE("%s", sError.c_str());
        sTestPassed = false;
    }
};

sp<IAAudioService> getAAudioService(const sp<IBinder::DeathRecipient>& recipient) {
    auto sm = defaultServiceManager();
    if (sm == nullptr) {
        sError = "Cannot get service manager";
        ALOGE("%s", sError.c_str());
        return nullptr;
    }
    sp<IBinder> binder = sm->waitForService(String16(AAUDIO_SERVICE_NAME));
    if (binder == nullptr) {
        sError = "Cannot get aaudio service";
        ALOGE("%s", sError.c_str());
        return nullptr;
    }
    if (binder->linkToDeath(recipient) != NO_ERROR) {
        sError = "Cannot link to binder death";
        ALOGE("%s", sError.c_str());
        return nullptr;
    }
    return interface_cast<IAAudioService>(binder);
}

void openAndMultipleClose(const sp<IAAudioService>& aaudioService) {
    auto start = std::chrono::system_clock::now();
    bool hasFailedOpening = false;
    while (sTestPassed && std::chrono::system_clock::now() - start < TEST_DURATION) {
        StreamRequest inRequest;
        StreamParameters outParams;
        int32_t handle = 0;
        inRequest.attributionSource.uid = getuid();
        inRequest.attributionSource.pid = getpid();
        inRequest.attributionSource.token = sp<BBinder>::make();
        auto status = aaudioService->openStream(inRequest, &outParams, &handle);
        if (!status.isOk()) {
            sError = "Cannot open stream, it can be caused by service death";
            ALOGE("%s", sError.c_str());
            sTestPassed = false;
            break;
        }
        if (handle <= 0) {
            sError = "Cannot get stream handle after open, returned handle"
                    + std::to_string(handle);
            ALOGE("%s", sError.c_str());
            sTestPassed = false;
            break;
        }
        hasFailedOpening = false;

        Signal isReady;
        Signal startWork;
        Signal isCompleted;
        std::unique_lock readyLock(isReady.lock);
        std::unique_lock completedLock(isCompleted.lock);
        for (int i = 0; i < THREAD_NUM; ++i) {
            std::thread closeStream([aaudioService, handle, &isReady, &startWork, &isCompleted] {
                isReady.value++;
                isReady.cv.notify_one();
                {
                    std::shared_lock<std::shared_mutex> _l(startWork.lock);
                    startWork.cv.wait(_l, [&startWork] { return startWork.value.load() == 1; });
                }
                int32_t result;
                aaudioService->closeStream(handle, &result);
                isCompleted.value++;
                isCompleted.cv.notify_one();
            });
            closeStream.detach();
        }
        isReady.cv.wait(readyLock, [&isReady] { return isReady.value == THREAD_NUM; });
        {
            std::unique_lock startWorkLock(startWork.lock);
            startWork.value.store(1);
        }
        startWork.cv.notify_all();
        isCompleted.cv.wait_for(completedLock,
                                std::chrono::milliseconds(1000),
                                [&isCompleted] { return isCompleted.value == THREAD_NUM; });
        if (isCompleted.value != THREAD_NUM) {
            sError = "Close is not completed within 1 second";
            ALOGE("%s", sError.c_str());
            sTestPassed = false;
            break;
        }
    }
}

TEST(test_multiple_close_simultaneously, open_multiple_close) {
    const auto recipient = sp<AAudioServiceDeathRecipient>::make();
    auto aaudioService = getAAudioService(recipient);
    ASSERT_NE(nullptr, aaudioService) << sError;
    openAndMultipleClose(aaudioService);
    ASSERT_TRUE(sTestPassed) << sError;
}
