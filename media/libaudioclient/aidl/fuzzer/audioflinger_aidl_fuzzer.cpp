/*
 * Copyright (C) 2022 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */
#include <AudioFlinger.h>
#include <android-base/logging.h>
#include <android/binder_interface_utils.h>
#include <android/binder_process.h>
#include <android/media/IAudioPolicyService.h>
#include <fakeservicemanager/FakeServiceManager.h>
#include <fuzzbinder/libbinder_driver.h>
#include <fuzzbinder/random_binder.h>
#include <fuzzer/FuzzedDataProvider.h>
#include <media/IAudioFlinger.h>
#include <service/AudioPolicyService.h>

using namespace android;
using namespace android::binder;
using android::fuzzService;

[[clang::no_destroy]] static std::once_flag gSmOnce;
sp<FakeServiceManager> gFakeServiceManager;

bool addService(const String16& serviceName, const sp<FakeServiceManager>& fakeServiceManager,
                FuzzedDataProvider& fdp) {
    sp<IBinder> binder = getRandomBinder(&fdp);
    if (binder == nullptr) {
        return false;
    }
    CHECK_EQ(NO_ERROR, fakeServiceManager->addService(serviceName, binder));
    return true;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    FuzzedDataProvider fdp(data, size);

    std::call_once(gSmOnce, [&] {
        /* Create a FakeServiceManager instance and add required services */
        gFakeServiceManager = sp<FakeServiceManager>::make();
        setDefaultServiceManager(gFakeServiceManager);
    });
    gFakeServiceManager->clear();

    for (const char* service :
         {"activity", "sensor_privacy", "permission", "scheduling_policy",
          "android.hardware.audio.core.IConfig", "batterystats", "media.metrics"}) {
        if (!addService(String16(service), gFakeServiceManager, fdp)) {
            return 0;
        }
    }

    const auto audioFlinger = sp<AudioFlinger>::make();
    const auto afAdapter = sp<AudioFlingerServerAdapter>::make(audioFlinger);

    CHECK_EQ(NO_ERROR,
             gFakeServiceManager->addService(
                     String16(IAudioFlinger::DEFAULT_SERVICE_NAME), IInterface::asBinder(afAdapter),
                     false /* allowIsolated */, IServiceManager::DUMP_FLAG_PRIORITY_DEFAULT));

    AudioSystem::get_audio_flinger_for_fuzzer();
    const auto audioPolicyService = sp<AudioPolicyService>::make();

    CHECK_EQ(NO_ERROR,
             gFakeServiceManager->addService(String16("media.audio_policy"), audioPolicyService,
                                             false /* allowIsolated */,
                                             IServiceManager::DUMP_FLAG_PRIORITY_DEFAULT));

    sp<IBinder> audioFlingerServiceBinder =
            gFakeServiceManager->getService(String16(IAudioFlinger::DEFAULT_SERVICE_NAME));
    sp<media::IAudioFlingerService> audioFlingerService =
            interface_cast<media::IAudioFlingerService>(audioFlingerServiceBinder);

    fuzzService(media::IAudioFlingerService::asBinder(audioFlingerService), std::move(fdp));

    return 0;
}
