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
#include <ISchedulingPolicyService.h>
#include <fakeservicemanager/FakeServiceManager.h>
#include <android-base/logging.h>
#include <android/binder_interface_utils.h>
#include <android/binder_process.h>
#include <android/media/IAudioPolicyService.h>
#include <binder/IActivityManager.h>
#include <binder/IPermissionController.h>
#include <binder/IServiceManager.h>
#include <binder/PermissionController.h>
#include <fuzzbinder/libbinder_driver.h>
#include <fuzzer/FuzzedDataProvider.h>
#include <media/IAudioFlinger.h>
#include <mediautils/SchedulingPolicyService.h>
#include <sensorprivacy/SensorPrivacyManager.h>
#include <service/AudioPolicyService.h>

using namespace android;
using namespace android::binder;
using android::fuzzService;

static sp<media::IAudioFlingerService> gAudioFlingerService;

class FuzzerSchedulingPolicyService : public BnInterface<ISchedulingPolicyService> {
    int32_t requestPriority(int32_t /*pid_t*/, int32_t /*tid*/, int32_t /*prio*/, bool /*isForApp*/,
                            bool /*asynchronous*/) {
        return 0;
    }

    int32_t requestCpusetBoost(bool /*enable*/, const sp<IBinder>& /*client*/) { return 0; }
};

class FuzzerPermissionController : public BnInterface<IPermissionController> {
  public:
    bool checkPermission(const String16& /*permission*/, int32_t /*pid*/, int32_t /*uid*/) {
        return true;
    }
    int32_t noteOp(const String16& /*op*/, int32_t /*uid*/, const String16& /*packageName*/) {
        return 0;
    }
    void getPackagesForUid(const uid_t /*uid*/, Vector<String16>& /*packages*/) {}
    bool isRuntimePermission(const String16& /*permission*/) { return true; }
    int32_t getPackageUid(const String16& /*package*/, int /*flags*/) { return 0; }
};

class FuzzerSensorPrivacyManager : public BnInterface<hardware::ISensorPrivacyManager> {
  public:
    Status supportsSensorToggle(int32_t /*toggleType*/, int32_t /*sensor*/,
                                bool* /*_aidl_return*/) override {
        return Status::fromStatusT(UNKNOWN_TRANSACTION);
    }
    Status addSensorPrivacyListener(
            const sp<hardware::ISensorPrivacyListener>& /*listener*/) override {
        return Status::fromStatusT(::android::UNKNOWN_TRANSACTION);
    }
    Status addToggleSensorPrivacyListener(
            const sp<hardware::ISensorPrivacyListener>& /*listener*/) override {
        return Status::fromStatusT(UNKNOWN_TRANSACTION);
    }
    Status removeSensorPrivacyListener(
            const sp<hardware::ISensorPrivacyListener>& /*listener*/) override {
        return Status::fromStatusT(::android::UNKNOWN_TRANSACTION);
    }
    Status removeToggleSensorPrivacyListener(
            const sp<hardware::ISensorPrivacyListener>& /*listener*/) override {
        return Status::fromStatusT(::android::UNKNOWN_TRANSACTION);
    }
    Status isSensorPrivacyEnabled(bool* /*_aidl_return*/) override {
        return Status::fromStatusT(UNKNOWN_TRANSACTION);
    }
    Status isCombinedToggleSensorPrivacyEnabled(int32_t /*sensor*/,
                                                bool* /*_aidl_return*/) override {
        return Status::fromStatusT(UNKNOWN_TRANSACTION);
    }
    Status isToggleSensorPrivacyEnabled(int32_t /*toggleType*/, int32_t /*sensor*/,
                                        bool* /*_aidl_return*/) override {
        return Status::fromStatusT(UNKNOWN_TRANSACTION);
    }
    Status setSensorPrivacy(bool /*enable*/) override {
        return Status::fromStatusT(UNKNOWN_TRANSACTION);
    }
    Status setToggleSensorPrivacy(int32_t /*userId*/, int32_t /*source*/, int32_t /*sensor*/,
                                  bool /*enable*/) override {
        return Status::fromStatusT(UNKNOWN_TRANSACTION);
    }
    Status setToggleSensorPrivacyForProfileGroup(int32_t /*userId*/, int32_t /*source*/,
                                                 int32_t /*sensor*/, bool /*enable*/) override {
        return Status::fromStatusT(UNKNOWN_TRANSACTION);
    }
};

class FuzzerActivityManager : public BnInterface<IActivityManager> {
  public:
    int32_t openContentUri(const String16& /*stringUri*/) override { return 0; }

    status_t registerUidObserver(const sp<IUidObserver>& /*observer*/, const int32_t /*event*/,
                                 const int32_t /*cutpoint*/,
                                 const String16& /*callingPackage*/) override {
        return OK;
    }

    status_t unregisterUidObserver(const sp<IUidObserver>& /*observer*/) override { return OK; }

    bool isUidActive(const uid_t /*uid*/, const String16& /*callingPackage*/) override {
        return true;
    }

    int32_t getUidProcessState(const uid_t /*uid*/, const String16& /*callingPackage*/) override {
        return ActivityManager::PROCESS_STATE_UNKNOWN;
    }

    status_t checkPermission(const String16& /*permission*/, const pid_t /*pid*/,
                             const uid_t /*uid*/, int32_t* /*outResult*/) override {
        return NO_ERROR;
    }

    status_t registerUidObserverForUids(const sp<IUidObserver>& /*observer*/ ,
                                        const int32_t /*event*/ ,
                                        const int32_t /*cutpoint*/ ,
                                        const String16& /*callingPackage*/ ,
                                        const int32_t uids[] ,
                                        size_t /*nUids*/ ,
                                        /*out*/ sp<IBinder>& /*observerToken*/ ) {
        (void)uids;
        return OK;
    }

    status_t addUidToObserver(const sp<IBinder>& /*observerToken*/ ,
                              const String16& /*callingPackage*/ ,
                              int32_t /*uid*/ ) override {
        return NO_ERROR;
    }

    status_t removeUidFromObserver(const sp<IBinder>& /*observerToken*/ ,
                                   const String16& /*callingPackage*/ ,
                                   int32_t /*uid*/ ) override {
        return NO_ERROR;
    }

    status_t logFgsApiBegin(int32_t /*apiType*/ , int32_t /*appUid*/ ,
                            int32_t /*appPid*/ ) override {
        return NO_ERROR;
    }
    status_t logFgsApiEnd(int32_t /*apiType*/ , int32_t /*appUid*/ ,
                          int32_t /*appPid*/ ) override {
        return NO_ERROR;
    }
    status_t logFgsApiStateChanged(int32_t /*apiType*/ , int32_t /*state*/ ,
                                   int32_t /*appUid*/ ,
                                   int32_t /*appPid*/ ) override {
        return NO_ERROR;
    }
};

extern "C" int LLVMFuzzerInitialize(int* /* argc */, char*** /* argv */) {
    /* Create a FakeServiceManager instance and add required services */
    sp<FakeServiceManager> fakeServiceManager = new FakeServiceManager();
    setDefaultServiceManager(fakeServiceManager);
    ABinderProcess_setThreadPoolMaxThreadCount(0);
    sp<FuzzerActivityManager> am = new FuzzerActivityManager();
    fakeServiceManager->addService(String16("activity"), IInterface::asBinder(am));

    sp<FuzzerSensorPrivacyManager> sensorPrivacyManager = new FuzzerSensorPrivacyManager();
    fakeServiceManager->addService(String16("sensor_privacy"),
                                   IInterface::asBinder(sensorPrivacyManager));
    sp<FuzzerPermissionController> permissionController = new FuzzerPermissionController();
    fakeServiceManager->addService(String16("permission"),
                                   IInterface::asBinder(permissionController));

    sp<FuzzerSchedulingPolicyService> schedulingService = new FuzzerSchedulingPolicyService();
    fakeServiceManager->addService(String16("scheduling_policy"),
                                   IInterface::asBinder(schedulingService));

    const auto audioFlingerObj = sp<AudioFlinger>::make();
    const auto afAdapter = sp<AudioFlingerServerAdapter>::make(audioFlingerObj);

    fakeServiceManager->addService(String16(IAudioFlinger::DEFAULT_SERVICE_NAME),
                                   IInterface::asBinder(afAdapter), false /* allowIsolated */,
                                   IServiceManager::DUMP_FLAG_PRIORITY_DEFAULT);

    const auto audioPolicyService = sp<AudioPolicyService>::make();
    fakeServiceManager->addService(String16("media.audio_policy"), audioPolicyService,
                                   false /* allowIsolated */,
                                   IServiceManager::DUMP_FLAG_PRIORITY_DEFAULT);

    sp<IBinder> binder =
            fakeServiceManager->getService(String16(IAudioFlinger::DEFAULT_SERVICE_NAME));
    gAudioFlingerService = interface_cast<media::IAudioFlingerService>(binder);
    return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    if (!gAudioFlingerService) {
        return 0;
    }

    fuzzService(media::IAudioFlingerService::asBinder(gAudioFlingerService),
                FuzzedDataProvider(data, size));

    return 0;
}
