/*
 * Copyright (C) 2022 The Android Open Source Project
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

#include <android/hardware/BnCameraServiceListener.h>
#include <android/hardware/BnCameraServiceProxy.h>
#include <android/hardware/camera2/BnCameraDeviceCallbacks.h>
#include <android/hardware/ICameraService.h>

#include <private/android_filesystem_config.h>

#include <camera/CameraUtils.h>

#include "../CameraService.h"
#include "../utils/CameraServiceProxyWrapper.h"

#include <gtest/gtest.h>

#include <memory>
#include <vector>

using namespace android;
using namespace android::hardware::camera;

// Empty service listener.
class TestCameraServiceListener : public hardware::BnCameraServiceListener {
public:
    virtual ~TestCameraServiceListener() {}

    virtual binder::Status onStatusChanged(int32_t , const std::string&, int32_t) {
        return binder::Status::ok();
    }

    virtual binder::Status onPhysicalCameraStatusChanged(int32_t /*status*/,
            const std::string& /*cameraId*/, const std::string& /*physicalCameraId*/,
            int32_t /*deviceId*/) {
        // No op
        return binder::Status::ok();
    }

    virtual binder::Status onTorchStatusChanged(int32_t /*status*/,
            const std::string& /*cameraId*/, int32_t /*deviceId*/) {
        return binder::Status::ok();
    }

    virtual binder::Status onCameraAccessPrioritiesChanged() {
        // No op
        return binder::Status::ok();
    }

    virtual binder::Status onCameraOpened(const std::string& /*cameraId*/,
            const std::string& /*clientPackageName*/, int32_t /*deviceId*/) {
        // No op
        return binder::Status::ok();
    }

    virtual binder::Status onCameraClosed(const std::string& /*cameraId*/, int32_t /*deviceId*/) {
        // No op
        return binder::Status::ok();
    }

    virtual binder::Status onTorchStrengthLevelChanged(const std::string& /*cameraId*/,
            int32_t /*torchStrength*/, int32_t /*deviceId*/) {
        // No op
        return binder::Status::ok();
    }
};

// Empty device callback.
class TestCameraDeviceCallbacks : public hardware::camera2::BnCameraDeviceCallbacks {
public:
    TestCameraDeviceCallbacks() {}

    virtual ~TestCameraDeviceCallbacks() {}

    virtual binder::Status onDeviceError(int /*errorCode*/,
            const CaptureResultExtras& /*resultExtras*/) {
        return binder::Status::ok();
    }

    virtual binder::Status onDeviceIdle() {
        return binder::Status::ok();
    }

    virtual binder::Status onCaptureStarted(const CaptureResultExtras& /*resultExtras*/,
            int64_t /*timestamp*/) {
        return binder::Status::ok();
    }

    virtual binder::Status onResultReceived(const CameraMetadata& /*metadata*/,
            const CaptureResultExtras& /*resultExtras*/,
            const std::vector<PhysicalCaptureResultInfo>& /*physicalResultInfos*/) {
        return binder::Status::ok();
    }

    virtual binder::Status onPrepared(int /*streamId*/) {
        return binder::Status::ok();
    }

    virtual binder::Status onRepeatingRequestError(
            int64_t /*lastFrameNumber*/, int32_t /*stoppedSequenceId*/) {
        return binder::Status::ok();
    }

    virtual binder::Status onRequestQueueEmpty() {
        return binder::Status::ok();
    }
};

// Override isCameraDisabled from the CameraServiceProxy with a flag.
class CameraServiceProxyOverride : public ::android::hardware::BnCameraServiceProxy {
public:
    CameraServiceProxyOverride() :
            mCameraServiceProxy(CameraServiceProxyWrapper::getDefaultCameraServiceProxy()),
            mCameraDisabled(false), mOverrideCameraDisabled(false)
    { }

    virtual binder::Status getRotateAndCropOverride(const std::string& packageName, int lensFacing,
            int userId, int *ret) override {
        return mCameraServiceProxy->getRotateAndCropOverride(packageName, lensFacing,
                userId, ret);
    }

    virtual binder::Status getAutoframingOverride(const std::string& packageName, int *ret) override {
        return mCameraServiceProxy->getAutoframingOverride(packageName, ret);
    }

    virtual binder::Status pingForUserUpdate() override {
        return mCameraServiceProxy->pingForUserUpdate();
    }

    virtual binder::Status notifyCameraState(
            const hardware::CameraSessionStats& cameraSessionStats) override {
        return mCameraServiceProxy->notifyCameraState(cameraSessionStats);
    }

    virtual binder::Status isCameraDisabled(int userId, bool *ret) override {
        if (mOverrideCameraDisabled) {
            *ret = mCameraDisabled;
            return binder::Status::ok();
        }
        return mCameraServiceProxy->isCameraDisabled(userId, ret);
    }

    void setCameraDisabled(bool cameraDisabled) {
        mCameraDisabled = cameraDisabled;
    }

    void setOverrideCameraDisabled(bool overrideCameraDisabled) {
        mOverrideCameraDisabled = overrideCameraDisabled;
    }

protected:
    sp<hardware::ICameraServiceProxy> mCameraServiceProxy;
    bool mCameraDisabled;
    bool mOverrideCameraDisabled;
};

class AutoDisconnectDevice {
public:
    AutoDisconnectDevice(sp<hardware::camera2::ICameraDeviceUser> device) :
            mDevice(device)
    { }

    ~AutoDisconnectDevice() {
        if (mDevice != nullptr) {
            mDevice->disconnect();
        }
    }

private:
    sp<hardware::camera2::ICameraDeviceUser> mDevice;
};

class CameraPermissionsTest : public ::testing::Test {
protected:
    static sp<CameraService> sCameraService;
    static sp<CameraServiceProxyOverride> sCameraServiceProxy;
    static std::shared_ptr<CameraServiceProxyWrapper> sCameraServiceProxyWrapper;
    static uid_t sOldUid;

    static void SetUpTestSuite() {
        sOldUid = getuid();
        setuid(AID_CAMERASERVER);
        sCameraServiceProxy = new CameraServiceProxyOverride();
        sCameraServiceProxyWrapper =
            std::make_shared<CameraServiceProxyWrapper>(sCameraServiceProxy);
        sCameraService = new CameraService(sCameraServiceProxyWrapper);
        sCameraService->clearCachedVariables();
    }

    static void TearDownTestSuite() {
        sCameraServiceProxyWrapper = nullptr;
        sCameraServiceProxy = nullptr;
        sCameraService = nullptr;
        setuid(sOldUid);
    }
};

sp<CameraService> CameraPermissionsTest::sCameraService = nullptr;
sp<CameraServiceProxyOverride> CameraPermissionsTest::sCameraServiceProxy = nullptr;
std::shared_ptr<CameraServiceProxyWrapper>
CameraPermissionsTest::sCameraServiceProxyWrapper = nullptr;
uid_t CameraPermissionsTest::sOldUid = 0;

// Test that camera connections fail with ERROR_DISABLED when the camera is disabled via device
// policy, and succeed when it isn't.
TEST_F(CameraPermissionsTest, TestCameraDisabled) {
    std::vector<hardware::CameraStatus> statuses;
    sp<TestCameraServiceListener> serviceListener = new TestCameraServiceListener();
    sCameraService->addListenerTest(serviceListener, &statuses);
    sCameraServiceProxy->setOverrideCameraDisabled(true);

    sCameraServiceProxy->setCameraDisabled(true);
    for (auto s : statuses) {
        sp<TestCameraDeviceCallbacks> callbacks = new TestCameraDeviceCallbacks();
        sp<hardware::camera2::ICameraDeviceUser> device;
        binder::Status status =
                sCameraService->connectDevice(callbacks, s.cameraId, std::string(), {},
                android::CameraService::USE_CALLING_UID, 0/*oomScoreDiff*/,
                /*targetSdkVersion*/__ANDROID_API_FUTURE__,
                hardware::ICameraService::ROTATION_OVERRIDE_NONE,
                kDefaultDeviceId, /*devicePolicy*/0, &device);
        AutoDisconnectDevice autoDisconnect(device);
        ASSERT_TRUE(!status.isOk()) << "connectDevice returned OK status";
        ASSERT_EQ(status.serviceSpecificErrorCode(), hardware::ICameraService::ERROR_DISABLED)
                << "connectDevice returned exception code " << status.exceptionCode();
    }

    sCameraServiceProxy->setCameraDisabled(false);
    for (auto s : statuses) {
        sp<TestCameraDeviceCallbacks> callbacks = new TestCameraDeviceCallbacks();
        sp<hardware::camera2::ICameraDeviceUser> device;
        binder::Status status =
                sCameraService->connectDevice(callbacks, s.cameraId, std::string(), {},
                android::CameraService::USE_CALLING_UID, 0/*oomScoreDiff*/,
                /*targetSdkVersion*/__ANDROID_API_FUTURE__,
                hardware::ICameraService::ROTATION_OVERRIDE_NONE,
                kDefaultDeviceId, /*devicePolicy*/0, &device);
        AutoDisconnectDevice autoDisconnect(device);
        ASSERT_TRUE(status.isOk());
    }
}

// Test that consecutive camera connections succeed.
TEST_F(CameraPermissionsTest, TestConsecutiveConnections) {
    std::vector<hardware::CameraStatus> statuses;
    sp<TestCameraServiceListener> serviceListener = new TestCameraServiceListener();
    sCameraService->addListenerTest(serviceListener, &statuses);
    sCameraServiceProxy->setOverrideCameraDisabled(false);

    for (auto s : statuses) {
        sp<TestCameraDeviceCallbacks> callbacks = new TestCameraDeviceCallbacks();
        sp<hardware::camera2::ICameraDeviceUser> deviceA, deviceB;
        binder::Status status =
                sCameraService->connectDevice(callbacks, s.cameraId, std::string(), {},
                android::CameraService::USE_CALLING_UID, 0/*oomScoreDiff*/,
                /*targetSdkVersion*/__ANDROID_API_FUTURE__,
                hardware::ICameraService::ROTATION_OVERRIDE_NONE,
                kDefaultDeviceId, /*devicePolicy*/0, &deviceA);
        AutoDisconnectDevice autoDisconnectA(deviceA);
        ASSERT_TRUE(status.isOk()) << "Exception code " << status.exceptionCode() <<
                " service specific error code " << status.serviceSpecificErrorCode();
        status =
                sCameraService->connectDevice(callbacks, s.cameraId, std::string(), {},
                android::CameraService::USE_CALLING_UID, 0/*oomScoreDiff*/,
                /*targetSdkVersion*/__ANDROID_API_FUTURE__,
                hardware::ICameraService::ROTATION_OVERRIDE_NONE,
                kDefaultDeviceId, /*devicePolicy*/0, &deviceB);
        AutoDisconnectDevice autoDisconnectB(deviceB);
        ASSERT_TRUE(status.isOk()) << "Exception code " << status.exceptionCode() <<
                " service specific error code " << status.serviceSpecificErrorCode();
    }
}

// Test that consecutive camera connections succeed even when a nonzero oomScoreOffset is provided
// in the second call.
TEST_F(CameraPermissionsTest, TestConflictingOomScoreOffset) {
    std::vector<hardware::CameraStatus> statuses;
    sp<TestCameraServiceListener> serviceListener = new TestCameraServiceListener();
    sCameraService->addListenerTest(serviceListener, &statuses);
    sCameraServiceProxy->setOverrideCameraDisabled(false);

    for (auto s : statuses) {
        sp<TestCameraDeviceCallbacks> callbacks = new TestCameraDeviceCallbacks();
        sp<hardware::camera2::ICameraDeviceUser> deviceA, deviceB;
        binder::Status status =
                sCameraService->connectDevice(callbacks, s.cameraId, std::string(), {},
                android::CameraService::USE_CALLING_UID, 0/*oomScoreDiff*/,
                /*targetSdkVersion*/__ANDROID_API_FUTURE__,
                hardware::ICameraService::ROTATION_OVERRIDE_NONE,
                kDefaultDeviceId, /*devicePolicy*/0, &deviceA);
        AutoDisconnectDevice autoDisconnectA(deviceA);
        ASSERT_TRUE(status.isOk()) << "Exception code " << status.exceptionCode() <<
                " service specific error code " << status.serviceSpecificErrorCode();
        status =
                sCameraService->connectDevice(callbacks, s.cameraId, std::string(), {},
                android::CameraService::USE_CALLING_UID, 1/*oomScoreDiff*/,
                /*targetSdkVersion*/__ANDROID_API_FUTURE__,
                hardware::ICameraService::ROTATION_OVERRIDE_NONE,
                kDefaultDeviceId, /*devicePolicy*/0, &deviceB);
        AutoDisconnectDevice autoDisconnectB(deviceB);
        ASSERT_TRUE(status.isOk()) << "Exception code " << status.exceptionCode() <<
                " service specific error code " << status.serviceSpecificErrorCode();
    }
}
