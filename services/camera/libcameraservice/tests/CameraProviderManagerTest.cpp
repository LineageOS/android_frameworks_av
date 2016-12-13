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

#define LOG_NDEBUG 0
#define LOG_TAG "CameraProviderManagerTest"

#include "../common/CameraProviderManager.h"
#include <android/hidl/manager/1.0/IServiceManager.h>
#include <android/hidl/manager/1.0/IServiceNotification.h>

#include <gtest/gtest.h>

using namespace android;
using namespace android::hardware::camera;
using android::hardware::camera::common::V1_0::Status;

/**
 * Basic test implementation of a camera provider
 */
struct TestICameraProvider : virtual public provider::V2_4::ICameraProvider {
    sp<provider::V2_4::ICameraProviderCallbacks> mCallbacks;

    std::vector<hardware::hidl_string> mDeviceNames;

    TestICameraProvider() {
        mDeviceNames.push_back("device@3.2/test/0");
        mDeviceNames.push_back("device@1.0/test/0");
        mDeviceNames.push_back("device@3.2/test/1");
    }

    virtual hardware::Return<Status> setCallbacks(
            const sp<provider::V2_4::ICameraProviderCallbacks>& callbacks) override {
        mCallbacks = callbacks;
        return hardware::Return<Status>(Status::OK);
    }

    using getVendorTags_cb = std::function<void(Status status,
            const hardware::hidl_vec<common::V1_0::VendorTagSection>& sections)>;
    virtual hardware::Return<void> getVendorTags(getVendorTags_cb _hidl_cb) override {
        hardware::hidl_vec<common::V1_0::VendorTagSection> sections;
        _hidl_cb(Status::OK, sections);
        return hardware::Void();
    }

    using getCameraIdList_cb = std::function<void(Status status,
            const hardware::hidl_vec<hardware::hidl_string>& cameraDeviceNames)>;
    virtual hardware::Return<void> getCameraIdList(getCameraIdList_cb _hidl_cb) override {
        _hidl_cb(Status::OK, mDeviceNames);
        return hardware::Void();
    }

    using getCameraDeviceInterface_V1_x_cb = std::function<void(Status status,
            const sp<device::V1_0::ICameraDevice>& device)>;
    virtual hardware::Return<void> getCameraDeviceInterface_V1_x(
            const hardware::hidl_string& cameraDeviceName,
            getCameraDeviceInterface_V1_x_cb _hidl_cb) override {
        (void) cameraDeviceName;
        _hidl_cb(Status::OK, nullptr);
        return hardware::Void();
    }

    using getCameraDeviceInterface_V3_x_cb = std::function<void(Status status,
            const sp<device::V3_2::ICameraDevice>& device)>;
    virtual hardware::Return<void> getCameraDeviceInterface_V3_x(
            const hardware::hidl_string& cameraDeviceName,
            getCameraDeviceInterface_V3_x_cb _hidl_cb) override {
        (void) cameraDeviceName;
        _hidl_cb(Status::OK, nullptr);
        return hardware::Void();
    }

};

/**
 * Simple test version of the interaction proxy, to use to inject onRegistered calls to the
 * CameraProviderManager
 */
struct TestInteractionProxy : public CameraProviderManager::ServiceInteractionProxy {
    sp<hidl::manager::V1_0::IServiceNotification> mManagerNotificationInterface;
    const sp<TestICameraProvider> mTestCameraProvider;

    TestInteractionProxy() :
            mTestCameraProvider(new TestICameraProvider()) {

    }
    std::string mLastRequestedServiceName;

    virtual ~TestInteractionProxy() {}

    virtual bool registerForNotifications(
            const std::string &serviceName,
            const sp<hidl::manager::V1_0::IServiceNotification> &notification) override {
        (void) serviceName;
        mManagerNotificationInterface = notification;
        return true;
    }

    virtual sp<hardware::camera::provider::V2_4::ICameraProvider> getService(
            const std::string &serviceName) override {
        mLastRequestedServiceName = serviceName;
        return mTestCameraProvider;
    }

};

TEST(CameraProviderManagerTest, InitializeTest) {

    status_t res;
    sp<CameraProviderManager> providerManager = new CameraProviderManager();
    TestInteractionProxy serviceProxy{};

    res = providerManager->initialize(&serviceProxy);
    ASSERT_EQ(res, OK) << "Unable to initialize provider manager";

    hardware::hidl_string legacyInstanceName = "legacy/0";
    ASSERT_EQ(serviceProxy.mLastRequestedServiceName, legacyInstanceName) <<
            "Legacy instance not requested from service manager";

    hardware::hidl_string testProviderFqInterfaceName =
            "android.hardware.camera.provider@2.4::ICameraProvider";
    hardware::hidl_string testProviderInstanceName = "test/0";
    serviceProxy.mManagerNotificationInterface->onRegistration(
            testProviderFqInterfaceName,
            testProviderInstanceName, false);

    ASSERT_EQ(serviceProxy.mLastRequestedServiceName, testProviderInstanceName) <<
            "Incorrect instance requested from service manager";
}
