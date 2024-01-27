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
#include <aidl/android/hardware/camera/device/BnCameraDevice.h>
#include <aidl/android/hardware/camera/provider/BnCameraProvider.h>
#include <android_companion_virtualdevice_flags.h>
#include <android/binder_auto_utils.h>
#include <android/binder_ibinder.h>
#include <android/binder_interface_utils.h>
#include <android/binder_libbinder.h>
#include <android/binder_manager.h>
#include <android/binder_parcel.h>
#include <android/hardware/camera/device/3.2/ICameraDeviceCallback.h>
#include <android/hardware/camera/device/3.2/ICameraDeviceSession.h>
#include <android/hidl/manager/1.0/IServiceManager.h>
#include <android/hidl/manager/1.0/IServiceNotification.h>
#include <binder/IServiceManager.h>
#include <camera_metadata_hidden.h>
#include <com_android_internal_camera_flags.h>
#include <flag_macros.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <hidl/HidlBinderSupport.h>
#include <utility>

using namespace android;
using namespace android::hardware::camera;
using ::aidl::android::hardware::camera::provider::ICameraProviderCallback;
using android::hardware::camera::common::V1_0::CameraMetadataType;
using android::hardware::camera::common::V1_0::Status;
using android::hardware::camera::common::V1_0::VendorTag;
using android::hardware::camera::common::V1_0::VendorTagSection;
using android::hardware::camera::device::V3_2::ICameraDeviceCallback;
using android::hardware::camera::device::V3_2::ICameraDeviceSession;
using android::hardware::camera::provider::V2_5::DeviceState;
using ::testing::ElementsAre;

namespace flags = com::android::internal::camera::flags;
namespace vd_flags = android::companion::virtualdevice::flags;

/**
 * Basic test implementation of a camera ver. 3.2 device interface
 */
struct TestDeviceInterface : public device::V3_2::ICameraDevice {
    std::vector<hardware::hidl_string> mDeviceNames;
    android::hardware::hidl_vec<uint8_t> mCharacteristics;

    TestDeviceInterface(std::vector<hardware::hidl_string> deviceNames,
            android::hardware::hidl_vec<uint8_t> chars) :
        mDeviceNames(deviceNames), mCharacteristics(chars) {}

    TestDeviceInterface(std::vector<hardware::hidl_string> deviceNames) :
        mDeviceNames(deviceNames) {}

    using getResourceCost_cb = std::function<void(
            hardware::camera::common::V1_0::Status status,
            const hardware::camera::common::V1_0::CameraResourceCost& resourceCost)>;
    virtual ::android::hardware::Return<void> getResourceCost(
            getResourceCost_cb _hidl_cb) override {
        hardware::camera::common::V1_0::CameraResourceCost resourceCost = {100,
                mDeviceNames};
        _hidl_cb(Status::OK, resourceCost);
        return hardware::Void();
    }

    using getCameraCharacteristics_cb = std::function<void(
            hardware::camera::common::V1_0::Status status,
            const hardware::hidl_vec<uint8_t>& cameraCharacteristics)>;
    hardware::Return<void> getCameraCharacteristics(
            getCameraCharacteristics_cb _hidl_cb) override {
        _hidl_cb(Status::OK, mCharacteristics);
        return hardware::Void();
    }

    hardware::Return<hardware::camera::common::V1_0::Status> setTorchMode(
            ::android::hardware::camera::common::V1_0::TorchMode) override {
        return Status::OK;
    }

    using open_cb = std::function<void(
            ::android::hardware::camera::common::V1_0::Status status,
             const ::android::sp<ICameraDeviceSession>& session)>;
    hardware::Return<void> open(
            const ::android::sp<ICameraDeviceCallback>&,
            open_cb _hidl_cb) override {
        sp<ICameraDeviceSession> deviceSession = nullptr;
        _hidl_cb(Status::OK, deviceSession);
        return hardware::Void();
    }

    hardware::Return<void> dumpState(
            const ::android::hardware::hidl_handle&) override {
        return hardware::Void();
    }
};

/**
 * Basic test implementation of a camera provider
 */
struct TestICameraProvider : virtual public provider::V2_5::ICameraProvider {
    sp<provider::V2_4::ICameraProviderCallback> mCallbacks;
    std::vector<hardware::hidl_string> mDeviceNames;
    sp<device::V3_2::ICameraDevice> mDeviceInterface;
    hardware::hidl_vec<common::V1_0::VendorTagSection> mVendorTagSections;

    // Whether to call a physical camera unavailable callback upon setCallback
    bool mHasPhysicalCameraUnavailableCallback;
    hardware::hidl_string mLogicalCameraId;
    hardware::hidl_string mUnavailablePhysicalCameraId;

    TestICameraProvider(const std::vector<hardware::hidl_string> &devices,
            const hardware::hidl_vec<common::V1_0::VendorTagSection> &vendorSection) :
        mDeviceNames(devices),
        mDeviceInterface(new TestDeviceInterface(devices)),
        mVendorTagSections (vendorSection),
        mHasPhysicalCameraUnavailableCallback(false) {}

    TestICameraProvider(const std::vector<hardware::hidl_string> &devices,
            const hardware::hidl_vec<common::V1_0::VendorTagSection> &vendorSection,
            android::hardware::hidl_vec<uint8_t> chars) :
        mDeviceNames(devices),
        mDeviceInterface(new TestDeviceInterface(devices, chars)),
        mVendorTagSections (vendorSection),
        mHasPhysicalCameraUnavailableCallback(false) {}

    TestICameraProvider(const std::vector<hardware::hidl_string> &devices,
            const hardware::hidl_vec<common::V1_0::VendorTagSection> &vendorSection,
            android::hardware::hidl_vec<uint8_t> chars,
            const hardware::hidl_string& logicalCameraId,
            const hardware::hidl_string& unavailablePhysicalCameraId) :
        mDeviceNames(devices),
        mDeviceInterface(new TestDeviceInterface(devices, chars)),
        mVendorTagSections (vendorSection),
        mHasPhysicalCameraUnavailableCallback(true),
        mLogicalCameraId(logicalCameraId),
        mUnavailablePhysicalCameraId(unavailablePhysicalCameraId) {}

    virtual hardware::Return<Status> setCallback(
            const sp<provider::V2_4::ICameraProviderCallback>& callbacks) override {
        mCalledCounter[SET_CALLBACK]++;
        mCallbacks = callbacks;
        if (mHasPhysicalCameraUnavailableCallback) {
            auto cast26 = provider::V2_6::ICameraProviderCallback::castFrom(callbacks);
            if (!cast26.isOk()) {
                ADD_FAILURE() << "Failed to cast ICameraProviderCallback to V2_6";
            } else {
                sp<provider::V2_6::ICameraProviderCallback> callback26 = cast26;
                if (callback26 == nullptr) {
                    ADD_FAILURE() << "V2_6::ICameraProviderCallback is null after conversion";
                } else {
                    callback26->physicalCameraDeviceStatusChange(mLogicalCameraId,
                            mUnavailablePhysicalCameraId,
                            android::hardware::camera::common::V1_0::CameraDeviceStatus::NOT_PRESENT);
                }
            }
        }
        return hardware::Return<Status>(Status::OK);
    }

    using getVendorTags_cb = std::function<void(Status status,
            const hardware::hidl_vec<common::V1_0::VendorTagSection>& sections)>;
    hardware::Return<void> getVendorTags(getVendorTags_cb _hidl_cb) override {
        mCalledCounter[GET_VENDOR_TAGS]++;
        _hidl_cb(Status::OK, mVendorTagSections);
        return hardware::Void();
    }

    using isSetTorchModeSupported_cb = std::function<void(
            ::android::hardware::camera::common::V1_0::Status status,
             bool support)>;
    virtual ::hardware::Return<void> isSetTorchModeSupported(
            isSetTorchModeSupported_cb _hidl_cb) override {
        mCalledCounter[IS_SET_TORCH_MODE_SUPPORTED]++;
        _hidl_cb(Status::OK, false);
        return hardware::Void();
    }

    using getCameraIdList_cb = std::function<void(Status status,
            const hardware::hidl_vec<hardware::hidl_string>& cameraDeviceNames)>;
    virtual hardware::Return<void> getCameraIdList(getCameraIdList_cb _hidl_cb) override {
        mCalledCounter[GET_CAMERA_ID_LIST]++;
        _hidl_cb(Status::OK, mDeviceNames);
        return hardware::Void();
    }

    using getCameraDeviceInterface_V1_x_cb = std::function<void(Status status,
            const sp<device::V1_0::ICameraDevice>& device)>;
    virtual hardware::Return<void> getCameraDeviceInterface_V1_x(
            [[maybe_unused]] const hardware::hidl_string& cameraDeviceName,
            getCameraDeviceInterface_V1_x_cb _hidl_cb) override {
        _hidl_cb(Status::OK, nullptr); //TODO: impl. of ver. 1.0 device interface
                                       //      otherwise enumeration will fail.
        return hardware::Void();
    }

    using getCameraDeviceInterface_V3_x_cb = std::function<void(Status status,
            const sp<device::V3_2::ICameraDevice>& device)>;
    virtual hardware::Return<void> getCameraDeviceInterface_V3_x(
            const hardware::hidl_string&,
            getCameraDeviceInterface_V3_x_cb _hidl_cb) override {
        _hidl_cb(Status::OK, mDeviceInterface);
        return hardware::Void();
    }

    virtual hardware::Return<void> notifyDeviceStateChange(
            hardware::hidl_bitfield<DeviceState> newState) override {
        mCalledCounter[NOTIFY_DEVICE_STATE]++;
        mCurrentState = newState;
        return hardware::Void();
    }

    virtual ::android::hardware::Return<bool> linkToDeath(
            const ::android::sp<::android::hardware::hidl_death_recipient>& recipient,
            uint64_t cookie) {
        if (mInitialDeathRecipient.get() == nullptr) {
            mInitialDeathRecipient =
                std::make_unique<::android::hardware::hidl_binder_death_recipient>(recipient,
                        cookie, this);
        }
        return true;
    }

    void signalInitialBinderDeathRecipient() {
        if (mInitialDeathRecipient.get() != nullptr) {
            mInitialDeathRecipient->binderDied(nullptr /*who*/);
        }
    }

    std::unique_ptr<::android::hardware::hidl_binder_death_recipient> mInitialDeathRecipient;

    enum MethodNames {
        SET_CALLBACK,
        GET_VENDOR_TAGS,
        IS_SET_TORCH_MODE_SUPPORTED,
        NOTIFY_DEVICE_STATE,
        GET_CAMERA_ID_LIST,

        METHOD_NAME_COUNT
    };
    int mCalledCounter[METHOD_NAME_COUNT] {0};

    hardware::hidl_bitfield<DeviceState> mCurrentState = 0xFFFFFFFF; // Unlikely to be a real state
};

struct TestAidlCameraDevice : public aidl::android::hardware::camera::device::BnCameraDevice {
    ::ndk::ScopedAStatus getCameraCharacteristics(
            ::aidl::android::hardware::camera::device::CameraMetadata*) override {
        return ndk::ScopedAStatus::ok();
    }
    ::ndk::ScopedAStatus getPhysicalCameraCharacteristics(
            const std::string&,
            ::aidl::android::hardware::camera::device::CameraMetadata*) override {
        return ndk::ScopedAStatus::ok();
    }
    ::ndk::ScopedAStatus getResourceCost(
            ::aidl::android::hardware::camera::common::CameraResourceCost* aidl_return) override {
        auto cost = ::aidl::android::hardware::camera::common::CameraResourceCost();
        aidl_return->resourceCost = 100;
        return ndk::ScopedAStatus::ok();
    }
    ::ndk::ScopedAStatus isStreamCombinationSupported(
            const ::aidl::android::hardware::camera::device::StreamConfiguration&, bool*) override {
        return ndk::ScopedAStatus::ok();
    }
    ::ndk::ScopedAStatus
    open(const std::shared_ptr<::aidl::android::hardware::camera::device::ICameraDeviceCallback>&,
         std::shared_ptr<::aidl::android::hardware::camera::device::ICameraDeviceSession>*)
            override {
        return ndk::ScopedAStatus::ok();
    }
    ::ndk::ScopedAStatus openInjectionSession(
            const std::shared_ptr<
                    ::aidl::android::hardware::camera::device::ICameraDeviceCallback>&,
            std::shared_ptr<::aidl::android::hardware::camera::device::ICameraInjectionSession>*)
            override {
        return ndk::ScopedAStatus::ok();
    }
    ::ndk::ScopedAStatus setTorchMode(bool) override { return ndk::ScopedAStatus::ok(); }
    ::ndk::ScopedAStatus turnOnTorchWithStrengthLevel(int32_t) override {
        return ndk::ScopedAStatus::ok();
    }
    ::ndk::ScopedAStatus getTorchStrengthLevel(int32_t*) override {
        return ndk::ScopedAStatus::ok();
    }
    ::ndk::ScopedAStatus constructDefaultRequestSettings(
            ::aidl::android::hardware::camera::device::RequestTemplate,
            ::aidl::android::hardware::camera::device::CameraMetadata*) override {
        return ndk::ScopedAStatus::ok();
    }
    ::ndk::ScopedAStatus isStreamCombinationWithSettingsSupported(
            const ::aidl::android::hardware::camera::device::StreamConfiguration&,
            bool*) override {
        return ndk::ScopedAStatus::ok();
    }

    ::ndk::ScopedAStatus getSessionCharacteristics(
        const ::aidl::android::hardware::camera::device::StreamConfiguration&,
        ::aidl::android::hardware::camera::device::CameraMetadata*) override {
        return ndk::ScopedAStatus::ok();
    }
};

/**
 * Basic test implementation of a AIDL camera provider
 */
class TestAidlICameraProvider : public aidl::android::hardware::camera::provider::BnCameraProvider {
  public:
    std::shared_ptr<ICameraProviderCallback> mCallback;
    std::vector<std::string> mDeviceNames;

    TestAidlICameraProvider(const std::vector<std::string>& deviceNames) {
        mDeviceNames = deviceNames;
    }

    ::ndk::ScopedAStatus setCallback(
            const std::shared_ptr<
                    ::aidl::android::hardware::camera::provider::ICameraProviderCallback>& callback)
            override {
        mCallback = callback;
        return ndk::ScopedAStatus::ok();
    }
    ::ndk::ScopedAStatus getVendorTags(
            std::vector<::aidl::android::hardware::camera::common::VendorTagSection>*) override {
        return ndk::ScopedAStatus::ok();
    }
    ::ndk::ScopedAStatus getCameraIdList(std::vector<std::string>* camera_list) override {
        ALOGW("getCameraIdList");
        for (size_t i = 0; i < mDeviceNames.size(); i++) {
            camera_list->push_back(mDeviceNames.at(i));
        }
        return ndk::ScopedAStatus::ok();
    }
    ::ndk::ScopedAStatus getCameraDeviceInterface(
            const std::string&,
            std::shared_ptr<::aidl::android::hardware::camera::device::ICameraDevice>* device)
            override {
        *device = ndk::SharedRefBase::make<TestAidlCameraDevice>();
        return ndk::ScopedAStatus::ok();
    }
    ::ndk::ScopedAStatus notifyDeviceStateChange(int64_t) override {
        return ndk::ScopedAStatus::ok();
    }
    ::ndk::ScopedAStatus getConcurrentCameraIds(
            std::vector<
                    ::aidl::android::hardware::camera::provider::ConcurrentCameraIdCombination>*)
            override {
        return ndk::ScopedAStatus::ok();
    }
    ::ndk::ScopedAStatus isConcurrentStreamCombinationSupported(
            const std::vector<
                    ::aidl::android::hardware::camera::provider::CameraIdAndStreamCombination>&,
            bool*) override {
        return ndk::ScopedAStatus::ok();
    }
};

/**
 * Simple test version of HidlServiceInteractionProxy, to use to inject onRegistered calls to the
 * CameraProviderManager
 */
struct TestHidlInteractionProxy : public CameraProviderManager::HidlServiceInteractionProxy {
    sp<hidl::manager::V1_0::IServiceNotification> mManagerNotificationInterface;
    sp<TestICameraProvider> mTestCameraProvider;

    TestHidlInteractionProxy() {}

    void setProvider(sp<TestICameraProvider> provider) {
        mTestCameraProvider = provider;
    }

    std::vector<std::string> mLastRequestedServiceNames;

    virtual ~TestHidlInteractionProxy() {}

    virtual bool registerForNotifications(
            [[maybe_unused]] const std::string &serviceName,
            const sp<hidl::manager::V1_0::IServiceNotification> &notification) override {
        mManagerNotificationInterface = notification;
        return true;
    }

    virtual sp<hardware::camera::provider::V2_4::ICameraProvider> tryGetService(
            const std::string &serviceName) override {
        // If no provider has been given, act like the HAL isn't available and return null.
        if (mTestCameraProvider == nullptr) return nullptr;
        return getService(serviceName);
    }

    virtual sp<hardware::camera::provider::V2_4::ICameraProvider> getService(
            const std::string &serviceName) override {
        // If no provider has been given, fail; in reality, getService would
        // block for HALs that don't start correctly, so we should never use
        // getService when we don't have a valid HAL running
        if (mTestCameraProvider == nullptr) {
            ADD_FAILURE() << "getService called with no valid provider; would block indefinitely";
            // Real getService would block, but that's bad in unit tests. So
            // just record an error and return nullptr
            return nullptr;
        }
        mLastRequestedServiceNames.push_back(serviceName);
        return mTestCameraProvider;
    }

    virtual hardware::hidl_vec<hardware::hidl_string> listServices() override {
        // Always provide a list even if there's no actual provider yet, to
        // simulate stuck HAL situations as well
        hardware::hidl_vec<hardware::hidl_string> ret = {"test/0"};
        return ret;
    }
};

/**
 * Simple test version of AidlServiceInteractionProxy, to use to inject onRegistered calls to the
 * CameraProviderManager
 */
struct TestAidlInteractionProxy : public CameraProviderManager::AidlServiceInteractionProxy {
    std::shared_ptr<TestAidlICameraProvider> mTestAidlCameraProvider;

    TestAidlInteractionProxy() {}

    void setProvider(std::shared_ptr<TestAidlICameraProvider> provider) {
        mTestAidlCameraProvider = provider;
    }

    std::vector<std::string> mLastRequestedServiceNames;

    virtual ~TestAidlInteractionProxy() {}

    virtual std::shared_ptr<aidl::android::hardware::camera::provider::ICameraProvider>
            getService(const std::string& serviceName) override {
        if (!flags::delay_lazy_hal_instantiation()) {
            return mTestAidlCameraProvider;
        }

        // If no provider has been given, fail; in reality, getService would
        // block for HALs that don't start correctly, so we should never use
        // getService when we don't have a valid HAL running
        if (mTestAidlCameraProvider == nullptr) {
            ADD_FAILURE() << __FUNCTION__ << "called with no valid provider;"
                          << " would block indefinitely";
            // Real getService would block, but that's bad in unit tests. So
            // just record an error and return nullptr
            return nullptr;
        }
        mLastRequestedServiceNames.push_back(serviceName);
        return mTestAidlCameraProvider;
    }

    virtual std::shared_ptr<aidl::android::hardware::camera::provider::ICameraProvider>
    tryGetService(const std::string&) override {
        return mTestAidlCameraProvider;
    }
};

struct TestStatusListener : public CameraProviderManager::StatusListener {
    int mPhysicalCameraStatusChangeCount = 0;

    ~TestStatusListener() {}

    void onDeviceStatusChanged(const std::string &,
            CameraDeviceStatus) override {}
    void onDeviceStatusChanged(const std::string &, const std::string &,
            CameraDeviceStatus) override {
        mPhysicalCameraStatusChangeCount++;
    }
    void onTorchStatusChanged(const std::string &,
            TorchModeStatus) override {}
    void onTorchStatusChanged(const std::string &,
            TorchModeStatus, SystemCameraKind) override {}
    void onNewProviderRegistered() override {}
};

TEST(CameraProviderManagerTest, InitializeDynamicDepthTest) {
    std::vector<hardware::hidl_string> deviceNames;
    deviceNames.push_back("device@3.2/test/0");
    hardware::hidl_vec<common::V1_0::VendorTagSection> vendorSection;
    status_t res;
    sp<CameraProviderManager> providerManager = new CameraProviderManager();
    sp<TestStatusListener> statusListener = new TestStatusListener();
    TestHidlInteractionProxy serviceProxy;

    android::hardware::hidl_vec<uint8_t> chars;
    CameraMetadata meta;
    int32_t charKeys[] = { ANDROID_DEPTH_DEPTH_IS_EXCLUSIVE,
            ANDROID_DEPTH_AVAILABLE_DEPTH_STREAM_CONFIGURATIONS };
    meta.update(ANDROID_REQUEST_AVAILABLE_CHARACTERISTICS_KEYS, charKeys,
            sizeof(charKeys) / sizeof(charKeys[0]));
    uint8_t depthIsExclusive = ANDROID_DEPTH_DEPTH_IS_EXCLUSIVE_FALSE;
    meta.update(ANDROID_DEPTH_DEPTH_IS_EXCLUSIVE, &depthIsExclusive, 1);
    int32_t sizes[] = { HAL_PIXEL_FORMAT_BLOB,
            640, 480, ANDROID_SCALER_AVAILABLE_STREAM_CONFIGURATIONS_OUTPUT };
    meta.update(ANDROID_SCALER_AVAILABLE_STREAM_CONFIGURATIONS, sizes,
            sizeof(sizes) / sizeof(sizes[0]));
    sizes[0] = HAL_PIXEL_FORMAT_Y16;
    meta.update(ANDROID_DEPTH_AVAILABLE_DEPTH_STREAM_CONFIGURATIONS, sizes,
            sizeof(sizes) / sizeof(sizes[0]));
    int64_t durations[] = { HAL_PIXEL_FORMAT_BLOB, 640, 480, 0 };
    meta.update(ANDROID_SCALER_AVAILABLE_MIN_FRAME_DURATIONS, durations,
            sizeof(durations) / sizeof(durations[0]));
    meta.update(ANDROID_SCALER_AVAILABLE_STALL_DURATIONS, durations,
            sizeof(durations) / sizeof(durations[0]));
    durations[0]= HAL_PIXEL_FORMAT_Y16;
    meta.update(ANDROID_DEPTH_AVAILABLE_DEPTH_MIN_FRAME_DURATIONS, durations,
            sizeof(durations) / sizeof(durations[0]));
    meta.update(ANDROID_DEPTH_AVAILABLE_DEPTH_STALL_DURATIONS, durations,
            sizeof(durations) / sizeof(durations[0]));
    camera_metadata_t* metaBuffer = const_cast<camera_metadata_t*>(meta.getAndLock());
    chars.setToExternal(reinterpret_cast<uint8_t*>(metaBuffer),
            get_camera_metadata_size(metaBuffer));

    sp<TestICameraProvider> provider =  new TestICameraProvider(deviceNames,
            vendorSection, chars);
    serviceProxy.setProvider(provider);

    res = providerManager->initialize(statusListener, &serviceProxy);
    ASSERT_EQ(res, OK) << "Unable to initialize provider manager";
}

TEST(CameraProviderManagerTest, InitializeTest) {
    std::vector<hardware::hidl_string> deviceNames;
    deviceNames.push_back("device@3.2/test/0");
    deviceNames.push_back("device@1.0/test/0");
    deviceNames.push_back("device@3.2/test/1");
    hardware::hidl_vec<common::V1_0::VendorTagSection> vendorSection;
    status_t res;
    sp<CameraProviderManager> providerManager = new CameraProviderManager();
    sp<TestStatusListener> statusListener = new TestStatusListener();
    TestHidlInteractionProxy serviceProxy;
    sp<TestICameraProvider> provider =  new TestICameraProvider(deviceNames,
            vendorSection);
    serviceProxy.setProvider(provider);

    int numProviders = static_cast<int>(serviceProxy.listServices().size());

    res = providerManager->initialize(statusListener, &serviceProxy);
    ASSERT_EQ(res, OK) << "Unable to initialize provider manager";
    // Check that both "legacy" and "external" providers (really the same object) are called
    // once for all the init methods
    EXPECT_EQ(provider->mCalledCounter[TestICameraProvider::SET_CALLBACK], numProviders) <<
            "Only one call to setCallback per provider expected during init";
    EXPECT_EQ(provider->mCalledCounter[TestICameraProvider::GET_VENDOR_TAGS], numProviders) <<
            "Only one call to getVendorTags per provider expected during init";
    EXPECT_EQ(provider->mCalledCounter[TestICameraProvider::IS_SET_TORCH_MODE_SUPPORTED],
            numProviders) <<
            "Only one call to isSetTorchModeSupported per provider expected during init";
    EXPECT_EQ(provider->mCalledCounter[TestICameraProvider::GET_CAMERA_ID_LIST], numProviders) <<
            "Only one call to getCameraIdList per provider expected during init";
    EXPECT_EQ(provider->mCalledCounter[TestICameraProvider::NOTIFY_DEVICE_STATE], numProviders) <<
            "Only one call to notifyDeviceState per provider expected during init";

    hardware::hidl_string testProviderFqInterfaceName =
            "android.hardware.camera.provider@2.4::ICameraProvider";
    hardware::hidl_string testProviderInstanceName = "test/0";
    serviceProxy.mManagerNotificationInterface->onRegistration(
            testProviderFqInterfaceName,
            testProviderInstanceName, false);

    ASSERT_EQ(serviceProxy.mLastRequestedServiceNames.back(), testProviderInstanceName) <<
            "Incorrect instance requested from service manager";
}

TEST(CameraProviderManagerTest, MultipleVendorTagTest) {
    hardware::hidl_string sectionName = "VendorTestSection";
    hardware::hidl_string tagName = "VendorTestTag";
    uint32_t tagId = VENDOR_SECTION << 16;
    hardware::hidl_vec<common::V1_0::VendorTagSection> vendorSection;
    CameraMetadataType tagType = CameraMetadataType::BYTE;
    vendorSection.resize(1);
    vendorSection[0].sectionName = sectionName;
    vendorSection[0].tags.resize(1);
    vendorSection[0].tags[0].tagId = tagId;
    vendorSection[0].tags[0].tagName = tagName;
    vendorSection[0].tags[0].tagType = tagType;
    std::vector<hardware::hidl_string> deviceNames = {"device@3.2/test/0"};

    sp<CameraProviderManager> providerManager = new CameraProviderManager();
    sp<TestStatusListener> statusListener = new TestStatusListener();
    TestHidlInteractionProxy serviceProxy;

    sp<TestICameraProvider> provider =  new TestICameraProvider(deviceNames,
            vendorSection);
    serviceProxy.setProvider(provider);

    auto res = providerManager->initialize(statusListener, &serviceProxy);
    ASSERT_EQ(res, OK) << "Unable to initialize provider manager";

    hardware::hidl_string testProviderInstanceName = "test/0";
    hardware::hidl_string testProviderFqInterfaceName =
            "android.hardware.camera.provider@2.4::ICameraProvider";
    serviceProxy.mManagerNotificationInterface->onRegistration(
            testProviderFqInterfaceName, testProviderInstanceName, false);
    ASSERT_EQ(serviceProxy.mLastRequestedServiceNames.back(), testProviderInstanceName) <<
            "Incorrect instance requested from service manager";

    hardware::hidl_string sectionNameSecond = "SecondVendorTestSection";
    hardware::hidl_string secondTagName = "SecondVendorTestTag";
    CameraMetadataType secondTagType = CameraMetadataType::DOUBLE;
    vendorSection[0].sectionName = sectionNameSecond;
    vendorSection[0].tags[0].tagId = tagId;
    vendorSection[0].tags[0].tagName = secondTagName;
    vendorSection[0].tags[0].tagType = secondTagType;
    deviceNames = {"device@3.2/test2/1"};

    sp<TestICameraProvider> secondProvider =  new TestICameraProvider(
            deviceNames, vendorSection);
    serviceProxy.setProvider(secondProvider);
    hardware::hidl_string testProviderSecondInstanceName = "test2/0";
    serviceProxy.mManagerNotificationInterface->onRegistration(
            testProviderFqInterfaceName, testProviderSecondInstanceName, false);
    ASSERT_EQ(serviceProxy.mLastRequestedServiceNames.back(),
              testProviderSecondInstanceName) <<
            "Incorrect instance requested from service manager";

    ASSERT_EQ(NO_ERROR , providerManager->setUpVendorTags());
    sp<VendorTagDescriptorCache> vendorCache =
            VendorTagDescriptorCache::getGlobalVendorTagCache();
    ASSERT_NE(nullptr, vendorCache.get());

    metadata_vendor_id_t vendorId = std::hash<std::string> {} (
            testProviderInstanceName.c_str());
    metadata_vendor_id_t vendorIdSecond = std::hash<std::string> {} (
            testProviderSecondInstanceName.c_str());

    hardware::hidl_string resultTag = vendorCache->getTagName(tagId, vendorId);
    ASSERT_EQ(resultTag, tagName);

    resultTag = vendorCache->getTagName(tagId, vendorIdSecond);
    ASSERT_EQ(resultTag, secondTagName);

    // Check whether we can create two separate CameraMetadata instances
    // using different tag vendor vendors.
    camera_metadata *metaBuffer = allocate_camera_metadata(10, 20);
    ASSERT_NE(nullptr, metaBuffer);
    set_camera_metadata_vendor_id(metaBuffer, vendorId);
    CameraMetadata metadata(metaBuffer);

    uint8_t byteVal = 10;
    ASSERT_TRUE(metadata.isEmpty());
    ASSERT_EQ(OK, metadata.update(tagId, &byteVal, 1));
    ASSERT_FALSE(metadata.isEmpty());
    ASSERT_TRUE(metadata.exists(tagId));

    metaBuffer = allocate_camera_metadata(10, 20);
    ASSERT_NE(nullptr, metaBuffer);
    set_camera_metadata_vendor_id(metaBuffer, vendorIdSecond);
    CameraMetadata secondMetadata(metaBuffer);

    ASSERT_TRUE(secondMetadata.isEmpty());
    double doubleVal = 1.0f;
    ASSERT_EQ(OK, secondMetadata.update(tagId, &doubleVal, 1));
    ASSERT_FALSE(secondMetadata.isEmpty());
    ASSERT_TRUE(secondMetadata.exists(tagId));

    // Check whether CameraMetadata copying works as expected
    CameraMetadata metadataCopy(metadata);
    ASSERT_FALSE(metadataCopy.isEmpty());
    ASSERT_TRUE(metadataCopy.exists(tagId));
    ASSERT_EQ(OK, metadataCopy.update(tagId, &byteVal, 1));
    ASSERT_TRUE(metadataCopy.exists(tagId));

    // Check whether values are as expected
    camera_metadata_entry_t entry = metadata.find(tagId);
    ASSERT_EQ(1u, entry.count);
    ASSERT_EQ(byteVal, entry.data.u8[0]);
    entry = secondMetadata.find(tagId);
    ASSERT_EQ(1u, entry.count);
    ASSERT_EQ(doubleVal, entry.data.d[0]);

    // Swap and erase
    secondMetadata.swap(metadataCopy);
    ASSERT_TRUE(metadataCopy.exists(tagId));
    ASSERT_TRUE(secondMetadata.exists(tagId));
    ASSERT_EQ(OK, secondMetadata.erase(tagId));
    ASSERT_TRUE(secondMetadata.isEmpty());
    doubleVal = 0.0f;
    ASSERT_EQ(OK, metadataCopy.update(tagId, &doubleVal, 1));
    entry = metadataCopy.find(tagId);
    ASSERT_EQ(1u, entry.count);
    ASSERT_EQ(doubleVal, entry.data.d[0]);

    // Append
    uint8_t sceneMode = ANDROID_CONTROL_SCENE_MODE_ACTION;
    secondMetadata.update(ANDROID_CONTROL_SCENE_MODE, &sceneMode, 1);
    // Append from two different vendor tag providers is not supported!
    ASSERT_NE(OK, metadataCopy.append(secondMetadata));
    ASSERT_EQ(OK, metadataCopy.erase(tagId));
    metadataCopy.update(ANDROID_CONTROL_SCENE_MODE, &sceneMode, 1);
    // However appending from same vendor tag provider should be fine
    ASSERT_EQ(OK, metadata.append(secondMetadata));
    // Append from a metadata without vendor tag provider should be supported
    CameraMetadata regularMetadata(10, 20);
    uint8_t controlMode = ANDROID_CONTROL_MODE_AUTO;
    regularMetadata.update(ANDROID_CONTROL_MODE, &controlMode, 1);
    ASSERT_EQ(OK, secondMetadata.append(regularMetadata));
    ASSERT_EQ(2u, secondMetadata.entryCount());
    ASSERT_EQ(2u, metadata.entryCount());

    // Dump
    metadata.dump(1, 2);
    metadataCopy.dump(1, 2);
    secondMetadata.dump(1, 2);
}

TEST(CameraProviderManagerTest, NotifyStateChangeTest) {
    std::vector<hardware::hidl_string> deviceNames {
        "device@3.2/test/0",
        "device@1.0/test/0",
        "device@3.2/test/1"};

    hardware::hidl_vec<common::V1_0::VendorTagSection> vendorSection;
    status_t res;
    sp<CameraProviderManager> providerManager = new CameraProviderManager();
    sp<TestStatusListener> statusListener = new TestStatusListener();
    TestHidlInteractionProxy serviceProxy;
    sp<TestICameraProvider> provider =  new TestICameraProvider(deviceNames,
            vendorSection);
    serviceProxy.setProvider(provider);

    res = providerManager->initialize(statusListener, &serviceProxy);
    ASSERT_EQ(res, OK) << "Unable to initialize provider manager";

    ASSERT_EQ(provider->mCurrentState,
            static_cast<hardware::hidl_bitfield<DeviceState>>(DeviceState::NORMAL))
            << "Initial device state not set";

    res = providerManager->notifyDeviceStateChange(
        static_cast<hardware::hidl_bitfield<DeviceState>>(DeviceState::FOLDED));

    ASSERT_EQ(res, OK) << "Unable to call notifyDeviceStateChange";
    ASSERT_EQ(provider->mCurrentState,
            static_cast<hardware::hidl_bitfield<DeviceState>>(DeviceState::FOLDED))
            << "Unable to change device state";

}

// Test that CameraProviderManager doesn't get stuck when the camera HAL isn't really working
TEST(CameraProviderManagerTest, BadHalStartupTest) {

    std::vector<hardware::hidl_string> deviceNames;
    deviceNames.push_back("device@3.2/test/0");
    deviceNames.push_back("device@1.0/test/0");
    deviceNames.push_back("device@3.2/test/1");
    hardware::hidl_vec<common::V1_0::VendorTagSection> vendorSection;
    status_t res;

    sp<CameraProviderManager> providerManager = new CameraProviderManager();
    sp<TestStatusListener> statusListener = new TestStatusListener();
    TestHidlInteractionProxy serviceProxy;
    sp<TestICameraProvider> provider =  new TestICameraProvider(deviceNames,
            vendorSection);

    // Not setting up provider in the service proxy yet, to test cases where a
    // HAL isn't starting right
    res = providerManager->initialize(statusListener, &serviceProxy);
    ASSERT_EQ(res, OK) << "Unable to initialize provider manager";

    // Now set up provider and trigger a registration
    serviceProxy.setProvider(provider);
    int numProviders = static_cast<int>(serviceProxy.listServices().size());

    hardware::hidl_string testProviderFqInterfaceName =
            "android.hardware.camera.provider@2.4::ICameraProvider";
    hardware::hidl_string testProviderInstanceName = "test/0";
    serviceProxy.mManagerNotificationInterface->onRegistration(
            testProviderFqInterfaceName,
            testProviderInstanceName, false);

    // Check that new provider is called once for all the init methods
    EXPECT_EQ(provider->mCalledCounter[TestICameraProvider::SET_CALLBACK], numProviders) <<
            "Only one call to setCallback per provider expected during register";
    EXPECT_EQ(provider->mCalledCounter[TestICameraProvider::GET_VENDOR_TAGS], numProviders) <<
            "Only one call to getVendorTags per provider expected during register";
    EXPECT_EQ(provider->mCalledCounter[TestICameraProvider::IS_SET_TORCH_MODE_SUPPORTED],
            numProviders) <<
            "Only one call to isSetTorchModeSupported per provider expected during init";
    EXPECT_EQ(provider->mCalledCounter[TestICameraProvider::GET_CAMERA_ID_LIST], numProviders) <<
            "Only one call to getCameraIdList per provider expected during init";
    EXPECT_EQ(provider->mCalledCounter[TestICameraProvider::NOTIFY_DEVICE_STATE], numProviders) <<
            "Only one call to notifyDeviceState per provider expected during init";

    ASSERT_EQ(serviceProxy.mLastRequestedServiceNames.back(), testProviderInstanceName) <<
            "Incorrect instance requested from service manager";
}

// Test that CameraProviderManager can handle races between provider death notifications and
// provider registration callbacks
TEST(CameraProviderManagerTest, BinderDeathRegistrationRaceTest) {

    std::vector<hardware::hidl_string> deviceNames;
    deviceNames.push_back("device@3.2/test/0");
    deviceNames.push_back("device@3.2/test/1");
    hardware::hidl_vec<common::V1_0::VendorTagSection> vendorSection;
    status_t res;

    sp<CameraProviderManager> providerManager = new CameraProviderManager();
    sp<TestStatusListener> statusListener = new TestStatusListener();
    TestHidlInteractionProxy serviceProxy;
    sp<TestICameraProvider> provider =  new TestICameraProvider(deviceNames,
            vendorSection);

    // Not setting up provider in the service proxy yet, to test cases where a
    // HAL isn't starting right
    res = providerManager->initialize(statusListener, &serviceProxy);
    ASSERT_EQ(res, OK) << "Unable to initialize provider manager";

    // Now set up provider and trigger a registration
    serviceProxy.setProvider(provider);

    hardware::hidl_string testProviderFqInterfaceName =
            "android.hardware.camera.provider@2.4::ICameraProvider";
    hardware::hidl_string testProviderInstanceName = "test/0";
    serviceProxy.mManagerNotificationInterface->onRegistration(
            testProviderFqInterfaceName,
            testProviderInstanceName, false);

    // Simulate artificial delay of the registration callback which arrives before the
    // death notification
    serviceProxy.mManagerNotificationInterface->onRegistration(
            testProviderFqInterfaceName,
            testProviderInstanceName, false);

    provider->signalInitialBinderDeathRecipient();

    auto deviceCount = static_cast<unsigned> (providerManager->getCameraCount().second);
    ASSERT_EQ(deviceCount, deviceNames.size()) <<
            "Unexpected amount of camera devices";
}

// Test that CameraProviderManager does not trigger
// onDeviceStatusChanged(NOT_PRESENT) for physical camera before initialize()
// returns.
TEST(CameraProviderManagerTest, PhysicalCameraAvailabilityCallbackRaceTest) {
    std::vector<hardware::hidl_string> deviceNames;
    deviceNames.push_back("device@3.2/test/0");
    hardware::hidl_vec<common::V1_0::VendorTagSection> vendorSection;

    sp<CameraProviderManager> providerManager = new CameraProviderManager();
    sp<TestStatusListener> statusListener = new TestStatusListener();
    TestHidlInteractionProxy serviceProxy;

    android::hardware::hidl_vec<uint8_t> chars;
    CameraMetadata meta;
    int32_t charKeys[] = { ANDROID_REQUEST_AVAILABLE_CAPABILITIES };
    meta.update(ANDROID_REQUEST_AVAILABLE_CHARACTERISTICS_KEYS, charKeys,
            sizeof(charKeys) / sizeof(charKeys[0]));
    uint8_t capabilities[] = { ANDROID_REQUEST_AVAILABLE_CAPABILITIES_LOGICAL_MULTI_CAMERA };
    meta.update(ANDROID_REQUEST_AVAILABLE_CAPABILITIES, capabilities,
            sizeof(capabilities)/sizeof(capabilities[0]));
    uint8_t physicalCameraIds[] = { '2', '\0', '3', '\0' };
    meta.update(ANDROID_LOGICAL_MULTI_CAMERA_PHYSICAL_IDS, physicalCameraIds,
            sizeof(physicalCameraIds)/sizeof(physicalCameraIds[0]));
    camera_metadata_t* metaBuffer = const_cast<camera_metadata_t*>(meta.getAndLock());
    chars.setToExternal(reinterpret_cast<uint8_t*>(metaBuffer),
            get_camera_metadata_size(metaBuffer));

    sp<TestICameraProvider> provider = new TestICameraProvider(deviceNames,
            vendorSection, chars, "device@3.2/test/0", "2");
    serviceProxy.setProvider(provider);

    status_t res = providerManager->initialize(statusListener, &serviceProxy);
    ASSERT_EQ(res, OK) << "Unable to initialize provider manager";

    ASSERT_EQ(statusListener->mPhysicalCameraStatusChangeCount, 0)
            << "Unexpected physical camera status change callback upon provider init.";

    std::unordered_map<std::string, std::set<std::string>> unavailablePhysicalIds;
    auto cameraIds = providerManager->getCameraDeviceIds(&unavailablePhysicalIds);
    ASSERT_TRUE(unavailablePhysicalIds.count("0") > 0 && unavailablePhysicalIds["0"].count("2") > 0)
        << "Unavailable physical camera Ids not set properly.";
}
TEST_WITH_FLAGS(CameraProviderManagerTest, AidlVirtualCameraProviderDiscovered,
                REQUIRES_FLAGS_ENABLED(ACONFIG_FLAG(vd_flags, virtual_camera_service_discovery))) {
    sp<CameraProviderManager> providerManager = new CameraProviderManager();
    sp<TestStatusListener> statusListener = new TestStatusListener();
    TestAidlInteractionProxy aidlServiceProxy;
    TestHidlInteractionProxy hidlServiceProxy;

    status_t res = providerManager->initialize(statusListener,
                                               &hidlServiceProxy, &aidlServiceProxy);
    ASSERT_EQ(res, OK) << "Unable to initialize provider manager";

    std::vector<std::string> cameraList = {"device@1.1/virtual/123"};

    std::shared_ptr<TestAidlICameraProvider> aidlProvider =
            ndk::SharedRefBase::make<TestAidlICameraProvider>(cameraList);
    ndk::SpAIBinder spBinder = aidlProvider->asBinder();
    AIBinder* aiBinder = spBinder.get();
    aidlServiceProxy.setProvider(aidlProvider);
    providerManager->onServiceRegistration(
            String16("android.hardware.camera.provider.ICameraProvider/virtual/0"),
            AIBinder_toPlatformBinder(aiBinder));

    std::unordered_map<std::string, std::set<std::string>> unavailableDeviceIds;
    auto cameraIds = providerManager->getCameraDeviceIds(&unavailableDeviceIds);

    EXPECT_THAT(cameraIds, ElementsAre("123"));
}

TEST_WITH_FLAGS(CameraProviderManagerTest, AidlVirtualCameraProviderDiscoveredOnInit,
                REQUIRES_FLAGS_ENABLED(ACONFIG_FLAG(vd_flags, virtual_camera_service_discovery))) {
    sp<CameraProviderManager> providerManager = new CameraProviderManager();
    sp<TestStatusListener> statusListener = new TestStatusListener();
    TestAidlInteractionProxy aidlServiceProxy;
    TestHidlInteractionProxy hidlServiceProxy;

    std::vector<std::string> cameraList = {"device@1.1/virtual/123"};

    std::shared_ptr<TestAidlICameraProvider> aidlProvider =
            ndk::SharedRefBase::make<TestAidlICameraProvider>(cameraList);
    aidlServiceProxy.setProvider(aidlProvider);

    status_t res = providerManager->initialize(statusListener,
                                               &hidlServiceProxy, &aidlServiceProxy);
    ASSERT_EQ(res, OK) << "Unable to initialize provider manager";

    std::unordered_map<std::string, std::set<std::string>> unavailableDeviceIds;
    std::vector<std::string> cameraIds = providerManager->getCameraDeviceIds(&unavailableDeviceIds);

    EXPECT_THAT(cameraIds, ElementsAre("123"));
}
