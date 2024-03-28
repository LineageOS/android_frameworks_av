/*
 * Copyright (C) 2021 The Android Open Source Project
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

#ifndef ANDROID_SERVERS_CAMERA_CAMERAPROVIDER_AIDLPROVIDERINFOH
#define ANDROID_SERVERS_CAMERA_CAMERAPROVIDER_AIDLPROVIDERINFOH

#include "common/CameraProviderManager.h"

#include <aidl/android/hardware/camera/common/Status.h>
#include <aidl/android/hardware/camera/provider/BnCameraProviderCallback.h>
#include <aidl/android/hardware/camera/device/ICameraDevice.h>

namespace android {

struct AidlProviderInfo : public CameraProviderManager::ProviderInfo {
    // Current overall Android device physical status
    int64_t mDeviceState;

    // This pointer is used to keep a reference to the ICameraProvider that was last accessed.
    std::weak_ptr<aidl::android::hardware::camera::provider::ICameraProvider> mActiveInterface;

    std::shared_ptr<aidl::android::hardware::camera::provider::ICameraProvider> mSavedInterface;

    AidlProviderInfo(
            const std::string &providerName,
            const std::string &providerInstance,
            CameraProviderManager *manager);

    static status_t mapToStatusT(const ndk::ScopedAStatus& s);

    // Start camera device interface, start the camera provider process for lazy
    // hals, if needed
    status_t initializeAidlProvider(
        std::shared_ptr<aidl::android::hardware::camera::provider::ICameraProvider>& interface,
        int64_t currentDeviceState);

    static void binderDied(void *cookie);

    virtual IPCTransport getIPCTransport() const override {return IPCTransport::AIDL;}

    const std::shared_ptr<aidl::android::hardware::camera::provider::ICameraProvider>
    startProviderInterface();

    virtual status_t setUpVendorTags() override;
    virtual status_t notifyDeviceStateChange(int64_t newDeviceState) override;

    virtual bool successfullyStartedProviderInterface() override;

    virtual int64_t getDeviceState() override { return mDeviceState; };

    /**
     * Query the camera provider for concurrent stream configuration support
     */
    virtual status_t isConcurrentSessionConfigurationSupported(
        const std::vector<CameraIdAndSessionConfiguration> &cameraIdsAndSessionConfigs,
        const std::set<std::string>& perfClassPrimaryCameraIds,
        int targetSdkVersion, bool *isSupported) override;

    std::shared_ptr<aidl::android::hardware::camera::device::ICameraDevice>
            startDeviceInterface(const std::string &deviceName);

    // AIDL ICameraProviderCallback interface - these lock the parent
    // mInterfaceMutex

    ::ndk::ScopedAStatus cameraDeviceStatusChange(const std::string& cameraDeviceName,
            ::aidl::android::hardware::camera::common::CameraDeviceStatus newStatus);

    ::ndk::ScopedAStatus torchModeStatusChange(const std::string& cameraDeviceName,
            ::aidl::android::hardware::camera::common::TorchModeStatus newStatus);

    ::ndk::ScopedAStatus physicalCameraDeviceStatusChange(
            const std::string& cameraDeviceName,
            const std::string& physicalCameraDeviceName,
            ::aidl::android::hardware::camera::common::CameraDeviceStatus newStatus);

    struct AidlProviderCallbacks :
            public aidl::android::hardware::camera::provider::BnCameraProviderCallback {
        AidlProviderCallbacks(wp<AidlProviderInfo> parent) : mParent(parent) { }
        virtual ::ndk::ScopedAStatus cameraDeviceStatusChange(const std::string& cameraDeviceName,
                ::aidl::android::hardware::camera::common::CameraDeviceStatus newStatus) override;

        virtual ::ndk::ScopedAStatus torchModeStatusChange(const std::string& cameraDeviceName,
                ::aidl::android::hardware::camera::common::TorchModeStatus newStatus) override;

        virtual ::ndk::ScopedAStatus physicalCameraDeviceStatusChange(
                const std::string& cameraDeviceName,
                const std::string& physicalCameraDeviceName,
                ::aidl::android::hardware::camera::common::CameraDeviceStatus newStatus) override;

       private:
        wp<AidlProviderInfo> mParent = nullptr;

    };

    struct AidlDeviceInfo3 : public CameraProviderManager::ProviderInfo::DeviceInfo3 {

        std::shared_ptr<aidl::android::hardware::camera::device::ICameraDevice>
                mSavedInterface = nullptr;

        AidlDeviceInfo3(const std::string& , const metadata_vendor_id_t ,
                const std::string &, uint16_t ,
                const CameraResourceCost& ,
                sp<ProviderInfo> ,
                const std::vector<std::string>& ,
                std::shared_ptr<aidl::android::hardware::camera::device::ICameraDevice>);

        ~AidlDeviceInfo3() {}

        virtual status_t setTorchMode(bool enabled) override;
        virtual status_t turnOnTorchWithStrengthLevel(int32_t torchStrength) override;
        virtual status_t getTorchStrengthLevel(int32_t *torchStrength) override;

        virtual status_t dumpState(int fd) override;

        virtual status_t isSessionConfigurationSupported(
                const SessionConfiguration &/*configuration*/,
                bool overrideForPerfClass, bool checkSessionParams,
                bool *status/*status*/);

        virtual status_t createDefaultRequest(
                    camera3::camera_request_template_t templateId,
                    CameraMetadata* metadata) override;

        virtual status_t getSessionCharacteristics(
                const SessionConfiguration &/*configuration*/,
                bool overrideForPerfClass, camera3::metadataGetter /*getMetadata*/,
                CameraMetadata *sessionCharacteristics /*sessionCharacteristics*/);

        std::shared_ptr<aidl::android::hardware::camera::device::ICameraDevice>
                startDeviceInterface();
        std::vector<int32_t> mAdditionalKeysForFeatureQuery;
    };

 private:

    // Helper for initializeDeviceInfo to use the right CameraProvider get method.
    virtual std::unique_ptr<DeviceInfo> initializeDeviceInfo(const std::string &,
            const metadata_vendor_id_t , const std::string &,
            uint16_t ) override;

    virtual status_t reCacheConcurrentStreamingCameraIdsLocked() override;

    //Expects to have mLock locked

    status_t getConcurrentCameraIdsInternalLocked(
        std::shared_ptr<aidl::android::hardware::camera::provider::ICameraProvider> &interface);

    //expects to have mManager->mInterfaceMutex locked

    status_t convertToAidlHALStreamCombinationAndCameraIdsLocked(
        const std::vector<CameraIdAndSessionConfiguration> &cameraIdsAndSessionConfigs,
        const std::set<std::string>& perfClassPrimaryCameraIds,
        int targetSdkVersion,
        std::vector<aidl::android::hardware::camera::provider::CameraIdAndStreamCombination>
                *halCameraIdsAndStreamCombinations,
        bool *earlyExit);
    std::shared_ptr<AidlProviderCallbacks> mCallbacks = nullptr;
    ndk::ScopedAIBinder_DeathRecipient mDeathRecipient;

};

} // namespace android
#endif
