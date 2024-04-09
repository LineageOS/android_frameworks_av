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

#ifndef ANDROID_SERVERS_CAMERA_CAMERAPROVIDER_HIDLPROVIDERINFOH
#define ANDROID_SERVERS_CAMERA_CAMERAPROVIDER_HIDLPROVIDERINFOH

#include "common/CameraProviderManager.h"

namespace android {

struct HidlProviderInfo : public CameraProviderManager::ProviderInfo,
            virtual public hardware::camera::provider::V2_6::ICameraProviderCallback,
            virtual public hardware::hidl_death_recipient {
    // Current overall Android device physical status
    hardware::hidl_bitfield<hardware::camera::provider::V2_5::DeviceState> mDeviceState;

    // This pointer is used to keep a reference to the ICameraProvider that was last accessed.
    wp<hardware::camera::provider::V2_4::ICameraProvider> mActiveInterface;

    sp<hardware::camera::provider::V2_4::ICameraProvider> mSavedInterface;
    HidlProviderInfo(
            const std::string &providerName,
            const std::string &providerInstance,
            CameraProviderManager *manager) :
            CameraProviderManager::ProviderInfo(providerName, providerInstance, manager) {}

    virtual ~HidlProviderInfo() {}

    static status_t mapToStatusT(const hardware::camera::common::V1_0::Status &status);

    status_t initializeHidlProvider(
            sp<hardware::camera::provider::V2_4::ICameraProvider>& interface,
            int64_t currentDeviceState);

    IPCTransport getIPCTransport() const override {return IPCTransport::HIDL;}

    const sp<hardware::camera::provider::V2_4::ICameraProvider> startProviderInterface();

    virtual bool successfullyStartedProviderInterface() override;

    virtual int64_t getDeviceState() override {return mDeviceState;};

    virtual status_t setUpVendorTags() override;
    virtual status_t notifyDeviceStateChange(int64_t) override;

    /**
     * Query the camera provider for concurrent stream configuration support
     */
    virtual status_t isConcurrentSessionConfigurationSupported(
        const std::vector<CameraIdAndSessionConfiguration> &cameraIdsAndSessionConfigs,
        const std::set<std::string>& perfClassPrimaryCameraIds,
        int targetSdkVersion, bool *isSupported) override;

    // Helper for initializeDeviceInfo to use the right CameraProvider get method.
    sp<hardware::camera::device::V3_2::ICameraDevice>
            startDeviceInterface(const std::string &deviceName);

    // ICameraProviderCallbacks interface - these lock the parent mInterfaceMutex
    hardware::Return<void> cameraDeviceStatusChange(
            const hardware::hidl_string& ,
            hardware::camera::common::V1_0::CameraDeviceStatus ) override;
    hardware::Return<void> torchModeStatusChange(
            const hardware::hidl_string& ,
            hardware::camera::common::V1_0::TorchModeStatus ) override;
    hardware::Return<void> physicalCameraDeviceStatusChange(
            const hardware::hidl_string& ,
            const hardware::hidl_string& ,
            hardware::camera::common::V1_0::CameraDeviceStatus ) override;

    // hidl_death_recipient interface - this locks the parent mInterfaceMutex
    virtual void serviceDied(uint64_t , const wp<hidl::base::V1_0::IBase>& ) override;

    struct HidlDeviceInfo3 : public CameraProviderManager::ProviderInfo::DeviceInfo3 {

        const hardware::hidl_version mVersion = hardware::hidl_version{3, 2};
        sp<IBase> mSavedInterface = nullptr;

        HidlDeviceInfo3(const std::string& , const metadata_vendor_id_t ,
                const std::string &, uint16_t ,
                const CameraResourceCost& ,
                sp<ProviderInfo> ,
                const std::vector<std::string>& ,
                sp<hardware::camera::device::V3_2::ICameraDevice>);

        ~HidlDeviceInfo3() {}

        virtual status_t setTorchMode(bool enabled) override;
        virtual status_t turnOnTorchWithStrengthLevel(int32_t torchStrength) override;
        virtual status_t getTorchStrengthLevel(int32_t *torchStrength) override;

        virtual status_t dumpState(int fd) override;

        virtual status_t isSessionConfigurationSupported(
                const SessionConfiguration &/*configuration*/,
                bool overrideForPerfClass, camera3::metadataGetter /*getMetadata*/,
                bool checkSessionParams, bool *status/*status*/);

        sp<hardware::camera::device::V3_2::ICameraDevice> startDeviceInterface();
    };

 private:

    virtual std::unique_ptr<DeviceInfo> initializeDeviceInfo(const std::string &,
            const metadata_vendor_id_t , const std::string &,
            uint16_t ) override;
    virtual status_t reCacheConcurrentStreamingCameraIdsLocked() override;

    //Expects to have mLock locked
    status_t getConcurrentCameraIdsInternalLocked(
            sp<hardware::camera::provider::V2_6::ICameraProvider> &);

    //expects to have mManager->mInterfaceMutex locked
    status_t convertToHALStreamCombinationAndCameraIdsLocked(
        const std::vector<hardware::camera2::utils::CameraIdAndSessionConfiguration>&
                cameraIdsAndSessionConfigs,
        const std::set<std::string>& perfClassPrimaryCameraIds,
        int targetSdkVersion,
        hardware::hidl_vec<hardware::camera::provider::V2_7::CameraIdAndStreamCombination>*
                halCameraIdsAndStreamCombinations,
        bool *earlyExit);
}; // HidlProviderInfo

} // namespace android
#endif
