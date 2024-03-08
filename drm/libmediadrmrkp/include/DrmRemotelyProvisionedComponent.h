/*
 * Copyright (C) 2023 The Android Open Source Project
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

#ifndef DRM_RKP_COMPONENT_H_
#define DRM_RKP_COMPONENT_H_

#include <aidl/android/hardware/drm/IDrmPlugin.h>
#include <aidl/android/hardware/security/keymint/BnRemotelyProvisionedComponent.h>
#include <aidl/android/hardware/security/keymint/RpcHardwareInfo.h>
#include <cppbor.h>

namespace android::mediadrm {

using ::aidl::android::hardware::drm::IDrmPlugin;
using ::aidl::android::hardware::security::keymint::BnRemotelyProvisionedComponent;
using ::aidl::android::hardware::security::keymint::DeviceInfo;
using ::aidl::android::hardware::security::keymint::MacedPublicKey;
using ::aidl::android::hardware::security::keymint::ProtectedData;
using ::aidl::android::hardware::security::keymint::RpcHardwareInfo;
using ::ndk::ScopedAStatus;

class DrmRemotelyProvisionedComponent : public BnRemotelyProvisionedComponent {
  public:
    DrmRemotelyProvisionedComponent(std::shared_ptr<IDrmPlugin> drm, std::string drmVendor,
                                    std::string drmDesc, std::vector<uint8_t> bcc);
    ScopedAStatus getHardwareInfo(RpcHardwareInfo* info) override;

    ScopedAStatus generateEcdsaP256KeyPair(bool testMode, MacedPublicKey* macedPublicKey,
                                           std::vector<uint8_t>* privateKeyHandle) override;

    ScopedAStatus generateCertificateRequest(bool testMode,
                                             const std::vector<MacedPublicKey>& keysToSign,
                                             const std::vector<uint8_t>& endpointEncCertChain,
                                             const std::vector<uint8_t>& challenge,
                                             DeviceInfo* deviceInfo, ProtectedData* protectedData,
                                             std::vector<uint8_t>* keysToSignMac) override;

    ScopedAStatus generateCertificateRequestV2(const std::vector<MacedPublicKey>& keysToSign,
                                               const std::vector<uint8_t>& challenge,
                                               std::vector<uint8_t>* csr) override;

  private:
    ScopedAStatus getVerifiedDeviceInfo(cppbor::Map& deviceInfoMap);
    ScopedAStatus getDeviceInfo(std::vector<uint8_t>* deviceInfo);

    std::shared_ptr<IDrmPlugin> mDrm;
    std::string mDrmVendor;
    std::string mDrmDesc;
    std::vector<uint8_t> mBcc;
};
}  // namespace android::mediadrm

#endif  // DRM_RKP_COMPONENT_H_