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

#define LOG_TAG "DrmRemotelyProvisionedComponent"
#include "DrmRemotelyProvisionedComponent.h"

#include <android-base/properties.h>
#include <cppbor.h>
#include <cppbor_parse.h>
#include <log/log.h>
#include <map>
#include <string>

namespace android::mediadrm {
DrmRemotelyProvisionedComponent::DrmRemotelyProvisionedComponent(std::shared_ptr<IDrmPlugin> drm,
                                                                 std::string drmVendor,
                                                                 std::string drmDesc,
                                                                 std::vector<uint8_t> bcc)
    : mDrm(std::move(drm)),
      mDrmVendor(std::move(drmVendor)),
      mDrmDesc(std::move(drmDesc)),
      mBcc(std::move(bcc)) {}

ScopedAStatus DrmRemotelyProvisionedComponent::getHardwareInfo(RpcHardwareInfo* info) {
    info->versionNumber = 3;
    info->rpcAuthorName = mDrmVendor;
    info->supportedEekCurve = RpcHardwareInfo::CURVE_NONE;
    info->supportedNumKeysInCsr = RpcHardwareInfo::MIN_SUPPORTED_NUM_KEYS_IN_CSR;
    info->uniqueId = mDrmDesc;
    return ScopedAStatus::ok();
}

ScopedAStatus DrmRemotelyProvisionedComponent::generateEcdsaP256KeyPair(bool, MacedPublicKey*,
                                                                        std::vector<uint8_t>*) {
    return ScopedAStatus(AStatus_fromServiceSpecificErrorWithMessage(
            IRemotelyProvisionedComponent::STATUS_REMOVED,
            "generateEcdsaP256KeyPair not supported."));
}

ScopedAStatus DrmRemotelyProvisionedComponent::generateCertificateRequest(
        bool, const std::vector<MacedPublicKey>&, const std::vector<uint8_t>&,
        const std::vector<uint8_t>&, DeviceInfo*, ProtectedData*, std::vector<uint8_t>*) {
    return ScopedAStatus(AStatus_fromServiceSpecificErrorWithMessage(
            IRemotelyProvisionedComponent::STATUS_REMOVED,
            "generateCertificateRequest not supported."));
}

ScopedAStatus DrmRemotelyProvisionedComponent::getVerifiedDeviceInfo(cppbor::Map& deviceInfoMap) {
    std::vector<uint8_t> verifiedDeviceInfo;
    auto status = mDrm->getPropertyByteArray("verifiedDeviceInfo", &verifiedDeviceInfo);
    if (!status.isOk()) {
        ALOGE("getPropertyByteArray verifiedDeviceInfo failed. Details: [%s].",
              status.getDescription().c_str());
        return status;
    }

    auto [parsed, _, err] = cppbor::parse(
            reinterpret_cast<const uint8_t*>(verifiedDeviceInfo.data()), verifiedDeviceInfo.size());

    if (!parsed || !parsed->asMap()) {
        ALOGE("Failed to parse the verified device info cbor: %s", err.c_str());
        return ScopedAStatus(AStatus_fromServiceSpecificErrorWithMessage(
                IRemotelyProvisionedComponent::STATUS_FAILED,
                "Failed to parse the verified device info cbor."));
    }

    const cppbor::Map* verifiedDeviceInfoMap = parsed->asMap();
    for (size_t i = 0; i < verifiedDeviceInfoMap->size(); i++) {
        auto& [keyItem, valueItem] = (*verifiedDeviceInfoMap)[i];
        ALOGI("Found device info %s", keyItem->asTstr()->value().data());
        if (valueItem != nullptr && valueItem->asTstr() != nullptr &&
            valueItem->asTstr()->value().empty()) {
            ALOGI("Value is empty. Skip");
            continue;
        }
        deviceInfoMap.add(keyItem->clone(), valueItem->clone());
    }

    return ScopedAStatus::ok();
}

ScopedAStatus DrmRemotelyProvisionedComponent::getDeviceInfo(std::vector<uint8_t>* deviceInfo) {
    auto deviceInfoMap = cppbor::Map();
    auto status = getVerifiedDeviceInfo(deviceInfoMap);
    if (!status.isOk()) {
        ALOGE("getVerifiedDeviceInfo failed. Details: [%s].", status.getDescription().c_str());
        return status;
    }
    const std::map<std::string, std::string> keyToProp{{"brand", "ro.product.brand"},
                                                       {"manufacturer", "ro.product.manufacturer"},
                                                       {"model", "ro.product.model"},
                                                       {"device", "ro.product.device"},
                                                       {"product", "ro.product.name"}};
    for (auto i : keyToProp) {
        auto key = i.first;
        auto prop = i.second;
        const auto& val= deviceInfoMap.get(key);
        if (val == nullptr || val->asTstr()->value().empty()) {
            std::string propValue = android::base::GetProperty(prop, "");
            if (propValue.empty()) {
                ALOGE("Failed to get OS property %s", prop.c_str());
                return ScopedAStatus(AStatus_fromServiceSpecificErrorWithMessage(
                        IRemotelyProvisionedComponent::STATUS_FAILED,
                        "Failed to get OS property."));
            }
            deviceInfoMap.add(cppbor::Tstr(key), cppbor::Tstr(propValue));
            ALOGI("use OS property %s: %s", prop.c_str(), propValue.c_str());
        } else {
            ALOGI("use verified key %s: %s", key.c_str(), val->asTstr()->value().data());
        }
    }
    deviceInfoMap.canonicalize();
    *deviceInfo = deviceInfoMap.encode();
    return ScopedAStatus::ok();
}

ScopedAStatus DrmRemotelyProvisionedComponent::generateCertificateRequestV2(
        const std::vector<MacedPublicKey>&, const std::vector<uint8_t>& challenge,
        std::vector<uint8_t>* out) {
    // access csr input/output via setPropertyByteArray/getPropertyByteArray
    auto status = mDrm->setPropertyByteArray("certificateSigningRequestChallenge", challenge);
    if (!status.isOk()) {
        ALOGE("setPropertyByteArray certificateSigningRequestChallenge failed. Details: [%s].",
              status.getDescription().c_str());
        return status;
    }

    std::vector<uint8_t> deviceInfo;
    status = getDeviceInfo(&deviceInfo);
    if (!status.isOk()) {
        ALOGE("getDeviceInfo failed. Details: [%s].", status.getDescription().c_str());
        return status;
    }

    status = mDrm->setPropertyByteArray("deviceInfo", deviceInfo);
    if (!status.isOk()) {
        ALOGE("setPropertyByteArray deviceInfo failed. Details: [%s].",
              status.getDescription().c_str());
        return status;
    }

    std::vector<uint8_t> deviceSignedCsrPayload;
    status = mDrm->getPropertyByteArray("deviceSignedCsrPayload", &deviceSignedCsrPayload);
    if (!status.isOk()) {
        ALOGE("getPropertyByteArray deviceSignedCsrPayload failed. Details: [%s].",
              status.getDescription().c_str());
        return status;
    }

    // assemble AuthenticatedRequest (definition in IRemotelyProvisionedComponent.aidl)
    *out = cppbor::Array()
                   .add(1 /* version */)
                   .add(cppbor::Map() /* UdsCerts */)
                   .add(cppbor::EncodedItem(mBcc))
                   .add(cppbor::EncodedItem(std::move(deviceSignedCsrPayload)))
                   .encode();
    return ScopedAStatus::ok();
}
}  // namespace android::mediadrm