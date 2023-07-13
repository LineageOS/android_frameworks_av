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

#define LOG_TAG "DrmRkpAdapter"
#include "DrmRkpAdapter.h"
#include <aidl/android/hardware/drm/IDrmFactory.h>
#include <aidl/android/hardware/drm/IDrmPlugin.h>
#include <aidl/android/hardware/security/keymint/BnRemotelyProvisionedComponent.h>
#include <android/binder_manager.h>
#include <log/log.h>
#include "DrmRemotelyProvisionedComponent.h"

namespace android::mediadrm {
using CryptoSchemes = ::aidl::android::hardware::drm::CryptoSchemes;
using IDrmFactory = ::aidl::android::hardware::drm::IDrmFactory;
using IDrmPlugin = ::aidl::android::hardware::drm::IDrmPlugin;

std::map<std::string, std::shared_ptr<IRemotelyProvisionedComponent>>
getDrmRemotelyProvisionedComponents() {
    std::map<std::string, std::shared_ptr<IRemotelyProvisionedComponent>> comps;
    AServiceManager_forEachDeclaredInstance(
            IDrmFactory::descriptor, &comps, [](const char* instance, void* context) {
                auto fullName = std::string(IDrmFactory::descriptor) + "/" + std::string(instance);
                auto factory = IDrmFactory::fromBinder(
                        ::ndk::SpAIBinder(AServiceManager_waitForService(fullName.c_str())));
                if (factory == nullptr) {
                    ALOGE("not found IDrmFactory. Instance name:[%s]", fullName.c_str());
                    return;
                }

                ALOGI("found IDrmFactory. Instance name:[%s]", fullName.c_str());
                CryptoSchemes schemes{};
                auto status = factory->getSupportedCryptoSchemes(&schemes);
                if (!status.isOk()) {
                    ALOGE("getSupportedCryptoSchemes failed.Detail: [%s].",
                          status.getDescription().c_str());
                    return;
                }

                if (schemes.uuids.empty()) {
                    ALOGW("IDrmFactory Instance [%s] has empty supported schemes",
                          fullName.c_str());
                    return;
                }

                std::shared_ptr<IDrmPlugin> mDrm;
                status = factory->createDrmPlugin(schemes.uuids[0], "DrmRkpAdapter", &mDrm);
                if (!status.isOk()) {
                    ALOGE("createDrmPlugin failed.Detail: [%s].", status.getDescription().c_str());
                    return;
                }

                std::string drmVendor;
                status = mDrm->getPropertyString("vendor", &drmVendor);
                if (!status.isOk()) {
                    ALOGE("mDrm->getPropertyString(\"vendor\") failed.Detail: [%s].",
                          status.getDescription().c_str());
                    return;
                }

                std::string drmDesc;
                status = mDrm->getPropertyString("description", &drmDesc);
                if (!status.isOk()) {
                    ALOGE("mDrm->getPropertyString(\"description\") failed.Detail: [%s].",
                          status.getDescription().c_str());
                    return;
                }

                std::vector<uint8_t> bcc;
                status = mDrm->getPropertyByteArray("bootCertificateChain", &bcc);
                if (!status.isOk()) {
                    ALOGE("mDrm->getPropertyByteArray(\"bootCertificateChain\") failed."
                          "Detail: [%s].",
                          status.getDescription().c_str());
                    return;
                }

                std::string compName(instance);
                auto comps = static_cast<
                        std::map<std::string, std::shared_ptr<IRemotelyProvisionedComponent>>*>(
                        context);
                (*comps)[compName] = ::ndk::SharedRefBase::make<DrmRemotelyProvisionedComponent>(
                        mDrm, drmVendor, drmDesc, bcc);
            });
    return comps;
}
}  // namespace android::mediadrm