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
#include "DrmRkpAdapter.h"

using ::aidl::android::hardware::security::keymint::MacedPublicKey;
int main() {
    std::vector<uint8_t> challenge(16);
    std::vector<uint8_t> csr;
    std::vector<MacedPublicKey> k;
    for (auto const& e : android::mediadrm::getDrmRemotelyProvisionedComponents()) {
        auto status = e.second.get()->generateCertificateRequestV2(k, challenge, &csr);
        printf("%s calls generateCertificateRequestV2() gets status.isOk():%d\n",
               e.first.c_str(), status.isOk());
    }

    return 0;
}