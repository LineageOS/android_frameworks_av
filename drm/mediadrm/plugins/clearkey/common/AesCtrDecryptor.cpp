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
#define LOG_TAG "clearkey-AesDecryptor"

#include <utils/Log.h>

#include <openssl/aes.h>

#include "AesCtrDecryptor.h"
#include "ClearKeyTypes.h"

namespace clearkeydrm {

static const size_t kBlockBitCount = kBlockSize * 8;

CdmResponseType AesCtrDecryptor::decrypt(const std::vector<uint8_t>& key, const Iv iv,
                                         const uint8_t* source, uint8_t* destination,
                                         const std::vector<int32_t>& clearDataLengths,
                                         const std::vector<int32_t>& encryptedDataLengths,
                                         size_t* bytesDecryptedOut) {

    if (key.size() != kBlockSize || clearDataLengths.size() != encryptedDataLengths.size()) {
        android_errorWriteLog(0x534e4554, "63982768");
        return clearkeydrm::ERROR_DECRYPT;
    }

    uint32_t blockOffset = 0;
    uint8_t previousEncryptedCounter[kBlockSize];
    memset(previousEncryptedCounter, 0, kBlockSize);

    size_t offset = 0;
    AES_KEY opensslKey;
    AES_set_encrypt_key(key.data(), kBlockBitCount, &opensslKey);
    Iv opensslIv;
    memcpy(opensslIv, iv, sizeof(opensslIv));

    for (size_t i = 0; i < clearDataLengths.size(); ++i) {
        int32_t numBytesOfClearData = clearDataLengths[i];
        if (numBytesOfClearData > 0) {
            memcpy(destination + offset, source + offset, numBytesOfClearData);
            offset += numBytesOfClearData;
        }

        int32_t numBytesOfEncryptedData = encryptedDataLengths[i];
        if (numBytesOfEncryptedData > 0) {
            AES_ctr128_encrypt(source + offset, destination + offset,
                               numBytesOfEncryptedData, &opensslKey, opensslIv,
                               previousEncryptedCounter, &blockOffset);
            offset += numBytesOfEncryptedData;
        }
    }

    *bytesDecryptedOut = offset;
    return clearkeydrm::OK;
}

}  // namespace clearkeydrm
